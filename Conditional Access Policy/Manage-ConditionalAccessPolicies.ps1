#Requires -Module Microsoft.Graph.Identity.SignIns

param(
    [switch]$Export,           # Export all policies
    [switch]$Import,           # Import from file(s)
    [string]$InputPath,        # Single file or folder path
    [string]$OutputPath = "."  # Export folder
)

# Connect (interactive if needed)
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess", "Policy.Read.All" -ErrorAction Stop

# -------------------------------
# Helper: Remove read-only properties
# -------------------------------
function Clean-PolicyBody {
    param([hashtable]$Body)

    $readOnly = @(
        "id",
        "@odata.context", 
        "createdDateTime", 
        "modifiedDateTime",
        "templateId", 
        "version"
    )
    foreach ($key in $readOnly) {
        $Body.Remove($key) | Out-Null
    }
    return $Body
}

# -------------------------------
# Helper: Find policy by ID or Name
# -------------------------------
function Find-Policy {
    param(
        [string]$Id,
        [string]$Name
    )
    if ($Id) {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$Id" -ErrorAction SilentlyContinue
        } catch { }
    }
    if ($Name) {
        $all = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies").value
        return $all | Where-Object { $_.displayName -eq $Name } | Select-Object -First 1
    }
    return $null
}

# -------------------------------
# 1. EXPORT ALL CA POLICIES
# -------------------------------
if ($Export) {
    Write-Host "Exporting all Conditional Access policies..." -ForegroundColor Cyan

    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

    $policies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

    foreach ($pol in $policies.value) {
        $id = $pol.id
        $name = $pol.displayName
        $safeName = ($name -replace '[\\/:*?"<>|]', '_').Trim()
        $fileName = if ($safeName) { "$safeName.json" } else { "Policy_$id.json" }
        $filePath = Join-Path $OutputPath $fileName

        # Save full raw policy
        $pol | ConvertTo-Json -Depth 20 | Out-File $filePath -Encoding UTF8 -Force
        Write-Host "Saved: $filePath" -ForegroundColor Green
    }

    Write-Host "Export complete: $($policies.value.Count) policies saved to '$OutputPath'" -ForegroundColor Cyan
    return
}

# -------------------------------
# 2. IMPORT / UPDATE / DELETE POLICIES
# -------------------------------
if (-not $Import) {
    Write-Host "Use -Export or -Import with -InputPath" -ForegroundColor Red
    return
}

if (-not $InputPath) {
    Write-Error "-InputPath is required for import"
    return
}

$files = @()
$deleteFolder = $null

# Resolve input path
if (Test-Path $InputPath -PathType Container) {
    $files = Get-ChildItem -Path $InputPath -Filter "*.json" -File -Recurse
    # Look for 'delete' subfolder
    $deleteFolder = Get-ChildItem -Path $InputPath -Directory -Filter "delete" | Select-Object -First 1
} elseif (Test-Path $InputPath -PathType Leaf) {
    $files = Get-Item $InputPath
    # Check if parent has a 'delete' folder
    $parent = Split-Path $InputPath -Parent
    $deleteFolder = Get-ChildItem -Path $parent -Directory -Filter "delete" | Select-Object -First 1
} else {
    Write-Error "Invalid -InputPath: $InputPath"
    return
}

if ($files.Count -eq 0 -and -not $deleteFolder) {
    Write-Host "No JSON files or 'delete' folder found in '$InputPath'" -ForegroundColor Yellow
    return
}

Write-Host "Processing import and delete operations..." -ForegroundColor Cyan

# -------------------------------
# Step 1: Handle DELETE folder
# -------------------------------
if ($deleteFolder) {
    Write-Host "Found 'delete' folder: $($deleteFolder.FullName)" -ForegroundColor Yellow
    $deleteFiles = Get-ChildItem -Path $deleteFolder.FullName -Filter "*.json" -File

    foreach ($file in $deleteFiles) {
        try {
            $json = Get-Content $file.FullName -Raw | ConvertFrom-Json -AsHashtable
            $id = $json.id
            $name = $json.displayName

            $existing = Find-Policy -Id $id -Name $name

            if ($existing) {
                Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($existing.id)"
                Write-Host "DELETED: '$name' ($($existing.id))" -ForegroundColor Red
            } else {
                Write-Warning "Not found to delete: '$name' (ID: $id)"
            }
        }
        catch {
            Write-Error "Failed to delete '$($file.Name)': $($_.Exception.Message)"
        }
    }
}

# -------------------------------
# Step 2: Handle IMPORT/UPDATE (non-delete files)
# -------------------------------
$importFiles = $files | Where-Object { $_.DirectoryName -notlike "*\delete" -and $_.DirectoryName -notlike "*/delete" }

if ($importFiles.Count -gt 0) {
    Write-Host "Importing/updating $($importFiles.Count) policy file(s)..." -ForegroundColor Cyan
}

foreach ($file in $importFiles) {
    try {
        $json = Get-Content $file.FullName -Raw | ConvertFrom-Json -AsHashtable
        if (-not $json) { throw "Invalid JSON" }

        $originalId = $json.id
        $displayName = $json.displayName

        # Clean body for create/update
        $body = Clean-PolicyBody -Body $json
        $bodyJson = $body | ConvertTo-Json -Depth 20

        # Find existing policy: first by ID, then by name
        $existing = Find-Policy -Id $originalId -Name $displayName

        if ($existing) {
            # UPDATE
            $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($existing.id)"
            Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $bodyJson -ContentType "application/json"
            Write-Host "Updated: '$displayName' ($($existing.id))" -ForegroundColor Green
        } else {
            # CREATE
            $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            $newPol = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $bodyJson -ContentType "application/json"
            Write-Host "Created: '$displayName' (New ID: $($newPol.id))" -ForegroundColor Magenta
        }
    }
    catch {
        Write-Error "Failed '$($file.Name)': $($_.Exception.Message)"
    }
}

Write-Host "All operations complete." -ForegroundColor Cyan




## 1. Export all
#.\Manage-ConditionalAccessPolicies.ps1 -Export -OutputPath "C:\CAPolicies"
#
## 2. Import + Delete (from folder with 'delete' subfolder)
#.\Manage-ConditionalAccessPolicies.ps1 -Import -InputPath "C:\CAPolicies"
#
## 3. Import single file (and check parent for 'delete')
#.\Manage-ConditionalAccessPolicies.ps1 -Import -InputPath "C:\CAPolicies\Block Legacy Auth.json"
