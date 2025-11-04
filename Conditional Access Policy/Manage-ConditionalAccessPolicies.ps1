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
        "version"#, 
        #"state"  # state can be updated, but omit unless changing
    )
    foreach ($key in $readOnly) {
        $Body.Remove($key) | Out-Null
    }
    return $Body
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
# 2. IMPORT / UPDATE POLICIES
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
if (Test-Path $InputPath -PathType Container) {
    $files = Get-ChildItem -Path $InputPath -Filter "*.json" -File
} elseif (Test-Path $InputPath -PathType Leaf) {
    $files = Get-Item $InputPath
} else {
    Write-Error "Invalid -InputPath: $InputPath"
    return
}

if ($files.Count -eq 0) {
    Write-Host "No JSON files found in '$InputPath'" -ForegroundColor Yellow
    return
}

Write-Host "Importing $($files.Count) policy file(s)..." -ForegroundColor Cyan

foreach ($file in $files) {
    try {
        $json = Get-Content $file.FullName -Raw | ConvertFrom-Json -AsHashtable
        if (-not $json) { throw "Invalid JSON" }

        $originalId = $json.id
        $displayName = $json.displayName

        # Clean body
        $body = Clean-PolicyBody -Body $json

        # Convert to JSON string
        $bodyJson = $body | ConvertTo-Json -Depth 20

        # Decide: Update or Create?
        $existing = $null
        if ($originalId) {
            try {
                $existing = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$originalId" -ErrorAction SilentlyContinue
            } catch { $existing = $null }
        }

        if ($existing) {
            # UPDATE (PATCH)
            $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$originalId"
            Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $bodyJson -ContentType "application/json"
            Write-Host "Updated: '$displayName' ($originalId)" -ForegroundColor Green
        } else {
            # CREATE (POST)
            $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            $newPol = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $bodyJson -ContentType "application/json"
            Write-Host "Created: '$displayName' (New ID: $($newPol.id))" -ForegroundColor Magenta
        }
    }
    catch {
        Write-Error "Failed '$($file.Name)': $($_.Exception.Message)"
    }
}

Write-Host "Import complete." -ForegroundColor Cyan







#How to Use
#1. Export All Policies
#powershell.\Manage-ConditionalAccessPolicies.ps1 -Export -OutputPath "C:\CAPolicies"
#→ Creates one .json file per policy in the folder.
#2. Import from Folder
#powershell.\Manage-ConditionalAccessPolicies.ps1 -Import -InputPath "C:\CAPolicies"
#→ Updates existing or creates new.
#3. Import Single File
#powershell.\Manage-ConditionalAccessPolicies.ps1 -Import -InputPath "C:\CAPolicies\Block Legacy Auth.json"
