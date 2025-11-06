#Requires -Module Microsoft.Graph.Identity.SignIns

param(
    [switch]$Export,           # Export all policies
    [switch]$Import,           # Import from file(s)
    [switch]$Zip,              # NEW: Zip exported JSONs with datetime
    [switch]$Clean,            # NEW: Delete existing .json files in OutputPath before export
    [string]$InputPath,        # Single file or folder path
    [string]$OutputPath = "."  # Export folder (or zip location)
)

# Load .NET ZIP support (ZIP format only)
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Connect (interactive if needed)
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess", "Policy.Read.All" -ErrorAction Stop

# -------------------------------
# Logging: remove previous logs and create a fresh per-run log
# -------------------------------
# Ensure OutputPath exists (use default '.' if not provided)
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

# Use a dedicated log folder under OutputPath
$logFolder = Join-Path $OutputPath 'log'
if (-not (Test-Path $logFolder)) { New-Item -ItemType Directory -Path $logFolder -Force | Out-Null }

$script:LogPattern = 'Manage-ConditionalAccessPolicies*.log'
# Remove previous run logs matching pattern from the log folder
try {
    Get-ChildItem -Path $logFolder -Filter $script:LogPattern -File -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
} catch { }

# Create new log file for this run inside the log folder
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:LogFile = Join-Path $logFolder "Manage-ConditionalAccessPolicies_$timestamp.log"
New-Item -Path $script:LogFile -ItemType File -Force | Out-Null

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [string]$Level = 'INFO'
    )
    $ts = Get-Date -Format o
    $line = "$ts [$Level] $Message"
    try { Add-Content -Path $script:LogFile -Value $line } catch { }
    # Do not write to the console here to avoid duplicate output.
    # Callers should explicitly Write-Host when console output is desired.
    return
}

# -------------------------------
# Helper: Remove read-only properties
# -------------------------------
function Clean-PolicyBody {
    param([object]$Body)

    # Normalize input: accept PSObject, Hashtable or raw JSON-convertible objects
    if (-not ($Body -is [System.Collections.IDictionary])) {
        try {
            # Prefer ConvertFrom-Json -AsHashtable when available (PowerShell 7+)
            $json = $Body | ConvertTo-Json -Depth 100
            try {
                $Body = $json | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            } catch {
                $Body = $json | ConvertFrom-Json
            }
        } catch {
            # If converting fails, leave the Body as-is; downstream checks will handle types
        }
    }

    # Remove read-only and @odata keys recursively from hashtables/arrays
    $readOnlyNames = @(
        'id',
        'createdDateTime',
        'modifiedDateTime',
        'templateId',
        'version'
    )

    function Clean-Recursively {
        param([object]$Node)

        if ($null -eq $Node) { return }

        # Handle dictionaries / hashtables / PSObjects
        if ($Node -is [System.Collections.IDictionary]) {
            # Capture keys first because we'll remove items during iteration
            $keys = @($Node.Keys)
            foreach ($k in $keys) {
                try {
                    $val = $Node[$k]
                } catch {
                    $val = $null
                }

                # Remove keys that are odata metadata or known read-only names
                if ($k -match "@odata" -or ($readOnlyNames -contains $k)) {
                    $Node.Remove($k) | Out-Null
                    continue
                }

                # Special-case: authenticationStrength nested object is read-only except for a reference by id
                if ($k -ieq 'authenticationStrength') {
                    try {
                        if ($val -is [System.Collections.IDictionary] -and $val.ContainsKey('id') -and $val.id) {
                            # Replace large object with a minimal reference containing only the id
                            $Node[$k] = @{'id' = $val.id}
                        } else {
                            # If no id present, remove the property to avoid schema errors
                            $Node.Remove($k) | Out-Null
                        }
                    } catch {
                        # On any error, remove to be safe
                        $Node.Remove($k) | Out-Null
                    }
                    continue
                }

                # Remove explicit nulls
                if ($val -eq $null) {
                    $Node.Remove($k) | Out-Null
                    continue
                }

                # Recurse into nested structures
                Clean-Recursively -Node $val
            }
        }
        # Handle arrays/lists
        elseif ($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [string])) {
            foreach ($item in $Node) { Clean-Recursively -Node $item }
        }
    }

    Clean-Recursively -Node $Body
    return $Body
}

# -------------------------------
# Helper: Log full error details (including possible HTTP response body)
# -------------------------------
function Log-FullError {
    param(
        [Parameter(Mandatory=$true)] $ErrorRecord,
        [string]$Context = '',
        [string]$RequestBody = $null
    )

    Write-Host "--- ERROR: $Context ---" -ForegroundColor Red
    if ($ErrorRecord -and $ErrorRecord.Exception) {
        Write-Host "Message: $($ErrorRecord.Exception.Message)" -ForegroundColor Red
        try { Write-Log "ERROR: $($ErrorRecord.Exception.Message)" "ERROR" } catch { }

        function Get-ResponseContentFromException {
            param([Exception]$ex)
            if (-not $ex) { return $null }

            # 1) Exception.Response property (HttpResponseMessage or similar)
            try {
                if ($ex.PSObject.Properties.Name -contains 'Response') {
                    $resp = $ex.Response
                    if ($resp -is [string]) { return $resp }
                    if ($resp -is [System.Net.Http.HttpResponseMessage]) {
                        return $resp.Content.ReadAsStringAsync().Result
                    }
                    if ($resp -ne $null) {
                        if ($resp.PSObject.Properties.Name -contains 'Content') { return $resp.Content }
                        if ($resp.PSObject.Properties.Name -contains 'Body') { return $resp.Body }
                    }
                }
            } catch { }

            # 2) InnerException
            try {
                if ($ex.InnerException) { return Get-ResponseContentFromException -ex $ex.InnerException }
            } catch { }

            # 3) Some Graph SDK exceptions include a ResponseBody or RawResponse
            try {
                if ($ex.PSObject.Properties.Name -contains 'ResponseBody') { return $ex.ResponseBody }
                if ($ex.PSObject.Properties.Name -contains 'RawResponse') { return $ex.RawResponse }
            } catch { }

            # 4) As a last resort, return the exception message
            return $ex.Message
        }

        # Attempt to extract response content
        $responseContent = $null
        try { $responseContent = Get-ResponseContentFromException -ex $ErrorRecord.Exception } catch { $responseContent = $null }

        if ($responseContent) {
            Write-Host "Response content (raw):" -ForegroundColor Red
                try { Write-Log "Response content (raw): $responseContent" "ERROR" } catch { }
            # Try to pretty-print JSON if possible
            try {
                $parsed = $null
                if ($responseContent -is [string]) {
                    $parsed = $responseContent | ConvertFrom-Json -ErrorAction SilentlyContinue
                } else {
                    $parsed = $responseContent
                }
                if ($parsed) { $parsed | ConvertTo-Json -Depth 50 | Write-Host -ForegroundColor Red } else { Write-Host $responseContent -ForegroundColor Red }
            } catch {
                Write-Host $responseContent -ForegroundColor Red
            }
        }

            if ($RequestBody) {
            Write-Host "Request body (truncated to 10k chars):" -ForegroundColor Yellow
            $rb = $RequestBody
            if ($rb.Length -gt 10000) { $rb = $rb.Substring(0,10000) + "... (truncated)" }
            Write-Host $rb -ForegroundColor Yellow
            try { Write-Log "Request body (truncated): $rb" "DEBUG" } catch { }
        }

        Write-Host "Full ErrorRecord:" -ForegroundColor Yellow
        $ErrorRecord | Format-List * -Force | Out-String | Write-Host -ForegroundColor Yellow
        try { Write-Log ($ErrorRecord | Format-List * -Force | Out-String) "ERROR" } catch { }
    } else {
        Write-Host ($ErrorRecord | Out-String) -ForegroundColor Red
    }
    Write-Host "--- END ERROR ---" -ForegroundColor Red
}

# -------------------------------
# Helper: Find policy by ID or Name
# -------------------------------
function Find-Policy {
    param(
        [string]$Id,
        [string]$Name
    )
    # Try lookup by ID first (fast, reliable)
    if ($Id) {
        try {
            $res = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$Id" -ErrorAction SilentlyContinue
            if ($res) { return $res }
        } catch { }
    }

    # If name provided, use server-side filter to avoid paging issues and false negatives
    if ($Name) {
        try {
            # Escape single quotes per OData rules
            $escaped = $Name -replace "'","''"
            $filter = "displayName eq '$escaped'"
            $encoded = [System.Uri]::EscapeDataString($filter)
            $uri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$filter=' + $encoded

            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
            if ($resp -and $resp.value) {
                # Prefer exact match from server response
                $match = $resp.value | Where-Object { $_.displayName -eq $Name } | Select-Object -First 1
                if ($match) { return $match }
            }
        } catch { }

        # Fallback: fetch all and search locally (should be rare)
        try {
            $all = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies").value
            return $all | Where-Object { $_.displayName -eq $Name } | Select-Object -First 1
        } catch { }
    }
    return $null
}

# -------------------------------
# 1. EXPORT ALL CA POLICIES
# -------------------------------
if ($Export) {
    Write-Host "Exporting all Conditional Access policies..." -ForegroundColor Cyan
    Write-Log "Exporting all Conditional Access policies..." "INFO"

    # Resolve export path
    $exportPath = $OutputPath
    $tempExportPath = $null

    # If -Zip: export to temp folder first
    if ($Zip) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $tempExportPath = Join-Path ([System.IO.Path]::GetTempPath()) "CA_Export_$timestamp"
        New-Item -ItemType Directory -Path $tempExportPath -Force | Out-Null
        $exportPath = $tempExportPath
        Write-Host "Exporting to temporary folder: $tempExportPath" -ForegroundColor Gray
        Write-Log "Exporting to temporary folder: $tempExportPath" "DEBUG"
    } else {
        # Ensure output folder exists
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
    }

    # -------------------------------
    # CLEAN: Remove existing .json files if -Clean is used
    # -------------------------------
    if ($Clean -and -not $Zip) {
        $existingJsons = Get-ChildItem -Path $OutputPath -Filter "*.json" -File
        if ($existingJsons.Count -gt 0) {
            Write-Host "Cleaning $($existingJsons.Count) existing .json file(s) in '$OutputPath'..." -ForegroundColor Yellow
            Write-Log "Cleaning $($existingJsons.Count) existing .json file(s) in '$OutputPath'..." "INFO"
            $existingJsons | Remove-Item -Force
            Write-Host "Clean complete." -ForegroundColor Gray
            Write-Log "Clean complete." "DEBUG"
        }
    }

    # Also remove previous log files when -Clean is used, but keep the most recent log (if any)
    if ($Clean -and -not $Zip) {
        try {
            $logFiles = Get-ChildItem -Path $OutputPath -Include "*.log","*.txt" -File -Recurse -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending
            if ($logFiles -and $logFiles.Count -gt 0) {
                # Keep the newest log file; remove the rest
                $keep = $logFiles[0]
                $toRemove = if ($logFiles.Count -gt 1) { $logFiles | Select-Object -Skip 1 } else { @() }
                if ($toRemove.Count -gt 0) {
                    Write-Host "Removing $($toRemove.Count) old log file(s) from '$OutputPath' (keeping '$($keep.Name)')..." -ForegroundColor Yellow
                    Write-Log "Removing $($toRemove.Count) old log file(s) from '$OutputPath' (keeping '$($keep.Name)')..." "INFO"
                    $toRemove | Remove-Item -Force -ErrorAction SilentlyContinue
                    Write-Host "Old log cleanup complete." -ForegroundColor Gray
                    Write-Log "Old log cleanup complete." "DEBUG"
                } else {
                    Write-Host "No old log files to remove; keeping '$($keep.Name)'" -ForegroundColor Gray
                }
            }
        } catch {
            Write-Host "Warning: failed to clean log files in '$OutputPath': $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # -------------------------------
    # EXPORT POLICIES
    # -------------------------------
    $policies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

    foreach ($pol in $policies.value) {
        $id   = $pol.id
        $name = $pol.displayName
        $safeName = if ($name) { ($name -replace '[\\/:*?"<>|]', '_').Trim() } else { "Policy" }

        # Use a filename that includes the policy id to keep files stable across renames
        $fileName = "$safeName - $id.json"
        $filePath = Join-Path $exportPath $fileName

        # Remove any existing files for this policy id (old name variants) to avoid duplicates
        try {
            $existingMatches = Get-ChildItem -Path $exportPath -Filter "*$id*.json" -File -ErrorAction SilentlyContinue
            foreach ($m in $existingMatches) {
                if ($m.FullName -ne $filePath) { Remove-Item -LiteralPath $m.FullName -Force -ErrorAction SilentlyContinue }
            }
        } catch {
            # ignore cleanup errors
        }

        $pol | ConvertTo-Json -Depth 20 | Out-File $filePath -Encoding UTF8 -Force
        Write-Host "Saved: $filePath" -ForegroundColor Green
        Write-Log "Saved: $filePath" "INFO"
    }

    Write-Host "Export complete: $($policies.value.Count) policies saved." -ForegroundColor Cyan

    # -------------------------------
    # ZIP: Create archive if -Zip was used
    # -------------------------------
    if ($Zip) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $zipFileName = "ConditionalAccess_Policies_$timestamp.zip"

        # Ensure a backup folder exists under OutputPath and store the zip there
        $backupFolder = Join-Path $OutputPath 'backup'
        if (-not (Test-Path $backupFolder)) { New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null }
        $zipFilePath = Join-Path $backupFolder $zipFileName

        Write-Host "Creating ZIP archive: $zipFilePath" -ForegroundColor Yellow
        Write-Log "Creating ZIP archive: $zipFilePath" "INFO"
        [System.IO.Compression.ZipFile]::CreateFromDirectory($tempExportPath, $zipFilePath)

        Write-Host "ZIP created: $zipFilePath" -ForegroundColor Green
        Write-Log "ZIP created: $zipFilePath" "INFO"

        # Clean up temp folder
        if (Test-Path $tempExportPath) {
            Remove-Item $tempExportPath -Recurse -Force
            Write-Host "Temporary export folder removed." -ForegroundColor Gray
            Write-Log "Temporary export folder removed: $tempExportPath" "DEBUG"
        }
    }

    Write-Host "Export operation finished." -ForegroundColor Cyan
    Write-Log "Export operation finished." "INFO"
    return
}

# -------------------------------
# 2. IMPORT / UPDATE / DELETE POLICIES
# -------------------------------
if (-not $Import) {
    Write-Host "Use -Export [-Zip] [-Clean] [-OutputPath <path>] or -Import -InputPath <path>" -ForegroundColor Red
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
    $deleteFolder = Get-ChildItem -Path $InputPath -Directory -Filter "delete" | Select-Object -First 1
} elseif (Test-Path $InputPath -PathType Leaf) {
    $files = Get-Item $InputPath
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
Write-Log "Processing import and delete operations..." "INFO"

# -------------------------------
# Step 1: Handle DELETE folder
# -------------------------------
if ($deleteFolder) {
    Write-Host "Found 'delete' folder: $($deleteFolder.FullName)" -ForegroundColor Yellow
    Write-Log "Found 'delete' folder: $($deleteFolder.FullName)" "INFO"
    $deleteFiles = Get-ChildItem -Path $deleteFolder.FullName -Filter "*.json" -File

    foreach ($file in $deleteFiles) {
        try {
            $json = Get-Content $file.FullName -Raw | ConvertFrom-Json -AsHashtable
            $id   = $json.id
            $name = $json.displayName

            $existing = Find-Policy -Id $id -Name $name

            if ($existing) {
                try {
                    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($existing.id)"
                    Write-Host "DELETED: '$name' ($($existing.id))" -ForegroundColor Red
                    Write-Log "DELETED: '$name' ($($existing.id))" "WARN"
                } catch {
                    Log-FullError -ErrorRecord $_ -Context "Failed to DELETE policy '$name' (ID: $($existing.id))"
                }
            } else {
                Write-Warning "Not found to delete: '$name' (ID: $id)"
                Write-Log "Not found to delete: '$name' (ID: $id)" "WARN"
            }
        }
        catch {
            Log-FullError -ErrorRecord $_ -Context "Failed to process delete file '$($file.Name)'"
        }
    }
}

# -------------------------------
# Step 2: Handle IMPORT/UPDATE
# -------------------------------
$importFiles = $files | Where-Object { $_.DirectoryName -notlike "*\delete" -and $_.DirectoryName -notlike "*/delete" }

if ($importFiles.Count -gt 0) {
    Write-Host "Importing/updating $($importFiles.Count) policy file(s)..." -ForegroundColor Cyan
    Write-Log "Importing/updating $($importFiles.Count) policy file(s)..." "INFO"
}

foreach ($file in $importFiles) {
    try {
        $json = Get-Content $file.FullName -Raw | ConvertFrom-Json -AsHashtable
        if (-not $json) { throw "Invalid JSON" }

        $originalId   = $json.id
        $displayName  = $json.displayName

        $body = Clean-PolicyBody -Body $json
        $bodyJson = $body | ConvertTo-Json -Depth 20

        $existing = Find-Policy -Id $originalId -Name $displayName

        if ($existing) {
            $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($existing.id)"
                try {
                    Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $bodyJson -ContentType "application/json"
                    Write-Host "Updated: '$displayName' ($($existing.id))" -ForegroundColor Green
                    Write-Log "Updated: '$displayName' ($($existing.id))" "INFO"
                } catch {
                    Log-FullError -ErrorRecord $_ -Context "Failed to PATCH policy '$displayName' (ID: $($existing.id)) from file '$($file.Name)'" -RequestBody $bodyJson
                }
        } else {
            $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
                try {
                    $newPol = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $bodyJson -ContentType "application/json"
                    Write-Host "Created: '$displayName' (New ID: $($newPol.id))" -ForegroundColor Magenta
                    Write-Log "Created: '$displayName' (New ID: $($newPol.id))" "INFO"
                } catch {
                    Log-FullError -ErrorRecord $_ -Context "Failed to POST (create) policy '$displayName' from file '$($file.Name)'" -RequestBody $bodyJson
                }
        }
    }
        catch {
            Log-FullError -ErrorRecord $_ -Context "Top-level failure processing file '$($file.Name)'" -RequestBody $bodyJson
        }
}

Write-Host "All operations complete." -ForegroundColor Cyan
Write-Log "All operations complete." "INFO"
