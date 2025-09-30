<#
.SYNOPSIS
    Retrieves discovered cloud apps and associated users from Microsoft Graph Cloud App Discovery API
    and exports the data to a CSV file.

.DESCRIPTION
    This script:
      - Authenticates to Microsoft Graph using client credentials (App ID + Secret).
      - Retrieves aggregated app details for a specified uploaded stream and period.
      - Fetches discovered users per app.
      - Exports results to CSV.

.NOTES
    Author        : Mrunal Brahmbhatt
    Last Updated  : 30-Sep-2025
    Tested On     : PowerShell 7.x
    Endpoint      : https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery
    IMPORTANT     : Uses Microsoft Graph **beta** endpoint (schema may change).

.REQUIREMENTS
    - Azure AD App Registration with Microsoft Graph **Application** permission:
        CloudApp-Discovery.Read.All
      Admin consent must be granted.
    - Values for Tenant ID, Client ID, Client Secret (store secret securely).
    - Network egress to https://login.microsoftonline.com and https://graph.microsoft.com.

.PARAMETERS
    $streamId     : The ID of the uploaded stream in Cloud App Discovery.
    $csvPath      : Output CSV path.
    $period       : ISO8601 duration for aggregation (e.g., P30D, P90D).
    $tenantId     : Entra ID tenant ID (GUID).
    $clientId     : App registration Application (client) ID.
    $clientSecret : App registration client secret (avoid hardcoding in production).

.EXAMPLE
    .\Get-CloudAppDiscovery.ps1
#>

# =========================
# PARAMETERS (edit these)
# =========================
$streamId     = "<streamId>"                 # Replace with your static stream ID
$csvPath      = "C:\Temp\CloudApps_Users.csv"
$period       = "P90D"                       # e.g., P30D for 30 days, P90D for 90 days
# App Registration Details (replace with your values)
$tenantId     = "<tenant-id>"
$clientId     = "<client-id>"
$clientSecret = "<clientSecret>"             # Prefer Azure Key Vault in production

# =========================
# SCRIPT SETTINGS
# =========================
$GraphBase    = "https://graph.microsoft.com/beta"
$MaxRetries   = 5
$InitialDelay = 2   # seconds for backoff start

# =========================
# HELPER FUNCTIONS
# =========================

function Write-LogInfo {
    param([string]$Message)
    Write-Host "[INFO ] $Message" -ForegroundColor Cyan
}
function Write-LogWarn {
    param([string]$Message)
    Write-Warning "$Message"
}
function Write-LogError {
    param([string]$Message)
    Write-Error "$Message"
}

function Get-GraphAccessToken {
    param(
        [Parameter(Mandatory=$true)][string]$TenantId,
        [Parameter(Mandatory=$true)][string]$ClientId,
        [Parameter(Mandatory=$true)][string]$ClientSecret
    )
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }

    try {
        $resp = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($resp.access_token)) {
            throw "Token endpoint returned no access_token."
        }
        return $resp.access_token
    } catch {
        throw "Failed to acquire access token: $($_.Exception.Message)"
    }
}

function Invoke-GraphGet {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][hashtable]$Headers
    )
    # Single GET with retry (handles 429/5xx)
    $attempt = 0
    $delay   = $InitialDelay
    while ($true) {
        try {
            return Invoke-RestMethod -Method Get -Uri $Url -Headers $Headers -ErrorAction Stop
        } catch {
            $attempt++
            $statusCode = $_.Exception.Response.StatusCode.Value__ 2>$null
            $message = $_.Exception.Message
            if ($attempt -lt $MaxRetries -and ($statusCode -in 429,500,502,503,504)) {
                Write-LogWarn "GET failed (HTTP $statusCode). Retrying in $delay sec... ($attempt/$MaxRetries) :: $message"
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 60)
            } else {
                throw "Request failed for URL '$Url' after $attempt attempts. Last error: $message"
            }
        }
    }
}

function Invoke-GraphGetAll {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][hashtable]$Headers
    )
    $items = New-Object System.Collections.Generic.List[object]
    $next  = $Url

    while ($next) {
        $resp = Invoke-GraphGet -Url $next -Headers $Headers
        if ($resp.value) {
            $items.AddRange($resp.value)
        } elseif ($resp -and -not $resp.value) {
            # Some endpoints may return a single object
            $items.Add($resp)
        }

        $next = $resp.'@odata.nextLink'
    }
    return ,$items  # ensure array
}

# =========================
# VALIDATION
# =========================
if ([string]::IsNullOrWhiteSpace($streamId))    { Write-LogError "Stream ID is empty.";   exit 1 }
if ([string]::IsNullOrWhiteSpace($tenantId))    { Write-LogError "Tenant ID is empty.";   exit 1 }
if ([string]::IsNullOrWhiteSpace($clientId))    { Write-LogError "Client ID is empty.";   exit 1 }
if ([string]::IsNullOrWhiteSpace($clientSecret)){ Write-LogError "Client Secret is empty.";exit 1 }

# Ensure output directory exists
try {
    $outDir = Split-Path -Path $csvPath -Parent
    if (-not (Test-Path -LiteralPath $outDir)) {
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null
    }
} catch {
    Write-LogError "Failed to ensure output directory: $($_.Exception.Message)"
    exit 1
}

# =========================
# AUTHENTICATION
# =========================
Write-LogInfo "Requesting access token..."
try {
    $accessToken = Get-GraphAccessToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
    Write-LogInfo "Access token acquired."
} catch {
    Write-LogError $_
    exit 1
}

$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
    "Accept"        = "application/json"
}

# =========================
# FETCH APPS
# =========================
# NOTE: Avoid $select for fragile properties (e.g., 'riskRating' was removed). Rely on default fields.
# Keep filter to reduce noise.
$appsUrl = "$GraphBase/security/dataDiscovery/cloudAppDiscovery/uploadedStreams/$streamId/aggregatedAppsDetails(period=duration'$period')?`$filter=userCount%20ge%200"

Write-LogInfo "Fetching discovered apps for stream: $streamId (period=$period)"
try {
    $apps = Invoke-GraphGetAll -Url $appsUrl -Headers $headers
    $totalApps = $apps.Count
    if ($totalApps -eq 0) {
        Write-LogWarn "No apps found for stream '$streamId'."
        # Still export empty CSV to indicate run execution
        @() | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-LogInfo "Export complete (empty): $csvPath"
        exit 0
    }
    Write-LogInfo "Apps discovered: $totalApps"
} catch {
    Write-LogError "Failed to fetch apps: $_"
    exit 1
}

# =========================
# PROCESS APPS + USERS (with progress)
# =========================
$results  = New-Object System.Collections.Generic.List[object]
$counter  = 0
$outerId  = 1
$innerId  = 2

foreach ($app in $apps) {
    $counter++
    $appId   = $app.id
    $appName = $app.displayName
    $category = $null
    if ($app.PSObject.Properties.Name -contains 'category') { $category = $app.category }

    $pct = [math]::Round(($counter / $totalApps) * 100, 2)
    Write-Progress -Id $outerId -Activity "Processing Apps ($counter/$totalApps)" -Status "Fetching users for: $appName" -PercentComplete $pct

    if ([string]::IsNullOrWhiteSpace($appId)) {
        Write-LogWarn "Skipping app with missing ID."
        continue
    }

    # Users endpoint for this app
    $encodedAppId = [System.Net.WebUtility]::UrlEncode($appId)
    $usersUrl = "$GraphBase/security/dataDiscovery/cloudAppDiscovery/uploadedStreams/$streamId/aggregatedAppsDetails(period=duration'$period')/$encodedAppId/users"

    try {
        $users = Invoke-GraphGetAll -Url $usersUrl -Headers $headers
    } catch {
        Write-LogWarn "Failed to fetch users for app '$appName' ($appId): $_"
        continue
    }

    $userCount = $users.Count
    if ($userCount -eq 0) {
        Write-LogWarn "No users found for app '$appName'."
        continue
    }

    # Inner progress for users
    $idx = 0
    foreach ($user in $users) {
        $idx++
        $pctUsers = [math]::Round(($idx / [math]::Max($userCount,1)) * 100, 2)
        Write-Progress -Id $innerId -ParentId $outerId -Activity "Processing Users ($idx/$userCount)" -Status "$appName" -PercentComplete $pctUsers

        $results.Add([PSCustomObject]@{
            StreamId         = $streamId
            AppName          = $appName
            AppId            = $appId
            Category         = $category
            UserIdentifier   = $user.userIdentifier
        })
    }

    # Complete inner progress for this app
    Write-Progress -Id $innerId -Activity "Processing Users" -Completed
}

# Complete outer progress
Write-Progress -Id $outerId -Activity "Processing Apps" -Completed

# =========================
# EXPORT RESULTS
# =========================
try {
    if ($results.Count -eq 0) {
        Write-LogWarn "No data collected to export."
        # Export empty to maintain pipeline expectations
        @() | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
    } else {
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
        Write-LogInfo "Export complete: $csvPath"
    }
} catch {
    Write-LogError "Failed to export CSV to '$csvPath': $($_.Exception.Message)"
    exit 1
}

# =========================
# END
# =========================
Write-LogInfo "Done."
