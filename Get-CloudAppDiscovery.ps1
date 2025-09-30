<#
.SYNOPSIS
    Fetches discovered cloud apps and associated users from Microsoft Graph Cloud App Discovery API
    and exports the data to a CSV file.

.DESCRIPTION
    This script:
    - Authenticates to Microsoft Graph using client credentials (App ID + Secret).
    - Retrieves aggregated app details for a specified uploaded stream.
    - Fetches user details for each discovered app.
    - Exports the combined data to a CSV file.

.NOTES
    Last Updated: 30-Sep-2025
    Tested On: PowerShell 7.x, Microsoft.Graph PowerShell SDK
    API Endpoint: https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery

.REQUIREMENTS
    - Azure AD App Registration with:
        * Microsoft Graph API permissions:
            - CloudApp-Discovery.Read.All (Application)
        * Admin consent granted.
    - Client ID and Secret (or certificate/Managed Identity for secure auth).
    - PowerShell module: Microsoft.Graph.Authentication (v2.0.0 or later).


PARAMETERS
    $streamId    : The ID of the uploaded stream in Cloud App Discovery.
    $csvPath     : Path to export the CSV file.
    $period      : Duration for aggregated data (e.g., P30D for 30 days, P90D for 90 days).
    $tenantId    : Azure AD tenant ID.
    $clientId    : App registration client ID.
    $clientSecret: App registration client secret (store securely in Key Vault ideally).

.EXAMPLE
    .\Get-CloudAppDiscovery.ps1 `
        -streamId "<streamId>" `
        -csvPath "C:\Temp\CloudApps_Users.csv" `
        -period "P90D" `
        -tenantId "<tenant-id>" `
        -clientId "<client-id>" `
        -clientSecret "<client-secret>"

#>

# =========================
# Configuration
# =========================
$streamId = "<streamId>"  # Replace with your static stream ID
$csvPath = "C:\Temp\CloudApps_Users.csv"
$period = "P90D"  # Last 30 days; adjust as needed (e.g., P90D for 90 days)

# App Registration Details (replace with your values)
$tenantId = "<tenant-id>"
$clientId = "<client-id>"
$clientSecret = "<clientSecret>"  # Store securely in Key Vault ideally

# =========================
# Get Access Token
# =========================
Write-Host "Requesting access token..."
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$body = @{
    grant_type    = "client_credentials"
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = "https://graph.microsoft.com/.default"
}

try {
    $response = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop
    $accessToken = $response.access_token
    if (-not $accessToken) {
        Write-Error "Failed to retrieve access token."
        exit
    }
    Write-Host "Access token retrieved successfully."
}
catch {
    Write-Error "Error fetching token: $_"
    exit
}

# =========================
# Prepare Headers
# =========================
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# =========================
# Validate Stream ID
# =========================
if (-not $streamId) {
    Write-Error "Stream ID is empty or invalid."
    exit
}

# =========================
# Fetch Apps
# =========================
$results = @()
$appsUrl = "https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams/$streamId/aggregatedAppsDetails(period=duration'$period')?`$filter=userCount%20ge%201&`$select=id,displayName"

try {
    Write-Host "Fetching apps for stream: $streamId"
    $appsResponse = Invoke-RestMethod -Uri $appsUrl -Headers $headers -Method Get -ErrorAction Stop
    $apps = $appsResponse.value
    if (-not $apps) {
        Write-Warning "No apps found for stream $streamId."
    }
}
catch {
    Write-Error "Failed to fetch apps for stream $streamId : $_"
    exit
}

# =========================
# Loop through Apps and Fetch Users
# =========================
foreach ($app in $apps) {
    $appId = $app.id
    $appName = $app.displayName
    if (-not $appId -or -not $appName) {
        Write-Warning "Skipping app with missing ID or name."
        continue
    }
    Write-Host "Fetching users for app: $appName"

    $usersUrl = "https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams/$streamId/aggregatedAppsDetails(period=duration'$period')/$appId/users"
    try {
        $usersResponse = Invoke-RestMethod -Uri $usersUrl -Headers $headers -Method Get -ErrorAction Stop
        $users = $usersResponse.value
        if (-not $users) {
            Write-Warning "No users found for app $appName."
            continue
        }
    }
    catch {
        Write-Warning "Failed to fetch users for app $appName : $_"
        continue
    }

    foreach ($user in $users) {
        $results += [PSCustomObject]@{
            AppName          = $appName
            AppId            = $appId
            UserIdentifier   = $user.userIdentifier
        }
    }
}

# =========================
# Export to CSV
# =========================
if ($results.Count -eq 0) {
    Write-Warning "No data found to export."
}
else {
    try {
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "Export complete: $csvPath"
    }
    catch {
        Write-Error "Failed to export CSV to $csvPath : $_"
    }
}