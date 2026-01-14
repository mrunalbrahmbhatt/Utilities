# Azure Arc Status Check Script (with MDE & SQL Extension Checks)
# Compatible: Windows Server 2012 R2 to 2025
# Run as Administrator
#
# Usage: .\ValidateArcMDE.ps1 -ExpectedOrgId "<MDE_ORG_ID>" [-Region "<REGION>"]
# Example: .\ValidateArcMDE.ps1 -ExpectedOrgId "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
# Example: .\ValidateArcMDE.ps1 -ExpectedOrgId "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" -Region "US"

<#
.SYNOPSIS
    Azure Arc-Enabled Server Status Check with MDE validation.

.DESCRIPTION
    Comprehensive health check for Azure Arc-enabled servers including:
    - Arc Agent status, heartbeat, certificates, and dependent services
    - Microsoft Defender for Endpoint (MDE) onboarding and Organization ID
    - Azure Arc Extensions status
    - System disk space monitoring
    - Windows Setup status (ImageState)
    - Network connectivity validation

.PARAMETER ExpectedOrgId
    REQUIRED: The expected MDE Organization ID GUID for validation.
    If the detected OrgId doesn't match this value, a CRITICAL alert will be raised.

.PARAMETER Region
    OPTIONAL: Azure region for MDE connectivity checks. Default is "Australia".
    Valid values: Australia, US, Europe, UK, Canada, Asia
    This filters region-specific endpoints (blob storage, gateways, EDR).

.EXAMPLE
    .\ValidateArcMDE.ps1 -ExpectedOrgId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    
.EXAMPLE
    .\ValidateArcMDE.ps1 -ExpectedOrgId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -Region "US"

.NOTES
    MDE Connectivity Model:
    - This script uses URLs from Microsoft's Standard Connectivity model
    - Newer tenants may use Streamlined Connectivity (*.endpoint.security.microsoft.com)
    - Both models are supported; URLs overlap or redirect appropriately
    - For latest URL list, see: https://learn.microsoft.com/en-us/defender-endpoint/configure-proxy-internet
#>

param(
    [Parameter(
        Mandatory=$true,
        HelpMessage="Enter the expected MDE Organization ID GUID (example: 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX')"
    )]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedOrgId,
    
    [Parameter(
        Mandatory=$false,
        HelpMessage="Select your Azure region for MDE connectivity checks"
    )]
    [ValidateSet("Australia", "US", "Europe", "UK", "Canada", "Asia")]
    [string]$Region = "Australia",
    
    [Parameter(
        Mandatory=$false,
        HelpMessage="Skip Azure Arc agent validation checks"
    )]
    [switch]$SkipArc = $false,
    
    [Parameter(
        Mandatory=$false,
        HelpMessage="Force direct connectivity testing (bypass proxy) instead of auto-detecting proxy. By default, script will use proxy if detected."
    )]
    [switch]$ForceDirectConnection = $false,
    
    [Parameter(Mandatory=$false, HelpMessage="Explicit credentials for proxy authentication. Use when running as SYSTEM or service account. Example: Get-Credential")]
    [System.Management.Automation.PSCredential]
    $ProxyCredential
)

# Ensure Region has a valid value (defense against empty strings)
if ([string]::IsNullOrWhiteSpace($Region)) {
    $Region = "Australia"
    Write-Host "Region parameter was empty, defaulting to: Australia" -ForegroundColor Yellow
    Write-Host ""
}

# Function to detect execution context
function Get-ExecutionContext {
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userName = $currentUser.Name
        $isSystem = $currentUser.IsSystem
        
        $context = @{
            UserName = $userName
            IsSystem = $isSystem
            IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            SID = $currentUser.User.Value
        }
        
        # Determine account type
        if ($isSystem) {
            $context.AccountType = "SYSTEM"
            $context.SupportsDefaultCredentials = $false
            $context.Warning = "Running as SYSTEM - no user credentials available for proxy authentication"
        } elseif ($userName -match "NT AUTHORITY\\LOCAL SERVICE" -or $userName -match "NT AUTHORITY\\NETWORK SERVICE") {
            $context.AccountType = "Service Account"
            $context.SupportsDefaultCredentials = $false
            $context.Warning = "Running as service account - limited credentials for proxy authentication"
        } elseif ($userName -match "\\\$") {
            # Machine account
            $context.AccountType = "Machine Account"
            $context.SupportsDefaultCredentials = $false
            $context.Warning = "Running as machine account - may not have proxy credentials"
        } else {
            $context.AccountType = "User Account"
            $context.SupportsDefaultCredentials = $true
            $context.Warning = $null
        }
        
        return $context
    } catch {
        return @{
            UserName = "Unknown"
            IsSystem = $false
            IsElevated = $false
            AccountType = "Unknown"
            SupportsDefaultCredentials = $true
            Warning = $null
            Error = $_.Exception.Message
        }
    }
}

# Function to detect proxy configuration
function Get-ProxyConfiguration {
    try {
        $proxyInfo = @{
            ProxyEnabled = $false
            ProxyServer = $null
            ProxyAutoConfigURL = $null
            ProxyBypass = $null
            Method = "None"
            AutoDetect = $false
            WPADDetected = $false
            DetectionSource = @()  # Track where settings were found
        }
        
        # Check Machine-level (HKLM) Internet Settings FIRST (takes precedence on servers)
        $regPathMachine = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
        if (Test-Path $regPathMachine) {
            $proxyEnable = Get-ItemProperty -Path $regPathMachine -Name ProxyEnable -ErrorAction SilentlyContinue
            $proxyServer = Get-ItemProperty -Path $regPathMachine -Name ProxyServer -ErrorAction SilentlyContinue
            $autoConfigURL = Get-ItemProperty -Path $regPathMachine -Name AutoConfigURL -ErrorAction SilentlyContinue
            $proxyOverride = Get-ItemProperty -Path $regPathMachine -Name ProxyOverride -ErrorAction SilentlyContinue
            
            if ($proxyEnable.ProxyEnable -eq 1 -and $proxyServer.ProxyServer) {
                $proxyInfo.ProxyEnabled = $true
                $proxyInfo.ProxyServer = $proxyServer.ProxyServer
                $proxyInfo.Method = "Machine-level Proxy (HKLM)"
                $proxyInfo.DetectionSource += "HKLM"
                if ($proxyOverride.ProxyOverride) {
                    $proxyInfo.ProxyBypass = $proxyOverride.ProxyOverride
                }
            }
            
            if ($autoConfigURL.AutoConfigURL) {
                $proxyInfo.ProxyEnabled = $true
                $proxyInfo.ProxyAutoConfigURL = $autoConfigURL.AutoConfigURL
                if ($proxyInfo.Method -eq "Machine-level Proxy (HKLM)") {
                    $proxyInfo.Method = "Machine-level Proxy + PAC (HKLM)"
                } else {
                    $proxyInfo.Method = "Machine-level PAC (HKLM)"
                    $proxyInfo.DetectionSource += "HKLM"
                }
            }
        }
        
        # Check Group Policy proxy settings
        $regPathGP = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
        if (Test-Path $regPathGP) {
            $proxyEnableGP = Get-ItemProperty -Path $regPathGP -Name ProxyEnable -ErrorAction SilentlyContinue
            $proxyServerGP = Get-ItemProperty -Path $regPathGP -Name ProxyServer -ErrorAction SilentlyContinue
            $autoConfigURLGP = Get-ItemProperty -Path $regPathGP -Name AutoConfigURL -ErrorAction SilentlyContinue
            
            if ($proxyEnableGP.ProxyEnable -eq 1 -and $proxyServerGP.ProxyServer) {
                $proxyInfo.ProxyEnabled = $true
                $proxyInfo.ProxyServer = $proxyServerGP.ProxyServer
                $proxyInfo.Method = "Group Policy Proxy"
                $proxyInfo.DetectionSource += "Group Policy"
            }
            
            if ($autoConfigURLGP.AutoConfigURL) {
                $proxyInfo.ProxyEnabled = $true
                $proxyInfo.ProxyAutoConfigURL = $autoConfigURLGP.AutoConfigURL
                if ($proxyInfo.Method -match "Group Policy") {
                    $proxyInfo.Method = "Group Policy Proxy + PAC"
                } else {
                    $proxyInfo.Method = "Group Policy PAC"
                    $proxyInfo.DetectionSource += "Group Policy"
                }
            }
        }
        
        # Check User-level (HKCU) Internet Settings (lower priority)
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        if (Test-Path $regPath) {
            $proxyEnable = Get-ItemProperty -Path $regPath -Name ProxyEnable -ErrorAction SilentlyContinue
            $proxyServer = Get-ItemProperty -Path $regPath -Name ProxyServer -ErrorAction SilentlyContinue
            $autoConfigURL = Get-ItemProperty -Path $regPath -Name AutoConfigURL -ErrorAction SilentlyContinue
            $proxyOverride = Get-ItemProperty -Path $regPath -Name ProxyOverride -ErrorAction SilentlyContinue
            $autoDetect = Get-ItemProperty -Path $regPath -Name AutoDetect -ErrorAction SilentlyContinue
            
            # Check for WPAD (Automatically detect settings) - User level
            if ($autoDetect.AutoDetect -eq 1) {
                $proxyInfo.ProxyEnabled = $true
                $proxyInfo.AutoDetect = $true
                $proxyInfo.WPADDetected = $true
                if ($proxyInfo.Method -eq "None") {
                    $proxyInfo.Method = "WPAD (Automatic Discovery - User)"
                    $proxyInfo.DetectionSource += "HKCU-WPAD"
                }
            }
            
            # Only use HKCU proxy if not already set by HKLM/GP
            if ($proxyEnable.ProxyEnable -eq 1 -and $proxyServer.ProxyServer -and $proxyInfo.Method -notmatch "Machine-level|Group Policy") {
                $proxyInfo.ProxyEnabled = $true
                $proxyInfo.ProxyServer = $proxyServer.ProxyServer
                if ($proxyInfo.Method -match "WPAD") {
                    $proxyInfo.Method = "WPAD + Manual Proxy (User)"
                } else {
                    $proxyInfo.Method = "User-level Proxy (HKCU)"
                    $proxyInfo.DetectionSource += "HKCU"
                }
                if ($proxyOverride.ProxyOverride -and -not $proxyInfo.ProxyBypass) {
                    $proxyInfo.ProxyBypass = $proxyOverride.ProxyOverride
                }
            }
            
            if ($autoConfigURL.AutoConfigURL -and $proxyInfo.Method -notmatch "Machine-level|Group Policy") {
                $proxyInfo.ProxyEnabled = $true
                $proxyInfo.ProxyAutoConfigURL = $autoConfigURL.AutoConfigURL
                if ($proxyInfo.Method -match "WPAD") {
                    $proxyInfo.Method = "WPAD + PAC (User)"
                } elseif ($proxyInfo.Method -match "Manual Proxy") {
                    $proxyInfo.Method = "User Proxy + PAC (HKCU)"
                } else {
                    $proxyInfo.Method = "User-level PAC (HKCU)"
                    $proxyInfo.DetectionSource += "HKCU"
                }
            }
        }
        
        # Check WinHTTP proxy settings (system-wide)
        try {
            $winHttpProxy = netsh winhttp show proxy 2>$null
            if ($winHttpProxy -match "Direct access \(no proxy server\)") {
                # WinHTTP is set to direct - don't override user settings detection
            } elseif ($winHttpProxy -match "Proxy Server\(s\)\s*:\s*(.+)") {
                if (-not $proxyInfo.ProxyEnabled) {
                    $proxyInfo.ProxyEnabled = $true
                    $proxyInfo.ProxyServer = $matches[1].Trim()
                    $proxyInfo.Method = "WinHTTP System Proxy"
                    $proxyInfo.DetectionSource += "WinHTTP"
                }
            } elseif ($winHttpProxy -match "AutoConfigURL\s*:\s*(.+)") {
                if (-not $proxyInfo.ProxyEnabled) {
                    $proxyInfo.ProxyEnabled = $true
                    $proxyInfo.ProxyAutoConfigURL = $matches[1].Trim()
                    $proxyInfo.Method = "WinHTTP PAC"
                    $proxyInfo.DetectionSource += "WinHTTP"
                }
            }
            if ($winHttpProxy -match "Bypass List\s*:\s*(.+)") {
                if (-not $proxyInfo.ProxyBypass) {
                    $proxyInfo.ProxyBypass = $matches[1].Trim()
                }
            }
        } catch { }
        
        # Additional WPAD detection - check Connections registry key
        try {
            $connectionsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
            if (Test-Path $connectionsPath) {
                $defaultConnection = Get-ItemProperty -Path $connectionsPath -Name "DefaultConnectionSettings" -ErrorAction SilentlyContinue
                if ($defaultConnection.DefaultConnectionSettings) {
                    # Byte 8 (index 8) contains proxy configuration flags
                    # 0x01 = Manual proxy, 0x02 = PAC, 0x04 = Auto-detect (WPAD), 0x08 = Direct
                    $flags = $defaultConnection.DefaultConnectionSettings[8]
                    if ($flags -band 0x04) {
                        $proxyInfo.AutoDetect = $true
                        $proxyInfo.WPADDetected = $true
                        if (-not $proxyInfo.ProxyEnabled -or $proxyInfo.Method -eq "None") {
                            $proxyInfo.ProxyEnabled = $true
                            $proxyInfo.Method = "WPAD (Automatic Discovery)"
                        }
                    }
                }
            }
        } catch { }
        
        return $proxyInfo
    } catch {
        return @{
            ProxyEnabled = $false
            ProxyServer = $null
            ProxyAutoConfigURL = $null
            ProxyBypass = $null
            Method = "Detection Failed"
            AutoDetect = $false
            WPADDetected = $false
            DetectionSource = @()
            Error = $_.Exception.Message
        }
    }
}

# Function to detect Private Link configuration
function Get-PrivateLinkConfiguration {
    try {
        $privateLinkInfo = @{
            ArcPrivateLinkDetected = $false
            PrivateEndpoints = @()
            PrivateIPs = @()
        }
        
        # Check for Arc Private Link endpoints by resolving DNS
        $arcEndpoints = @(
            "ae.his.arc.azure.com",
            "gbl.his.arc.azure.com",
            "agentserviceapi.guestconfiguration.azure.com"
        )
        
        foreach ($endpoint in $arcEndpoints) {
            try {
                $dnsResult = Resolve-DnsName $endpoint -ErrorAction SilentlyContinue
                if ($dnsResult) {
                    foreach ($record in $dnsResult) {
                        if ($record.IPAddress) {
                            # Check if IP is in private range (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
                            $ip = $record.IPAddress
                            if ($ip -match "^10\." -or $ip -match "^172\.(1[6-9]|2[0-9]|3[0-1])\." -or $ip -match "^192\.168\." -or $ip -match "^100\." -or $ip -match "^fd") {
                                $privateLinkInfo.ArcPrivateLinkDetected = $true
                                $privateLinkInfo.PrivateEndpoints += $endpoint
                                $privateLinkInfo.PrivateIPs += $ip
                            }
                        }
                    }
                }
            } catch { }
        }
        
        return $privateLinkInfo
    } catch {
        return @{
            ArcPrivateLinkDetected = $false
            PrivateEndpoints = @()
            PrivateIPs = @()
            Error = $_.Exception.Message
        }
    }
}

# Function to detect execution context
function Get-ExecutionContext {
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userName = $currentUser.Name
        $isSystem = $currentUser.IsSystem
        
        $context = @{
            UserName = $userName
            IsSystem = $isSystem
            IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            SID = $currentUser.User.Value
        }
        
        # Determine account type
        if ($isSystem) {
            $context.AccountType = "SYSTEM"
            $context.SupportsDefaultCredentials = $false
            $context.Warning = "Running as SYSTEM - no user credentials available for proxy authentication"
        } elseif ($userName -match "NT AUTHORITY\\LOCAL SERVICE" -or $userName -match "NT AUTHORITY\\NETWORK SERVICE") {
            $context.AccountType = "Service Account"
            $context.SupportsDefaultCredentials = $false
            $context.Warning = "Running as service account - limited credentials for proxy authentication"
        } elseif ($userName -match "\\$") {
            # Machine account
            $context.AccountType = "Machine Account"
            $context.SupportsDefaultCredentials = $false
            $context.Warning = "Running as machine account - may not have proxy credentials"
        } else {
            $context.AccountType = "User Account"
            $context.SupportsDefaultCredentials = $true
            $context.Warning = $null
        }
        
        return $context
    } catch {
        return @{
            UserName = "Unknown"
            IsSystem = $false
            IsElevated = $false
            AccountType = "Unknown"
            SupportsDefaultCredentials = $true
            Warning = $null
            Error = $_.Exception.Message
        }
    }
}

# Function to test if proxy requires authentication
function Test-ProxyAuthentication {
    param(
        [Parameter(Mandatory=$false)]
        [string]$TestUrl = "https://www.microsoft.com",
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential = $null
    )
    
    try {
        # Test 1: Try without credentials
        try {
            $response = Invoke-WebRequest -Uri $TestUrl -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            return @{
                RequiresAuth = $false
                AuthType = "None"
                TestPassed = $true
                Message = "Proxy accessible without authentication"
            }
        } catch {
            $error1 = $_
            
            # Check if error is 407 (Proxy Authentication Required)
            if ($error1.Exception.Response.StatusCode.value__ -eq 407) {
                # Test 2: Try with credentials (explicit or default)
                try {
                    if ($Credential) {
                        # Use provided credentials
                        $response = Invoke-WebRequest -Uri $TestUrl -Method Head -TimeoutSec 5 -UseBasicParsing -Credential $Credential -ErrorAction Stop
                        return @{
                            RequiresAuth = $true
                            AuthType = "Explicit Credentials (Working)"
                            TestPassed = $true
                            Message = "Proxy requires authentication - Provided credentials working"
                        }
                    } else {
                        # Use default credentials
                        $response = Invoke-WebRequest -Uri $TestUrl -Method Head -TimeoutSec 5 -UseBasicParsing -UseDefaultCredentials -ErrorAction Stop
                        return @{
                            RequiresAuth = $true
                            AuthType = "Windows/NTLM (Working)"
                            TestPassed = $true
                            Message = "Proxy requires authentication - Windows credentials working"
                        }
                    }
                } catch {
                    return @{
                        RequiresAuth = $true
                        AuthType = if ($Credential) { "Explicit Credentials (Failed)" } else { "Windows/NTLM (Failed)" }
                        TestPassed = $false
                        Message = "Proxy requires authentication but credentials failed"
                        Error = $_.Exception.Message
                    }
                }
            } else {
                # Different error (timeout, DNS, etc.)
                return @{
                    RequiresAuth = "Unknown"
                    AuthType = "N/A"
                    TestPassed = $false
                    Message = "Connectivity test failed (not auth-related)"
                    Error = $error1.Exception.Message
                }
            }
        }
    } catch {
        return @{
            RequiresAuth = "Unknown"
            AuthType = "N/A"
            TestPassed = $false
            Message = "Test failed"
            Error = $_.Exception.Message
        }
    }
}

# Function to get actual proxy that will be used for a URL
function Get-ActualProxyForUrl {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url
    )
    
    try {
        $uri = [System.Uri]$Url
        $request = [System.Net.WebRequest]::Create($uri)
        
        # Get the proxy that will be used
        if ($request.Proxy -ne $null) {
            $proxyUri = $request.Proxy.GetProxy($uri)
            
            # If proxy URI equals the original URI, it means direct connection
            if ($proxyUri.AbsoluteUri -eq $uri.AbsoluteUri) {
                return @{
                    UsesProxy = $false
                    ProxyAddress = "Direct"
                    RoutingMethod = "Direct Connection"
                }
            } else {
                return @{
                    UsesProxy = $true
                    ProxyAddress = $proxyUri.AbsoluteUri
                    ProxyHost = $proxyUri.Host
                    ProxyPort = $proxyUri.Port
                    RoutingMethod = "Via Proxy"
                }
            }
        } else {
            return @{
                UsesProxy = $false
                ProxyAddress = "Direct"
                RoutingMethod = "Direct Connection (No Proxy Configured)"
            }
        }
    } catch {
        return @{
            UsesProxy = $false
            ProxyAddress = "Unknown"
            RoutingMethod = "Unable to determine"
            Error = $_.Exception.Message
        }
    }
}

# Function to test connectivity with proxy support and automatic fallback
function Test-ConnectivityWithProxy {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,
        
        [Parameter(Mandatory=$false)]
        [bool]$UseProxyMethod = $false,
        
        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 10,
        
        [Parameter(Mandatory=$false)]
        [bool]$TryProxyFirst = $true,
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$ProxyCredential = $null
    )
    
    $uri = [System.Uri]$Url
    
    # If proxy method requested and TryProxyFirst is enabled, try proxy first
    if ($UseProxyMethod -and $TryProxyFirst) {
        # Store original proxy settings
        $originalProxy = [System.Net.WebRequest]::DefaultWebProxy
        $proxyError = $null
        $proxyErrorDetails = ""
        
        try {
            # Attempt 1: Use Invoke-WebRequest with system proxy (WPAD, PAC, manual)
            # Try GET first (more compatible than HEAD), fallback to HEAD if needed
            # Use credentials (explicit or default) for proxy authentication
            try {
                if ($ProxyCredential) {
                    $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec $TimeoutSeconds -UseBasicParsing -Credential $ProxyCredential -ErrorAction Stop
                } else {
                    $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec $TimeoutSeconds -UseBasicParsing -UseDefaultCredentials -ErrorAction Stop
                }
            } catch {
                # Some servers reject GET, try HEAD
                if ($ProxyCredential) {
                    $response = Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec $TimeoutSeconds -UseBasicParsing -Credential $ProxyCredential -ErrorAction Stop
                } else {
                    $response = Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec $TimeoutSeconds -UseBasicParsing -UseDefaultCredentials -ErrorAction Stop
                }
            }
            return @{ Success = $true; Method = "Web Request (Proxy-aware)"; StatusCode = $response.StatusCode; TriedFallback = $false }
        } catch {
            $proxyError = $_.Exception.Message
            # Extract more details from exception
            if ($_.Exception.InnerException) {
                $proxyErrorDetails = $_.Exception.InnerException.Message
            }
            if ($_.Exception.Response) {
                $proxyErrorDetails += " [HTTP $($_.Exception.Response.StatusCode.value__)]"  
            }
            
            # Attempt 2: Proxy failed, try Invoke-WebRequest with NO PROXY (direct connection)
            try {
                # Temporarily disable proxy for this request
                $noProxy = New-Object System.Net.WebProxy
                [System.Net.WebRequest]::DefaultWebProxy = $noProxy
                
                # Try GET first, fallback to HEAD
                try {
                    $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec $TimeoutSeconds -UseBasicParsing -Proxy $noProxy -UseDefaultCredentials -ErrorAction Stop
                } catch {
                    $response = Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec $TimeoutSeconds -UseBasicParsing -Proxy $noProxy -UseDefaultCredentials -ErrorAction Stop
                }
                
                # Restore original proxy
                [System.Net.WebRequest]::DefaultWebProxy = $originalProxy
                
                return @{ 
                    Success = $true
                    Method = "Web Request (Direct - Fallback from Proxy)"
                    StatusCode = $response.StatusCode
                    TriedFallback = $true
                    ProxyError = if ($proxyErrorDetails) { $proxyErrorDetails } else { $proxyError }
                }
            } catch {
                # Restore original proxy
                [System.Net.WebRequest]::DefaultWebProxy = $originalProxy
                
                $directError = $_.Exception.Message
                if ($_.Exception.InnerException) {
                    $directError = $_.Exception.InnerException.Message
                }
                
                return @{ 
                    Success = $false
                    Method = "Web Request (Both Proxy and Direct Failed)"
                    StatusCode = 0
                    TriedFallback = $true
                    Error = "Proxy: $($proxyError.Substring(0, [Math]::Min(100, $proxyError.Length))) | Direct: $($directError.Substring(0, [Math]::Min(100, $directError.Length)))"
                    ProxyErrorFull = if ($proxyErrorDetails) { $proxyErrorDetails } else { $proxyError }
                    DirectErrorFull = $directError
                }
            }
        }
    } elseif ($UseProxyMethod) {
        # Proxy method requested but no fallback
        try {
            # Try GET first, fallback to HEAD
            # Use default credentials for proxy authentication
            try {
                $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec $TimeoutSeconds -UseBasicParsing -UseDefaultCredentials -ErrorAction Stop
            } catch {
                $response = Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec $TimeoutSeconds -UseBasicParsing -UseDefaultCredentials -ErrorAction Stop
            }
            return @{ Success = $true; Method = "Web Request (Proxy-aware)"; StatusCode = $response.StatusCode; TriedFallback = $false }
        } catch {
            $errorMsg = $_.Exception.Message
            if ($_.Exception.InnerException) {
                $errorMsg = $_.Exception.InnerException.Message
            }
            return @{ Success = $false; Method = "Web Request (Proxy-aware)"; StatusCode = 0; TriedFallback = $false; Error = $errorMsg }
        }
    } else {
        # Direct connection only (bypass proxy completely)
        $originalProxy = [System.Net.WebRequest]::DefaultWebProxy
        try {
            # Disable proxy for direct connection
            $noProxy = New-Object System.Net.WebProxy
            [System.Net.WebRequest]::DefaultWebProxy = $noProxy
            
            # Try GET first, fallback to HEAD
            try {
                $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec $TimeoutSeconds -UseBasicParsing -Proxy $noProxy -UseDefaultCredentials -ErrorAction Stop
            } catch {
                $response = Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec $TimeoutSeconds -UseBasicParsing -Proxy $noProxy -UseDefaultCredentials -ErrorAction Stop
            }
            
            # Restore original proxy
            [System.Net.WebRequest]::DefaultWebProxy = $originalProxy
            
            return @{ Success = $true; Method = "Web Request (Direct)"; StatusCode = $response.StatusCode; TriedFallback = $false }
        } catch {
            # Restore original proxy
            [System.Net.WebRequest]::DefaultWebProxy = $originalProxy
            
            $errorMsg = $_.Exception.Message
            if ($_.Exception.InnerException) {
                $errorMsg = $_.Exception.InnerException.Message
            }
            return @{ Success = $false; Method = "Web Request (Direct)"; StatusCode = 0; TriedFallback = $false; Error = $errorMsg }
        }
    }
}

# Function to convert Windows FILETIME to readable DateTime
function Convert-FileTimeToDateTime {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FileTime
    )
    
    try {
        # Convert string to Int64
        $fileTimeValue = [Int64]$FileTime
        
        # Convert FILETIME (100-nanosecond intervals since 1601-01-01) to DateTime
        $dateTime = [DateTime]::FromFileTime($fileTimeValue)
        
        return $dateTime
    } catch {
        return $null
    }
}

# Detect proxy configuration
$proxyConfig = Get-ProxyConfiguration

# Detect Private Link configuration
$privateLinkConfig = Get-PrivateLinkConfiguration

# Detect execution context (User/SYSTEM/Service Account)
$scriptExecutionContext = Get-ExecutionContext

# Auto-determine if we should use proxy-aware testing
$UseProxy = $false
if ($ForceDirectConnection) {
    $UseProxy = $false
    $connectivityApproach = "Direct Connection (Forced)"
} elseif ($proxyConfig.ProxyEnabled) {
    $UseProxy = $true
    $connectivityApproach = "Proxy-First with Direct Fallback (Auto-detected)"
} else {
    $UseProxy = $false
    $connectivityApproach = "Direct Connection (No Proxy Detected)"
}

Write-Host "=== Azure Arc-Enabled Server Status Check ===" -ForegroundColor Cyan
Write-Host "Server: $($env:COMPUTERNAME)" -ForegroundColor Yellow
Write-Host "Current Date: $(Get-Date)" -ForegroundColor Yellow
Write-Host "Region: $Region" -ForegroundColor Yellow
Write-Host "Execution Context: $($scriptExecutionContext.AccountType) ($($scriptExecutionContext.UserName))" -ForegroundColor $(if ($scriptExecutionContext.AccountType -eq "User Account") { "Green" } else { "Yellow" })
if ($SkipArc) {
    Write-Host "Arc Validation: SKIPPED" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     PROXY DETECTION & CONNECTIVITY APPROACH       ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($proxyConfig.ProxyEnabled) {
    Write-Host "Proxy Status: DETECTED" -ForegroundColor Green
    Write-Host "  Detection Method: $($proxyConfig.Method)" -ForegroundColor Gray
    if ($proxyConfig.DetectionSource -and $proxyConfig.DetectionSource.Count -gt 0) {
        Write-Host "  Detection Source: $($proxyConfig.DetectionSource -join ', ')" -ForegroundColor Gray
    }
    
    # Test proxy authentication
    Write-Host ""
    Write-Host "  Testing proxy authentication..." -ForegroundColor Gray
    
    # Check if running as SYSTEM/Service Account and warn
    if (-not $scriptExecutionContext.SupportsDefaultCredentials) {
        Write-Host "  ⚠️  WARNING: Running as $($scriptExecutionContext.AccountType)" -ForegroundColor Yellow
        Write-Host "     $($scriptExecutionContext.Warning)" -ForegroundColor Yellow
        if ($ProxyCredential) {
            Write-Host "     ✅ Explicit credentials provided via -ProxyCredential" -ForegroundColor Green
            $proxyAuthTest = Test-ProxyAuthentication -TestUrl "https://www.microsoft.com" -Credential $ProxyCredential
        } else {
            Write-Host "     💡 Use -ProxyCredential parameter to provide explicit credentials" -ForegroundColor Cyan
            Write-Host "        Example: -ProxyCredential (Get-Credential)" -ForegroundColor Gray
            $proxyAuthTest = Test-ProxyAuthentication -TestUrl "https://www.microsoft.com"
        }
    } else {
        # Running as user account - use provided credentials or default
        if ($ProxyCredential) {
            $proxyAuthTest = Test-ProxyAuthentication -TestUrl "https://www.microsoft.com" -Credential $ProxyCredential
        } else {
            $proxyAuthTest = Test-ProxyAuthentication -TestUrl "https://www.microsoft.com"
        }
    }
    
    if ($proxyAuthTest.TestPassed) {
        Write-Host "  Proxy Authentication: " -NoNewline -ForegroundColor Gray
        Write-Host "$($proxyAuthTest.AuthType)" -ForegroundColor Green
        if ($proxyAuthTest.RequiresAuth) {
            if ($ProxyCredential) {
                Write-Host "    └─ Using provided credentials for proxy" -ForegroundColor Cyan
            } else {
                Write-Host "    └─ Using Windows credentials (current user context)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "    └─ No authentication required" -ForegroundColor Cyan
        }
    } else {
        Write-Host "  Proxy Authentication: " -NoNewline -ForegroundColor Gray
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "    └─ $($proxyAuthTest.Message)" -ForegroundColor Yellow
        if ($proxyAuthTest.Error) {
            Write-Host "    └─ Error: $($proxyAuthTest.Error)" -ForegroundColor DarkGray
        }
        if (-not $scriptExecutionContext.SupportsDefaultCredentials -and -not $ProxyCredential) {
            Write-Host "    └─ Consider using -ProxyCredential parameter" -ForegroundColor Yellow
        }
    }
    
    if ($proxyConfig.WPADDetected) {
        Write-Host ""
        Write-Host "  WPAD (Web Proxy Auto-Discovery): ENABLED" -ForegroundColor Cyan
        Write-Host "    ├─ Automatically detect settings: YES" -ForegroundColor Gray
        Write-Host "    ├─ Discovery Method: DNS/DHCP query for wpad.dat" -ForegroundColor Gray
        Write-Host "    └─ Proxy will be resolved automatically at runtime" -ForegroundColor Gray
    }
    
    if ($proxyConfig.ProxyServer) {
        Write-Host "  Manual Proxy Server: $($proxyConfig.ProxyServer)" -ForegroundColor Gray
    }
    
    if ($proxyConfig.ProxyAutoConfigURL) {
        Write-Host "  PAC File URL: $($proxyConfig.ProxyAutoConfigURL)" -ForegroundColor Gray
    }
    
    if ($proxyConfig.ProxyBypass) {
        Write-Host "  Bypass List: $($proxyConfig.ProxyBypass)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Connectivity Strategy: $connectivityApproach" -ForegroundColor Yellow
    Write-Host "  1. Try proxy-aware connection first (Invoke-WebRequest)" -ForegroundColor Gray
    Write-Host "     └─ Will use detected proxy (WPAD/PAC/Manual)" -ForegroundColor Gray
    if ($ProxyCredential) {
        Write-Host "     └─ Credentials: Using provided credentials (-ProxyCredential)" -ForegroundColor Cyan
    } else {
        Write-Host "     └─ Credentials: Using Windows Authentication (UseDefaultCredentials)" -ForegroundColor Cyan
        if (-not $scriptExecutionContext.SupportsDefaultCredentials) {
            Write-Host "        ⚠️  Running as $($scriptExecutionContext.AccountType) - may need -ProxyCredential" -ForegroundColor Yellow
        }
    }
    Write-Host "  2. If proxy fails, automatically fallback to direct connection" -ForegroundColor Gray
    Write-Host "     └─ Uses Invoke-WebRequest with proxy disabled" -ForegroundColor Gray
    
    if ($ForceDirectConnection) {
        Write-Host ""
        Write-Host "  NOTE: -ForceDirectConnection specified, bypassing proxy" -ForegroundColor Red
    }
} else {
    Write-Host "Proxy Status: NOT DETECTED" -ForegroundColor Yellow
    Write-Host "  WPAD: Not enabled" -ForegroundColor Gray
    Write-Host "  Manual Proxy: Not configured" -ForegroundColor Gray
    Write-Host "  PAC File: Not configured" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Connectivity Strategy: $connectivityApproach" -ForegroundColor Yellow
    Write-Host "  └─ Using Invoke-WebRequest with direct connection (no proxy)" -ForegroundColor Gray
    Write-Host "  └─ Credentials: Using Windows Authentication if needed" -ForegroundColor Cyan
}

# Check for Private Link configuration
Write-Host ""
if ($privateLinkConfig.ArcPrivateLinkDetected) {
    Write-Host "╔═══════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║     ⚠️  PRIVATE LINK DETECTED                     ║" -ForegroundColor Yellow
    Write-Host "╚═══════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Azure Arc Private Link: ENABLED" -ForegroundColor Yellow
    Write-Host "  Private Endpoints Found: $($privateLinkConfig.PrivateEndpoints.Count)" -ForegroundColor Gray
    foreach ($i in 0..($privateLinkConfig.PrivateEndpoints.Count - 1)) {
        if ($i -lt $privateLinkConfig.PrivateIPs.Count) {
            Write-Host "    • $($privateLinkConfig.PrivateEndpoints[$i]) → $($privateLinkConfig.PrivateIPs[$i])" -ForegroundColor Gray
        }
    }
    Write-Host ""
    Write-Host "⚠️  IMPORTANT: MDE Connectivity Impact" -ForegroundColor Yellow
    Write-Host "  ────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "  • Azure Arc uses Private Link (working via private IPs)" -ForegroundColor Cyan
    Write-Host "  • MDE tests use PUBLIC endpoints" -ForegroundColor Red
    Write-Host "  • If firewall blocks public internet, MDE tests will FAIL" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Solutions:" -ForegroundColor Yellow
    Write-Host "    1. Configure MDE to use Private Link endpoints" -ForegroundColor Green
    Write-Host "       https://learn.microsoft.com/en-us/defender-endpoint/configure-private-link" -ForegroundColor Gray
    Write-Host "    2. Add firewall rules for MDE public endpoints" -ForegroundColor Green
    Write-Host "       (See connectivity check results below)" -ForegroundColor Gray
    Write-Host ""
}

Write-Host ""
Write-Host "Collecting status information..." -ForegroundColor Cyan
Write-Host ""

# Initialize status collection
$status = @{
    ServerName = $env:COMPUTERNAME
    CheckDate = Get-Date
    ArcAgent = @{}
    Certificates = @()
    MDE = @{}
    Extensions = @()
    Connectivity = ""
    PrivateLink = $privateLinkConfig
}

$azcmagentPath = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
$certsPath = "$env:ProgramData\AzureConnectedMachineAgent\Certs"

# Section 1: Collect Azure Arc Agent Info
if (-not $SkipArc -and (Test-Path $azcmagentPath)) {
    $status.ArcAgent.Installed = $true
    
    $showOutput = & $azcmagentPath show 2>$null
    $status.ArcAgent.RawOutput = $showOutput
    
    # Parse Agent Status
    $statusLine = $showOutput | Select-String "Agent Status"
    if ($statusLine) {
        $agentStatus = $statusLine.ToString().Trim() -replace 'Agent Status\s*:\s*',''
        $status.ArcAgent.Status = $agentStatus
    } else {
        $status.ArcAgent.Status = "Unknown"
    }
    
    # Parse Agent Last Heartbeat
    $heartbeatLine = $showOutput | Select-String "Agent Last Heartbeat"
    if ($heartbeatLine) {
        $heartbeatStr = $heartbeatLine.ToString().Trim() -replace 'Agent Last Heartbeat\s*:\s*',''
        $status.ArcAgent.LastHeartbeat = $heartbeatStr
        try {
            $heartbeatTime = [DateTime]::Parse($heartbeatStr)
            $hoursSinceHeartbeat = ((Get-Date) - $heartbeatTime).TotalHours
            $status.ArcAgent.HoursSinceHeartbeat = [Math]::Round($hoursSinceHeartbeat, 1)
        } catch {
            $status.ArcAgent.HoursSinceHeartbeat = $null
        }
    }
    
    # Parse Agent Error Code
    $errorCodeLine = $showOutput | Select-String "Agent Error Code"
    if ($errorCodeLine) {
        $errorCode = $errorCodeLine.ToString().Trim() -replace 'Agent Error Code\s*:\s*',''
        if ($errorCode -and $errorCode -ne "") {
            $status.ArcAgent.ErrorCode = $errorCode
        }
    }
    
    # Parse Agent Error Details
    $errorDetailsLine = $showOutput | Select-String "Agent Error Details"
    if ($errorDetailsLine) {
        $errorDetails = $errorDetailsLine.ToString().Trim() -replace 'Agent Error Details\s*:\s*',''
        if ($errorDetails -and $errorDetails -ne "") {
            $status.ArcAgent.ErrorDetails = $errorDetails
        }
    }
    
    # Parse Agent Error Timestamp
    $errorTimestampLine = $showOutput | Select-String "Agent Error Timestamp"
    if ($errorTimestampLine) {
        $errorTimestamp = $errorTimestampLine.ToString().Trim() -replace 'Agent Error Timestamp\s*:\s*',''
        if ($errorTimestamp -and $errorTimestamp -ne "") {
            $status.ArcAgent.ErrorTimestamp = $errorTimestamp
        }
    }
    
    # Parse Dependent Services from azcmagent show output
    $status.ArcAgent.DependentServices = @{}
    $inDependentSection = $false
    foreach ($line in $showOutput) {
        if ($line -match "Dependent Service Status") {
            $inDependentSection = $true
            continue
        }
        if ($inDependentSection) {
            if ($line -match "^\s*Agent Service \(himds\)\s*:\s*(.+)$") {
                $status.ArcAgent.DependentServices.himds = $matches[1].Trim()
            } elseif ($line -match "^\s*Azure Arc Proxy \(arcproxy\)\s*:\s*(.+)$") {
                $status.ArcAgent.DependentServices.arcproxy = $matches[1].Trim()
            } elseif ($line -match "^\s*Extension Service \(extensionservice\)\s*:\s*(.+)$") {
                $status.ArcAgent.DependentServices.extensionservice = $matches[1].Trim()
            } elseif ($line -match "^\s*GC Service \(gcarcservice\)\s*:\s*(.+)$") {
                $status.ArcAgent.DependentServices.gcarcservice = $matches[1].Trim()
            } elseif ($line -match "^[A-Z]" -and $line -notmatch "^\s+") {
                # Reached next section
                $inDependentSection = $false
            }
        }
    }

    # Also check HIMDS service directly
    try {
        $himdsService = Get-Service -Name "himds" -ErrorAction SilentlyContinue
        if ($himdsService) {
            $status.ArcAgent.HimdsService = $himdsService.Status
        } else {
            $status.ArcAgent.HimdsService = "Not Found"
        }
    } catch {
        # Fallback to WMI if Get-Service fails
        try {
            $himdsServiceWmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='himds'" -ErrorAction SilentlyContinue
            if ($himdsServiceWmi) {
                $status.ArcAgent.HimdsService = $himdsServiceWmi.State
            } else {
                $status.ArcAgent.HimdsService = "Not Found"
            }
        } catch {
            $status.ArcAgent.HimdsService = "Not Found"
        }
    }

    # Collect Certificate Info
    if (Test-Path $certsPath) {
        $certFiles = Get-ChildItem -Path "$certsPath\*" -Include "*.cer", "*.pfx", "*.crt" -ErrorAction SilentlyContinue
        if ($certFiles) {
            foreach ($file in $certFiles) {
                try {
                    $cert = $null
                    
                    if ($file.Extension -eq ".pfx") {
                        # PFX files
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($file.FullName, "")
                    } else {
                        # Try loading as DER first (binary format)
                        try {
                            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($file.FullName)
                        } catch {
                            # If DER fails, try PEM format (Base64 with headers)
                            $certContent = Get-Content $file.FullName -Raw
                            if ($certContent -match "-----BEGIN CERTIFICATE-----") {
                                # Remove PEM headers and decode Base64
                                $certContent = $certContent -replace "-----BEGIN CERTIFICATE-----", ""
                                $certContent = $certContent -replace "-----END CERTIFICATE-----", ""
                                $certContent = $certContent -replace "`n", "" -replace "`r", "" -replace " ", ""
                                $certBytes = [Convert]::FromBase64String($certContent)
                                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)
                            } else {
                                throw
                            }
                        }
                    }

                    if ($cert) {
                        $expiry = $cert.NotAfter
                        $issued = $cert.NotBefore
                        $daysLeft = ($expiry - (Get-Date)).Days
                        $subject = $cert.Subject

                        $certStatus = "Valid"
                        if ($daysLeft -lt 0) {
                            $certStatus = "EXPIRED"
                        } elseif ($daysLeft -lt 30) {
                            $certStatus = "Expiring Soon"
                        }

                        $status.Certificates += @{
                            FileName = $file.Name
                            Subject = $subject
                            IssuedDate = $issued
                            ExpiryDate = $expiry
                            DaysRemaining = $daysLeft
                            Status = $certStatus
                        }
                        
                        $cert.Dispose()
                    }
                } catch {
                    $status.Certificates += @{
                        FileName = $file.Name
                        Status = "Error"
                        Error = $_.Exception.Message
                    }
                }
            }
        } else {
            $status.Certificates += @{ Status = "No certificates found" }
        }
    } else {
        $status.Certificates += @{ Status = "Certificate folder not found" }
    }
} elseif (-not $SkipArc) {
    $status.ArcAgent.Installed = $false
} else {
    $status.ArcAgent.Installed = "Skipped"
}

# Section 2: Collect MDE Sensor Info
try {
    $senseService = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
    if ($senseService) {
        $status.MDE.SenseService = $senseService.Status
    } else {
        $status.MDE.SenseService = "Not Found"
    }
} catch {
    # Fallback to WMI if Get-Service fails (e.g., MUI file error on older systems)
    try {
        $senseServiceWmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='Sense'" -ErrorAction SilentlyContinue
        if ($senseServiceWmi) {
            $status.MDE.SenseService = $senseServiceWmi.State
        } else {
            $status.MDE.SenseService = "Not Found"
        }
    } catch {
        $status.MDE.SenseService = "Not Found"
    }
}

$msSenseProcess = Get-Process -Name "MsSense" -ErrorAction SilentlyContinue
$status.MDE.MsSenseProcess = if ($msSenseProcess) { "Running" } else { "Not Running" }

# Check MDE Installation Path
$mdeInstallPath = "C:\Program Files\Windows Defender Advanced Threat Protection"
$status.MDE.InstallPath = if (Test-Path $mdeInstallPath) { "Exists" } else { "Not Found" }

# Check MDE Executable
$mdeSenseExe = "$mdeInstallPath\MsSense.exe"
$status.MDE.SenseExeExists = if (Test-Path $mdeSenseExe) { 
    try {
        $exeVersion = (Get-Item $mdeSenseExe -ErrorAction SilentlyContinue).VersionInfo.FileVersion
        "Yes (v$exeVersion)"
    } catch {
        "Yes"
    }
} else { "No" }

# Check MDE Sense Health State (indicates if actively communicating with cloud)
$status.MDE.SenseHealthState = "Unknown"
try {
    $senseHealthReg = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if (Test-Path $senseHealthReg) {
        $healthInfo = Get-ItemProperty -Path $senseHealthReg -ErrorAction SilentlyContinue
        
        # Check if sensor is in healthy state (actively connected to cloud)
        if ($healthInfo.PSObject.Properties.Name -contains 'SenseIsRunning') {
            $status.MDE.SenseHealthState = if ($healthInfo.SenseIsRunning -eq 1) { "Running and Healthy" } else { "Not Healthy" }
        }
        
        # Check cyber folder state (indicates data submission)
        if ($healthInfo.PSObject.Properties.Name -contains 'CyberFolderState') {
            $status.MDE.CyberFolderState = $healthInfo.CyberFolderState
        }
    }
} catch { 
    $status.MDE.SenseHealthState = "Error checking health"
}

# Check MDE Onboarding Status
$onboardingState = "Not Onboarded"
$status.MDE.RealTimeProtection = "Unknown"
$status.MDE.PlatformVersion = "Unknown"
$status.MDE.EngineVersion = "Unknown"

# Additional MDE health metrics for comprehensive validation
$status.MDE.MAPSReporting = "Unknown"
$status.MDE.SubmitSamplesConsent = "Unknown"
$status.MDE.SignatureUpdateLastChecked = $null
$status.MDE.AntivirusSignatureAge = "Unknown"
$status.MDE.BehaviorMonitorEnabled = "Unknown"
$status.MDE.IoavProtectionEnabled = "Unknown"
$status.MDE.NetworkRealtimeInspectionEnabled = "Unknown"
$status.MDE.OnAccessProtectionEnabled = "Unknown"
$status.MDE.DefenderSignaturesOutOfDate = "Unknown"

try {
    # Try Windows Defender status first
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus) {
        # Check if ATP/MDE is actually onboarded
        if ($mpStatus.AMServiceEnabled) {
            $status.MDE.RealTimeProtection = if ($mpStatus.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" }
            $status.MDE.PlatformVersion = if ($mpStatus.AMProductVersion) { $mpStatus.AMProductVersion } else { "Unknown" }
            $status.MDE.EngineVersion = if ($mpStatus.AMEngineVersion) { $mpStatus.AMEngineVersion } else { "Unknown" }
            
            # Cloud/Telemetry settings
            if ($mpStatus.PSObject.Properties.Name -contains 'MAPSReporting') {
                $mapsValue = $mpStatus.MAPSReporting
                $status.MDE.MAPSReporting = switch ($mapsValue) {
                    0 { "Disabled" }
                    1 { "Basic" }
                    2 { "Advanced" }
                    default { $mapsValue }
                }
            }
            
            if ($mpStatus.PSObject.Properties.Name -contains 'SubmitSamplesConsent') {
                $samplesValue = $mpStatus.SubmitSamplesConsent
                $status.MDE.SubmitSamplesConsent = switch ($samplesValue) {
                    0 { "Always Prompt" }
                    1 { "Send Safe Samples" }
                    2 { "Never Send" }
                    3 { "Send All Samples" }
                    default { $samplesValue }
                }
            }
            
            # Signature freshness
            if ($mpStatus.PSObject.Properties.Name -contains 'AntivirusSignatureLastUpdated') {
                $status.MDE.SignatureUpdateLastChecked = $mpStatus.AntivirusSignatureLastUpdated
                $signatureAge = (Get-Date) - $mpStatus.AntivirusSignatureLastUpdated
                $status.MDE.AntivirusSignatureAge = "$([math]::Round($signatureAge.TotalDays)) days old"
            }
            
            if ($mpStatus.PSObject.Properties.Name -contains 'DefenderSignaturesOutOfDate') {
                $status.MDE.DefenderSignaturesOutOfDate = if ($mpStatus.DefenderSignaturesOutOfDate) { "Yes" } else { "No" }
            }
            
            # Protection features
            if ($mpStatus.PSObject.Properties.Name -contains 'BehaviorMonitorEnabled') {
                $status.MDE.BehaviorMonitorEnabled = if ($mpStatus.BehaviorMonitorEnabled) { "Enabled" } else { "Disabled" }
            }
            
            if ($mpStatus.PSObject.Properties.Name -contains 'IoavProtectionEnabled') {
                $status.MDE.IoavProtectionEnabled = if ($mpStatus.IoavProtectionEnabled) { "Enabled" } else { "Disabled" }
            }
            
            if ($mpStatus.PSObject.Properties.Name -contains 'NISEnabled') {
                $status.MDE.NetworkRealtimeInspectionEnabled = if ($mpStatus.NISEnabled) { "Enabled" } else { "Disabled" }
            }
            
            if ($mpStatus.PSObject.Properties.Name -contains 'OnAccessProtectionEnabled') {
                $status.MDE.OnAccessProtectionEnabled = if ($mpStatus.OnAccessProtectionEnabled) { "Enabled" } else { "Disabled" }
            }
            
            # Check for actual MDE onboarding (not just Defender)
            if ($mpStatus.PSObject.Properties.Name -contains 'OnboardingState') {
                $onboardingState = $mpStatus.OnboardingState
            }
        }
    }
} catch { }

# Check MDE registry key for Arc servers (more reliable than Get-MpComputerStatus)
try {
    $mdeRegPath = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if (Test-Path $mdeRegPath) {
        $onboardingInfo = Get-ItemProperty -Path $mdeRegPath -ErrorAction SilentlyContinue
        
        # OnboardingState = 1 means onboarded
        if ($onboardingInfo.PSObject.Properties.Name -contains 'OnboardingState') {
            if ($onboardingInfo.OnboardingState -eq 1) {
                # Check if OrgId exists - required for valid onboarding
                $hasOrgId = $onboardingInfo.PSObject.Properties.Name -contains 'OrgId' -and 
                            $onboardingInfo.OrgId -and 
                            $onboardingInfo.OrgId -ne ""
                
                if (-not $hasOrgId) {
                    # OnboardingState=1 but no OrgId = Incomplete/Failed onboarding
                    $onboardingState = "Onboarding Incomplete/Failed"
                } elseif ($onboardingInfo.PSObject.Properties.Name -contains 'LastConnected' -and 
                          $onboardingInfo.LastConnected -and 
                          $onboardingInfo.LastConnected -ne "0" -and 
                          $onboardingInfo.LastConnected -ne 0) {
                    # Has OrgId AND LastConnected = Fully onboarded
                    $onboardingState = "Onboarded"
                } else {
                    # Has OrgId but no LastConnected = Onboarded locally, never reached cloud
                    $onboardingState = "Onboarded Locally (Never Connected)"
                }
            } elseif ($onboardingInfo.OnboardingState -eq 0) {
                $onboardingState = "Not Onboarded"
            }
        }
        
        # Get OrgId if available
        if ($onboardingInfo.OrgId) {
            $status.MDE.OrgId = $onboardingInfo.OrgId
        } else {
            $status.MDE.OrgId = "Not Available"
        }
        
        # Get LastConnected timestamp if available
        if ($onboardingInfo.PSObject.Properties.Name -contains 'LastConnected') {
            $status.MDE.LastConnected = $onboardingInfo.LastConnected
            # Convert FILETIME to readable DateTime
            $lastConnectedDateTime = Convert-FileTimeToDateTime -FileTime $onboardingInfo.LastConnected
            if ($lastConnectedDateTime) {
                $status.MDE.LastConnectedDateTime = $lastConnectedDateTime
            }
        }
    } else {
        $status.MDE.OrgId = "Not Available"
    }
} catch { 
    $status.MDE.OrgId = "Error"
}

# Final determination - cross-check multiple indicators
if ($onboardingState -ne "Onboarded") {
    # Additional check: If Sense service is running AND blob exists, likely onboarded but registry not updated
    if ($status.MDE.SenseService -eq "Running" -and $status.MDE.OnboardingBlobExists -eq "Yes") {
        $onboardingState = "Onboarded (Detected via Service)"
    }
}

$status.MDE.OnboardingState = $onboardingState

# ========== ADDITIONAL MDE ONBOARDING VALIDATION CHECKS (per Microsoft Documentation) ==========

# 1. Check DiagTrack Service (Windows Diagnostic Data Service)
$status.MDE.DiagTrackService = @{
    Status = "Unknown"
    StartType = "Unknown"
    Issue = $null
}
try {
    $diagTrackSvc = Get-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
    if ($diagTrackSvc) {
        $status.MDE.DiagTrackService.Status = $diagTrackSvc.Status.ToString()
        $status.MDE.DiagTrackService.StartType = $diagTrackSvc.StartType.ToString()
        
        if ($diagTrackSvc.StartType -ne "Automatic") {
            $status.MDE.DiagTrackService.Issue = "Not set to Automatic start"
        }
        if ($diagTrackSvc.Status -ne "Running") {
            $status.MDE.DiagTrackService.Issue = "Service not running"
        }
    } else {
        $status.MDE.DiagTrackService.Status = "Not Found"
    }
} catch {
    $status.MDE.DiagTrackService.Status = "Error"
    $status.MDE.DiagTrackService.Issue = $_.Exception.Message
}

# 2. Check Windows Defender ELAM Driver Status
$status.MDE.ELAMDriver = @{
    DisableAntiSpyware = "Not Set"
    DisableAntiVirus = "Not Set"
    Issue = $null
}
try {
    $wdPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    if (Test-Path $wdPolicyPath) {
        $wdPolicy = Get-ItemProperty -Path $wdPolicyPath -ErrorAction SilentlyContinue
        
        if ($wdPolicy.PSObject.Properties.Name -contains "DisableAntiSpyware") {
            $status.MDE.ELAMDriver.DisableAntiSpyware = $wdPolicy.DisableAntiSpyware
            if ($wdPolicy.DisableAntiSpyware -eq 1) {
                $status.MDE.ELAMDriver.Issue = "ELAM driver disabled by policy (DisableAntiSpyware=1)"
            }
        }
        
        if ($wdPolicy.PSObject.Properties.Name -contains "DisableAntiVirus") {
            $status.MDE.ELAMDriver.DisableAntiVirus = $wdPolicy.DisableAntiVirus
            if ($wdPolicy.DisableAntiVirus -eq 1) {
                $status.MDE.ELAMDriver.Issue = "ELAM driver disabled by policy (DisableAntiVirus=1)"
            }
        }
    }
} catch {
    $status.MDE.ELAMDriver.Issue = "Error checking ELAM driver: $($_.Exception.Message)"
}

# 3. Check Windows Defender Core Services
$status.MDE.DefenderServices = @{}
$defenderServices = @("WdBoot", "WdFilter", "WdNisDrv", "WdNisSvc", "WinDefend")
foreach ($svcName in $defenderServices) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            $status.MDE.DefenderServices[$svcName] = @{
                Status = $svc.Status.ToString()
                StartType = $svc.StartType.ToString()
            }
        } else {
            $status.MDE.DefenderServices[$svcName] = @{ Status = "Not Found" }
        }
    } catch {
        $status.MDE.DefenderServices[$svcName] = @{ Status = "Error" }
    }
}

# 4. Check SENSE Feature on Demand (FoD)
$status.MDE.SenseFoD = @{
    Installed = "Unknown"
    Output = ""
}
try {
    $dismOutput = & DISM.EXE /Online /Get-CapabilityInfo /CapabilityName:Microsoft.Windows.Sense.Client~~~~ 2>&1
    $status.MDE.SenseFoD.Output = $dismOutput -join "`n"
    
    if ($dismOutput -match "State\s*:\s*Installed") {
        $status.MDE.SenseFoD.Installed = "Yes"
    } elseif ($dismOutput -match "State\s*:\s*Not Present") {
        $status.MDE.SenseFoD.Installed = "No"
    } else {
        $status.MDE.SenseFoD.Installed = "Unknown"
    }
} catch {
    $status.MDE.SenseFoD.Installed = "Error"
    $status.MDE.SenseFoD.Output = $_.Exception.Message
}

# ========== STREAMLINED CONNECTIVITY PREREQUISITES CHECK ==========
# Reference: https://learn.microsoft.com/en-us/defender-endpoint/configure-device-connectivity#prerequisites

$status.MDE.StreamlinedConnectivity = @{
    Supported = $false
    OSSupported = $false
    KBUpdateSupported = $false
    SenseVersionSupported = $false
    AMVersionSupported = $false
    EngineVersionSupported = $false
    SecurityIntelligenceSupported = $false
    Issues = @()
    Details = @{}
}

# Get OS information for streamlined connectivity check (collected early before main OS section)
$osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$osVersion = if ($osInfo) { $osInfo.Version } else { "Unknown" }
$osBuild = if ($osInfo -and $osInfo.BuildNumber) { [int]$osInfo.BuildNumber } else { 0 }
$osCaption = if ($osInfo) { $osInfo.Caption } else { "Unknown" }

# Check OS Version Support for Streamlined Connectivity

# Determine OS support
$osSupported = $false
$osSupportMessage = ""

if ($osCaption -match "Windows 11") {
    $osSupported = $true
    $osSupportMessage = "Windows 11 (Fully Supported)"
    $minRequiredBuild = 22000
} elseif ($osCaption -match "Windows 10" -and $osBuild -ge 17763) {
    # Windows 10 1809 (17763) or later
    $osSupported = $true
    if ($osBuild -ge 19041) {
        $osSupportMessage = "Windows 10 version 1809+ (Fully Supported)"
    } elseif ($osBuild -ge 16299 -and $osBuild -lt 17763) {
        $osSupportMessage = "Windows 10 version 1607-1803 (Requires different URL list)"
        $status.MDE.StreamlinedConnectivity.Issues += "OS version requires extended URL list - see https://aka.ms/MDE-streamlined-urls"
    } else {
        $osSupportMessage = "Windows 10 version 1809+ (Fully Supported)"
    }
} elseif ($osCaption -match "Server 2022") {
    $osSupported = $true
    $osSupportMessage = "Windows Server 2022 (Supported)"
} elseif ($osCaption -match "Server 2019") {
    $osSupported = $true
    $osSupportMessage = "Windows Server 2019 (Supported)"
} elseif ($osCaption -match "Server 2016" -or $osCaption -match "Server 2012 R2") {
    # NOT supported for streamlined connectivity - no KB updates available
    $osSupported = $false
    $osSupportMessage = "Windows Server 2016/2012 R2 (NOT SUPPORTED for streamlined connectivity)"
    $status.MDE.StreamlinedConnectivity.Issues += "Server 2016/2012 R2 do not support streamlined connectivity - requires Windows Server 2019+ or modern unified solution package"
} else {
    $osSupportMessage = "OS not supported for streamlined connectivity"
    $status.MDE.StreamlinedConnectivity.Issues += "OS version not supported - requires Windows 10 1809+, Windows 11, or Windows Server 2019+"
}

$status.MDE.StreamlinedConnectivity.OSSupported = $osSupported
$status.MDE.StreamlinedConnectivity.Details.OSVersion = $osSupportMessage

# Check Required KB Updates (Windows only - per Microsoft documentation)
# Reference: https://learn.microsoft.com/en-us/defender-endpoint/configure-device-connectivity#prerequisites
$kbUpdateSupported = $false
$kbUpdateMessage = "Not applicable"
$requiredKB = $null

if ($osCaption -match "Windows") {
    # Define required KB updates based on Windows version
    if ($osCaption -match "Windows 11") {
        $requiredKB = "KB5011493"  # March 8, 2022
        $minBuild = 22000
    } elseif ($osCaption -match "Windows 10") {
        if ($osBuild -ge 19044) {
            # Windows 10 21H2, 22H2
            if ($osBuild -ge 19045) {
                $requiredKB = "KB5020953"  # October 28, 2022 for 22H2
            } else {
                $requiredKB = "KB5011487"  # March 8, 2022 for 20H2/21H2
            }
        } elseif ($osBuild -ge 19042) {
            $requiredKB = "KB5011487"  # March 8, 2022 for 20H2
        } elseif ($osBuild -ge 18363) {
            $requiredKB = "KB5011485"  # March 8, 2022 for 19H2 (1909)
        } elseif ($osBuild -ge 17763) {
            $requiredKB = "KB5011503"  # March 8, 2022 for 1809
        } elseif ($osBuild -ge 16299 -and $osBuild -lt 17763) {
            # Windows 10 1607, 1703, 1709, 1803 - end of service but supported with different URL list
            $requiredKB = "End of service"
            $kbUpdateMessage = "OS version end of service (requires extended URL list)"
            $kbUpdateSupported = $false
        }
    } elseif ($osCaption -match "Server 2022") {
        $requiredKB = "KB5011497"  # March 8, 2022
    } elseif ($osCaption -match "Server 2019") {
        $requiredKB = "KB5011503"  # March 8, 2022 (same as Windows 10 1809)
    } elseif ($osCaption -match "Server 2016" -or $osCaption -match "Server 2012 R2") {
        $requiredKB = "N/A"
        $kbUpdateMessage = "KB NOT REQUIRED - Streamlined connectivity not supported on Server 2016/2012 R2 (requires Server 2019+)"
        $kbUpdateSupported = $false
    }
    
    # Check if required KB is installed (if applicable)
    if ($requiredKB -and $requiredKB -notmatch "End of service|Unified Agent|Not available|N/A") {
        try {
            # Check installed hotfixes
            $installedKB = Get-HotFix | Where-Object { $_.HotFixID -match $requiredKB.Replace("KB", "") }
            
            if ($installedKB) {
                $kbUpdateSupported = $true
                $kbUpdateMessage = "$requiredKB installed (Installed: $($installedKB.InstalledOn))"
            } else {
                # KB might be integrated into the build - check build revision
                # For Windows 10/11, March 2022 updates have specific build revisions
                $currentBuild = $osBuild
                $buildRevision = if ($osVersion -match "\d+\.\d+\.(\d+)\.(\d+)") { 
                    [int]$matches[2] 
                } else { 
                    0 
                }
                
                # Define minimum build numbers and revisions for March 2022 updates
                $minBuildNumber = 0
                $minRevision = 0
                
                if ($osCaption -match "Windows 11") {
                    $minBuildNumber = 22000
                    $minRevision = 556  # Build 22000.556 (March 2022)
                } elseif ($osCaption -match "Windows 10") {
                    if ($currentBuild -eq 19044 -or $currentBuild -eq 19043 -or $currentBuild -eq 19042) {
                        $minBuildNumber = 19042
                        $minRevision = 1586  # Build 19044.1586/19042.1586 (March 2022)
                    } elseif ($currentBuild -eq 18363) {
                        $minBuildNumber = 18363
                        $minRevision = 2097  # Build 18363.2097 (March 2022)
                    } elseif ($currentBuild -eq 17763) {
                        $minBuildNumber = 17763
                        $minRevision = 2628  # Build 17763.2628 (March 2022)
                    }
                } elseif ($osCaption -match "Server 2022") {
                    $minBuildNumber = 20348
                    $minRevision = 587   # Server 2022 Build 20348.587 (March 2022)
                } elseif ($osCaption -match "Server 2019") {
                    $minBuildNumber = 17763
                    $minRevision = 2628  # Same as Windows 10 1809
                }
                
                # Check if current build is newer than the minimum required build
                if ($currentBuild -gt $minBuildNumber -and $minBuildNumber -gt 0) {
                    # Build number is higher than March 2022 baseline - definitely includes the update
                    $kbUpdateSupported = $true
                    $kbUpdateMessage = "$requiredKB or later integrated (Build: $currentBuild.$buildRevision - newer than required $minBuildNumber.$minRevision)"
                } elseif ($currentBuild -eq $minBuildNumber) {
                    # Same build number - check revision
                    if ($buildRevision -ge $minRevision) {
                        $kbUpdateSupported = $true
                        $kbUpdateMessage = "$requiredKB or later integrated (Build: $currentBuild.$buildRevision)"
                    } else {
                        $kbUpdateMessage = "$requiredKB NOT FOUND (Current: $currentBuild.$buildRevision, Required: >= $minBuildNumber.$minRevision)"
                        $status.MDE.StreamlinedConnectivity.Issues += "Required KB update $requiredKB not installed (March 8, 2022 or later required)"
                    }
                } else {
                    # Build number is older than March 2022 baseline
                    $kbUpdateMessage = "$requiredKB NOT FOUND (Current: $currentBuild.$buildRevision, Required: >= $minBuildNumber.$minRevision)"
                    $status.MDE.StreamlinedConnectivity.Issues += "Required KB update $requiredKB not installed (March 8, 2022 or later required)"
                }
            }
        } catch {
            $kbUpdateMessage = "Error checking KB updates: $($_.Exception.Message)"
            $status.MDE.StreamlinedConnectivity.Issues += "Unable to verify required KB update"
        }
    }
} else {
    # Non-Windows OS
    $kbUpdateMessage = "Not applicable (non-Windows OS)"
}

$status.MDE.StreamlinedConnectivity.KBUpdateSupported = $kbUpdateSupported
$status.MDE.StreamlinedConnectivity.Details.KBUpdate = $kbUpdateMessage
if ($requiredKB -and $requiredKB -notmatch "End of service|Unified Agent") {
    $status.MDE.StreamlinedConnectivity.Details.RequiredKB = $requiredKB
}

# Check SENSE Version (Minimum: 10.8040.* - March 8, 2022)
$senseVersionSupported = $false
$senseVersionMessage = "Unknown"

if ($status.MDE.SenseExeExists -match "Yes") {
    try {
        $senseExePath = "$mdeInstallPath\MsSense.exe"
        $senseFileVersion = (Get-Item $senseExePath -ErrorAction SilentlyContinue).VersionInfo.FileVersion
        
        if ($senseFileVersion) {
            # Parse version (format: 10.8804.xxxxx.xxxx)
            if ($senseFileVersion -match "(\d+)\.(\d+)\.(\d+)") {
                $senseMajor = [int]$matches[1]
                $senseMinor = [int]$matches[2]
                $senseBuild = [int]$matches[3]
                
                # Check if >= 10.8040 (March 2022 minimum)
                if ($senseMajor -gt 10 -or ($senseMajor -eq 10 -and $senseMinor -ge 8040)) {
                    $senseVersionSupported = $true
                    $senseVersionMessage = "Version $senseFileVersion (Supported - March 2022+)"
                } else {
                    $senseVersionMessage = "Version $senseFileVersion (Too old - requires 10.8040+)"
                    $status.MDE.StreamlinedConnectivity.Issues += "SENSE version $senseFileVersion is below minimum 10.8040.* (March 2022)"
                }
            } else {
                $senseVersionMessage = "Version $senseFileVersion (Unable to parse)"
            }
        }
    } catch {
        $senseVersionMessage = "Error checking version"
    }
} else {
    $senseVersionMessage = "MsSense.exe not found"
    $status.MDE.StreamlinedConnectivity.Issues += "SENSE agent not installed"
}

$status.MDE.StreamlinedConnectivity.SenseVersionSupported = $senseVersionSupported
$status.MDE.StreamlinedConnectivity.Details.SenseVersion = $senseVersionMessage

# Check Microsoft Defender Antivirus Versions
# Minimum requirements:
# - Antimalware Client: 4.18.2211.5
# - Engine: 1.1.19900.2
# - Security Intelligence: 1.391.345.0

$amVersionSupported = $false
$engineVersionSupported = $false
$siVersionSupported = $false

if ($status.MDE.PlatformVersion -ne "Unknown") {
    try {
        # Parse Platform/AM Client version (4.18.2211.5)
        if ($status.MDE.PlatformVersion -match "(\d+)\.(\d+)\.(\d+)\.(\d+)") {
            $amMajor = [int]$matches[1]
            $amMinor = [int]$matches[2]
            $amBuild = [int]$matches[3]
            $amRevision = [int]$matches[4]
            
            # Check if >= 4.18.2211.5
            if ($amMajor -gt 4 -or 
                ($amMajor -eq 4 -and $amMinor -gt 18) -or
                ($amMajor -eq 4 -and $amMinor -eq 18 -and $amBuild -gt 2211) -or
                ($amMajor -eq 4 -and $amMinor -eq 18 -and $amBuild -eq 2211 -and $amRevision -ge 5)) {
                $amVersionSupported = $true
                $status.MDE.StreamlinedConnectivity.Details.AMClientVersion = "$($status.MDE.PlatformVersion) (Supported)"
            } else {
                $status.MDE.StreamlinedConnectivity.Details.AMClientVersion = "$($status.MDE.PlatformVersion) (Below minimum 4.18.2211.5)"
                $status.MDE.StreamlinedConnectivity.Issues += "Antimalware Client version below minimum 4.18.2211.5"
            }
        }
    } catch {
        $status.MDE.StreamlinedConnectivity.Details.AMClientVersion = "Error parsing version"
    }
} else {
    $status.MDE.StreamlinedConnectivity.Details.AMClientVersion = "Not available"
    $status.MDE.StreamlinedConnectivity.Issues += "Unable to determine Antimalware Client version"
}

if ($status.MDE.EngineVersion -ne "Unknown") {
    try {
        # Parse Engine version (1.1.19900.2)
        if ($status.MDE.EngineVersion -match "(\d+)\.(\d+)\.(\d+)\.(\d+)") {
            $engMajor = [int]$matches[1]
            $engMinor = [int]$matches[2]
            $engBuild = [int]$matches[3]
            
            # Check if >= 1.1.19900.2
            if ($engMajor -gt 1 -or
                ($engMajor -eq 1 -and $engMinor -gt 1) -or
                ($engMajor -eq 1 -and $engMinor -eq 1 -and $engBuild -ge 19900)) {
                $engineVersionSupported = $true
                $status.MDE.StreamlinedConnectivity.Details.EngineVersion = "$($status.MDE.EngineVersion) (Supported)"
            } else {
                $status.MDE.StreamlinedConnectivity.Details.EngineVersion = "$($status.MDE.EngineVersion) (Below minimum 1.1.19900.2)"
                $status.MDE.StreamlinedConnectivity.Issues += "Engine version below minimum 1.1.19900.2"
            }
        }
    } catch {
        $status.MDE.StreamlinedConnectivity.Details.EngineVersion = "Error parsing version"
    }
} else {
    $status.MDE.StreamlinedConnectivity.Details.EngineVersion = "Not available"
    $status.MDE.StreamlinedConnectivity.Issues += "Unable to determine Engine version"
}

# Check Security Intelligence version (signatures)
if ($status.MDE.AntivirusSignatureAge -ne "Unknown") {
    # Note: We can't easily check the exact version number (1.391.345.0) without additional queries
    # But we can check if signatures are current
    if ($status.MDE.DefenderSignaturesOutOfDate -eq "No") {
        $siVersionSupported = $true
        $status.MDE.StreamlinedConnectivity.Details.SecurityIntelligence = "Current (Up-to-date)"
    } else {
        $status.MDE.StreamlinedConnectivity.Details.SecurityIntelligence = "Outdated ($($status.MDE.AntivirusSignatureAge))"
        $status.MDE.StreamlinedConnectivity.Issues += "Security Intelligence signatures are outdated"
    }
} else {
    $status.MDE.StreamlinedConnectivity.Details.SecurityIntelligence = "Not available"
}

$status.MDE.StreamlinedConnectivity.AMVersionSupported = $amVersionSupported
$status.MDE.StreamlinedConnectivity.EngineVersionSupported = $engineVersionSupported
$status.MDE.StreamlinedConnectivity.SecurityIntelligenceSupported = $siVersionSupported

# Check if device is CURRENTLY USING streamlined connectivity (not just capable)
$status.MDE.StreamlinedConnectivity.CurrentlyUsing = @{
    InUse = $false
    Configured = $false
    Functional = $false
    Method = "Unknown"
    StreamlinedDomain = "Not tested"
    Evidence = @()
    Issues = @()
}

# Only check if MDE is onboarded
if ($status.MDE.OnboardingState -eq "Onboarded") {
    try {
        $streamlinedConfigured = $false
        $standardConfigured = $false
        
        # Test connectivity to streamlined domain (region-specific EDR endpoint)
        # Map regions to their EDR endpoints (these are the streamlined connectivity endpoints)
        $streamlinedEndpoints = @{
            "Australia" = "edr-aue.au.endpoint.security.microsoft.com"
            "US" = "edr-eus.us.endpoint.security.microsoft.com"
            "Europe" = "edr-weu.eu.endpoint.security.microsoft.com"
            "UK" = "edr-uks.uk.endpoint.security.microsoft.com"
            "Canada" = "edr-cac.ca.endpoint.security.microsoft.com"
            "Asia" = "edr-eas.asia.endpoint.security.microsoft.com"
        }
        
        $streamlinedDomain = $streamlinedEndpoints[$Region]
        $streamlinedTestUrl = "https://$streamlinedDomain"
        $streamlinedTestResult = Test-ConnectivityWithProxy -Url $streamlinedTestUrl -UseProxyMethod $UseProxy -TimeoutSeconds 10 -ProxyCredential $ProxyCredential
        
        if ($streamlinedTestResult.Success) {
            $status.MDE.StreamlinedConnectivity.CurrentlyUsing.StreamlinedDomain = "Reachable"
            $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Evidence += "Streamlined domain ($streamlinedDomain) is reachable for $Region region"
        } else {
            $status.MDE.StreamlinedConnectivity.CurrentlyUsing.StreamlinedDomain = "Unreachable"
        }
        
        # Check onboarding info from registry for clues
        $onboardingInfoPath = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
        if (Test-Path $onboardingInfoPath) {
            $onboardingInfo = Get-ItemProperty -Path $onboardingInfoPath -ErrorAction SilentlyContinue
            
            # Check OrgId to see if it's using newer format (streamlined tends to have different patterns)
            if ($onboardingInfo.PSObject.Properties.Name -contains "OnboardingInfo") {
                $onboardingInfoValue = $onboardingInfo.OnboardingInfo
                if ($onboardingInfoValue -match "endpoint\.security\.microsoft\.com") {
                    $streamlinedConfigured = $true
                    $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Configured = $true
                    $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Evidence += "Onboarding info contains streamlined domain"
                }
            }
        }
        
        # Check SENSE service configuration for URL patterns
        $senseConfigPath = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection"
        if (Test-Path $senseConfigPath) {
            $senseConfig = Get-ItemProperty -Path $senseConfigPath -ErrorAction SilentlyContinue
            
            # Look for configuration keys that might indicate streamlined connectivity
            foreach ($prop in $senseConfig.PSObject.Properties) {
                if ($prop.Value -match "endpoint\.security\.microsoft\.com") {
                    $streamlinedConfigured = $true
                    $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Configured = $true
                    $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Evidence += "Configuration contains streamlined domain ($($prop.Name))"
                } elseif ($prop.Value -match "winatp-gw-.*\.microsoft\.com") {
                    $standardConfigured = $true
                }
            }
        }
        
        # Determine method and functional status
        if ($streamlinedConfigured) {
            $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Method = "Streamlined (Configured)"
            
            # Check if it's actually functional
            if ($status.MDE.StreamlinedConnectivity.CurrentlyUsing.StreamlinedDomain -eq "Reachable") {
                $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Functional = $true
                $status.MDE.StreamlinedConnectivity.CurrentlyUsing.InUse = $true
                $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Method = "Streamlined"
            } else {
                # Configured but not functional
                $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Issues += "Streamlined configured but domain unreachable - connectivity blocked"
                
                # Check if OS even supports streamlined
                if (-not $osSupported) {
                    $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Issues += "OS does not support streamlined connectivity - requires Windows 10 1809+, Windows 11, or Windows Server 2019+"
                    $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Issues += "Server 2012 R2/2016 require unified agent upgrade"
                }
            }
        } elseif ($standardConfigured) {
            $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Method = "Standard"
            $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Evidence += "Configuration contains standard gateway URLs"
            # Standard method doesn't require domain test
            $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Functional = $true
        } else {
            # If still unknown but device is onboarded and working, assume standard method
            $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Method = "Standard (Inferred)"
            $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Evidence += "Device is onboarded but no streamlined indicators found - likely using standard connectivity"
            $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Functional = $true
        }
        
    } catch {
        $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Method = "Error checking: $($_.Exception.Message)"
    }
} else {
    $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Method = "N/A (Device not onboarded)"
}

# Overall determination
if ($osSupported -and $kbUpdateSupported -and $senseVersionSupported -and $amVersionSupported -and $engineVersionSupported) {
    $status.MDE.StreamlinedConnectivity.Supported = $true
} else {
    $status.MDE.StreamlinedConnectivity.Supported = $false
}

# Add summary
$passedChecks = 0
$totalChecks = 6
if ($osSupported) { $passedChecks++ }
if ($kbUpdateSupported) { $passedChecks++ }
if ($senseVersionSupported) { $passedChecks++ }
if ($amVersionSupported) { $passedChecks++ }
if ($engineVersionSupported) { $passedChecks++ }
if ($siVersionSupported) { $passedChecks++ }

$status.MDE.StreamlinedConnectivity.Summary = "$passedChecks of $totalChecks prerequisites met"

# 5. Check MDE Registry Permissions & Status Key
$status.MDE.RegistryHealth = @{
    PolicyKeyExists = $false
    StatusKeyExists = $false
    OnboardingStateValue = $null
    Issue = $null
}
try {
    # Check Policy key
    $policyKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"
    $status.MDE.RegistryHealth.PolicyKeyExists = Test-Path $policyKeyPath
    
    # Check Status key
    $statusKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    $status.MDE.RegistryHealth.StatusKeyExists = Test-Path $statusKeyPath
    
    if ($status.MDE.RegistryHealth.StatusKeyExists) {
        $statusKey = Get-ItemProperty -Path $statusKeyPath -ErrorAction SilentlyContinue
        if ($statusKey.PSObject.Properties.Name -contains "OnboardingState") {
            $status.MDE.RegistryHealth.OnboardingStateValue = $statusKey.OnboardingState
        }
    }
    
    # Check if Policy key exists but Status key doesn't (indicates onboarding issue)
    if ($status.MDE.RegistryHealth.PolicyKeyExists -and -not $status.MDE.RegistryHealth.StatusKeyExists) {
        $status.MDE.RegistryHealth.Issue = "Policy key exists but Status key missing - SENSE service may not have started successfully"
    }
} catch {
    $status.MDE.RegistryHealth.Issue = "Error checking registry: $($_.Exception.Message)"
}

# 6. Check SENSE Event Log for Critical Errors
$status.MDE.EventLogErrors = @{
    CriticalErrors = @()
    RecentErrorCount = 0
}
try {
    $senseLog = Get-WinEvent -LogName "Microsoft-Windows-SENSE/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue | 
        Where-Object { $_.Level -le 3 -and $_.TimeCreated -gt (Get-Date).AddHours(-24) }
    
    if ($senseLog) {
        $status.MDE.EventLogErrors.RecentErrorCount = $senseLog.Count
        
        # Capture specific critical event IDs from Microsoft documentation
        $criticalEventIds = @(5, 6, 7, 9, 10, 15, 17, 25, 27, 29, 30, 32, 55, 63, 64, 68, 69)
        $criticalEvents = $senseLog | Where-Object { $_.Id -in $criticalEventIds }
        
        foreach ($event in $criticalEvents | Select-Object -First 5) {
            $status.MDE.EventLogErrors.CriticalErrors += @{
                EventId = $event.Id
                Message = $event.Message
                TimeCreated = $event.TimeCreated
            }
        }
    }
} catch {
    $status.MDE.EventLogErrors.RecentErrorCount = "Error: $($_.Exception.Message)"
}

# 7. Check Connected User Experiences and Telemetry Service
$status.MDE.TelemetryService = @{
    Status = "Unknown"
    StartType = "Unknown"
}
try {
    # This service location should be properly configured by MDE
    $telemetrySvc = Get-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
    if ($telemetrySvc) {
        $status.MDE.TelemetryService.Status = $telemetrySvc.Status.ToString()
        $status.MDE.TelemetryService.StartType = $telemetrySvc.StartType.ToString()
    }
} catch {
    $status.MDE.TelemetryService.Status = "Error"
}

# Analyze MDE version age (Platform version format: 4.18.YYMDD.revision)
$status.MDE.VersionAge = "Unknown"
try {
    if ($status.MDE.PlatformVersion -match "4\.18\.(\d{5})") {
        $versionDate = $matches[1]
        # Parse YYMDD format (e.g., 25110 = Year 25, Month 11, Day 0 = Nov 2025)
        $year = "20" + $versionDate.Substring(0,2)
        $month = $versionDate.Substring(2,2)
        $day = if ($versionDate.Substring(4,1) -eq "0") { "01" } else { $versionDate.Substring(4,1) }
        
        try {
            $versionDateTime = Get-Date -Year $year -Month $month -Day $day -ErrorAction SilentlyContinue
            $daysSinceVersion = ((Get-Date) - $versionDateTime).Days
            $status.MDE.VersionAge = "$daysSinceVersion days old"
            
            # Classify version age
            if ($daysSinceVersion -gt 180) {
                $status.MDE.VersionStatus = "CRITICALLY OUTDATED (6+ months old)"
            } elseif ($daysSinceVersion -gt 90) {
                $status.MDE.VersionStatus = "Outdated (3+ months old)"
            } elseif ($daysSinceVersion -gt 30) {
                $status.MDE.VersionStatus = "Needs Update (1+ month old)"
            } else {
                $status.MDE.VersionStatus = "Current"
            }
        } catch {
            $status.MDE.VersionStatus = "Unable to parse version date"
        }
    }
} catch {
    $status.MDE.VersionStatus = "Unable to analyze"
}

# Check System Drive Space
$status.SystemDrive = @{}
try {
    $drive = Get-PSDrive -Name C -ErrorAction SilentlyContinue
    if ($drive) {
        $freeSpaceGB = [Math]::Round($drive.Free / 1GB, 2)
        $usedSpaceGB = [Math]::Round($drive.Used / 1GB, 2)
        $totalSpaceGB = [Math]::Round(($drive.Free + $drive.Used) / 1GB, 2)
        $freeSpacePercent = [Math]::Round(($drive.Free / ($drive.Free + $drive.Used)) * 100, 1)
        
        $status.SystemDrive.FreeSpaceGB = $freeSpaceGB
        $status.SystemDrive.UsedSpaceGB = $usedSpaceGB
        $status.SystemDrive.TotalSpaceGB = $totalSpaceGB
        $status.SystemDrive.FreeSpacePercent = $freeSpacePercent
    }
} catch {
    $status.SystemDrive.Error = $_.Exception.Message
}

# Collect Operating System Information
$status.OperatingSystem = @{}
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        $status.OperatingSystem.Caption = $os.Caption
        $status.OperatingSystem.Version = $os.Version
        $status.OperatingSystem.BuildNumber = $os.BuildNumber
        $status.OperatingSystem.Architecture = $os.OSArchitecture
        $status.OperatingSystem.InstallDate = $os.InstallDate
    }
} catch {
    $status.OperatingSystem.Error = $_.Exception.Message
}

# Check Windows Setup Status
$status.WindowsSetup = @{}
try {
    $setupPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State"
    if (Test-Path $setupPath) {
        $setupInfo = Get-ItemProperty -Path $setupPath -ErrorAction SilentlyContinue
        if ($setupInfo -and $setupInfo.PSObject.Properties.Name -contains "ImageState") {
            $imageState = $setupInfo.ImageState
            $status.WindowsSetup.ImageState = $imageState
            
            if ($imageState -eq "IMAGE_STATE_COMPLETE") {
                $status.WindowsSetup.Status = "Completed"
            } elseif ($imageState -match "OOBE|GENERALIZE") {
                $status.WindowsSetup.Status = "In Progress"
            } else {
                $status.WindowsSetup.Status = "Incomplete"
            }
        } else {
            $status.WindowsSetup.ImageState = "Not Found"
            $status.WindowsSetup.Status = "No Data"
        }
    } else {
        $status.WindowsSetup.ImageState = "Path Not Found"
        $status.WindowsSetup.Status = "No Data"
    }
} catch {
    $status.WindowsSetup.ImageState = "Error: $($_.Exception.Message)"
    $status.WindowsSetup.Status = "Error"
}

# Collect Operating System Information
$status.OperatingSystem = @{}
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        $status.OperatingSystem.Caption = $os.Caption
        $status.OperatingSystem.Version = $os.Version
        $status.OperatingSystem.BuildNumber = $os.BuildNumber
        $status.OperatingSystem.Architecture = $os.OSArchitecture
        $status.OperatingSystem.InstallDate = $os.InstallDate
    }
} catch {
    $status.OperatingSystem.Error = $_.Exception.Message
}

# Check Azure Arc Extension Service Status
$status.ExtensionService = @{
    Status = "Unknown"
    LogPath = "$env:ProgramData\GuestConfig\ext_mgr_logs\gc_ext.log"
    LogExists = (Test-Path "$env:ProgramData\GuestConfig\ext_mgr_logs\gc_ext.log")
}
try {
    $extService = Get-Service -Name "ExtensionService" -ErrorAction SilentlyContinue
    if ($extService) {
        $status.ExtensionService.Status = $extService.Status
        $status.ExtensionService.StartType = $extService.StartType
    }
} catch {
    $status.ExtensionService.Error = $_.Exception.Message
}

# Section 3: Collect Extension Info
$guestConfigPath = "$env:ProgramData\GuestConfig"
$extensionLogsPath = "$guestConfigPath\extension_logs"

if (Test-Path $extensionLogsPath) {
    $extFolders = Get-ChildItem -Path $extensionLogsPath -Directory -ErrorAction SilentlyContinue
    
    if ($extFolders) {
        foreach ($extFolder in $extFolders) {
            $extInfo = @{
                Name = $extFolder.Name
                Status = "Unknown"
                Message = ""
                RuntimeSettings = @{
                    Found = $false
                    LastModified = $null
                    ConfigCount = 0
                }
            }
            
            # Check for RuntimeSettings files (proves Azure sent configuration)
            $pluginPath = "$env:SystemDrive\Packages\Plugins\$($extFolder.Name)*"
            $runtimeSettingsFiles = Get-ChildItem -Path $pluginPath -Recurse -Filter "*.settings" -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -like "*RuntimeSettings*" }
            if ($runtimeSettingsFiles) {
                $extInfo.RuntimeSettings.Found = $true
                $latestSettings = $runtimeSettingsFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                $extInfo.RuntimeSettings.LastModified = $latestSettings.LastWriteTime
                $extInfo.RuntimeSettings.ConfigCount = $runtimeSettingsFiles.Count
                $extInfo.RuntimeSettings.FilePath = $latestSettings.FullName
            }
            
            # First check for state.json in extension_logs
            $statusFile = Get-ChildItem -Path $extFolder.FullName -Filter "state.json" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            
            # If not found, try *status*.json pattern
            if (-not $statusFile) {
                $statusFile = Get-ChildItem -Path $extFolder.FullName -Filter "*status*.json" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            }
            
            # If still not found, check in C:\Packages\Plugins\<extension_name>\* for state.json or *.status
            if (-not $statusFile) {
                $pluginPath = "$env:SystemDrive\Packages\Plugins\$($extFolder.Name)*"
                # Try state.json first
                $statusFile = Get-ChildItem -Path $pluginPath -Recurse -Filter "state.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                # If not found, try *.status files
                if (-not $statusFile) {
                    $statusFile = Get-ChildItem -Path $pluginPath -Recurse -Filter "*.status" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                }
            }
            
            if ($statusFile) {
                # Store the status file path for reference
                $extInfo.StatusFilePath = $statusFile.FullName
                
                try {
                    $extStatus = Get-Content $statusFile.FullName -Raw | ConvertFrom-Json
                    
                    # Handle different JSON structures (state.json vs *.status)
                    if ($extStatus.status) {
                        # *.status file format
                        if ($extStatus.status.status) {
                            $extInfo.Status = $extStatus.status.status
                        } elseif ($extStatus.status.state) {
                            $extInfo.Status = $extStatus.status.state
                        } else {
                            $extInfo.Status = "Unknown structure"
                        }
                        
                        if ($extStatus.status.formattedMessage -and $extStatus.status.formattedMessage.message) {
                            $extInfo.Message = $extStatus.status.formattedMessage.message
                        }
                    } elseif ($extStatus.state) {
                        # state.json format - extract key information instead of full JSON
                        if ($extStatus.state -is [string]) {
                            $extInfo.Status = $extStatus.state
                        } else {
                            # Complex state object - extract useful fields
                            if ($extStatus.Blocked -ne $null) {
                                $extInfo.Status = if ($extStatus.Blocked) { "Blocked" } else { "Active" }
                            } else {
                                $extInfo.Status = "Unknown state"
                            }
                            
                            # Store error message if present
                            if ($extStatus.ErrorMsg -and $extStatus.ErrorMsg -ne "") {
                                $extInfo.Message = $extStatus.ErrorMsg
                            }
                        }
                    } else {
                        # Unknown format - show condensed info
                        $extInfo.Status = "See logs for details"
                    }
                } catch {
                    $extInfo.Status = "Error reading status: $($_.Exception.Message)"
                }
            } else {
                $extInfo.Status = "No status file"
            }
            
            $status.Extensions += $extInfo
        }
    }
}

# Check specific extensions
# Check if MDE.Windows extension is actually installed (check Packages\Plugins folder)
$mdeExtPluginPath = "$env:SystemDrive\Packages\Plugins\Microsoft.Azure.AzureDefenderForServers.MDE.Windows"
$mdeExtInfo = @{
    Name = "MDE.Windows (AzureDefenderForServers)"
    Installed = Test-Path $mdeExtPluginPath
    HandlerState = "Unknown"
    DetailedStatus = "Unknown"
    ErrorMessage = ""
    ErrorCode = ""
}

if ($mdeExtInfo.Installed) {
    # Get the extension version folder
    $mdeExtVersionFolder = Get-ChildItem -Path $mdeExtPluginPath -Directory | Sort-Object Name -Descending | Select-Object -First 1
    if ($mdeExtVersionFolder) {
        $mdeExtInfo.Version = $mdeExtVersionFolder.Name
    }
    
    # Get detailed status from status file
    $statusFile = Get-ChildItem -Path "$mdeExtPluginPath\*" -Recurse -Filter "*.status" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($statusFile) {
        try {
            $statusContent = Get-Content $statusFile.FullName -Raw | ConvertFrom-Json
            if ($statusContent.status) {
                $mdeExtInfo.DetailedStatus = $statusContent.status.status
                
                # Parse the message - it could be error or success information
                if ($statusContent.status.formattedMessage -and $statusContent.status.formattedMessage.message) {
                    $messageContent = $statusContent.status.formattedMessage.message
                    
                    # Try to parse as JSON to see if it's structured info
                    try {
                        $parsedMessage = $messageContent | ConvertFrom-Json
                        
                        # Check if this is success information
                        if ($parsedMessage.onboardingPackageOperationResultCode -eq "Success") {
                            $mdeExtInfo.OnboardingSuccess = $true
                            $mdeExtInfo.MachineId = $parsedMessage.machineId
                            $mdeExtInfo.AzureResourceId = $parsedMessage.azureResourceId
                            $mdeExtInfo.WorkspaceId = $parsedMessage.securityWorkspaceId
                            
                            # Store full details for display
                            $mdeExtInfo.OnboardingDetails = $parsedMessage
                        } else {
                            # It's structured but not success
                            $mdeExtInfo.ErrorMessage = $messageContent
                        }
                    } catch {
                        # Not JSON, treat as regular message
                        if ($messageContent -match "error|failed|exception") {
                            $mdeExtInfo.ErrorMessage = $messageContent
                        } else {
                            $mdeExtInfo.StatusMessage = $messageContent
                        }
                    }
                }
                
                if ($statusContent.status.code) {
                    $mdeExtInfo.ErrorCode = $statusContent.status.code
                }
            }
        } catch { }
    }
    
    # Parse execution log for specific errors
    $executionLog = Get-ChildItem -Path "$mdeExtPluginPath\*" -Recurse -Filter "*execution*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($executionLog) {
        try {
            $logContent = Get-Content $executionLog.FullName -Tail 100 -ErrorAction SilentlyContinue
            $mdeExtInfo.LogFile = $executionLog.FullName
            
            # Check for specific error patterns
            if ($logContent -match "Unable to connect to the remote server") {
                $mdeExtInfo.ConnectivityIssue = $true
            }
            if ($logContent -match "timeout during updating") {
                $mdeExtInfo.TimeoutIssue = $true
            }
            if ($logContent -match "vNext/Unified agent installation failed") {
                $mdeExtInfo.InstallationFailed = $true
            }
        } catch { }
    }
}
$status.Extensions += $mdeExtInfo

$sqlExtPath = "$env:ProgramData\GuestConfig\extension_logs\Microsoft.AzureData.WindowsAgent.SqlServer"
$sqlExtInfo = @{
    Name = "WindowsAgent.SqlServer"
    Installed = Test-Path $sqlExtPath
    ServiceStatus = "N/A"
}

if ($sqlExtInfo.Installed) {
    try {
        $sqlService = Get-Service -Name "SQLServerExtension" -ErrorAction SilentlyContinue
        if ($sqlService) {
            $sqlExtInfo.ServiceStatus = $sqlService.Status
        }
    } catch {
        # Fallback to WMI if Get-Service fails
        try {
            $sqlServiceWmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='SQLServerExtension'" -ErrorAction SilentlyContinue
            if ($sqlServiceWmi) {
                $sqlExtInfo.ServiceStatus = $sqlServiceWmi.State
            }
        } catch {
            $sqlExtInfo.ServiceStatus = "Error"
        }
    }
}
$status.Extensions += $sqlExtInfo

$amaExtPath = "$env:ProgramData\GuestConfig\extension_logs\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent"
$status.Extensions += @{
    Name = "AzureMonitorAgent"
    Installed = Test-Path $amaExtPath
}

# Section 4: Collect Connectivity Info
$status.ConnectivityChecks = @()

# Check Azure Arc connectivity (only if agent is installed)
if (Test-Path $azcmagentPath) {
    $connectivityOutput = & $azcmagentPath check 2>&1
    $status.Connectivity = $connectivityOutput | Out-String
    
    # Parse individual endpoint checks
    foreach ($line in $connectivityOutput) {
        # Match patterns like "✓ <url>" or "✗ <url>" or "Checking <url>...reachable"
        if ($line -match "✓.*?(https?://[^\s]+)") {
            $status.ConnectivityChecks += @{
                URL = $matches[1]
                Status = "Passed"
                Category = "Azure Arc"
                RawLine = $line.ToString()
            }
        } elseif ($line -match "✗.*?(https?://[^\s]+)") {
            $status.ConnectivityChecks += @{
                URL = $matches[1]
                Status = "Failed"
                Category = "Azure Arc"
                RawLine = $line.ToString()
            }
        } elseif ($line -match "(https?://[^\s]+).*?reachable") {
            $status.ConnectivityChecks += @{
                URL = $matches[1]
                Status = "Passed"
                Category = "Azure Arc"
                RawLine = $line.ToString()
            }
        } elseif ($line -match "(https?://[^\s]+).*?unreachable") {
            $status.ConnectivityChecks += @{
                URL = $matches[1]
                Status = "Failed"
                Category = "Azure Arc"
                RawLine = $line.ToString()
            }
        } elseif ($line -match "Passed.*?(https?://[^\s]+)") {
            $status.ConnectivityChecks += @{
                URL = $matches[1]
                Status = "Passed"
                Category = "Azure Arc"
                RawLine = $line.ToString()
            }
        } elseif ($line -match "Failed.*?(https?://[^\s]+)") {
            $status.ConnectivityChecks += @{
                URL = $matches[1]
                Status = "Failed"
                Category = "Azure Arc"
                RawLine = $line.ToString()
            }
        }
    }
}

# Add MDE endpoint checks (run regardless of Arc agent installation)
# Category "MDE.Windows" = Required for Arc extension installation
# Category "MDE" = Required for MDE agent runtime (both manual and Arc-managed)

# Define region-specific mappings
$regionConfig = @{
    "Australia" = @{
        BlobStorage = @("aue", "aus")
        Gateways = @("aus", "aue", "auc")
        EDR = "edr-aue.au.endpoint.security.microsoft.com"
        CyberData = "au-v20.events.data.microsoft.com"
    }
    "US" = @{
        BlobStorage = @("cus", "eus", "wus")
        Gateways = @("eus", "wus", "cus")
        EDR = "edr-eus.us.endpoint.security.microsoft.com"
        CyberData = "us-v20.events.data.microsoft.com"
    }
    "Europe" = @{
        BlobStorage = @("weu", "neu")
        Gateways = @("weu", "neu")
        EDR = "edr-weu.eu.endpoint.security.microsoft.com"
        CyberData = "eu-v20.events.data.microsoft.com"
    }
    "UK" = @{
        BlobStorage = @("uks", "ukw")
        Gateways = @("uks", "ukw")
        EDR = "edr-uks.uk.endpoint.security.microsoft.com"
        CyberData = "uk-v20.events.data.microsoft.com"
    }
    "Canada" = @{
        BlobStorage = @("cac", "cae")
        Gateways = @("cac", "cae")
        EDR = "edr-cac.ca.endpoint.security.microsoft.com"
        CyberData = "us-v20.events.data.microsoft.com"
    }
    "Asia" = @{
        BlobStorage = @("eas", "seas")
        Gateways = @("eas", "seas")
        EDR = "edr-eas.asia.endpoint.security.microsoft.com"
        CyberData = "us-v20.events.data.microsoft.com"
    }
}

$selectedRegion = $regionConfig[$Region]

# Build endpoint list dynamically based on region
$mdeEndpoints = @()

# MDE.Windows Extension Installation Requirements (Region-specific blob storage)
$mdeEndpoints += @{ URL = "go.microsoft.com"; Port = 443; Description = "MDE Installer Download"; Category = "MDE.Windows"; Mandatory = $true }
foreach ($regionCode in $selectedRegion.BlobStorage) {
    $mdeEndpoints += @{ 
        URL = "automatedirstrprd$regionCode.blob.core.windows.net"
        Port = 443
        Description = "MDE Package Storage ($($Region) - $($regionCode.ToUpper()))"
        Category = "MDE.Windows"
        Mandatory = $true
    }
}

# MDE Agent Runtime Requirements (Region-specific gateways)
foreach ($gatewayCode in $selectedRegion.Gateways) {
    $mdeEndpoints += @{
        URL = "winatp-gw-$gatewayCode.microsoft.com"
        Port = 443
        Description = "MDE $Region Gateway ($($gatewayCode.ToUpper()))"
        Category = "MDE"
        Mandatory = $true
    }
}

# EDR Endpoint (Region-specific)
$mdeEndpoints += @{
    URL = $selectedRegion.EDR
    Port = 443
    Description = "MDE EDR $Region Endpoint"
    Category = "MDE"
    Mandatory = $true
}

# Cyber Data Endpoint (Region-specific)
$mdeEndpoints += @{
    URL = $selectedRegion.CyberData
    Port = 443
    Description = "Cyber Data $Region"
    Category = "MDE"
    Mandatory = $true
}

# Global MDE Endpoints (Common to all regions)
$mdeEndpoints += @(
    # Cloud-delivered protection and sample submission (MANDATORY)
    @{ URL = "wdcp.microsoft.com"; Port = 443; Description = "Cloud-delivered Protection"; Category = "MDE"; Mandatory = $true }
    @{ URL = "wdcpalt.microsoft.com"; Port = 443; Description = "Cloud-delivered Protection (Alternate)"; Category = "MDE"; Mandatory = $true }
    
    # Telemetry (MANDATORY - Global)
    @{ URL = "events.data.microsoft.com"; Port = 443; Description = "MDE Telemetry (Global)"; Category = "MDE"; Mandatory = $true }
    
    # Content Delivery and Updates (MANDATORY)
    @{ URL = "x.cp.wd.microsoft.com"; Port = 443; Description = "MDE Content Delivery"; Category = "MDE"; Mandatory = $true }
    @{ URL = "cdn.x.cp.wd.microsoft.com"; Port = 443; Description = "MDE CDN Content Delivery"; Category = "MDE"; Mandatory = $true }
    
    # Security Intelligence Updates (MANDATORY)
    @{ URL = "go.microsoft.com"; Port = 443; Description = "Security Intelligence Updates"; Category = "MDE"; Mandatory = $true }
    @{ URL = "definitionupdates.microsoft.com"; Port = 443; Description = "Definition Updates"; Category = "MDE"; Mandatory = $true }
    
    # Supporting/Optional Endpoints (OPTIONAL)
    @{ URL = "ctldl.windowsupdate.com"; Port = 443; Description = "Certificate Trust List"; Category = "MDE"; Mandatory = $false }
    @{ URL = "win.vortex.data.microsoft.com"; Port = 443; Description = "Windows Telemetry (Optional)"; Category = "MDE"; Mandatory = $false }
    @{ URL = "settings-win.data.microsoft.com"; Port = 443; Description = "Windows Settings"; Category = "MDE"; Mandatory = $false }
    @{ URL = "fe3.delivery.mp.microsoft.com"; Port = 443; Description = "Windows Update Delivery"; Category = "MDE"; Mandatory = $false }
    @{ URL = "crl.microsoft.com"; Port = 80; Description = "Certificate Revocation List"; Category = "MDE"; Mandatory = $false }
)
    
foreach ($endpoint in $mdeEndpoints) {
        try {
            $testUrl = "https://$($endpoint.URL):$($endpoint.Port)"
            if ($endpoint.Port -eq 80) {
                $testUrl = "http://$($endpoint.URL):$($endpoint.Port)"
            }
            
            $testResult = Test-ConnectivityWithProxy -Url $testUrl -UseProxyMethod $UseProxy -TimeoutSeconds 10 -ProxyCredential $ProxyCredential
            
            $status.ConnectivityChecks += @{
                URL = $testUrl
                Status = if ($testResult.Success) { "Passed" } else { "Failed" }
                Category = $endpoint.Category
                Description = $endpoint.Description
                Mandatory = $endpoint.Mandatory
                TestMethod = $testResult.Method
            }
        } catch {
            $status.ConnectivityChecks += @{
                URL = "https://$($endpoint.URL):$($endpoint.Port)"
                Status = "Failed"
                Category = $endpoint.Category
                Description = $endpoint.Description
                Mandatory = $endpoint.Mandatory
                TestMethod = if ($UseProxy) { "Web Request (Proxy-aware)" } else { "Direct TCP" }
                Error = $_.Exception.Message
            }
        }
    }

# ========== REPORT ALL STATUS ==========
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "         STATUS REPORT SUMMARY          " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ==================== SYSTEM INFORMATION ====================
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     SYSTEM INFORMATION                 ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Report 0: Operating System Information
Write-Host "OPERATING SYSTEM" -ForegroundColor Green
Write-Host "   ----------------------------------------"
if ($status.OperatingSystem.Caption) {
    Write-Host "   OS Name:          $($status.OperatingSystem.Caption)" -ForegroundColor Cyan
    Write-Host "   OS Version:       $($status.OperatingSystem.Version)" -ForegroundColor Cyan
    Write-Host "   Build Number:     $($status.OperatingSystem.BuildNumber)" -ForegroundColor Cyan
    Write-Host "   Architecture:     $($status.OperatingSystem.Architecture)" -ForegroundColor Cyan
    if ($status.OperatingSystem.InstallDate) {
        Write-Host "   Install Date:     $($status.OperatingSystem.InstallDate)" -ForegroundColor Gray
    }
} else {
    Write-Host "   Unable to retrieve OS information" -ForegroundColor Yellow
    if ($status.OperatingSystem.Error) {
        Write-Host "   Error: $($status.OperatingSystem.Error)" -ForegroundColor Red
    }
}
Write-Host ""

# ==================== AZURE ARC CHECKS ====================
if (-not $SkipArc) {
    Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     AZURE ARC CHECKS                   ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# Report 1: Azure Arc Agent
if (-not $SkipArc) {
    Write-Host "1. AZURE ARC AGENT" -ForegroundColor Green
    Write-Host "   ----------------------------------------"
    if ($status.ArcAgent.Installed) {
        Write-Host "   Agent Installed:  YES" -ForegroundColor Green
    Write-Host "   Agent Status:     $($status.ArcAgent.Status)" -ForegroundColor $(if ($status.ArcAgent.Status -match "Connected") {"Green"} elseif ($status.ArcAgent.Status -match "Disconnected|Expired") {"Red"} else {"Yellow"})
    
    if ($status.ArcAgent.LastHeartbeat) {
        $heartbeatColor = "Green"
        if ($status.ArcAgent.HoursSinceHeartbeat -gt 24) {
            $heartbeatColor = "Red"
        } elseif ($status.ArcAgent.HoursSinceHeartbeat -gt 2) {
            $heartbeatColor = "Yellow"
        }
        Write-Host "   Last Heartbeat:   $($status.ArcAgent.LastHeartbeat)" -ForegroundColor $heartbeatColor
        if ($status.ArcAgent.HoursSinceHeartbeat) {
            Write-Host "                     ($($status.ArcAgent.HoursSinceHeartbeat) hours ago)" -ForegroundColor $heartbeatColor
        }
    }
    
    if ($status.ArcAgent.ErrorCode) {
        Write-Host "   Error Code:       $($status.ArcAgent.ErrorCode)" -ForegroundColor Red
    }
    if ($status.ArcAgent.ErrorDetails) {
        Write-Host "   Error Details:    $($status.ArcAgent.ErrorDetails)" -ForegroundColor Red
    }
    if ($status.ArcAgent.ErrorTimestamp) {
        Write-Host "   Error Timestamp:  $($status.ArcAgent.ErrorTimestamp)" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "   Dependent Services:" -ForegroundColor Cyan
    if ($status.ArcAgent.DependentServices.Count -gt 0) {
        if ($status.ArcAgent.DependentServices.himds) {
            Write-Host "     himds:            $($status.ArcAgent.DependentServices.himds)" -ForegroundColor $(if ($status.ArcAgent.DependentServices.himds -eq "running") {"Green"} else {"Red"})
        }
        if ($status.ArcAgent.DependentServices.arcproxy) {
            Write-Host "     arcproxy:         $($status.ArcAgent.DependentServices.arcproxy)" -ForegroundColor $(if ($status.ArcAgent.DependentServices.arcproxy -eq "running") {"Green"} else {"Yellow"})
        }
        if ($status.ArcAgent.DependentServices.extensionservice) {
            Write-Host "     extensionservice: $($status.ArcAgent.DependentServices.extensionservice)" -ForegroundColor $(if ($status.ArcAgent.DependentServices.extensionservice -eq "running") {"Green"} else {"Red"})
        }
        if ($status.ArcAgent.DependentServices.gcarcservice) {
            Write-Host "     gcarcservice:     $($status.ArcAgent.DependentServices.gcarcservice)" -ForegroundColor $(if ($status.ArcAgent.DependentServices.gcarcservice -eq "running") {"Green"} else {"Red"})
        }
    } else {
        Write-Host "     (Unable to retrieve service status)" -ForegroundColor Gray
    }
    } else {
        Write-Host "   Agent Installed:  NO" -ForegroundColor Red
    }
    Write-Host ""
}

# Report 2: Certificates
if (-not $SkipArc) {
    $certSectionNumber = if ($SkipArc) { "1" } else { "2" }
    Write-Host "${certSectionNumber}. MANAGED IDENTITY CERTIFICATES" -ForegroundColor Green
    Write-Host "   ----------------------------------------"
    $criticalCerts = @()
    $warnCerts = @()
    foreach ($cert in $status.Certificates) {
        if ($cert.Status) {
            if ($cert.Status -eq "No certificates found" -or $cert.Status -eq "Certificate folder not found") {
                Write-Host "   $($cert.Status)" -ForegroundColor Yellow
            } elseif ($cert.Status -eq "EXPIRED") {
                Write-Host "   [$($cert.FileName)]" -ForegroundColor Red
                Write-Host "     Status: EXPIRED ($($cert.DaysRemaining) days overdue)" -ForegroundColor Red
                Write-Host "     Expired: $($cert.ExpiryDate)" -ForegroundColor Red
                $criticalCerts += $cert.FileName
            } elseif ($cert.Status -eq "Expiring Soon") {
                Write-Host "   [$($cert.FileName)]" -ForegroundColor Yellow
                Write-Host "     Status: Expiring Soon ($($cert.DaysRemaining) days left)" -ForegroundColor Yellow
                Write-Host "     Expires: $($cert.ExpiryDate)" -ForegroundColor Yellow
                $warnCerts += $cert.FileName
            } elseif ($cert.Status -eq "Valid") {
                Write-Host "   [$($cert.FileName)]" -ForegroundColor Green
                Write-Host "     Status: Valid ($($cert.DaysRemaining) days remaining)" -ForegroundColor Green
            } elseif ($cert.Status -eq "Error") {
                Write-Host "   [$($cert.FileName)] Error: $($cert.Error)" -ForegroundColor Red
            }
        }
    }
    Write-Host ""
}

# ==================== MICROSOFT DEFENDER FOR ENDPOINT CHECKS ====================
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  MICROSOFT DEFENDER FOR ENDPOINT       ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Report 3: MDE Onboarding
$mdeSectionNumber = if ($SkipArc) { "1" } else { "3" }
Write-Host "${mdeSectionNumber}. MICROSOFT DEFENDER FOR ENDPOINT - ONBOARDING" -ForegroundColor Green
Write-Host "   ----------------------------------------"
Write-Host "   Installation:" -ForegroundColor Cyan
Write-Host "     Install Path:     $($status.MDE.InstallPath)" -ForegroundColor $(if ($status.MDE.InstallPath -eq "Exists") {"Green"} else {"Red"})
Write-Host "     MsSense.exe:      $($status.MDE.SenseExeExists)" -ForegroundColor $(if ($status.MDE.SenseExeExists -match "Yes") {"Green"} else {"Red"})
Write-Host ""
Write-Host "   Service Status:" -ForegroundColor Cyan
Write-Host "     Sense Service:    $($status.MDE.SenseService)" -ForegroundColor $(if ($status.MDE.SenseService -eq "Running") {"Green"} else {"Red"})
Write-Host "     MsSense Process:  $($status.MDE.MsSenseProcess)" -ForegroundColor $(if ($status.MDE.MsSenseProcess -eq "Running") {"Green"} else {"Red"})
if ($status.MDE.SenseHealthState -ne "Unknown") {
    Write-Host "     Health State:     $($status.MDE.SenseHealthState)" -ForegroundColor $(if ($status.MDE.SenseHealthState -match "Healthy") {"Green"} else {"Yellow"})
}
Write-Host ""
Write-Host "   Onboarding Status:" -ForegroundColor Cyan
$onboardingColor = if ($status.MDE.OnboardingState -eq "Onboarded") {"Green"} elseif ($status.MDE.OnboardingState -match "Onboarded Locally") {"Yellow"} elseif ($status.MDE.OnboardingState -match "Incomplete|Failed") {"Red"} else {"Red"}
Write-Host "     Onboarding State: $($status.MDE.OnboardingState)" -ForegroundColor $onboardingColor
if ($status.MDE.OnboardingState -match "Never Connected") {
    Write-Host "                       Note: Registry shows onboarded but no cloud connection established" -ForegroundColor Yellow
} elseif ($status.MDE.OnboardingState -match "Incomplete|Failed") {
    Write-Host "                       Note: OnboardingState=1 but missing Organization ID (onboarding script failed)" -ForegroundColor Red
}
if ($status.MDE.OrgId -and $status.MDE.OrgId -ne "Not Available" -and $status.MDE.OrgId -ne "Error") {
    Write-Host "     Organization ID:  $($status.MDE.OrgId)" -ForegroundColor Cyan
    if ($status.MDE.OrgId -ne $ExpectedOrgId) {
        Write-Host "                       CRITICAL: Does not match expected ID!" -ForegroundColor Red
        Write-Host "                       Expected: $ExpectedOrgId" -ForegroundColor Yellow
    }
} else {
    Write-Host "     Organization ID:  $($status.MDE.OrgId)" -ForegroundColor Yellow
}
if ($status.MDE.LastConnected -and $status.MDE.LastConnected -ne "0" -and $status.MDE.LastConnected -ne 0) {
    if ($status.MDE.LastConnectedDateTime) {
        Write-Host "     Last Connected:   $($status.MDE.LastConnectedDateTime)" -ForegroundColor Cyan
        Write-Host "                       (Raw: $($status.MDE.LastConnected))" -ForegroundColor DarkGray
    } else {
        Write-Host "     Last Connected:   $($status.MDE.LastConnected) (Unable to convert)" -ForegroundColor Cyan
    }
} else {
    if ([string]::IsNullOrWhiteSpace($status.MDE.LastConnected)) {
        Write-Host "     Last Connected:   MISSING - Device has not connected to cloud" -ForegroundColor Red
    } elseif ($status.MDE.LastConnected -eq "0" -or $status.MDE.LastConnected -eq 0) {
        Write-Host "     Last Connected:   INVALID (0) - Device has not connected to cloud" -ForegroundColor Red
    } else {
        Write-Host "     Last Connected:   ERROR - $($status.MDE.LastConnected)" -ForegroundColor Red
    }
}
if ($status.MDE.CyberFolderState) {
    Write-Host "     Cyber Folder:     $($status.MDE.CyberFolderState)" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "   Platform Info:" -ForegroundColor Cyan
if ($status.MDE.PlatformVersion -ne "Unknown") {
    Write-Host "     Platform Ver:     $($status.MDE.PlatformVersion)" -ForegroundColor Green
    if ($status.MDE.VersionAge -ne "Unknown") {
        $versionColor = "Green"
        if ($status.MDE.VersionStatus -match "CRITICALLY OUTDATED") { $versionColor = "Red" }
        elseif ($status.MDE.VersionStatus -match "Outdated|Needs Update") { $versionColor = "Yellow" }
        Write-Host "     Version Age:      $($status.MDE.VersionAge)" -ForegroundColor $versionColor
        Write-Host "     Version Status:   $($status.MDE.VersionStatus)" -ForegroundColor $versionColor
    }
}
if ($status.MDE.EngineVersion -ne "Unknown") {
    Write-Host "     Engine Version:   $($status.MDE.EngineVersion)" -ForegroundColor Green
}
if ($status.MDE.RealTimeProtection -ne "Unknown") {
    Write-Host "     Real-time Prot:   $($status.MDE.RealTimeProtection)" -ForegroundColor $(if ($status.MDE.RealTimeProtection -eq "Enabled") {"Green"} else {"Yellow"})
}
Write-Host ""

# Report 3.1: MDE COMPREHENSIVE HEALTH VALIDATION
Write-Host "${mdeSectionNumber}.1 MDE COMPREHENSIVE HEALTH CHECK" -ForegroundColor Green
Write-Host "   ----------------------------------------"

# Perform comprehensive validation
$mdeHealthChecks = @{
    ServiceRunning = $false
    ProcessRunning = $false
    Onboarded = $false
    CloudConnected = $false
    SignaturesFresh = $false
    RealTimeProtectionOn = $false
    CloudProtectionOn = $false
    BehaviorMonitorOn = $false
    NetworkProtectionOn = $false
    TelemetryEnabled = $false
    GatewayReachable = $false
}

$mdeIssues = @()

# Check 1: Service Running
if ($status.MDE.SenseService -eq "Running" -or $status.MDE.SenseService -eq "running") {
    $mdeHealthChecks.ServiceRunning = $true
} else {
    $mdeIssues += "Sense service not running (Status: $($status.MDE.SenseService))"
}

# Check 2: Process Running
if ($status.MDE.MsSenseProcess) {
    $mdeHealthChecks.ProcessRunning = $true
} else {
    $mdeIssues += "MsSense.exe process not running"
}

# Check 3: Onboarded (registry state AND has OrgId)
if ($status.MDE.OnboardingState -eq "Onboarded" -or $status.MDE.OnboardingState -match "Onboarded Locally") {
    $mdeHealthChecks.Onboarded = $true
} else {
    $mdeIssues += "MDE not onboarded (State: $($status.MDE.OnboardingState))"
}

# Check 4: Cloud Connected
if ($status.MDE.LastConnected) {
    $mdeHealthChecks.CloudConnected = $true
} else {
    $mdeIssues += "No cloud connection established (LastConnected missing)"
}

# Check 5: Signatures Fresh (< 7 days)
if ($status.MDE.AntivirusSignatureAge -match "(\d+) days") {
    $days = [int]$matches[1]
    if ($days -le 7) {
        $mdeHealthChecks.SignaturesFresh = $true
    } else {
        $mdeIssues += "Signatures outdated ($days days old)"
    }
} elseif ($status.MDE.DefenderSignaturesOutOfDate -eq "No") {
    $mdeHealthChecks.SignaturesFresh = $true
}

if (-not $mdeHealthChecks.SignaturesFresh -and $status.MDE.AntivirusSignatureAge -ne "Unknown") {
    $mdeIssues += "Signatures not updated recently"
}

# Check 6: Real-Time Protection
if ($status.MDE.RealTimeProtection -eq "Enabled") {
    $mdeHealthChecks.RealTimeProtectionOn = $true
} else {
    $mdeIssues += "Real-time protection disabled"
}

# Check 7: Cloud Protection (MAPS) - Optional for streamlined connectivity
if ($status.MDE.MAPSReporting -match "Basic|Advanced") {
    $mdeHealthChecks.CloudProtectionOn = $true
} elseif ($status.MDE.StreamlinedConnectivity.CurrentlyUsing.Functional -eq $true) {
    # MAPS is optional when streamlined connectivity is working
    $mdeHealthChecks.CloudProtectionOn = $true  # Don't fail check
    $mdeIssues += "[OPTIONAL] MAPS disabled, but streamlined connectivity covers MDE cloud protection"
} else {
    $mdeIssues += "Cloud-delivered protection disabled (MAPS: $($status.MDE.MAPSReporting))"
}

# Check 8: Behavior Monitor
if ($status.MDE.BehaviorMonitorEnabled -eq "Enabled") {
    $mdeHealthChecks.BehaviorMonitorOn = $true
} else {
    $mdeIssues += "Behavior monitoring disabled"
}

# Check 9: Network Protection
if ($status.MDE.NetworkRealtimeInspectionEnabled -eq "Enabled") {
    $mdeHealthChecks.NetworkProtectionOn = $true
}

# Check 10: Telemetry - Consider streamlined connectivity
if ($status.MDE.MAPSReporting -ne "Disabled" -and $status.MDE.MAPSReporting -ne "Unknown") {
    $mdeHealthChecks.TelemetryEnabled = $true
} elseif ($status.MDE.StreamlinedConnectivity.CurrentlyUsing.Functional -eq $true) {
    # Streamlined connectivity handles telemetry through EDR endpoints
    $mdeHealthChecks.TelemetryEnabled = $true
}

# Check 11: Gateway Connectivity (from existing checks)
$mdeGatewayAll = @($status.ConnectivityChecks | Where-Object { 
    $_.Category -eq "MDE" -and 
    $_.URL -like "*winatp-gw-*"
})
$mdeGatewayPassed = @($mdeGatewayAll | Where-Object { $_.Status -eq "Passed" })

if ($mdeGatewayPassed.Count -gt 0) {
    $mdeHealthChecks.GatewayReachable = $true
    # Warn if only partial gateway connectivity
    if ($mdeGatewayAll.Count -gt 0 -and $mdeGatewayPassed.Count -lt $mdeGatewayAll.Count) {
        $mdeIssues += "Partial gateway connectivity ($($mdeGatewayPassed.Count)/$($mdeGatewayAll.Count) gateways reachable)"
    }
} else {
    $mdeIssues += "MDE gateway endpoints not reachable"
}

# Calculate health score
$totalChecks = $mdeHealthChecks.Keys.Count
$passedChecks = ($mdeHealthChecks.Values | Where-Object { $_ -eq $true }).Count
$healthPercentage = [math]::Round(($passedChecks / $totalChecks) * 100)

# Overall health status
Write-Host "   Overall MDE Health: " -NoNewline
if ($healthPercentage -ge 90) {
    Write-Host "FULLY OPERATIONAL ($passedChecks/$totalChecks checks passed - $healthPercentage%)" -ForegroundColor Green
} elseif ($healthPercentage -ge 70) {
    Write-Host "PARTIALLY FUNCTIONAL ($passedChecks/$totalChecks checks passed - $healthPercentage%)" -ForegroundColor Yellow
} else {
    Write-Host "DEGRADED/NOT FUNCTIONAL ($passedChecks/$totalChecks checks passed - $healthPercentage%)" -ForegroundColor Red
}
Write-Host ""

# Detailed checks
Write-Host "   Detailed Health Checks:" -ForegroundColor Cyan
Write-Host "     [$(if ($mdeHealthChecks.ServiceRunning) {'✓'} else {'✗'})] Sense Service Running" -ForegroundColor $(if ($mdeHealthChecks.ServiceRunning) {"Green"} else {"Red"})
Write-Host "     [$(if ($mdeHealthChecks.ProcessRunning) {'✓'} else {'✗'})] MsSense Process Active" -ForegroundColor $(if ($mdeHealthChecks.ProcessRunning) {"Green"} else {"Red"})
Write-Host "     [$(if ($mdeHealthChecks.Onboarded) {'✓'} else {'✗'})] MDE Onboarded (Registry State = 1)" -ForegroundColor $(if ($mdeHealthChecks.Onboarded) {"Green"} else {"Red"})
Write-Host "     [$(if ($mdeHealthChecks.CloudConnected) {'✓'} else {'✗'})] Cloud Connection Established" -ForegroundColor $(if ($mdeHealthChecks.CloudConnected) {"Green"} else {"Red"})
Write-Host "     [$(if ($mdeHealthChecks.SignaturesFresh) {'✓'} else {'✗'})] Signatures Up-to-Date (<7 days)" -ForegroundColor $(if ($mdeHealthChecks.SignaturesFresh) {"Green"} else {"Red"})
Write-Host "     [$(if ($mdeHealthChecks.RealTimeProtectionOn) {'✓'} else {'✗'})] Real-Time Protection Enabled" -ForegroundColor $(if ($mdeHealthChecks.RealTimeProtectionOn) {"Green"} else {"Red"})
# Show MAPS status with context about streamlined
    $mapsIcon = if ($mdeHealthChecks.CloudProtectionOn) {'✓'} elseif ($status.MDE.StreamlinedConnectivity.CurrentlyUsing.Functional) {'i'} else {'✗'}
    $mapsColor = if ($mdeHealthChecks.CloudProtectionOn) {"Green"} elseif ($status.MDE.StreamlinedConnectivity.CurrentlyUsing.Functional) {"Cyan"} else {"Red"}
    $mapsLabel = if ($status.MDE.StreamlinedConnectivity.CurrentlyUsing.Functional -and $status.MDE.MAPSReporting -notmatch "Basic|Advanced") { "Cloud-Delivered Protection (MAPS - Optional with Streamlined)" } else { "Cloud-Delivered Protection (MAPS)" }
    Write-Host "     [$mapsIcon] $mapsLabel" -ForegroundColor $mapsColor
Write-Host "     [$(if ($mdeHealthChecks.BehaviorMonitorOn) {'✓'} else {'✗'})] Behavior Monitoring Enabled" -ForegroundColor $(if ($mdeHealthChecks.BehaviorMonitorOn) {"Green"} else {"Red"})
Write-Host "     [$(if ($mdeHealthChecks.NetworkProtectionOn) {'✓'} else {'i'})] Network Inspection Enabled" -ForegroundColor $(if ($mdeHealthChecks.NetworkProtectionOn) {"Green"} else {"Gray"})
Write-Host "     [$(if ($mdeHealthChecks.TelemetryEnabled) {'✓'} else {'✗'})] Telemetry Enabled" -ForegroundColor $(if ($mdeHealthChecks.TelemetryEnabled) {"Green"} else {"Yellow"})
Write-Host "     [$(if ($mdeHealthChecks.GatewayReachable) {'✓'} else {'✗'})] Gateway Connectivity Working" -ForegroundColor $(if ($mdeHealthChecks.GatewayReachable) {"Green"} else {"Red"})
Write-Host ""

# Show detailed metrics
Write-Host "   Cloud Communication Metrics:" -ForegroundColor Cyan
if ($status.MDE.MAPSReporting -ne "Unknown") {
    Write-Host "     MAPS Reporting:   $($status.MDE.MAPSReporting)" -ForegroundColor $(if ($status.MDE.MAPSReporting -match "Basic|Advanced") {"Green"} else {"Yellow"})
}
if ($status.MDE.SubmitSamplesConsent -ne "Unknown") {
    Write-Host "     Sample Submission: $($status.MDE.SubmitSamplesConsent)" -ForegroundColor Gray
}
if ($status.MDE.SignatureUpdateLastChecked) {
    Write-Host "     Last Sig Update:  $($status.MDE.SignatureUpdateLastChecked)" -ForegroundColor $(if ($mdeHealthChecks.SignaturesFresh) {"Green"} else {"Yellow"})
}
if ($status.MDE.AntivirusSignatureAge -ne "Unknown") {
    Write-Host "     Signature Age:    $($status.MDE.AntivirusSignatureAge)" -ForegroundColor $(if ($mdeHealthChecks.SignaturesFresh) {"Green"} else {"Red"})
}
if ($status.MDE.DefenderSignaturesOutOfDate -ne "Unknown") {
    Write-Host "     Signatures Status: $(if ($status.MDE.DefenderSignaturesOutOfDate -eq 'No') {'Current'} else {'Out of Date'})" -ForegroundColor $(if ($status.MDE.DefenderSignaturesOutOfDate -eq "No") {"Green"} else {"Red"})
}
Write-Host ""

# Show issues summary
if ($mdeIssues.Count -gt 0) {
    Write-Host "   Issues Detected:" -ForegroundColor Yellow
    foreach ($issue in $mdeIssues) {
        Write-Host "     • $issue" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # Provide actionable fixes
    Write-Host "   Recommended Actions to Fix Issues:" -ForegroundColor Cyan
    Write-Host "   ─────────────────────────────────────" -ForegroundColor Cyan
    
    # Action 1: Service not running
    if (-not $mdeHealthChecks.ServiceRunning) {
        Write-Host ""
        Write-Host "   [1] Fix: Sense Service Not Running" -ForegroundColor Yellow
        Write-Host "       Command: Restart-Service Sense -Force" -ForegroundColor White
        Write-Host "       Verify:  Get-Service Sense | Select-Object Status, StartType" -ForegroundColor Gray
    }
    
    # Action 2: Process not running
    if (-not $mdeHealthChecks.ProcessRunning -and $mdeHealthChecks.ServiceRunning) {
        Write-Host ""
        Write-Host "   [2] Fix: MsSense Process Not Running (Service is running)" -ForegroundColor Yellow
        Write-Host "       This indicates a process crash or startup failure" -ForegroundColor Gray
        Write-Host "       Command: Restart-Service Sense -Force" -ForegroundColor White
        Write-Host "       Check Logs: Get-WinEvent -LogName 'Microsoft-Windows-SENSE/Operational' -MaxEvents 20" -ForegroundColor Gray
    }
    
    # Action 3: Not onboarded
    if (-not $mdeHealthChecks.Onboarded) {
        Write-Host ""
        Write-Host "   [3] Fix: MDE Not Onboarded" -ForegroundColor Yellow
        Write-Host "       Action: Device needs to be onboarded to Microsoft Defender for Endpoint" -ForegroundColor Gray
        Write-Host "       1. Obtain onboarding package from security.microsoft.com" -ForegroundColor White
        Write-Host "       2. Run: WindowsDefenderATPOnboardingScript.cmd" -ForegroundColor White
        Write-Host "       3. Restart service: Restart-Service Sense -Force" -ForegroundColor White
    }
    
    # Action 4: No cloud connection
    if (-not $mdeHealthChecks.CloudConnected -and $mdeHealthChecks.Onboarded) {
        Write-Host ""
        Write-Host "   [4] Fix: No Cloud Connection (LastConnected Missing)" -ForegroundColor Yellow
        Write-Host "       Root Cause: Firewall blocking MDE endpoints" -ForegroundColor Gray
        Write-Host "       Required Firewall Rules (for $Region region):" -ForegroundColor White
        
        # Region-specific gateway URLs
        switch ($Region) {
            "Australia" {
                Write-Host "       • https://winatp-gw-aus.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-aue.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-auc.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://au-v20.events.data.microsoft.com:443" -ForegroundColor Cyan
            }
            "US" {
                Write-Host "       • https://winatp-gw-us.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-use.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-usw.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://us-v20.events.data.microsoft.com:443" -ForegroundColor Cyan
            }
            "Europe" {
                Write-Host "       • https://winatp-gw-neu.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-weu.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-euc.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://eu-v20.events.data.microsoft.com:443" -ForegroundColor Cyan
            }
            "UK" {
                Write-Host "       • https://winatp-gw-uks.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-ukw.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-ukc.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://uk-v20.events.data.microsoft.com:443" -ForegroundColor Cyan
            }
            "Canada" {
                Write-Host "       • https://winatp-gw-cac.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-cae.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-caw.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://us-v20.events.data.microsoft.com:443" -ForegroundColor Cyan
            }
            "Asia" {
                Write-Host "       • https://winatp-gw-seas.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-eas.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-seas2.microsoft.com:443" -ForegroundColor Cyan
                Write-Host "       • https://seas-v20.events.data.microsoft.com:443" -ForegroundColor Cyan
            }
        }
        Write-Host "       • https://events.data.microsoft.com:443" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "       After firewall fix:" -ForegroundColor White
        Write-Host "       1. Restart-Service Sense -Force" -ForegroundColor White
        Write-Host "       2. Wait 5-10 minutes for connection" -ForegroundColor Gray
        Write-Host "       3. Verify: Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' | Select-Object LastConnected" -ForegroundColor White
    }
    
    # Action 5: Signatures outdated
    if (-not $mdeHealthChecks.SignaturesFresh) {
        Write-Host ""
        Write-Host "   [5] Fix: Signatures Outdated" -ForegroundColor Yellow
        if (-not $mdeHealthChecks.CloudConnected) {
            Write-Host "       Root Cause: No cloud connection - fix connectivity first" -ForegroundColor Red
        } elseif (-not $mdeHealthChecks.GatewayReachable) {
            Write-Host "       Root Cause: Update endpoints blocked by firewall" -ForegroundColor Red
            Write-Host "       Required URLs:" -ForegroundColor White
            Write-Host "       • https://definitionupdates.microsoft.com:443" -ForegroundColor Cyan
            Write-Host "       • https://go.microsoft.com:443" -ForegroundColor Cyan
            Write-Host "       • https://x.cp.wd.microsoft.com:443" -ForegroundColor Cyan
        } else {
            Write-Host "       Manual Update Command:" -ForegroundColor White
            Write-Host "       Update-MpSignature -UpdateSource MicrosoftUpdateServer" -ForegroundColor White
            Write-Host "       Verify: Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated" -ForegroundColor Gray
        }
    }
    
    # Action 6: Real-time protection disabled
    if (-not $mdeHealthChecks.RealTimeProtectionOn) {
        Write-Host ""
        Write-Host "   [6] Fix: Real-Time Protection Disabled" -ForegroundColor Yellow
        Write-Host "       Enable Command:" -ForegroundColor White
        Write-Host "       Set-MpPreference -DisableRealtimeMonitoring `$false" -ForegroundColor White
        Write-Host "       Verify: Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled" -ForegroundColor Gray
        Write-Host "       Note: Group Policy may override this setting" -ForegroundColor Yellow
    }
    
    # Action 7: Cloud protection disabled (skip if streamlined is working)
    if (-not $mdeHealthChecks.CloudProtectionOn -and -not $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Functional) {
        Write-Host ""
        Write-Host "   [7] Fix: Cloud-Delivered Protection Disabled" -ForegroundColor Yellow
        Write-Host "       Enable MAPS Reporting:" -ForegroundColor White
        Write-Host "       Set-MpPreference -MAPSReporting Advanced" -ForegroundColor White
        Write-Host "       Verify: Get-MpComputerStatus | Select-Object MAPSReporting" -ForegroundColor Gray
        Write-Host "       Note: Requires network connectivity to Microsoft cloud" -ForegroundColor Yellow
    } elseif (-not $mdeHealthChecks.CloudProtectionOn -and $status.MDE.StreamlinedConnectivity.CurrentlyUsing.Functional) {
        Write-Host ""
        Write-Host "   [INFO] MAPS Not Configured (Optional with Streamlined Connectivity)" -ForegroundColor Cyan
        Write-Host "         MDE cloud protection is working via streamlined connectivity" -ForegroundColor Gray
        Write-Host "         MAPS is a Windows Defender AV feature, not required for MDE EDR" -ForegroundColor Gray
        Write-Host "         Optional: Enable for additional AV cloud features" -ForegroundColor Gray
        Write-Host "         Set-MpPreference -MAPSReporting Advanced" -ForegroundColor DarkGray
    }
    
    # Action 8: Behavior monitoring disabled
    if (-not $mdeHealthChecks.BehaviorMonitorOn) {
        Write-Host ""
        Write-Host "   [8] Fix: Behavior Monitoring Disabled" -ForegroundColor Yellow
        Write-Host "       Enable Command:" -ForegroundColor White
        Write-Host "       Set-MpPreference -DisableBehaviorMonitoring `$false" -ForegroundColor White
        Write-Host "       Verify: Get-MpComputerStatus | Select-Object BehaviorMonitorEnabled" -ForegroundColor Gray
    }
    
    # Action 9: Gateway not reachable
    if (-not $mdeHealthChecks.GatewayReachable) {
        Write-Host ""
        Write-Host "   [9] Fix: MDE Gateway Endpoints Not Reachable" -ForegroundColor Yellow
        Write-Host "       Root Cause: Firewall blocking MDE cloud communication" -ForegroundColor Red
        Write-Host ""
        Write-Host "       Required Firewall Configuration:" -ForegroundColor White
        Write-Host "       Add these URLs to firewall/proxy allowlist:" -ForegroundColor Gray
        Write-Host ""
        Write-Host "       CRITICAL - MDE Gateways ($Region region):" -ForegroundColor Yellow
        
        $testGateway = ""
        switch ($Region) {
            "Australia" {
                Write-Host "       • https://winatp-gw-aus.microsoft.com:443 (Primary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-aue.microsoft.com:443 (Secondary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-auc.microsoft.com:443 (Tertiary)" -ForegroundColor Cyan
                $testGateway = "winatp-gw-aue.microsoft.com"
            }
            "US" {
                Write-Host "       • https://winatp-gw-us.microsoft.com:443 (Primary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-use.microsoft.com:443 (Secondary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-usw.microsoft.com:443 (Tertiary)" -ForegroundColor Cyan
                $testGateway = "winatp-gw-use.microsoft.com"
            }
            "Europe" {
                Write-Host "       • https://winatp-gw-neu.microsoft.com:443 (Primary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-weu.microsoft.com:443 (Secondary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-euc.microsoft.com:443 (Tertiary)" -ForegroundColor Cyan
                $testGateway = "winatp-gw-weu.microsoft.com"
            }
            "UK" {
                Write-Host "       • https://winatp-gw-uks.microsoft.com:443 (Primary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-ukw.microsoft.com:443 (Secondary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-ukc.microsoft.com:443 (Tertiary)" -ForegroundColor Cyan
                $testGateway = "winatp-gw-uks.microsoft.com"
            }
            "Canada" {
                Write-Host "       • https://winatp-gw-cac.microsoft.com:443 (Primary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-cae.microsoft.com:443 (Secondary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-caw.microsoft.com:443 (Tertiary)" -ForegroundColor Cyan
                $testGateway = "winatp-gw-cae.microsoft.com"
            }
            "Asia" {
                Write-Host "       • https://winatp-gw-seas.microsoft.com:443 (Primary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-eas.microsoft.com:443 (Secondary)" -ForegroundColor Cyan
                Write-Host "       • https://winatp-gw-seas2.microsoft.com:443 (Tertiary)" -ForegroundColor Cyan
                $testGateway = "winatp-gw-seas.microsoft.com"
            }
        }
        
        Write-Host ""
        Write-Host "       CRITICAL - Data Endpoints:" -ForegroundColor Yellow
        Write-Host "       • https://events.data.microsoft.com:443" -ForegroundColor Cyan
        switch ($Region) {
            "Australia" { Write-Host "       • https://au-v20.events.data.microsoft.com:443" -ForegroundColor Cyan }
            "US" { Write-Host "       • https://us-v20.events.data.microsoft.com:443" -ForegroundColor Cyan }
            "Europe" { Write-Host "       • https://eu-v20.events.data.microsoft.com:443" -ForegroundColor Cyan }
            "UK" { Write-Host "       • https://uk-v20.events.data.microsoft.com:443" -ForegroundColor Cyan }
            "Canada" { Write-Host "       • https://us-v20.events.data.microsoft.com:443" -ForegroundColor Cyan }
            "Asia" { Write-Host "       • https://seas-v20.events.data.microsoft.com:443" -ForegroundColor Cyan }
        }
        Write-Host ""
        Write-Host "       Test Connectivity:" -ForegroundColor White
        Write-Host "       Test-NetConnection -ComputerName $testGateway -Port 443" -ForegroundColor White
        Write-Host ""
        Write-Host "       After firewall fix: Restart-Service Sense -Force" -ForegroundColor White
    }
    
    Write-Host ""
}

# Final verdict
if ($healthPercentage -ge 90) {
    Write-Host "   VERDICT: MDE is FULLY FUNCTIONAL and protecting this device" -ForegroundColor Green
} elseif ($healthPercentage -ge 70) {
    Write-Host "   VERDICT: MDE is PARTIALLY working but has issues that need attention" -ForegroundColor Yellow
} else {
    Write-Host "   VERDICT: MDE is NOT FULLY OPERATIONAL - requires immediate attention" -ForegroundColor Red
}
Write-Host ""

# Report 3.2: Additional MDE Onboarding Validation (Microsoft Documentation Checks)
Write-Host "${mdeSectionNumber}.2 ADDITIONAL MDE ONBOARDING VALIDATION" -ForegroundColor Green
Write-Host "   ----------------------------------------"

# DiagTrack Service Check
Write-Host "   DiagTrack Service (Windows Diagnostic Data):" -ForegroundColor Cyan
Write-Host "     Status:      $($status.MDE.DiagTrackService.Status)" -ForegroundColor $(if ($status.MDE.DiagTrackService.Status -eq "Running") {"Green"} else {"Yellow"})
Write-Host "     Start Type:  $($status.MDE.DiagTrackService.StartType)" -ForegroundColor $(if ($status.MDE.DiagTrackService.StartType -eq "Automatic") {"Green"} else {"Yellow"})
if ($status.MDE.DiagTrackService.Issue) {
    Write-Host "     Issue:       $($status.MDE.DiagTrackService.Issue)" -ForegroundColor Yellow
    Write-Host "     Action:      sc config diagtrack start=auto && sc start diagtrack" -ForegroundColor Gray
}
Write-Host ""

# ELAM Driver Check
Write-Host "   Windows Defender ELAM Driver:" -ForegroundColor Cyan
Write-Host "     DisableAntiSpyware: $($status.MDE.ELAMDriver.DisableAntiSpyware)" -ForegroundColor $(if ($status.MDE.ELAMDriver.DisableAntiSpyware -eq 1) {"Red"} else {"Green"})
Write-Host "     DisableAntiVirus:   $($status.MDE.ELAMDriver.DisableAntiVirus)" -ForegroundColor $(if ($status.MDE.ELAMDriver.DisableAntiVirus -eq 1) {"Red"} else {"Green"})
if ($status.MDE.ELAMDriver.Issue) {
    Write-Host "     Issue:              $($status.MDE.ELAMDriver.Issue)" -ForegroundColor Red
    Write-Host "     Action:             Remove DisableAntiSpyware and DisableAntiVirus policies" -ForegroundColor Gray
}
Write-Host ""

# Windows Defender Services
Write-Host "   Windows Defender Core Services:" -ForegroundColor Cyan
foreach ($svcName in $status.MDE.DefenderServices.Keys | Sort-Object) {
    $svc = $status.MDE.DefenderServices[$svcName]
    $statusColor = if ($svc.Status -eq "Running" -or $svc.StartType -match "Auto|Manual") {"Green"} else {"Yellow"}
    Write-Host "     $($svcName.PadRight(12)): $($svc.Status)" -ForegroundColor $statusColor
}
Write-Host ""

# SENSE FoD Check
Write-Host "   SENSE Feature on Demand:" -ForegroundColor Cyan
Write-Host "     Installed:   $($status.MDE.SenseFoD.Installed)" -ForegroundColor $(if ($status.MDE.SenseFoD.Installed -eq "Yes") {"Green"} elseif ($status.MDE.SenseFoD.Installed -eq "No") {"Red"} else {"Yellow"})
if ($status.MDE.SenseFoD.Installed -eq "No") {
    Write-Host "     Action:      Install SENSE FoD using:" -ForegroundColor Gray
    Write-Host "                  Add-WindowsCapability -Online -Name Microsoft.Windows.Sense.Client~~~~" -ForegroundColor White
}
Write-Host ""

# Registry Health
Write-Host "   MDE Registry Health:" -ForegroundColor Cyan
Write-Host "     Policy Key Exists:  $($status.MDE.RegistryHealth.PolicyKeyExists)" -ForegroundColor $(if ($status.MDE.RegistryHealth.PolicyKeyExists) {"Green"} else {"Red"})
Write-Host "     Status Key Exists:  $($status.MDE.RegistryHealth.StatusKeyExists)" -ForegroundColor $(if ($status.MDE.RegistryHealth.StatusKeyExists) {"Green"} else {"Red"})
if ($status.MDE.RegistryHealth.OnboardingStateValue -ne $null) {
    Write-Host "     OnboardingState:    $($status.MDE.RegistryHealth.OnboardingStateValue)" -ForegroundColor $(if ($status.MDE.RegistryHealth.OnboardingStateValue -eq 1) {"Green"} else {"Red"})
}
if ($status.MDE.RegistryHealth.Issue) {
    Write-Host "     Issue:              $($status.MDE.RegistryHealth.Issue)" -ForegroundColor Yellow
}
Write-Host ""

# Event Log Errors
Write-Host "   SENSE Event Log Analysis (Last 24 hours):" -ForegroundColor Cyan
if ($status.MDE.EventLogErrors.RecentErrorCount -is [int]) {
    Write-Host "     Error Count:     $($status.MDE.EventLogErrors.RecentErrorCount)" -ForegroundColor $(if ($status.MDE.EventLogErrors.RecentErrorCount -eq 0) {"Green"} else {"Yellow"})
    
    if ($status.MDE.EventLogErrors.CriticalErrors.Count -gt 0) {
        Write-Host "     Critical Events:" -ForegroundColor Red
        foreach ($evt in $status.MDE.EventLogErrors.CriticalErrors) {
            Write-Host "       Event ID $($evt.EventId): $($evt.Message.Substring(0, [Math]::Min(80, $evt.Message.Length)))..." -ForegroundColor Yellow
            Write-Host "       Time: $($evt.TimeCreated)" -ForegroundColor Gray
        }
        Write-Host "       Check: Get-WinEvent -LogName 'Microsoft-Windows-SENSE/Operational' -MaxEvents 50" -ForegroundColor Gray
    }
} else {
    Write-Host "     Status:          $($status.MDE.EventLogErrors.RecentErrorCount)" -ForegroundColor Yellow
}
Write-Host ""

# Report 3.3: Streamlined Connectivity Prerequisites
Write-Host "${mdeSectionNumber}.3 STREAMLINED CONNECTIVITY PREREQUISITES" -ForegroundColor Green
Write-Host "   ----------------------------------------" -ForegroundColor Green
Write-Host "   Reference: https://learn.microsoft.com/en-us/defender-endpoint/configure-device-connectivity#prerequisites" -ForegroundColor DarkGray
Write-Host ""

$streamlinedStatus = $status.MDE.StreamlinedConnectivity
$streamlinedColor = if ($streamlinedStatus.Supported) { "Green" } else { "Yellow" }

Write-Host "   Overall Status:   $(if ($streamlinedStatus.Supported) { 'SUPPORTED' } else { 'NOT FULLY SUPPORTED' })" -ForegroundColor $streamlinedColor
Write-Host "   Summary:          $($streamlinedStatus.Summary)" -ForegroundColor Cyan
Write-Host ""

Write-Host "   Prerequisite Checks:" -ForegroundColor Cyan
Write-Host "     [$(if ($streamlinedStatus.OSSupported) { '✓' } else { '✗' })] Operating System:      $($streamlinedStatus.Details.OSVersion)" -ForegroundColor $(if ($streamlinedStatus.OSSupported) { "Green" } else { "Red" })
Write-Host "     [$(if ($streamlinedStatus.KBUpdateSupported) { '✓' } else { '✗' })] Required KB Update:    $($streamlinedStatus.Details.KBUpdate)" -ForegroundColor $(if ($streamlinedStatus.KBUpdateSupported) { "Green" } else { "Red" })
Write-Host "     [$(if ($streamlinedStatus.SenseVersionSupported) { '✓' } else { '✗' })] SENSE Version:        $($streamlinedStatus.Details.SenseVersion)" -ForegroundColor $(if ($streamlinedStatus.SenseVersionSupported) { "Green" } else { "Red" })
Write-Host "     [$(if ($streamlinedStatus.AMVersionSupported) { '✓' } else { '✗' })] AM Client Version:    $($streamlinedStatus.Details.AMClientVersion)" -ForegroundColor $(if ($streamlinedStatus.AMVersionSupported) { "Green" } else { "Red" })
Write-Host "     [$(if ($streamlinedStatus.EngineVersionSupported) { '✓' } else { '✗' })] Engine Version:       $($streamlinedStatus.Details.EngineVersion)" -ForegroundColor $(if ($streamlinedStatus.EngineVersionSupported) { "Green" } else { "Red" })
Write-Host "     [$(if ($streamlinedStatus.SecurityIntelligenceSupported) { '✓' } else { '✗' })] Security Intelligence: $($streamlinedStatus.Details.SecurityIntelligence)" -ForegroundColor $(if ($streamlinedStatus.SecurityIntelligenceSupported) { "Green" } else { "Red" })
Write-Host ""

# Display current connectivity method in use
# Add Server 2016/2012 R2 specific guidance
if ($status.OperatingSystem -match "Server 2016|Server 2012 R2") {
    Write-Host "" 
    Write-Host "   ⚠️  IMPORTANT: Windows Server 2016/2012 R2 Guidance" -ForegroundColor Yellow
    Write-Host "   ─────────────────────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   Streamlined connectivity is NOT supported via KB updates for Server 2016/2012 R2" -ForegroundColor Yellow
    Write-Host "" 
    Write-Host "   Alternative Option: Modern Unified Solution Agent" -ForegroundColor Cyan
    Write-Host "     • Requires downloading and installing the modern unified solution package" -ForegroundColor Gray
    Write-Host "     • Provides streamlined connectivity without KB updates" -ForegroundColor Gray
    Write-Host "     • Reference: https://learn.microsoft.com/en-us/defender-endpoint/server-migration" -ForegroundColor Gray
    Write-Host "" 
    Write-Host "   Current Status: Using Standard Connectivity (Classic Method)" -ForegroundColor Cyan
    Write-Host "     • This is the expected configuration for Server 2016/2012 R2" -ForegroundColor Gray
    Write-Host "     • Standard connectivity remains fully supported" -ForegroundColor Gray
    Write-Host "" 
}

Write-Host "   Currently Using:" -ForegroundColor Cyan
$currentMethod = $streamlinedStatus.CurrentlyUsing.Method
$isConfigured = $streamlinedStatus.CurrentlyUsing.Configured
$isFunctional = $streamlinedStatus.CurrentlyUsing.Functional

# Determine color based on functional status
if ($currentMethod -match "Streamlined" -and $isFunctional) {
    $methodColor = "Green"
    $statusIcon = "✅"
} elseif ($currentMethod -match "Streamlined" -and $isConfigured -and -not $isFunctional) {
    $methodColor = "Red"
    $statusIcon = "⚠️"
} elseif ($currentMethod -match "Standard") {
    $methodColor = "Yellow"
    $statusIcon = "ℹ️"
} else {
    $methodColor = "Gray"
    $statusIcon = " "
}

Write-Host "     $statusIcon Connectivity Method: $currentMethod" -ForegroundColor $methodColor

# Show functional status for streamlined
if ($currentMethod -match "Streamlined") {
    if ($isFunctional) {
        Write-Host "     Status: FUNCTIONAL - Streamlined connectivity is working" -ForegroundColor Green
    } else {
        Write-Host "     Status: NOT FUNCTIONAL - Configuration present but connectivity blocked" -ForegroundColor Red
    }
}

if ($streamlinedStatus.CurrentlyUsing.StreamlinedDomain -ne "Not tested") {
    $domainColor = if ($streamlinedStatus.CurrentlyUsing.StreamlinedDomain -eq "Reachable") { "Green" } else { "Red" }
    Write-Host "     Streamlined Domain:  $($streamlinedStatus.CurrentlyUsing.StreamlinedDomain) (*.endpoint.security.microsoft.com)" -ForegroundColor $domainColor
}

if ($streamlinedStatus.CurrentlyUsing.Evidence.Count -gt 0) {
    Write-Host "     Detection Evidence:" -ForegroundColor Gray
    foreach ($evidence in $streamlinedStatus.CurrentlyUsing.Evidence) {
        Write-Host "       • $evidence" -ForegroundColor Gray
    }
}

# Show issues with current configuration
if ($streamlinedStatus.CurrentlyUsing.Issues.Count -gt 0) {
    Write-Host "     Configuration Issues:" -ForegroundColor Red
    foreach ($issue in $streamlinedStatus.CurrentlyUsing.Issues) {
        Write-Host "       ⚠️  $issue" -ForegroundColor Yellow
    }
}
Write-Host ""

if ($streamlinedStatus.Issues.Count -gt 0) {
    Write-Host "   Issues Found:" -ForegroundColor Yellow
    foreach ($issue in $streamlinedStatus.Issues) {
        Write-Host "     • $issue" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($streamlinedStatus.Supported) {
    Write-Host "   ✅ This device MEETS all prerequisites for streamlined connectivity" -ForegroundColor Green
    
    # Check if already using streamlined
    if ($streamlinedStatus.CurrentlyUsing.InUse -and $streamlinedStatus.CurrentlyUsing.Functional) {
        Write-Host "   ✅ Device is ALREADY USING streamlined connectivity (FUNCTIONAL)" -ForegroundColor Green
        Write-Host "   Current configuration:" -ForegroundColor Cyan
        Write-Host "     • Simplified domain: *.endpoint.security.microsoft.com" -ForegroundColor Gray
        Write-Host "     • Reduced URL set for easier firewall configuration" -ForegroundColor Gray
        Write-Host "     • No migration needed" -ForegroundColor Gray
    } elseif ($streamlinedStatus.CurrentlyUsing.Configured -and -not $streamlinedStatus.CurrentlyUsing.Functional) {
        Write-Host "   ⚠️  Device is CONFIGURED for streamlined but NOT FUNCTIONAL" -ForegroundColor Red
        Write-Host "   Problem: Streamlined domain is unreachable - connectivity blocked" -ForegroundColor Red
        Write-Host "" 
        Write-Host "   Required Actions:" -ForegroundColor Yellow
        Write-Host "     1. Add firewall rules to allow:" -ForegroundColor Gray
        Write-Host "        • *.endpoint.security.microsoft.com:443" -ForegroundColor Gray
        Write-Host "        • Specific endpoints like edr-*.endpoint.security.microsoft.com:443" -ForegroundColor Gray
        Write-Host "     2. Also ensure standard fallback URLs are accessible:" -ForegroundColor Gray
        Write-Host "        • winatp-gw-*.microsoft.com:443" -ForegroundColor Gray
        Write-Host "        • events.data.microsoft.com:443" -ForegroundColor Gray
        Write-Host "        • go.microsoft.com:443" -ForegroundColor Gray
        Write-Host "        • definitionupdates.microsoft.com:443" -ForegroundColor Gray
        Write-Host "     3. Restart SENSE service: Restart-Service Sense -Force" -ForegroundColor Gray
        Write-Host "     4. Verify connectivity: Test-NetConnection endpoint.security.microsoft.com -Port 443" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   Alternative: If firewall changes not possible:" -ForegroundColor Cyan
        Write-Host "     • Re-onboard using standard connectivity package" -ForegroundColor Gray
        Write-Host "     • Download from portal with 'Standard' connectivity type" -ForegroundColor Gray
    } elseif ($streamlinedStatus.CurrentlyUsing.Method -match "Standard") {
        Write-Host "   ℹ️  Device is currently using STANDARD connectivity" -ForegroundColor Yellow
        Write-Host "   Migration to streamlined is available:" -ForegroundColor Cyan
        Write-Host "     1. Download new streamlined onboarding package from Microsoft Defender portal" -ForegroundColor Gray
        Write-Host "        Settings > Endpoints > Device management > Onboarding" -ForegroundColor Gray
        Write-Host "        Select 'Streamlined' from Connectivity type dropdown" -ForegroundColor Gray
        Write-Host "     2. Apply the new onboarding package" -ForegroundColor Gray
        Write-Host "     3. Reboot the device" -ForegroundColor Gray
        Write-Host "     4. Verify connectivity to *.endpoint.security.microsoft.com" -ForegroundColor Gray
        Write-Host "     Reference: https://learn.microsoft.com/en-us/defender-endpoint/migrate-devices-streamlined" -ForegroundColor DarkGray
    } else {
        Write-Host "   You can onboard using the streamlined method with:" -ForegroundColor Cyan
        Write-Host "     • Simplified domain: *.endpoint.security.microsoft.com" -ForegroundColor Gray
        Write-Host "     • Reduced URL set for easier firewall configuration" -ForegroundColor Gray
        Write-Host "     • Static IP ranges (optional alternative)" -ForegroundColor Gray
    }
} else {
    Write-Host "   ⚠️  This device DOES NOT meet all prerequisites for streamlined connectivity" -ForegroundColor Yellow
    
    # Special case: Streamlined configured but OS doesn't support it
    if ($streamlinedStatus.CurrentlyUsing.Configured -and -not $osSupported) {
        Write-Host ""
        Write-Host "   ⚠️  CRITICAL CONFIGURATION ISSUE:" -ForegroundColor Red
        Write-Host "   Device is configured for streamlined connectivity, but OS does not support it!" -ForegroundColor Red
        Write-Host ""
        Write-Host "   Current OS: $osCaption (Build $osBuild)" -ForegroundColor Yellow
        Write-Host "   Issue: Windows Server 2012 R2 / 2016 require modern unified agent for streamlined" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   Required Actions (Choose one):" -ForegroundColor Cyan
        Write-Host "   Option 1 - Upgrade to Unified Agent:" -ForegroundColor White
        Write-Host "     • Uninstall current MDE installation" -ForegroundColor Gray
        Write-Host "     • Install modern unified solution via MSI installer" -ForegroundColor Gray
        Write-Host "     • Re-onboard with streamlined package" -ForegroundColor Gray
        Write-Host "     • Reference: https://learn.microsoft.com/en-us/defender-endpoint/server-migration" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "   Option 2 - Switch to Standard Connectivity (Recommended for Server 2012 R2):" -ForegroundColor White
        Write-Host "     • Download standard onboarding package from portal" -ForegroundColor Gray
        Write-Host "     • Settings > Endpoints > Onboarding > Select 'Standard' connectivity" -ForegroundColor Gray
        Write-Host "     • Offboard current configuration" -ForegroundColor Gray
        Write-Host "     • Re-onboard with standard package" -ForegroundColor Gray
        Write-Host "     • Configure firewall for standard endpoints (winatp-gw-*.microsoft.com)" -ForegroundColor Gray
        Write-Host ""
    } else {
        Write-Host "   Required Actions:" -ForegroundColor Yellow
        Write-Host "     • Update OS/SENSE/Defender versions to meet minimum requirements" -ForegroundColor Gray
        Write-Host "     • Continue using standard connectivity method until prerequisites are met" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "   Minimum Requirements (per Microsoft documentation):" -ForegroundColor Cyan
Write-Host "     • OS: Windows 10 1809+, Windows 11, Windows Server 2019+" -ForegroundColor Gray
Write-Host "     • KB Update: March 8, 2022 update or later for your OS version" -ForegroundColor Gray
Write-Host "       - Windows 11: KB5011493" -ForegroundColor Gray
Write-Host "       - Windows 10 22H2: KB5020953 (October 28, 2022)" -ForegroundColor Gray
Write-Host "       - Windows 10 20H2/21H2: KB5011487" -ForegroundColor Gray
Write-Host "       - Windows 10 19H2 (1909): KB5011485" -ForegroundColor Gray
Write-Host "       - Windows 10 1809: KB5011503" -ForegroundColor Gray
Write-Host "       - Windows Server 2022: KB5011497" -ForegroundColor Gray
Write-Host "       - Windows Server 2019: KB5011503" -ForegroundColor Gray
Write-Host "     • SENSE: Version 10.8040.* or higher (March 2022+)" -ForegroundColor Gray
Write-Host "     • AM Client: Version 4.18.2211.5 or higher" -ForegroundColor Gray
Write-Host "     • Engine: Version 1.1.19900.2 or higher" -ForegroundColor Gray
Write-Host "     • Security Intelligence: Current and up-to-date" -ForegroundColor Gray
Write-Host ""

# ==================== ADDITIONAL CHECKS ====================
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     ADDITIONAL SYSTEM CHECKS           ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Report 4: Windows Setup Status
$setupSectionNumber = if ($SkipArc) { "2" } else { "4" }
Write-Host "${setupSectionNumber}. WINDOWS SETUP STATUS" -ForegroundColor Green
Write-Host "   ----------------------------------------"
Write-Host "   Setup Status:     $($status.WindowsSetup.Status)" -ForegroundColor $(if ($status.WindowsSetup.Status -eq "Completed") {"Green"} elseif ($status.WindowsSetup.Status -match "In Progress") {"Yellow"} else {"Red"})
if ($status.WindowsSetup.ImageState -and $status.WindowsSetup.ImageState -ne "Not Found" -and $status.WindowsSetup.ImageState -ne "Path Not Found") {
    Write-Host "   ImageState Value: '$($status.WindowsSetup.ImageState)'" -ForegroundColor Cyan
} else {
    Write-Host "   ImageState:       $($status.WindowsSetup.ImageState)" -ForegroundColor Yellow
}
Write-Host "   Registry Path:    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" -ForegroundColor DarkGray
Write-Host ""

# ==================== AZURE ARC EXTENSIONS ====================
if (-not $SkipArc) {
    Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     AZURE ARC EXTENSIONS               ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# Report 4.1: Extension Service Status
if (-not $SkipArc) {
    Write-Host "${setupSectionNumber}.1 AZURE ARC EXTENSION SERVICE" -ForegroundColor Green
Write-Host "   ----------------------------------------"
if ($status.ExtensionService.Status -eq "Running") {
    Write-Host "   Extension Service: RUNNING" -ForegroundColor Green
    Write-Host "   Start Type:        $($status.ExtensionService.StartType)" -ForegroundColor Cyan
} elseif ($status.ExtensionService.Status -eq "Stopped") {
    Write-Host "   Extension Service: STOPPED" -ForegroundColor Red
    Write-Host "   Start Type:        $($status.ExtensionService.StartType)" -ForegroundColor Yellow
    Write-Host "   Impact:            Extensions cannot install/update when service is stopped" -ForegroundColor Yellow
} else {
    Write-Host "   Extension Service: $($status.ExtensionService.Status)" -ForegroundColor Yellow
}
if ($status.ExtensionService.LogExists) {
    Write-Host "   Extension Log:     Available at $($status.ExtensionService.LogPath)" -ForegroundColor Gray
} else {
    Write-Host "   Extension Log:     Not found (service may not have started)" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Report 5: Extensions
if (-not $SkipArc) {
    $extSectionNumber = if ($SkipArc) { "3" } else { "5" }
    Write-Host "${extSectionNumber}. AZURE ARC EXTENSIONS" -ForegroundColor Green
Write-Host "   ----------------------------------------"
Write-Host "   NOTE: This section shows TWO types of extension checks:" -ForegroundColor Cyan
Write-Host "         1. Azure Policy Status - Shows if Azure sent configuration to this server" -ForegroundColor Cyan
Write-Host "         2. Local Installation Status - Shows if extension actually installed on disk" -ForegroundColor Cyan
Write-Host ""
if ($status.Extensions.Count -gt 0) {
    foreach ($ext in $status.Extensions) {
        $displayName = $ext.Name
        if ($ext.Installed -ne $null) {
            # Specific extension check (Local Installation Status)
            if ($ext.Installed) {
                $extColor = "Green"
                if ($ext.DetailedStatus -match "error|failed") { $extColor = "Red" }
                elseif ($ext.DetailedStatus -match "transitioning|warning") { $extColor = "Yellow" }
                
                Write-Host "   [$displayName] - LOCAL INSTALLATION CHECK" -ForegroundColor $extColor
                Write-Host "     Installation: FOUND (Extension exists at C:\Packages\Plugins\)" -ForegroundColor Green
                
                if ($ext.Version) {
                    Write-Host "     Version: $($ext.Version)" -ForegroundColor Gray
                }
                if ($ext.DetailedStatus -and $ext.DetailedStatus -ne "Unknown") {
                    Write-Host "     Status: $($ext.DetailedStatus)" -ForegroundColor $extColor
                }
                
                # Show onboarding success information
                if ($ext.OnboardingSuccess) {
                    Write-Host "     Onboarding: SUCCESS" -ForegroundColor Green
                    if ($ext.MachineId) {
                        Write-Host "     Machine ID: $($ext.MachineId)" -ForegroundColor Gray
                    }
                    if ($ext.WorkspaceId) {
                        Write-Host "     Workspace ID: $($ext.WorkspaceId)" -ForegroundColor Gray
                    }
                    if ($ext.OnboardingDetails) {
                        Write-Host "     Details:" -ForegroundColor Cyan
                        Write-Host "       • OS: $($ext.OnboardingDetails.osDetails.osName)" -ForegroundColor Gray
                        Write-Host "       • Azure Resource: $(($ext.OnboardingDetails.azureResourceId -split '/')[-1])" -ForegroundColor Gray
                        if ($ext.OnboardingDetails.proxyUri) {
                            Write-Host "       • Proxy: $($ext.OnboardingDetails.proxyUri)" -ForegroundColor Gray
                        } else {
                            Write-Host "       • Proxy: Not configured (direct connection)" -ForegroundColor Gray
                        }
                    }
                }
                
                if ($ext.HandlerState -and $ext.HandlerState -ne "Unknown") {
                    Write-Host "     Handler State: $($ext.HandlerState)" -ForegroundColor $(if ($ext.HandlerState -eq "Enabled") {"Green"} else {"Yellow"})
                }
                if ($ext.ErrorCode -and -not $ext.OnboardingSuccess) {
                    Write-Host "     Error Code: $($ext.ErrorCode)" -ForegroundColor Red
                }
                if ($ext.ErrorMessage) {
                    Write-Host "     Error: $($ext.ErrorMessage)" -ForegroundColor Red
                }
                if ($ext.StatusMessage) {
                    Write-Host "     Message: $($ext.StatusMessage)" -ForegroundColor Cyan
                }
                if ($ext.ConnectivityIssue) {
                    Write-Host "     Issue Detected: Connectivity problem during installation" -ForegroundColor Yellow
                }
                if ($ext.TimeoutIssue) {
                    Write-Host "     Issue Detected: Timeout downloading updated installer" -ForegroundColor Yellow
                }
                if ($ext.InstallationFailed) {
                    Write-Host "     Issue Detected: MDE agent installation failed" -ForegroundColor Red
                }
                if ($ext.LogFile) {
                    Write-Host "     Log: $($ext.LogFile)" -ForegroundColor DarkGray
                }
                if ($ext.ServiceStatus -and $ext.ServiceStatus -ne "N/A") {
                    Write-Host "     Service: $($ext.ServiceStatus)" -ForegroundColor $(if ($ext.ServiceStatus -eq "Running") {"Green"} else {"Red"})
                }
            } else {
                Write-Host "   [$displayName] - LOCAL INSTALLATION CHECK" -ForegroundColor Gray
                Write-Host "     Installation: NOT FOUND (Extension does not exist at C:\Packages\Plugins\)" -ForegroundColor Red
                Write-Host "     Meaning: Extension installation failed or was never attempted" -ForegroundColor Yellow
            }
        } else {
            # General extension from logs (Azure Policy Status)
            $statusColor = "Yellow"
            if ($ext.Status -match "success|ready|enabled") { $statusColor = "Green" }
            elseif ($ext.Status -match "error|failed") { $statusColor = "Red" }
            
            Write-Host "   [$displayName] - AZURE POLICY CHECK" -ForegroundColor $statusColor
            Write-Host "     Extension Status: $($ext.Status)" -ForegroundColor $statusColor
            
            # Show status file path if available
            if ($ext.StatusFilePath) {
                Write-Host "     Status File: $($ext.StatusFilePath)" -ForegroundColor DarkGray
            }
            
            # Show RuntimeSettings information with clear explanation
            if ($ext.RuntimeSettings) {
                if ($ext.RuntimeSettings.Found) {
                    Write-Host "     Azure Policy: ASSIGNED (Azure sent configuration to this server)" -ForegroundColor Green
                    Write-Host "     Config Received: $($ext.RuntimeSettings.ConfigCount) settings file(s)" -ForegroundColor Green
                    Write-Host "     Last Updated:    $($ext.RuntimeSettings.LastModified)" -ForegroundColor Gray
                    Write-Host "     Meaning: Azure Resource Manager deployed this extension policy" -ForegroundColor Cyan
                } else {
                    Write-Host "     Azure Policy: NOT ASSIGNED (No configuration sent)" -ForegroundColor Red
                    Write-Host "     Issue: Extension policy not deployed from Azure portal" -ForegroundColor Yellow
                }
            }
            
            if ($ext.Status -match "See logs for details") {
                Write-Host "" -ForegroundColor DarkGray
                Write-Host "     EXPLANATION: 'See logs for details' means:" -ForegroundColor Yellow
                Write-Host "     - Status file exists but format is non-standard" -ForegroundColor Gray
                Write-Host "     - Extension may be installing, running, or encountering issues" -ForegroundColor Gray
                Write-Host "     - Check logs for actual operational status" -ForegroundColor Gray
            }
            
            if ($ext.Status -match "No status file") {
                Write-Host "" -ForegroundColor DarkGray
                Write-Host "     EXPLANATION: Portal vs Local Status Difference" -ForegroundColor Yellow
                Write-Host "     - Azure Portal: Shows deployment status (from Azure cloud)" -ForegroundColor Gray
                Write-Host "     - This Script: Shows execution status (from local files)" -ForegroundColor Gray
                Write-Host "     - 'No status file' = Extension hasn't written status yet" -ForegroundColor Gray
                Write-Host "     - This is NORMAL for newly deployed extensions (wait 5-10 min)" -ForegroundColor Cyan
                Write-Host "     - Check logs: $($status.ExtensionService.LogPath)" -ForegroundColor DarkGray
            }
            if ($ext.Message) {
                Write-Host "     Message: $($ext.Message)" -ForegroundColor Gray
            }
        }
        Write-Host ""
    }
} else {
    Write-Host "   No extensions found" -ForegroundColor Yellow
}
Write-Host ""
}

# ==================== CONNECTIVITY CHECKS ====================
Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     CONNECTIVITY CHECKS                ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Report 6: Connectivity
$connSectionNumber = if ($SkipArc) { "3" } else { "6" }
Write-Host "${connSectionNumber}. CONNECTIVITY CHECK" -ForegroundColor Green
Write-Host "   ----------------------------------------"
if ($status.ConnectivityChecks -and $status.ConnectivityChecks.Count -gt 0) {
    # Separate Arc, MDE.Windows, and MDE checks
    $arcChecks = $status.ConnectivityChecks | Where-Object { $_.Category -eq "Azure Arc" }
    $mdeWindowsChecks = $status.ConnectivityChecks | Where-Object { $_.Category -eq "MDE.Windows" }
    $mdeChecks = $status.ConnectivityChecks | Where-Object { $_.Category -eq "MDE" }
    
    $totalPassed = ($status.ConnectivityChecks | Where-Object { $_.Status -eq "Passed" }).Count
    $totalFailed = ($status.ConnectivityChecks | Where-Object { $_.Status -eq "Failed" }).Count
    
    Write-Host "   Overall Summary: $totalPassed Passed, $totalFailed Failed" -ForegroundColor $(if ($totalFailed -eq 0) {"Green"} else {"Red"})
    Write-Host ""
    
    # Display Azure Arc endpoints
    if (-not $SkipArc -and $arcChecks.Count -gt 0) {
        $arcPassed = ($arcChecks | Where-Object { $_.Status -eq "Passed" }).Count
        $arcFailed = ($arcChecks | Where-Object { $_.Status -eq "Failed" }).Count
        Write-Host "   Azure Arc Endpoints: $arcPassed Passed, $arcFailed Failed" -ForegroundColor Cyan
        foreach ($check in $arcChecks) {
            $statusColor = if ($check.Status -eq "Passed") { "Green" } else { "Red" }
            $statusIcon = if ($check.Status -eq "Passed") { "✓" } else { "✗" }
            Write-Host "   [$statusIcon] $($check.Status.PadRight(6)) - $($check.URL)" -ForegroundColor $statusColor
        }
        Write-Host ""
    } elseif (-not $SkipArc) {
        # If no Arc checks were parsed, show raw output
        Write-Host "   Azure Arc Endpoints:" -ForegroundColor Cyan
        if ($status.Connectivity) {
            # Check if output looks like formatted table (successful parse)
            if ($status.Connectivity -match "Use Case.*Endpoint.*Reachable") {
                Write-Host "   (Showing azcmagent check results)" -ForegroundColor Cyan
            } else {
                Write-Host "   (Unable to parse azcmagent check output - showing raw results)" -ForegroundColor Yellow
            }
            $status.Connectivity -split "`n" | ForEach-Object {
                if ($_ -match "✓|Passed|reachable|succeeded|true") {
                    Write-Host "   $_" -ForegroundColor Green
                } elseif ($_ -match "✗|Failed|unreachable|error|false") {
                    Write-Host "   $_" -ForegroundColor Red
                } elseif ($_ -match "https?://") {
                    Write-Host "   $_" -ForegroundColor Gray
                } else {
                    Write-Host "   $_" -ForegroundColor Gray
                }
            }
        }
        Write-Host ""
    }
    
    # Display MDE.Windows Extension endpoints (for Arc extension installation)
    if (-not $SkipArc -and $mdeWindowsChecks.Count -gt 0) {
        $mdeWindowsPassed = ($mdeWindowsChecks | Where-Object { $_.Status -eq "Passed" }).Count
        $mdeWindowsFailed = ($mdeWindowsChecks | Where-Object { $_.Status -eq "Failed" }).Count
        Write-Host "   MDE.Windows Extension Endpoints (Arc Extension Installation): $mdeWindowsPassed Passed, $mdeWindowsFailed Failed" -ForegroundColor Cyan
        Write-Host "   Note: Required for Arc-managed MDE extension installation" -ForegroundColor DarkGray
        foreach ($check in $mdeWindowsChecks) {
            $statusColor = if ($check.Status -eq "Passed") { "Green" } else { "Red" }
            $statusIcon = if ($check.Status -eq "Passed") { "✓" } else { "✗" }
            $mandatoryTag = if ($check.Mandatory -eq $false) { " [OPTIONAL]" } else { "" }
            $description = if ($check.Description) { " ($($check.Description))" } else { "" }
            Write-Host "   [$statusIcon] $($check.Status.PadRight(6)) - $($check.URL)$description$mandatoryTag" -ForegroundColor $statusColor
        }
        Write-Host ""
    }
    
    # Display MDE Runtime endpoints (for both manual and Arc-managed MDE)
    if ($mdeChecks.Count -gt 0) {
        $mdePassed = ($mdeChecks | Where-Object { $_.Status -eq "Passed" }).Count
        $mdeFailed = ($mdeChecks | Where-Object { $_.Status -eq "Failed" }).Count
        $mdeMandatoryFailed = @($mdeChecks | Where-Object { $_.Status -eq "Failed" -and $_.Mandatory -eq $true }).Count
        $mdeOptionalFailed = @($mdeChecks | Where-Object { $_.Status -eq "Failed" -and $_.Mandatory -eq $false }).Count
        $mdeMandatoryTotal = @($mdeChecks | Where-Object { $_.Mandatory -eq $true }).Count
        $mdeOptionalTotal = @($mdeChecks | Where-Object { $_.Mandatory -eq $false }).Count
        $mdeTitle = if ($SkipArc) { "MDE Agent Runtime Endpoints" } else { "MDE Agent Runtime Endpoints (Manual & Arc-managed)" }
        $mdeNote = if ($SkipArc) { "Required for MDE agent operation" } else { "Required for MDE agent operation (both onboarding methods)" }
        Write-Host "   $mdeTitle`: $mdePassed Passed, $mdeFailed Failed" -ForegroundColor Cyan
        Write-Host "   Endpoint Breakdown: $mdeMandatoryTotal Mandatory, $mdeOptionalTotal Optional" -ForegroundColor DarkGray
        if ($mdeMandatoryFailed -gt 0 -or $mdeOptionalFailed -gt 0) {
            Write-Host "   Failed Breakdown: $mdeMandatoryFailed Mandatory, $mdeOptionalFailed Optional" -ForegroundColor $(if ($mdeMandatoryFailed -gt 0) { "Red" } else { "Yellow" })
        }
        Write-Host "   Note: $mdeNote" -ForegroundColor DarkGray
        foreach ($check in $mdeChecks) {
            $statusColor = if ($check.Status -eq "Passed") { "Green" } elseif ($check.Mandatory -eq $false) { "Yellow" } else { "Red" }
            $statusIcon = if ($check.Status -eq "Passed") { "✓" } else { "✗" }
            $mandatoryTag = if ($check.Mandatory -eq $false) { " [OPTIONAL]" } else { "" }
            $description = if ($check.Description) { " ($($check.Description))" } else { "" }
            Write-Host "   [$statusIcon] $($check.Status.PadRight(6)) - $($check.URL)$description$mandatoryTag" -ForegroundColor $statusColor
        }
    }
} elseif ($status.Connectivity) {
    Write-Host "   Full Output:" -ForegroundColor Cyan
    $status.Connectivity -split "`n" | ForEach-Object {
        if ($_ -match "✓|Passed|succeeded|reachable") {
            Write-Host "   $_" -ForegroundColor Green
        } elseif ($_ -match "✗|Failed|error|unreachable") {
            Write-Host "   $_" -ForegroundColor Red
        } else {
            Write-Host "   $_"
        }
    }
} else {
    Write-Host "   Connectivity check not available" -ForegroundColor Yellow
}
Write-Host ""

# Comprehensive Proxy Routing Analysis
try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   COMPREHENSIVE PROXY ROUTING ANALYSIS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Analyzing routing configuration for ALL tested endpoints..." -ForegroundColor Gray
    Write-Host "This shows which proxy (if any) will be used for each URL" -ForegroundColor Gray
    Write-Host ""

# Collect ALL endpoints from connectivity results
$allEndpointsToAnalyze = @()

# Add Arc endpoints (from azcmagent check if available)
$arcEndpoints = @(
    @{URL = "https://ae.his.arc.azure.com:443"; Name = "Azure Arc - HIS Australia East"; Category = "Azure Arc"; Mandatory = $true},
    @{URL = "https://gbl.his.arc.azure.com:443"; Name = "Azure Arc - HIS Global"; Category = "Azure Arc"; Mandatory = $true},
    @{URL = "https://agentserviceapi.guestconfiguration.azure.com:443"; Name = "Azure Arc - Guest Config API"; Category = "Azure Arc"; Mandatory = $true},
    @{URL = "https://australiaeast-gas.guestconfiguration.azure.com:443"; Name = "Azure Arc - Guest Config Australia East"; Category = "Azure Arc"; Mandatory = $true},
    @{URL = "https://login.microsoftonline.com:443"; Name = "Azure AD Login"; Category = "Azure Arc"; Mandatory = $true},
    @{URL = "https://management.azure.com:443"; Name = "Azure Management API"; Category = "Azure Arc"; Mandatory = $true},
    @{URL = "https://pas.windows.net:443"; Name = "Azure PAS Service"; Category = "Azure Arc"; Mandatory = $true}
)
$allEndpointsToAnalyze += $arcEndpoints

# Add MDE Extension endpoints
$mdeExtensionEndpoints = @(
    @{URL = "https://go.microsoft.com:443"; Name = "MDE Installer Download"; Category = "MDE Extension"; Mandatory = $true},
    @{URL = "https://automatedirstrprdaue.blob.core.windows.net:443"; Name = "MDE Package Storage (AUE)"; Category = "MDE Extension"; Mandatory = $true},
    @{URL = "https://automatedirstrprdaus.blob.core.windows.net:443"; Name = "MDE Package Storage (AUS)"; Category = "MDE Extension"; Mandatory = $true}
)
$allEndpointsToAnalyze += $mdeExtensionEndpoints

# Add MDE Runtime endpoints (Mandatory)
$mdeRuntimeMandatory = @(
    @{URL = "https://winatp-gw-aus.microsoft.com:443"; Name = "MDE Gateway (AUS)"; Category = "MDE Runtime - Gateway"; Mandatory = $true},
    @{URL = "https://winatp-gw-aue.microsoft.com:443"; Name = "MDE Gateway (AUE)"; Category = "MDE Runtime - Gateway"; Mandatory = $true},
    @{URL = "https://winatp-gw-auc.microsoft.com:443"; Name = "MDE Gateway (AUC)"; Category = "MDE Runtime - Gateway"; Mandatory = $true},
    @{URL = "https://edr-aue.au.endpoint.security.microsoft.com:443"; Name = "MDE EDR Australia Endpoint"; Category = "MDE Runtime - EDR"; Mandatory = $true},
    @{URL = "https://au-v20.events.data.microsoft.com:443"; Name = "Cyber Data Australia"; Category = "MDE Runtime - Telemetry"; Mandatory = $true},
    @{URL = "https://wdcp.microsoft.com:443"; Name = "Cloud-delivered Protection"; Category = "MDE Runtime - Protection"; Mandatory = $true},
    @{URL = "https://wdcpalt.microsoft.com:443"; Name = "Cloud-delivered Protection (Alternate)"; Category = "MDE Runtime - Protection"; Mandatory = $true},
    @{URL = "https://events.data.microsoft.com:443"; Name = "MDE Telemetry (Global)"; Category = "MDE Runtime - Telemetry"; Mandatory = $true},
    @{URL = "https://x.cp.wd.microsoft.com:443"; Name = "MDE Content Delivery"; Category = "MDE Runtime - Content"; Mandatory = $true},
    @{URL = "https://cdn.x.cp.wd.microsoft.com:443"; Name = "MDE CDN Content Delivery"; Category = "MDE Runtime - Content"; Mandatory = $true},
    @{URL = "https://definitionupdates.microsoft.com:443"; Name = "Definition Updates"; Category = "MDE Runtime - Updates"; Mandatory = $true}
)
$allEndpointsToAnalyze += $mdeRuntimeMandatory

# Add MDE Runtime endpoints (Optional)
$mdeRuntimeOptional = @(
    @{URL = "https://ctldl.windowsupdate.com:443"; Name = "Certificate Trust List"; Category = "MDE Runtime - Optional"; Mandatory = $false},
    @{URL = "https://win.vortex.data.microsoft.com:443"; Name = "Windows Telemetry"; Category = "MDE Runtime - Optional"; Mandatory = $false},
    @{URL = "https://settings-win.data.microsoft.com:443"; Name = "Windows Settings"; Category = "MDE Runtime - Optional"; Mandatory = $false},
    @{URL = "https://fe3.delivery.mp.microsoft.com:443"; Name = "Windows Update Delivery"; Category = "MDE Runtime - Optional"; Mandatory = $false},
    @{URL = "http://crl.microsoft.com:80"; Name = "Certificate Revocation List"; Category = "MDE Runtime - Optional"; Mandatory = $false}
)
$allEndpointsToAnalyze += $mdeRuntimeOptional

# Analyze routing for each endpoint
$routingResults = @()
foreach ($endpoint in $allEndpointsToAnalyze) {
    $routeInfo = Get-ActualProxyForUrl -Url $endpoint.URL
    $routingResults += [PSCustomObject]@{
        Category = $endpoint.Category
        Name = $endpoint.Name
        URL = $endpoint.URL
        Mandatory = $endpoint.Mandatory
        UsesProxy = $routeInfo.UsesProxy
        ProxyAddress = $routeInfo.ProxyAddress
        ProxyHost = $routeInfo.ProxyHost
        ProxyPort = $routeInfo.ProxyPort
        RoutingMethod = $routeInfo.RoutingMethod
    }
}

# Group by routing method
$proxyGroups = $routingResults | Where-Object { $_.UsesProxy } | Group-Object ProxyAddress
$directEndpoints = $routingResults | Where-Object { -not $_.UsesProxy }

# Display results grouped by proxy
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  ROUTING ANALYSIS BY PROXY SERVER                       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$proxyIndex = 1
foreach ($proxyGroup in $proxyGroups) {
    Write-Host "[$proxyIndex] PROXY: $($proxyGroup.Name)" -ForegroundColor Yellow
    Write-Host "    Endpoints using this proxy: $($proxyGroup.Count)" -ForegroundColor Gray
    Write-Host ""
    
    # Group by category
    $categories = $proxyGroup.Group | Group-Object Category | Sort-Object Name
    foreach ($cat in $categories) {
        Write-Host "    📁 $($cat.Name) ($($cat.Count) endpoints)" -ForegroundColor Cyan
        foreach ($ep in $cat.Group | Sort-Object Name) {
            $mandatoryTag = if ($ep.Mandatory) { "[MANDATORY]" } else { "[OPTIONAL]" }
            $tagColor = if ($ep.Mandatory) { "Red" } else { "DarkGray" }
            Write-Host "       🔀 $($ep.Name)" -ForegroundColor White
            Write-Host "          URL: $($ep.URL)" -ForegroundColor DarkGray
            Write-Host "          Type: $mandatoryTag" -ForegroundColor $tagColor
        }
        Write-Host ""
    }
    $proxyIndex++
}

# Display direct connections
if ($directEndpoints.Count -gt 0) {
    Write-Host "[$proxyIndex] DIRECT CONNECTION (No Proxy)" -ForegroundColor Green
    Write-Host "    Endpoints using direct connection: $($directEndpoints.Count)" -ForegroundColor Gray
    Write-Host ""
    
    $categories = $directEndpoints | Group-Object Category | Sort-Object Name
    foreach ($cat in $categories) {
        Write-Host "    📁 $($cat.Name) ($($cat.Count) endpoints)" -ForegroundColor Cyan
        foreach ($ep in $cat.Group | Sort-Object Name) {
            $mandatoryTag = if ($ep.Mandatory) { "[MANDATORY]" } else { "[OPTIONAL]" }
            $tagColor = if ($ep.Mandatory) { "Red" } else { "DarkGray" }
            Write-Host "       ➡️  $($ep.Name)" -ForegroundColor White
            Write-Host "          URL: $($ep.URL)" -ForegroundColor DarkGray
            Write-Host "          Type: $mandatoryTag" -ForegroundColor $tagColor
        }
        Write-Host ""
    }
}

# Summary statistics
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║  ROUTING SUMMARY                                         ║" -ForegroundColor Yellow
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host ""

$totalEndpoints = $routingResults.Count
$proxyEndpoints = ($routingResults | Where-Object { $_.UsesProxy }).Count
$directEndpointsCount = ($routingResults | Where-Object { -not $_.UsesProxy }).Count
$uniqueProxies = ($routingResults | Where-Object { $_.UsesProxy } | Select-Object -Unique ProxyAddress).Count

Write-Host "   Total Endpoints Analyzed: $totalEndpoints" -ForegroundColor White
Write-Host "   • Using Proxy:            $proxyEndpoints ($([math]::Round($proxyEndpoints/$totalEndpoints*100))%)" -ForegroundColor Cyan
Write-Host "   • Using Direct:           $directEndpointsCount ($([math]::Round($directEndpointsCount/$totalEndpoints*100))%)" -ForegroundColor Green
Write-Host "   • Unique Proxies Found:   $uniqueProxies" -ForegroundColor Yellow
Write-Host ""

# Detect specific scenarios
$mandatoryViaProxy = ($routingResults | Where-Object { $_.Mandatory -and $_.UsesProxy }).Count
$mandatoryDirect = ($routingResults | Where-Object { $_.Mandatory -and -not $_.UsesProxy }).Count

if ($mandatoryViaProxy -gt 0 -and $mandatoryDirect -gt 0) {
    Write-Host "   ⚠️  CRITICAL FINDING: Mixed Routing for MANDATORY Endpoints" -ForegroundColor Red
    Write-Host "      • $mandatoryViaProxy mandatory endpoints use proxy" -ForegroundColor Yellow
    Write-Host "      • $mandatoryDirect mandatory endpoints use direct connection" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "      IMPACT: If proxy requires authentication or blocks MDE traffic," -ForegroundColor Yellow
    Write-Host "              endpoints routed through proxy will FAIL while direct" -ForegroundColor Yellow
    Write-Host "              endpoints (like Arc Private Link) will work." -ForegroundColor Yellow
    Write-Host ""
}

# Check if Arc uses direct but MDE uses proxy
$arcDirect = ($routingResults | Where-Object { $_.Category -eq "Azure Arc" -and -not $_.UsesProxy }).Count
$mdeViaProxy = ($routingResults | Where-Object { $_.Category -like "MDE*" -and $_.UsesProxy }).Count

if ($arcDirect -gt 0 -and $mdeViaProxy -gt 0) {
    Write-Host "   🎯 ARC vs MDE ROUTING DIFFERENCE DETECTED:" -ForegroundColor Red
    Write-Host "      • Azure Arc: $arcDirect endpoints use DIRECT (Private Link)" -ForegroundColor Green
    Write-Host "      • MDE:       $mdeViaProxy endpoints use PROXY" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "      EXPLANATION: Arc works because it bypasses proxy via Private Link" -ForegroundColor Yellow
    Write-Host "                   MDE fails because proxy blocks/requires auth for MDE URLs" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "      SOLUTIONS:" -ForegroundColor Yellow
    Write-Host "      1. Configure MDE to use Private Link (like Arc does)" -ForegroundColor White
    Write-Host "      2. Fix proxy to allow MDE traffic (add authentication if needed)" -ForegroundColor White
    Write-Host "      3. Add MDE URLs to proxy bypass list" -ForegroundColor White
    Write-Host ""
}

# Check for multiple proxies (PAC file indicator)
if ($uniqueProxies -gt 1) {
    Write-Host "   🔍 MULTIPLE PROXIES DETECTED ($uniqueProxies different proxies)" -ForegroundColor Yellow
    Write-Host "      This indicates PAC file or advanced proxy routing rules" -ForegroundColor Gray
    Write-Host ""
    Write-Host "      Proxies found:" -ForegroundColor Gray
    foreach ($proxy in ($routingResults | Where-Object { $_.UsesProxy } | Select-Object -Unique ProxyAddress)) {
        $count = ($routingResults | Where-Object { $_.ProxyAddress -eq $proxy.ProxyAddress }).Count
        Write-Host "      • $($proxy.ProxyAddress) ($count endpoints)" -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "      ACTION: Verify ALL proxies allow MDE traffic" -ForegroundColor Yellow
    Write-Host "              Check if any proxy requires authentication" -ForegroundColor Yellow
    Write-Host ""
}

# Check if proxy detected but Get-ProxyConfiguration says "NOT DETECTED"
if (-not $proxyConfig.ProxyEnabled -and $proxyEndpoints -gt 0) {
    Write-Host "   ⚠️  PROXY DETECTION DISCREPANCY:" -ForegroundColor Red
    Write-Host "      • Get-ProxyConfiguration: NOT DETECTED" -ForegroundColor Red
    Write-Host "      • Actual routing analysis: $proxyEndpoints endpoints use proxy" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "      ROOT CAUSE: Proxy configured outside standard locations" -ForegroundColor Yellow
    Write-Host "      Likely configured via:" -ForegroundColor Gray
    Write-Host "      • PAC file (AutoConfigURL in IE settings)" -ForegroundColor Gray
    Write-Host "      • WPAD via DHCP Option 252" -ForegroundColor Gray
    Write-Host "      • WPAD via DNS (wpad.domain.com)" -ForegroundColor Gray
    Write-Host "      • Browser-only proxy settings" -ForegroundColor Gray
    Write-Host ""
    Write-Host "      INVESTIGATION COMMANDS:" -ForegroundColor Yellow
    Write-Host "      1. Check IE proxy: Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'" -ForegroundColor Cyan
    Write-Host "      2. Check WPAD DNS: nslookup wpad" -ForegroundColor Cyan
    Write-Host "      3. Check DHCP: ipconfig /all | Select-String 'DHCP'" -ForegroundColor Cyan
    Write-Host "      4. Get PAC file: [System.Net.WebRequest]::DefaultWebProxy.GetProxy([Uri]'http://test.com')" -ForegroundColor Cyan
    Write-Host ""
}

Write-Host ""
} catch {
    Write-Host "⚠️  Error during proxy routing analysis: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   Details: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    Write-Host ""
}

# Summary and Recommendations
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "      ISSUES `& RECOMMENDATIONS          " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$issuesFound = $false

if (-not $SkipArc -and -not $status.ArcAgent.Installed) {
    Write-Host "[CRITICAL] Azure Arc Agent is not installed" -ForegroundColor Red
    Write-Host "           Action: Install the Azure Arc agent" -ForegroundColor Yellow
    $issuesFound = $true
} elseif ($SkipArc -and $status.ArcAgent.Installed -eq "Skipped") {
    Write-Host "[INFO] Azure Arc validation was skipped (-SkipArc)" -ForegroundColor Cyan
}

# Check for certificate thumbprint mismatch
if (-not $SkipArc -and $status.ArcAgent.ErrorDetails -and $status.ArcAgent.ErrorDetails -match "thumbprint.*does not match") {
    Write-Host "[CRITICAL] Certificate thumbprint mismatch detected" -ForegroundColor Red
    Write-Host "           Issue: The certificate thumbprint in the certificate file does not match the expected thumbprint" -ForegroundColor Red
    Write-Host "           Root Cause: Certificate files may be corrupted or out of sync" -ForegroundColor Yellow
    Write-Host "           Action: Run the following commands to fix:" -ForegroundColor Yellow
    Write-Host "                   1. azcmagent disconnect --force-local-only" -ForegroundColor Cyan
    Write-Host "                   2. azcmagent connect --resource-group <RG> --tenant-id <TENANT> --location <LOCATION> --subscription-id <SUB>" -ForegroundColor Cyan
    Write-Host "           Alternative: Delete certificate files from %ProgramData%\AzureConnectedMachineAgent\Certs and reconnect" -ForegroundColor Yellow
    $issuesFound = $true
} elseif (-not $SkipArc -and $status.ArcAgent.Status -match "Disconnected" -and $status.ArcAgent.Installed) {
    Write-Host "[CRITICAL] Azure Arc Agent is disconnected" -ForegroundColor Red
    
    # Check if certificate errors exist
    $certErrors = @()
    if ($status.Certificates) {
        foreach ($cert in $status.Certificates.GetEnumerator()) {
            if ($cert.Value -match "Error|Exception|Unspecified error") {
                $certErrors += $cert.Key
            }
        }
    }
    
    if ($certErrors.Count -gt 0) {
        Write-Host "           Root Cause: Certificate error detected - $($certErrors -join ', ')" -ForegroundColor Red
        Write-Host "           Issue: Failed to load managed identity certificate(s)" -ForegroundColor Red
        Write-Host "           Impact: Arc agent cannot authenticate with Azure" -ForegroundColor Yellow
    }
    
    # Check if Arc endpoints are reachable despite disconnection
    $arcEndpointsReachable = $false
    if ($status.ConnectivityChecks) {
        $arcConnectivityOK = @($status.ConnectivityChecks | Where-Object { $_.Category -eq "Azure Arc" -and $_.Status -eq "Passed" })
        if ($arcConnectivityOK.Count -gt 0) {
            $arcEndpointsReachable = $true
            Write-Host "           Note: Arc endpoints ARE reachable ($($arcConnectivityOK.Count) endpoints working)" -ForegroundColor Yellow
            Write-Host "                 Disconnection is likely due to certificate/authentication issues, not network" -ForegroundColor Yellow
        }
    }
    
    if ($status.ArcAgent.ErrorCode) {
        Write-Host "           Error Code: $($status.ArcAgent.ErrorCode)" -ForegroundColor Red
    }
    
    Write-Host "           Action: Disconnect and reconnect the agent to regenerate certificates" -ForegroundColor Yellow
    Write-Host "                   azcmagent disconnect --force-local-only" -ForegroundColor Cyan
    Write-Host "                   azcmagent connect --resource-group <RG> --tenant-id <TENANT> --location <LOCATION> --subscription-id <SUB>" -ForegroundColor Cyan
    $issuesFound = $true
} elseif (-not $SkipArc -and $status.ArcAgent.Status -notmatch "Connected" -and $status.ArcAgent.Installed) {
    Write-Host "[CRITICAL] Azure Arc Agent is not connected" -ForegroundColor Red
    Write-Host "           Action: Check agent logs and network connectivity" -ForegroundColor Yellow
    $issuesFound = $true
}

# Check for stale heartbeat
if (-not $SkipArc -and $status.ArcAgent.HoursSinceHeartbeat -and $status.ArcAgent.HoursSinceHeartbeat -gt 24) {
    Write-Host "[CRITICAL] Agent heartbeat is stale (last: $($status.ArcAgent.HoursSinceHeartbeat) hours ago)" -ForegroundColor Red
    Write-Host "           Issue: Agent has not communicated with Azure in over 24 hours" -ForegroundColor Red
    Write-Host "           Action: Check network connectivity to Azure endpoints" -ForegroundColor Yellow
    Write-Host "                   Run: azcmagent check" -ForegroundColor Cyan
    Write-Host "                   Verify proxy settings and firewall rules" -ForegroundColor Yellow
    $issuesFound = $true
} elseif (-not $SkipArc -and $status.ArcAgent.HoursSinceHeartbeat -and $status.ArcAgent.HoursSinceHeartbeat -gt 2) {
    Write-Host "[WARNING] Agent heartbeat is delayed (last: $($status.ArcAgent.HoursSinceHeartbeat) hours ago)" -ForegroundColor Yellow
    Write-Host "          Action: Monitor connectivity and check for intermittent network issues" -ForegroundColor Yellow
    $issuesFound = $true
}

# Check dependent services
if (-not $SkipArc -and $status.ArcAgent.DependentServices.himds -and $status.ArcAgent.DependentServices.himds -ne "running") {
    Write-Host "[CRITICAL] HIMDS Service is not running (Status: $($status.ArcAgent.DependentServices.himds))" -ForegroundColor Red
    Write-Host "           Action: Restart the service with: Restart-Service himds" -ForegroundColor Yellow
    $issuesFound = $true
}

if (-not $SkipArc -and $status.ArcAgent.DependentServices.extensionservice -and $status.ArcAgent.DependentServices.extensionservice -ne "running") {
    Write-Host "[CRITICAL] Extension Service is not running (Status: $($status.ArcAgent.DependentServices.extensionservice))" -ForegroundColor Red
    Write-Host "           Action: Restart the service with: Restart-Service extensionservice" -ForegroundColor Yellow
    Write-Host "           Note: Extensions will not function until this service is running" -ForegroundColor Yellow
    $issuesFound = $true
}

# Check connectivity failures
if ($status.ConnectivityChecks) {
    # Check Azure Arc connectivity failures
    $failedArcConnectivity = $status.ConnectivityChecks | Where-Object { $_.Status -eq "Failed" -and $_.Category -eq "Azure Arc" }
    if (-not $SkipArc -and $failedArcConnectivity.Count -gt 0) {
        Write-Host "[CRITICAL] $($failedArcConnectivity.Count) Azure Arc connectivity check(s) failed" -ForegroundColor Red
        Write-Host "           Failed Azure Arc endpoints:" -ForegroundColor Red
        foreach ($failed in $failedArcConnectivity) {
            Write-Host "           - $($failed.URL)" -ForegroundColor Red
        }
        Write-Host "           Issue: Unable to reach required Azure Arc endpoints" -ForegroundColor Red
        Write-Host "           Action: Verify firewall rules and proxy configuration" -ForegroundColor Yellow
        Write-Host "                   Check DNS resolution for failed endpoints" -ForegroundColor Yellow
        Write-Host "                   Ensure outbound HTTPS (443) is allowed" -ForegroundColor Yellow
        $issuesFound = $true
    }
    
    # Check MDE connectivity failures (combined MDE.Windows and MDE categories)
    $failedMDEMandatory = @($status.ConnectivityChecks | Where-Object { $_.Status -eq "Failed" -and ($_.Category -eq "MDE" -or $_.Category -eq "MDE.Windows") -and $_.Mandatory -eq $true })
    $failedMDEOptional = @($status.ConnectivityChecks | Where-Object { $_.Status -eq "Failed" -and ($_.Category -eq "MDE" -or $_.Category -eq "MDE.Windows") -and $_.Mandatory -eq $false })
    
    if ($failedMDEMandatory.Count -gt 0) {
        Write-Host "[CRITICAL] $($failedMDEMandatory.Count) MANDATORY MDE connectivity check(s) failed" -ForegroundColor Red
        Write-Host "           Failed MANDATORY MDE endpoints:" -ForegroundColor Red
        foreach ($failed in $failedMDEMandatory) {
            $desc = if ($failed.Description) { " - $($failed.Description)" } else { "" }
            Write-Host "           - $($failed.URL)$desc" -ForegroundColor Red
        }
        Write-Host "           Issue: Unable to reach critical MDE endpoints - MDE functionality degraded" -ForegroundColor Red
        $impactMsg = if ($SkipArc) { "EDR protection degraded" } else { "Extension installation/updates may fail, EDR protection degraded" }
        Write-Host "           Impact: $impactMsg" -ForegroundColor Red
        Write-Host "           Root Cause: Network connectivity or firewall blocking MDE traffic" -ForegroundColor Red
        Write-Host "           Action: Verify firewall allows access to MANDATORY MDE endpoints" -ForegroundColor Yellow
        Write-Host "                   Required MDE URLs (see failed endpoints above for specifics):" -ForegroundColor Yellow
        Write-Host "                   - *.blob.core.windows.net:443 (MDE Package Storage)" -ForegroundColor Gray
        Write-Host "                   - go.microsoft.com:443 (MDE Installer)" -ForegroundColor Gray
        Write-Host "                   - *.wd.microsoft.com:443 (Content Delivery)" -ForegroundColor Gray
        Write-Host "                   - winatp-gw-*.microsoft.com:443 (Regional Gateways)" -ForegroundColor Gray
        Write-Host "                   - edr-*.endpoint.security.microsoft.com:443 (EDR Endpoints)" -ForegroundColor Gray
        Write-Host "                   - events.data.microsoft.com:443 (Telemetry)" -ForegroundColor Gray
        Write-Host "                   Check DNS resolution: Resolve-DnsName <endpoint>" -ForegroundColor Yellow
        Write-Host "                   Test connectivity: Test-NetConnection -ComputerName <endpoint> -Port 443" -ForegroundColor Yellow
        $issuesFound = $true
    }
    
    if ($failedMDEOptional.Count -gt 0) {
        Write-Host "[INFO] $($failedMDEOptional.Count) OPTIONAL MDE connectivity check(s) failed" -ForegroundColor Yellow
        Write-Host "       Failed OPTIONAL MDE endpoints (MDE will still function):" -ForegroundColor Yellow
        foreach ($failed in $failedMDEOptional) {
            $desc = if ($failed.Description) { " - $($failed.Description)" } else { "" }
            Write-Host "       - $($failed.URL)$desc" -ForegroundColor Yellow
        }
        Write-Host "       Impact: Limited - Core MDE functionality not affected" -ForegroundColor Yellow
        Write-Host "       Note: These endpoints provide enhanced features (Windows telemetry, CRL, etc.)" -ForegroundColor Gray
        Write-Host "       Action: Optional - Fix only if enhanced features are required" -ForegroundColor Gray
    }
}

if ($status.ArcAgent.DependentServices.gcarcservice -and $status.ArcAgent.DependentServices.gcarcservice -ne "running") {
    Write-Host "[CRITICAL] GC Arc Service is not running (Status: $($status.ArcAgent.DependentServices.gcarcservice))" -ForegroundColor Red
    Write-Host "           Action: Restart the service with: Restart-Service gcarcservice" -ForegroundColor Yellow
    $issuesFound = $true
}

if ($status.ArcAgent.DependentServices.arcproxy -and $status.ArcAgent.DependentServices.arcproxy -ne "running") {
    Write-Host "[WARNING] Arc Proxy Service is stopped (Status: $($status.ArcAgent.DependentServices.arcproxy))" -ForegroundColor Yellow
    Write-Host "          Note: This is normal if no proxy is configured" -ForegroundColor Gray
    Write-Host "          Action: If proxy is required, check proxy configuration" -ForegroundColor Yellow
}

if ($criticalCerts.Count -gt 0) {
    Write-Host "[CRITICAL] $($criticalCerts.Count) certificate(s) EXPIRED" -ForegroundColor Red
    Write-Host "           Certificates: $($criticalCerts -join ', ')" -ForegroundColor Red
    Write-Host "           Action: Run: azcmagent disconnect; azcmagent connect" -ForegroundColor Yellow
    $issuesFound = $true
}

if ($warnCerts.Count -gt 0) {
    Write-Host "[WARNING] $($warnCerts.Count) certificate(s) expiring soon" -ForegroundColor Yellow
    Write-Host "          Certificates: $($warnCerts -join ', ')" -ForegroundColor Yellow
    Write-Host "          Action: Monitor and plan re-onboarding if needed" -ForegroundColor Yellow
    $issuesFound = $true
}



if ($status.MDE.SenseService -ne "Running" -and $status.MDE.SenseService -ne "Not Found") {
    Write-Host "[CRITICAL] MDE Sense Service is not running" -ForegroundColor Red
    Write-Host "           Action: Start the service with: Start-Service Sense" -ForegroundColor Yellow
    Write-Host "           Note: MDE protection is not active until this service is running" -ForegroundColor Yellow
    $issuesFound = $true
}

# Detailed MDE diagnostic - explain portal status differences
# KEY: Portal shows "Onboarded" ONLY if LastConnected registry value exists
#      Connectivity failures don't prevent "Onboarded" status if agent has connected at least once

$mdeFullyOnboarded = $false
$portalShowsOnboarded = $false

Write-Host ""
Write-Host "=== MDE ONBOARDING STATUS ANALYSIS ===" -ForegroundColor Cyan
Write-Host ""

if ($status.MDE.InstallPath -eq "Not Found" -or $status.MDE.SenseExeExists -eq "No") {
    Write-Host "[CRITICAL] MDE Agent Not Installed" -ForegroundColor Red
    Write-Host "           The MDE agent software is not present on this server" -ForegroundColor Red
    Write-Host "           Portal Status: 'Defender for Endpoint can be onboarded'" -ForegroundColor Yellow
    Write-Host "           Action: Install MDE via Arc extension or manual onboarding" -ForegroundColor Yellow
    Write-Host ""
    $issuesFound = $true
} elseif ($status.MDE.OnboardingState -notmatch "Onboarded") {
    Write-Host "[CRITICAL] MDE Agent Installed but NOT ONBOARDED" -ForegroundColor Red
    Write-Host "           MDE software is installed but registry shows not onboarded" -ForegroundColor Red
    Write-Host "           Registry OnboardingState: $($status.MDE.OnboardingState)" -ForegroundColor Red
    Write-Host "           Portal Status: 'Defender for Endpoint can be onboarded'" -ForegroundColor Yellow
    Write-Host "           Root Cause: Onboarding script was never run or failed" -ForegroundColor Yellow
    Write-Host "           Action: Run MDE onboarding script (WindowsDefenderATPOnboardingScript.cmd)" -ForegroundColor Yellow
    Write-Host "                   Or deploy via Arc extension: Install MDE.Windows extension" -ForegroundColor Yellow
    Write-Host ""
    $issuesFound = $true
} else {
    # OnboardingState = Onboarded in registry
    # Now check if portal recognizes it (depends on LastConnected)
    
    if (-not $status.MDE.LastConnected) {
        # CRITICAL FINDING: This is THE reason portal shows "Can be onboarded"
        Write-Host "[CRITICAL] Portal Shows 'Can be onboarded' - Missing Cloud Connection" -ForegroundColor Red
        Write-Host ""
        Write-Host "           ROOT CAUSE IDENTIFIED:" -ForegroundColor Yellow
        Write-Host "           =====================" -ForegroundColor Yellow
        Write-Host "           Registry OnboardingState: 1 (Onboarded) [✓]" -ForegroundColor Green
        Write-Host "           Registry LastConnected: NOT PRESENT [✗]" -ForegroundColor Red
        Write-Host ""
        Write-Host "           THE PROBLEM:" -ForegroundColor Red
        Write-Host "           - MDE was onboarded locally (registry key set)" -ForegroundColor Gray
        Write-Host "           - But agent has NEVER connected to Microsoft Defender cloud" -ForegroundColor Red
        Write-Host "           - Portal cannot verify this device exists" -ForegroundColor Red
        Write-Host "           - Therefore portal shows: 'Defender for Endpoint can be onboarded'" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "           Registry Location: HKLM:\\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\Status" -ForegroundColor DarkGray
        Write-Host ""
        
        # Add version analysis as supporting evidence
        if ($status.MDE.VersionStatus -match "OUTDATED|CRITICALLY|Needs Update" -and $status.MDE.VersionAge -ne "Unknown") {
            Write-Host "           SUPPORTING EVIDENCE - Outdated Agent Version:" -ForegroundColor Yellow
            Write-Host "           - Platform: $($status.MDE.PlatformVersion)" -ForegroundColor Red
            Write-Host "           - Age: $($status.MDE.VersionAge)" -ForegroundColor Red
            Write-Host "           - Status: $($status.MDE.VersionStatus)" -ForegroundColor Red
            Write-Host "           - Conclusion: Outdated version proves NO cloud connectivity" -ForegroundColor Red
            Write-Host "             (Agent cannot get updates without connecting to Microsoft cloud)" -ForegroundColor Gray
            Write-Host ""
        }
        
        Write-Host "           WHY THIS HAPPENED:" -ForegroundColor Yellow
        Write-Host "           1. Firewall blocking MDE endpoints (see connectivity test results above)" -ForegroundColor Gray
        if ($failedMDEConnectivity -and $failedMDEConnectivity.Count -gt 0) {
            $failedUrls = ($failedMDEConnectivity | Select-Object -First 3 | ForEach-Object { $_.URL }) -join ', '
            Write-Host "              Critical blocked: $failedUrls..." -ForegroundColor Red
        }
        Write-Host "           2. Service never started after onboarding, OR" -ForegroundColor Gray
        Write-Host "           3. Onboarding configuration incomplete/corrupted" -ForegroundColor Gray
        Write-Host ""
        Write-Host "           CURRENT STATUS CHECK:" -ForegroundColor Cyan
        Write-Host "           - Sense Service: $($status.MDE.SenseService)" -ForegroundColor $(if ($status.MDE.SenseService -eq "Running") {"Green"} else {"Red"})
        Write-Host ""
        Write-Host "           HOW TO FIX:" -ForegroundColor Yellow
        Write-Host "           ===========" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "           Step 1: ADD FIREWALL RULES (CRITICAL - Root Cause!)" -ForegroundColor Red
        Write-Host "           -----------------------------------------------" -ForegroundColor Red
        Write-Host "           Whitelist these EXACT URLs in your firewall/proxy:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "           CRITICAL - Minimum Required for Onboarding:" -ForegroundColor Yellow
        
        # Show region-specific critical endpoints
        $regionGateways = $regionConfig[$Region].Gateways
        foreach ($gateway in $regionGateways) {
            Write-Host "           • https://winatp-gw-$gateway.microsoft.com:443" -ForegroundColor Cyan
        }
        Write-Host "           • https://events.data.microsoft.com:443" -ForegroundColor Cyan
        Write-Host "           • https://$($regionConfig[$Region].CyberData):443" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "           IMPORTANT - Required for Updates/Operations:" -ForegroundColor Yellow
        Write-Host "           • https://go.microsoft.com:443" -ForegroundColor Cyan
        Write-Host "           • https://definitionupdates.microsoft.com:443" -ForegroundColor Cyan
        Write-Host "           • https://x.cp.wd.microsoft.com:443" -ForegroundColor Cyan
        Write-Host "           • https://wdcp.microsoft.com:443" -ForegroundColor Cyan
        Write-Host "           • https://wdcpalt.microsoft.com:443" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "           BLOB STORAGE - Region-specific for your deployment:" -ForegroundColor Yellow
        foreach ($blob in $regionConfig[$Region].BlobStorage) {
            Write-Host "           • https://automatedirstrprd$blob.blob.core.windows.net:443" -ForegroundColor Cyan
        }
        Write-Host ""
        Write-Host "           OPTIONAL - Supporting Services:" -ForegroundColor Yellow
        Write-Host "           • https://ctldl.windowsupdate.com:443" -ForegroundColor Cyan
        Write-Host "           • https://crl.microsoft.com:80" -ForegroundColor Cyan
        Write-Host "           • https://win.vortex.data.microsoft.com:443" -ForegroundColor Cyan
        Write-Host "           • https://settings-win.data.microsoft.com:443" -ForegroundColor Cyan
        Write-Host "           • https://fe3.delivery.mp.microsoft.com:443" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "           Firewall Rule Format Example:" -ForegroundColor DarkGray
        Write-Host "           Allow Outbound: Protocol=HTTPS, Port=443, Destination=winatp-gw-*.microsoft.com" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host ""
        Write-Host "           Step 2: RESTART MDE SERVICE" -ForegroundColor Yellow
        Write-Host "           ---------------------------" -ForegroundColor Yellow
        Write-Host "           After firewall rules are applied, restart the MDE service:" -ForegroundColor Gray
        Write-Host ""
        Write-Host "           Restart-Service Sense -Force" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "           This forces the agent to re-attempt cloud connection with new firewall rules" -ForegroundColor Gray
        Write-Host ""
        Write-Host ""
        Write-Host "           Step 3: WAIT FOR INITIAL CLOUD CONNECTION" -ForegroundColor Yellow
        Write-Host "           -----------------------------------------" -ForegroundColor Yellow
        Write-Host "           After firewall fix and service restart, wait 5-10 minutes for:" -ForegroundColor Gray
        Write-Host "           - Agent to detect connectivity is restored" -ForegroundColor Gray
        Write-Host "           - Connect to Microsoft Defender cloud" -ForegroundColor Gray
        Write-Host "           - Establish device identity" -ForegroundColor Gray
        Write-Host "           - Set LastConnected registry value" -ForegroundColor Gray
        Write-Host ""
        Write-Host ""
        Write-Host "           Step 4: VERIFY LastConnected VALUE (Automatic Check)" -ForegroundColor Yellow
        Write-Host "           -----------------------------------------------------" -ForegroundColor Yellow
        Write-Host "           Checking current LastConnected status..." -ForegroundColor Gray
        Write-Host ""
        
        # Automatically check LastConnected status
        try {
            $lastConnectedCheck = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name LastConnected -ErrorAction SilentlyContinue
            
            if ($lastConnectedCheck -and $lastConnectedCheck.LastConnected -and $lastConnectedCheck.LastConnected -ne 0) {
                # Convert FILETIME to readable DateTime
                $lastConnectedDateTime = Convert-FileTimeToDateTime -FileTime $lastConnectedCheck.LastConnected
                
                Write-Host "           ✅ SUCCESS: LastConnected value EXISTS" -ForegroundColor Green
                if ($lastConnectedDateTime) {
                    Write-Host "           Date/Time: $lastConnectedDateTime" -ForegroundColor Green
                    Write-Host "           Raw Value: $($lastConnectedCheck.LastConnected)" -ForegroundColor DarkGray
                } else {
                    Write-Host "           Raw Value: $($lastConnectedCheck.LastConnected)" -ForegroundColor Green
                }
                Write-Host ""
                Write-Host "           This means:" -ForegroundColor Cyan
                Write-Host "           • MDE successfully connected to Microsoft cloud" -ForegroundColor Gray
                Write-Host "           • Device identity established" -ForegroundColor Gray
                Write-Host "           • Portal should recognize this device within 10-15 minutes" -ForegroundColor Gray
                Write-Host ""
                Write-Host "           Next Steps:" -ForegroundColor Yellow
                Write-Host "           1. Wait 10-15 minutes for portal to sync" -ForegroundColor Gray
                Write-Host "           2. Verify in Azure Portal → Defender for Cloud → Servers" -ForegroundColor Gray
                Write-Host "           3. Look for server: $($env:COMPUTERNAME)" -ForegroundColor Cyan
                Write-Host "           4. Status should show: 'Defender for Server: Onboarded'" -ForegroundColor Gray
            } else {
                Write-Host "           ❌ FAILURE: LastConnected value is MISSING" -ForegroundColor Red
                Write-Host "           Registry: HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -ForegroundColor Gray
                Write-Host ""
                Write-Host "           This means MDE has NOT connected to Microsoft cloud yet" -ForegroundColor Red
                Write-Host ""
                Write-Host "           Troubleshooting steps:" -ForegroundColor Yellow
                Write-Host "           • Wait 10 more minutes and run this script again" -ForegroundColor Gray
                Write-Host "           • Verify firewall rules are applied correctly" -ForegroundColor Gray
                Write-Host "           • Check DNS resolution: Resolve-DnsName winatp-gw-aue.microsoft.com" -ForegroundColor Gray
                Write-Host "           • Test connectivity: Test-NetConnection -ComputerName winatp-gw-aue.microsoft.com -Port 443" -ForegroundColor Gray
                Write-Host "           • Check MDE service is running: Get-Service Sense" -ForegroundColor Gray
                Write-Host "           • Review SENSE event logs for connection errors:" -ForegroundColor Gray
                Write-Host "             Get-WinEvent -LogName 'Microsoft-Windows-SENSE/Operational' -MaxEvents 20" -ForegroundColor Cyan
            }
        } catch {
            Write-Host "           ⚠️  ERROR: Unable to check LastConnected value" -ForegroundColor Yellow
            Write-Host "           Error: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        Write-Host ""
        Write-Host ""
        Write-Host "           Step 5: VERIFY IN AZURE PORTAL" -ForegroundColor Yellow
        Write-Host "           ------------------------------" -ForegroundColor Yellow
        Write-Host "           After LastConnected value appears, wait additional 10-15 minutes then:" -ForegroundColor Gray
        Write-Host "           - Open Azure Portal → Defender for Cloud → Servers" -ForegroundColor Gray
        Write-Host "           - Locate this server: $($env:COMPUTERNAME)" -ForegroundColor Cyan
        Write-Host "           - Refresh the page (Ctrl+F5)" -ForegroundColor Gray
        Write-Host "           - Verify status shows: 'Defender for Server: Onboarded' [OK]" -ForegroundColor Green
        Write-Host ""
        $issuesFound = $true
        $portalShowsOnboarded = $false
    } else {
        # LastConnected exists - portal recognizes device as onboarded
        $mdeFullyOnboarded = $true
        $portalShowsOnboarded = $true
        
        Write-Host "[SUCCESS] Portal Shows 'Onboarded' - Cloud Connection Established" -ForegroundColor Green
        Write-Host ""
        Write-Host "          VERIFIED STATUS:" -ForegroundColor Green
        Write-Host "          ===============" -ForegroundColor Green
        Write-Host "          Registry OnboardingState: 1 (Onboarded) [OK]" -ForegroundColor Green
        
        # Display LastConnected with readable DateTime
        if ($status.MDE.LastConnected -and $status.MDE.LastConnected -ne "0" -and $status.MDE.LastConnected -ne 0) {
            if ($status.MDE.LastConnectedDateTime) {
                Write-Host "          Registry LastConnected: $($status.MDE.LastConnectedDateTime) [OK]" -ForegroundColor Green
                Write-Host "                                  (Raw: $($status.MDE.LastConnected))" -ForegroundColor DarkGray
            } else {
                Write-Host "          Registry LastConnected: $($status.MDE.LastConnected) (Unable to convert) [WARNING]" -ForegroundColor Yellow
            }
        } else {
            if ([string]::IsNullOrWhiteSpace($status.MDE.LastConnected)) {
                Write-Host "          Registry LastConnected: MISSING [ERROR]" -ForegroundColor Red
            } elseif ($status.MDE.LastConnected -eq "0" -or $status.MDE.LastConnected -eq 0) {
                Write-Host "          Registry LastConnected: INVALID (0) [ERROR]" -ForegroundColor Red
            } else {
                Write-Host "          Registry LastConnected: ERROR ($($status.MDE.LastConnected)) [ERROR]" -ForegroundColor Red
            }
        }
        
        Write-Host "          Portal Status: 'Defender for Server: Onboarded' [OK]" -ForegroundColor Green
        Write-Host ""
        
        # Show version status as evidence of cloud connectivity
        if ($status.MDE.VersionStatus -and $status.MDE.VersionStatus -ne "Unable to analyze") {
            if ($status.MDE.VersionStatus -eq "Current") {
                Write-Host "          Agent Version: $($status.MDE.PlatformVersion)" -ForegroundColor Green
                Write-Host "          Version Status: $($status.MDE.VersionStatus) [OK]" -ForegroundColor Green
                Write-Host "          (Agent successfully receiving updates from Microsoft cloud)" -ForegroundColor Cyan
                Write-Host ""
            } else {
                Write-Host "          Agent Version: $($status.MDE.PlatformVersion) ($($status.MDE.VersionAge))" -ForegroundColor Yellow
                Write-Host "          Version Status: $($status.MDE.VersionStatus)" -ForegroundColor Yellow
                Write-Host "          Note: Agent connected to cloud before but may have connectivity issues now" -ForegroundColor Yellow
                Write-Host ""
            }
        }
        
        # Even if connectivity is failing NOW, device is recognized because it connected before
        if ($failedMDEConnectivity -and $failedMDEConnectivity.Count -gt 0) {
            Write-Host "          CONNECTIVITY WARNING:" -ForegroundColor Yellow
            Write-Host "          =====================" -ForegroundColor Yellow
            Write-Host "          Portal shows 'Onboarded' because:" -ForegroundColor Cyan
            Write-Host "          - Device successfully connected to cloud IN THE PAST" -ForegroundColor Green
            Write-Host "          - LastConnected registry value was set" -ForegroundColor Green
            Write-Host "          - Portal verified device identity" -ForegroundColor Green
            Write-Host ""
            Write-Host "          BUT currently has $($failedMDEConnectivity.Count) connectivity failures" -ForegroundColor Red
            Write-Host ""
            Write-Host "          WHAT THIS MEANS:" -ForegroundColor Yellow
            Write-Host "          - Firewall rules likely changed AFTER initial onboarding" -ForegroundColor Gray
            Write-Host "          - Device is 'onboarded' but operating in degraded mode" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "          CURRENT IMPACT:" -ForegroundColor Yellow
            Write-Host "          - Real-time cloud protection queries may fail" -ForegroundColor Red
            Write-Host "          - Telemetry submission blocked" -ForegroundColor Red
            Write-Host "          - Agent cannot receive updates" -ForegroundColor Red
            Write-Host "          - Security posture degraded" -ForegroundColor Red
            Write-Host ""
            Write-Host "          RECOMMENDATION:" -ForegroundColor Yellow
            Write-Host "          Fix firewall to restore full MDE functionality" -ForegroundColor Yellow
            Write-Host "          See failed endpoints in connectivity test above" -ForegroundColor Gray
            Write-Host "          Priority: winatp-gw-*.microsoft.com, events.data.microsoft.com" -ForegroundColor Cyan
            Write-Host ""
        }
    }
}
Write-Host ""

# Check for manual MDE onboarding vs Arc-managed extension mismatch
if (-not $SkipArc -and $portalShowsOnboarded) {
    $mdeExtInstalled = $status.Extensions | Where-Object { $_.Name -match "MDE.Windows" -and $_.Installed -eq $true }
    if (-not $mdeExtInstalled) {
        Write-Host "[INFO] MDE Onboarding Method: Manual/Classic (not Arc-managed)" -ForegroundColor Cyan
        
        # Check if Arc agent is actually installed before claiming it's connected
        $arcStatus = if ($status.ArcAgent.Installed) { "Connected ✓" } else { "NOT INSTALLED ✗" }
        $arcColor = if ($status.ArcAgent.Installed) { "Green" } else { "Red" }
        Write-Host "       Azure Arc: $arcStatus" -ForegroundColor $arcColor
        
        Write-Host "       MDE Agent: Onboarded ✓ (manually, not via Arc extension)" -ForegroundColor Green
        Write-Host "       MDE.Windows Extension: NOT INSTALLED" -ForegroundColor Yellow
        Write-Host ""
        
        if ($status.ArcAgent.Installed) {
            Write-Host "       Portal Status Breakdown:" -ForegroundColor Cyan
            Write-Host "       ├─ 'Defender for Server': Onboarded ✓" -ForegroundColor Green
            Write-Host "       ├─ 'Defender for Endpoint': Can be onboarded" -ForegroundColor Yellow
            Write-Host "       └─ 'Last device update': Shows current date (device IS communicating)" -ForegroundColor Green
            Write-Host ""
            Write-Host "       Why 'Can be onboarded' Shows When Device IS Already Onboarded:" -ForegroundColor Yellow
            Write-Host "         • Portal displays TWO different onboarding statuses:" -ForegroundColor Gray
            Write-Host "           - 'Defender for Server': Shows manual onboarding status (Onboarded ✓)" -ForegroundColor Gray
            Write-Host "           - 'Defender for Endpoint': Shows Arc extension status (Can be onboarded)" -ForegroundColor Gray
            Write-Host "         • 'Can be onboarded' means: MDE.Windows extension can be installed" -ForegroundColor Gray
            Write-Host "         • 'Last device update' proves device IS working and communicating" -ForegroundColor Gray
            Write-Host ""
            Write-Host "       Current Configuration:" -ForegroundColor Cyan
            Write-Host "         ✓ Azure Arc agent: Connected and healthy" -ForegroundColor Green
            Write-Host "         ✓ MDE agent: Onboarded and communicating (manual method)" -ForegroundColor Green
            Write-Host "         ℹ MDE.Windows extension: Not installed (optional - alternative method)" -ForegroundColor Gray
            Write-Host ""
            Write-Host "       Summary: MDE is working correctly - no action required" -ForegroundColor Green
            Write-Host "                (Arc extension is optional alternative to manual onboarding)" -ForegroundColor Cyan
        } else {
            Write-Host "       Current Configuration:" -ForegroundColor Cyan
            Write-Host "         ✗ Azure Arc agent: NOT INSTALLED" -ForegroundColor Red
            Write-Host "         ✓ MDE agent: Onboarded and communicating (manual onboarding method)" -ForegroundColor Green
            Write-Host ""
            Write-Host "       Summary: MDE is working correctly using manual onboarding" -ForegroundColor Green
            Write-Host "                Azure Arc agent is not required for manual MDE onboarding" -ForegroundColor Cyan
        }
        Write-Host ""
    }
}

# Check for MDE extension specific issues
$mdeExt = $status.Extensions | Where-Object { $_.Name -match "MDE.Windows" }
if ($mdeExt) {
    $hasMDEIssue = $false
    
    # Skip failure detection if onboarding was successful
    if (-not $mdeExt.OnboardingSuccess) {
        # Check multiple indicators of failure
        if ($mdeExt.DetailedStatus -match "(?i)error|failed|transitioning") { $hasMDEIssue = $true }
        if ($mdeExt.InstallationFailed) { $hasMDEIssue = $true }
        if ($mdeExt.ConnectivityIssue) { $hasMDEIssue = $true }
        if ($mdeExt.ErrorMessage -and $mdeExt.ErrorMessage -ne "") { $hasMDEIssue = $true }
        if ($mdeExt.ErrorCode -and $mdeExt.ErrorCode -ne "" -and $mdeExt.ErrorCode -ne 0) { $hasMDEIssue = $true }
    }
    
    if ($hasMDEIssue) {
        Write-Host "[CRITICAL] MDE Extension installation/configuration failed" -ForegroundColor Red
        if ($mdeExt.DetailedStatus -and $mdeExt.DetailedStatus -ne "Unknown") {
            Write-Host "           Status: $($mdeExt.DetailedStatus)" -ForegroundColor Red
        }
        if ($mdeExt.ErrorCode) {
            Write-Host "           Error Code: $($mdeExt.ErrorCode)" -ForegroundColor Red
        }
        if ($mdeExt.ErrorMessage) {
            Write-Host "           Error: $($mdeExt.ErrorMessage)" -ForegroundColor Red
        }
        
        if ($mdeExt.ConnectivityIssue) {
            Write-Host "           Root Cause: Unable to connect to MDE download servers" -ForegroundColor Red
            Write-Host "           Symptoms: 'Unable to connect to the remote server' in logs" -ForegroundColor Yellow
            Write-Host "" 
            Write-Host "           Troubleshooting Steps:" -ForegroundColor Cyan
            Write-Host "           1. Verify internet connectivity to Microsoft endpoints" -ForegroundColor Yellow
            Write-Host "              Test: Test-NetConnection -ComputerName go.microsoft.com -Port 443" -ForegroundColor Gray
            Write-Host "           2. Check proxy configuration if applicable" -ForegroundColor Yellow
            Write-Host "              Get proxy: netsh winhttp show proxy" -ForegroundColor Gray
            Write-Host "           3. Verify firewall rules allow outbound HTTPS (443)" -ForegroundColor Yellow
            Write-Host "           4. Required URLs for MDE:" -ForegroundColor Yellow
            Write-Host "              - *.blob.core.windows.net" -ForegroundColor Gray
            Write-Host "              - go.microsoft.com" -ForegroundColor Gray
            Write-Host "              - *.wd.microsoft.com" -ForegroundColor Gray
            Write-Host "              - winatp-gw-*.microsoft.com (aus, aue, auc, eus, weu)" -ForegroundColor Gray
            Write-Host "              - edr-*.endpoint.security.microsoft.com" -ForegroundColor Gray
            Write-Host "           5. Check DNS resolution" -ForegroundColor Yellow
            Write-Host "              Test: Resolve-DnsName go.microsoft.com" -ForegroundColor Gray
            Write-Host "" 
            Write-Host "           Action: After fixing connectivity, retry extension:" -ForegroundColor Yellow
            Write-Host "                   - Remove extension from Azure Portal" -ForegroundColor Cyan
            Write-Host "                   - Wait 5 minutes for cleanup" -ForegroundColor Cyan
            Write-Host "                   - Re-add MDE.Windows extension" -ForegroundColor Cyan
        } elseif ($mdeExt.TimeoutIssue) {
            Write-Host "           Root Cause: Timeout downloading MDE installer (md4ws.msi)" -ForegroundColor Red
            Write-Host "           Action: Check network bandwidth and latency to Azure endpoints" -ForegroundColor Yellow
            Write-Host "                   Test: Test-NetConnection -ComputerName go.microsoft.com -Port 443" -ForegroundColor Gray
        } else {
            Write-Host "           Action: Check detailed logs in extension directory" -ForegroundColor Yellow
            if ($mdeExt.LogFile) {
                Write-Host "                   Log File: $($mdeExt.LogFile)" -ForegroundColor Gray
            } else {
                Write-Host "                   Log Path: C:\Packages\Plugins\Microsoft.Azure.AzureDefenderForServers*\" -ForegroundColor Gray
            }
        }
        $issuesFound = $true
        Write-Host ""
    }
}

# Check for other extension failures
$failedExtensions = $status.Extensions | Where-Object { ($_.Status -match "(?i)error|failed") -and ($_.Name -notmatch "MDE.Windows") }
if ($failedExtensions.Count -gt 0) {
    Write-Host "[WARNING] $($failedExtensions.Count) extension(s) have errors" -ForegroundColor Yellow
    foreach ($ext in $failedExtensions) {
        Write-Host "          Extension: $($ext.Name) - Status: $($ext.Status)" -ForegroundColor Yellow
        if ($ext.Message) {
            Write-Host "          Message: $($ext.Message)" -ForegroundColor Gray
        }
    }
    Write-Host "          Action: Check extension logs for details" -ForegroundColor Yellow
    $issuesFound = $true
}

# Check MDE connectivity prerequisites when extension is not installed
$mdeExtCheck = $status.Extensions | Where-Object { $_.Name -match "MDE.Windows" }
if (-not $SkipArc -and $mdeExtCheck -and -not $mdeExtCheck.Installed) {
    # Check if MDE connectivity tests were performed (focus on MDE.Windows category for extension installation)
    $mdeWindowsConnectivityTests = $status.ConnectivityChecks | Where-Object { $_.Category -eq "MDE.Windows" }
    $mdeConnectivityTests = $status.ConnectivityChecks | Where-Object { $_.Category -eq "MDE" -or $_.Category -eq "MDE.Windows" }
    if ($mdeConnectivityTests -and $mdeConnectivityTests.Count -gt 0) {
        $failedMDEPrereqs = $mdeConnectivityTests | Where-Object { $_.Status -eq "Failed" }
        $failedMDEWindowsPrereqs = $mdeWindowsConnectivityTests | Where-Object { $_.Status -eq "Failed" }
        
        if ($failedMDEWindowsPrereqs.Count -gt 0) {
            Write-Host "[WARNING] MDE.Windows extension not installed - Extension installation prerequisites NOT met" -ForegroundColor Yellow
            Write-Host "          Failed MDE.Windows connectivity checks: $($failedMDEWindowsPrereqs.Count) of $($mdeWindowsConnectivityTests.Count)" -ForegroundColor Yellow
            Write-Host "          Critical: These URLs are required for Arc extension installer download" -ForegroundColor Red
            Write-Host "          Failed extension endpoints:" -ForegroundColor Yellow
            foreach ($failed in $failedMDEWindowsPrereqs) {
                $desc = if ($failed.Description) { " - $($failed.Description)" } else { "" }
                Write-Host "          - $($failed.URL)$desc" -ForegroundColor Red
            }
            Write-Host "          Issue: Cannot install MDE.Windows Arc extension without these endpoints" -ForegroundColor Red
            Write-Host "          Action: Fix firewall/proxy to allow access to these endpoints before installing extension" -ForegroundColor Yellow
            Write-Host "                  Required MDE URLs (see failed endpoints above for specifics):" -ForegroundColor Yellow
            Write-Host "                  - *.blob.core.windows.net:443 (MDE Package Storage)" -ForegroundColor Gray
            Write-Host "                  - go.microsoft.com:443 (MDE Installer)" -ForegroundColor Gray
            Write-Host "                  - *.wd.microsoft.com:443 (Content Delivery)" -ForegroundColor Gray
            Write-Host "                  - winatp-gw-*.microsoft.com:443 (Regional Gateways: aus, aue, auc)" -ForegroundColor Gray
            Write-Host "                  - edr-*.endpoint.security.microsoft.com:443 (EDR Endpoints)" -ForegroundColor Gray
            Write-Host "                  - events.data.microsoft.com:443 (Telemetry)" -ForegroundColor Gray
            Write-Host "                  - ctldl.windowsupdate.com:443 (Certificate Trust List)" -ForegroundColor Gray
            Write-Host "                  - crl.microsoft.com:80 (Certificate Revocation List)" -ForegroundColor Gray
            Write-Host "                  - *.data.microsoft.com:443 (Windows Telemetry/Settings)" -ForegroundColor Gray
            Write-Host "                  - *.delivery.mp.microsoft.com:443 (Windows Update)" -ForegroundColor Gray
            $issuesFound = $true
        } elseif ($failedMDEPrereqs.Count -gt 0) {
            Write-Host "[WARNING] MDE.Windows extension not installed - Some MDE runtime endpoints NOT accessible" -ForegroundColor Yellow
            Write-Host "          Failed MDE runtime checks: $($failedMDEPrereqs.Count) of $($mdeConnectivityTests.Count)" -ForegroundColor Yellow
            Write-Host "          Note: Extension can install, but MDE agent may not function properly" -ForegroundColor Yellow
            Write-Host "          Failed runtime endpoints:" -ForegroundColor Yellow
            foreach ($failed in $failedMDEPrereqs) {
                if ($failed.Category -eq "MDE") {
                    $desc = if ($failed.Description) { " - $($failed.Description)" } else { "" }
                    Write-Host "          - $($failed.URL)$desc" -ForegroundColor Red
                }
            }
            $issuesFound = $true
        } else {
            Write-Host "[INFO] MDE.Windows extension not installed - Connectivity prerequisites VERIFIED" -ForegroundColor Cyan
            Write-Host "       All $($mdeWindowsConnectivityTests.Count) extension installation endpoint checks passed" -ForegroundColor Green
            Write-Host "       All $($mdeConnectivityTests.Count - $mdeWindowsConnectivityTests.Count) MDE runtime endpoint checks passed" -ForegroundColor Green
            Write-Host "       Server is ready for MDE.Windows Arc extension installation" -ForegroundColor Green
        }
        Write-Host ""
    }
}

# Check for incorrect Organization ID
if ($status.MDE.OrgId -and $status.MDE.OrgId -ne "Not Available" -and $status.MDE.OrgId -ne "Error") {
    if ($status.MDE.OrgId -ne $ExpectedOrgId) {
        Write-Host "[CRITICAL] MDE Organization ID mismatch" -ForegroundColor Red
        Write-Host "           Expected: $ExpectedOrgId" -ForegroundColor Red
        Write-Host "           Found:    $($status.MDE.OrgId)" -ForegroundColor Red
        Write-Host "           Action: Server is onboarded to wrong organization - re-onboard required" -ForegroundColor Yellow
        $issuesFound = $true
    }
}

# Check Extension Service Status
if (-not $SkipArc -and $status.ExtensionService.Status -ne "Running") {
    Write-Host "[CRITICAL] Azure Arc Extension Service is not running" -ForegroundColor Red
    Write-Host "           Service Status: $($status.ExtensionService.Status)" -ForegroundColor Red
    Write-Host "           Impact: Extensions cannot install, update, or report status" -ForegroundColor Red
    Write-Host ""
    Write-Host "           WHY 'No status file' appears:" -ForegroundColor Yellow
    Write-Host "           - Extension Service writes status files to local disk" -ForegroundColor Gray
    Write-Host "           - When service is stopped/failed, no status files are created" -ForegroundColor Gray
    Write-Host "           - Portal shows ARM deployment status (from Azure)" -ForegroundColor Gray
    Write-Host "           - Script shows local file status (from machine)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "           TROUBLESHOOTING STEPS:" -ForegroundColor Yellow
    Write-Host "           1. Check service status: Get-Service ExtensionService" -ForegroundColor Cyan
    Write-Host "           2. Check dependent services: azcmagent show" -ForegroundColor Cyan
    Write-Host "           3. Review extension logs:" -ForegroundColor Cyan
    Write-Host "              $($status.ExtensionService.LogPath)" -ForegroundColor DarkGray
    Write-Host "           4. Check GuestConfig folder permissions:" -ForegroundColor Cyan
    Write-Host "              $env:ProgramData\GuestConfig\" -ForegroundColor DarkGray
    Write-Host "           5. Restart Extension Service if needed:" -ForegroundColor Cyan
    Write-Host "              Restart-Service ExtensionService -Force" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "           Reference: https://learn.microsoft.com/en-us/azure/azure-arc/servers/troubleshoot-vm-extensions" -ForegroundColor DarkGray
    $issuesFound = $true
}

# Check if extensions show 'No status file' but service is running
$noStatusExtensions = $status.Extensions | Where-Object { $_.Status -match "No status file" }
if (-not $SkipArc -and $noStatusExtensions.Count -gt 0 -and $status.ExtensionService.Status -eq "Running") {
    Write-Host "[INFO] Extensions showing 'No status file' while Extension Service is running" -ForegroundColor Cyan
    Write-Host "       This is NORMAL for newly deployed extensions that haven't completed first run" -ForegroundColor Gray
    Write-Host ""
    Write-Host "       Portal Status vs Local Status:" -ForegroundColor Cyan
    Write-Host "       - Azure Portal: Shows ARM deployment status (from Azure cloud)" -ForegroundColor Gray
    Write-Host "       - This Script: Shows local status files (from machine disk)" -ForegroundColor Gray
    Write-Host "       - If Portal shows 'Succeeded' = Extension deployed successfully via ARM" -ForegroundColor Gray
    Write-Host "       - 'No status file' = Extension hasn't written local status yet" -ForegroundColor Gray
    Write-Host ""
    Write-Host "       Wait 5-10 minutes and check extension logs at:" -ForegroundColor Cyan
    Write-Host "       $env:ProgramData\GuestConfig\extension_logs\" -ForegroundColor DarkGray
    Write-Host ""
}

# Check Windows Setup ImageState
if ($status.WindowsSetup.ImageState -and $status.WindowsSetup.ImageState -ne "Not Found" -and $status.WindowsSetup.ImageState -ne "Path Not Found") {
    if ($status.WindowsSetup.ImageState -ne "IMAGE_STATE_COMPLETE") {
        Write-Host "[CRITICAL] Windows Setup ImageState is incomplete" -ForegroundColor Red
        Write-Host "           Current ImageState: '$($status.WindowsSetup.ImageState)'" -ForegroundColor Red
        Write-Host "           Expected: 'IMAGE_STATE_COMPLETE'" -ForegroundColor Yellow
        Write-Host "           Issue: System has not completed Windows setup/OOBE process" -ForegroundColor Red
        Write-Host "           Action: Complete Windows installation and OOBE configuration" -ForegroundColor Yellow
        Write-Host "           Registry: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" -ForegroundColor Gray
        $issuesFound = $true
    }
}

# Check System Drive Space
if ($status.SystemDrive.FreeSpaceGB -ne $null) {
    if ($status.SystemDrive.FreeSpaceGB -lt 5) {
        Write-Host "[CRITICAL] System drive (C:) has critically low disk space" -ForegroundColor Red
        Write-Host "           Free Space: $($status.SystemDrive.FreeSpaceGB) GB ($($status.SystemDrive.FreeSpacePercent)%)" -ForegroundColor Red
        Write-Host "           Total Space: $($status.SystemDrive.TotalSpaceGB) GB" -ForegroundColor Yellow
        Write-Host "           Issue: Less than 5 GB free space available" -ForegroundColor Red
        Write-Host "           Action: Free up disk space immediately to prevent system issues" -ForegroundColor Yellow
        Write-Host "           Recommended: Clean temp files, logs, and unnecessary data" -ForegroundColor Yellow
        $issuesFound = $true
    } elseif ($status.SystemDrive.FreeSpaceGB -lt 10) {
        Write-Host "[WARNING] System drive (C:) has low disk space" -ForegroundColor Yellow
        Write-Host "          Free Space: $($status.SystemDrive.FreeSpaceGB) GB ($($status.SystemDrive.FreeSpacePercent)%)" -ForegroundColor Yellow
        Write-Host "          Total Space: $($status.SystemDrive.TotalSpaceGB) GB" -ForegroundColor Gray
        Write-Host "          Action: Consider freeing up disk space" -ForegroundColor Yellow
        $issuesFound = $true
    } elseif ($status.SystemDrive.FreeSpacePercent -lt 10) {
        Write-Host "[WARNING] System drive (C:) has low disk space percentage" -ForegroundColor Yellow
        Write-Host "          Free Space: $($status.SystemDrive.FreeSpaceGB) GB ($($status.SystemDrive.FreeSpacePercent)%)" -ForegroundColor Yellow
        Write-Host "          Total Space: $($status.SystemDrive.TotalSpaceGB) GB" -ForegroundColor Gray
        Write-Host "          Action: Monitor disk usage and plan cleanup" -ForegroundColor Yellow
        $issuesFound = $true
    } else {
        Write-Host "[INFO] System drive (C:) space: $($status.SystemDrive.FreeSpaceGB) GB free ($($status.SystemDrive.FreeSpacePercent)%) of $($status.SystemDrive.TotalSpaceGB) GB total" -ForegroundColor Cyan
    }
}

if (-not $issuesFound) {
    Write-Host "[OK] No critical issues detected" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   FIREWALL WHITELIST ANALYSIS         " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if there are failed mandatory MDE endpoints
$failedMandatoryEndpoints = @($status.ConnectivityChecks | Where-Object { 
    $_.Status -eq "Failed" -and ($_.Category -eq "MDE" -or $_.Category -eq "MDE.Windows") -and $_.Mandatory -eq $true 
})

if ($failedMandatoryEndpoints -and $failedMandatoryEndpoints.Count -gt 0) {
    Write-Host "ANALYSIS: Comparing failed endpoints against typical firewall whitelist" -ForegroundColor Yellow
    Write-Host ""
    
    # Define what firewall team typically claims to whitelist
    $typicalWhitelist = @(
        "*.endpoint.security.microsoft.com"
        "*.smartscreen-prod.microsoft.com"
        "*.smartscreen.microsoft.com"
        "*.checkappexec.microsoft.com"
        "*.urs.microsoft.com"
        "go.microsoft.com"
        "definitionupdates.microsoft.com"
        "*.update.microsoft.com"
        "*.delivery.mp.microsoft.com"
        "*.windowsupdate.com"
        "*.download.windowsupdate.com"
        "*.download.microsoft.com"
        "www.microsoft.com"
        "ctldl.windowsupdate.com"
        "crl.microsoft.com"
        "login.microsoftonline.com"
        "*.wns.windows.com"
        "login.live.com"
        "*.security.microsoft.com"
        "*.blob.core.windows.net"
        "login.windows.net"
        "settings-win.data.microsoft.com"
        "*.wdcp.microsoft.com"
        "*.wd.microsoft.com"
        "au.vortex-win.data.microsoft.com"
        "au-v20.events.data.microsoft.com"
        "*.microsoftonline-p.com"
        "secure.aadcdn.microsoftonline-p.com"
        "static2.sharepointonline.com"
        "*.securitycenter.windows.com"
        "*.api.security.microsoft.com"
        "security.microsoft.com"
        "x.cp.wd.microsoft.com"
    )
    
    # Check each failed endpoint
    $missingFromWhitelist = @()
    
    foreach ($endpoint in $failedMandatoryEndpoints) {
        $url = $endpoint.URL -replace "https://", "" -replace "http://", "" -replace ":443", "" -replace ":80", ""
        $hostname = $url
        
        # Check if this hostname matches any whitelist pattern
        $isWhitelisted = $false
        foreach ($pattern in $typicalWhitelist) {
            # Convert wildcard pattern to regex
            $regexPattern = "^" + ($pattern -replace "\.", "\." -replace "\*", ".*") + "$"
            if ($hostname -match $regexPattern) {
                $isWhitelisted = $true
                break
            }
        }
        
        if (-not $isWhitelisted) {
            $missingFromWhitelist += [PSCustomObject]@{
                URL = $endpoint.URL
                Hostname = $hostname
                Purpose = $endpoint.Description
            }
        }
    }
    
    if ($missingFromWhitelist.Count -gt 0) {
        Write-Host "🔴 CRITICAL FINDING: Missing URLs in Firewall Whitelist" -ForegroundColor Red
        Write-Host ""
        Write-Host "   The following MANDATORY MDE endpoints are FAILING connectivity tests" -ForegroundColor Red
        Write-Host "   but are NOT covered by typical firewall whitelist patterns:" -ForegroundColor Red
        Write-Host ""
        
        foreach ($missing in $missingFromWhitelist) {
            Write-Host "   ❌ $($missing.URL)" -ForegroundColor Red
            if ($missing.Purpose) {
                Write-Host "      Purpose: $($missing.Purpose)" -ForegroundColor Gray
            }
            Write-Host "      Status: NOT whitelisted - Add to firewall rules" -ForegroundColor Yellow
            Write-Host ""
        }
        
        Write-Host "   ACTION REQUIRED: Add these URLs to firewall whitelist" -ForegroundColor Yellow
        Write-Host "   ───────────────────────────────────────────────────────" -ForegroundColor Yellow
        Write-Host ""
        
        # Extract unique wildcard patterns needed
        $neededPatterns = @()
        foreach ($missing in $missingFromWhitelist) {
            $hostname = $missing.Hostname
            
            # Suggest wildcard pattern
            if ($hostname -match "winatp-gw-.*\.microsoft\.com") {
                $pattern = "winatp-gw-*.microsoft.com"
            } elseif ($hostname -match "edr-.*\.endpoint\.security\.microsoft\.com") {
                $pattern = "edr-*.*.endpoint.security.microsoft.com"
            } elseif ($hostname -match ".*\.events\.data\.microsoft\.com") {
                $pattern = "*.events.data.microsoft.com"
            } elseif ($hostname -eq "events.data.microsoft.com") {
                $pattern = "events.data.microsoft.com"
            } elseif ($hostname -match "cdn\..*\.cp\.wd\.microsoft\.com") {
                $pattern = "cdn.*.cp.wd.microsoft.com"
            } elseif ($hostname -match ".*\.cp\.wd\.microsoft\.com") {
                $pattern = "*.cp.wd.microsoft.com"
            } else {
                $pattern = $hostname
            }
            
            if ($neededPatterns -notcontains $pattern) {
                $neededPatterns += $pattern
            }
        }
        
        Write-Host "   Firewall Rules to Add (Wildcard Patterns):" -ForegroundColor Cyan
        foreach ($pattern in $neededPatterns) {
            Write-Host "   • $pattern" -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "   Configuration Example:" -ForegroundColor Cyan
        Write-Host "   Protocol: HTTPS" -ForegroundColor Gray
        Write-Host "   Port: 443" -ForegroundColor Gray
        Write-Host "   Direction: Outbound" -ForegroundColor Gray
        Write-Host "   Action: Allow" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   After adding rules:" -ForegroundColor Yellow
        Write-Host "   1. Verify rules are applied: Test-NetConnection <endpoint> -Port 443" -ForegroundColor Gray
        Write-Host "   2. Restart MDE service: Restart-Service Sense -Force" -ForegroundColor Gray
        Write-Host "   3. Wait 5-10 minutes for cloud connection" -ForegroundColor Gray
        Write-Host "   4. Re-run this script to verify connectivity" -ForegroundColor Gray
        Write-Host ""
        
    } else {
        Write-Host "✅ All failed mandatory endpoints ARE covered by typical whitelist patterns" -ForegroundColor Green
        Write-Host ""
        Write-Host "   Problem: Firewall rules may be configured but not applied correctly" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   Possible Issues:" -ForegroundColor Cyan
        Write-Host "   • Rules configured but not activated/pushed to devices" -ForegroundColor Gray
        Write-Host "   • Proxy authentication required but not configured" -ForegroundColor Gray
        Write-Host "   • DNS resolution failing for these domains" -ForegroundColor Gray
        Write-Host "   • Intermediate proxy/firewall blocking traffic" -ForegroundColor Gray
        Write-Host "   • SSL inspection breaking HTTPS connections" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   Troubleshooting Steps:" -ForegroundColor Cyan
        Write-Host "   1. Verify firewall rules are actually applied on the network path" -ForegroundColor Gray
        Write-Host "   2. Check DNS resolution: Resolve-DnsName <failed-endpoint>" -ForegroundColor Gray
        Write-Host "   3. Test from server: Test-NetConnection <endpoint> -Port 443" -ForegroundColor Gray
        Write-Host "   4. Check proxy configuration: netsh winhttp show proxy" -ForegroundColor Gray
        Write-Host "   5. Test with curl: curl -v https://<endpoint>" -ForegroundColor Gray
        Write-Host "   6. Check if SSL inspection is interfering" -ForegroundColor Gray
        Write-Host ""
    }
    
} else {
    Write-Host "✅ No mandatory MDE endpoint connectivity failures detected" -ForegroundColor Green
    Write-Host "   All critical URLs are reachable" -ForegroundColor Gray
    Write-Host ""
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "             LOG LOCATIONS              " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
if (-not $SkipArc) {
    Write-Host "   Arc Agent:   C:\ProgramData\AzureConnectedMachineAgent\Log\"
}
Write-Host "   MDE:         Event Viewer > Applications and Services Logs > Microsoft > Windows > SENSE"
if (-not $SkipArc) {
    Write-Host "   Extensions:  C:\ProgramData\GuestConfig\extension_logs\"
    Write-Host "   Arc Plugins: C:\Packages\Plugins\Microsoft.Azure.*\"
}
Write-Host ""
Write-Host "=== Check Complete ===" -ForegroundColor Cyan

