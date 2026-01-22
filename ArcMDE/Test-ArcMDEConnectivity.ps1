
<# 
.SYNOPSIS
 Validates Microsoft Defender for Endpoint (MDE) connectivity for Australia (AU) with proxy/PAC/WPAD awareness.

.DESCRIPTION
 - Imports Microsoft’s official MDE URL list (CSV/XLSX) when provided (recommended), or tries to download the Streamlined sheet.
 - Filters for Geography in ('WW','AU') and Defender for Endpoint services for your chosen model (Streamlined|Standard).
 - Falls back to a minimal built-in AU/WW endpoint set when lists aren’t available.
 - Performs DNS, TCP:443, and optional HTTPS HEAD tests with TLS 1.2.
 - Respects WinINET proxy, PAC/WPAD, or an explicit -Proxy (with optional -ProxyCredential).

.PARAMETER UrlListPath
 Local path to the exported **Microsoft official** MDE URL list (CSV recommended). The script auto-filters to AU + WW rows. 
 See: Learn guidance to use the consolidated (streamlined) list and filter by geography. 

.PARAMETER TryDownload
 Attempt to download the Streamlined URL list from Microsoft (aka.ms). If download fails, uses the built-in minimal list.

.PARAMETER Model
 'Streamlined' (new consolidated URL set) or 'Standard' (legacy full list for older agents).

.PARAMETER Region
 Use 'AU' (default). The filter keeps rows with Geography 'WW' or matching 'AU'.

.PARAMETER Proxy
 Explicit proxy URI (e.g., http://proxy:8080). Overrides auto-detected settings.

.PARAMETER ProxyCredential
 PSCredential for authenticating to the proxy if needed.

.PARAMETER SkipHttp
 Skip HTTPS HEAD/GET tests (only DNS + TCP:443 are tested). Useful where SSL interception blocks requests.

.OUTPUTS
 - Console table with Pass/Fail per endpoint.
 - CSV: .\MDE_Connectivity_AU_<timestamp>.csv
 - JSON: .\MDE_Connectivity_AU_<timestamp>.json

.NOTES
 - Based on Microsoft guidance to use the consolidated/streamlined URL list and filter by geography. 
   See: https://learn.microsoft.com/…/defender-endpoint/configure-environment  (consolidated list & geography filter)
        https://learn.microsoft.com/…/defender-endpoint/configure-device-connectivity (streamlined connectivity)
 - Proxy/Private Link considerations stem from recent troubleshooting threads and AU defaults used in field scripts.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$UrlListPath,

    [switch]$TryDownload,

    [ValidateSet('Streamlined','Standard')]
    [string]$Model = 'Streamlined',

    [ValidateSet('AU','WW','US','EU','UK','CA','ASIA')]
    [string]$Region = 'AU',

    [string]$Proxy,

    [System.Management.Automation.PSCredential]$ProxyCredential,

    [switch]$SkipHttp
)

# -------- Helpers --------

function Write-Section($title) {
    $line = ('=' * ($title.Length + 2))
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host " $title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Get-ProxyConfiguration {
    $proxyConfig = @{
        ProxyEnabled = $false
        ProxyServer = $null
        ProxyBypass = $null
        AutoConfigURL = $null
        AutoDetect = $false
        DetectionMethod = "None"
        EffectiveProxy = $null
    }

    # Check HKLM (System-wide, takes precedence on servers)
    $hklmPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    if (Test-Path $hklmPath) {
        $hklmSettings = Get-ItemProperty -Path $hklmPath -ErrorAction SilentlyContinue
        
        if ($hklmSettings.ProxyEnable -eq 1) {
            $proxyConfig.ProxyEnabled = $true
            $proxyConfig.ProxyServer = $hklmSettings.ProxyServer
            $proxyConfig.ProxyBypass = $hklmSettings.ProxyOverride
            $proxyConfig.DetectionMethod = "HKLM Registry (System-wide)"
        }
        
        if ($hklmSettings.AutoConfigURL) {
            $proxyConfig.AutoConfigURL = $hklmSettings.AutoConfigURL
            $proxyConfig.DetectionMethod = "PAC File (HKLM)"
        }
        
        if ($hklmSettings.AutoDetect -eq 1) {
            $proxyConfig.AutoDetect = $true
            $proxyConfig.DetectionMethod = "WPAD Auto-Detect (HKLM)"
        }
    }

    # Check HKCU (User-specific, fallback if HKLM not set)
    if (-not $proxyConfig.ProxyEnabled -and -not $proxyConfig.AutoConfigURL -and -not $proxyConfig.AutoDetect) {
        $hkcuPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        if (Test-Path $hkcuPath) {
            $hkcuSettings = Get-ItemProperty -Path $hkcuPath -ErrorAction SilentlyContinue
            
            if ($hkcuSettings.ProxyEnable -eq 1) {
                $proxyConfig.ProxyEnabled = $true
                $proxyConfig.ProxyServer = $hkcuSettings.ProxyServer
                $proxyConfig.ProxyBypass = $hkcuSettings.ProxyOverride
                $proxyConfig.DetectionMethod = "HKCU Registry (User-specific)"
            }
            
            if ($hkcuSettings.AutoConfigURL) {
                $proxyConfig.AutoConfigURL = $hkcuSettings.AutoConfigURL
                $proxyConfig.DetectionMethod = "PAC File (HKCU)"
            }
            
            if ($hkcuSettings.AutoDetect -eq 1) {
                $proxyConfig.AutoDetect = $true
                $proxyConfig.DetectionMethod = "WPAD Auto-Detect (HKCU)"
            }
        }
    }

    # Try to get runtime proxy using .NET WebRequest (this respects PAC/WPAD at runtime)
    try {
        $systemProxy = [System.Net.WebRequest]::GetSystemWebProxy()
        if ($systemProxy) {
            # Test with a common URL to see if proxy is actually used
            $testUri = [System.Uri]"https://www.microsoft.com"
            $proxyUri = $systemProxy.GetProxy($testUri)
            
            # If GetProxy returns a different URI than the test URI, proxy is in use
            if ($proxyUri -and $proxyUri.ToString() -ne $testUri.ToString()) {
                $proxyConfig.EffectiveProxy = $proxyUri.ToString()
                if (-not $proxyConfig.DetectionMethod -or $proxyConfig.DetectionMethod -eq "None") {
                    $proxyConfig.DetectionMethod = "Runtime (.NET GetSystemWebProxy)"
                }
            }
        }
    } catch {
        Write-Verbose "Could not detect runtime proxy: $_"
    }

    # If we detected any proxy configuration, mark as enabled
    if ($proxyConfig.ProxyServer -or $proxyConfig.AutoConfigURL -or $proxyConfig.AutoDetect -or $proxyConfig.EffectiveProxy) {
        $proxyConfig.ProxyEnabled = $true
    }

    return $proxyConfig
}

function Get-EffectiveProxy {
    param($ExplicitProxy, $ProxyCred)

    $res = [ordered]@{
        Mode           = 'None'
        Proxy          = $null
        BypassList     = $null
        PAC            = $null
        AutoDetectWPAD = $false
        Credential     = $ProxyCred
    }

    if ($ExplicitProxy) {
        $res.Mode  = 'Explicit'
        $res.Proxy = $ExplicitProxy
        return $res
    }

    # Use the comprehensive proxy detection
    $detected = Get-ProxyConfiguration
    
    if ($detected.AutoConfigURL) {
        $res.Mode = 'PAC'
        $res.PAC = $detected.AutoConfigURL
        $res.BypassList = $detected.ProxyBypass
    }
    elseif ($detected.AutoDetect) {
        $res.Mode = 'WPAD'
        $res.AutoDetectWPAD = $true
    }
    elseif ($detected.ProxyServer) {
        $res.Mode = 'WinINET'
        $res.Proxy = $detected.ProxyServer
        $res.BypassList = $detected.ProxyBypass
    }
    elseif ($detected.EffectiveProxy) {
        $res.Mode = 'Runtime'
        $res.Proxy = $detected.EffectiveProxy
    }

    return $res
}

function Set-Tls12 {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } catch { }
}

function Invoke-Web {
    param(
        [string]$Uri,
        [int]$TimeoutSec = 5,
        [string]$ProxyMode,
        [string]$ProxyUri,
        [System.Management.Automation.PSCredential]$ProxyCred
    )
    
    $splat = @{
        Uri                 = $Uri
        Method              = 'Head'
        UseBasicParsing     = $true
        TimeoutSec          = $TimeoutSec
        ErrorAction         = 'Stop'
        MaximumRedirection  = 5
    }
    if ($ProxyMode -in @('Explicit','WinINET')) {
        if ($ProxyUri) { $splat['Proxy'] = $ProxyUri }
        if ($ProxyCred) { $splat['ProxyCredential'] = $ProxyCred }
    }
    try {
        $r = Invoke-WebRequest @splat
        # Try to detect if proxy was actually used during the request
        $actualProxy = $null
        try {
            $webProxy = [System.Net.WebRequest]::DefaultWebProxy
            if ($webProxy) {
                $targetUri = [Uri]$Uri
                $proxyUri = $webProxy.GetProxy($targetUri)
                if ($proxyUri -and $proxyUri.ToString() -ne $targetUri.ToString()) {
                    $actualProxy = $proxyUri.Host
                }
            }
        } catch { }
        return @{ Ok = $true; Code = $r.StatusCode; Desc = $r.StatusDescription; ProxyUsed = $actualProxy }
    }
    catch {
        return @{ Ok = $false; Code = $null; Desc = $_.Exception.Message; ProxyUsed = $null }
    }
}

function Test-Host443 {
    param([string]$HostName)
    try {
        # Use TcpClient for faster connection test (much faster than Test-NetConnection)
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connection = $tcpClient.BeginConnect($HostName, 443, $null, $null)
        $wait = $connection.AsyncWaitHandle.WaitOne(3000, $false)  # 3 second timeout
        
        if ($wait) {
            try {
                $tcpClient.EndConnect($connection)
                $remoteIp = ($tcpClient.Client.RemoteEndPoint).Address.ToString()
                # Strip IPv6 prefix from IPv4-mapped addresses for cleaner display
                if ($remoteIp -match '^::ffff:(.+)$') {
                    $remoteIp = $Matches[1]
                }
                $tcpClient.Close()
                return @{ TcpOk = $true; RemoteAddress = $remoteIp }
            } catch {
                $tcpClient.Close()
                return @{ TcpOk = $false; RemoteAddress = $null }
            }
        } else {
            $tcpClient.Close()
            return @{ TcpOk = $false; RemoteAddress = $null }
        }
    } catch {
        return @{ TcpOk = $false; RemoteAddress = $null }
    }
}

function Test-PrivateIpAddress {
    param([string]$IpAddress)
    
    if (-not $IpAddress) { return $false }
    
    try {
        $ip = [System.Net.IPAddress]::Parse($IpAddress)
        $bytes = $ip.GetAddressBytes()
        
        # Check RFC 1918 private ranges:
        # 10.0.0.0/8
        if ($bytes[0] -eq 10) { return $true }
        
        # 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $true }
        
        # 192.168.0.0/16
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
        
        return $false
    } catch {
        return $false
    }
}

function Resolve-Host {
    param([string]$HostName)
    try {
        $dns = Resolve-DnsName -Name $HostName -Type A -ErrorAction Stop
        $addresses = ($dns | Where-Object {$_.Type -eq 'A'} | Select-Object -ExpandProperty IPAddress)
        
        # Check for Private Link CNAME in the resolution chain
        $hasPrivateLink = $false
        $cnameRecords = $dns | Where-Object {$_.Type -eq 'CNAME'} | Select-Object -ExpandProperty NameHost
        if ($cnameRecords) {
            $hasPrivateLink = $cnameRecords | Where-Object { $_ -match 'privatelink' } | Measure-Object | Select-Object -ExpandProperty Count
            $hasPrivateLink = $hasPrivateLink -gt 0
        }
        
        # Check if any resolved IP is private
        $hasPrivateIp = $false
        if ($addresses) {
            foreach ($addr in $addresses) {
                if (Test-PrivateIpAddress -IpAddress $addr) {
                    $hasPrivateIp = $true
                    break
                }
            }
        }
        
        return @{ 
            DnsOk = $true
            Addresses = $addresses
            HasPrivateLink = ($hasPrivateLink -or $hasPrivateIp)
            PrivateLinkMethod = if ($hasPrivateLink) { 'CNAME' } elseif ($hasPrivateIp) { 'PrivateIP' } else { $null }
        }
    } catch {
        return @{ DnsOk = $false; Addresses = @(); HasPrivateLink = $false; PrivateLinkMethod = $null }
    }
}

function Get-ProxyIpAddress {
    param([string]$ProxyUri)
    
    if (-not $ProxyUri) { return $null }
    
    try {
        # Extract hostname from proxy URI (e.g., http://proxy.company.com:8080 -> proxy.company.com)
        $uri = [Uri]$ProxyUri
        $proxyHost = $uri.Host
        
        $dns = Resolve-DnsName -Name $proxyHost -Type A -ErrorAction Stop
        $proxyIp = ($dns | Where-Object {$_.Type -eq 'A'} | Select-Object -First 1).IPAddress
        return $proxyIp
    } catch {
        return $null
    }
}

function Get-ActualProxyForUrl {
    param(
        [string]$TargetUrl,
        [object]$ProxyInfo
    )
    
    # For WPAD/PAC, we need to check what proxy is actually used for this specific URL
    try {
        $webProxy = [System.Net.WebRequest]::DefaultWebProxy
        if ($null -eq $webProxy) { return $null }
        
        $targetUri = [Uri]$TargetUrl
        $proxyUri = $webProxy.GetProxy($targetUri)
        
        # If GetProxy returns the same URI, it means direct connection (no proxy)
        if ($null -eq $proxyUri -or $proxyUri.ToString() -eq $targetUri.ToString()) {
            return $null
        }
        
        # Extract proxy IP - handle both hostname and IP
        $proxyHost = $proxyUri.Host
        
        # Check if it's already an IP address
        $ipAddress = $null
        if ([System.Net.IPAddress]::TryParse($proxyHost, [ref]$ipAddress)) {
            return $proxyHost
        }
        
        # It's a hostname, resolve it
        try {
            $dns = Resolve-DnsName -Name $proxyHost -Type A -ErrorAction Stop
            $proxyIp = ($dns | Where-Object {$_.Type -eq 'A'} | Select-Object -First 1).IPAddress
            return $proxyIp
        } catch {
            # If DNS resolution fails, return the hostname
            return $proxyHost
        }
    } catch {
        return $null
    }
}

function Get-NextHopIp {
    param([string]$DestinationIp)
    
    if (-not $DestinationIp) { return $null }
    
    try {
        # Get the route to the destination
        $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | 
            Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' } | 
            Select-Object -First 1
        
        if ($route -and $route.NextHop) {
            return $route.NextHop
        }
        
        # Fallback: try to find specific route
        $specificRoute = Find-NetRoute -RemoteIPAddress $DestinationIp -ErrorAction SilentlyContinue | 
            Select-Object -First 1
        
        if ($specificRoute -and $specificRoute.NextHop -and $specificRoute.NextHop -ne '0.0.0.0') {
            return $specificRoute.NextHop
        }
        
        return $null
    } catch {
        return $null
    }
}

function Get-LocalComputerInfo {
    $info = @{
        Hostname = $env:COMPUTERNAME
        FQDN = $null
    }
    
    try {
        # Try to get FQDN using .NET DNS methods
        $fqdn = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
        if ($fqdn) {
            $info.FQDN = $fqdn
        }
    } catch {
        # Fallback: try to construct FQDN from domain
        try {
            $domain = (Get-WmiObject Win32_ComputerSystem).Domain
            if ($domain -and $domain -ne 'WORKGROUP') {
                $info.FQDN = "$($env:COMPUTERNAME).$domain"
            } else {
                $info.FQDN = $env:COMPUTERNAME
            }
        } catch {
            $info.FQDN = $env:COMPUTERNAME
        }
    }
    
    return $info
}

function Import-OfficialList {
    param(
        [string]$Path,
        [string]$Model,
        [string]$Region
    )
    if (-not $Path) { return @() }
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()

    # We prefer CSV because it imports cleanly without extra modules
    if ($ext -eq '.csv') {
        $rows = Import-Csv -Path $Path
    } elseif ($ext -in @('.xlsx','.xls')) {
        # Lightweight XLSX reader via COM may not be available; advise CSV when possible.
        Write-Warning "XLS/XLSX detected. Please export the official sheet as CSV for best results."
        try {
            $rows = Import-Csv -Path $Path  # If it’s actually CSV via wrong extension, this still works
        } catch {
            return @()
        }
    } else {
        Write-Warning "Unsupported file extension '$ext'. Provide CSV if possible."
        return @()
    }

    # Expected headers vary; we try to normalize common patterns from the official sheet:
    # Columns often include: Service, Model, Geography, URL/Domain or Domain, Ports, Notes
    $norm = foreach ($r in $rows) {
        # PowerShell 5.1 compatible null-coalescing
        $svc = if ($r.Service) { $r.Service } elseif ($r.'Service Name') { $r.'Service Name' } elseif ($r.'Workload') { $r.'Workload' } else { '' }
        $mdl = if ($r.Model) { $r.Model } elseif ($r.'Connectivity Model') { $r.'Connectivity Model' } else { '' }
        $geo = if ($r.Geography) { $r.Geography } elseif ($r.'Geo') { $r.'Geo' } else { '' }
        $dom = if ($r.Domain) { $r.Domain } elseif ($r.'URL/Domain') { $r.'URL/Domain' } elseif ($r.'FQDN') { $r.'FQDN' } elseif ($r.'Hostname') { $r.'Hostname' } else { '' }
        $prt = if ($r.Ports) { $r.Ports } elseif ($r.'Port') { $r.'Port' } else { '' }
        
        [pscustomobject]@{
            Service   = $svc
            Model     = $mdl
            Geography = $geo
            Domain    = $dom
            Ports     = $prt
        }
    }

    $geoFilter = @('WW', $Region.ToUpper())
    $modelWant = if ($Model -eq 'Streamlined') { 'Streamlined' } else { 'Standard' }

    $filtered = $norm |
        Where-Object {
            $_.Service -match 'Defender.*Endpoint' -and
            $geoFilter -contains ($_.Geography.ToUpper()) -and
            ( ($_.Model -eq $null -and $Model -eq 'Standard') -or ($_.Model -match $modelWant) )
        } |
        Where-Object { $_.Domain -and $_.Domain -notmatch '^\s*$' } |
        Select-Object -ExpandProperty Domain -Unique

    return $filtered
}

function Get-BuiltinMinimalList {
    param(
        [string]$Model,
        [string]$Region = 'AU'
    )

    # Comprehensive set for WW (Worldwide) and regional endpoints
    # Returns endpoints filtered by region + WW (Worldwide)
    # Duplicates removed, obsolete endpoints removed
    $allEndpoints = @(
        # ===== CORE MDE ENDPOINTS =====
        # Core MDE endpoints (WW) - Required
        @{Domain='go.microsoft.com'; Geo='WW'; Model='Both'; Service='MDE'; Purpose='MDE Installer & Updates'},
        @{Domain='api.security.microsoft.com'; Geo='WW'; Model='Streamlined'; Service='MDE'; Purpose='MDE API Endpoint'},
        @{Domain='endpoint.security.microsoft.com'; Geo='WW'; Model='Streamlined'; Service='MDE'; Purpose='MDE Security Endpoint'},
        @{Domain='securitycenter.windows.com'; Geo='WW'; Model='Both'; Service='MDE'; Purpose='Security Center Portal'},
        @{Domain='login.microsoftonline.com'; Geo='WW'; Model='Both'; Service='MDE'; Purpose='Azure AD Authentication'},
        @{Domain='login.windows.net'; Geo='WW'; Model='Streamlined'; Service='MDE'; Purpose='Azure AD Authentication Alt'},
        
        # United States specific MDE endpoints - Required
        @{Domain='winatp-gw-us.microsoft.com'; Geo='US'; Model='Both'; Service='MDE'; Purpose='MDE Gateway US'},
        @{Domain='winatp-gw-use.microsoft.com'; Geo='US'; Model='Both'; Service='MDE'; Purpose='MDE Gateway US East'},
        @{Domain='winatp-gw-usw.microsoft.com'; Geo='US'; Model='Both'; Service='MDE'; Purpose='MDE Gateway US West'},
        @{Domain='us-v20.events.data.microsoft.com'; Geo='US'; Model='Both'; Service='MDE'; Purpose='Cyber Data US'},
        @{Domain='automatedirstrprdusc.blob.core.windows.net'; Geo='US'; Model='Streamlined'; Service='MDE'; Purpose='MDE Package Storage US Central'},
        @{Domain='automatedirstrprduse.blob.core.windows.net'; Geo='US'; Model='Streamlined'; Service='MDE'; Purpose='MDE Package Storage US East'},
        
        # Australia specific MDE endpoints - Required
        @{Domain='endpoint-aus.security.microsoft.com'; Geo='AU'; Model='Streamlined'; Service='MDE'; Purpose='MDE Endpoint AU South'},
        @{Domain='endpoint-aue.security.microsoft.com'; Geo='AU'; Model='Streamlined'; Service='MDE'; Purpose='MDE Endpoint AU East'},
        @{Domain='winatp-gw-aus.microsoft.com'; Geo='AU'; Model='Both'; Service='MDE'; Purpose='MDE Gateway AU South'},
        @{Domain='winatp-gw-aue.microsoft.com'; Geo='AU'; Model='Both'; Service='MDE'; Purpose='MDE Gateway AU East'},
        @{Domain='automatedirstrprdaue.blob.core.windows.net'; Geo='AU'; Model='Streamlined'; Service='MDE'; Purpose='MDE Package Storage AU East'},
        @{Domain='automatedirstrprdaus.blob.core.windows.net'; Geo='AU'; Model='Both'; Service='MDE'; Purpose='MDE Package Storage AU South'},
        @{Domain='au-v20.events.data.microsoft.com'; Geo='AU'; Model='Both'; Service='MDE'; Purpose='Cyber Data AU'},
        
        # MDE Telemetry & Optional endpoints (WW)
        @{Domain='events.data.microsoft.com'; Geo='WW'; Model='Both'; Service='MDE'; Purpose='MDE Telemetry'},
        @{Domain='settings-win.data.microsoft.com'; Geo='WW'; Model='Both'; Service='MDE'; Purpose='Windows Settings'},
        @{Domain='ris.api.iris.microsoft.com'; Geo='WW'; Model='Streamlined'; Service='MDE'; Purpose='Iris API Service'},
        @{Domain='wdcp.microsoft.com'; Geo='WW'; Model='Both'; Service='MDE'; Purpose='Cloud Protection'},
        @{Domain='wdcpalt.microsoft.com'; Geo='WW'; Model='Streamlined'; Service='MDE'; Purpose='Cloud Protection Alt'},
        @{Domain='x.cp.wd.microsoft.com'; Geo='WW'; Model='Both'; Service='MDE'; Purpose='Content Delivery'},
        
        # MDE Updates & Definitions (WW)
        @{Domain='definitionupdates.microsoft.com'; Geo='WW'; Model='Both'; Service='MDE'; Purpose='Definition Updates'},
        @{Domain='fe3.delivery.mp.microsoft.com'; Geo='WW'; Model='Both'; Service='MDE'; Purpose='Windows Update Delivery'},
        
        # MDE Management & Onboarding (WW only)
        @{Domain='onboardingpackageseusprd.blob.core.windows.net'; Geo='WW'; Model='Streamlined'; Service='MDE'; Purpose='Onboarding Packages'},
        @{Domain='winatpmanagement.windows.com'; Geo='WW'; Model='Streamlined'; Service='MDE'; Purpose='MDE Management'},
        
        # Certificate validation (WW) - Optional
        @{Domain='crl.microsoft.com'; Geo='WW'; Model='Both'; Service='MDE'; Purpose='Certificate Revocation'},
        @{Domain='ctldl.windowsupdate.com'; Geo='WW'; Model='Both'; Service='MDE'; Purpose='Certificate Trust List'},
        @{Domain='www.microsoft.com'; Geo='WW'; Model='Streamlined'; Service='MDE'; Purpose='Microsoft Homepage'},
        
        # ===== AZURE ARC CORE ENDPOINTS =====
        # Azure Arc Core Services (WW) - Required for Arc-enabled servers
        @{Domain='management.azure.com'; Geo='WW'; Model='Both'; Service='Arc'; Purpose='Azure Management API'},
        @{Domain='pas.windows.net'; Geo='WW'; Model='Both'; Service='Arc'; Purpose='Azure PAS Service'},
        @{Domain='guestnotificationservice.azure.com'; Geo='WW'; Model='Both'; Service='Arc'; Purpose='Guest Notification Service'},
        @{Domain='his.arc.azure.com'; Geo='WW'; Model='Both'; Service='Arc'; Purpose='Hybrid Identity Service'},
        @{Domain='guestconfiguration.azure.com'; Geo='WW'; Model='Both'; Service='Arc'; Purpose='Guest Configuration Service'},
        
        # Azure Arc - Private Link Endpoints (commonly used with Private Endpoint)
        @{Domain='ae.his.arc.azure.com'; Geo='AU'; Model='Both'; Service='Arc'; Purpose='HIS Private Link AU East'},
        @{Domain='gbl.his.arc.azure.com'; Geo='WW'; Model='Both'; Service='Arc'; Purpose='HIS Private Link Global'},
        @{Domain='agentserviceapi.guestconfiguration.azure.com'; Geo='WW'; Model='Both'; Service='Arc'; Purpose='Guest Config API Private Link'},
        @{Domain='australiaeast-gas.guestconfiguration.azure.com'; Geo='AU'; Model='Both'; Service='Arc'; Purpose='Guest Config AU East Private Link'},
        
        # Azure Arc - Australia Region Endpoints
        @{Domain='aus.his.arc.azure.com'; Geo='AU'; Model='Both'; Service='Arc'; Purpose='HIS AU South'},
        @{Domain='aus2.his.arc.azure.com'; Geo='AU'; Model='Both'; Service='Arc'; Purpose='HIS AU South 2'},
        @{Domain='australiaeast-dp.guestconfiguration.azure.com'; Geo='AU'; Model='Both'; Service='Arc'; Purpose='Guest Config Data Plane AU East'},
        @{Domain='australiasoutheast-dp.guestconfiguration.azure.com'; Geo='AU'; Model='Both'; Service='Arc'; Purpose='Guest Config Data Plane AU SE'},
        
        # Azure Arc - Download & Package Management
        @{Domain='download.microsoft.com'; Geo='WW'; Model='Both'; Service='Arc'; Purpose='Microsoft Downloads'},
        @{Domain='packages.microsoft.com'; Geo='WW'; Model='Both'; Service='Arc'; Purpose='Package Repository'},
        
        # ===== AZURE ARC EXTENSIONS =====
        # MDE Extension for Azure Arc (Australia region only)
        @{Domain='australia.cp.wd.microsoft.com'; Geo='AU'; Model='Both'; Service='Ext'; Purpose='MDE Extension Content AU'},
        
        # SQL Server Extension for Azure Arc (Monitoring & Log Analytics)
        @{Domain='san-af-aus-prod.azurewebsites.net'; Geo='AU'; Model='Both'; Service='Ext'; Purpose='SQL Extension Service AU'},
        @{Domain='aus.handler.control.monitor.azure.com'; Geo='AU'; Model='Both'; Service='Ext'; Purpose='Monitor Handler AU'},
        @{Domain='dc.services.visualstudio.com'; Geo='WW'; Model='Both'; Service='Ext'; Purpose='Application Insights'},
        
        # Azure Monitor Agent Extension (if using monitoring)
        @{Domain='global.handler.control.monitor.azure.com'; Geo='WW'; Model='Both'; Service='Ext'; Purpose='Monitor Handler Global'}
    )

    # Filter by region: return WW + selected region endpoints only
    $geoFilter = @('WW', $Region.ToUpper())
    $filtered = $allEndpoints | Where-Object { $geoFilter -contains $_.Geo }
    
    return $filtered
}

function Try-DownloadStreamlinedCsv {
    param($ProxyMode,$ProxyUri,$ProxyCred)

    # Microsoft Learn points to a consolidated/streamlined URL sheet via aka.ms link.
    # We use the public redirector; your egress must allow it.
    $aka = 'https://aka.ms/MDE-streamlined-urls'   # From Microsoft Learn guidance
    $tmp = Join-Path $env:TEMP ("MDE_streamlined_{0}.csv" -f ([Guid]::NewGuid()))
    try {
        $splat = @{ Uri = $aka; OutFile = $tmp; UseBasicParsing = $true; }
        if ($ProxyMode -in @('Explicit','WinINET') -and $ProxyUri) { $splat['Proxy'] = $ProxyUri }
        if ($ProxyCred) { $splat['ProxyCredential'] = $ProxyCred }
        Invoke-WebRequest @splat
        if (Test-Path $tmp) { return $tmp }
    } catch {
        Write-Warning "Auto-download failed: $($_.Exception.Message)"
    }
    return $null
}

# -------- Main --------
Write-Section "MDE Connectivity Test - Australia"
"Model     : Both (Standard + Streamlined)"
"Region    : $Region"

$proxyInfo = Get-EffectiveProxy -ExplicitProxy $Proxy -ProxyCred $ProxyCredential
$proxyDisplay = if ($proxyInfo.Proxy) { "[$($proxyInfo.Proxy)]" } elseif ($proxyInfo.PAC) { "[PAC: $($proxyInfo.PAC)]" } else { "" }
"ProxyMode : {0} {1}" -f $proxyInfo.Mode, $proxyDisplay
if ($proxyInfo.Mode -eq 'None') {
    Write-Host "Note: Per-URL proxy routing will be detected at runtime (PAC/WPAD may apply)" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Type Key: Both=Both models, Stream=Streamlined only, Stand=Standard only" -ForegroundColor Cyan

Set-Tls12

# Get local computer information once
$localInfo = Get-LocalComputerInfo

# Initialize DefaultWebProxy based on detected proxy configuration
if ($proxyInfo.Mode -eq 'PAC' -and $proxyInfo.PAC) {
    try {
        $webProxy = New-Object System.Net.WebProxy
        $webProxy.Address = $null
        $webProxy.ScriptLocation = [Uri]$proxyInfo.PAC
        [System.Net.WebRequest]::DefaultWebProxy = $webProxy
        Write-Host "Initialized PAC proxy: $($proxyInfo.PAC)" -ForegroundColor Yellow
    } catch {
        Write-Warning "Failed to initialize PAC proxy: $_"
        # Fallback to GetSystemWebProxy
        [System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
        Write-Host "Initialized system default proxy" -ForegroundColor Yellow
    }
}
elseif ($proxyInfo.Mode -eq 'WPAD') {
    # For WPAD, we need to use system defaults which auto-detect
    $webProxy = [System.Net.WebRequest]::GetSystemWebProxy()
    [System.Net.WebRequest]::DefaultWebProxy = $webProxy
    Write-Host "Initialized WPAD auto-detection" -ForegroundColor Yellow
}
elseif ($proxyInfo.Mode -eq 'WinINET' -and $proxyInfo.Proxy) {
    $webProxy = New-Object System.Net.WebProxy($proxyInfo.Proxy, $true)
    if ($proxyInfo.BypassList) {
        $webProxy.BypassList = $proxyInfo.BypassList -split ';'
    }
    [System.Net.WebRequest]::DefaultWebProxy = $webProxy
    Write-Host "Initialized WinINET proxy: $($proxyInfo.Proxy)" -ForegroundColor Yellow
}
elseif ($proxyInfo.Mode -eq 'Runtime' -and $proxyInfo.Proxy) {
    # Runtime detected proxy - use GetSystemWebProxy to respect PAC/WPAD evaluation
    $webProxy = [System.Net.WebRequest]::GetSystemWebProxy()
    [System.Net.WebRequest]::DefaultWebProxy = $webProxy
    Write-Host "Initialized runtime-detected proxy: $($proxyInfo.Proxy)" -ForegroundColor Yellow
}
elseif ($proxyInfo.Mode -eq 'Explicit' -and $proxyInfo.Proxy) {
    $webProxy = New-Object System.Net.WebProxy($proxyInfo.Proxy, $true)
    if ($proxyInfo.Credential) {
        $webProxy.Credentials = $proxyInfo.Credential
    }
    [System.Net.WebRequest]::DefaultWebProxy = $webProxy
    Write-Host "Initialized explicit proxy: $($proxyInfo.Proxy)" -ForegroundColor Yellow
}
else {
    # No proxy detected, but still initialize DefaultWebProxy to be safe
    [System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
}

$source = 'Builtin'
$domains = @()

if ($UrlListPath) {
    $domains = Import-OfficialList -Path $UrlListPath -Model $Model -Region $Region
    if ($domains.Count -gt 0) { $source = "Official-List ($UrlListPath)" }
    else { Write-Warning "No domains imported from '$UrlListPath'. Falling back to built-in minimal set." }
}
elseif ($TryDownload) {
    $dl = Try-DownloadStreamlinedCsv -ProxyMode $proxyInfo.Mode -ProxyUri $proxyInfo.Proxy -ProxyCred $proxyInfo.Credential
    if ($dl) {
        $domains = Import-OfficialList -Path $dl -Model 'Streamlined' -Region $Region
        if ($domains.Count -gt 0) { $source = "Official-List (downloaded: $dl)"; $Model = 'Streamlined' }
        else { Write-Warning "Downloaded file did not parse. Falling back to built-in minimal set." }
    }
}

if ($domains.Count -eq 0) {
    $domains = Get-BuiltinMinimalList -Model $Model -Region $Region
}

Write-Section "Test Targets"
"Source    : $source"
"Endpoints : $($domains.Count)"
$domains | Sort-Object { if ($_ -is [hashtable]) { $_.Domain } else { $_ } } | ForEach-Object { 
    if ($_ -is [hashtable]) {
        " - $($_.Domain) [$($_.Geo)]"
    } else {
        " - $_"
    }
}

Write-Section "Running Tests"
$results = @()
$idx = 0

# Resolve proxy IP once if explicit proxy configured
$globalProxyIp = if ($proxyInfo.Proxy -and $proxyInfo.Mode -eq 'Explicit') { 
    Get-ProxyIpAddress -ProxyUri $proxyInfo.Proxy 
} else { 
    $null 
}

foreach ($d in $domains) {
    $idx++
    
    # Handle both hashtable objects (from builtin list) and strings (from CSV import)
    $domain = if ($d -is [hashtable]) { $d.Domain } else { $d }
    $geography = if ($d -is [hashtable]) { $d.Geo } else { 'WW' }
    $modelTag = if ($d -is [hashtable]) { $d.Model } else { 'Unknown' }
    $serviceTag = if ($d -is [hashtable] -and $d.Service) { $d.Service } else { 'MDE' }
    $purposeTag = if ($d -is [hashtable] -and $d.Purpose) { $d.Purpose } else { '-' }
    
    $hostname = $domain -replace '^\*\.', 'www.'  # basic wildcard normalization for testing
    $testUrl = "https://{0}/" -f $hostname

    $dns = Resolve-Host -HostName $hostname
    $tcp = Test-Host443 -HostName $hostname

    # Always check for actual proxy used for THIS specific URL
    # Even if proxy mode shows "None", DefaultWebProxy might have PAC/WPAD configured
    $actualProxyIp = Get-ActualProxyForUrl -TargetUrl $testUrl -ProxyInfo $proxyInfo
    
    # If no dynamic proxy found, use explicit proxy if configured
    if (-not $actualProxyIp -and $globalProxyIp) {
        $actualProxyIp = $globalProxyIp
    }
    
    # Determine routing type
    $routingType = if ($actualProxyIp) { "PROXY" } else { "DIRECT" }
    
    # Get next hop (gateway) IP for routing
    $nextHop = if ($tcp.RemoteAddress) {
        Get-NextHopIp -DestinationIp $tcp.RemoteAddress
    } else {
        $null
    }

    $httpOk = $null; $httpCode = $null; $httpDesc = $null; $httpProxyUsed = $null
    if (-not $SkipHttp) {
        $hres = Invoke-Web -Uri $testUrl -TimeoutSec 5 `
            -ProxyMode $proxyInfo.Mode -ProxyUri $proxyInfo.Proxy -ProxyCred $proxyInfo.Credential
        $httpOk   = $hres.Ok
        $httpCode = $hres.Code
        $httpDesc = $hres.Desc
        $httpProxyUsed = $hres.ProxyUsed
        
        # If HTTP request revealed proxy usage, get the proxy IP
        if ($httpProxyUsed -and -not $actualProxyIp) {
            try {
                $proxyDns = Resolve-DnsName -Name $httpProxyUsed -Type A -ErrorAction Stop
                $actualProxyIp = ($proxyDns | Where-Object {$_.Type -eq 'A'} | Select-Object -First 1).IPAddress
                # Update routing type if HTTP used proxy but we thought it was direct
                if ($routingType -eq "DIRECT") {
                    $routingType = "PROXY"
                }
            } catch { }
        }
    }

    $results += [pscustomobject]@{
        Index        = $idx
        LocalHostname = $localInfo.Hostname
        LocalFQDN    = $localInfo.FQDN
        Domain       = $domain
        Geography    = $geography
        Model        = $modelTag
        Service      = $serviceTag
        Purpose      = $purposeTag
        Route        = $routingType
        PrivateLink  = $dns.HasPrivateLink
        PvtLinkType  = $dns.PrivateLinkMethod
        DnsOk        = $dns.DnsOk
        Addresses    = ($dns.Addresses -join ';')
        Tcp443Ok     = $tcp.TcpOk
        RemoteIp     = $tcp.RemoteAddress
        NextHop      = $nextHop
        ProxyIp      = $actualProxyIp
        HttpsOk      = $httpOk
        HttpStatus   = $httpCode
        HttpNote     = $httpDesc
    }
}

Write-Section "Results"
Write-Host "Local Computer: $($localInfo.Hostname) ($($localInfo.FQDN))" -ForegroundColor Yellow
Write-Host "Proxy IP: Shows actual proxy server IP when proxy routing detected, otherwise '-' for direct connection" -ForegroundColor Cyan
Write-Host "PvtLink: Shows 'Yes' if Azure Private Link/Private Endpoint detected (CNAME or Private IP), 'No' otherwise" -ForegroundColor Cyan
Write-Host ""

# Calculate maximum domain and purpose length for consistent column width
$maxDomainWidth = ($results | ForEach-Object { $_.Domain.Length } | Measure-Object -Maximum).Maximum
if ($maxDomainWidth -lt 6) { $maxDomainWidth = 6 }  # Minimum width for "Domain" header
$maxPurposeWidth = ($results | ForEach-Object { $_.Purpose.Length } | Measure-Object -Maximum).Maximum
if ($maxPurposeWidth -lt 7) { $maxPurposeWidth = 7 }  # Minimum width for "Purpose" header

# Display table header with improved spacing for better visibility
Write-Host ("  {0,3}  {1,-3}  {2,-3}  {3,-6}  {4,-6}  {5,-14}  {6,-$maxDomainWidth}  {7,-$maxPurposeWidth}  {8,-4}  {9,-8}  {10,-6}  {11,-6}  {12,-16}  {13,-13}  {14}" -f `
    "#", "Geo", "Svc", "Type", "Route", "PvtLink", "Domain", "Purpose", "DNS", "TCP:443", "HTTPS", "Status", "Target IP", "Next Hop", "Proxy IP") -ForegroundColor Cyan
Write-Host ("  {0,-3}  {1,-3}  {2,-3}  {3,-6}  {4,-6}  {5,-14}  {6,-$maxDomainWidth}  {7,-$maxPurposeWidth}  {8,-4}  {9,-8}  {10,-6}  {11,-6}  {12,-16}  {13,-13}  {14}" -f `
    "-", "---", "---", "------", "------", "--------------", ("-" * $maxDomainWidth), ("-" * $maxPurposeWidth), "---", "-------", "------", "------", "---------", "--------", "--------") -ForegroundColor Cyan

# Display results with color-coded symbols
foreach ($r in $results) {
    $dnsSymbol = if($r.DnsOk){"Ok"}else{"-"}
    $dnsColor = if($r.DnsOk){"Green"}else{"Red"}
    $tcpSymbol = if($r.Tcp443Ok){"Ok"}else{"-"}
    $tcpColor = if($r.Tcp443Ok){"Green"}else{"Red"}
    $httpsSymbol = if($r.HttpsOk){"Ok"}elseif($null -eq $r.HttpsOk){"-"}else{"-"}
    $httpsColor = if($r.HttpsOk){"Green"}elseif($null -eq $r.HttpsOk){"Gray"}else{"Red"}
    
    # Private Link detection with color coding
    $pvtLinkSymbol = if($r.PrivateLink){"Yes"}else{"No"}
    $pvtLinkColor = if($r.PrivateLink){"Magenta"}else{"Gray"}
    $pvtLinkDisplay = if($r.PrivateLink -and $r.PvtLinkType){"{0}({1})" -f $pvtLinkSymbol, $r.PvtLinkType}else{$pvtLinkSymbol}
    
    $type = if($r.Model -eq 'Both'){'Both'}elseif($r.Model -eq 'Streamlined'){'Stream'}else{'Stand'}
    $targetIp = if($r.RemoteIp){$r.RemoteIp}else{"-"}
    $nextHop = if($r.NextHop){$r.NextHop}else{"-"}
    $proxyIp = if($r.ProxyIp){$r.ProxyIp}else{"-"}
    $status = if($r.HttpStatus){$r.HttpStatus}else{"-"}
    
    # First part: Index, Geo, Service, Type, Route with improved spacing
    Write-Host ("{0,3}  {1,-3}  {2,-3}  {3,-6}  {4,-6}  " -f $r.Index, $r.Geography, $r.Service, $type, $r.Route) -NoNewline
    
    # Private Link column (14 chars width + 2 spaces) with color
    Write-Host ("{0,-14}  " -f $pvtLinkDisplay) -ForegroundColor $pvtLinkColor -NoNewline
    
    # Domain column
    Write-Host ("{0,-$maxDomainWidth}  " -f $r.Domain) -NoNewline
    
    # Purpose column
    Write-Host ("{0,-$maxPurposeWidth}  " -f $r.Purpose) -ForegroundColor Gray -NoNewline
    
    # DNS column (4 chars width + 2 spaces)
    Write-Host ("{0,-4}  " -f $dnsSymbol) -ForegroundColor $dnsColor -NoNewline
    
    # TCP:443 column (8 chars width + 2 spaces)
    Write-Host ("{0,-8}  " -f $tcpSymbol) -ForegroundColor $tcpColor -NoNewline
    
    # HTTPS column (6 chars width + 2 spaces)
    Write-Host ("{0,-6}  " -f $httpsSymbol) -ForegroundColor $httpsColor -NoNewline
    
    # Status, Target IP, Next Hop, Proxy IP with improved spacing
    Write-Host ("{0,-6}  {1,-16}  {2,-13}  {3}" -f $status, $targetIp, $nextHop, $proxyIp)
}

Write-Host ""

Write-Section "Summary"
$pass = $results | Where-Object { $_.DnsOk -and $_.Tcp443Ok -and ( $SkipHttp -or $_.HttpsOk ) }
$fail = $results | Where-Object { -not ($_.DnsOk -and $_.Tcp443Ok -and ( $SkipHttp -or $_.HttpsOk )) }
$privateLink = $results | Where-Object { $_.PrivateLink }

"Passed      : $($pass.Count)"
"Failed      : $($fail.Count)"
"PrivateLink : $($privateLink.Count)"
if ($privateLink.Count -gt 0) {
    Write-Host ""
    Write-Host "Endpoints using Private Link/Private Endpoint:" -ForegroundColor Magenta
    foreach ($pl in $privateLink) {
        $methodTag = if ($pl.PvtLinkType) { " [$($pl.PvtLinkType)]" } else { "" }
        Write-Host ("  - {0} ({1}){2}" -f $pl.Domain, $pl.Service, $methodTag) -ForegroundColor Magenta
    }
}

$stamp = (Get-Date -Format "yyyyMMdd_HHmmss")
$csv = "MDE_Connectivity_AU_$stamp.csv"
$json = "MDE_Connectivity_AU_$stamp.json"
$results | Export-Csv -NoTypeInformation -Path $csv
$results | ConvertTo-Json | Out-File -Encoding utf8 -FilePath $json

Write-Host ""
Write-Host "Saved: $csv" -ForegroundColor Green
Write-Host "Saved: $json" -ForegroundColor Green

# Exit code 0 if all passed; 1 otherwise
if ($fail.Count -gt 0) { exit 1 } else { exit 0 }
``
