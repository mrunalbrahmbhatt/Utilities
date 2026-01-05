# Azure Arc Status Check Script (with MDE & SQL Extension Checks)
# Compatible: Windows Server 2012 R2 to 2025
# Run as Administrator
#
# Usage: .\ValidateARC.ps1 -ExpectedOrgId "<MDE_ORG_ID>" [-Region "<REGION>"]
# Example: .\ValidateARC.ps1 -ExpectedOrgId "8769b673-6805-6789-8f77-12345f4d22b9"
# Example: .\ValidateARC.ps1 -ExpectedOrgId "8769b673-6805-6789-8f77-12345f4d22b9" -Region "US"

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
    .\ValidateARC.ps1 -ExpectedOrgId "8769b673-6805-6789-8f77-12345f4d22b9"
    
.EXAMPLE
    .\ValidateARC.ps1 -ExpectedOrgId "8769b673-6805-6789-8f77-12345f4d22b9" -Region "US"

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
        HelpMessage="Enter the expected MDE Organization ID GUID (example: '8769b673-6805-6789-8f77-12345f4d22b9')"
    )]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedOrgId,
    
    [Parameter(
        Mandatory=$false,
        HelpMessage="Select your Azure region for MDE connectivity checks"
    )]
    [ValidateSet("Australia", "US", "Europe", "UK", "Canada", "Asia")]
    [string]$Region = "Australia"
)

# Ensure Region has a valid value (defense against empty strings)
if ([string]::IsNullOrWhiteSpace($Region)) {
    $Region = "Australia"
    Write-Host "Region parameter was empty, defaulting to: Australia" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "=== Azure Arc-Enabled Server Status Check ===" -ForegroundColor Cyan
Write-Host "Server: $($env:COMPUTERNAME)" -ForegroundColor Yellow
Write-Host "Current Date: $(Get-Date)" -ForegroundColor Yellow
Write-Host "Region: $Region" -ForegroundColor Yellow
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
}

$azcmagentPath = "C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe"
$certsPath = "$env:ProgramData\AzureConnectedMachineAgent\Certs"

# Section 1: Collect Azure Arc Agent Info
if (Test-Path $azcmagentPath) {
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
} else {
    $status.ArcAgent.Installed = $false
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
                $onboardingState = "Onboarded"
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
                if ($statusContent.status.formattedMessage -and $statusContent.status.formattedMessage.message) {
                    $mdeExtInfo.ErrorMessage = $statusContent.status.formattedMessage.message
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
            $testResult = Test-NetConnection -ComputerName $endpoint.URL -Port $endpoint.Port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -InformationLevel Quiet
            $status.ConnectivityChecks += @{
                URL = "https://$($endpoint.URL):$($endpoint.Port)"
                Status = if ($testResult) { "Passed" } else { "Failed" }
                Category = $endpoint.Category
                Description = $endpoint.Description
                Mandatory = $endpoint.Mandatory
            }
        } catch {
            $status.ConnectivityChecks += @{
                URL = "https://$($endpoint.URL):$($endpoint.Port)"
                Status = "Failed"
                Category = $endpoint.Category
                Description = $endpoint.Description
                Mandatory = $endpoint.Mandatory
            }
        }
    }

# ========== REPORT ALL STATUS ==========
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "         STATUS REPORT SUMMARY          " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Report 0: Operating System Information
Write-Host "OPERATING SYSTEM INFORMATION" -ForegroundColor Green
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

# Report 1: Azure Arc Agent
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

# Report 2: Certificates
Write-Host "2. MANAGED IDENTITY CERTIFICATES" -ForegroundColor Green
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

# Report 3: MDE Onboarding
Write-Host "3. MICROSOFT DEFENDER FOR ENDPOINT - ONBOARDING" -ForegroundColor Green
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
Write-Host "     Onboarding State: $($status.MDE.OnboardingState)" -ForegroundColor $(if ($status.MDE.OnboardingState -match "Onboarded") {"Green"} else {"Yellow"})
if ($status.MDE.OrgId -and $status.MDE.OrgId -ne "Not Available" -and $status.MDE.OrgId -ne "Error") {
    Write-Host "     Organization ID:  $($status.MDE.OrgId)" -ForegroundColor Cyan
    if ($status.MDE.OrgId -ne $ExpectedOrgId) {
        Write-Host "                       WARNING: Does not match expected ID!" -ForegroundColor Red
        Write-Host "                       Expected: $ExpectedOrgId" -ForegroundColor Yellow
    }
} else {
    Write-Host "     Organization ID:  $($status.MDE.OrgId)" -ForegroundColor Yellow
}
if ($status.MDE.LastConnected) {
    Write-Host "     Last Connected:   $($status.MDE.LastConnected)" -ForegroundColor Cyan
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
Write-Host "3.1 MDE COMPREHENSIVE HEALTH CHECK" -ForegroundColor Green
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

# Check 3: Onboarded
if ($status.MDE.OnboardingState -match "Onboarded") {
    $mdeHealthChecks.Onboarded = $true
} else {
    $mdeIssues += "MDE not onboarded"
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

# Check 7: Cloud Protection (MAPS)
if ($status.MDE.MAPSReporting -match "Basic|Advanced") {
    $mdeHealthChecks.CloudProtectionOn = $true
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

# Check 10: Telemetry
if ($status.MDE.MAPSReporting -ne "Disabled" -and $status.MDE.MAPSReporting -ne "Unknown") {
    $mdeHealthChecks.TelemetryEnabled = $true
}

# Check 11: Gateway Connectivity (from existing checks)
$mdeGatewayPassed = $status.ConnectivityChecks | Where-Object { 
    $_.Category -eq "MDE" -and 
    $_.URL -like "*winatp-gw-*" -and 
    $_.Status -eq "Passed" 
}
if ($mdeGatewayPassed) {
    $mdeHealthChecks.GatewayReachable = $true
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
Write-Host "     [$(if ($mdeHealthChecks.Onboarded) {'✓'} else {'✗'})] MDE Onboarded (Registry)" -ForegroundColor $(if ($mdeHealthChecks.Onboarded) {"Green"} else {"Red"})
Write-Host "     [$(if ($mdeHealthChecks.CloudConnected) {'✓'} else {'✗'})] Cloud Connection Established" -ForegroundColor $(if ($mdeHealthChecks.CloudConnected) {"Green"} else {"Red"})
Write-Host "     [$(if ($mdeHealthChecks.SignaturesFresh) {'✓'} else {'✗'})] Signatures Up-to-Date (<7 days)" -ForegroundColor $(if ($mdeHealthChecks.SignaturesFresh) {"Green"} else {"Red"})
Write-Host "     [$(if ($mdeHealthChecks.RealTimeProtectionOn) {'✓'} else {'✗'})] Real-Time Protection Enabled" -ForegroundColor $(if ($mdeHealthChecks.RealTimeProtectionOn) {"Green"} else {"Red"})
Write-Host "     [$(if ($mdeHealthChecks.CloudProtectionOn) {'✓'} else {'✗'})] Cloud-Delivered Protection (MAPS)" -ForegroundColor $(if ($mdeHealthChecks.CloudProtectionOn) {"Green"} else {"Red"})
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
    
    # Action 7: Cloud protection disabled
    if (-not $mdeHealthChecks.CloudProtectionOn) {
        Write-Host ""
        Write-Host "   [7] Fix: Cloud-Delivered Protection Disabled" -ForegroundColor Yellow
        Write-Host "       Enable MAPS Reporting:" -ForegroundColor White
        Write-Host "       Set-MpPreference -MAPSReporting Advanced" -ForegroundColor White
        Write-Host "       Verify: Get-MpComputerStatus | Select-Object MAPSReporting" -ForegroundColor Gray
        Write-Host "       Note: Requires network connectivity to Microsoft cloud" -ForegroundColor Yellow
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

# Report 4: Windows Setup Status
Write-Host "4. WINDOWS SETUP STATUS" -ForegroundColor Green
Write-Host "   ----------------------------------------"
Write-Host "   Setup Status:     $($status.WindowsSetup.Status)" -ForegroundColor $(if ($status.WindowsSetup.Status -eq "Completed") {"Green"} elseif ($status.WindowsSetup.Status -match "In Progress") {"Yellow"} else {"Red"})
if ($status.WindowsSetup.ImageState -and $status.WindowsSetup.ImageState -ne "Not Found" -and $status.WindowsSetup.ImageState -ne "Path Not Found") {
    Write-Host "   ImageState Value: '$($status.WindowsSetup.ImageState)'" -ForegroundColor Cyan
} else {
    Write-Host "   ImageState:       $($status.WindowsSetup.ImageState)" -ForegroundColor Yellow
}
Write-Host "   Registry Path:    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" -ForegroundColor DarkGray
Write-Host ""

# Report 4.1: Extension Service Status
Write-Host "4.1 AZURE ARC EXTENSION SERVICE" -ForegroundColor Green
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

# Report 5: Extensions
Write-Host "5. AZURE ARC EXTENSIONS" -ForegroundColor Green
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
                if ($ext.HandlerState -and $ext.HandlerState -ne "Unknown") {
                    Write-Host "     Handler State: $($ext.HandlerState)" -ForegroundColor $(if ($ext.HandlerState -eq "Enabled") {"Green"} else {"Yellow"})
                }
                if ($ext.ErrorCode) {
                    Write-Host "     Error Code: $($ext.ErrorCode)" -ForegroundColor Red
                }
                if ($ext.ErrorMessage) {
                    Write-Host "     Error: $($ext.ErrorMessage)" -ForegroundColor Red
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

# Report 6: Connectivity
Write-Host "6. CONNECTIVITY CHECK" -ForegroundColor Green
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
    if ($arcChecks.Count -gt 0) {
        $arcPassed = ($arcChecks | Where-Object { $_.Status -eq "Passed" }).Count
        $arcFailed = ($arcChecks | Where-Object { $_.Status -eq "Failed" }).Count
        Write-Host "   Azure Arc Endpoints: $arcPassed Passed, $arcFailed Failed" -ForegroundColor Cyan
        foreach ($check in $arcChecks) {
            $statusColor = if ($check.Status -eq "Passed") { "Green" } else { "Red" }
            $statusIcon = if ($check.Status -eq "Passed") { "✓" } else { "✗" }
            Write-Host "   [$statusIcon] $($check.Status.PadRight(6)) - $($check.URL)" -ForegroundColor $statusColor
        }
        Write-Host ""
    } else {
        # If no Arc checks were parsed, show raw output
        Write-Host "   Azure Arc Endpoints:" -ForegroundColor Cyan
        Write-Host "   (Unable to parse azcmagent check output - showing raw results)" -ForegroundColor Yellow
        if ($status.Connectivity) {
            $status.Connectivity -split "`n" | ForEach-Object {
                if ($_ -match "✓|Passed|reachable|succeeded") {
                    Write-Host "   $_" -ForegroundColor Green
                } elseif ($_ -match "✗|Failed|unreachable|error") {
                    Write-Host "   $_" -ForegroundColor Red
                } elseif ($_ -match "https?://") {
                    Write-Host "   $_" -ForegroundColor Gray
                }
            }
        }
        Write-Host ""
    }
    
    # Display MDE.Windows Extension endpoints (for Arc extension installation)
    if ($mdeWindowsChecks.Count -gt 0) {
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
        $mdeMandatoryFailed = ($mdeChecks | Where-Object { $_.Status -eq "Failed" -and $_.Mandatory -eq $true }).Count
        $mdeOptionalFailed = ($mdeChecks | Where-Object { $_.Status -eq "Failed" -and $_.Mandatory -eq $false }).Count
        Write-Host "   MDE Agent Runtime Endpoints (Manual & Arc-managed): $mdePassed Passed, $mdeFailed Failed" -ForegroundColor Cyan
        if ($mdeMandatoryFailed -gt 0 -or $mdeOptionalFailed -gt 0) {
            Write-Host "   Failed Endpoints: $mdeMandatoryFailed Mandatory, $mdeOptionalFailed Optional" -ForegroundColor $(if ($mdeMandatoryFailed -gt 0) { "Red" } else { "Yellow" })
        }
        Write-Host "   Note: Required for MDE agent operation (both onboarding methods)" -ForegroundColor DarkGray
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

# Summary and Recommendations
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "      ISSUES `& RECOMMENDATIONS          " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$issuesFound = $false

if (-not $status.ArcAgent.Installed) {
    Write-Host "[CRITICAL] Azure Arc Agent is not installed" -ForegroundColor Red
    Write-Host "           Action: Install the Azure Arc agent" -ForegroundColor Yellow
    $issuesFound = $true
}

# Check for certificate thumbprint mismatch
if ($status.ArcAgent.ErrorDetails -and $status.ArcAgent.ErrorDetails -match "thumbprint.*does not match") {
    Write-Host "[CRITICAL] Certificate thumbprint mismatch detected" -ForegroundColor Red
    Write-Host "           Issue: The certificate thumbprint in the certificate file does not match the expected thumbprint" -ForegroundColor Red
    Write-Host "           Root Cause: Certificate files may be corrupted or out of sync" -ForegroundColor Yellow
    Write-Host "           Action: Run the following commands to fix:" -ForegroundColor Yellow
    Write-Host "                   1. azcmagent disconnect --force-local-only" -ForegroundColor Cyan
    Write-Host "                   2. azcmagent connect --resource-group <RG> --tenant-id <TENANT> --location <LOCATION> --subscription-id <SUB>" -ForegroundColor Cyan
    Write-Host "           Alternative: Delete certificate files from %ProgramData%\AzureConnectedMachineAgent\Certs and reconnect" -ForegroundColor Yellow
    $issuesFound = $true
} elseif ($status.ArcAgent.Status -match "Disconnected" -and $status.ArcAgent.Installed) {
    Write-Host "[CRITICAL] Azure Arc Agent is disconnected" -ForegroundColor Red
    if ($status.ArcAgent.ErrorCode) {
        Write-Host "           Error: $($status.ArcAgent.ErrorCode)" -ForegroundColor Red
    }
    Write-Host "           Action: Disconnect and reconnect the agent" -ForegroundColor Yellow
    Write-Host "                   azcmagent disconnect" -ForegroundColor Cyan
    Write-Host "                   azcmagent connect --resource-group <RG> --tenant-id <TENANT> --location <LOCATION> --subscription-id <SUB>" -ForegroundColor Cyan
    $issuesFound = $true
} elseif ($status.ArcAgent.Status -notmatch "Connected" -and $status.ArcAgent.Installed) {
    Write-Host "[CRITICAL] Azure Arc Agent is not connected" -ForegroundColor Red
    Write-Host "           Action: Check agent logs and network connectivity" -ForegroundColor Yellow
    $issuesFound = $true
}

# Check for stale heartbeat
if ($status.ArcAgent.HoursSinceHeartbeat -and $status.ArcAgent.HoursSinceHeartbeat -gt 24) {
    Write-Host "[CRITICAL] Agent heartbeat is stale (last: $($status.ArcAgent.HoursSinceHeartbeat) hours ago)" -ForegroundColor Red
    Write-Host "           Issue: Agent has not communicated with Azure in over 24 hours" -ForegroundColor Red
    Write-Host "           Action: Check network connectivity to Azure endpoints" -ForegroundColor Yellow
    Write-Host "                   Run: azcmagent check" -ForegroundColor Cyan
    Write-Host "                   Verify proxy settings and firewall rules" -ForegroundColor Yellow
    $issuesFound = $true
} elseif ($status.ArcAgent.HoursSinceHeartbeat -and $status.ArcAgent.HoursSinceHeartbeat -gt 2) {
    Write-Host "[WARNING] Agent heartbeat is delayed (last: $($status.ArcAgent.HoursSinceHeartbeat) hours ago)" -ForegroundColor Yellow
    Write-Host "          Action: Monitor connectivity and check for intermittent network issues" -ForegroundColor Yellow
    $issuesFound = $true
}

# Check dependent services
if ($status.ArcAgent.DependentServices.himds -and $status.ArcAgent.DependentServices.himds -ne "running") {
    Write-Host "[CRITICAL] HIMDS Service is not running (Status: $($status.ArcAgent.DependentServices.himds))" -ForegroundColor Red
    Write-Host "           Action: Restart the service with: Restart-Service himds" -ForegroundColor Yellow
    $issuesFound = $true
}

if ($status.ArcAgent.DependentServices.extensionservice -and $status.ArcAgent.DependentServices.extensionservice -ne "running") {
    Write-Host "[CRITICAL] Extension Service is not running (Status: $($status.ArcAgent.DependentServices.extensionservice))" -ForegroundColor Red
    Write-Host "           Action: Restart the service with: Restart-Service extensionservice" -ForegroundColor Yellow
    Write-Host "           Note: Extensions will not function until this service is running" -ForegroundColor Yellow
    $issuesFound = $true
}

# Check connectivity failures
if ($status.ConnectivityChecks) {
    # Check Azure Arc connectivity failures
    $failedArcConnectivity = $status.ConnectivityChecks | Where-Object { $_.Status -eq "Failed" -and $_.Category -eq "Azure Arc" }
    if ($failedArcConnectivity.Count -gt 0) {
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
    $failedMDEMandatory = $status.ConnectivityChecks | Where-Object { $_.Status -eq "Failed" -and ($_.Category -eq "MDE" -or $_.Category -eq "MDE.Windows") -and $_.Mandatory -eq $true }
    $failedMDEOptional = $status.ConnectivityChecks | Where-Object { $_.Status -eq "Failed" -and ($_.Category -eq "MDE" -or $_.Category -eq "MDE.Windows") -and $_.Mandatory -eq $false }
    
    if ($failedMDEMandatory.Count -gt 0) {
        Write-Host "[CRITICAL] $($failedMDEMandatory.Count) MANDATORY MDE connectivity check(s) failed" -ForegroundColor Red
        Write-Host "           Failed MANDATORY MDE endpoints:" -ForegroundColor Red
        foreach ($failed in $failedMDEMandatory) {
            $desc = if ($failed.Description) { " - $($failed.Description)" } else { "" }
            Write-Host "           - $($failed.URL)$desc" -ForegroundColor Red
        }
        Write-Host "           Issue: Unable to reach critical MDE endpoints - MDE functionality degraded" -ForegroundColor Red
        Write-Host "           Impact: Extension installation/updates may fail, EDR protection degraded" -ForegroundColor Red
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
        Write-Host "           Registry OnboardingState: 1 (Onboarded) \u2713" -ForegroundColor Green
        Write-Host "           Registry LastConnected: NOT PRESENT \u2717" -ForegroundColor Red
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
        Write-Host "           THE DIFFERENCE BETWEEN THIS SERVER AND WORKING SERVERS:" -ForegroundColor Cyan
        Write-Host "           Working servers: Had connectivity when first onboarded → connected → got LastConnected value" -ForegroundColor Gray
        Write-Host "           This server: Firewall blocked BEFORE first connection → never connected → no LastConnected" -ForegroundColor Gray
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
        Write-Host "           Step 4: VERIFY LastConnected VALUE APPEARS" -ForegroundColor Yellow
        Write-Host "           ------------------------------------------" -ForegroundColor Yellow
        Write-Host "           Run this PowerShell command to verify cloud connection:" -ForegroundColor Gray
        Write-Host ""
        Write-Host "           Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\Status' | Select-Object LastConnected" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "           SUCCESS: Returns a numeric timestamp value (e.g., 134118086265734088)" -ForegroundColor Green
        Write-Host "           FAILURE: Returns nothing, blank, or error" -ForegroundColor Red
        Write-Host ""
        Write-Host "           If FAILURE after 10 minutes:" -ForegroundColor Yellow
        Write-Host "           - Re-check firewall rules are applied correctly" -ForegroundColor Gray
        Write-Host "           - Check DNS resolution: Resolve-DnsName winatp-gw-aue.microsoft.com" -ForegroundColor Gray
        Write-Host "           - Test connectivity: Test-NetConnection -ComputerName winatp-gw-aue.microsoft.com -Port 443" -ForegroundColor Gray
        Write-Host "           - Check MDE service logs:" -ForegroundColor Gray
        Write-Host "             Event Viewer → Applications and Services Logs → Microsoft → Windows → SENSE → Operational" -ForegroundColor DarkGray
        Write-Host "             Or run: Get-WinEvent -LogName 'Microsoft-Windows-SENSE/Operational' -MaxEvents 20" -ForegroundColor Cyan
        Write-Host ""
        Write-Host ""
        Write-Host "           Step 5: VERIFY IN AZURE PORTAL" -ForegroundColor Yellow
        Write-Host "           ------------------------------" -ForegroundColor Yellow
        Write-Host "           After LastConnected value appears, wait additional 10-15 minutes then:" -ForegroundColor Gray
        Write-Host "           - Open Azure Portal → Defender for Cloud → Servers" -ForegroundColor Gray
        Write-Host "           - Locate this server: $($env:COMPUTERNAME)" -ForegroundColor Cyan
        Write-Host "           - Refresh the page (Ctrl+F5)" -ForegroundColor Gray
        Write-Host "           - Verify status shows: 'Defender for Server: Onboarded' \u2713" -ForegroundColor Green
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
        Write-Host "          Registry OnboardingState: 1 (Onboarded) \u2713" -ForegroundColor Green
        Write-Host "          Registry LastConnected: $($status.MDE.LastConnected) \u2713" -ForegroundColor Green
        Write-Host "          Portal Status: 'Defender for Server: Onboarded' \u2713" -ForegroundColor Green
        Write-Host ""
        
        # Show version status as evidence of cloud connectivity
        if ($status.MDE.VersionStatus -and $status.MDE.VersionStatus -ne "Unable to analyze") {
            if ($status.MDE.VersionStatus -eq "Current") {
                Write-Host "          Agent Version: $($status.MDE.PlatformVersion)" -ForegroundColor Green
                Write-Host "          Version Status: $($status.MDE.VersionStatus) \u2713" -ForegroundColor Green
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
if ($portalShowsOnboarded) {
    $mdeExtInstalled = $status.Extensions | Where-Object { $_.Name -match "MDE.Windows" -and $_.Installed -eq $true }
    if (-not $mdeExtInstalled) {
        Write-Host "[INFO] MDE Onboarding Method: Manual/Classic (not Arc-managed)" -ForegroundColor Cyan
        Write-Host "       Device is fully onboarded but Arc extension is not installed" -ForegroundColor Cyan
        Write-Host "       Portal 'Defender for Server': 'Onboarded' ✓" -ForegroundColor Green
        Write-Host "       Portal 'Defender for Endpoint': 'Can be onboarded' (Arc extension missing)" -ForegroundColor Yellow
        Write-Host "       Explanation: Device was onboarded manually, not via Arc extension" -ForegroundColor Cyan
        Write-Host "                    To use Arc-managed method, install MDE.Windows extension" -ForegroundColor Cyan
        Write-Host ""
    }
}

# Check for MDE extension specific issues
$mdeExt = $status.Extensions | Where-Object { $_.Name -match "MDE.Windows" }
if ($mdeExt) {
    $hasMDEIssue = $false
    
    # Check multiple indicators of failure
    if ($mdeExt.DetailedStatus -match "(?i)error|failed|transitioning") { $hasMDEIssue = $true }
    if ($mdeExt.InstallationFailed) { $hasMDEIssue = $true }
    if ($mdeExt.ConnectivityIssue) { $hasMDEIssue = $true }
    if ($mdeExt.ErrorMessage -and $mdeExt.ErrorMessage -ne "") { $hasMDEIssue = $true }
    if ($mdeExt.ErrorCode -and $mdeExt.ErrorCode -ne "" -and $mdeExt.ErrorCode -ne 0) { $hasMDEIssue = $true }
    
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
if ($mdeExtCheck -and -not $mdeExtCheck.Installed) {
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
if ($status.ExtensionService.Status -ne "Running") {
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
if ($noStatusExtensions.Count -gt 0 -and $status.ExtensionService.Status -eq "Running") {
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
Write-Host "             LOG LOCATIONS              " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Arc Agent:   C:\ProgramData\AzureConnectedMachineAgent\Log\"
Write-Host "   MDE:         Event Viewer > Applications and Services Logs > Microsoft > Windows > SENSE"
Write-Host "   Extensions:  C:\ProgramData\GuestConfig\extension_logs\"
Write-Host "   Arc Plugins: C:\Packages\Plugins\Microsoft.Azure.*\"
Write-Host ""
Write-Host "=== Check Complete ===" -ForegroundColor Cyan
