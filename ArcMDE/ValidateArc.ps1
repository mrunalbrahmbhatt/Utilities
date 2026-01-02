# Azure Arc Status Check Script (with MDE & SQL Extension Checks)
# Compatible: Windows Server 2012 R2 to 2025
# Run as Administrator
#
# Usage: .\ValidateArcps1 -ExpectedOrgId "<MDE_ORG_ID>"
# Example: .\ValidateArcps1 -ExpectedOrgId "8769b673-6805-6789-8f77-12345f4d22b9"

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

.EXAMPLE
    .\ValidateArcps1 -ExpectedOrgId "8769b673-6805-6789-8f77-12345f4d22b9"

#>

param(
    [Parameter(
        Mandatory=$true,
        HelpMessage="Enter the expected MDE Organization ID GUID (example: '8769b673-6805-6789-8f77-12345f4d22b9')"
    )]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedOrgId
)

Write-Host "=== Azure Arc-Enabled Server Status Check ===" -ForegroundColor Cyan
Write-Host "Server: $($env:COMPUTERNAME)" -ForegroundColor Yellow
Write-Host "Current Date: $(Get-Date)" -ForegroundColor Yellow
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
    $himdsService = Get-Service -Name "himds" -ErrorAction SilentlyContinue
    if ($himdsService) {
        $status.ArcAgent.HimdsService = $himdsService.Status
    } else {
        $status.ArcAgent.HimdsService = "Not Found"
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
$senseService = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
if ($senseService) {
    $status.MDE.SenseService = $senseService.Status
} else {
    $status.MDE.SenseService = "Not Found"
}

$msSenseProcess = Get-Process -Name "MsSense" -ErrorAction SilentlyContinue
$status.MDE.MsSenseProcess = if ($msSenseProcess) { "Running" } else { "Not Running" }

# Check MDE Onboarding Status
$onboardingState = "Not Onboarded"
try {
    # Try Windows Defender status first
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus -and $mpStatus.AMServiceEnabled) {
        $onboardingState = if ($mpStatus.OnboardingState) { $mpStatus.OnboardingState } else { "Onboarded" }
    }
} catch { }

# Check MDE registry key for Arc servers
try {
    $mdeRegPath = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
    if (Test-Path $mdeRegPath) {
        $onboardingInfo = Get-ItemProperty -Path $mdeRegPath -ErrorAction SilentlyContinue
        if ($onboardingInfo.OnboardingState -eq 1) {
            $onboardingState = "Onboarded"
        }
        # Get OrgId if available
        if ($onboardingInfo.OrgId) {
            $status.MDE.OrgId = $onboardingInfo.OrgId
        } else {
            $status.MDE.OrgId = "Not Available"
        }
    } else {
        $status.MDE.OrgId = "Not Available"
    }
} catch { 
    $status.MDE.OrgId = "Error"
}

$status.MDE.OnboardingState = $onboardingState

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

# Check KB4052623 Installation (SHA-2 Code Signing Support)
$status.KB4052623 = @{}
try {
    $kb = Get-HotFix -Id "KB4052623" -ErrorAction SilentlyContinue
    if ($kb) {
        $status.KB4052623.Installed = $true
        $status.KB4052623.InstalledOn = $kb.InstalledOn
        $status.KB4052623.Description = $kb.Description
    } else {
        $status.KB4052623.Installed = $false
    }
} catch {
    $status.KB4052623.Installed = $false
    $status.KB4052623.Error = $_.Exception.Message
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
            }
            
            $statusFile = Get-ChildItem -Path $extFolder.FullName -Filter "*status*.json" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            
            if ($statusFile) {
                try {
                    $extStatus = Get-Content $statusFile.FullName -Raw | ConvertFrom-Json
                    $extInfo.Status = $extStatus.status.status -or $extStatus.status.state -or "Unknown"
                    
                    if ($extStatus.status.formattedMessage) {
                        $extInfo.Message = $extStatus.status.formattedMessage.message
                    }
                } catch {
                    $extInfo.Status = "Error reading status"
                }
            } else {
                $extInfo.Status = "No status file"
            }
            
            $status.Extensions += $extInfo
        }
    }
}

# Check specific extensions
$mdeExtPath = "$env:ProgramData\GuestConfig\extension_logs\Microsoft.Azure.AzureDefenderForServers"
$mdeExtInfo = @{
    Name = "MDE.Windows (AzureDefenderForServers)"
    Installed = Test-Path $mdeExtPath
    HandlerState = "Unknown"
    DetailedStatus = "Unknown"
    ErrorMessage = ""
    ErrorCode = ""
}

if ($mdeExtInfo.Installed) {
    # Check handler state
    $handlerState = Get-ChildItem -Path "$env:SystemDrive\Packages\Plugins\Microsoft.Azure.AzureDefenderForServers*" -Recurse -Filter "HandlerState.json" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($handlerState) {
        try {
            $state = Get-Content $handlerState.FullName -Raw | ConvertFrom-Json
            $mdeExtInfo.HandlerState = $state.state
        } catch { }
    }
    
    # Get detailed status from status file
    $statusFile = Get-ChildItem -Path "$env:SystemDrive\Packages\Plugins\Microsoft.Azure.AzureDefenderForServers*" -Recurse -Filter "*.status" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
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
    $executionLog = Get-ChildItem -Path "$env:SystemDrive\Packages\Plugins\Microsoft.Azure.AzureDefenderForServers*" -Recurse -Filter "*execution*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
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
    $sqlService = Get-Service -Name "SQLServerExtension" -ErrorAction SilentlyContinue
    if ($sqlService) {
        $sqlExtInfo.ServiceStatus = $sqlService.Status
    }
}
$status.Extensions += $sqlExtInfo

$amaExtPath = "$env:ProgramData\GuestConfig\extension_logs\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent"
$status.Extensions += @{
    Name = "AzureMonitorAgent"
    Installed = Test-Path $amaExtPath
}

# Section 4: Collect Connectivity Info
if (Test-Path $azcmagentPath) {
    $connectivityOutput = & $azcmagentPath check 2>&1
    $status.Connectivity = $connectivityOutput | Out-String
    
    # Parse individual endpoint checks
    $status.ConnectivityChecks = @()
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
    
    # Add MDE-specific endpoint checks
    $mdeEndpoints = @(
        @{ URL = "go.microsoft.com"; Port = 443; Description = "MDE Installer Download" }
        # @{ URL = "automatedirstrprdcus.blob.core.windows.net"; Port = 443; Description = "MDE Package Storage (US)" }
        @{ URL = "automatedirstrprdaue.blob.core.windows.net"; Port = 443; Description = "MDE Package Storage (AU East)" }
        @{ URL = "automatedirstrprdaus.blob.core.windows.net"; Port = 443; Description = "MDE Package Storage (AU Southeast)" }
        @{ URL = "ctldl.windowsupdate.com"; Port = 443; Description = "Certificate Trust List" }
        @{ URL = "win.vortex.data.microsoft.com"; Port = 443; Description = "Windows Telemetry" }
        @{ URL = "settings-win.data.microsoft.com"; Port = 443; Description = "Windows Settings" }
        @{ URL = "x.cp.wd.microsoft.com"; Port = 443; Description = "MDE Content Delivery" }
        @{ URL = "fe3.delivery.mp.microsoft.com"; Port = 443; Description = "Windows Update Delivery" }
        @{ URL = "winatp-gw-aus.microsoft.com"; Port = 443; Description = "MDE Australia Southeast Gateway" }
        @{ URL = "winatp-gw-aue.microsoft.com"; Port = 443; Description = "MDE Australia East Gateway" }
        @{ URL = "winatp-gw-auc.microsoft.com"; Port = 443; Description = "MDE Australia Central Gateway" }
        @{ URL = "edr-aue.au.endpoint.security.microsoft.com"; Port = 443; Description = "MDE EDR Australia East Endpoint" }
        # @{ URL = "winatp-gw-eus.microsoft.com"; Port = 443; Description = "MDE East US Gateway" }
        # @{ URL = "winatp-gw-weu.microsoft.com"; Port = 443; Description = "MDE West Europe Gateway" }
        @{ URL = "events.data.microsoft.com"; Port = 443; Description = "MDE Telemetry" }
        @{ URL = "crl.microsoft.com"; Port = 80; Description = "Certificate Revocation List" }
    )
    
    foreach ($endpoint in $mdeEndpoints) {
        try {
            $testResult = Test-NetConnection -ComputerName $endpoint.URL -Port $endpoint.Port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -InformationLevel Quiet
            $status.ConnectivityChecks += @{
                URL = "https://$($endpoint.URL):$($endpoint.Port)"
                Status = if ($testResult) { "Passed" } else { "Failed" }
                Category = "MDE"
                Description = $endpoint.Description
            }
        } catch {
            $status.ConnectivityChecks += @{
                URL = "https://$($endpoint.URL):$($endpoint.Port)"
                Status = "Failed"
                Category = "MDE"
                Description = $endpoint.Description
            }
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
Write-Host "   Sense Service:    $($status.MDE.SenseService)" -ForegroundColor $(if ($status.MDE.SenseService -eq "Running") {"Green"} else {"Red"})
Write-Host "   MsSense Process:  $($status.MDE.MsSenseProcess)" -ForegroundColor $(if ($status.MDE.MsSenseProcess -eq "Running") {"Green"} else {"Red"})
Write-Host "   Onboarding State: $($status.MDE.OnboardingState)" -ForegroundColor $(if ($status.MDE.OnboardingState -match "Onboarded") {"Green"} else {"Yellow"})
if ($status.MDE.OrgId -and $status.MDE.OrgId -ne "Not Available") {
    Write-Host "   Organization ID:  $($status.MDE.OrgId)" -ForegroundColor Cyan
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

# Report 4.1: KB4052623 Status
Write-Host "4.1 KB4052623 (SHA-2 CODE SIGNING SUPPORT)" -ForegroundColor Green
Write-Host "   ----------------------------------------"
if ($status.KB4052623.Installed) {
    Write-Host "   KB4052623 Status: INSTALLED" -ForegroundColor Green
    if ($status.KB4052623.InstalledOn) {
        Write-Host "   Installed On:     $($status.KB4052623.InstalledOn)" -ForegroundColor Cyan
    }
    if ($status.KB4052623.Description) {
        Write-Host "   Description:      $($status.KB4052623.Description)" -ForegroundColor Gray
    }
} else {
    Write-Host "   KB4052623 Status: NOT INSTALLED" -ForegroundColor Red
    if ($status.KB4052623.Error) {
        Write-Host "   Error:            $($status.KB4052623.Error)" -ForegroundColor Yellow
    }
}
Write-Host ""

# Report 5: Extensions
Write-Host "5. AZURE ARC EXTENSIONS" -ForegroundColor Green
Write-Host "   ----------------------------------------"
if ($status.Extensions.Count -gt 0) {
    foreach ($ext in $status.Extensions) {
        $displayName = $ext.Name
        if ($ext.Installed -ne $null) {
            # Specific extension check
            if ($ext.Installed) {
                $extColor = "Green"
                if ($ext.DetailedStatus -match "error|failed") { $extColor = "Red" }
                elseif ($ext.DetailedStatus -match "transitioning|warning") { $extColor = "Yellow" }
                
                Write-Host "   [$displayName]" -ForegroundColor $extColor
                
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
                Write-Host "   [$displayName] Not Installed" -ForegroundColor Gray
            }
        } else {
            # General extension from logs
            $statusColor = "Yellow"
            if ($ext.Status -match "success|ready|enabled") { $statusColor = "Green" }
            elseif ($ext.Status -match "error|failed") { $statusColor = "Red" }
            
            Write-Host "   [$displayName]" -ForegroundColor $statusColor
            Write-Host "     Status: $($ext.Status)" -ForegroundColor $statusColor
            if ($ext.Message) {
                Write-Host "     Message: $($ext.Message)" -ForegroundColor Gray
            }
        }
    }
} else {
    Write-Host "   No extensions found" -ForegroundColor Yellow
}
Write-Host ""

# Report 6: Connectivity
Write-Host "6. CONNECTIVITY CHECK" -ForegroundColor Green
Write-Host "   ----------------------------------------"
if ($status.ConnectivityChecks -and $status.ConnectivityChecks.Count -gt 0) {
    # Separate Arc and MDE checks
    $arcChecks = $status.ConnectivityChecks | Where-Object { $_.Category -eq "Azure Arc" }
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
    
    # Display MDE endpoints
    if ($mdeChecks.Count -gt 0) {
        $mdePassed = ($mdeChecks | Where-Object { $_.Status -eq "Passed" }).Count
        $mdeFailed = ($mdeChecks | Where-Object { $_.Status -eq "Failed" }).Count
        Write-Host "   MDE Endpoints: $mdePassed Passed, $mdeFailed Failed" -ForegroundColor Cyan
        foreach ($check in $mdeChecks) {
            $statusColor = if ($check.Status -eq "Passed") { "Green" } else { "Red" }
            $statusIcon = if ($check.Status -eq "Passed") { "✓" } else { "✗" }
            $description = if ($check.Description) { " ($($check.Description))" } else { "" }
            Write-Host "   [$statusIcon] $($check.Status.PadRight(6)) - $($check.URL)$description" -ForegroundColor $statusColor
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
    
    # Check MDE connectivity failures
    $failedMDEConnectivity = $status.ConnectivityChecks | Where-Object { $_.Status -eq "Failed" -and $_.Category -eq "MDE" }
    if ($failedMDEConnectivity.Count -gt 0) {
        Write-Host "[CRITICAL] $($failedMDEConnectivity.Count) MDE connectivity check(s) failed" -ForegroundColor Red
        Write-Host "           Failed MDE endpoints:" -ForegroundColor Red
        foreach ($failed in $failedMDEConnectivity) {
            $desc = if ($failed.Description) { " - $($failed.Description)" } else { "" }
            Write-Host "           - $($failed.URL)$desc" -ForegroundColor Red
        }
        Write-Host "           Issue: Unable to reach MDE endpoints - Extension installation/updates will fail" -ForegroundColor Red
        Write-Host "           Root Cause: Network connectivity or firewall blocking MDE traffic" -ForegroundColor Red
        Write-Host "           Action: Verify firewall allows access to MDE endpoints" -ForegroundColor Yellow
        Write-Host "                   Required MDE URLs:" -ForegroundColor Yellow
        Write-Host "                   - *.blob.core.windows.net" -ForegroundColor Gray
        Write-Host "                   - go.microsoft.com" -ForegroundColor Gray
        Write-Host "                   - *.wd.microsoft.com" -ForegroundColor Gray
        Write-Host "                   - winatp-gw-*.microsoft.com (aus, aue, auc, eus, weu)" -ForegroundColor Gray
        Write-Host "                   - edr-*.endpoint.security.microsoft.com" -ForegroundColor Gray
        Write-Host "                   - events.data.microsoft.com" -ForegroundColor Gray
        Write-Host "                   - crl.microsoft.com" -ForegroundColor Gray
        Write-Host "                   Check DNS resolution: Resolve-DnsName <endpoint>" -ForegroundColor Yellow
        Write-Host "                   Test connectivity: Test-NetConnection -ComputerName <endpoint> -Port 443" -ForegroundColor Yellow
        $issuesFound = $true
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
    # Check if MDE connectivity tests were performed
    $mdeConnectivityTests = $status.ConnectivityChecks | Where-Object { $_.Category -eq "MDE" }
    if ($mdeConnectivityTests -and $mdeConnectivityTests.Count -gt 0) {
        $failedMDEPrereqs = $mdeConnectivityTests | Where-Object { $_.Status -eq "Failed" }
        
        if ($failedMDEPrereqs.Count -gt 0) {
            Write-Host "[WARNING] MDE.Windows extension not installed - Connectivity prerequisites NOT met" -ForegroundColor Yellow
            Write-Host "          Failed connectivity checks: $($failedMDEPrereqs.Count) of $($mdeConnectivityTests.Count)" -ForegroundColor Yellow
            Write-Host "          Failed endpoints:" -ForegroundColor Yellow
            foreach ($failed in $failedMDEPrereqs) {
                $desc = if ($failed.Description) { " - $($failed.Description)" } else { "" }
                Write-Host "          - $($failed.URL)$desc" -ForegroundColor Red
            }
            Write-Host "          Issue: Cannot install MDE extension until connectivity is established" -ForegroundColor Red
            Write-Host "          Action: Fix firewall/proxy to allow access to these endpoints before installing extension" -ForegroundColor Yellow
            Write-Host "                  Required MDE URLs:" -ForegroundColor Yellow
            Write-Host "                  - *.blob.core.windows.net" -ForegroundColor Gray
            Write-Host "                  - go.microsoft.com" -ForegroundColor Gray
            Write-Host "                  - *.wd.microsoft.com" -ForegroundColor Gray
            Write-Host "                  - winatp-gw-*.microsoft.com (aus, aue, auc, eus, weu)" -ForegroundColor Gray
            Write-Host "                  - edr-*.endpoint.security.microsoft.com" -ForegroundColor Gray
            Write-Host "                  - events.data.microsoft.com" -ForegroundColor Gray
            Write-Host "                  - crl.microsoft.com" -ForegroundColor Gray
            $issuesFound = $true
        } else {
            Write-Host "[INFO] MDE.Windows extension not installed - Connectivity prerequisites VERIFIED" -ForegroundColor Cyan
            Write-Host "       All $($mdeConnectivityTests.Count) MDE endpoint connectivity checks passed" -ForegroundColor Green
            Write-Host "       Server is ready for MDE extension installation" -ForegroundColor Green
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

# Check KB4052623 Installation
if (-not $status.KB4052623.Installed) {
    $osVersion = [Environment]::OSVersion.Version
    $isServer2012R2 = ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 3)
    $isServer2012 = ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 2)
    
    if ($isServer2012R2 -or $isServer2012) {
        Write-Host "[CRITICAL] KB4052623 is not installed" -ForegroundColor Red
        Write-Host "           Issue: SHA-2 code signing support update is missing" -ForegroundColor Red
        Write-Host "           Impact: Required for modern Azure Arc agent and MDE extension installation" -ForegroundColor Red
        Write-Host "           OS Detected: Windows Server $(if ($isServer2012R2) {'2012 R2'} else {'2012'})" -ForegroundColor Yellow
        Write-Host "           Action: Install KB4052623 from Windows Update or download manually" -ForegroundColor Yellow
        Write-Host "                   Download: https://support.microsoft.com/help/4052623" -ForegroundColor Cyan
        Write-Host "                   This update enables SHA-2 code signing support required for security updates" -ForegroundColor Gray
        $issuesFound = $true
    } elseif ($osVersion.Major -eq 6) {
        Write-Host "[WARNING] KB4052623 is not installed" -ForegroundColor Yellow
        Write-Host "          Note: This update may be required for older Windows Server versions" -ForegroundColor Yellow
        Write-Host "          Action: Consider installing KB4052623 if experiencing certificate validation issues" -ForegroundColor Yellow
        $issuesFound = $true
    }
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
Write-Host "   Arc Agent:   %ProgramData%\AzureConnectedMachineAgent\Log\"
Write-Host "   MDE:         Event Viewer `> Microsoft `> Windows `> SENSE"
Write-Host "   Extensions:  %ProgramData%\GuestConfig\extension_logs\"
Write-Host ""
Write-Host "=== Check Complete ===" -ForegroundColor Cyan
