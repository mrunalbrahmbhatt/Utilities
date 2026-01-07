# ValidateArcMDE.ps1

## Overview

A comprehensive PowerShell diagnostic script for validating Azure Arc-enabled servers with Microsoft Defender for Endpoint (MDE) onboarding. Performs extensive health checks, connectivity validation, and provides detailed troubleshooting guidance with automated remediation recommendations.

## Key Features

### Core Diagnostics
- ✅ **Azure Arc Agent** - Installation, connectivity, heartbeat, dependent services
- ✅ **Managed Identity Certificates** - Expiration validation with 30-day warnings
- ✅ **MDE Onboarding** - Installation, service status, organization ID verification
- ✅ **MDE Health Check** - 11-point comprehensive health assessment with scoring
- ✅ **Streamlined Connectivity** - Prerequisites validation and method detection
- ✅ **Arc Extensions** - Installation status and configuration analysis
- ✅ **Network Connectivity** - Endpoint reachability for all required URLs
- ✅ **Firewall Analysis** - Automated whitelist gap detection

### Advanced Capabilities
- 🔍 Automatic detection of streamlined vs. standard connectivity methods
- 🔍 Real-time firewall whitelist gap analysis with missing URL identification
- 🔍 Certificate expiration monitoring with renewal guidance
- 🔍 MDE version age tracking with update recommendations
- 🔍 SENSE event log error analysis (Event ID 5 detection)
- 🔍 Automatic LastConnected registry verification with ✅/❌ status
- 🔍 Step-by-step remediation guidance for each detected issue

## System Requirements

- **Operating System**: Windows 10 1607+, Windows 11, Windows Server 2012 R2+
- **PowerShell**: Version 5.1 or later
- **Permissions**: Administrator privileges required
- **Network**: Internet connectivity to test endpoints
- **Optional**: Azure Arc agent (for Arc-specific validation)

## Parameters

### Required Parameters

**`-ExpectedOrgId`** (String)
- MDE Organization ID for validation
- Verifies device is onboarded to correct tenant
- Example: `"8769b673-6805-6789-8f77-12345f4d22b9"`

**`-Region`** (String)
- Azure region for endpoint testing
- Valid values: `"US"`, `"Australia"`, `"Europe"`, `"UK"`, `"Canada"`, `"Asia"`
- Determines which regional endpoints to validate
- Default: `"Australia"`

## Usage Examples

### Basic Usage
```powershell
.\ValidateArcMDE.ps1 -ExpectedOrgId "your-org-id-here" -Region "US"
```

### Australia Region (Default)
```powershell
.\ValidateArcMDE.ps1 -ExpectedOrgId "8769b673-6805-6789-8f77-12345f4d22b9" -Region "Australia"
```

### Run as Administrator
```powershell
Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"C:\Tools\ValidateArcMDE.ps1`" -ExpectedOrgId `"your-org-id`" -Region `"US`""
```

## Output Sections

### 1. Operating System Information
- OS name, version, build number, architecture
- Installation date and system uptime
- Current date/time and server name

### 2. Azure Arc Agent Status
**Validates:**
- Installation and connection status
- Last heartbeat timestamp and age
- Dependent services health:
  - `himds` - Hybrid Instance Metadata Service
  - `arcproxy` - Arc Proxy Service (optional)
  - `extensionservice` - Extension Management
  - `gcarcservice` - Guest Configuration Service

### 3. Managed Identity Certificates
**Monitors:**
- Certificate validation (`myCert.cer`, `sslCert.cer`)
- Expiration dates with 30-day warning threshold
- Renewal recommendations for expiring certificates
- Certificate decode error detection

### 4. Microsoft Defender for Endpoint

#### 4.1 Installation & Service Status
- Install path verification (`C:\Program Files\Windows Defender Advanced Threat Protection`)
- MsSense.exe version detection and age tracking
- SENSE service and process status validation

#### 4.2 Onboarding Status
- Registry-based onboarding state verification
- Organization ID validation against expected tenant
- LastConnected timestamp (proof of cloud connectivity)
- Platform version age analysis with update recommendations

#### 4.3 Comprehensive Health Check (11-Point Assessment)
Evaluates 11 critical health indicators:

1. ✅ **Sense Service Running** - Core MDE service operational
2. ✅ **MsSense Process Active** - Agent process executing
3. ✅ **MDE Onboarded** - Registry OnboardingState = 1
4. ✅ **Cloud Connection Established** - LastConnected value present
5. ✅ **Signatures Up-to-Date** - Updated within 7 days
6. ✅ **Real-Time Protection Enabled** - Active threat detection
7. ✅ **Cloud-Delivered Protection (MAPS)** - Advanced protection active
8. ✅ **Behavior Monitoring Enabled** - Behavioral analysis active
9. ✅ **Network Inspection Enabled** - Network traffic scanning
10. ✅ **Telemetry Enabled** - Diagnostic data reporting
11. ✅ **Gateway Connectivity Working** - Regional gateway reachable

**Health Score Interpretation:**
- **11/11 (100%)** - Fully Operational ✅
- **9-10/11 (82-91%)** - Partially Functional ⚠️
- **6-8/11 (55-73%)** - Degraded/Not Functional ⚠️
- **<6/11 (<55%)** - Critical Issues ❌

**Actionable Recommendations:**
Each failed check includes specific remediation steps with PowerShell commands.

#### 4.4 Streamlined Connectivity Prerequisites
Validates per [Microsoft Documentation](https://learn.microsoft.com/en-us/defender-endpoint/configure-device-connectivity#prerequisites):

**Operating System Requirements:**
- ✅ Windows 10 1809 or later
- ✅ Windows 11
- ✅ Windows Server 2019 or later
- ⚠️ Windows Server 2016/2012 R2 - Requires modern unified solution agent

**KB Update Requirements (March 8, 2022 or later):**
| OS Version | Required KB | Release Date |
|------------|-------------|--------------|
| Windows 11 | KB5011493 | March 8, 2022 |
| Windows 10 22H2 | KB5020953 | October 28, 2022 |
| Windows 10 20H2/21H2 | KB5011487 | March 8, 2022 |
| Windows 10 19H2 (1909) | KB5011485 | March 8, 2022 |
| Windows 10 1809 | KB5011503 | March 8, 2022 |
| Windows Server 2022 | KB5011497 | March 8, 2022 |
| Windows Server 2019 | KB5011503 | March 8, 2022 |

**Component Version Requirements:**
- **SENSE**: 10.8040.* or higher (March 2022+)
- **AM Client**: 4.18.2211.5 or higher
- **Engine**: 1.1.19900.2 or higher
- **Security Intelligence**: Current and up-to-date

**Connectivity Method Detection:**
- **Configured vs. Functional** status tracking
- Streamlined domain reachability test (`*.endpoint.security.microsoft.com`)
- Configuration evidence collection from registry
- Automatic fallback recommendations when blocked

### 5. Windows Setup Status
- Setup completion verification
- ImageState registry validation (`IMAGE_STATE_COMPLETE`)
- Installation integrity check

### 6. Azure Arc Extensions

#### Extension Check Types
1. **Azure Policy Check** - Configuration deployment from Azure Resource Manager
2. **Local Installation Check** - Physical installation verification on disk

#### Supported Extensions
- `MDE.Windows (AzureDefenderForServers)` - Microsoft Defender for Endpoint
- `WindowsPatchExtension` - Windows Update management
- `WindowsOsUpdateExtension` - OS update orchestration
- `WindowsAgent.SqlServer` - SQL Server monitoring
- `AzureMonitorAgent` - Azure Monitor data collection

#### Extension Status Parsing
**Success Detection:**
```
Onboarding: SUCCESS ✅
Machine ID: 81754f8888e182d1d36865f83407e767764bdeab
Workspace ID: 4812c228-b392-47d6-b5e8-6f088d09d213
Details:
  • OS: Microsoft Windows Server 2012 R2 Standard
  • Azure Resource: /subscriptions/.../SERVERNAME
  • Proxy: Not configured (direct connection)
```

**Failure Detection:**
- Installation errors with detailed messages
- Configuration issues with troubleshooting steps
- Connectivity failures with required URLs

### 7. Connectivity Check

#### Azure Arc Endpoints
- Core Azure services (management.azure.com, login.microsoftonline.com)
- Guest configuration services
- Private Link Scope validation

#### MDE.Windows Extension Endpoints (Installation Requirements)
**Purpose:** Arc extension installer download and package retrieval

- `go.microsoft.com:443` - MDE installer download
- `automatedirstrprd*.blob.core.windows.net:443` - Regional blob storage

**Regional Blob Storage by Region:**
- **US**: cus, eus, wus
- **Australia**: aue, aus
- **Europe**: neu, weu
- **UK**: uks, ukw

#### MDE Agent Runtime Endpoints (Operational Requirements)

**MANDATORY Endpoints (12 endpoints):**
| Endpoint | Purpose |
|----------|---------|
| `winatp-gw-*.microsoft.com:443` | Regional MDE gateways |
| `edr-*.endpoint.security.microsoft.com:443` | EDR telemetry endpoints |
| `events.data.microsoft.com:443` | Global telemetry service |
| `*-v20.events.data.microsoft.com:443` | Regional telemetry service |
| `wdcp.microsoft.com:443` | Cloud-delivered protection |
| `wdcpalt.microsoft.com:443` | Alternate cloud protection |
| `x.cp.wd.microsoft.com:443` | Content delivery network |
| `cdn.x.cp.wd.microsoft.com:443` | CDN content delivery |
| `go.microsoft.com:443` | Download service |
| `definitionupdates.microsoft.com:443` | Signature updates |

**OPTIONAL Endpoints (5 endpoints):**
| Endpoint | Purpose |
|----------|---------|
| `ctldl.windowsupdate.com:443` | Certificate Trust List |
| `win.vortex.data.microsoft.com:443` | Windows telemetry |
| `settings-win.data.microsoft.com:443` | Windows settings |
| `fe3.delivery.mp.microsoft.com:443` | Windows Update delivery |
| `crl.microsoft.com:80` | Certificate revocation list |

### 8. Issues & Recommendations

**Severity Levels:**
- **[CRITICAL]** ❌ - Requires immediate attention (service down, no connectivity)
- **[WARNING]** ⚠️ - Should be addressed (expiring certificates, version updates)
- **[INFO]** ℹ️ - Informational guidance (configuration recommendations)

**Issue Categories:**
- Arc agent installation/connectivity
- MDE onboarding and cloud connection
- Extension installation failures
- Network connectivity and firewall
- Certificate expiration
- Disk space and system resources

### 9. MDE Onboarding Status Analysis

#### Scenario 1: Portal Shows 'Onboarded' ✅
**Indicators:**
- Registry OnboardingState: 1 (Onboarded)
- Registry LastConnected: Present with timestamp
- Portal Status: 'Defender for Server: Onboarded'

**Interpretation:** Device successfully onboarded and communicating with MDE cloud

#### Scenario 2: Portal Shows 'Can be onboarded' ❌
**Indicators:**
- Registry OnboardingState: 1 (Onboarded)
- Registry LastConnected: NOT PRESENT
- Portal Status: 'Defender for Endpoint can be onboarded'

**Root Cause:** Firewall blocking - device onboarded locally but never connected to cloud

**Evidence:**
- Outdated platform version (proves no cloud connectivity)
- SENSE event log errors (Event ID 5: "Contacted server X times, all failed")
- Failed connectivity tests to MDE endpoints

**5-Step Remediation:**
1. **Add Firewall Rules** - Whitelist required MDE URLs (see Firewall Analysis section)
2. **Restart SENSE Service** - `Restart-Service Sense -Force`
3. **Wait for Connection** - 5-10 minutes for cloud handshake
4. **Verify LastConnected** - Script automatically checks with ✅/❌ status
5. **Confirm in Portal** - Wait additional 10-15 minutes, refresh portal

#### Scenario 3: Manual vs. Arc-Managed Onboarding
**Manual/Classic Method:**
```
Azure Arc: Connected ✓
MDE Agent: Onboarded ✓ (manually, not via Arc extension)
MDE.Windows Extension: NOT INSTALLED

Portal Status Breakdown:
├─ 'Defender for Server': Onboarded ✓
├─ 'Defender for Endpoint': Can be onboarded
└─ 'Last device update': Shows current date (communicating)

Explanation:
• Portal displays TWO different onboarding statuses
• 'Defender for Server' = Manual onboarding status (✓)
• 'Defender for Endpoint' = Arc extension status
• 'Can be onboarded' means Arc extension CAN be installed
• Device IS working correctly - no action required
```

### 10. Firewall Whitelist Analysis

**NEW FEATURE:** Automated firewall gap detection

Compares failed endpoints against typical firewall whitelist patterns and identifies missing URLs.

**Example Output:**
```
🔴 CRITICAL FINDING: Missing URLs in Firewall Whitelist

The following MANDATORY MDE endpoints are FAILING connectivity tests
but are NOT covered by typical firewall whitelist patterns:

❌ https://winatp-gw-aus.microsoft.com:443
   Purpose: MDE Australia Gateway (AUS)
   Status: NOT whitelisted - Add to firewall rules

❌ https://events.data.microsoft.com:443
   Purpose: MDE Telemetry (Global)
   Status: NOT whitelisted - Add to firewall rules

ACTION REQUIRED: Add these URLs to firewall whitelist
───────────────────────────────────────────────────────

Firewall Rules to Add (Wildcard Patterns):
• winatp-gw-*.microsoft.com
• events.data.microsoft.com
• edr-*.*.endpoint.security.microsoft.com

Configuration Example:
Protocol: HTTPS
Port: 443
Direction: Outbound
Action: Allow

After adding rules:
1. Verify rules applied: Test-NetConnection <endpoint> -Port 443
2. Restart MDE service: Restart-Service Sense -Force
3. Wait 5-10 minutes for cloud connection
4. Re-run this script to verify connectivity
```

**Troubleshooting Scenarios:**
- ✅ **URLs covered but still failing** - Rules configured but not applied/activated
- ⚠️ **Proxy authentication** - Credentials required but not configured
- ⚠️ **DNS resolution failures** - Domain names not resolving
- ⚠️ **SSL inspection** - Intermediate proxy breaking HTTPS connections

## Regional Endpoint Reference

### United States (US)
**Gateways:**
- `winatp-gw-eus.microsoft.com` (East US)
- `winatp-gw-wus.microsoft.com` (West US)
- `winatp-gw-cus.microsoft.com` (Central US)

**EDR & Telemetry:**
- `edr-eus.us.endpoint.security.microsoft.com`
- `us-v20.events.data.microsoft.com`

**Blob Storage:**
- `automatedirstrprdcus.blob.core.windows.net`
- `automatedirstrprdeus.blob.core.windows.net`
- `automatedirstrprdwus.blob.core.windows.net`

### Australia
**Gateways:**
- `winatp-gw-aus.microsoft.com` (Australia Southeast)
- `winatp-gw-aue.microsoft.com` (Australia East)
- `winatp-gw-auc.microsoft.com` (Australia Central)

**EDR & Telemetry:**
- `edr-aue.au.endpoint.security.microsoft.com`
- `au-v20.events.data.microsoft.com`

**Blob Storage:**
- `automatedirstrprdaue.blob.core.windows.net`
- `automatedirstrprdaus.blob.core.windows.net`

### Europe
**Gateways:**
- `winatp-gw-neu.microsoft.com` (North Europe)
- `winatp-gw-weu.microsoft.com` (West Europe)

**EDR & Telemetry:**
- `edr-neu.eu.endpoint.security.microsoft.com`
- `eu-v20.events.data.microsoft.com`

**Blob Storage:**
- `automatedirstrprdneu.blob.core.windows.net`
- `automatedirstrprdweu.blob.core.windows.net`

### United Kingdom (UK)
**Gateways:**
- `winatp-gw-uks.microsoft.com` (UK South)
- `winatp-gw-ukw.microsoft.com` (UK West)

**EDR & Telemetry:**
- `edr-uks.uk.endpoint.security.microsoft.com`
- `uk-v20.events.data.microsoft.com`

**Blob Storage:**
- `automatedirstrprduks.blob.core.windows.net`
- `automatedirstrprdukw.blob.core.windows.net`

## Common Issues & Solutions

### Issue 1: Portal Shows "Can be onboarded" But Device Has LastConnected Value
**Symptom:** Confusing portal status despite device working correctly

**Cause:** Device onboarded manually (not via Arc extension)

**Explanation:**
- Portal shows TWO different onboarding methods:
  - 'Defender for Server': Manual onboarding status (✓ Onboarded)
  - 'Defender for Endpoint': Arc extension availability (Can be onboarded)
- LastConnected value proves device IS communicating with MDE cloud
- "Can be onboarded" refers to Arc extension installation option
- **No action required** - device is working correctly

**Portal Indicators:**
- ✅ 'Defender for Server': Onboarded
- ℹ️ 'Defender for Endpoint': Can be onboarded
- ✅ 'Last device update': Shows current date

### Issue 2: Portal Shows "Can be onboarded" With NO LastConnected Value
**Symptom:** Device appears onboarded locally but not in cloud

**Cause:** Firewall blocking all MDE endpoints - device never connected

**Root Cause Evidence:**
- Registry OnboardingState: 1 (onboarded locally)
- Registry LastConnected: NOT PRESENT (never connected to cloud)
- Platform version critically outdated (proves no auto-updates)
- SENSE event log: Event ID 5 errors

**Solution:**
1. **Review Firewall Analysis section** in script output
2. **Add missing URLs** identified by script
3. **Restart SENSE service**: `Restart-Service Sense -Force`
4. **Wait 5-10 minutes** for initial cloud connection
5. **Verify automatically**: Script checks LastConnected with ✅/❌
6. **Confirm in portal**: Wait 10-15 more minutes, refresh page

### Issue 3: Streamlined Connectivity Configured But Not Functional
**Symptoms:**
- Connectivity Method: Streamlined (Configured)
- Status: NOT FUNCTIONAL
- SENSE Event ID 5: "Contacted server 5 times, all failed, URI: https://edr-*.endpoint.security.microsoft.com"
- Streamlined domain unreachable

**Cause:** Firewall blocking `*.endpoint.security.microsoft.com` wildcard pattern

**Solution:**
```powershell
# Add these firewall rules:
# 1. Streamlined domain (primary)
*.endpoint.security.microsoft.com:443
edr-*.endpoint.security.microsoft.com:443

# 2. Fallback URLs (required)
winatp-gw-*.microsoft.com:443
events.data.microsoft.com:443

# 3. Restart SENSE service
Restart-Service Sense -Force

# 4. Verify connectivity
Test-NetConnection endpoint.security.microsoft.com -Port 443
```

**Alternative:** Re-onboard with standard connectivity package if firewall changes not feasible

### Issue 4: Server 2016/2012 R2 Shows Prerequisites Not Met
**Symptoms:**
- [✗] Operating System: Windows Server 2016/2012 R2 (NOT SUPPORTED)
- [✗] Required KB Update: NOT SUPPORTED - No KB update available

**Explanation:**
KB updates for streamlined connectivity are **NOT AVAILABLE** for Server 2016/2012 R2

**Important Guidance:**
```
⚠️ IMPORTANT: Windows Server 2016/2012 R2 Guidance
───────────────────────────────────────────────────────
Streamlined connectivity is NOT supported via KB updates for Server 2016/2012 R2

Alternative Option: Modern Unified Solution Agent
  • Requires downloading modern unified solution package
  • Provides streamlined connectivity without KB updates
  • Reference: https://learn.microsoft.com/en-us/defender-endpoint/server-migration

Current Status: Using Standard Connectivity (Classic Method)
  • This is the expected configuration for Server 2016/2012 R2
  • Standard connectivity remains fully supported
```

**Options:**
1. **Keep Standard Connectivity** (Recommended) - Current setup is normal and fully functional
2. **Upgrade to Unified Agent** - For streamlined connectivity support

### Issue 5: MDE Extension Shows "success" But Appears as Error
**Previous Confusing Behavior:**
```
Status: success
Error: { "onboardingPackageOperationResultCode": "Success", ... }
```

**Fixed - Now Shows:**
```
Onboarding: SUCCESS ✅
Machine ID: 81754f8888e182d1d36865f83407e767764bdeab
Workspace ID: 4812c228-b392-47d6-b5e8-6f088d09d213
Details:
  • OS: Microsoft Windows Server 2012 R2 Standard
  • Azure Resource: INFRAG10
  • Proxy: Not configured (direct connection)
```

### Issue 6: MDE Platform Version Critically Outdated
**Symptoms:**
- Platform version 400+ days old
- Status: CRITICALLY OUTDATED (6+ months old)
- Signatures not updating

**Root Cause:** No cloud connectivity - agent cannot auto-update

**Solution Sequence:**
1. Fix connectivity issues (see Firewall Analysis)
2. Restart SENSE service
3. Wait for cloud connection
4. Updates occur automatically once connected
5. Force signature update: `Update-MpSignature`

### Issue 7: Certificate Expiring Soon
**Warning:** Certificate expires in <30 days

**Impact:** Device loses Arc connectivity when certificate expires

**Mitigation:**
1. Arc agent attempts auto-renewal 45 days before expiry
2. Monitor certificate status in script output
3. If auto-renewal fails, manually re-onboard to Arc
4. Check logs: `C:\ProgramData\AzureConnectedMachineAgent\Log\`

## Troubleshooting Commands

### Azure Arc Agent
```powershell
# Check Arc agent status
azcmagent show

# Test Arc connectivity
azcmagent check

# View Arc agent logs
Get-Content "C:\ProgramData\AzureConnectedMachineAgent\Log\himds.log" -Tail 50

# Restart Arc services
Restart-Service himds, extensionservice, gcarcservice -Force
```

### MDE Service & Onboarding
```powershell
# Check SENSE service status
Get-Service Sense

# Restart SENSE service
Restart-Service Sense -Force

# View SENSE event logs (last 50 events)
Get-WinEvent -LogName 'Microsoft-Windows-SENSE/Operational' -MaxEvents 50

# Filter for errors only
Get-WinEvent -LogName 'Microsoft-Windows-SENSE/Operational' -MaxEvents 50 | Where-Object {$_.LevelDisplayName -eq 'Error'}

# Check onboarding registry
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'

# Verify LastConnected value specifically
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' | Select-Object LastConnected, OnboardingState, OrgId
```

### MDE Platform & Configuration
```powershell
# Get comprehensive MDE status
Get-MpComputerStatus

# Update security intelligence signatures
Update-MpSignature

# Enable MAPS (cloud-delivered protection)
Set-MpPreference -MAPSReporting Advanced

# Enable behavior monitoring
Set-MpPreference -DisableBehaviorMonitoring $false

# Check platform versions
Get-MpComputerStatus | Select-Object AMProductVersion, AMEngineVersion, AntispywareSignatureLastUpdated, AntispywareSignatureAge

# View all MDE preferences
Get-MpPreference
```

### Network Connectivity Testing
```powershell
# Test specific endpoint
Test-NetConnection -ComputerName winatp-gw-aue.microsoft.com -Port 443

# Test with detailed output
Test-NetConnection winatp-gw-aue.microsoft.com -Port 443 -InformationLevel Detailed

# Check DNS resolution
Resolve-DnsName winatp-gw-aue.microsoft.com

# Check proxy configuration
netsh winhttp show proxy

# Test with curl (verbose output)
curl -v https://winatp-gw-aue.microsoft.com

# Test multiple endpoints at once
$endpoints = @(
    "winatp-gw-eus.microsoft.com",
    "events.data.microsoft.com",
    "go.microsoft.com",
    "definitionupdates.microsoft.com"
)
$endpoints | ForEach-Object {
    Test-NetConnection $_ -Port 443 | Select-Object ComputerName, TcpTestSucceeded
}
```

### Extension Service Management
```powershell
# Check extension service
Get-Service ExtensionService

# Restart extension service
Restart-Service ExtensionService -Force

# View extension manager logs (last 100 lines)
Get-Content "C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext.log" -Tail 100

# List all installed Arc extensions
Get-ChildItem "C:\Packages\Plugins\" -Directory

# Check specific extension status files
Get-ChildItem "C:\ProgramData\GuestConfig\extension_logs\" -Recurse -Filter "*.json"
```

## Log File Locations

### Script Output
- **Console Only** - Script outputs diagnostics to console, no files created

### System Logs for Manual Review
| Component | Location |
|-----------|----------|
| Arc Agent | `C:\ProgramData\AzureConnectedMachineAgent\Log\` |
| MDE (SENSE) | Event Viewer → Applications and Services Logs → Microsoft → Windows → SENSE → Operational |
| Extensions | `C:\ProgramData\GuestConfig\extension_logs\` |
| Extension Manager | `C:\ProgramData\GuestConfig\ext_mgr_logs\gc_ext.log` |
| Arc Plugins | `C:\Packages\Plugins\Microsoft.Azure.*\` |

## Version History

### Version 2.0 (January 2026)

#### Major Enhancements
- ✨ **Firewall Whitelist Analysis** - Automated gap detection with missing URL identification
- ✨ **Automatic LastConnected Verification** - Clear ✅/❌ status display
- ✨ **Streamlined Connectivity Detection** - Configured vs. Functional status tracking
- ✨ **Extension Status Parsing** - Success vs. error distinction with structured output
- ✨ **Server 2016/2012 R2 Guidance** - Clear explanations and alternative options
- ✨ **Onboarding Method Detection** - Manual vs. Arc-managed differentiation
- ✨ **Portal Status Clarification** - "Can be onboarded" explanation

#### Bug Fixes
- 🐛 Fixed OS data collection timing in streamlined connectivity check
- 🐛 Fixed extension success detection (improved JSON parsing)
- 🐛 Fixed confusing "Status: success, Error: {JSON}" display
- 🐛 Fixed build revision comparison for integrated KB updates
- 🐛 Fixed firewall analysis not detecting failed endpoints correctly

#### Improvements
- 📝 Step-by-step remediation guidance for each issue
- 📝 Better evidence collection for connectivity problems
- 📝 Enhanced troubleshooting recommendations
- 📝 Added configuration examples for firewall rules
- 📝 Improved health check scoring and interpretation

## Technical Requirements

### PowerShell Version Check
```powershell
# Check current PowerShell version
$PSVersionTable.PSVersion
# Required: 5.1 or later
```

### Execution Policy
```powershell
# Check current execution policy
Get-ExecutionPolicy

# Set for current session (if needed)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Run script with bypass
powershell -ExecutionPolicy Bypass -File ".\ValidateArcMDE.ps1" -ExpectedOrgId "your-org-id" -Region "US"
```

### Administrator Check
```powershell
# Verify running as administrator
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

## Microsoft Documentation Links

### Core Documentation
- [Azure Arc-enabled servers overview](https://learn.microsoft.com/en-us/azure/azure-arc/servers/overview)
- [Onboard Windows servers to MDE](https://learn.microsoft.com/en-us/defender-endpoint/onboard-windows-server)
- [MDE streamlined connectivity](https://learn.microsoft.com/en-us/defender-endpoint/configure-device-connectivity)
- [Server migration to modern unified solution](https://learn.microsoft.com/en-us/defender-endpoint/server-migration)
- [Troubleshoot VM extensions on Arc](https://learn.microsoft.com/en-us/azure/azure-arc/servers/troubleshoot-vm-extensions)

### Azure Portals
- [Azure Portal](https://portal.azure.com) - Arc resources and management
- [Microsoft Defender Portal](https://security.microsoft.com) - MDE management and reporting
- [Azure Arc Overview](https://portal.azure.com/#view/Microsoft_Azure_HybridCompute/AzureArcCenterBlade) - Centralized Arc management

## License

**This script is provided AS-IS with no warranties. Use at your own risk.**

The author(s) and contributor(s) of this script are not responsible for any damage, data loss, or issues that may arise from its use. Always test in a non-production environment first and ensure you have proper backups before making any system changes.

## Contributing

Contributions are welcome! If you have improvements, bug fixes, or new features to suggest:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes with clear, commented code
4. Test thoroughly on multiple Windows versions
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature/improvement`)
7. Create a Pull Request with detailed description

### Pull Request Requirements
Please ensure your PR includes:
- ✅ Clear description of changes and motivation
- ✅ Testing performed (OS versions, scenarios tested)
- ✅ Documentation updates (README.md, inline comments)
- ✅ No breaking changes to existing functionality (unless clearly justified)

### Reporting Issues
For questions, bugs, or feature requests, please open a GitHub issue with:
- Script version and PowerShell version
- Operating system and build number
- Complete error messages or unexpected output
- Steps to reproduce the issue

---

**Script Version**: 2.0  
**Last Updated**: January 7, 2026  
**Compatibility**: Windows 10 1607+, Windows 11, Windows Server 2012 R2+  
**PowerShell**: 5.1+  
**License**: AS-IS, Use at Your Own Risk


