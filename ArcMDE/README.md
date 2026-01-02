# ValidateARC.ps1 - Azure Arc Health Check Script

## Overview

ValidateARC.ps1 is a comprehensive PowerShell diagnostic script for Azure Arc-enabled servers. It performs detailed health checks on Azure Arc agent status, Microsoft Defender for Endpoint (MDE) integration, extensions, and system prerequisites.

## Features

- **Operating System Information** - Display OS name, version, build, and architecture
- **Azure Arc Agent Status** - Agent connectivity, heartbeat monitoring, and service health
- **Managed Identity Certificates** - Certificate validation and expiration monitoring
- **MDE Onboarding** - Defender for Endpoint status and Organization ID verification
- **Windows Setup State** - System ImageState validation
- **KB4052623 Detection** - SHA-2 code signing support verification (critical for Server 2012/2012 R2)
- **Extension Health** - Status monitoring for all Azure Arc extensions
- **Network Connectivity** - Comprehensive endpoint testing for Azure Arc and MDE services
- **System Disk Space** - C: drive space monitoring and alerts
- **Actionable Recommendations** - Detailed troubleshooting steps for detected issues

## Requirements

- **Operating System**: Windows Server 2012 R2 or later
- **PowerShell**: Version 5.1 or later
- **Privileges**: Must run as Administrator
- **Azure Arc Agent**: Optional (script detects if not installed)

## Installation

1. Download `ValidateARC.ps1` to a local directory (e.g., `C:\Tools`)
2. Open PowerShell as Administrator
3. Set execution policy if needed:
   ``powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
   ``

## Usage

### Basic Syntax

``powershell
.\ValidateARC.ps1 -ExpectedOrgId "<MDE_ORGANIZATION_ID>"
``

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-ExpectedOrgId` | Yes | Your Microsoft Defender for Endpoint Organization ID (GUID format) |

### Example

``powershell
.\ValidateARC.ps1 -ExpectedOrgId "bea9b673-6805-4d37-8f77-d45f8f4d22b9"
``

## Health Checks Performed

### 1. Operating System Information
- OS Name and Version
- Build Number
- Architecture (32-bit/64-bit)
- Installation Date

### 2. Azure Arc Agent
- Installation status
- Connection state (Connected/Disconnected)
- Last heartbeat timestamp
- Hours since last heartbeat
- Error codes and details
- Dependent services status:
  - `himds` - Hybrid Instance Metadata Service
  - `arcproxy` - Azure Arc Proxy Service
  - `extensionservice` - Extension Management Service
  - `gcarcservice` - Guest Configuration Arc Service

### 3. Managed Identity Certificates
- Certificate expiration dates
- Days remaining until expiration
- Expired certificates detection
- Certificate validation errors

### 4. Microsoft Defender for Endpoint
- Sense service status
- MsSense process status
- Onboarding state
- Organization ID verification
- OrgId mismatch detection

### 5. Windows Setup Status
- ImageState validation
- OOBE completion check
- Setup completeness verification

### 6. KB4052623 (SHA-2 Support)
- Installation status
- OS version detection (Server 2012/2012 R2)
- SHA-2 code signing support validation

### 7. Azure Arc Extensions
- **MDE.Windows** (Azure Defender for Servers)
  - Installation status
  - Handler state
  - Error detection (connectivity, timeout, installation failures)
- **WindowsAgent.SqlServer**
  - Installation and service status
- **AzureMonitorAgent**
  - Installation status

### 8. Network Connectivity
- **Azure Arc Endpoints** (via `azcmagent check`)
- **MDE Endpoints** (via `Test-NetConnection`):
  - go.microsoft.com
  - automatedirstrprdaue.blob.core.windows.net (Australia East)
  - automatedirstrprdaus.blob.core.windows.net (Australia Southeast)
  - ctldl.windowsupdate.com (Certificate Trust List)
  - win.vortex.data.microsoft.com
  - settings-win.data.microsoft.com
  - x.cp.wd.microsoft.com
  - fe3.delivery.mp.microsoft.com
  - winatp-gw-aus.microsoft.com (Australia Southeast)
  - winatp-gw-aue.microsoft.com (Australia East)
  - winatp-gw-auc.microsoft.com (Australia Central)
  - edr-aue.au.endpoint.security.microsoft.com
  - events.data.microsoft.com
  - crl.microsoft.com

### 9. System Drive Space
- Free space (GB and %)
- Used space (GB)
- Total capacity (GB)
- Low disk space alerts

## Output Format

The script provides color-coded output:
- **Green**: Healthy/Success
- **Yellow**: Warning/Attention needed
- **Red**: Critical/Error
- **Cyan**: Informational
- **Gray**: Secondary details

### Report Sections

1. **Operating System Information**
2. **Azure Arc Agent Status**
3. **Managed Identity Certificates**
4. **Microsoft Defender for Endpoint - Onboarding**
5. **Windows Setup Status**
6. **KB4052623 (SHA-2 Code Signing Support)**
7. **Azure Arc Extensions**
8. **Connectivity Check**
9. **Issues & Recommendations**
10. **Log Locations**

## Common Issues and Solutions

### [CRITICAL] Azure Arc Agent is not installed
**Action**: Install the Azure Arc agent from Azure Portal

### [CRITICAL] Agent heartbeat is stale
**Actions**:
- Run: `azcmagent check`
- Verify proxy settings and firewall rules
- Check network connectivity to Azure endpoints

### [CRITICAL] Certificate thumbprint mismatch
**Actions**:
1. `azcmagent disconnect --force-local-only`
2. `azcmagent connect --resource-group <RG> --tenant-id <TENANT> --location <LOCATION> --subscription-id <SUB>`

### [CRITICAL] MDE Extension installation failed
**Root Causes**:
- Connectivity issues to MDE download servers
- Timeout downloading installer
- Firewall blocking required endpoints

**Actions**:
- Test connectivity: `Test-NetConnection -ComputerName go.microsoft.com -Port 443`
- Check proxy: `netsh winhttp show proxy`
- Verify firewall allows HTTPS (443) to MDE endpoints
- Remove extension, wait 5 minutes, re-add from Azure Portal

### [CRITICAL] KB4052623 is not installed (Server 2012/2012 R2)
**Action**: Install KB4052623 from Windows Update or download from:
- https://support.microsoft.com/help/4052623

### [CRITICAL] MDE Organization ID mismatch
**Action**: Server is onboarded to wrong organization - re-onboard required

## MDE Connectivity Prerequisites

Before installing MDE.Windows extension, ensure connectivity to:
- `*.blob.core.windows.net`
- `go.microsoft.com`
- `*.wd.microsoft.com`
- `winatp-gw-*.microsoft.com` (regional gateways)
- `edr-*.endpoint.security.microsoft.com`
- `events.data.microsoft.com`
- `crl.microsoft.com`

## Log Locations

- **Arc Agent**: `%ProgramData%\AzureConnectedMachineAgent\Log\`
- **MDE**: Event Viewer > Microsoft > Windows > SENSE
- **Extensions**: `%ProgramData%\GuestConfig\extension_logs\`

## Exit Codes

- **0**: Script completed successfully (may still have detected issues)
- **Non-zero**: Script execution error

## Compatibility

- Windows Server 2012 R2
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022
- Windows Server 2025

## Version History

- **Latest**: Added Operating System information, KB4052623 check, comprehensive MDE endpoint testing
- Includes Australian MDE endpoints (aus, aue, auc)
- Enhanced connectivity prerequisite validation

## Support

For issues with:
- **Azure Arc**: Check Azure Arc documentation and support
- **Microsoft Defender for Endpoint**: Refer to MDE documentation
- **This Script**: Review output recommendations and log files

## License

This script is provided as-is for public use. Users may freely use, modify, and distribute this script at their own risk. 

**Disclaimer**: This tool is provided without warranty of any kind, express or implied. The author(s) shall not be held liable for any damages arising from the use of this script. Users are responsible for testing in their own environments and ensuring compliance with their organization's policies and procedures.

