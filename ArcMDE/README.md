# Azure Arc-Enabled Server Validation Script

Comprehensive health check script for Azure Arc-enabled servers with Microsoft Defender for Endpoint (MDE) validation and connectivity testing.

## Overview

`ValidateARC.ps1` performs detailed validation of Azure Arc-enabled servers including:
- Azure Arc Agent status and heartbeat monitoring
- Managed Identity certificate validation
- Microsoft Defender for Endpoint onboarding verification
- MDE Organization ID validation
- Azure Arc Extensions status (MDE.Windows, SQL Server, Azure Monitor Agent)
- Network connectivity testing (Azure Arc & MDE endpoints)
- System disk space monitoring
- Windows Setup status verification

## Requirements

- **Operating System**: Windows Server 2012 R2 or later, Windows 10/11
- **Execution Policy**: PowerShell script execution must be allowed
- **Permissions**: Run as Administrator (required for service checks and registry access)
- **PowerShell Version**: 5.1 or later

## Parameters

### `-ExpectedOrgId` (Required)
The expected Microsoft Defender for Endpoint Organization ID (GUID format). The script validates the onboarded MDE agent against this ID.

**Example**: `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`

### `-Region` (Optional)
Azure region for MDE connectivity checks. Determines which regional endpoints to test.

**Default**: `"Australia"`

**Valid Options**:
- `Australia`
- `US`
- `Europe`
- `UK`
- `Canada`
- `Asia`

## Usage

### Basic Usage
```powershell
.\ValidateARC.ps1 -ExpectedOrgId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### Specify Region
```powershell
.\ValidateARC.ps1 -ExpectedOrgId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -Region "US"
```

### Run with Elevated Permissions
```powershell
# Right-click PowerShell and "Run as Administrator"
cd C:\Tools
.\ValidateARC.ps1 -ExpectedOrgId "your-org-id-here"
```

## Features

### 1. Azure Arc Agent Validation
- Installation status
- Agent connection state (Connected/Disconnected)
- Last heartbeat timestamp and age
- Error code and details reporting
- Dependent services status (himds, arcproxy, extensionservice, gcarcservice)

### 2. Certificate Monitoring
- Managed Identity certificate validation
- Expiration date checking
- Early warning for certificates expiring within 30 days
- Critical alerts for expired certificates

### 3. MDE Comprehensive Health Check (11-point validation)
- ✅ Sense Service running
- ✅ MsSense process active
- ✅ MDE onboarded (registry check)
- ✅ Cloud connection established
- ✅ Signatures up-to-date (<7 days)
- ✅ Real-time protection enabled
- ✅ Cloud-delivered protection (MAPS)
- ✅ Behavior monitoring enabled
- ✅ Network inspection enabled
- ✅ Telemetry enabled
- ✅ Gateway connectivity working

### 4. MDE Organization ID Validation
- Compares detected Org ID against expected value
- CRITICAL alert if mismatch detected
- Provides remediation guidance

### 5. Extension Status Checking
- MDE.Windows (Azure Defender for Servers)
- WindowsAgent.SqlServer
- AzureMonitorAgent
- Local installation verification
- Azure Policy status correlation

### 6. Network Connectivity Testing

#### Azure Arc Endpoints
Tests connectivity to required Azure Arc service endpoints.

#### MDE Endpoints (Mandatory vs Optional Classification)

**Mandatory Endpoints** (Core MDE functionality):
- `*.blob.core.windows.net` - MDE package storage
- `go.microsoft.com` - MDE installer and security intelligence updates
- `winatp-gw-*.microsoft.com` - Regional gateways (EDR communication)
- `edr-*.endpoint.security.microsoft.com` - EDR endpoints
- `events.data.microsoft.com` - MDE telemetry
- `*.wd.microsoft.com` - Content delivery
- `wdcp.microsoft.com` / `wdcpalt.microsoft.com` - Cloud-delivered protection
- `definitionupdates.microsoft.com` - Definition updates

**Optional Endpoints** (Enhanced features):
- `win.vortex.data.microsoft.com` - Windows diagnostic telemetry
- `ctldl.windowsupdate.com` - Certificate Trust List
- `settings-win.data.microsoft.com` - Windows settings
- `fe3.delivery.mp.microsoft.com` - Windows Update delivery
- `crl.microsoft.com` - Certificate Revocation List

### 7. Issue Detection & Recommendations
Automatically identifies and provides actionable guidance for:
- Arc agent installation/connection issues
- Certificate expiration problems
- Service failures
- Connectivity failures (prioritized by mandatory/optional)
- MDE health issues
- Org ID mismatches

## Output Sections

### 1. Operating System Information
- OS name, version, build number, architecture
- Installation date

### 2. Azure Arc Agent Status
- Installation state
- Connection status and last heartbeat
- Dependent service states
- Error details (if any)

### 3. Managed Identity Certificates
- Certificate inventory with expiration dates
- Status indicators (Valid/Expiring Soon/Expired)

### 4. Microsoft Defender for Endpoint
- Installation verification
- Service and process status
- Onboarding state and Organization ID
- Platform version and age
- Real-time protection status
- 11-point health check results

### 5. Azure Arc Extensions
- Local installation verification
- Extension version information
- Status file analysis

### 6. Connectivity Check
- Overall pass/fail summary
- Azure Arc endpoints results
- MDE.Windows extension endpoints (Arc installation)
- MDE agent runtime endpoints (with mandatory/optional tags)
- Failed endpoint breakdown

### 7. Issues & Recommendations
- Prioritized list of detected issues
- Color-coded severity ([CRITICAL], [WARNING], [INFO])
- Actionable remediation steps

### 8. MDE Onboarding Status Analysis
- Detailed onboarding verification
- Portal status interpretation
- Connectivity impact assessment
- Onboarding method detection (Manual vs Arc-managed)

## Color Coding

- 🟢 **Green**: Healthy/Passed/Connected
- 🟡 **Yellow**: Warning/Needs Attention/Optional Failure
- 🔴 **Red**: Critical/Failed/Disconnected/Expired

## Example Output Interpretation

### Healthy System
```
Overall Summary: 20 Passed, 0 Failed
[✓] Agent Status: Connected
[✓] MDE Health: FULLY FUNCTIONAL (11/11 checks passed)
```

### System with Optional Failures
```
Failed Endpoints: 0 Mandatory, 1 Optional
[✗] Failed - https://win.vortex.data.microsoft.com:443 [OPTIONAL]

[INFO] 1 OPTIONAL MDE connectivity check(s) failed
       Impact: Limited - Core MDE functionality not affected
```

### System with Critical Issues
```
[CRITICAL] 2 MANDATORY MDE connectivity check(s) failed
           Failed MANDATORY MDE endpoints:
           - https://winatp-gw-aus.microsoft.com:443
           Impact: Extension installation/updates may fail, EDR protection degraded
```

## Connectivity Models

This script supports both MDE connectivity models:

- **Standard Connectivity**: Traditional endpoints (*.microsoft.com, *.wd.microsoft.com)
- **Streamlined Connectivity**: Newer model (*.endpoint.security.microsoft.com)

Both models are tested; URLs often overlap or redirect appropriately.

**Reference**: [Microsoft Defender for Endpoint Network Requirements](https://learn.microsoft.com/en-us/defender-endpoint/configure-proxy-internet)

## Troubleshooting

### Script Execution Issues

**Error**: "Execution Policy Restricted"
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Error**: "Access Denied"
- Ensure you're running PowerShell as Administrator

### Common Findings

**"Agent heartbeat is stale"**
- Check network connectivity to Azure
- Verify firewall rules allow outbound HTTPS (443)
- Run: `azcmagent check`

**"MDE Organization ID mismatch"**
- Server is onboarded to wrong tenant
- Re-onboard using correct workspace credentials

**"Extension Service not running"**
- Check: `Get-Service ExtensionService`
- Restart: `Restart-Service ExtensionService -Force`

**"Connectivity failures"**
1. Check DNS resolution: `Resolve-DnsName <endpoint>`
2. Test connectivity: `Test-NetConnection -ComputerName <endpoint> -Port 443`
3. Verify proxy configuration (if applicable)
4. Review firewall rules for outbound HTTPS

## Log Locations

- **Arc Agent**: `C:\ProgramData\AzureConnectedMachineAgent\Log\`
- **MDE**: Event Viewer → Applications and Services Logs → Microsoft → Windows → SENSE
- **Extensions**: `C:\ProgramData\GuestConfig\extension_logs\`
- **Arc Plugins**: `C:\Packages\Plugins\Microsoft.Azure.*\`

## Known Limitations

- Requires Arc agent installed for full Arc connectivity testing
- MDE checks work independently of Arc agent installation
- Network tests use `Test-NetConnection` (basic TCP connectivity only)
- Does not validate proxy authentication
- Regional endpoint selection requires manual parameter specification

## Best Practices

1. **Run Regularly**: Schedule weekly checks to catch issues early
2. **Document Baseline**: Save initial output for comparison
3. **Prioritize Mandatory Failures**: Focus on mandatory endpoint connectivity first
4. **Certificate Monitoring**: Address "Expiring Soon" warnings proactively
5. **Version Updates**: Keep MDE platform version current (monthly updates)

## Version History

- **Latest**: Added mandatory/optional endpoint classification for better prioritization
- Comprehensive MDE 11-point health check
- Regional endpoint support for multiple Azure regions
- Enhanced error reporting with actionable remediation steps

## Support Resources

- [Azure Arc Documentation](https://learn.microsoft.com/en-us/azure/azure-arc/servers/)
- [Microsoft Defender for Endpoint Documentation](https://learn.microsoft.com/en-us/defender-endpoint/)
- [Azure Arc Troubleshooting](https://learn.microsoft.com/en-us/azure/azure-arc/servers/troubleshoot-vm-extensions)
- [MDE Network Requirements](https://learn.microsoft.com/en-us/defender-endpoint/configure-proxy-internet)

## License

This script is provided AS-IS with no warranties. Use at your own risk.

## Contributing

Contributions are welcome! If you have improvements, bug fixes, or new features:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Test thoroughly
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature/improvement`)
7. Create a Pull Request

Please ensure your PR includes:
- Clear description of changes
- Testing performed
- Any relevant documentation updates

For questions or issues, open a GitHub issue

