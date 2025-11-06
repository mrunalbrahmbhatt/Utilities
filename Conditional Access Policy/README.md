# 🛡️ CA Policy Manager: Your Conditional Access Guardian

Simple yet powerful PowerShell automation to manage Microsoft Entra ID Conditional Access policies. Export, import, update, or delete policies with safety guardrails and detailed logging.

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-Export` | No | - | Export all policies to JSON files |
| `-Import` | No | - | Import/update policies from JSON files |
| `-Zip` | No | False | Create ZIP archive of exports in OutputPath\backup |
| `-Clean` | No | False | Remove existing JSON files before export |
| `-InputPath` | Yes (for Import) | - | Source folder containing JSON files or single file path |
| `-OutputPath` | No | "." | Destination folder for exports and logs |

## Quick Start

```powershell
# Export all policies
.\Manage-ConditionalAccessPolicies.improved.ps1 -Export -OutputPath "C:\temp\ca"

# Export and create ZIP backup
.\Manage-ConditionalAccessPolicies.improved.ps1 -Export -Zip -OutputPath "C:\temp\ca"

# Import/update from folder
.\Manage-ConditionalAccessPolicies.improved.ps1 -Import -InputPath "C:\temp\ca"

# Delete policies: Move JSONs to 'delete' folder and import
mkdir "C:\temp\ca\delete"
Move-Item "C:\temp\ca\Policy-to-remove.json" "C:\temp\ca\delete\"
.\Manage-ConditionalAccessPolicies.improved.ps1 -Import -InputPath "C:\temp\ca"
```

## Folder Structure

| Folder | Purpose |
|--------|---------|
| `OutputPath` | Exported JSON policy files |
| `OutputPath\log` | Per-run log files |
| `OutputPath\backup` | ZIP archives when using -Zip |
| `InputPath\delete` | Place policies here to delete them |

## Requirements

- PowerShell (5.1 or 7+)
- Microsoft.Graph PowerShell modules
- Permissions: Policy.ReadWrite.ConditionalAccess, Policy.Read.All

## Features

- Logs operations to `OutputPath\log`
- Export filenames include policy ID for stability
- Safely handles read-only fields and authentication strength
- Server-side filtered lookups to prevent duplicates
- Detailed error logging with Graph response bodies

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Duplicate policies created** | Ensure policy displayName matches exactly. Check logs in `OutputPath\log` for details. |
| **Graph schema errors** | View full error in the log file. Usually caused by read-only fields that Clean-PolicyBody should handle. |
| **Authentication failed** | Verify your account has Policy.ReadWrite.ConditionalAccess permissions. |
| **Cloud Shell differences** | Script works in both PowerShell 5.1 and 7+, but 7+ is recommended for better JSON handling. |

## Looking for Logs?

- Console shows real-time progress
- Detailed logs in `OutputPath\log` folder
- Full request/response data for debugging
- Graph error details captured automatically

## License

MIT Licensed. See LICENSE file.

⚠️ **Important**: 
- Test in non-production first
- Review changes before applying
- Check logs for any errors
- Back up policies with `-Zip` flag

- Idempotency & duplicates: The script attempts to find existing policies by ID first, then by using a server-side OData `$filter` on `displayName`. This reduces false negatives and prevents creating duplicate policies when the script previously missed a match.

- Policy cleaning: Prior to PATCH/POST, the script runs `Clean-PolicyBody` which:
  - Removes read-only fields (`id`, `createdDateTime`, `modifiedDateTime`, `templateId`, `version`) and any `@odata` metadata.
  - Removes explicit nulls.
  - Normalizes `authenticationStrength` into an `{ id: "..." }` reference or removes it if no id is present.

- Cloud Shell compatibility: The script handles differences in `ConvertFrom-Json` behavior between PS versions by trying `-AsHashtable` first then falling back; however PowerShell 7+ is recommended.

Troubleshooting

- Duplicate policies still being created:
  - Confirm the JSON `displayName` exactly matches the policy to update. The script uses server-side filtering but displayName must match exactly to be considered the same policy. Check logs in `OutputPath\log` for filter URIs and results (if you enable additional debug logging).

- Graph returns schema errors (BadRequest):
  - Check the run log — `Log-FullError` attempts to capture the Graph response body and logs the truncated request body. If the error points to a nested read-only object, the script's `Clean-PolicyBody` is designed to remove such fields; open an issue if you have a policy that still fails and include the log.

- Authentication/permissions:
  - Ensure the account you use to Connect-MgGraph has the required scopes/permissions. Interactive Connect-MgGraph is used by default.

- Want console echo from logger?
  - `Write-Log` deliberately doesn't write to console to avoid duplicates. If you want logs echoed, request a change and I can add a global `$script:LogEchoToConsole` switch or an optional `-VerboseLog` parameter.

Extensibility / next steps (optional)

- Add retention logic for `backup` and `log` folders to prune old archives/logs.
- Add a `-WhatIf`/`-DryRun` mode that shows what would change without calling Graph.
- Add Pester tests for `Clean-PolicyBody` and `Find-Policy` (mocking Graph responses).
- Add a `-DebugFindPolicy` flag to log raw Find-Policy URIs and responses for forensic debugging.

License / attribution

- This is a helper script intended for administrators. Use at your own risk; test in a non-production tenant before performing bulk changes.

Contact / changes

If you want further changes (retention, debug switches, CI, or tests), tell me which additions you'd like and I can implement them.
