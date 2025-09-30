# Utilities
Misc. utilities used or developed during development.


## 1. TDS to Unicorn
This script will crawl your given folder for .scproj files and generates the 95% of equivalent Unicorn single config file. Afterward, the user can customize the generated config according to their needs if something is not working.

### How to use:

1. .\TDStoUnicorn2.ps1 -ProjectName "ProjectName"  *> Project.Website.Serialization.config
2. Replace "ProjectName" in "Unicorn.ProjectName.Config" file content and name.

## 2. [Sync-workflow in mulitiple repositories](https://github.com/mrunalbrahmbhatt/Utilities/blob/master/sync-workflows.sh)
The script lists all non-archived repositories, fetches their default branch, clones each, adds msdevopssec.yml (Microsoft Secuirty DevOps Task), commits, and pushes to the correct branch.
### How to use [Bash command]:

1. Make sure [msdevopssec.yml](https://github.com/mrunalbrahmbhatt/Utilities/blob/master/.github/workflows/msdevopssec.yml) is in same folder as script.
2. chmod +x sync-workflows.sh
3. gh auth login
4. ./sync-workflows.sh



## 3. [Cloud App Discovery Export Script](https://github.com/mrunalbrahmbhatt/Utilities/blob/master/Get-CloudAppDiscovery.ps1)
This PowerShell script retrieves **discovered cloud applications** and their associated **users** from the Microsoft Graph **Cloud App Discovery API** and exports the data to a CSV file.  
It uses **OAuth 2.0 client credentials (App ID + Secret)** for secure, non-interactive authentication.


### 🔒 Requirements
- **Azure AD App Registration** with:
  - Microsoft Graph API **Application Permission**: `CloudApp-Discovery.Read.All`
  - Admin consent granted
- PowerShell module: `Microsoft.Graph.Authentication` (v2.0.0+)
- Network access to:
  - `https://login.microsoftonline.com`
  - `https://graph.microsoft.com`


### ⚙️ Parameters

<pre><code class="language-powershell">
$streamId     = ""   # Uploaded stream ID
$csvPath      = "C:\Temp\CloudApps_Users.csv"
$period       = "P90D"   # Duration (e.g., P30D, P90D)
$tenantId     = ""
$clientId     = ""
$clientSecret = ""   # Store securely (e.g., Azure Key Vault)
</code></pre>

### ✅ Usage
<pre><code class="language-powershell">.\Get-CloudAppDiscovery.ps1</code></pre>


### Disclaimer

This script is tested on internal projects only, thus feel free to modify to satisfy your needs. I'm not PowerShell/Shell script expert so please ignore my poor scripting. Also, I'm not favoring any tool here.Use at your own risk.

### Suggestion

Please share your suggestions or if you find the better way to do it @ it.mrunal@gmail.com.
Happy Sharing.


