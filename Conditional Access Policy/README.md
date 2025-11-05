# Export/Import Conditional Access Policy (Microsoft Graph)

This PowerShell script provides functionality to export and import/update Conditional Access (CA) policies in Azure AD/Entra ID using the Microsoft Graph API. It allows for bulk management of policies, including a specific mechanism for deleting policies via a dedicated folder.

The script assumes you are using the `Microsoft.Graph` PowerShell module.

## Prerequisites

You must have the following PowerShell module installed:

Install-Module -Name Microsoft.Graph.Identity.SignIns


## Required Permissions (Scopes)

The script connects to the Microsoft Graph and requires the following permissions for read and write operations on Conditional Access policies:

* `Policy.ReadWrite.ConditionalAccess`
* `Policy.Read.All`

You will be prompted to authenticate interactively upon execution if a connection is not already established with these scopes.

## Usage and Parameters

The script supports two primary modes of operation, determined by the `Export` or `Import` switch.

### Parameters

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| **-Export** | `[switch]` | No | | Exports all Conditional Access policies to JSON files. |
| **-Import** | `[switch]` | No | | Imports, updates, or deletes policies based on files in the specified path. |
| **-InputPath** | `[string]` | Yes (for Import) | | Path to a single JSON file or a folder containing policy JSON files. |
| **-OutputPath** | `[string]` | No (for Export) | `.` | Folder path where exported policies will be saved. |
| **-Clean** | `[string]` | Yes (for Export) | `.` | Clean folder before export, deletes all json file. |
| **-Zip** | `[string]` | Yes (for Export) | `.` | Zip all json file with time stamp. |

### 1. Exporting Policies

Use the `-Export` switch and optionally define an output path. The script will save the raw JSON representation of all CA policies.

**Command:**

.\Manage-ConditionalAccessPolicies.ps1 -Export -OutputPath "C:\CAPolicies"


### 2. Importing, Updating, and Deleting Policies

Use the `-Import` switch along with the `-InputPath` pointing to a folder or a single policy file.

#### Import & Update Logic

* The script reads JSON files from the specified input path.
* For each file, it attempts to find an existing policy by its **ID** (if present in the JSON) or its **Display Name**.
* **If a match is found:** The policy is **updated** (`PATCH`) with the content of the JSON file.
* **If no match is found:** A new policy is **created** (`POST`).

> **Note on Updates:** The script automatically removes read-only properties (`id`, `@odata.context`, `createdDateTime`, etc.) before sending the update/create request to the Graph.

#### Deletion Mechanism

To delete policies, place the policy JSON file (typically exported previously) into a subfolder named **`delete`** within your primary input directory.

* The script checks for a `delete` subfolder inside the `-InputPath` directory.
* Any JSON files found in this `delete` subfolder are processed for deletion.
* The policy is identified by its ID or Display Name before being deleted (`DELETE`).

**Command (Import/Update/Delete from a folder):**
If `C:\CAPolicies` contains new or updated policy files, and `C:\CAPolicies\delete` contains files for policies to be removed:

.\Manage-ConditionalAccessPolicies.ps1 -Import -InputPath "C:\CAPolicies"


**Command (Import/Update single file):**
If you only want to import or update one policy file:

.\Manage-ConditionalAccessPolicies.ps1 -Import -InputPath "C:\CAPolicies\Block Legacy Auth.json"


## Helper Functions

The script uses two internal helper functions:

1. **`Clean-PolicyBody`**: Removes Graph read-only properties from the policy JSON payload to ensure successful updates and creations.

2. **`Find-Policy`**: Searches for an existing policy by its `id` or `displayName` using the Graph API.
