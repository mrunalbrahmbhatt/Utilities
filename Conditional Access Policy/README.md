# Manage-ConditionalAccessPolicies.ps1

A PowerShell script to **export**, **import**, and **update** Microsoft Entra ID (Azure AD) **Conditional Access policies** using the **Microsoft Graph API**.

> Perfect for **backup**, **version control**, **cross-tenant migration**, or **infrastructure-as-code (IaC)**.

---

## Features

- **Export** all Conditional Access policies to individual `.json` files  
- **Import** policies from JSON files – **update existing** or **create new**  
- **Safe filename sanitization** (removes invalid characters)  
- **Preserves full policy structure** (conditions, grant/session controls, etc.)  
- **Idempotent imports** – no duplicates  
- **Automatically removes read-only properties** before import  
- Supports **single file** or **entire folder** input  
- Color-friendly output with color-coded status  

---

## Requirements

- **PowerShell 5.1 or later** (Windows PowerShell or PowerShell 7+)
- **Microsoft Graph PowerShell SDK**:

```powershell
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

## Permissions

This script requires the following **Microsoft Graph permissions**:

| Permission                          | Type        | Purpose |
|-------------------------------------|-------------|---------|
| `Policy.Read.All`                   | Delegated   | Read Conditional Access policies |
| `Policy.ReadWrite.ConditionalAccess`| Delegated   | Create/Update policies |

> **Recommended role**:  
> - **Conditional Access Administrator**  
> - **Global Administrator** (for full access)

> The script uses `Connect-MgGraph` and will prompt for consent if permissions are missing.

---

## Usage

### Export All Policies
```powershell
.\Manage-ConditionalAccessPolicies.ps1 -Export -OutputPath "C:\CAPolicies"
```
### Import All Policies
```powershell
.\Manage-ConditionalAccessPolicies.ps1 -Import -InputPath "C:\CAPolicies"
```

### Import Single File
```powershell
.\Manage-ConditionalAccessPolicies.ps1 -Import -InputPath "C:\CAPolicies\Block_Legacy_Auth.json"
```


## Parameters

| Parameter       | Type     | Required?             | Description |
|-----------------|----------|-----------------------|-------------|
| `-Export`       | `Switch` | Yes (for export mode) | **Export** all Conditional Access policies to individual `.json` files |
| `-Import`       | `Switch` | Yes (for import mode) | **Import** policies from one or more `.json` files |
| `-InputPath`    | `String` | Yes (with `-Import`)  | Path to a **single `.json` file** or **folder** containing policy files |
| `-OutputPath`   | `String` | No                    | Destination folder for exported files<br>**Default**: Current directory (`.`) |

> **Note**: Use **either** `-Export` **or** `-Import`, not both.

---
## License

```text
MIT License

Copyright (c) 2025 [Your Name or Organization]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
