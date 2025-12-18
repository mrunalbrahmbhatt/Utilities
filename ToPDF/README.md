# Convert To PDF

Batch convert Microsoft Office documents (Word, Excel, PowerPoint) to PDF format using PowerShell and Office COM automation.

## Features

- **Multi-format support**: Converts `.doc`, `.docx`, `.rtf`, `.txt`, `.xls`, `.xlsx`, `.xlsm`, `.xlsb`, `.ppt`, and `.pptx` files
- **Recursive scanning**: Optional subfolder traversal
- **Flexible output**: Save PDFs next to originals or in a separate folder
- **Smart skip**: Automatically skips files if PDF already exists
- **Batch processing**: Converts multiple files in one run

## Requirements

- Windows with PowerShell 5.1 or later
- Microsoft Office installed (Word, Excel, and/or PowerPoint)
- Appropriate Office licenses for automation

## Usage

### Basic Conversion

Convert all Office files in current directory:
```powershell
.\ConvertToPDF.ps1
```

### Specify Folder

Convert files in a specific folder:
```powershell
.\ConvertToPDF.ps1 -FolderPath "C:\Documents"
```

### Include Subfolders

Recursively process all subfolders:
```powershell
.\ConvertToPDF.ps1 -FolderPath "C:\Documents" -Recurse
```

### Custom Output Folder

Save all PDFs to a specific location:
```powershell
.\ConvertToPDF.ps1 -FolderPath "C:\Documents" -OutputFolder "C:\PDFs"
```

### Combined Example

```powershell
.\ConvertToPDF.ps1 -FolderPath "C:\Reports" -OutputFolder "C:\Reports\PDFs" -Recurse
```

## Parameters

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `FolderPath` | String | No | `.` (current directory) | Source folder containing Office files |
| `OutputFolder` | String | No | Empty (same as source) | Destination folder for PDFs |
| `Recurse` | Switch | No | False | Include subfolders in conversion |

## Supported File Types

### Word Documents
- `.doc` - Word 97-2003 Document
- `.docx` - Word Document
- `.rtf` - Rich Text Format
- `.txt` - Plain Text

### Excel Spreadsheets
- `.xls` - Excel 97-2003 Workbook
- `.xlsx` - Excel Workbook
- `.xlsm` - Excel Macro-Enabled Workbook
- `.xlsb` - Excel Binary Workbook

### PowerPoint Presentations
- `.ppt` - PowerPoint 97-2003 Presentation
- `.pptx` - PowerPoint Presentation

## Output

The script provides console output for each file:
- **Success**: `Converted: document.docx → document.pdf`
- **Skip**: `Skipping (PDF exists): document.docx`
- **Error**: `Failed (Word): document.docx - [error details]`

## Notes

- PDFs are saved with the same filename as the source (with `.pdf` extension)
- Existing PDFs are never overwritten
- Office applications run invisibly in the background
- COM objects are properly cleaned up after processing
- Conversion failures are logged but don't stop the batch process

## Troubleshooting

### "New-Object : Retrieving the COM class factory failed"
- Ensure Microsoft Office is installed
- Run PowerShell as Administrator
- Check Office is properly activated

### Conversion hangs or fails
- Close all Office applications before running
- Ensure source files are not password-protected
- Check files are not corrupted or locked

### Permission errors
- Verify read access to source folder
- Verify write access to output folder
- Run as Administrator if accessing protected folders

## Examples

**Convert Word documents only:**
```powershell
Get-ChildItem -Filter "*.docx" | ForEach-Object { .\ConvertToPDF.ps1 -FolderPath $_.DirectoryName }
```

**Scheduled batch conversion:**
```powershell
# Add to Windows Task Scheduler
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File "C:\Tools\ConvertToPDF.ps1" -FolderPath "C:\Incoming" -OutputFolder "C:\Processed" -Recurse
```

## License

Free to use and modify for personal or commercial purposes.
