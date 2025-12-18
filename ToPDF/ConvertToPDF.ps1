param(
    [string]$FolderPath = ".",   # Default: current directory
    [string]$OutputFolder = "",  # Optional: separate output folder (leave empty to save next to originals)
    [switch]$Recurse             # Optional: include subfolders
)

# PDF export constants
$wdFormatPDF = 17
$xlFixedFormatTypePDF = 0
$ppSaveAsPDF = 32

# Supported extensions grouped by application
$WordExtensions = @(".doc", ".docx", ".rtf", ".txt")
$ExcelExtensions = @(".xls", ".xlsx", ".xlsm", ".xlsb")
$PowerPointExtensions = @(".ppt", ".pptx")

# Resolve output folder
if ($OutputFolder) {
    $OutputFolder = Resolve-Path $OutputFolder -ErrorAction Stop
} else {
    $OutputFolder = $null
}

# Helper: Get files by extension list
function Get-Files {
    param(
        [string]$Path,
        [string[]]$Extensions,
        [bool]$Recurse
    )
    $splat = @{
        Path = $Path
        File = $true
    }
    if ($Recurse) { $splat.Recurse = $true }

    $Extensions | ForEach-Object {
        Get-ChildItem @splat -Filter "*$_"
    } | Sort-Object FullName -Unique
}

# Convert with Word
function Convert-WithWord {
    param($Files)
    if (-not $Files) { return }

    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = $false

    foreach ($file in $Files) {
        $pdfPath = if ($OutputFolder) {
            Join-Path $OutputFolder ($file.BaseName + ".pdf")
        } else {
            [IO.Path]::ChangeExtension($file.FullName, ".pdf")
        }

        if (Test-Path $pdfPath) {
            Write-Host "Skipping (PDF exists): $($file.Name)"
            continue
        }

        try {
            $doc = $word.Documents.Open($file.FullName, $false, $true)
            $doc.SaveAs([ref]$pdfPath, [ref]$wdFormatPDF)
            $doc.Close()
            Write-Host "Converted: $($file.Name) → $(Split-Path $pdfPath -Leaf)"
        }
        catch {
            Write-Warning "Failed (Word): $($file.Name) - $_"
        }
    }

    $word.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
}

# Convert with Excel
function Convert-WithExcel {
    param($Files)
    if (-not $Files) { return }

    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false

    foreach ($file in $Files) {
        $pdfPath = if ($OutputFolder) {
            Join-Path $OutputFolder ($file.BaseName + ".pdf")
        } else {
            [IO.Path]::ChangeExtension($file.FullName, ".pdf")
        }

        if (Test-Path $pdfPath) {
            Write-Host "Skipping (PDF exists): $($file.Name)"
            continue
        }

        try {
            $wb = $excel.Workbooks.Open($file.FullName)
            $wb.ExportAsFixedFormat($xlFixedFormatTypePDF, $pdfPath)
            $wb.Close($false)
            Write-Host "Converted: $($file.Name) → $(Split-Path $pdfPath -Leaf)"
        }
        catch {
            Write-Warning "Failed (Excel): $($file.Name) - $_"
        }
    }

    $excel.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
}

# Convert with PowerPoint
function Convert-WithPowerPoint {
    param($Files)
    if (-not $Files) { return }

    $ppt = New-Object -ComObject PowerPoint.Application

    foreach ($file in $Files) {
        $pdfPath = if ($OutputFolder) {
            Join-Path $OutputFolder ($file.BaseName + ".pdf")
        } else {
            [IO.Path]::ChangeExtension($file.FullName, ".pdf")
        }

        if (Test-Path $pdfPath) {
            Write-Host "Skipping (PDF exists): $($file.Name)"
            continue
        }

        try {
            $pres = $ppt.Presentations.Open($file.FullName, $true, $false, $false)
            $pres.SaveAs($pdfPath, $ppSaveAsPDF)
            $pres.Close()
            Write-Host "Converted: $($file.Name) → $(Split-Path $pdfPath -Leaf)"
        }
        catch {
            Write-Warning "Failed (PowerPoint): $($file.Name) - $_"
        }
    }

    $ppt.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ppt) | Out-Null
}

# === Main ===

$wordFiles    = Get-Files -Path $FolderPath -Extensions $WordExtensions      -Recurse $Recurse
$excelFiles   = Get-Files -Path $FolderPath -Extensions $ExcelExtensions     -Recurse $Recurse
$pptFiles     = Get-Files -Path $FolderPath -Extensions $PowerPointExtensions -Recurse $Recurse

Convert-WithWord $wordFiles
Convert-WithExcel $excelFiles
Convert-WithPowerPoint $pptFiles

Write-Host "All done! Converted $($wordFiles.Count + $excelFiles.Count + $pptFiles.Count) files."
