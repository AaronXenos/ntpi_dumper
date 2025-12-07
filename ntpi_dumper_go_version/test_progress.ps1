# Test Progress Bar Display
# This script demonstrates the new progress bar format

Write-Host "╔═══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     NTPI Dumper Go - Progress Bar Test           ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Host "New progress bar features:" -ForegroundColor Yellow
Write-Host "  • Individual progress bar for each file" -ForegroundColor White
Write-Host "  • Aligned file names (45 chars)" -ForegroundColor White
Write-Host "  • Uses '=' symbols for progress" -ForegroundColor White
Write-Host "  • Shows real-time speed (B/s)" -ForegroundColor White
Write-Host "  • Auto-clears when complete" -ForegroundColor White
Write-Host ""

Write-Host "Example output format:" -ForegroundColor Yellow
Write-Host ""
Write-Host "abl (2.0 MB)                           100% |====================| (90 MB/s)" -ForegroundColor Green
Write-Host "boot (101 MB)                          100% |====================| (85 MB/s)" -ForegroundColor Green
Write-Host "dtbo (8.4 MB)                           67% |=============       | (92 MB/s)" -ForegroundColor Cyan
Write-Host ""

Write-Host "Available executables:" -ForegroundColor Yellow
Get-ChildItem -Filter "ntpi-dumper*.exe" | ForEach-Object {
    $size = [math]::Round($_.Length / 1MB, 2)
    $mode = if ($_.Name -like "*cgo*") { "CGO (High-Performance)" } else { "Pure Go (Portable)" }
    Write-Host "  • $($_.Name.PadRight(30)) - $size MB - $mode" -ForegroundColor White
}

Write-Host ""
Write-Host "To test the progress bars:" -ForegroundColor Yellow
Write-Host "  .\ntpi-dumper-cgo.exe <your-file.ntpi>" -ForegroundColor White
Write-Host "  or" -ForegroundColor Gray
Write-Host "  .\ntpi-dumper-aligned.exe <your-file.ntpi>" -ForegroundColor White
Write-Host ""
