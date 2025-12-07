# Quick rebuild script - Fixed version
Write-Host "=" * 50 -ForegroundColor Cyan
Write-Host "NTPI Dumper - Quick Rebuild (Fixed)" -ForegroundColor Green
Write-Host "=" * 50 -ForegroundColor Cyan
Write-Host ""

# Clean old builds
Write-Host "[1/3] Cleaning..." -ForegroundColor Yellow
@("build", "dist") | ForEach-Object {
    if (Test-Path $_) {
        Remove-Item -Path $_ -Recurse -Force
        Write-Host "  Removed $_" -ForegroundColor Gray
    }
}
Write-Host ""

# Build
Write-Host "[2/3] Building with fixed settings..." -ForegroundColor Yellow
Write-Host "  - UPX: Disabled (fixes DLL loading)" -ForegroundColor Cyan
Write-Host "  - Strip: Disabled (prevents corruption)" -ForegroundColor Cyan
Write-Host "  - urllib: Included (required by Python)" -ForegroundColor Cyan
Write-Host ""

pyinstaller --clean ntpi_main.spec

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Build FAILED!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Test
Write-Host ""
Write-Host "[3/3] Testing..." -ForegroundColor Yellow
if (Test-Path "dist\ntpi_dumper.exe") {
    $size = [math]::Round((Get-Item "dist\ntpi_dumper.exe").Length / 1MB, 2)
    Write-Host "  Size: $size MB" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Running: ntpi_dumper.exe --version" -ForegroundColor Gray
    & "dist\ntpi_dumper.exe" --version
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "=" * 50 -ForegroundColor Green
        Write-Host "SUCCESS! Executable is working!" -ForegroundColor Green
        Write-Host "=" * 50 -ForegroundColor Green
        Write-Host ""
        Write-Host "Location: dist\ntpi_dumper.exe" -ForegroundColor Cyan
    } else {
        Write-Host ""
        Write-Host "WARNING: Executable created but test failed" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ERROR: dist\ntpi_dumper.exe not found!" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to exit"
