# NTPI Dumper - Clean rebuild script for PowerShell
# This script cleans old builds and creates a fresh exe package

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NTPI Dumper - Clean Rebuild" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Clean old artifacts
Write-Host "[1/4] Cleaning old build artifacts..." -ForegroundColor Yellow
$foldersToRemove = @("build", "dist", "__pycache__", "utils\__pycache__")
foreach ($folder in $foldersToRemove) {
    if (Test-Path $folder) {
        Remove-Item -Path $folder -Recurse -Force
        Write-Host "  Removed: $folder" -ForegroundColor Gray
    }
}
Write-Host "  Cleanup complete." -ForegroundColor Green
Write-Host ""

# Step 2: Verify Python
Write-Host "[2/4] Verifying Python environment..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "  $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Python not found!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host ""

# Step 3: Check dependencies
Write-Host "[3/4] Checking dependencies..." -ForegroundColor Yellow
$packages = @("pyinstaller", "pycryptodome", "tqdm", "colorama")
foreach ($package in $packages) {
    $installed = pip show $package 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Installing $package..." -ForegroundColor Yellow
        pip install $package
    } else {
        Write-Host "  $package: OK" -ForegroundColor Green
    }
}
Write-Host ""

# Step 4: Build
Write-Host "[4/4] Building executable with PyInstaller..." -ForegroundColor Yellow
Write-Host "  Running: pyinstaller --clean ntpi_main.spec" -ForegroundColor Gray
pyinstaller --clean ntpi_main.spec

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: Build failed!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host ""

# Test the build
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Output: dist\ntpi_dumper.exe" -ForegroundColor Green
Write-Host ""

if (Test-Path "dist\ntpi_dumper.exe") {
    Write-Host "Testing the executable..." -ForegroundColor Yellow
    Write-Host ""
    & "dist\ntpi_dumper.exe" --version
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "SUCCESS: Executable built and tested!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    # Show file size
    $fileSize = (Get-Item "dist\ntpi_dumper.exe").Length / 1MB
    Write-Host "File size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Cyan
} else {
    Write-Host "ERROR: Executable not found!" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to exit"
