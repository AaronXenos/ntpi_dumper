# Build script for NTPI Dumper Go
# Windows PowerShell

Write-Host "Building NTPI Dumper Go..." -ForegroundColor Cyan

# Change to project directory
Set-Location $PSScriptRoot

# Download dependencies
Write-Host "Downloading dependencies..." -ForegroundColor Yellow
go mod tidy
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to download dependencies!" -ForegroundColor Red
    exit 1
}

# Check if CGO is available
$useCGO = $false
if (Get-Command gcc -ErrorAction SilentlyContinue) {
    Write-Host "GCC found, checking for liblzma..." -ForegroundColor Yellow
    
    # Test if liblzma is available
    $testCode = "#include <lzma.h>`nint main() { return 0; }"
    $testCode | Out-File -Encoding ASCII test.c
    gcc test.c -llzma -o test.exe 2>$null
    
    if ($LASTEXITCODE -eq 0) {
        $useCGO = $true
        Write-Host "liblzma found! Building with CGO (high-performance mode)" -ForegroundColor Green
    } else {
        Write-Host "liblzma not found, building with pure Go (slower but portable)" -ForegroundColor Yellow
        Write-Host "To enable CGO: Install MSYS2 and run 'pacman -S mingw-w64-x86_64-xz'" -ForegroundColor Cyan
    }
    
    Remove-Item test.c, test.exe -ErrorAction SilentlyContinue
} else {
    Write-Host "GCC not found, building with pure Go (slower but portable)" -ForegroundColor Yellow
    Write-Host "To enable CGO: Install MSYS2 from https://www.msys2.org/" -ForegroundColor Cyan
}

# Build
Write-Host "Compiling..." -ForegroundColor Yellow
if ($useCGO) {
    $env:CGO_ENABLED = "1"
    go build -ldflags="-s -w" -o ntpi-dumper.exe ./cmd/ntpi-dumper
} else {
    $env:CGO_ENABLED = "0"
    go build -ldflags="-s -w" -o ntpi-dumper.exe ./cmd/ntpi-dumper
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Build successful!" -ForegroundColor Green
Write-Host "Executable: ntpi-dumper.exe" -ForegroundColor Cyan

# Show file size
$fileSize = (Get-Item ntpi-dumper.exe).Length / 1MB
Write-Host "File size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Cyan

if ($useCGO) {
    Write-Host "Mode: CGO (10-20x faster decompression)" -ForegroundColor Green
} else {
    Write-Host "Mode: Pure Go (portable but slower)" -ForegroundColor Yellow
}
