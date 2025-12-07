# Quick CGO rebuild script - for development/testing
# Minimal output, fast rebuild using bundled xz_source

Write-Host "Quick CGO rebuild..." -ForegroundColor Cyan
Set-Location $PSScriptRoot

# Set up paths (convert to absolute paths with forward slashes for CGO)
$xzIncludeDir = (Resolve-Path "xz_source\include").Path.Replace('\', '/')
$xzBinDir = (Resolve-Path "xz_source\bin_x86-64").Path.Replace('\', '/')

# Configure CGO with proper quoting
$env:CGO_ENABLED = "1"
$env:CGO_CFLAGS = "-I$xzIncludeDir"
$env:CGO_LDFLAGS = "-L$xzBinDir -llzma"

Write-Host "CGO_CFLAGS: $env:CGO_CFLAGS" -ForegroundColor Gray
Write-Host "CGO_LDFLAGS: $env:CGO_LDFLAGS" -ForegroundColor Gray

# Build
go build -tags cgo -o ntpi-dumper-cgo.exe ./cmd/ntpi-dumper

if ($LASTEXITCODE -eq 0) {
    # Copy DLL
    Copy-Item "$xzBinDir\liblzma.dll" -Destination ".\liblzma-5.dll" -Force
    Write-Host "Build successful! (CGO mode)" -ForegroundColor Green
    $size = (Get-Item ntpi-dumper-cgo.exe).Length / 1MB
    Write-Host "Size: $([math]::Round($size, 2)) MB" -ForegroundColor Cyan
} else {
    Write-Host "Build failed!" -ForegroundColor Red
}
