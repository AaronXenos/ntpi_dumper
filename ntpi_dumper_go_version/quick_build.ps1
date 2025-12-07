# Quick rebuild script - minimal rebuild for testing
# Windows PowerShell

Write-Host "Quick rebuild..." -ForegroundColor Cyan
Set-Location $PSScriptRoot

go build -o ntpi-dumper.exe ./cmd/ntpi-dumper

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful!" -ForegroundColor Green
} else {
    Write-Host "Build failed!" -ForegroundColor Red
}
