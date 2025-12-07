@echo off
REM Build script for NTPI Dumper Go with CGO (using bundled xz_source)
REM Windows Batch Script

echo.
echo ================================================
echo    Building NTPI Dumper Go with CGO Support
echo ================================================
echo.

REM Change to script directory
cd /d "%~dp0"

REM Check for GCC
echo [1/5] Checking for GCC compiler...
where gcc >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo X GCC not found!
    echo.
    echo To install GCC on Windows:
    echo   1. Install MSYS2 from: https://www.msys2.org/
    echo   2. Run: pacman -S mingw-w64-x86_64-gcc
    echo   3. Add to PATH: C:\msys64\mingw64\bin
    echo.
    exit /b 1
)
echo + GCC found
echo.

REM Set up xz_source paths
set XZ_INCLUDE=%~dp0xz_source\include
set XZ_BIN=%~dp0xz_source\bin_x86-64
set XZ_DLL=%XZ_BIN%\liblzma-5.dll

REM Verify xz_source files
echo [2/5] Checking xz_source directory...
if not exist "%XZ_INCLUDE%" (
    echo X xz_source\include directory not found!
    exit /b 1
)
if not exist "%XZ_DLL%" (
    echo X xz_source\bin_x86-64\liblzma-5.dll not found!
    exit /b 1
)
echo + xz_source files found
echo.

REM Download Go dependencies
echo [3/5] Downloading Go dependencies...
go mod tidy
if %ERRORLEVEL% NEQ 0 (
    echo X Failed to download dependencies!
    exit /b 1
)
echo + Dependencies ready
echo.

REM Set CGO environment variables
echo [4/5] Configuring CGO build environment...
set CGO_ENABLED=1
set CGO_CFLAGS=-I"%XZ_INCLUDE%"
set CGO_LDFLAGS=-L"%XZ_BIN%" -llzma
echo + CGO environment configured
echo.

REM Build with CGO
echo [5/5] Compiling with CGO...
go build -tags cgo -ldflags="-s -w" -o ntpi-dumper-cgo.exe ./cmd/ntpi-dumper

if %ERRORLEVEL% NEQ 0 (
    echo X Build failed!
    exit /b 1
)
echo + Build successful!
echo.

REM Copy DLL
echo Copying liblzma-5.dll...
copy /Y "%XZ_DLL%" "." >nul
echo + liblzma-5.dll copied
echo.

echo ================================================
echo          Build Completed Successfully!
echo ================================================
echo.
echo Output: ntpi-dumper-cgo.exe + liblzma-5.dll
echo Mode: CGO (High-Performance, 10-20x faster)
echo.
echo Usage: ntpi-dumper-cgo.exe ^<file.ntpi^>
echo.
echo Note: Keep liblzma-5.dll in the same directory!
echo.

pause
