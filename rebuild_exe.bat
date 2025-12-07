@echo off
REM NTPI Dumper - Clean rebuild script
REM This script cleans old builds and creates a fresh exe package

echo ========================================
echo NTPI Dumper - Clean Rebuild
echo ========================================
echo.

echo [1/4] Cleaning old build artifacts...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist __pycache__ rmdir /s /q __pycache__
if exist utils\__pycache__ rmdir /s /q utils\__pycache__
echo Cleanup complete.
echo.

echo [2/4] Verifying Python environment...
python --version
if %errorlevel% neq 0 (
    echo ERROR: Python not found!
    pause
    exit /b 1
)
echo.

echo [3/4] Checking dependencies...
pip show pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing PyInstaller...
    pip install pyinstaller
)
pip show pycryptodome >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing dependencies...
    pip install -r requirements.txt
)
echo.

echo [4/4] Building executable with PyInstaller...
pyinstaller --clean ntpi_main.spec
if %errorlevel% neq 0 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)
echo.

echo ========================================
echo Build Complete!
echo ========================================
echo Output: dist\ntpi_dumper.exe
echo.
echo Testing the executable...
echo.

REM Test the exe
if exist dist\ntpi_dumper.exe (
    dist\ntpi_dumper.exe --version
    echo.
    echo ========================================
    echo SUCCESS: Executable built and tested!
    echo ========================================
) else (
    echo ERROR: Executable not found!
)
echo.
pause
