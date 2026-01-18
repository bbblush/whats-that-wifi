@echo off
chcp 65001 > nul
cls
echo ========================================================
echo         Installing What's-that-WiFi?
echo ========================================================
echo.
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Error: Python not found.
    echo    Please install Python 3.8 or newer.
    echo    You can download it from the official website: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo ✅ Python is detected.
echo.
echo Installing required dependencies from requirements.txt...
pip install -r requirements.txt
if %errorlevel% equ 0 (
    echo.
    echo ✅ All dependencies have been successfully installed!
    echo.
    echo The application is ready to launch.
    echo To run it, use the 'START.bat' file.
) else (
    echo.
    echo ❌ An error occurred while installing dependencies.
    echo Please try running this script as an administrator.
)
echo.
pause