@echo off
chcp 65001 > nul
cls
echo =====================================================================
echo Launching...   Launching...   Launching...   Launching...   Launching...
echo =====================================================================
echo What's-That-WiFi         What's-That-WiFi         What's-That-WiFi
echo       What's-That-WiFi         What's-That-WiFi         What's-That-W
echo iFi         What's-That-WiFi         What's-That-WiFi         What's-
echo =====================================================================
echo Launching...   Launching...   Launching...   Launching...   Launching...
echo =====================================================================
echo.
timeout /t 2 /nobreak > nul
start "" pythonw.exe main.pyw
exit