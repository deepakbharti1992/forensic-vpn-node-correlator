@echo off
echo ============================================================
echo  Forensic VPN Node Correlator - Desktop Setup
echo ============================================================
echo.

:: Check admin
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo ERROR: Run this script as Administrator.
    pause
    exit /b 1
)

echo [1/4] Installing Python packages...
pip install -r requirements.txt
if %errorLevel% NEQ 0 (
    echo ERROR: pip install failed. Ensure Python 3.11+ is in PATH.
    pause
    exit /b 1
)

echo.
echo [2/4] Checking Npcap...
sc query npcap >nul 2>&1
if %errorLevel% NEQ 0 (
    echo WARNING: Npcap service not found.
    echo Download Npcap from https://npcap.com and install with WinPcap API compatibility.
    echo After installing Npcap, re-run this script.
    pause
)

echo.
echo [3/4] Creating output directory...
if not exist vnc_output mkdir vnc_output

echo.
echo [4/4] Setup complete.
echo.
echo To start the application:
echo   python main.py
echo.
echo IMPORTANT: Always run as Administrator for packet capture.
echo.
pause
