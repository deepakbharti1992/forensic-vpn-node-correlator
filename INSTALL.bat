@echo off
chcp 65001 >nul
title VNC Forensic — First Time Setup
color 1F
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║     FORENSIC VPN NODE CORRELATOR — INSTALLER        ║
echo  ║     First Time Setup                                 ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

set ROOT=%~dp0
set DESKTOP=%ROOT%desktop
set ADB=%ROOT%tools\adb.exe
set APK=%ROOT%VNCForensic-debug.apk
set ERRORS=0

:: ── Check Python ─────────────────────────────────────────────
echo [1/6] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo  [FAIL] Python not found!
    echo         Download from: https://python.org/downloads
    echo         Install Python 3.10 or higher, tick "Add to PATH"
    set ERRORS=1
    goto :ask_continue
) else (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  [OK]   %%v
)

:: ── Install Python packages ───────────────────────────────────
echo.
echo [2/6] Installing Python packages...
pip install -r "%DESKTOP%\requirements.txt" --quiet --disable-pip-version-check
if errorlevel 1 (
    echo  [FAIL] pip install failed — check internet connection
    set ERRORS=1
) else (
    echo  [OK]   All packages installed
)

:: ── Check Npcap ───────────────────────────────────────────────
echo.
echo [3/6] Checking Npcap (packet capture driver)...
sc query npcap >nul 2>&1
if errorlevel 1 (
    echo  [WARN] Npcap not found!
    echo         Opening Npcap download page...
    start https://npcap.com/#download
    echo         Install Npcap, then re-run this installer.
    echo         Make sure to tick "WinPcap API-compatible Mode"
    pause
) else (
    echo  [OK]   Npcap is installed
)

:: ── Check ADB ────────────────────────────────────────────────
echo.
echo [4/6] Checking ADB...
if not exist "%ADB%" (
    :: Try system ADB
    where adb >nul 2>&1
    if errorlevel 1 (
        echo  [WARN] ADB not found in tools\ or PATH
        echo         Download Android platform-tools and place adb.exe in:
        echo         %ROOT%tools\
        echo         https://developer.android.com/tools/releases/platform-tools
        set ERRORS=1
    ) else (
        for /f "tokens=*" %%a in ('where adb') do set ADB=%%a
        echo  [OK]   ADB found: %ADB%
    )
) else (
    echo  [OK]   ADB found: %ADB%
)

:: ── Check phone connection ───────────────────────────────────
echo.
echo [5/6] Checking phone connection...
echo       Make sure phone is connected via USB with USB Debugging ON
"%ADB%" devices 2>nul | findstr /i "device" | findstr /v "List" >nul
if errorlevel 1 (
    echo  [WARN] No phone detected via ADB
    echo         Connect phone via USB, enable USB Debugging
    echo         Then run INSTALL.bat again to install APK
    set ERRORS=1
    goto :skip_apk
)
echo  [OK]   Phone detected

:: ── Install APK ─────────────────────────────────────────────
echo.
echo [6/6] Installing APK on phone...
if not exist "%APK%" (
    echo  [FAIL] APK not found: %APK%
    set ERRORS=1
    goto :skip_apk
)
"%ADB%" install -r "%APK%" >nul 2>&1
if errorlevel 1 (
    echo  [WARN] APK install failed — may already be installed (OK)
) else (
    echo  [OK]   APK installed on phone
)

:: Enable AccessibilityService
echo        Enabling AccessibilityService on phone...
"%ADB%" shell settings put secure enabled_accessibility_services com.forensic.vpncorrelator/com.forensic.vpncorrelator.ForensicAccessibilityService >nul 2>&1
echo  [OK]   AccessibilityService enabled

:skip_apk

:: ── Summary ──────────────────────────────────────────────────
echo.
echo  ══════════════════════════════════════════════════════
if %ERRORS%==0 (
    echo  SETUP COMPLETE — Run START.bat to begin monitoring
) else (
    echo  SETUP DONE WITH WARNINGS — Fix issues above then
    echo  run INSTALL.bat again, then run START.bat
)
echo  ══════════════════════════════════════════════════════
echo.

:ask_continue
echo  Press any key to exit...
pause >nul
