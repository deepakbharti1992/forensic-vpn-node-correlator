@echo off
chcp 65001 >nul
title VNC Forensic — Live Monitor
color 2F

set ROOT=%~dp0
set DESKTOP=%ROOT%desktop
set ADB=%ROOT%tools\adb.exe

:: Fallback to system ADB if tools\adb.exe not present
if not exist "%ADB%" (
    where adb >nul 2>&1
    if not errorlevel 1 (
        for /f "tokens=*" %%a in ('where adb') do set ADB=%%a
    )
)

echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║     FORENSIC VPN NODE CORRELATOR — LIVE MONITOR     ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

:: ── Check phone ──────────────────────────────────────────────
echo  Checking phone connection...
"%ADB%" devices 2>nul | findstr /i "device" | findstr /v "List" >nul
if errorlevel 1 (
    echo  [WARN] No phone detected — connect USB and enable debugging
    echo  Continuing anyway (packet capture will still run)...
    echo.
    goto :start_monitor
)
echo  [OK] Phone detected

:: ── Setup ADB reverse tunnel ──────────────────────────────────
echo  Setting up ADB reverse tunnel (port 5000)...
"%ADB%" reverse tcp:5000 tcp:5000 >nul 2>&1
echo  [OK] Tunnel ready

:: ── Start TcpClientService on phone ──────────────────────────
echo  Starting VNC service on phone...
"%ADB%" shell am force-stop com.forensic.vpncorrelator >nul 2>&1
timeout /t 1 /nobreak >nul
"%ADB%" shell am start-foreground-service -n com.forensic.vpncorrelator/.TcpClientService --es host 127.0.0.1 --ei port 5000 >nul 2>&1
echo  [OK] Phone service started
echo.

:start_monitor
:: ── Choose mode ──────────────────────────────────────────────
echo  Select mode:
echo.
echo    [1] Continuous Monitor  (auto reconnect every 60s)
echo    [2] Single E2E Test     (one reconnect + result)
echo    [3] Live Session        (capture only, manual reconnect)
echo.
set /p MODE="  Enter 1, 2 or 3: "

if "%MODE%"=="1" goto :mode1
if "%MODE%"=="2" goto :mode2
if "%MODE%"=="3" goto :mode3
goto :mode1

:mode1
echo.
echo  Starting Continuous Monitor...
echo  (Ctrl+C to stop)
echo.
set PYTHONIOENCODING=utf-8
python "%DESKTOP%\continuous_monitor.py"
goto :end

:mode2
echo.
echo  Running single E2E test...
echo.
set PYTHONIOENCODING=utf-8
python "%DESKTOP%\test_e2e.py"
goto :end

:mode3
echo.
echo  Starting Live Session (manual reconnects)...
echo  (Ctrl+C to stop)
echo.
set PYTHONIOENCODING=utf-8
python "%DESKTOP%\start_session.py"
goto :end

:end
echo.
echo  Session ended. Output files saved in:
echo  %DESKTOP%\vnc_e2e_output\
echo  %DESKTOP%\vnc_master_log.csv
echo  %DESKTOP%\vnc_master_log.xlsx
echo.
pause
