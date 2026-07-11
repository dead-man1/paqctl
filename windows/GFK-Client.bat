@echo off
:: GFW-knocker Client Manager Launcher
:: Double-click to run

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ===============================================
echo   GFW-KNOCKER CLIENT MANAGER (v1.1.0)
echo ===============================================
echo.
echo   Launching GFW-Knocker Interactive Menu...
echo   From the menu, you can connect, configure settings,
echo   enable Windows Turbo Mode, or set up Auto-Reconnect.
echo.
echo   Once connected, configure your browser:
echo   SOCKS Host: 127.0.0.1    Port: 14000 (or custom SOCKS port)
echo   Select SOCKS v5 and check "Proxy DNS when using SOCKS v5"
echo.
echo ===============================================
echo.

:: Run the PowerShell script with gfk backend
powershell -ExecutionPolicy Bypass -NoExit -File "%~dp0paqet-client.ps1" -Backend gfk
