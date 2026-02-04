@echo off
:: Paqet Client Launcher
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
echo   PAQET CLIENT (KCP Raw Socket Proxy)
echo ===============================================
echo.
echo   Once connected, configure your browser:
echo.
echo   FIREFOX:
echo     Settings ^> Network Settings ^> Settings
echo     Select "Manual proxy configuration"
echo     SOCKS Host: 127.0.0.1    Port: 1080
echo     Select SOCKS v5
echo     Check "Proxy DNS when using SOCKS v5"
echo.
echo   CHROME (launch with proxy):
echo     chrome.exe --proxy-server="socks5://127.0.0.1:1080"
echo.
echo   To verify: Visit https://ifconfig.me
echo   (Should show your server IP, not your home IP)
echo.
echo   Press Ctrl+C to disconnect
echo ===============================================
echo.

:: Run the PowerShell script with paqet backend
powershell -ExecutionPolicy Bypass -NoExit -File "%~dp0paqet-client.ps1" -Backend paqet
