@echo off
setlocal
cd /d "%~dp0"
echo =================================================
echo Mini Rack V1 - read-only Raspberry Pi gateway check
echo No ESP32 flash, no Pi routing or firewall changes.
echo =================================================
if not exist "pi\gateway_safe_trial.sh" (
  echo ERROR: pi\gateway_safe_trial.sh missing
  pause
  exit /b 1
)
scp "pi\gateway_safe_trial.sh" salem@salem-pi.local:~/gateway_safe_trial.sh
if errorlevel 1 (
  echo Copy failed. Check Wi-Fi and Pi SSH connection.
  pause
  exit /b 1
)
echo.
echo Checking Pi prerequisites, without changing network settings...
ssh salem@salem-pi.local "bash ~/gateway_safe_trial.sh --plan"
if errorlevel 1 (
  echo Preflight did not pass. No settings were changed.
) else (
  echo Preflight command completed. No settings were changed.
)
pause
