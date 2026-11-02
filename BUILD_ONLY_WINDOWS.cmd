@echo off
setlocal
cd /d "%~dp0"
if not exist include\wg_secrets.h goto :private
if not exist include\wg_private_local.h goto :private
if not exist include\minirack_ap_defaults.h goto :private
if not exist src\minirack-bridge-secrets.h goto :private
where pio >nul 2>nul
if not errorlevel 1 (
  pio run -e esp32-s3-devkitc-1
  exit /b %errorlevel%
)
py -3 -m platformio run -e esp32-s3-devkitc-1
exit /b %errorlevel%
:private
echo ERROR: Copy the local-only .example.h files and set your private keys and Wi-Fi password first.
exit /b 1
