@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Mini Rack V1 - Build ONLY
set "PVT=%~dp0private"
echo ==================================================
echo Mini Rack V1 - Windows preflight + PlatformIO Build

echo No upload, no flash, no Raspberry Pi changes.
echo ==================================================
if not exist "platformio.ini" (
  echo ERROR: platformio.ini is missing from the project root.
  goto :failed
)
if not exist "%PVT%\wg_secrets.h" (
  echo ERROR: %PVT%\wg_secrets.h not found.
  goto :failed
)
if not exist "%PVT%\minirack-bridge-secrets.h" (
  echo ERROR: %PVT%\minirack-bridge-secrets.h not found.
  goto :failed
)
if not exist "%PVT%\Classifier.h" (
  echo ERROR: %PVT%\Classifier.h not found.
  goto :failed
)
if not exist "src\main.cpp" (
  echo ERROR: src\main.cpp missing.
  goto :failed
)
echo Preflight passed: expected local private headers exist.
echo This is not proof that private header contents are correct.
where pio >nul 2>nul
if not errorlevel 1 (
  echo Building using pio...
  pio run -e esp32-s3-devkitc-1
  goto :done
)
if exist "%USERPROFILE%\.platformio\penv\Scripts\platformio.exe" (
  echo Building using PlatformIO installed with VS Code...
  "%USERPROFILE%\.platformio\penv\Scripts\platformio.exe" run -e esp32-s3-devkitc-1
  goto :done
)
if exist "%USERPROFILE%\.platformio\penv\Scripts\pio.exe" (
  echo Building using PIO installed with VS Code...
  "%USERPROFILE%\.platformio\penv\Scripts\pio.exe" run -e esp32-s3-devkitc-1
  goto :done
)
echo ERROR: PlatformIO CLI not found.
echo Open this folder in VS Code and click PlatformIO: Build.
goto :failed
:done
if errorlevel 1 (
  echo BUILD FAILED: see error messages above. No firmware was uploaded.
  goto :failed
)
echo BUILD SUCCEEDED: firmware was compiled, NOT uploaded or tested on hardware.
pause
exit /b 0
:failed
echo STOPPED. No upload, flash, or Pi settings were changed.
pause
exit /b 1
