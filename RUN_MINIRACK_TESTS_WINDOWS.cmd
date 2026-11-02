@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title MiniRack - Software Regression Tests
echo ==================================================
echo MiniRack - V2 entitlement + integrated source checks
echo This does NOT flash ESP32 or change Pi settings.
echo ==================================================
where py >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python launcher not found. Install Python 3.10+.
  pause
  exit /b 1
)
py -3 -m unittest discover -s test -p "test_v2*.py" -v
if errorlevel 1 goto :failed
py -3 pi\v2_live_demo.py
if errorlevel 1 goto :failed
echo.
echo TESTS PASSED. Build/upload + hardware + printing remain to be verified locally.
pause
exit /b 0
:failed
echo TESTS FAILED. No firmware was flashed.
pause
exit /b 1
