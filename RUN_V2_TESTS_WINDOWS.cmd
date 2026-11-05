@echo off
cd /d "%~dp0"
echo [Mini Rack V2] Running tests...
py -3 -m unittest discover -s test -p "test_v2*.py" -v
if errorlevel 1 (echo FAILED & pause & exit /b 1)
echo.
echo [Mini Rack V2] Running live lab demo...
py -3 pi\v2_live_demo.py
if errorlevel 1 (echo FAILED & pause & exit /b 1)
echo.
echo Completed (PC/Pi software only, NOT ESP hardware test).
pause
