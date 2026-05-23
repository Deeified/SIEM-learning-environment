@echo off
cd /d "%~dp0"
echo.
echo  HomeSIEM v3 - SOC Training Platform
echo  =====================================
echo  Starting server...
echo.
start "" cmd /c "timeout /t 3 >nul && start http://localhost:5001"
python siem.py
pause
