@echo off
echo Starting VpsHelper...
cd /d "%~dp0"
set PORT=15018
echo Checking old process on port %PORT%...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":%PORT%" ^| findstr LISTENING') do (
    echo Stopping PID %%p ...
    taskkill /PID %%p /F >nul 2>nul
)
if not exist .venv (
    echo Creating virtual environment...
    python -m venv .venv
)
call .venv\Scripts\activate.bat
pip install -q -r requirements.txt
set TGHELPER_DEV=1
python VpsHelper.py
pause
