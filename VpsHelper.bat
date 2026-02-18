@echo off
setlocal
echo Starting VpsHelper (Go)...
cd /d "%~dp0goapp"

where go >nul 2>nul
if errorlevel 1 (
    echo Go is required. Install Go first: https://go.dev/dl/
    pause
    exit /b 1
)

set PORT=15018
echo Checking old process on port %PORT%...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":%PORT%" ^| findstr LISTENING') do (
    echo Stopping PID %%p ...
    taskkill /PID %%p /F >nul 2>nul
)
set TGHELPER_DEV=1
if "%TZ%"=="" set TZ=Asia/Shanghai
go run .\cmd\server
pause
