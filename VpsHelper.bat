@echo off
chcp 65001 >nul
cd /d "%~dp0"

if not exist ".venv\" (
    echo 创建虚拟环境...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

echo 安装依赖...
pip install -r requirements.txt

echo 启动 VpsHelper...
python VpsHelper.py

pause
