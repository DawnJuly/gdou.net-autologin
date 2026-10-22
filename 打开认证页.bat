@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 正在寻找校园网认证页……
python "%~dp0gdou_login.py" --open-portal
echo.
pause
