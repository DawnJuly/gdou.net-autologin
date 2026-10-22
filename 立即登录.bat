@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 正在尝试登录校园网……
python "%~dp0gdou_login.py" --once --wifi
echo.
echo 退出码 %errorlevel%（0=成功 / 1=失败）
pause
