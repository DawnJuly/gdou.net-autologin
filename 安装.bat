@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo  安装：广东海洋大学校园网开机自动登录
echo ============================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
echo.
pause
