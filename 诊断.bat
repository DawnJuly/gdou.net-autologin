@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo  诊断：检测本机网络和校园网认证服务器
echo  （请在已连上校园网 Wi-Fi 的情况下运行）
echo ============================================
python "%~dp0gdou_login.py" --probe
echo.
pause
