# 广东海洋大学校园网（GDOU.NET）开机自动登录 —— 安装脚本
# 用法：
#   .\install.ps1              装到「当前用户启动项」，登录 Windows 后自动后台运行，不需要管理员
#   .\install.ps1 -Task        注册为计划任务（需要管理员权限）
#   .\install.ps1 -Task -Resilient  计划任务每 5 分钟自检一次（睡眠唤醒/进程被杀也能自愈）
#   .\install.ps1 -Task -Highest  计划任务以最高权限运行（这样才能自动连 Wi-Fi）
#   .\install.ps1 -Uninstall   卸载

param(
    [switch]$Task,
    [switch]$Highest,
    [switch]$Resilient,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

$Here     = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script   = Join-Path $Here 'gdou_login.py'
$TaskName = 'GDOU-AutoLogin'
$Startup  = [Environment]::GetFolderPath('Startup')
$StartupVbs = Join-Path $Startup 'GDOU-AutoLogin.vbs'

function Find-PythonW {
    $cmd = Get-Command 'python.exe' -ErrorAction SilentlyContinue
    if ($cmd) {
        $w = Join-Path (Split-Path $cmd.Source -Parent) 'pythonw.exe'
        if (Test-Path $w) { return $w }
    }
    $patterns = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python*\pythonw.exe'),
        'C:\Python*\pythonw.exe',
        (Join-Path $env:ProgramFiles 'Python*\pythonw.exe')
    )
    foreach ($p in $patterns) {
        $hit = Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

# ---------------- 卸载 ----------------
if ($Uninstall) {
    if (Test-Path $StartupVbs) {
        Remove-Item $StartupVbs -Force
        Write-Host "已删除启动项：$StartupVbs"
    }
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "已删除计划任务：$TaskName"
    }
    Write-Host '卸载完成（后台进程会在下次重启后消失，也可在任务管理器结束 pythonw.exe）。'
    return
}

# ---------------- 安装 ----------------
if (-not (Test-Path $Script)) {
    throw "找不到 gdou_login.py。请把 install.ps1 和它放在同一个文件夹里。"
}

$py = Find-PythonW
if (-not $py) {
    throw '找不到 pythonw.exe。请先安装 Python 3（安装时勾选 "Add python.exe to PATH"）。'
}
Write-Host "使用解释器：$py"

# 语法自检，避免把坏文件装进启动项
$pyExe = Join-Path (Split-Path $py -Parent) 'python.exe'
if (Test-Path $pyExe) {
    & $pyExe -m py_compile $Script
    if ($LASTEXITCODE -ne 0) { throw 'gdou_login.py 语法检查未通过' }
    Write-Host '语法检查通过。'
}

if ($Task) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }

    $action  = New-ScheduledTaskAction -Execute $py -Argument ('"' + $Script + '" --daemon --no-echo')
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    try { $trigger.Delay = 'PT20S' } catch { }

    # 启动文件夹/登录触发器只在"登录"时跑一次，睡眠唤醒不会触发。
    # 这里给计划任务挂一个"每 5 分钟重复"的触发器：
    # 程序自己带单实例锁，重复触发会立刻退出，无副作用；
    # 但能覆盖 睡眠唤醒 / 进程被杀 / 网络切换 这些场景。
    if ($Resilient) {
        $rep = (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                    -RepetitionInterval (New-TimeSpan -Minutes 5) `
                    -RepetitionDuration (New-TimeSpan -Days 3650)).Repetition
        $trigger.Repetition = $rep
        Write-Host '已启用 Resilient：每 5 分钟自检一次，睡眠唤醒后也会自动连。'
    }
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries -StartWhenAvailable `
                    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) `
                    -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)

    $runLevel = if ($Highest) { 'Highest' } else { 'Limited' }
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -RunLevel $runLevel -Force `
        -Description '广东海洋大学校园网自动登录（GDOU.NET / 深澜 srun）' | Out-Null

    if (Test-Path $StartupVbs) { Remove-Item $StartupVbs -Force }
    Write-Host "已注册计划任务：$TaskName（登录 Windows 后 20 秒自动启动）" -ForegroundColor Green
}
else {
    # 不需要管理员：启动文件夹里放一个隐藏运行的小脚本
    $runLine = '"' + $py + ' ""' + $Script + '"" --daemon --no-echo"'
    $content = @"
' 广东海洋大学校园网自动登录（由 install.ps1 生成，删除本文件即取消自启）
Set sh = CreateObject("WScript.Shell")
sh.Run $runLine, 0, False
"@
    Set-Content -Path $StartupVbs -Value $content -Encoding Default
    Write-Host "已写入启动项：$StartupVbs" -ForegroundColor Green
    Write-Host '下次登录 Windows 时会自动在后台连接并认证校园网。'
}

Write-Host ''
Write-Host '手动试一次： python "' -NoNewline; Write-Host $Script -NoNewline; Write-Host '" --once'
Write-Host '网络诊断：   python "' -NoNewline; Write-Host $Script -NoNewline; Write-Host '" --probe'
Write-Host '日志文件：   ' -NoNewline; Write-Host (Join-Path $Here 'logs\gdou_login.log')
