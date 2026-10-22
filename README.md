# 海大校园网（GDOU.NET）开机自动登录

一个 **纯 Python 标准库** 的小程序，开机后自动帮你完成广东海洋大学校园网的深澜（srun）认证，不用每次手动打开认证页。

- 协议：深澜 srun（`srun_portal`），海大用的就是这套
- 依赖：Python 3.8+，**不需要 pip 安装任何东西**
- 行为：开机（登录 Windows）后后台静默运行；发现断网就重新认证；睡眠唤醒后自动重连
- 账号密码只存在本地 `config.json` 里，不会发往除学校认证服务器以外的任何地方
- `config.json` 已在 `.gitignore` 里，**不会**被提交到仓库

## 目录

| 文件 | 作用 |
| --- | --- |
| `gdou_login.py` | 主程序 |
| `config.example.json` | 配置模板，复制成 `config.json` 再填自己的账号 |
| `config.json` | 你的账号、密码、认证服务器等配置（不入库） |
| `安装.bat` | 装好开机自启（双击） |
| `立即登录.bat` | 立刻试登录一次（双击，能看到输出） |
| `打开认证页.bat` | 找不到认证入口时，用浏览器直接打开认证页（双击） |
| `诊断.bat` | 打印网络/认证服务器探测结果（出问题时先跑这个） |
| `卸载.bat` | 取消开机自启 |
| `install.ps1` | 安装/卸载脚本本体 |
| `logs/gdou_login.log` | 运行日志 |
| `tests/` | 自动化测试（算法与参考实现比对 + 假服务器联调） |

## 安装

第一步，复制配置模板：

```bat
copy config.example.json config.json
```

然后编辑 `config.json` 填上学号和密码，再双击 **`安装.bat`**。它会：

1. 找到 `pythonw.exe`（无窗口解释器）
2. 对 `gdou_login.py` 做语法检查
3. 在 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 放一个 `GDOU-AutoLogin.vbs`，登录 Windows 时静默启动

不需要管理员权限。想要更早启动（开机即运行、开机前不登录），用管理员 PowerShell 执行：

```powershell
.\install.ps1 -Task     # 注册计划任务，登录后 20 秒启动
```

### 关于"自动连 Wi-Fi"

Windows 自己就会连已保存过的 Wi-Fi，所以脚本默认只做**认证**这一步最稳。
`config.json` 里的 `wifi_ssid` 是"顺手帮你连一下"，但 `netsh wlan connect` 需要管理员权限，
普通启动项里多半会被拒绝（日志会写一行 WARN，不影响认证）。真要它自己连：

1. 先在 Windows 里手动连一次校园网并勾选"自动连接"（这样配置就存下来了）；
2. 用管理员身份执行 `.\install.ps1 -Task -Highest`，让计划任务带最高权限运行。

## 先手动验证一次

连上校园网 Wi-Fi（`GDOU.NET` / `海大校园网`），双击 **`立即登录.bat`**，或：

```bat
python gdou_login.py --once --wifi
```

看到 `已联网 ✓` 就成功了。之后再重启电脑验证自启即可。

## 如果失败了

先跑 **`诊断.bat`**，并把 `logs\gdou_login.log` 一起发我。常见情况对应改 `config.json`：

| 现象 | 原因 | 怎么改 |
| --- | --- | --- |
| 日志出现 `E2901 ... ldap_bind error` | 服务器拿我们的账号密码去 LDAP 验证时被拒——**账号或密码不对**（海大的上网密码可能和教务系统密码不是同一个） | 用浏览器登一次认证页确认密码，把正确的填回 `config.json` |
| Windows 弹「需要打开浏览器登录」但点了没反应 | 系统那个入口经常失灵，或默认浏览器被改坏 | 双击 `打开认证页.bat`，手动打开认证页登一次；登过一次后本程序才能接管 |
| 诊断里所有地址都"不是/无响应"，日志里有 `<html></html>` | 认证网关只对"像浏览器的请求"返回认证页 | 已修复：探测统一带 `Accept: text/html` 等浏览器头；如果仍不行，把认证页地址填进 `"portal"` |
| 诊断里"当前 Wi-Fi"不是 GDOU.NET | 连的是手机热点/别的网络，校园网认证根本用不上 | 先连上校园网 Wi-Fi；`"wifi_ssid"` 要填真实的 SSID |
| 诊断里所有地址都"不是/无响应" | 认证服务器地址不在默认候选里 | 在浏览器里打开认证页，把地址（如 `10.0.0.55`）填进 `"portal"` |
| 提示 `invalid ac_id` / `ac_id` 相关 | 不同楼栋/校区 `ac_id` 不同 | 打开认证页看 URL 里的 `ac_id=`，填进 `"ac_id"` |
| 账号密码正确但提示密码错 | 需要选运营商 | `"domain"` 填 `telecom` / `cmcc` / `unicom`（对应电信/移动/联通） |
| 提示认证成功但仍不能上网 | 欠费或未选套餐 | 先在网页端登录一次把套餐选好 |

`config.json` 其它字段：

| 字段 | 说明 |
| --- | --- |
| `username` / `password` | 学号和密码 |
| `domain` | 运营商后缀，留空表示校园网内网 |
| `portal` | 认证服务器地址，留空自动探测（推荐） |
| `ac_id` | 认证点编号，留空自动探测 |
| `ac_id_candidates` | 自动探测失败时依次尝试的 `ac_id` |
| `portal_candidates` | 自动探测失败时依次尝试的服务器地址 |
| `wifi_ssid` | 要自动连接的 Wi-Fi 名，留空则不管 Wi-Fi |
| `check_interval` | 在线时多久检查一次（秒） |
| `retry_interval` | 失败后重试间隔的基数（秒，会递增） |

## 命令行

```bat
python gdou_login.py            :: 守护模式（开机自启用的就是这个）
python gdou_login.py --once     :: 只登录一次
python gdou_login.py --probe    :: 诊断
python gdou_login.py --status   :: 当前是否已联网
python gdou_login.py --wifi     :: 先连 Wi-Fi 再登录
python gdou_login.py --open-portal  :: 找出认证页并用浏览器打开
```

## 卸载

双击 **`卸载.bat`**（或 `.\install.ps1 -Uninstall`），然后删掉整个文件夹。

## 测试

```bat
python tests\test_crypto.py   :: 加密算法与参考实现逐位比对
python tests\test_e2e.py      :: 用本地假服务器跑完整登录流程
```

## 说明

- 只做一件事：向学校认证服务器发一次标准登录请求，不修改系统网络配置、不改 DNS、不装驱动。
- 密码在 `config.json` 里是明文。这个文件夹别同步到网盘/公开仓库。想更保险可以右键文件夹 → 属性 → 安全，去掉其他用户的权限。
- 如果学校以后换了认证系统（不再是深澜），这个脚本需要相应调整。
