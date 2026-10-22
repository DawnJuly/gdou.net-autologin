#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广东海洋大学校园网（GDOU.NET / 海大校园网）开机自动认证

协议：深澜 srun（srun_portal）
依赖：仅 Python 3.8+ 标准库，无需 pip install 任何东西
用法：
    python gdou_login.py                 # 守护模式：断网就自动登录（开机自启用这个）
    python gdou_login.py --once          # 只尝试登录一次
    python gdou_login.py --probe         # 诊断：打印本机 IP/网关/认证服务器探测结果
    python gdou_login.py --status        # 检查当前是否已联网
    python gdou_login.py --wifi          # 先尝试连接配置里的 Wi-Fi 再登录
"""

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ----------------------------------------------------------------------------
# 常量
# ----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_PATH = os.path.join(LOG_DIR, "gdou_login.log")

# 深澜自定义 base64 字母表
ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
# info 字段前缀，深澜 2020 之后的后端用 SRBX1
INFO_PREFIX = "{SRBX1}"
ENC_VER = "srun_bx1"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# 很多校园网只对"像浏览器的请求"才吐认证页，对 Accept:*/* 的请求直接回一个空 <html></html>。
# 所以探测阶段必须带浏览器请求头，否则永远找不到认证页。
BROWSER_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
              "image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Upgrade-Insecure-Requests": "1",
}

# 用来判断"是否真的能上网"的探测地址（返回 204 表示直通，无需认证）
PROBE_URLS = [
    "http://connect.rom.miui.com/generate_204",
    "http://www.gstatic.com/generate_204",
]

# 未认证时用来"钓"出认证页的地址。msftconnecttest 就是 Windows 自己判定
# "需要打开浏览器登录"时用的那个，命中率最高。
CAPTIVE_DETECT_URLS = [
    "http://www.msftconnecttest.com/redirect",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://captive.apple.com/hotspot-detect.html",
    "http://connect.rom.miui.com/generate_204",
    "http://www.gstatic.com/generate_204",
    "http://www.baidu.com/",
]

# 响应里出现这些词，基本就是认证页
PORTAL_URL_HINT = re.compile(r"srun_portal|/cgi-bin/get_challenge|eportal|ac_id=|"
                             r"wlan_user_ip|portal|login", re.I)

# 没检测到认证页面时，按顺序尝试这些深澜常见地址
DEFAULT_PORTAL_CANDIDATES = ["10.0.0.55", "10.0.1.1"]

NO_WINDOW = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW


# ----------------------------------------------------------------------------
# 日志
# ----------------------------------------------------------------------------
class Log:
    def __init__(self, path=None, echo=True):
        self.path = path
        self.echo = echo
        if path:
            # 目录建不出来（只读安装位置/权限不足）不应该让程序直接崩掉
            try:
                d = os.path.dirname(path)
                if d:
                    os.makedirs(d, exist_ok=True)
            except Exception:
                pass

    def __call__(self, msg, level="INFO"):
        line = "%s [%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), level, msg)
        if self.echo:
            try:
                print(line, flush=True)
            except Exception:
                pass
        if self.path:
            try:
                self._rotate()
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass

    def _rotate(self, limit=2 * 1024 * 1024):
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) > limit:
                bak = self.path + ".1"
                if os.path.exists(bak):
                    os.remove(bak)
                os.replace(self.path, bak)
        except Exception:
            pass


# ----------------------------------------------------------------------------
# 深澜 srun 加密算法（与官网 JS 的 xEncode / base64 完全等价）
# ----------------------------------------------------------------------------
def _ordat(msg, idx):
    return ord(msg[idx]) if len(msg) > idx else 0


def _sencode(msg, key):
    """把字符串按 4 字节切分成 32 位字（小端）"""
    out = []
    for i in range(0, len(msg), 4):
        out.append(_ordat(msg, i)
                   | _ordat(msg, i + 1) << 8
                   | _ordat(msg, i + 2) << 16
                   | _ordat(msg, i + 3) << 24)
    if key:
        out.append(len(msg))
    return out


def _lencode(msg, key):
    """32 位字还原成字符串（小端，逐字节）"""
    n = len(msg)
    ll = (n - 1) << 2
    if key:
        m = msg[n - 1]
        if m < ll - 3 or m > ll:
            return None
        ll = m
    buf = []
    for w in msg:
        buf.append(chr(w & 0xFF))
        buf.append(chr((w >> 8) & 0xFF))
        buf.append(chr((w >> 16) & 0xFF))
        buf.append(chr((w >> 24) & 0xFF))
    text = "".join(buf)
    return text[:ll] if key else text


def xencode(msg, key):
    """深澜的 XXTEA 变种加密"""
    if not msg:
        return ""
    pwd = _sencode(msg, True)
    pwdk = _sencode(key, False)
    if len(pwdk) < 4:
        pwdk += [0] * (4 - len(pwdk))

    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0  # 0x9E3779B9
    m = 0
    e = 0
    p = 0
    d = 0
    q = math.floor(6 + 52 / (n + 1))
    while q > 0:
        d = (d + c) & 0xFFFFFFFF
        e = (d >> 2) & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = (z >> 5) ^ (y << 2)
            m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
            m += pwdk[(p & 3) ^ e] ^ z
            pwd[p] = (pwd[p] + m) & 0xFFFFFFFF
            z = pwd[p]
            p += 1
        y = pwd[0]
        m = (z >> 5) ^ (y << 2)
        m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
        m += pwdk[(p & 3) ^ e] ^ z
        pwd[n] = (pwd[n] + m) & 0xFFFFFFFF
        z = pwd[n]
        q -= 1
    return _lencode(pwd, False)


def srun_base64(s):
    """深澜自定义字母表的 base64"""
    if not s:
        return s
    pad = "="
    out = []
    imax = len(s) - len(s) % 3
    for i in range(0, imax, 3):
        b10 = (ord(s[i]) << 16) | (ord(s[i + 1]) << 8) | ord(s[i + 2])
        out.append(ALPHA[b10 >> 18])
        out.append(ALPHA[(b10 >> 12) & 63])
        out.append(ALPHA[(b10 >> 6) & 63])
        out.append(ALPHA[b10 & 63])
    rest = len(s) - imax
    if rest == 1:
        b10 = ord(s[imax]) << 16
        out.append(ALPHA[b10 >> 18] + ALPHA[(b10 >> 12) & 63] + pad + pad)
    elif rest == 2:
        b10 = (ord(s[imax]) << 16) | (ord(s[imax + 1]) << 8)
        out.append(ALPHA[b10 >> 18] + ALPHA[(b10 >> 12) & 63]
                   + ALPHA[(b10 >> 6) & 63] + pad)
    return "".join(out)


def md5_hex(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def sha1_hex(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def hmac_md5_hex(key, text):
    return hmac.new(key.encode("utf-8"), text.encode("utf-8"), hashlib.md5).hexdigest()


def build_info(username, password, ip, acid, token):
    """构造 info 字段：{SRBX1} + base64(xencode(json))"""
    plain = json.dumps({
        "username": username,
        "password": password,
        "ip": ip,
        "acid": acid,
        "enc_ver": ENC_VER,
    }, separators=(",", ":"), ensure_ascii=False)
    # 深澜的 xencode 只处理 latin-1 范围字符，非 ASCII 会报错
    plain.encode("latin-1")
    return INFO_PREFIX + srun_base64(xencode(plain, token))


def build_chksum(token, username, hmd5, ac_id, ip, n, typ, info):
    chk = token + username
    chk += token + hmd5
    chk += token + ac_id
    chk += token + ip
    chk += token + n
    chk += token + typ
    chk += token + info
    return sha1_hex(chk)


# ----------------------------------------------------------------------------
# 网络工具
# ----------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # 禁止自动跟随，方便拿 Location 判断是否被劫持


def http_get(url, timeout=6, follow=False, headers=None):
    """返回 (status, headers_dict, body_bytes, final_url)，3xx 也当正常结果返回"""
    hdrs = dict(BROWSER_HEADERS)
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    handlers = [] if follow else [_NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read(), resp.geturl()
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read()
        except Exception:
            body = b""
        return exc.code, dict(exc.headers or {}), body, url


def decode(body):
    if isinstance(body, bytes):
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                return body.decode(enc)
            except Exception:
                continue
        return body.decode("utf-8", "replace")
    return body


def local_ip_for(host, port=80):
    """本机在通往 host 的那块网卡上的 IP"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, port))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def _decode_console(raw):
    """系统命令输出可能是 UTF-8（netsh）也可能是 GBK（route），逐个试，绝不让它抛异常"""
    if not raw:
        return ""
    for enc in ("utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "replace")


def _run_text(cmd, timeout=20):
    """按字节取命令行输出再解码。用 text=True 会按 locale 解码，
    遇到编码不匹配会在读取线程里抛 UnicodeDecodeError 并把进程卡死。"""
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout, creationflags=NO_WINDOW)
    except Exception:
        return ""
    return _decode_console(proc.stdout)


def default_gateway():
    """默认网关（第一条 0.0.0.0 路由）"""
    for line in _run_text(["route", "print", "-4"]).splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            return parts[2]
    return None


def internet_ok(timeout=4):
    """能否直连外网（返回 True 说明已认证成功）"""
    for url in PROBE_URLS:
        try:
            status, _hdrs, _body, _final = http_get(url, timeout=timeout, follow=False)
            if status in (200, 204):
                return True
        except Exception:
            continue
    return False


# ----------------------------------------------------------------------------
# 认证服务器 / Wi-Fi
# ----------------------------------------------------------------------------
def _host_of(url):
    parts = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    return parts.netloc or ""


def _looks_blank(text):
    """校园网 AC 对"不像浏览器"的请求经常只回一个空壳：<html></html>"""
    t = re.sub(r"\s+", "", (text or "").lower())
    return t in ("", "<html></html>", "<html><body></body></html>", "<html/>",
                 "<html><head></head><body></body></html>", "<html><body></body></html>")


def _dns_hijack_ip():
    """认证网关上常见做法：任何域名都解析到同一个 IP，那个 IP 通常就是认证服务器"""
    for host in ("zz9f3a-portal-detect.invalid", "no-such-host-8c7f1.example.com"):
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            continue
        if ip and not ip.startswith(("127.", "0.")):
            return ip
    return None


def detect_interception(log=None):
    """未认证时"钓"出真实的认证页地址。

    返回候选列表 [(host, ac_id, page_url)]；同时记录 _last_portal_page 供 --open-portal 使用。
    """
    global _last_portal_page
    hits = []
    saw_blank = False

    for url in CAPTIVE_DETECT_URLS:
        try:
            status, hdrs, body, _final = http_get(url, timeout=5)
        except Exception:
            continue
        text = decode(body)
        loc = hdrs.get("Location") or hdrs.get("location") or ""

        cands = [loc] if loc else []
        cands += re.findall(r"https?://[^\s\"'<>]+", text)

        matched = None
        for cand in cands:
            cand = cand.strip().strip("\"'")
            if not cand.lower().startswith("http"):
                continue
            if PORTAL_URL_HINT.search(cand):
                matched = cand
                break

        if matched:
            host = _host_of(matched)
            ac = re.search(r"ac_id=(\d+)", matched)
            if host and not any(h[0] == host for h in hits):
                hits.append((host, ac.group(1) if ac else None, matched))
        elif status in (200, 204) and _looks_blank(text):
            saw_blank = True

    if not hits and saw_blank:
        # 所有请求都只拿到空壳：试试 DNS 劫持，把解析到的 IP 当认证服务器
        ip = _dns_hijack_ip()
        if ip:
            hits.append((ip, None, "http://%s/" % ip))

    if hits:
        _last_portal_page = hits[0][2]
    return hits


def probe_portal(host, username, ip, timeout=4):
    """确认 host 是不是深澜认证服务器：get_challenge 能返回 challenge 就是"""
    url = "http://%s/cgi-bin/get_challenge?callback=cb&username=%s&ip=%s&_=%d" % (
        host, urllib.parse.quote(username), urllib.parse.quote(ip or ""), int(time.time() * 1000))
    try:
        status, _h, body, _f = http_get(url, timeout=timeout)
    except Exception as exc:
        return False, "连接失败：%s" % exc
    text = decode(body)
    m = re.search(r'"challenge"\s*:\s*"([^"]*)"', text)
    if m:
        return True, text
    return False, text.strip()[:200]


def find_portal(cfg, log):
    """返回 (host, ac_id)"""
    if cfg.get("portal"):
        host = _host_of(cfg["portal"])
        ip = local_ip_for(host.split(":")[0])
        ok, _ = probe_portal(host, cfg["username"], ip)
        if ok:
            log("使用配置里的认证服务器：%s" % host)
            return host, cfg.get("ac_id") or None
        log("配置的认证服务器 %s 无响应，改为自动探测" % host, "WARN")

    for host, ac, page in detect_interception(log):
        ip = local_ip_for(host.split(":")[0])
        ok, detail = probe_portal(host, cfg["username"], ip)
        if ok:
            log("从认证页探测到服务器：%s（ac_id=%s）" % (host, ac))
            return host, ac
        log("候选 %s 不是深澜接口：%s" % (host, detail[:80]), "WARN")

    candidates = []
    gw = default_gateway()
    if gw:
        candidates.append(gw)
    candidates += cfg.get("portal_candidates") or DEFAULT_PORTAL_CANDIDATES

    seen = set()
    for cand in candidates:
        host = _host_of(cand)
        if not host or host in seen:
            continue
        seen.add(host)
        ip = local_ip_for(host.split(":")[0])
        ok, _ = probe_portal(host, cfg["username"], ip)
        if ok:
            log("探测到认证服务器：%s" % host)
            return host, None
    return None, None


def current_ssid():
    """当前连着的 Wi-Fi 名字（读不到就返回 None）"""
    out = _run_text(["netsh", "wlan", "show", "interfaces"], timeout=10)
    m = re.search(r"^\s+SSID\s+:\s*(.+)$", out, re.M)
    return m.group(1).strip() if m else None


def wifi_connect(ssid, log):
    """尝试连接 Wi-Fi（需要系统里已保存该 SSID 的配置文件）"""
    if not ssid:
        return False
    try:
        profiles = _run_text(["netsh", "wlan", "show", "profiles"], timeout=20)
        if not profiles:
            log("读取 Wi-Fi 配置列表失败，跳过自动连接", "WARN")
            return False
        if ssid not in profiles:
            log("系统里还没有 Wi-Fi「%s」的配置，跳过自动连接"
                "（在 Windows 里手动连一次并勾选自动连接即可）" % ssid, "WARN")
            return False

        out = _run_text(["netsh", "wlan", "connect", "name=" + ssid, "ssid=" + ssid], timeout=25)
        if "已成功" in out or "successfully" in out.lower():
            log("已发起 Wi-Fi 连接：%s" % ssid)
            time.sleep(5)
            return True
        if "需要提升" in out or "requires elevation" in out.lower():
            log("自动连 Wi-Fi 需要管理员权限；建议让 Windows 自己连（勾选「自动连接」）", "WARN")
            return False
        log("连接 Wi-Fi 失败：%s" % out.strip()[:160], "WARN")
    except Exception as exc:
        log("连接 Wi-Fi 出错：%s" % exc, "WARN")
    return False


# ----------------------------------------------------------------------------
# 登录
# ----------------------------------------------------------------------------
_token = ""
_last_portal_page = None   # 最近一次探测到的认证页地址，供 --open-portal 使用


def login_once(cfg, log, verbose=False):
    """执行一次完整登录，成功返回 True"""
    global _token

    username = cfg["username"]
    if cfg.get("domain"):
        domain = cfg["domain"] if cfg["domain"].startswith("@") else "@" + cfg["domain"]
        if not username.endswith(domain):
            username = username + domain
    password = cfg["password"]

    host, detected_ac = find_portal(cfg, log)
    if not host:
        ssid = current_ssid()
        log("当前 Wi-Fi：%s" % (ssid or "（读不到/没连 Wi-Fi）"), "ERROR")
        if ssid and cfg.get("wifi_ssid") and ssid != cfg["wifi_ssid"]:
            log("注意：当前连的不是「%s」，校园网认证只在校园 Wi-Fi 下才有意义"
                % cfg["wifi_ssid"], "ERROR")
        log("没能找到校园网认证服务器。可能原因：没连上校园网 / 已经在线 / 认证页改版", "ERROR")
        if _last_portal_page:
            log("但探测到了认证页：%s ，可以手动打开它（或双击 打开认证页.bat）"
                % _last_portal_page, "ERROR")
        else:
            log("可以双击 打开认证页.bat 让浏览器直接跳到认证页；"
                "也可以把认证服务器地址填进 config.json 的 portal 字段", "ERROR")
        return False

    base = "http://%s" % host
    ip = local_ip_for(host.split(":")[0]) or ""

    ac_ids = []
    for cand in [cfg.get("ac_id"), detected_ac] + list(cfg.get("ac_id_candidates") or ["1"]):
        if cand and str(cand) not in ac_ids:
            ac_ids.append(str(cand))
    if not ac_ids:
        ac_ids = ["1"]

    n = str(cfg.get("n") or "200")
    typ = str(cfg.get("type") or "1")
    os_name = cfg.get("os") or "windows+10"
    dev_name = cfg.get("name") or "windows"

    for ac_id in ac_ids:
        # 1) 取 token
        ts = int(time.time() * 1000)
        challenge_url = ("%s/cgi-bin/get_challenge?callback=cb%d&username=%s&ip=%s&_=%d"
                         % (base, ts, urllib.parse.quote(username),
                            urllib.parse.quote(ip), ts))
        try:
            status, _h, body, _f = http_get(challenge_url, timeout=6)
        except Exception as exc:
            log("获取 token 失败：%s" % exc, "ERROR")
            return False
        text = decode(body)
        m = re.search(r'"challenge"\s*:\s*"([^"]*)"', text)
        if not m:
            log("认证服务器返回内容异常：%s" % text.strip()[:200], "ERROR")
            return False
        _token = m.group(1)

        # token 里带了真实 client_ip 时以它为准（多网卡/路由时更准）
        ipm = re.search(r'"client_ip"\s*:\s*"([^"]*)"', text)
        if ipm and ipm.group(1):
            ip = ipm.group(1)

        if verbose:
            log("token=%s  ip=%s  ac_id=%s" % (_token[:8] + "...", ip, ac_id))

        # 2) 算三个加密字段
        info = build_info(username, password, ip, ac_id, _token)
        hmd5 = hmac_md5_hex(_token, password)
        chksum = build_chksum(_token, username, hmd5, ac_id, ip, n, typ, info)

        # 3) 发起登录
        params = {
            "callback": "cb%d" % ts,
            "action": "login",
            "username": username,
            "password": "{MD5}" + hmd5,
            "ac_id": ac_id,
            "ip": ip,
            "chksum": chksum,
            "info": info,
            "n": n,
            "type": typ,
            "os": os_name,
            "name": dev_name,
            "double_stack": "0",
            "_": str(ts),
        }
        login_url = "%s/cgi-bin/srun_portal?%s" % (base, urllib.parse.urlencode(params))
        try:
            status, _h, body, _f = http_get(
                login_url, timeout=8, headers={"Referer": "%s/srun_portal_pc?ac_id=%s" % (base, ac_id)})
        except Exception as exc:
            log("登录请求失败：%s" % exc, "ERROR")
            continue

        text = decode(body)
        result = _parse_jsonp(text)
        if verbose:
            log("服务器返回：%s" % text.strip()[:300])
        if _login_ok(result):
            log("认证接口返回成功（ac_id=%s，账号 %s）" % (ac_id, username))
            time.sleep(1)
            if internet_ok():
                log("已联网 ✓")
            else:
                log("认证接口说成功，但仍打不开外网：可能是欠费/被限速/需要先在网页里选运营商套餐", "WARN")
            return True

        reason = ""
        if isinstance(result, dict):
            reason = result.get("error_msg") or result.get("error") or result.get("suc_msg") or ""
        log("登录被拒绝（ac_id=%s）：%s" % (ac_id, reason or text.strip()[:160]), "WARN")
        if "ip" in str(reason).lower() or "acid" in str(reason).lower() or "ac_id" in str(reason).lower():
            break  # 换 ac_id 也没用

    return False


def _parse_jsonp(text):
    text = (text or "").strip()
    if text.startswith("{"):
        try:
            return json.loads(text)
        except Exception:
            pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except Exception:
            pass
    return None


def _login_ok(result):
    if not isinstance(result, dict):
        return False
    # 这个 IP 已经在线时，服务器会直接回 ecode:0 + suc_msg=ip_already_online_error，
    # 那并不是真的完成了一次认证，不能算成功（portal 自己的 JS 也是当提示处理的）。
    if str(result.get("suc_msg", "")).lower() == "ip_already_online_error":
        return False
    if str(result.get("ecode")) == "0":
        return True
    if str(result.get("error", "")).lower() in ("ok", "success"):
        return True
    return bool(result.get("suc_msg"))


# ----------------------------------------------------------------------------
# 守护模式
# ----------------------------------------------------------------------------
def acquire_single_instance():
    """用本地端口占用做单实例锁，返回 socket 或 None"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 51999))
        s.listen(1)
        return s
    except OSError:
        s.close()
        return None


def run_daemon(cfg, log):
    lock = acquire_single_instance()
    if lock is None:
        log("已有一个实例在运行，退出", "WARN")
        return 0
    log("守护模式启动（检查间隔 %ss）" % cfg.get("check_interval", 60))
    try:
        if cfg.get("wifi_ssid"):
            wifi_connect(cfg["wifi_ssid"], log)
    except Exception as exc:
        log("Wi-Fi 预连接步骤异常：%s（不影响后续认证）" % exc, "WARN")

    fails = 0
    while True:
        try:
            if internet_ok():
                fails = 0
                time.sleep(int(cfg.get("check_interval", 60)))
                continue

            log("检测到未联网，尝试认证……")
            if login_once(cfg, log):
                fails = 0
                time.sleep(int(cfg.get("check_interval", 60)))
            else:
                fails += 1
                wait = min(int(cfg.get("retry_interval", 15)) * fails, 300)
                log("认证未成功，%d 秒后重试（第 %d 次）" % (wait, fails), "WARN")
                time.sleep(wait)
        except KeyboardInterrupt:
            log("收到中断，退出")
            return 0
        except Exception as exc:
            log("守护循环异常：%r，10 秒后继续" % (exc,), "ERROR")
            time.sleep(10)


# ----------------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------------
def load_config():
    if not os.path.exists(CONFIG_PATH):
        raise SystemExit("找不到配置文件：%s" % CONFIG_PATH)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if not cfg.get("username") or not cfg.get("password"):
        raise SystemExit("config.json 里的 username / password 不能为空")
    return cfg


def main(argv=None):
    ap = argparse.ArgumentParser(description="广东海洋大学校园网 srun 自动登录")
    ap.add_argument("--daemon", action="store_true", help="守护模式（默认行为，供启动项显式指定）")
    ap.add_argument("--once", action="store_true", help="只尝试登录一次后退出")
    ap.add_argument("--probe", action="store_true", help="诊断网络与认证服务器")
    ap.add_argument("--status", action="store_true", help="只检查当前是否已联网")
    ap.add_argument("--wifi", action="store_true", help="先尝试连接配置里的 Wi-Fi")
    ap.add_argument("--open-portal", action="store_true",
                    help="找出认证页并用浏览器打开（Windows 那个「打开浏览器」不灵时用这个）")
    ap.add_argument("--no-echo", action="store_true", help="不往控制台打印（只在日志里记录）")
    args = ap.parse_args(argv)

    log = Log(LOG_PATH, echo=not args.no_echo)

    if args.status:
        ok = internet_ok()
        print("已联网（无需认证）" if ok else "未联网（需要认证）")
        return 0 if ok else 1

    cfg = load_config()

    if args.open_portal:
        hits = detect_interception(log)
        target = _last_portal_page
        if not target:
            gw = default_gateway()
            if gw:
                target = "http://%s/" % gw
        if not target:
            print("没找到认证页。请确认已经连上校园网 Wi-Fi（不是手机热点）。")
            return 1
        print("认证页地址：%s" % target)
        for host, ac, page in hits:
            print("  候选服务器：%s  ac_id=%s" % (host, ac))
        try:
            os.startfile(target)   # 用系统默认浏览器打开
        except Exception as exc:
            print("自动打开失败（%s），请手动复制上面的地址到浏览器。" % exc)
        return 0

    if args.probe:
        log("===== 诊断开始 =====")
        log("当前 Wi-Fi：%s" % (current_ssid() or "（读不到/没连 Wi-Fi）"))
        gw = default_gateway()
        log("默认网关：%s" % gw)
        log("能直连外网：%s" % internet_ok())
        hits = detect_interception(log)
        if hits:
            for host, ac, page in hits:
                log("认证页线索：host=%s ac_id=%s page=%s" % (host, ac, page))
        else:
            log("劫持探测：没有拿到认证页线索（可能已在线，或网络只回空页面）")
        for cand in [gw] + (cfg.get("portal_candidates") or DEFAULT_PORTAL_CANDIDATES):
            if not cand:
                continue
            h = _host_of(cand)
            ip = local_ip_for(h.split(":")[0])
            ok, detail = probe_portal(h, cfg["username"], ip)
            log("  探测 %-16s -> %s  %s" % (h, "深澜认证接口" if ok else "不是/无响应",
                                            "" if ok else detail[:100]))
        log("===== 诊断结束 =====")
        return 0

    if args.wifi and cfg.get("wifi_ssid"):
        try:
            wifi_connect(cfg["wifi_ssid"], log)
        except Exception as exc:
            log("Wi-Fi 预连接异常：%s" % exc, "WARN")

    if args.once:
        if internet_ok():
            log("当前已联网，无需认证")
            return 0
        return 0 if login_once(cfg, log, verbose=True) else 1

    return run_daemon(cfg, log)


def _fatal_log(text):
    """pythonw 没有控制台，把致命错误也写进日志，免得静默失败"""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write("%s [FATAL] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), text))
    except Exception:
        pass


if __name__ == "__main__":
    try:
        _code = main()
    except SystemExit as _exc:
        if _exc.code not in (0, None):
            _fatal_log("启动失败：%s" % (_exc.code,))
        raise
    except BaseException:
        import traceback
        _fatal_log("未捕获异常：\n" + traceback.format_exc())
        raise
    sys.exit(_code)
