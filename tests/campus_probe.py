# -*- coding: utf-8 -*-
"""连上校园网后跑一遍，把认证环境的真实情况全打印出来（只读，不做任何登录）。
为了不让超时把整体拖死，所有请求只发一次，结果复用。"""

import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Upgrade-Insecure-Requests": "1",
}
NO_WINDOW = 0x08000000
TIMEOUT = 4


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=30, creationflags=NO_WINDOW)
    raw = p.stdout or b""
    for enc in ("utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode("utf-8", "replace")


def gateway():
    for line in run(["route", "print", "-4"]).splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            return parts[2]
    return None


def local_ip(target="8.8.8.8"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url):
    req = urllib.request.Request(url, headers=HEADERS)
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            return {"status": r.status, "loc": dict(r.headers).get("Location", ""),
                    "body": r.read(), "err": ""}
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return {"status": e.code, "loc": dict(e.headers or {}).get("Location", ""),
                "body": body, "err": ""}
    except Exception as e:
        return {"status": None, "loc": "", "body": b"", "err": "%s: %s" % (type(e).__name__, e)}


def text_of(b):
    if isinstance(b, bytes):
        for enc in ("utf-8", "gbk"):
            try:
                return b.decode(enc)
            except Exception:
                pass
        return b.decode("utf-8", "replace")
    return b


def main():
    gw = gateway()
    ip = local_ip()

    print("=" * 70)
    print("本机 IP : %s" % ip)
    print("默认网关: %s" % gw)
    for line in run(["ipconfig"]).splitlines():
        if re.search(r"IPv4|默认网关|媒体状态|WLAN", line):
            print("   " + line.strip())

    print("\n[1] DNS 劫持检测（解析不存在的域名）")
    for host in ("zz9f3a-portal-detect.invalid", "no-such-host-8c7f1.example.com"):
        try:
            print("   %-40s -> %s" % (host, socket.gethostbyname(host)))
        except Exception as e:
            print("   %-40s -> 失败 %s" % (host, type(e).__name__))

    print("\n[2] 关键域名解析")
    for host in ("portal.gdou.edu.cn", "wifi.gdou.edu.cn", "eportal.gdou.edu.cn",
                 "srun.gdou.edu.cn", "aaa.gdou.edu.cn", "www.gdou.edu.cn",
                 "www.msftconnecttest.com"):
        try:
            print("   %-30s -> %s" % (host, socket.gethostbyname(host)))
        except Exception:
            print("   %-30s -> 解析失败" % host)

    print("\n" + "=" * 70)
    print("[3] HTTP 探测")
    urls = [
        "http://www.msftconnecttest.com/redirect",
        "http://www.msftconnecttest.com/connecttest.txt",
        "http://connect.rom.miui.com/generate_204",
        "http://www.gstatic.com/generate_204",
        "http://www.baidu.com/",
        "http://captive.apple.com/hotspot-detect.html",
    ]
    results = {}
    for url in urls:
        r = fetch(url)
        results[url] = r
        print("\n   URL   : %s" % url)
        print("   status: %s | Location: %s" % (r["status"], r["loc"]))
        if r["err"]:
            print("   error : %s" % r["err"])
        print("   body  : %s" % text_of(r["body"])[:300].replace("\n", " "))

    print("\n" + "=" * 70)
    print("[4] 网关 / 常见深澜地址")
    hosts = [h for h in dict.fromkeys([gw, "10.0.0.55", "10.0.1.1"]) if h]
    for h in hosts:
        for path in ("/", "/srun_portal_pc?ac_id=1",
                     "/cgi-bin/get_challenge?callback=cb&username=test&ip=1.1.1.1"):
            url = "http://%s%s" % (h, path)
            r = fetch(url)
            print("\n   URL   : %s" % url)
            print("   status: %s | Location: %s" % (r["status"], r["loc"]))
            if r["err"]:
                print("   error : %s" % r["err"])
            print("   body  : %s" % text_of(r["body"])[:400].replace("\n", " "))

    print("\n" + "=" * 70)
    print("[5] 响应里的跳转线索")
    probe = list(results.items())
    if gw:
        gw_url = "http://%s/" % gw
        probe.append((gw_url, fetch(gw_url)))
    for url, r in probe:
        body = text_of(r["body"])
        for m in re.findall(r"https?://[^\s\"'<>]+", body)[:8]:
            if any(k in m for k in ("srun", "portal", "ac_id", "login", "eportal", "wifi")):
                print("   %-40s -> %s" % (url[:40], m[:160]))
    print("\n探测结束")


if __name__ == "__main__":
    sys.exit(main())
