# -*- coding: utf-8 -*-
"""探测 portal.gdou.edu.cn 等候选地址，判断认证服务器/接口在哪。输出写 UTF-8 文件。"""

import re
import socket
import sys
import urllib.error
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Upgrade-Insecure-Requests": "1",
}
OUT = []
USER = "202500000001"


def say(*a):
    line = " ".join(str(x) for x in a)
    OUT.append(line)
    print(line.encode("ascii", "replace").decode("ascii"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(url, timeout=6):
    req = urllib.request.Request(url, headers=HEADERS)
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        return None, {"error": "%s: %s" % (type(e).__name__, e)}, b""


def txt(b):
    for enc in ("utf-8", "gbk"):
        try:
            return b.decode(enc)
        except Exception:
            pass
    return b.decode("utf-8", "replace")


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def main():
    hosts = ["portal.gdou.edu.cn", "210.38.137.86", "www.gdou.edu.cn"]
    for h in hosts:
        try:
            say("[DNS] %-22s -> %s" % (h, socket.gethostbyname(h)))
        except Exception as e:
            say("[DNS] %-22s -> fail %s" % (h, type(e).__name__))

    ip = local_ip()
    paths = ["/", "/srun_portal_pc?ac_id=1", "/eportal/",
             "/cgi-bin/get_challenge?callback=cb&username=%s&ip=%s" % (USER, ip),
             "/cgi-bin/srun_portal?action=logout"]
    for h in hosts:
        for scheme in ("http", "https"):
            for p in paths:
                url = "%s://%s%s" % (scheme, h, p)
                st, hdrs, body = fetch(url, timeout=5)
                loc = hdrs.get("Location") or ""
                err = hdrs.get("error") or ""
                t = txt(body)
                head = re.sub(r"\s+", " ", t)[:220]
                say("\nURL    : %s" % url)
                say("status : %s | Location: %s" % (st, loc))
                if err:
                    say("error  : %s" % err)
                say("body   : %s" % head)
                if '"challenge"' in t:
                    m = re.search(r'"challenge"\s*:\s*"([^"]*)"', t)
                    say(">>> 命中深澜 get_challenge，challenge=%s" % (m.group(1) if m else "?"))
                if "srun" in t.lower() or "ac_id" in t:
                    say(">>> 响应里含 srun/ac_id 关键字")

    open("logs/portal_probe.txt", "w", encoding="utf-8").write("\n".join(OUT))
    print("\nwritten logs/portal_probe.txt")


if __name__ == "__main__":
    sys.exit(main())
