# -*- coding: utf-8 -*-
"""把认证页和它的 JS 抓下来，找出这个 portal 自己用的加密算法和登录参数。"""

import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gdou_login as g  # noqa: E402

BASE = "http://10.129.1.1"
PAGE = BASE + "/srun_portal_pc?ac_id=17&theme=pro"
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(OUT_DIR, exist_ok=True)


def save(name, text):
    path = os.path.join(OUT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def main():
    st, hdrs, body, _ = g.http_get(PAGE, timeout=10)
    html = g.decode(body)
    print("page status =", st, "len =", len(html))
    save("portal_page.html", html)

    head = re.sub(r"\s+", " ", html)[:800]
    print("page head  =", head)

    refs = re.findall(r"""(?:src|href)\s*=\s*["']([^"']+)["']""", html)
    print("\nrefs:")
    for r in refs:
        print("   ", r)

    for ref in refs:
        if ".js" not in ref.lower():
            continue
        url = urllib.parse.urljoin(PAGE, ref)
        try:
            st2, _h, b2, _f = g.http_get(url, timeout=15)
        except Exception as e:
            print("fetch fail", url, e)
            continue
        js = g.decode(b2)
        name = re.sub(r"[^\w.\-]", "_", ref.replace("/", "_"))
        save("js_" + name, js)
        print("\n=== %s (status %s, %d bytes) ===" % (url, st2, len(js)))
        for key in ("xEncode", "base64", "hmd5", "chksum", "enc_ver", "srun_bx1",
                    "{MD5}", "{SRBX1}", "callback", "ac_id"):
            idx = js.find(key)
            if idx < 0:
                continue
            snippet = re.sub(r"\s+", " ", js[max(0, idx - 180): idx + 260])
            print("  [%s] ...%s..." % (key, snippet))
            if key in ("xEncode", "srun_bx1", "{MD5}"):
                break


if __name__ == "__main__":
    sys.exit(main())
