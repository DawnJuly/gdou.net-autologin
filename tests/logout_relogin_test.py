# -*- coding: utf-8 -*-
"""决定性测试：主动注销 -> 验证确实断网 -> 用本程序自动登录 -> 验证恢复联网。"""

import os
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gdou_login as g  # noqa: E402

IP = g.local_ip_for("10.129.1.1")
print("client ip      =", IP)
print("before online  =", g.internet_ok())

params = {
    "callback": "cb",
    "action": "logout",
    "username": "202500000001",
    "ac_id": "17",
    "ip": IP,
}
url = "http://10.129.1.1/cgi-bin/srun_portal?" + urllib.parse.urlencode(params)
st, hdrs, body, _ = g.http_get(url, timeout=8)
print("logout status  =", st)
print("logout body    =", g.decode(body)[:300])

time.sleep(3)
print("after logout online =", g.internet_ok())

cfg = g.load_config()
log = g.Log(g.LOG_PATH)
ok = g.login_once(cfg, log, verbose=True)
print("relogin ok     =", ok)

time.sleep(3)
print("after relogin online =", g.internet_ok())
