# -*- coding: utf-8 -*-
"""一个假的深澜认证服务器，用来在离线环境验证 gdou_login.py 的完整登录流程。
它会用参考实现独立校验客户端算出来的 info / hmd5 / chksum。"""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REF = None  # 由测试注入 reference_crypto 模块


class MockState:
    def __init__(self):
        self.username = "202500000001"
        self.password = "ExamplePass123"
        self.ac_id = "1"
        self.client_ip = "10.9.9.9"   # 故意和 127.0.0.1 不同，验证客户端会用服务器给的 IP
        self.challenge = "e0a1b2c3d4e5f60718293a4b5c6d7e8f"
        self.browser_only = False
        self.last = {}
        self.login_calls = 0
        self.errors = []


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            parts = urllib.parse.urlsplit(self.path)
            path, qs = parts.path, urllib.parse.parse_qs(parts.query, keep_blank_values=True)

            # 模拟"只对浏览器请求吐认证页"的 AC：Accept 不带 text/html 就回空壳
            if state.browser_only and "text/html" not in self.headers.get("Accept", ""):
                state.last["non_browser_hit"] = path
                self._send(200, "<html></html>", ctype="text/html; charset=utf-8")
                return

            if path == "/cgi-bin/get_challenge":
                cb = qs.get("callback", ["cb"])[0]
                state.last["challenge_ip"] = qs.get("ip", [""])[0]
                payload = {"challenge": state.challenge,
                           "client_ip": state.client_ip,
                           "res": "ok",
                           "ecode": 0}
                self._send(200, "%s(%s)" % (cb, json.dumps(payload)))
                return

            if path == "/cgi-bin/srun_portal":
                state.login_calls += 1
                p = {k: v[0] for k, v in qs.items()}
                state.last["login"] = p
                token = state.challenge
                user = p.get("username", "")
                ip = p.get("ip", "")
                acid = p.get("ac_id", "")
                hmd5_expect = REF.get_md5(state.password, token)
                info_expect = REF.build_info_reference(
                    user, state.password, ip, acid, token)
                chk_expect = REF.chksum_reference(
                    token, user, hmd5_expect, acid, ip,
                    p.get("n", ""), p.get("type", ""), p.get("info", ""))

                ok = True
                if user != state.username:
                    ok = False; state.errors.append("username=%r" % user)
                if p.get("password") != "{MD5}" + hmd5_expect:
                    ok = False; state.errors.append("password 字段不对")
                if p.get("info") != info_expect:
                    ok = False; state.errors.append("info 字段不对")
                if p.get("chksum") != chk_expect:
                    ok = False; state.errors.append("chksum 字段不对")
                if ip != state.client_ip:
                    ok = False; state.errors.append("ip=%r 应为 %r" % (ip, state.client_ip))

                if ok:
                    self._send(200, "%s(%s)" % (p.get("callback", "cb"),
                                                json.dumps({"ecode": 0, "error": "ok",
                                                            "suc_msg": "login_ok"})))
                else:
                    self._send(200, "%s(%s)" % (p.get("callback", "cb"),
                                                json.dumps({"ecode": 1,
                                                            "error": "login_error",
                                                            "error_msg": "; ".join(state.errors)})))
                return

            if path == "/blank":
                self._send(200, "<html></html>", ctype="text/html; charset=utf-8")
                return

            if path == "/srun_portal_pc":
                self._send(200, '<html><input id="user_ip" value="%s"></html>' % state.client_ip,
                           ctype="text/html; charset=utf-8")
                return

            # 其余路径模拟"被劫持到认证页"
            self._send(302, "", extra={"Location": "http://%s/srun_portal_pc?ac_id=%s"
                                       % (self.headers.get("Host", "127.0.0.1"), state.ac_id)})

    return Handler


def start(state=None):
    state = state or MockState()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, state, port
