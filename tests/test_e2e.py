# -*- coding: utf-8 -*-
"""端到端联调：用假服务器验证完整登录流程。运行：python tests/test_e2e.py"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import gdou_login as app            # noqa: E402
import reference_crypto as ref      # noqa: E402
import mock_srun_server as mock     # noqa: E402

mock.REF = ref
app.INTERNET_PENDING = True
# 测试里不要真去访问外网
app.internet_ok = lambda timeout=4: False

logs = []
log = lambda msg, level="INFO": logs.append("[%s] %s" % (level, msg))

fails = []


def check(name, cond, detail=""):
    print(("[ OK ] " if cond else "[FAIL] ") + name + ("" if cond else "  -> %s" % detail))
    if not cond:
        fails.append(name)


def base_cfg(port, **kw):
    cfg = {
        "username": "202500000001",
        "password": "ExamplePass123",
        "portal": "127.0.0.1:%d" % port,
        "ac_id": "",
        "ac_id_candidates": ["1"],
        "portal_candidates": [],
        "n": "200", "type": "1", "os": "windows+10", "name": "windows",
    }
    cfg.update(kw)
    return cfg


def main():
    # --- 正常登录 ---
    srv, state, port = mock.start()
    ok = app.login_once(base_cfg(port), log)
    check("正常登录返回 True", ok, "\n".join(logs))
    check("服务端校验全部通过", not state.errors, state.errors)
    got = state.last.get("login", {})
    check("ip 采用服务器返回的 client_ip", got.get("ip") == state.client_ip, got.get("ip"))
    check("info 以 {SRBX1} 开头", str(got.get("info", "")).startswith("{SRBX1}"))
    check("password 带 {MD5} 前缀", str(got.get("password", "")).startswith("{MD5}"))
    check("带了 ac_id", got.get("ac_id") == "1", got.get("ac_id"))
    for key in ("action", "n", "type", "os", "name", "double_stack", "chksum"):
        check("参数包含 %s" % key, key in got)
    check("action=login", got.get("action") == "login")
    srv.shutdown()

    # --- 密码错误：应返回 False 且不崩 ---
    logs.clear()
    srv, state, port = mock.start()
    state.password = "wrong-password"
    ok = app.login_once(base_cfg(port), log)
    check("密码错误返回 False", ok is False)
    check("密码错误只尝试一轮", state.login_calls == 1, state.login_calls)
    check("错误原因写进日志", any("登录被拒绝" in m for m in logs), logs[-1] if logs else "")
    srv.shutdown()

    # --- ac_id 回退：配置错了要用候选值重试 ---
    logs.clear()
    srv, state, port = mock.start()
    state.ac_id = "1"
    cfg = base_cfg(port, ac_id="99", ac_id_candidates=["1"])
    ok = app.login_once(cfg, log)
    check("ac_id 错误时能回退到候选值", ok is True, "\n".join(logs))
    srv.shutdown()

    # --- 运营商后缀 ---
    logs.clear()
    srv, state, port = mock.start()
    state.username = "202500000001@telecom"
    ok = app.login_once(base_cfg(port, domain="telecom"), log)
    check("username 自动补 @telecom", ok is True, "\n".join(logs))
    srv.shutdown()

    # --- 劫持跳转自动探测认证服务器 ---
    logs.clear()
    srv, state, port = mock.start()
    old_detect = app.CAPTIVE_DETECT_URLS
    app.CAPTIVE_DETECT_URLS = ["http://127.0.0.1:%d/generate_204" % port]
    try:
        cfg = base_cfg(port, portal="", ac_id="", ac_id_candidates=["1"])
        host, acid = app.find_portal(cfg, log)
        check("能从 302 劫持跳转探测到认证服务器", host == "127.0.0.1:%d" % port, host)
        check("能从跳转 URL 解析出 ac_id", acid == "1", acid)
        ok = app.login_once(cfg, log)
        check("探测到服务器后能登录成功", ok is True, "\n".join(logs))
    finally:
        app.CAPTIVE_DETECT_URLS = old_detect
        srv.shutdown()

    # --- 只对"浏览器请求"才吐认证页的 AC（真实校园网常见） ---
    logs.clear()
    srv, state, port = mock.start()
    state.browser_only = True
    old_detect = app.CAPTIVE_DETECT_URLS
    app.CAPTIVE_DETECT_URLS = ["http://127.0.0.1:%d/redirect" % port]
    try:
        hits = app.detect_interception(log)
        check("只对浏览器吐页时也能发现认证页",
              len(hits) == 1 and hits[0][0] == "127.0.0.1:%d" % port, hits)
        check("能从认证页解析出 ac_id", bool(hits) and hits[0][1] == "1", hits)
        check("探测请求带的是浏览器 Accept（没被当非浏览器请求打回）",
              "non_browser_hit" not in state.last, state.last.get("non_browser_hit"))
    finally:
        app.CAPTIVE_DETECT_URLS = old_detect
        srv.shutdown()

    # --- 全是空壳页面时的降级：不应抛异常 ---
    logs.clear()
    srv, state, port = mock.start()
    old_detect = app.CAPTIVE_DETECT_URLS
    app.CAPTIVE_DETECT_URLS = ["http://127.0.0.1:%d/blank" % port]
    try:
        hits = app.detect_interception(log)
        check("AC 只回空壳页面时不抛异常", isinstance(hits, list))
    finally:
        app.CAPTIVE_DETECT_URLS = old_detect
        srv.shutdown()

    print("\n%s" % ("端到端测试全部通过" if not fails else "失败 %d 项" % len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
