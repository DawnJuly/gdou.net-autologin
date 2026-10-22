# -*- coding: utf-8 -*-
"""从浏览器历史里找出校园网认证页的地址（只统计与 portal/srun/gdou 相关的条目）。
只读取一份副本，不改动原数据库。"""

import glob
import os
import shutil
import sqlite3
import sys
import tempfile

PATTERNS = ("%gdou%", "%srun%", "%eportal%", "%ac_id%", "%10.141%",
            "%portal%", "%wifi%", "%login%", "%drcom%", "%10.0.0%")

BROWSER_DIRS = [
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "BraveSoftware", "Brave-Browser", "User Data"),
    os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles"),
]

out = []


def say(s=""):
    out.append(s)
    print(s.encode("ascii", "replace").decode("ascii"))


def query_db(path):
    tmp = os.path.join(tempfile.gettempdir(), "dsh_hist_%d.db" % os.getpid())
    try:
        shutil.copy2(path, tmp)
    except Exception as e:
        say("  [copy fail] %s -> %s" % (path, e))
        return
    try:
        con = sqlite3.connect(tmp)
        cur = con.cursor()
        where = " OR ".join(["url LIKE ?"] * len(PATTERNS))
        cur.execute(
            "SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch','localtime') "
            "FROM urls WHERE (%s) ORDER BY last_visit_time DESC LIMIT 40" % where, PATTERNS)
        rows = cur.fetchall()
        con.close()
    except Exception as e:
        say("  [query fail] %s -> %s" % (path, e))
        rows = []
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

    if not rows:
        say("  （没有匹配记录）")
    for url, title, ts in rows:
        say("  %s  %s" % (ts, url))
        if title:
            say("      ^ %s" % str(title)[:100])


def main():
    found_any = False
    for d in BROWSER_DIRS:
        if not os.path.isdir(d):
            continue
        for hist in glob.glob(os.path.join(d, "*", "History")):
            say("\n[DB] %s" % hist)
            query_db(hist)
            found_any = True
    if not found_any:
        say("没有找到浏览器历史数据库")

    open("logs/history_hits.txt", "w", encoding="utf-8").write("\n".join(out))
    print("\nwritten logs/history_hits.txt")


if __name__ == "__main__":
    sys.exit(main())
