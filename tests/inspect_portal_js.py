# -*- coding: utf-8 -*-
"""在已保存的认证页/JS 里找运营商 domain 选项和登录参数细节。"""

import glob
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(ROOT, "logs")


def load(path):
    raw = open(path, "rb").read()
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode("utf-8", "replace")


def main():
    files = glob.glob(os.path.join(LOGS, "*.js")) + glob.glob(os.path.join(LOGS, "*.html"))
    at_words = set()
    for path in files:
        text = load(path)
        name = os.path.basename(path)
        opts = re.findall(r"<option[^>]*>", text)
        if opts:
            print("\n[%s] <option>:" % name)
            for o in opts[:20]:
                print("   ", re.sub(r"\s+", " ", o)[:160])
        for m in re.findall(r"""["'](@[A-Za-z0-9_\-]{1,24})["']""", text):
            at_words.add(m)
        # domain 关键字上下文
        for m in re.finditer(r"domain", text):
            i = m.start()
            ctx = re.sub(r"\s+", " ", text[max(0, i - 120): i + 160])
            if "select" in ctx.lower() or "@" in ctx or "option" in ctx.lower():
                print("\n[%s] domain 上下文: ...%s..." % (name, ctx))
                break
    print("\n\n所有 @xxx 形式的候选值:", sorted(at_words))

    # 看 Portal.js 里登录函数的确切流程
    for path in files:
        if "Portal.js" not in path:
            continue
        text = load(path)
        print("\n##### 文件：%s #####" % os.path.basename(path))
        for marker in ("hmd5 = md5", "enc = 'srun_bx1'", "params: {", "function md5",
                       "md5 =", "sha1 =", "double_stack"):
            idx = 0
            shown = 0
            while True:
                i = text.find(marker, idx)
                if i < 0 or shown >= 2:
                    break
                idx = i + 1
                shown += 1
                print("\n===== %s =====" % marker)
                print(re.sub(r"[ \t]+", " ", text[max(0, i - 700): i + 1200]))
        break


if __name__ == "__main__":
    main()
