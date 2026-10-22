# -*- coding: utf-8 -*-
"""把 gdou_login.py 的算法和参考实现逐位比对，运行：python tests/test_crypto.py"""

import os
import random
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import gdou_login as mine          # noqa: E402
import reference_crypto as ref     # noqa: E402

fails = []


def check(name, a, b):
    if a != b:
        fails.append(name)
        print("[FAIL] %s\n   mine=%r\n   ref =%r" % (name, a, b))
    else:
        print("[ OK ] %s" % name)


def rand_ascii(maxlen=24):
    n = random.randint(0, maxlen)
    return "".join(random.choice(string.printable[:94]) for _ in range(n))


def main():
    random.seed(20251141)

    # 1) base64：用 lencode 产出的 0-255 字符作为输入
    for t in range(200):
        words = [random.getrandbits(32) for _ in range(random.randint(0, 12))]
        s = "".join(chr(w & 0xFF) + chr((w >> 8) & 0xFF) + chr((w >> 16) & 0xFF)
                    + chr((w >> 24) & 0xFF) for w in words)
        check("base64#%d" % t, mine.srun_base64(s), ref.get_base64(s))

    # 2) xencode：随机明文 + 随机 token
    for t in range(300):
        msg = rand_ascii()
        key = rand_ascii(40) or "x"
        check("xencode#%d" % t, mine.xencode(msg, key), ref.get_xencode(msg, key))

    # 3) info 字段整体
    cases = [
        ("202500000001", "ExamplePass123", "192.168.1.23", "1"),
        ("202500000001", "ExamplePass123", "10.20.30.40", "7"),
        ("202500000001@telecom", "ExamplePass123", "172.16.5.6", "1"),
    ]
    for user, pwd, ip, acid in cases:
        token = "".join(random.choice(string.hexdigits) for _ in range(32))
        check("info:%s/%s" % (user, acid),
              mine.build_info(user, pwd, ip, acid, token),
              ref.build_info_reference(user, pwd, ip, acid, token))

    # 4) chksum / hmac / md5
    for t in range(50):
        token = "".join(random.choice(string.hexdigits) for _ in range(32))
        user, pwd, ip, acid, n, typ = "202500000001", "ExamplePass123", "10.0.0.9", "1", "200", "1"
        hmd5 = mine.hmac_md5_hex(token, pwd)
        check("hmac#%d" % t, hmd5, ref.get_md5(pwd, token))
        info = mine.build_info(user, pwd, ip, acid, token)
        check("chksum#%d" % t,
              mine.build_chksum(token, user, hmd5, acid, ip, n, typ, info),
              ref.chksum_reference(token, user, hmd5, acid, ip, n, typ, info))

    print("\n%s" % ("全部通过，算法与参考实现一致" if not fails else "失败 %d 项" % len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
