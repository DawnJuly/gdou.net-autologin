# -*- coding: utf-8 -*-
"""参考实现：抄自 Tim-Conner/SrunPortaLogin（huxiaofan1223 版 srun 代码），
只保留纯算法函数，用于和 gdou_login.py 逐位比对。"""

import hashlib
import hmac
import math

_PADCHAR = "="
_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"


def _getbyte(s, i):
    x = ord(s[i])
    if x > 255:
        raise ValueError("INVALID_CHARACTER_ERR")
    return x


def get_base64(s):
    i = 0
    b10 = 0
    x = []
    imax = len(s) - len(s) % 3
    if len(s) == 0:
        return s
    for i in range(0, imax, 3):
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2)
        x.append(_ALPHA[(b10 >> 18)])
        x.append(_ALPHA[(b10 >> 12) & 63])
        x.append(_ALPHA[(b10 >> 6) & 63])
        x.append(_ALPHA[b10 & 63])
    i = imax
    remaining = len(s) - imax
    if remaining == 1:
        b10 = _getbyte(s, i) << 16
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[(b10 >> 12) & 63] + _PADCHAR + _PADCHAR)
    elif remaining == 2:
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8)
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[(b10 >> 12) & 63] + _ALPHA[(b10 >> 6) & 63] + _PADCHAR)
    return "".join(x)


def get_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) |
            ordat(msg, i + 1) << 8 |
            ordat(msg, i + 2) << 16 |
            ordat(msg, i + 3) << 24
        )
    if key:
        pwd.append(l)
    return pwd


def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(l):
        msg[i] = (
            chr(msg[i] & 0xff) +
            chr((msg[i] >> 8) & 0xff) +
            chr((msg[i] >> 16) & 0xff) +
            chr((msg[i] >> 24) & 0xff)
        )
    if key:
        return "".join(msg)[:ll]
    return "".join(msg)


def get_xencode(msg, key):
    if not msg:
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk += [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while q > 0:
        d = (d + c) & 0xFFFFFFFF
        e = (d >> 2) & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = (z >> 5) ^ (y << 2)
            m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
            m += (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = (pwd[p] + m) & 0xFFFFFFFF
            z = pwd[p]
            p += 1
        y = pwd[0]
        m = (z >> 5) ^ (y << 2)
        m += ((y >> 3) ^ (z << 4)) ^ (d ^ y)
        m += (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = (pwd[n] + m) & 0xFFFFFFFF
        z = pwd[n]
        q -= 1
    return lencode(pwd, False)


def build_info_reference(username, password, ip, acid, token, enc_ver="srun_bx1"):
    info_temp = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": acid,
        "enc_ver": enc_ver,
    }
    i = str(info_temp).replace("'", '"').replace(" ", "")
    return "{SRBX1}" + get_base64(get_xencode(i, token))


def chksum_reference(token, username, hmd5, ac_id, ip, n, typ, i):
    chkstr = token + username
    chkstr += token + hmd5
    chkstr += token + ac_id
    chkstr += token + ip
    chkstr += token + n
    chkstr += token + typ
    chkstr += token + i
    return get_sha1(chkstr)
