#!/usr/bin/env python3
"""按 RFC 6238 算 TOTP 码，供集成测试走通真实 MFA 链路。

不用 pyotp：那需要额外安装，会给「跑一下测试」加前置条件。
标准库的 hmac / hashlib / base64 已经够了，算法本身只有十几行。

用法：
    python3 tests/totp.py <base32_secret> [step_offset]

step_offset 用来造「上一个时间窗的码」：SoulAuth 接受 ±1 个窗口，
但同一个窗口的码用过一次就不能再用（last_totp_step 水位线）。
测试要验重放拦截，就得能指名道姓地取某个窗口的码。
"""

import base64
import hashlib
import hmac
import struct
import sys
import time

PERIOD = 30
DIGITS = 6


def totp(secret_b32: str, offset: int = 0, at: float | None = None) -> str:
    # SoulAuth 发的 secret 可能没有 padding，b32decode 要求长度是 8 的倍数
    secret = secret_b32.strip().replace(" ", "").upper()
    secret += "=" * (-len(secret) % 8)
    key = base64.b32decode(secret)

    counter = int((at if at is not None else time.time()) // PERIOD) + offset
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()

    # 动态截断（RFC 4226 §5.4）
    idx = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[idx:idx + 4])[0] & 0x7FFF_FFFF
    return str(code % (10 ** DIGITS)).zfill(DIGITS)


def seconds_into_step(at: float | None = None) -> float:
    """当前时间窗已经过去了多少秒。用来避开窗口边界。"""
    return (at if at is not None else time.time()) % PERIOD


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    if sys.argv[1] == "--seconds-into-step":
        print(f"{seconds_into_step():.1f}")
    else:
        print(totp(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 0))
