#!/usr/bin/env python3
"""极简 SMTP 收信端，供集成测试验证发信路径。

为什么不用 `python3 -m smtpd`：该模块自 3.12 起已从标准库移除，
依赖它会让测试在新版 Python 上突然失效。这里只用 socket，任何 Python 3 都能跑。

为什么不用 aiosmtpd：需要额外安装，会给「跑一下测试」加上前置条件。

用法：
    python3 tests/smtp_sink.py <port> <outfile>

收到的每封信以 `===MAIL===` 分隔，原样追加写入 outfile。
"""

import socket
import sys
import threading

BANNER = b"220 sink ESMTP\r\n"
OK = b"250 OK\r\n"
SEPARATOR = "\n===MAIL===\n"


def handle(conn: socket.socket, outfile: str) -> None:
    """处理一次 SMTP 会话。协议实现到「能收下信」为止，不求完备。"""
    conn.sendall(BANNER)
    buf = b""
    in_data = False
    message: list[str] = []

    while True:
        try:
            chunk = conn.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk

        while b"\r\n" in buf:
            line, buf = buf.split(b"\r\n", 1)
            text = line.decode("utf-8", errors="replace")

            if in_data:
                # 单独一个点表示信体结束（RFC 5321 §4.1.1.4）
                if text == ".":
                    in_data = False
                    with open(outfile, "a", encoding="utf-8") as fh:
                        fh.write(SEPARATOR + "\n".join(message) + "\n")
                    message = []
                    conn.sendall(OK)
                else:
                    # 透明化传输：行首的额外句点要去掉
                    message.append(text[1:] if text.startswith("..") else text)
                continue

            upper = text.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                # 不宣告 STARTTLS / AUTH：测试端配置为明文无认证
                conn.sendall(b"250-sink\r\n250 SIZE 10485760\r\n")
            elif upper.startswith("DATA"):
                in_data = True
                conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            elif upper.startswith("QUIT"):
                conn.sendall(b"221 Bye\r\n")
                conn.close()
                return
            else:
                # MAIL FROM / RCPT TO / RSET / NOOP 等一律接受
                conn.sendall(OK)

    conn.close()


def main() -> None:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)

    port, outfile = int(sys.argv[1]), sys.argv[2]
    open(outfile, "w", encoding="utf-8").close()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)

    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        # 每封信一个线程：SoulAuth 的发信走 spawn_blocking，可能并发。
        threading.Thread(target=handle, args=(conn, outfile), daemon=True).start()


if __name__ == "__main__":
    main()
