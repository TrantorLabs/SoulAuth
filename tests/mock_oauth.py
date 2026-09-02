#!/usr/bin/env python3
"""Google / GitHub 的本地替身，供集成测试走通「换到令牌之后」那一段。

在此之前，两家的端点写死在 oauth.rs 里，回调只能测到「拿假 code 去换令牌然后
失败」为止 —— 取用户信息、按邮箱验证状态放行、建号或关联既有账号，
这些全都没被验证过。

路径形状照抄真实 provider（见 src/services/oauth.rs 的 endpoints 函数），
所以这是忠实替身而非另一套协议。

**按授权码选画像**：授权码原样编进访问令牌，取用户信息时再解出来。
这样替身本身无状态，测试却能驱动不同分支（含否定路径）。

用法：
    python3 tests/mock_oauth.py <port>
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

TOKEN_PREFIX = "at:"

# 授权码 → 该画像下 provider 返回的用户信息
PROFILES = {
    "google-ok": {
        "id": "google-uid-1",
        "email": "oauth-new@test.local",
        "verified_email": True,
        "name": "OAuth Newcomer",
        "picture": "https://example.test/a.png",
    },
    # 邮箱未验证：SoulAuth 必须拒绝，否则任何人注册一个同名未验证邮箱就能顶号
    "google-unverified": {
        "id": "google-uid-2",
        "email": "oauth-unverified@test.local",
        "verified_email": False,
        "name": "Unverified",
        "picture": None,
    },
    # 邮箱与既有本地账号相同：应当关联到该账号，而不是再建一个
    "google-existing": {
        "id": "google-uid-3",
        "email": "admin@test.local",
        "verified_email": True,
        "name": "Admin via Google",
        "picture": None,
    },
    "github-ok": {
        "id": 4001,
        "name": "GitHub Newcomer",
        "avatar_url": "https://example.test/b.png",
        "_emails": [
            {"email": "noreply@users.github.test", "primary": False, "verified": True},
            {"email": "oauth-gh@test.local", "primary": True, "verified": True},
        ],
    },
    # 主邮箱未验证：无「primary 且 verified」的邮箱，必须拒绝
    "github-unverified": {
        "id": 4002,
        "name": "GitHub Unverified",
        "avatar_url": None,
        "_emails": [
            {"email": "gh-unverified@test.local", "primary": True, "verified": False},
        ],
    },
    # ── 跨 provider 同号：两家给出**数值相同**的用户 id ──
    #
    # 身份查找若只按 provider_user_id 单列匹配（而不是 (provider, id) 两列），
    # 后一家登录就会命中前一家的记录，直接登进别人的账号。
    # 曾经实测到过：不建新号、不建新关联、HTTP 303 成功，全程无任何报错。
    # 这两个画像存在的唯一目的就是把那条路钉死。
    "google-collide": {
        "id": "4100",                       # Google 的 sub 是字符串
        "email": "collide-google@test.local",
        "verified_email": True,
        "name": "Collide via Google",
        "picture": None,
    },
    "github-collide": {
        "id": 4100,                         # GitHub 的 id 是整数，数值相同
        "name": "Collide via GitHub",
        "avatar_url": None,
        "_emails": [
            {"email": "collide-github@test.local", "primary": True, "verified": True},
        ],
    },
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # 保持测试输出干净
        pass

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _profile(self):
        """从 Authorization 头里的访问令牌解出画像。"""
        auth = self.headers.get("Authorization", "")
        token = auth.split(" ", 1)[1].strip() if " " in auth else ""
        if not token.startswith(TOKEN_PREFIX):
            return None
        return PROFILES.get(token[len(TOKEN_PREFIX):])

    def do_POST(self) -> None:
        if not self.path.split("?")[0].endswith(("/token", "/access_token")):
            self._send(404, {"error": "not_found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode())
        code = (form.get("code") or [""])[0]

        if code not in PROFILES:
            # 真实 provider 对无效授权码就是这个响应，替身照办
            self._send(400, {"error": "invalid_grant"})
            return

        self._send(200, {
            "access_token": TOKEN_PREFIX + code,
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": "user:email",
        })

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        profile = self._profile()

        if profile is None:
            self._send(401, {"error": "bad_credentials"})
            return

        if path == "/oauth2/v2/userinfo":            # Google
            self._send(200, profile)
        elif path == "/api/v3/user":                 # GitHub
            self._send(200, {k: v for k, v in profile.items() if not k.startswith("_")})
        elif path == "/api/v3/user/emails":          # GitHub
            self._send(200, profile.get("_emails", []))
        else:
            self._send(404, {"error": "not_found"})


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()


if __name__ == "__main__":
    main()
