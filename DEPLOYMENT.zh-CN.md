# SoulAuth 部署指南

> English version: [DEPLOYMENT.md](DEPLOYMENT.md)（主版本）

本文档说明如何把 SoulAuth 部署到生产环境。

> **命名空间与数据库必须自始至终一致。** 全文统一用 `auth` / `main`
> （即 `DATABASE_NAMESPACE` / `DATABASE_NAME` 的默认值）。若你改用别的名字，
> **导入 SQL 时用的和应用启动时读到的必须是同一对** —— 这是最常见的部署失败原因：
> schema 建在一处、应用连另一处，进程照常启动、`/health` 照常返回 ok，
> 直到第一个真实请求才 500。应用现在会在启动时自检并拒绝启动，
> 但前提仍然是你把这两处对齐。

本文件只保留**部署步骤本身**，因为 `tests/deployment_walkthrough.sh` 逐条执行的
就是它 —— 它必须和脚本待在同一个仓库里，CI 才能在每次推送时把这份文档跑一遍。

其余内容都在文档站，且更细：

| 你要找的 | 去处 |
|---|---|
| Docker Compose / systemd / 反向代理 / 版本升级 | [部署](https://soulauth.trantorlabs.sg/zh/operate/deployment) |
| 上线前该改什么 | [生产清单](https://soulauth.trantorlabs.sg/zh/operate/production-checklist) |
| 备份、密钥轮换、事故处理 | [运维与恢复](https://soulauth.trantorlabs.sg/zh/operate/operations-and-recovery) |
| 故障排除（13 类症状） | [故障排查](https://soulauth.trantorlabs.sg/zh/operate/troubleshooting) |
| 作为 OIDC Provider 接入 | [接入路径](https://soulauth.trantorlabs.sg/zh/start/integration-path) |
| 权限清单 | [管理](https://soulauth.trantorlabs.sg/zh/reference/administration) |

---

## 环境变量

**必填只有四项**（缺任一进程起不来）：

```env
JWT_SECRET=<至少 32 字符>
APP_URL=https://auth.example.com
SMTP_HOST=smtp.example.com
SMTP_FROM=noreply@example.com
```

`APP_URL` 是对外地址，不是监听地址。它决定三件事：OIDC `issuer`、邮件里链接的
前缀、cookie 是否带 `Secure`。填错的后果见文档站
[配置](https://soulauth.trantorlabs.sg/zh/reference/configuration)
的「`APP_URL` 与监听地址的区别」。

#### 生产环境额外必填（非环回 `APP_URL` 时强制）

`APP_URL` 的主机不是 `127.0.0.1` / `localhost` / `[::1]` 时，**`APP_URL` 本身必须是
https** —— 明文会让会话 cookie 掉 `Secure`、邮件里的链接走明文，并且 OIDC `issuer`
违反 Discovery 规范，按规范校验的接入方会直接拒绝。TLS 请在 SoulAuth 前面终结，
这里填对外那个 https 地址。

在此之上，下面三项缺任一**直接拒绝启动**：

```env
OIDC_RSA_PRIVATE_KEY_PATH=/etc/soulauth/oidc-signing.pem   # 或 _PEM 直接给内容
MFA_SECRET_ENCRYPTION_KEY=<openssl rand -base64 32>
AUDIT_INTEGRITY_KEY=<openssl rand -base64 32>
```

为什么是拒绝启动而不是警告：**这三项的后果都不在启动时显现**。

- 缺签名私钥 → 每次启动临时生成一把，**进程一重启，已签发的 ID Token 全部
  无法验签**；多副本部署里各副本各签各的，从第一天起就互不认账，
  表现为随机登录失败。
- 缺 MFA 密钥 → 从 `JWT_SECRET` 派生，**哪天轮换 `JWT_SECRET`，所有已存的
  TOTP 密钥变成无法解密**，全体 MFA 用户被锁在门外。
- 缺审计完整性密钥 → 哈希链照写，但**没有任何 checkpoint 被签出来**，
  而只有链的话，拥有数据库写权限的人可以把它整段重算。这件事要等到你真的
  需要拿日志当证据的那天才会发现。

三把钥匙是刻意分开的：轮换其中一把不该作废另外两把，而审计完整性恰恰
最不该被别处的例行轮换破坏。

等它自己暴露的时候已经是线上事故。本地开发仍然放行——否则这道闸门会被人用
环境变量绕过去。

#### 数据库

```env
DATABASE_URL=127.0.0.1:8000        # 默认 http://localhost:8000；写 https:// 即走 TLS
DATABASE_USER=root
DATABASE_PASS=root
DATABASE_NAMESPACE=auth            # 默认 auth
DATABASE_NAME=main                 # 默认 main
DATABASE_CONNECTION_TIMEOUT=30
```

**关于数据库链路加密**：`DATABASE_URL` 带 `https://` 前缀即用 TLS 连接器，
否则走明文。指向非环回地址却用明文时，启动日志会给出一条 WARN —— 那条链路上
跑的是数据库口令、密码哈希与会话令牌。放在受信私有网段里可以接受，
跨网段务必用 https。

> 早期版本无论写不写 `https://` 都只用明文连接器（scheme 会被剥掉后丢弃），
> 且没有任何提示。若你此前配的是 `https://`，请确认数据库侧确实启用了 TLS。

#### 网络与前端

```env
BIND_ADDR=0.0.0.0:8080             # 监听地址，默认 0.0.0.0:8080
SOULAUTH_INSTANCE_ID=              # 本副本的审计链，生产环境必填
CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
TRUST_PROXY_HEADERS=true           # 在反向代理后必须开，否则限流按代理 IP 计数
LOGIN_PAGE_URL=                    # 默认 {APP_URL}/login
VERIFY_EMAIL_PAGE_URL=             # 默认 {APP_URL}/verify-email
RESET_PASSWORD_PAGE_URL=           # 默认 {APP_URL}/reset-password
```

`CORS_ALLOWED_ORIGINS` 留空时回落到 `APP_URL` 自身。填 `*` 会在启动时被拒绝 ——
那等于任何站点都能带着用户的 `Authorization` 头调用本服务。

三个页面地址是邮件链接与登录后跳转的落点。前端不在 `APP_URL` 上时才需要配。
重置令牌以**路径段**的形式追加在 `RESET_PASSWORD_PAGE_URL` 后面（`{页面}/{令牌}`），
验证令牌走的是查询参数（`{页面}?token=...`）。

`TRUST_PROXY_HEADERS` 在反向代理后**必须开**：不开的话所有请求的来源 IP 都是
代理的 IP，限流与账号锁定会把全体用户算成同一个客户端——一个人被锁，所有人
一起被锁。反过来，**没有代理时绝不能开**：那样客户端可以自己伪造
`X-Forwarded-For` 绕过限流。

#### 第三方登录（可选，不配就是不启用）

```env
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
OAUTH_REDIRECT_URL=https://auth.example.com/api/auth/callback
```

只用邮箱密码登录的部署**不需要填任何一项**。未配置时
`GET /api/auth/login/google` 返回 **501「本部署未启用」**，而不是拿假凭证去
换令牌再吐一个看不懂的 OAuth 错误。

两条判定规则：

- **只配 id 不配 secret 算未配置**。只配一半比两个都不配更危险——它看起来是
  开着的。
- **配了任一 provider 就必须配 `OAUTH_REDIRECT_URL`**，否则拒绝启动。缺它时
  重定向 URI 会被拼成残缺地址，登录走到第一步才失败。它的判据与下面的端点覆盖
  相同：必须是绝对的 https URL，明文 http 只允许精确指向环回地址 —— 远端明文回调
  等于把授权码放在链路上裸奔。

可选的端点覆盖（默认走官方端点）：

```env
GOOGLE_OAUTH_BASE_URL=
GITHUB_OAUTH_BASE_URL=https://ghe.example.com    # 自托管 GitHub Enterprise
```

覆盖时沿用该 provider 真实的路径形状，只换根地址：Google 是
`{base}/o/oauth2/v2/auth` · `/token` · `/oauth2/v2/userinfo`；GitHub 是
`{base}/login/oauth/{authorize,access_token}` 与 `{base}/api/v3/user[/emails]`
—— 后者正是 GitHub Enterprise 的约定。

**明文 http 只允许指向环回地址**，且不得带尾斜杠，否则拒绝启动：远端端点走
明文等于把 `client_secret` 与访问令牌交给链路上的任何人。

#### 账号锁定

```env
LOCKOUT_MAX_ATTEMPTS=5             # 连续失败多少次后锁定，必须 ≥1
LOCKOUT_DURATION_MINUTES=15        # 锁定多少分钟，必须 ≥1
LOCKOUT_RESET_WINDOW_MINUTES=60    # 多久没有新失败就清零计数
LOCKOUT_USER_ENABLED=true          # 账号维度
LOCKOUT_IP_ENABLED=true            # IP 维度
```

前两项为 0 会在启动时被拒绝：0 次尝试即锁定等于任何人一登录就被锁死，
0 分钟锁定等于没锁 —— 这两种都不是「更严格」，是把服务配坏。

**手工解锁**（需 `soulauth:security.write`，种子里授予 admin 与 security_manager）：

```bash
# 查状态
curl "$APP_URL/api/security/lockout?scope=user&identifier=user%40example.com" \
  -H "Authorization: Bearer $TOKEN"
# → {"is_locked":true,"remaining_lockout_seconds":812,…}

# 解锁（scope 取 user 或 ip；解锁是幂等的，本来没锁会返回 unlocked:false）
curl -X POST "$APP_URL/api/security/unlock" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"scope":"user","identifier":"user@example.com"}'
# → {"unlocked":true}
```

用户维度的标识是**邮箱**：锁定计数在登录失败时按邮箱累加，那时还没有用户记录
可言 —— 不存在的邮箱同样会被计数，否则「有没有留下锁定记录」本身就成了
账号枚举信道。

每一次解锁都会写一条 `lockout_cleared` 审计（包括本来就没锁的空操作）。

#### 邮件

```env
SMTP_PORT=587                      # 默认 587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_INSECURE=false                # 仅本地测试用
EMAIL_VERIFICATION_ENABLED=false   # 开启后注册需先验证邮箱
```

**发信失败只记日志，不阻断请求。** 也就是说 SMTP 配错时，注册会成功而验证信
永远收不到，日志之外没有任何提示。上线后请实际走一遍注册确认收得到信。

#### 其它

```env
JWT_EXPIRATION=86400               # 会话与访问令牌有效期，秒，默认 1 天
PASSWORD_MIN_LENGTH=12
AUTH_SESSION_CACHE_TTL_SECONDS=5   # 0 = 每请求都校验会话
PROXY_ENABLED=false                # 出站 OAuth 请求走代理
PROXY_URL=
```

`AUTH_SESSION_CACHE_TTL_SECONDS` 是**多副本下的吊销延迟上限**：本实例的登出 /
改密 / 停用会立刻清缓存，其它副本最多滞后一个 TTL。设为 0 则吊销绝对即时，
代价是每个请求多两次查询。


---

## 部署步骤

1. **启动 SurrealDB** 并确认可达：
   ```bash
   surreal start --bind 127.0.0.1:8000 --user root --pass "$DB_PASS" \
     surrealkv:///var/lib/surrealdb/soulauth.db
   curl -f http://127.0.0.1:8000/health && echo " SurrealDB OK"
   ```

2. **准备环境变量**。四项必填，生产环境再加两项（见上面「环境变量」）：
   ```bash
   export DATABASE_URL=127.0.0.1:8000
   export DATABASE_NAMESPACE=auth      # 下一步导入时必须用同一个值
   export DATABASE_NAME=main           # 同上
   export DATABASE_USER=root
   export DATABASE_PASS="$DB_PASS"
   export JWT_SECRET=$(openssl rand -hex 32)
   export APP_URL=https://auth.example.com
   export SMTP_HOST=smtp.example.com
   export SMTP_FROM=noreply@example.com
   export OIDC_RSA_PRIVATE_KEY_PATH=/etc/soulauth/oidc-signing.pem
   export MFA_SECRET_ENCRYPTION_KEY=$(openssl rand -base64 32)
   ```

3. **准备数据库**。注意这里直接复用上一步导出的变量，
   保证导入目标与应用启动后连接的是同一个 ns/db：
   ```bash
   surreal import --endpoint "http://$DATABASE_URL" \
       --user "$DATABASE_USER" --pass "$DATABASE_PASS" \
       --namespace "$DATABASE_NAMESPACE" --database "$DATABASE_NAME" schema.sql

   surreal import --endpoint "http://$DATABASE_URL" \
       --user "$DATABASE_USER" --pass "$DATABASE_PASS" \
       --namespace "$DATABASE_NAMESPACE" --database "$DATABASE_NAME" initial_data.sql
   ```

   两个文件都可以重复导入：每条 `DEFINE` 都带 `IF NOT EXISTS`，种子数据全是
   `UPSERT`。

4. **构建应用程序**：
   ```bash
   cargo build --release
   ```

5. **启动应用程序**：
   ```bash
   ./target/release/soulauth
   ```

6. **验证部署**：
   ```bash
   curl http://localhost:8080/health
   # → {"status":"ok","uptime_seconds":12}
   ```

7. **建立第一个管理员**：

   全程不需要碰数据库。新实例在启动日志里打一枚一次性引导令牌（`WARN` 级别，
   默认日志级别下可见），用它换第一个管理员：

   ```bash
   # ① 从启动日志里取令牌
   #    WARN No administrator found. Bootstrap token for this process: 7f3a…
   #
   #    多副本部署时用 SOULAUTH_BOOTSTRAP_TOKEN 固定它；设为空串则完全
   #    关闭这条路径。

   # ② 用它建管理员。密码需满足策略：至少 12 个字符（PASSWORD_MIN_LENGTH），
   #    且含大写 / 小写 / 数字 / 符号四类中的三类
   curl -X POST http://localhost:8080/api/bootstrap/admin \
     -H 'Content-Type: application/json' \
     -d '{"token":"7f3a…","email":"admin@your-domain.com",
          "username":"admin","password":"CorrectHorse42!"}'
   # → {"user_id":"…","email":"admin@your-domain.com","is_admin":true}

   # ③ 登录拿会话令牌（引导响应里不含令牌）
   curl -X POST http://localhost:8080/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"admin@your-domain.com","password":"CorrectHorse42!"}'

   # ④ 确认权限已生效
   curl http://localhost:8080/api/auth/me -H "Authorization: Bearer <token>"
   # → "is_admin": true
   ```

   这道门是一次性的：系统里一旦存在管理员，端点永久拒绝，且对「令牌错」与
   「门已关」返回**逐字相同**的响应 —— 一枚失效令牌因此无法用来探测某个实例
   是否已经初始化。

   令牌是**这个进程**的（日志原话 `for this process`）：重启一次就换一枚，
   得回去看新的那行 `WARN`。

## 验证这份文档本身

`tests/deployment_walkthrough.sh` 会照上面「部署步骤」的 1-7 从零跑一遍，
最后断言拿到一个 `is_admin: true` 的管理员：

```bash
cargo build && ./tests/deployment_walkthrough.sh
```

改动本文档的部署步骤后请一并跑它。参数名写错、ns/db 三处不一致这类问题，
只有真正执行才会暴露。

