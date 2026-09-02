#!/usr/bin/env bash
#
# SoulAuth 端到端集成测试
#
# 为什么是脚本而不是 `cargo test`：
#   本套用例需要一个真实的 SurrealDB 与一个真实运行的服务进程。把它挂进
#   `cargo test` 会让原本 5 秒、零外部依赖的单元测试变成「必须装 surreal、
#   必须有空闲端口」，那是倒退。两者分工：
#     cargo test        —— 纯逻辑与一致性断言，随时可跑
#     tests/integration.sh —— 契约级行为，改完动真格的时候跑
#
# 用法：
#   cargo build && ./tests/integration.sh
#   SURREAL_PORT=8101 APP_PORT=8180 SINK_PORT=8125 ./tests/integration.sh   # 端口被占时
#   KEEP_WORK=1 ./tests/integration.sh                       # 失败时保留现场
#
# 退出码：0 全过；1 有断言失败；2 前置条件不满足。

set -uo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SURREAL_PORT="${SURREAL_PORT:-8101}"
readonly APP_PORT="${APP_PORT:-8180}"
# 用 SINK_PORT 而不是 SMTP_PORT：后者是应用要读的环境变量名，
# 脚本里若把它声明成 readonly，start_app 的命令前缀赋值会被拒
# （bash: "SMTP_PORT: readonly variable"），应用于是回落到默认端口，
# 信发到没人听的地方 —— 而发信失败只记日志，故障完全静默。
readonly SINK_PORT="${SINK_PORT:-8125}"
readonly OAUTH_PORT="${OAUTH_PORT:-8127}"
readonly APP2_PORT="${APP2_PORT:-8181}"   # 第二副本，用于验限流跨副本合账
readonly DB="http://127.0.0.1:${SURREAL_PORT}"
readonly APP="http://127.0.0.1:${APP_PORT}"
readonly WORK="$(mktemp -d)"

# 本机环境常有全局 HTTP 代理，会把 127.0.0.1 的请求也代理走。
export no_proxy="localhost,127.0.0.1" NO_PROXY="localhost,127.0.0.1"

readonly NL=$'\n'

PASS=0
FAIL=0
DB_PID=""
APP_PID=""
SINK_PID=""
MOCK_PID=""
APP2_PID=""

# ───────────────────────────────── 输出 ─────────────────────────────────

c_grn() { printf '\033[32m%s\033[0m' "$1"; }
c_red() { printf '\033[31m%s\033[0m' "$1"; }
c_dim() { printf '\033[2m%s\033[0m' "$1"; }

group() { printf '\n%s\n' "── $* ──"; }

ok()   { PASS=$((PASS+1)); printf '  %s %s\n' "$(c_grn ✓)" "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  %s %s\n' "$(c_red ✗)" "$1"
         [ $# -gt 1 ] && printf '      %s\n' "$(c_dim "$2")"; return 0; }

# 断言：期望值 实际值 描述
eq() {
    # 取值里出现换行，几乎都意味着取值逻辑坏了（典型：`grep -c ... || echo 0`
    # 会输出两行）。若不拦下来，调用方一旦把它送进 $(( )) 就是语法错，
    # 整条断言连同它的结果一起消失，汇总还会显示"全部通过"。
    # 用 $'\n' 字面量，不能用 "$(printf '\n')" —— 命令替换会剥掉尾部换行，
    # 那样模式退化成 `**`，匹配一切，每条断言都会被误判。
    case "$1$2" in
        *"$NL"*) bad "$3" "取值含换行，说明取值逻辑有误：期望 [$1] 实际 [$2]"; return ;;
    esac
    if [ "$1" = "$2" ]; then ok "$3"; else bad "$3" "期望 [$1]，实际 [$2]"; fi
}

# 断言：实际值中应包含子串
has() {
    case "$2" in
        *"$1"*) ok "$3" ;;
        *)      bad "$3" "未找到 [$1]，实际 [${2:0:120}]" ;;
    esac
}

# ───────────────────────────── HTTP / SQL 助手 ─────────────────────────────

# 发请求，回显 HTTP 状态码；响应体写入 $WORK/body
req() {
    local method="$1" path="$2"; shift 2
    curl -sS --max-time 25 -o "$WORK/body" -w '%{http_code}' \
        -X "$method" "${APP}${path}" "$@" 2>/dev/null || echo "000"
}
body() { cat "$WORK/body" 2>/dev/null; }

# 从响应体里取一个 JSON 字段（支持 data 包一层的情况）
jget() {
    python3 -c "
import json,sys
try: d=json.load(open('$WORK/body'))
except Exception: print(''); sys.exit()
# 全部端点现在都返回裸对象；这行只是对历史 ApiResponse 信封的兼容回退。
b=d.get('data') if isinstance(d,dict) and isinstance(d.get('data'),dict) else d
if not isinstance(b, dict):
    print(''); sys.exit()
v = b.get('$1')
# 布尔/数字要按 JSON 形态打印。直接 print 会得到 Python 的 True/False，
# 与接口返回的 true/false 对不上，断言就成了假失败。
print('' if v is None else v if isinstance(v, str) else json.dumps(v))" 2>/dev/null
}

# 直连数据库执行 SQL，回显首条语句的 result（JSON）
sql() {
    curl -sS --max-time 15 -u root:root \
        -H 'Accept: application/json' -H 'surreal-ns: auth' -H 'surreal-db: main' \
        --data "$1" "${DB}/sql" 2>/dev/null |
    python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)[0]['result']))" 2>/dev/null
}

# 取聚合计数（GROUP ALL 的查询）
sql_count() {
    # 兜底放在 python 内部，不用 `|| echo 0` —— 那样在 python 已经输出过
    # 内容的情况下会叠加成两行，调用方的算术展开直接语法错。
    sql "$1" | python3 -c "
import json,sys
try:
    r = json.load(sys.stdin)
    print(r[0].get('count', r[0].get('total', 0)) if r else 0)
except Exception:
    print(0)" 2>/dev/null
}

# ───────────────────────────── 邮件助手 ─────────────────────────────
#
# 信件是 quoted-printable 编码的：`=3D` 表示 `=`，行尾单个 `=` 是软换行，
# token 会被拦腰截断（`token=3D3b=\nf12ff5-...`）。所以**不能**拿正则去啃
# 原始 SMTP 数据，必须先解码。这里用标准库 email 模块，顺带把 base64 和
# 字符集一并处理掉。

MAILBOX=""

# 注意：`grep -c` 无匹配时会打印 0 **并且**退出码为 1。写成
# `grep -c ... || echo 0` 会打印两个 0，调用方拿到 "0\n0"，
# 于是 $((BEFORE + 1)) 直接语法错 —— 断言不是失败，而是**静默消失**，
# 汇总还照样说"全部通过"。grep -c 本来就总会输出数字，不需要兜底。
mail_count() {
    [ -f "$MAILBOX" ] || { echo 0; return; }
    grep -c '===MAIL===' "$MAILBOX" 2>/dev/null
}

# 最后一封信的解码正文
# bearer 凭证的落库指纹。必须与 `src/utils/crypto.rs::hash_bearer` 逐字节一致：
# SHA-256 → base64url-no-pad。库里存的是它，测试要按它查。
bearer_hash() {
    python3 -c "
import base64, hashlib, sys
print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).decode().rstrip('='))
" "$1"
}

mail_body() {
    python3 -c "
import email, sys
parts = open('$MAILBOX', encoding='utf-8', errors='replace').read().split('===MAIL===')
if len(parts) < 2: sys.exit()
msg = email.message_from_string(parts[-1].strip())
payload = msg.get_payload(decode=True)
print(payload.decode('utf-8', 'replace') if payload else '')" 2>/dev/null
}

# 最后一封信的某个头
mail_header() {
    python3 -c "
import email, sys
parts = open('$MAILBOX', encoding='utf-8', errors='replace').read().split('===MAIL===')
if len(parts) < 2: sys.exit()
print(email.message_from_string(parts[-1].strip()).get('$1', ''))" 2>/dev/null
}

# ───────────────────────────── 生命周期 ─────────────────────────────

cleanup() {
    [ -n "$SINK_PID" ] && kill -9 "$SINK_PID" 2>/dev/null
    [ -n "$MOCK_PID" ] && kill -9 "$MOCK_PID" 2>/dev/null
    [ -n "$APP2_PID" ] && kill -9 "$APP2_PID" 2>/dev/null
    [ -n "$APP_PID" ] && kill -9 "$APP_PID" 2>/dev/null
    [ -n "$DB_PID" ]  && kill -9 "$DB_PID"  2>/dev/null
    # 排查时用 KEEP_WORK=1 保留现场（服务日志、信箱、最后一次响应体）
    if [ -n "${KEEP_WORK:-}" ]; then
        printf '\n现场保留在 %s\n' "$WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

# 就绪等待。
#
# 超时给到 90 秒而不是 20：应用的就绪探针打的是 /api/oidc/jwks，而首次访问它会
# **现场生成一把 2048 位 RSA 密钥**（没配 OIDC_RSA_PRIVATE_KEY_PATH 时的开发行为，
# 启动日志里那句 "generating an ephemeral RSA key" 就是它）。生成时间是找素数，
# 本质随机，方差很大：本机空载约 5 秒，共享 runner 上偶尔超过 20 秒。
#
# 症状是 CI 间歇性 `exit 2`，而服务日志里什么错都没有 —— 因为根本不是错，
# 是等得不够久。整套跑一次全程约 3 分钟，这里多等 70 秒的代价可以忽略。
WAIT_TIMEOUT_TICKS="${WAIT_TIMEOUT_TICKS:-180}"   # ×0.5s = 90 秒
wait_for() {
    local url="$1" name="$2" n=0
    while [ $n -lt "$WAIT_TIMEOUT_TICKS" ]; do
        [ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "$url" 2>/dev/null)" != "000" ] && return 0
        sleep 0.5; n=$((n+1))
    done
    printf '%s %s 未能在 %s 秒内就绪\n' "$(c_red ✗)" "$name" "$((WAIT_TIMEOUT_TICKS / 2))"; return 1
}

start_db() {
    surreal start --bind "127.0.0.1:${SURREAL_PORT}" --user root --pass root memory \
        > "$WORK/surreal.log" 2>&1 &
    DB_PID=$!
    disown "$DB_PID" 2>/dev/null
    wait_for "${DB}/health" "SurrealDB" || exit 2
    for f in schema.sql initial_data.sql; do
        surreal import --endpoint "$DB" --user root --pass root \
            --namespace auth --database main "$ROOT/$f" > "$WORK/import.log" 2>&1 ||
            { printf '%s 导入 %s 失败\n' "$(c_red ✗)" "$f"; cat "$WORK/import.log"; exit 2; }
    done
}

# 启动服务。限流计数保存在进程内存里，重启即清零 ——
# 注册 3 次/5 分钟、登录 5 次/5 分钟，用例超过这个量必须重启，
# 否则后续断言全被 429 污染，看起来像功能坏了。
start_app() {
    (
        cd "$ROOT"
        DATABASE_URL="127.0.0.1:${SURREAL_PORT}" \
        DATABASE_USER=root DATABASE_PASS=root \
        DATABASE_NAMESPACE=auth DATABASE_NAME=main \
        JWT_SECRET=0123456789abcdef0123456789abcdef \
        GOOGLE_CLIENT_ID=dummy GOOGLE_CLIENT_SECRET=dummy \
        GITHUB_CLIENT_ID=dummy GITHUB_CLIENT_SECRET=dummy \
        OAUTH_REDIRECT_URL="${APP}/api/auth/callback" \
        SMTP_HOST=127.0.0.1 SMTP_PORT="${SINK_PORT}" SMTP_FROM=noreply@example.com \
        SMTP_INSECURE=true \
        APP_URL="$APP" EMAIL_VERIFICATION_ENABLED="${VERIFY_EMAIL:-false}" \
        GOOGLE_OAUTH_BASE_URL="${OAUTH_BASE:-}" \
        GITHUB_OAUTH_BASE_URL="${OAUTH_BASE:-}" \
        BIND_ADDR="127.0.0.1:${APP_PORT}" \
        RUST_LOG=soulauth=warn \
        exec ./target/debug/soulauth
    # 追加而不是覆盖：测试全程会多次 restart_app，用 `>` 的话前面组的错误
    # 会被后面的重启冲掉 —— 排查时看到"日志无错误"是假象，实际是日志没了。
    ) >> "$WORK/app.log" 2>&1 &
    APP_PID=$!
    disown "$APP_PID" 2>/dev/null   # 免得 kill -9 时 shell 打一行 "Killed ..." 混进输出
    wait_for "${APP}/api/oidc/jwks" "SoulAuth" || { cat "$WORK/app.log"; exit 2; }
}

restart_app() {
    kill -9 "$APP_PID" 2>/dev/null
    sleep 0.5
    # 限流现在有两层：进程内的随重启清空，跨副本的存在库里 **不会**随重启清空
    # —— 这正是它要的性质（重启副本不能当解封手段）。测试里 restart_app 的用途
    # 是「给我一份干净的配额」，所以两层都得清，否则前面组用掉的配额会一路
    # 累到后面，表现为大面积 429。
    #
    # 第 19 组验跨副本合账时中途没有 restart_app，不受这里影响。
    sql "DELETE rate_limit" > /dev/null 2>&1
    start_app
}

# 注册并登录，回显访问令牌
signup() {
    req POST /api/auth/register -H 'Content-Type: application/json' \
        -d "{\"email\":\"$1\",\"password\":\"CorrectHorse42!\",\"username\":\"$2\"}" > /dev/null
    jget id > "$WORK/uid_$2"   # register 返回 {token,user:{id}}，此处取不到就靠下面的 login
    req POST /api/auth/login -H 'Content-Type: application/json' \
        -d "{\"email\":\"$1\",\"password\":\"CorrectHorse42!\"}" > /dev/null
    jget token
}

user_id_of() {
    sql "SELECT VALUE type::string(id) FROM user WHERE email = '$1' LIMIT 1" |
        python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0].split(':',1)[1].strip('\`') if r else '')" 2>/dev/null
}

grant_admin() {
    # 角色分配挂在身份根上（Stage 3 起 user_role.user_id 是 record<actor_identity>），
    # 所以这里要先由 user 行取出它的 subject_id。
    sql "CREATE user_role CONTENT {
           user_id: (SELECT VALUE subject_id FROM type::record('user','$1'))[0],
           role_id: role:admin, assigned_at: 0, assigned_by: actor_identity:system }" > /dev/null
}

# ───────────────────────────── 前置检查 ─────────────────────────────

command -v surreal > /dev/null || { echo "缺少 surreal 可执行文件"; exit 2; }
command -v python3 > /dev/null || { echo "缺少 python3"; exit 2; }
[ -x "$ROOT/target/debug/soulauth" ] || { echo "请先 cargo build"; exit 2; }
for p in "$SURREAL_PORT" "$APP_PORT" "$SINK_PORT" "$OAUTH_PORT" "$APP2_PORT"; do
    if ss -ltn 2>/dev/null | grep -q ":${p} "; then
        echo "端口 ${p} 已被占用；可用 SURREAL_PORT / APP_PORT / SINK_PORT / OAUTH_PORT / APP2_PORT 覆盖"; exit 2
    fi
done

printf 'SoulAuth 集成测试  db=:%s  app=:%s\n' "$SURREAL_PORT" "$APP_PORT"
start_db
start_app

# ═══════════════════════════════ 用例 ═══════════════════════════════

group "1. 服务与发现端点"

eq 200 "$(req GET /api/oidc/jwks)" "GET /api/oidc/jwks"
has '"kty":"RSA"' "$(body)" "JWKS 含 RSA 公钥"
has '"kid"' "$(body)" "JWKS 含 kid"

eq 200 "$(req GET /api/oidc/.well-known/openid-configuration)" "OIDC 发现文档"
has '"RS256"' "$(body)" "ID Token 签名算法宣告为 RS256"
has '"S256"' "$(body)" "PKCE 只宣告 S256"

group "2. 注册 / 登录 / 会话"

ADMIN_TOKEN="$(signup admin@test.local admintest)"
[ -n "$ADMIN_TOKEN" ] && ok "注册并登录成功" || bad "注册并登录成功" "未取到令牌"

eq 200 "$(req GET /api/auth/me -H "Authorization: Bearer $ADMIN_TOKEN")" "GET /api/auth/me"
has 'admin@test.local' "$(body)" "/me 返回本人邮箱"

# RFC 7235：认证方案名不区分大小写
eq 200 "$(req GET /api/auth/me -H "authorization: bearer $ADMIN_TOKEN")" "小写 bearer 同样被接受"
eq 401 "$(req GET /api/auth/me -H "authorization: Basic $ADMIN_TOKEN")" "Basic 方案被拒绝"
eq 401 "$(req GET /api/auth/me)" "无令牌 401"

group "3. 引导路径（首个管理员）"

# 公开文档 03｜Quickstart 的验收标准：
#   「一个全新的 SoulAuth 实例，应该让开发者在不直接修改数据库的情况下，
#     从零走到第一份经过验证的 Actor 身份。」
# 这一组就是那条标准的可执行形式。测试库是 memory 后端，每次全新，
# 因此此刻系统里确实还没有任何管理员。

# 令牌只从启动日志取 —— 这同时验证了它的交付方式，而不只是验证端点本身。
BOOT_TOKEN="$(grep -oP 'Bootstrap token for this process: \K\S+' "$WORK/app.log" | head -1)"
[ -n "$BOOT_TOKEN" ] && ok "启动日志打印了引导令牌" ||
    bad "启动日志打印了引导令牌" "$(grep -i bootstrap "$WORK/app.log" | head -3)"

# 错误令牌必须被拒，且要留审计。
#
# 状态码是 403 而不是 401，与下面「已初始化」那两条**完全一致** —— 这是同一条
# 不变式的未初始化侧。曾经这里是 401：调顺序只统一了已初始化那一侧，拿一枚废
# 令牌打一次仍然能区分 401（未初始化）与 403（已初始化），探测信道原封不动。
eq 403 "$(req POST /api/bootstrap/admin -H 'Content-Type: application/json' \
    -d '{"token":"wrong","email":"nope@test.local","username":"nope","password":"CorrectHorse42!"}')" \
    "未初始化时错误引导令牌被拒，且与已初始化同一状态码"
# 留着这份响应体，等系统初始化之后逐字节比对。只统一状态码不够 ——
# 文案里只要出现 "an administrator already exists" 之类的措辞，信道就从
# 状态码搬进了 body。
BOOT_REJECT_UNINIT="$(body)"

# 密码策略不因为「这是第一个用户」而放宽。
eq 400 "$(req POST /api/bootstrap/admin -H 'Content-Type: application/json' \
    -d "{\"token\":\"${BOOT_TOKEN}\",\"email\":\"boot@test.local\",\"username\":\"boot\",\"password\":\"short\"}")" \
    "引导路径同样执行密码策略"

eq 200 "$(req POST /api/bootstrap/admin -H 'Content-Type: application/json' \
    -d "{\"token\":\"${BOOT_TOKEN}\",\"email\":\"boot@test.local\",\"username\":\"bootadmin\",\"password\":\"CorrectHorse42!\"}")" \
    "引导创建首个管理员"
has '"is_admin":true' "$(body)" "引导响应直接断言 is_admin"

# 引导后该账号登录，确认权限真的生效（令牌不带角色，必须重新登录）。
req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"boot@test.local","password":"CorrectHorse42!"}' > /dev/null
BOOT_TOKEN_USER="$(jget token)"
eq 200 "$(req GET /api/users -H "Authorization: Bearer ${BOOT_TOKEN_USER}")" \
    "引导出的管理员可访问受保护端点"

# 门是一次性的：已有管理员之后，正确令牌同样被拒。
eq 403 "$(req POST /api/bootstrap/admin -H 'Content-Type: application/json' \
    -d "{\"token\":\"${BOOT_TOKEN}\",\"email\":\"second@test.local\",\"username\":\"second\",\"password\":\"CorrectHorse42!\"}")" \
    "已有管理员后正确令牌也被拒"
# 且与错误令牌返回同一状态码 —— 否则失效令牌就成了「实例是否已初始化」的探针。
eq 403 "$(req POST /api/bootstrap/admin -H 'Content-Type: application/json' \
    -d '{"token":"wrong","email":"third@test.local","username":"third","password":"CorrectHorse42!"}')" \
    "已初始化后错误令牌返回同一状态码，不构成探测信道"
# 未初始化 / 已初始化，同一枚废令牌，响应必须逐字节相同 —— 状态码与 body 都是。
# 这条断言才是「引导端点不泄露部署状态」这句公开文档的真正守卫。
eq "$BOOT_REJECT_UNINIT" "$(body)" \
    "两种引导失败的响应体逐字节相同，部署状态不外泄"

group "4. 权限名前缀与 RBAC 守卫"

ADMIN_UID="$(user_id_of admin@test.local)"
grant_admin "$ADMIN_UID"

PERM_SAMPLE="$(sql "SELECT VALUE name FROM permission LIMIT 1" | python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r else '')")"
has 'soulauth:' "$PERM_SAMPLE" "库内权限名带 soulauth: 前缀"

UNPREFIXED="$(sql_count "SELECT count() FROM permission WHERE !string::starts_with(name,'soulauth:') GROUP ALL")"
eq 0 "$UNPREFIXED" "无未加前缀的残留权限"

eq 200 "$(req GET /api/rbac/roles -H "Authorization: Bearer $ADMIN_TOKEN")"          "管理员可读角色（soulauth:roles.read）"
eq 200 "$(req GET '/api/users?limit=2' -H "Authorization: Bearer $ADMIN_TOKEN")" "管理员可读用户（soulauth:users.read）"
eq 200 "$(req GET '/api/audit/dashboard?days=1' -H "Authorization: Bearer $ADMIN_TOKEN")" "管理员可读审计（soulauth:audit.read）"
eq 200 "$(req GET /api/oidc/clients -H "Authorization: Bearer $ADMIN_TOKEN")"        "管理员可读 OIDC 客户端"

PLAIN_TOKEN="$(signup plain@test.local plaintest)"
eq 403 "$(req GET /api/users -H "Authorization: Bearer $PLAIN_TOKEN")" "无权限用户被拒"
has 'soulauth:users.read' "$(body)" "拒绝信息里带命名空间前缀"

group "5. RBAC 授予与撤销的往返"

req POST /api/rbac/roles -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d '{"name":"itest","display_name":"IT","description":"d"}' > /dev/null
req POST /api/rbac/permissions -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d '{"name":"soulauth:itest.read","display_name":"ITR","resource":"itest","action":"read"}' > /dev/null

eq 204 "$(req POST /api/rbac/roles/itest/permissions/assign -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' -d '{"permission_name":"soulauth:itest.read"}')" "给角色授权限"
eq 1 "$(sql_count "SELECT count() FROM role_permission WHERE role_id IN (SELECT VALUE id FROM role WHERE name='itest') GROUP ALL")" \
    "授权确实落库"

eq 204 "$(req POST /api/rbac/roles/itest/permissions/remove -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' -d '{"permission_name":"soulauth:itest.read"}')" "撤销权限"
eq 0 "$(sql_count "SELECT count() FROM role_permission WHERE role_id IN (SELECT VALUE id FROM role WHERE name='itest') GROUP ALL")" \
    "撤销确实生效（不是只返回成功）"

group "6. OIDC 客户端与生命周期上限"

mk_client() {
    req POST /api/oidc/clients -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
        -d "{\"client_name\":\"$1\",\"client_type\":\"public\",
             \"redirect_uris\":[\"http://localhost:9000/cb\"],
             \"allowed_scopes\":[\"openid\"],
             \"allowed_grant_types\":[\"authorization_code\",\"refresh_token\"],
             \"allowed_response_types\":[\"code\"],\"require_pkce\":true
             ${2:+,\"id_token_lifetime\":$2}}" > /dev/null
}

mk_client clamp_hi 3600; eq 300 "$(jget id_token_lifetime)" "id_token_lifetime 3600 被夹到 300"
mk_client clamp_lo 60;   eq 60  "$(jget id_token_lifetime)" "id_token_lifetime 60 保持不变"
mk_client clamp_z  0;    eq 300 "$(jget id_token_lifetime)" "id_token_lifetime 0 回落到 300"

eq 404 "$(req GET /api/oidc/clients/no-such-client -H "Authorization: Bearer $ADMIN_TOKEN")" "不存在的客户端 404"
eq 404 "$(req DELETE /api/oidc/clients/no-such-client -H "Authorization: Bearer $ADMIN_TOKEN")" "禁用不存在的客户端 404（非 204）"
eq 404 "$(req POST /api/oidc/clients/no-such-client/regenerate-secret -H "Authorization: Bearer $ADMIN_TOKEN")" \
    "为不存在的客户端轮换密钥 404（非 200 + 假密钥）"

group "7. OIDC 授权码流程与 sid"

mk_client flow; CLIENT_ID="$(jget client_id)"
VERIFIER='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
CHALLENGE="$(python3 -c "
import hashlib,base64
print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")"

# 浏览器会话 cookie，authorize 靠它识别登录态
curl -sS --max-time 20 -c "$WORK/cookies" -o /dev/null \
    -X POST "${APP}/api/auth/login" -H 'Content-Type: application/json' \
    -d '{"email":"admin@test.local","password":"CorrectHorse42!"}' 2>/dev/null
EXPECT_SID="$(python3 -c "
import base64,json
tok=[l.split()[-1] for l in open('$WORK/cookies') if 'soulauth_session' in l][0]
p=tok.split('.')[1]; p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p))['sid'])" 2>/dev/null)"

AUTHZ="${APP}/api/oidc/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcb&scope=openid&state=st"
LOC="$(curl -sS --max-time 20 -b "$WORK/cookies" -o /dev/null -D - \
    "${AUTHZ}&code_challenge=${CHALLENGE}&code_challenge_method=S256" 2>/dev/null | grep -i '^location:' | tr -d '\r')"
CODE="$(printf '%s' "$LOC" | sed -n 's/.*code=\([^&]*\).*/\1/p')"
[ -n "$CODE" ] && ok "S256 授权请求签发授权码" || bad "S256 授权请求签发授权码" "$LOC"

# PKCE 降级必须在下发阶段就被拒
LOC_PLAIN="$(curl -sS --max-time 20 -b "$WORK/cookies" -o /dev/null -D - \
    "${AUTHZ}&code_challenge=${VERIFIER}&code_challenge_method=plain" 2>/dev/null | grep -i '^location:' | tr -d '\r')"
has 'error=invalid_request' "$LOC_PLAIN" "PKCE plain 被拒绝"
LOC_NOM="$(curl -sS --max-time 20 -b "$WORK/cookies" -o /dev/null -D - \
    "${AUTHZ}&code_challenge=${CHALLENGE}" 2>/dev/null | grep -i '^location:' | tr -d '\r')"
has 'error=invalid_request' "$LOC_NOM" "缺 code_challenge_method 被拒绝"

exchange() {
    req POST /api/oidc/token -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode 'grant_type=authorization_code' \
        --data-urlencode "code=$1" \
        --data-urlencode 'redirect_uri=http://localhost:9000/cb' \
        --data-urlencode "client_id=$CLIENT_ID" \
        --data-urlencode "code_verifier=$2"
}

eq 200 "$(exchange "$CODE" "$VERIFIER")" "授权码兑换成功"
ID_TOKEN="$(jget id_token)"; REFRESH="$(jget refresh_token)"

claim() {
    # 键缺失与 JSON null 都算「没有这个 claim」。
    #
    # `.get(k, '')` 只处理前者：不带 email scope 时 `email` 是 Rust 的
    # `Option::None`，序列化成 JSON null，`.get()` 取到 None 打印成字符串
    # "None" —— 断言「不含 email」于是拿到 "None" 而非空串，误报失败。
    python3 -c "
import base64,json
p='$1'.split('.')[1]; p+='='*(-len(p)%4)
v=json.loads(base64.urlsafe_b64decode(p)).get('$2')
print('' if v is None else v)" 2>/dev/null
}
eq "$EXPECT_SID" "$(claim "$ID_TOKEN" sid)" "ID Token 的 sid 等于认证会话主键"

# 这条流程申请的是 scope=openid（见上面的 AUTHZ）。ID Token 曾经无条件放
# email 与 preferred_username，而同一台服务器的 UserInfo 是按 scope 裁剪的 ——
# 同一份 claim 两套披露规则。这里把「只申请 openid 就什么身份属性都不给」钉死。
eq "" "$(claim "$ID_TOKEN" email)"              "scope=openid 的 ID Token 不含 email"
eq "" "$(claim "$ID_TOKEN" email_verified)"     "scope=openid 的 ID Token 不含 email_verified"
eq "" "$(claim "$ID_TOKEN" preferred_username)" "scope=openid 的 ID Token 不含 preferred_username"
# 协议骨架不受 scope 约束，必须始终存在。
[ -n "$(claim "$ID_TOKEN" sub)" ] && ok "scope=openid 的 ID Token 仍有 sub" ||
    bad "scope=openid 的 ID Token 仍有 sub" "sub 为空"
eq 300 "$(( $(claim "$ID_TOKEN" exp) - $(claim "$ID_TOKEN" iat) ))" "ID Token 寿命为 300 秒"
has 'RS256' "$(python3 -c "
import base64,json
p='$ID_TOKEN'.split('.')[0]; p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p))['alg'])")" "ID Token 用 RS256 签名"

eq 400 "$(exchange "$CODE" "$VERIFIER")" "同一授权码不可复用"
has 'invalid_grant' "$(body)" "复用返回 invalid_grant"

# 刷新同样签发 ID Token，sid 必须继续传递
eq 200 "$(req POST /api/oidc/token -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=refresh_token' \
    --data-urlencode "refresh_token=$REFRESH" \
    --data-urlencode "client_id=$CLIENT_ID")" "刷新令牌兑换成功"
eq "$EXPECT_SID" "$(claim "$(jget id_token)" sid)" "刷新后的 ID Token 保留同一 sid"

group "8. 认证会话缺失时拒签 ID Token（fail-closed）"

REFRESH2="$(jget refresh_token)"
sql "UPDATE oidc_refresh_token SET auth_session_ref = NONE WHERE client_id = '$CLIENT_ID'" > /dev/null
eq 400 "$(req POST /api/oidc/token -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=refresh_token' \
    --data-urlencode "refresh_token=$REFRESH2" \
    --data-urlencode "client_id=$CLIENT_ID")" "无会话引用时刷新被拒"
has 'Missing auth session reference' "$(body)" "拒绝原因明确"

group "9. OAuth 登录 CSRF 绑定"

restart_app   # 前面用掉了登录配额

HDRS="$(curl -sS --max-time 20 -o /dev/null -D - "${APP}/api/auth/login/google" 2>/dev/null)"
STATE="$(printf '%s' "$HDRS" | grep -io 'state=[^&[:space:]]*' | head -1 | cut -d= -f2 | tr -d '\r')"
NONCE="$(printf '%s' "$HDRS" | grep -io 'soulauth_oauth_state=[^;]*' | head -1 | cut -d= -f2 | tr -d '\r')"
[ -n "$NONCE" ] && ok "登录入口下发 state cookie" || bad "登录入口下发 state cookie"
has 'HttpOnly' "$HDRS" "state cookie 带 HttpOnly"

CB="/api/auth/callback/google?code=attacker-code&state=${STATE}"
eq 400 "$(req GET "$CB")" "有合法 state 但无 cookie —— 拒绝（这就是攻击场景）"
eq 400 "$(req GET "$CB" -H "Cookie: soulauth_oauth_state=00000000-0000-0000-0000-000000000000")" \
    "cookie nonce 不匹配 —— 拒绝"
eq 400 "$(req GET '/api/auth/callback/google?code=x')" "缺 state —— 拒绝"

# nonce 匹配时应越过 state 校验，止步于「拿假 code 找 Google 换令牌」
STATUS="$(req GET "$CB" -H "Cookie: soulauth_oauth_state=${NONCE}")"
has 'OAuth error' "$(body)" "nonce 匹配后越过 state 校验，止于上游兑换失败"

group "10. 账号锁定：并发失败登录不丢计数"

restart_app
sql "DELETE account_lockout" > /dev/null

PIDS=""
for _ in 1 2 3 4 5; do
    curl -sS --max-time 20 -o /dev/null -X POST "${APP}/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d '{"email":"admin@test.local","password":"WrongPassword999!"}' 2>/dev/null &
    PIDS="$PIDS $!"
done
for p in $PIDS; do wait "$p" 2>/dev/null; done   # 不能用裸 wait：会连服务进程一起等

eq 1 "$(sql_count "SELECT count() FROM account_lockout WHERE lockout_type='User' AND identifier='admin@test.local' GROUP ALL")" \
    "为该账号建立了锁定记录"
ATTEMPTS="$(sql "SELECT VALUE failed_attempts FROM account_lockout WHERE identifier='admin@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r else 0)")"
eq 5 "$ATTEMPTS" "5 次并发失败全部计入（读-改-写会丢计数）"
STATUS_L="$(sql "SELECT VALUE status FROM account_lockout WHERE identifier='admin@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r else '')")"
eq Locked "$STATUS_L" "达到阈值后置为 Locked"

group "11. 限流按路由模板计数"

restart_app

CODES=""
for i in 1 2 3 4 5 6; do
    CODES="$CODES $(req GET "/api/auth/verify-email/token-$i-$RANDOM")"
done
BLOCKED="$(printf '%s' "$CODES" | tr ' ' '\n' | grep -c 429)"
[ "$BLOCKED" -ge 1 ] &&
    ok "带路径参数的端点会被限流（每次 token 不同，共拦下 ${BLOCKED} 次）" ||
    bad "带路径参数的端点会被限流" "6 次请求无一被拦：$CODES"

group "12. 邮件投递：注册验证信"

# 这条链此前从未被验证过 —— 没有 SMTP 就只能标「无法实测」。
# 这里起一个零依赖的收信端（tests/smtp_sink.py），把整条
# 发信 → 取链接 → 验证 → 登录 走通。
#
# 信箱只增不清：断言用「收信数量的增量」，这样跑完还能用 KEEP_WORK=1
# 回看全部信件。清空信箱等于把证据自己抹掉。
MAILBOX="$WORK/mailbox.txt"
python3 "$ROOT/tests/smtp_sink.py" "$SINK_PORT" "$MAILBOX" > "$WORK/sink.log" 2>&1 &
SINK_PID=$!
disown "$SINK_PID" 2>/dev/null
sleep 1

VERIFY_EMAIL=true restart_app     # 开启邮箱验证后注册才会发信

BEFORE="$(mail_count)"
req POST /api/auth/register -H 'Content-Type: application/json' \
    -d '{"email":"mail@test.local","password":"CorrectHorse42!","username":"mailtest"}' > /dev/null
sleep 2                            # 发信走 spawn_blocking，给它落地的时间

eq "$((BEFORE + 1))" "$(mail_count)" "注册后确实发出了一封信"
eq 'Verify your email address' "$(mail_header Subject)" "主题为邮箱验证"
eq 'mail@test.local' "$(mail_header To)" "收件人正确"

VBODY="$(mail_body)"
case "$VBODY" in
    *CorrectHorse42*)                   bad "邮件不含用户密码" "正文里出现了明文密码" ;;
    *0123456789abcdef0123456789abcdef*) bad "邮件不含 JWT_SECRET" "正文里出现了签名密钥" ;;
    *)                                  ok "邮件不含密码与签名密钥" ;;
esac

VTOKEN="$(printf '%s' "$VBODY" | grep -oE 'token=[A-Za-z0-9-]+' | head -1 | cut -d= -f2)"
[ -n "$VTOKEN" ] && ok "验证链接里带 token" || bad "验证链接里带 token" "$VBODY"

# 库里存的是指纹，不是令牌本身。这条断言因此反过来：
# 明文一个字都不许留，而指纹必须与邮件里那枚对得上（对得上才说明链接可用）。
DBHASH="$(sql "SELECT VALUE verification_token_hash FROM user WHERE email='mail@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r and r[0] else '')")"
eq "$(bearer_hash "$VTOKEN")" "$DBHASH" "库里的指纹与邮件令牌对得上"
[ "$DBHASH" != "$VTOKEN" ] && ok "验证令牌不以明文落库" || bad "验证令牌明文落库" "$DBHASH"

eq 401 "$(req GET /api/auth/verify-email/deadbeef-not-a-real-token)" "伪造的验证 token 被拒"
eq 200 "$(req GET "/api/auth/verify-email/${VTOKEN}")" "真实 token 完成验证"

VERIFIED="$(sql "SELECT VALUE verified FROM user WHERE email='mail@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(str(r[0]).lower() if r else 'none')")"
eq true "$VERIFIED" "验证状态确实落库"

group "13. 邮件投递：密码重置信"

# 第 9 组是故意把 127.0.0.1 打到 IP 锁定的。锁定记录在库里，重启服务不会清，
# 而被锁时登录返回 429 —— 不清掉的话，本组的登录断言全成假阳性。
sql "DELETE account_lockout" > /dev/null
restart_app                          # 重置端点限流 3 次/15 分钟

BEFORE="$(mail_count)"
req POST /api/auth/request-password-reset -H 'Content-Type: application/json' \
    -d '{"email":"mail@test.local"}' > /dev/null
sleep 2
eq "$((BEFORE + 1))" "$(mail_count)" "申请重置后发出一封信"
eq 'Reset your password' "$(mail_header Subject)" "主题为密码重置"

# 重置链接是 {app_url}/reset-password/{token} 的路径形式，与验证信的 ?token= 不同
RBODY="$(mail_body)"
RTOKEN="$(printf '%s' "$RBODY" | grep -oE 'reset-password/[A-Za-z0-9-]+' | head -1 | cut -d/ -f2)"
[ -n "$RTOKEN" ] && ok "重置链接里带 token" || bad "重置链接里带 token" "$RBODY"

# 未注册邮箱不得发信，也不得因此暴露账号是否存在
BEFORE="$(mail_count)"
eq 200 "$(req POST /api/auth/request-password-reset -H 'Content-Type: application/json' \
    -d '{"email":"nobody-here@test.local"}')" "未注册邮箱同样返回 200（防枚举）"
sleep 1
eq "$BEFORE" "$(mail_count)" "未注册邮箱不发信"

eq 200 "$(req POST /api/auth/reset-password -H 'Content-Type: application/json' \
    -d "{\"token\":\"${RTOKEN}\",\"new_password\":\"BrandNewHorse43!\"}")" "用邮件里的 token 重置密码"
eq 401 "$(req POST /api/auth/reset-password -H 'Content-Type: application/json' \
    -d "{\"token\":\"${RTOKEN}\",\"new_password\":\"AnotherHorse44!\"}")" "同一 token 不可复用"

restart_app                          # 登录限流
eq 200 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"mail@test.local","password":"BrandNewHorse43!"}')" "可用新密码登录"
eq 401 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"mail@test.local","password":"CorrectHorse42!"}')" "旧密码已失效"

kill -9 "$SINK_PID" 2>/dev/null; SINK_PID=""

group "14. OAuth 回调：换到令牌之后的整段"

# 这一段此前完全没有覆盖：第 8 组只验到「拿假 code 去换令牌然后失败」，
# 再往后 —— 取用户信息、按邮箱验证状态放行、建号还是关联既有账号 ——
# 因为端点写死在代码里而无从下手。现在指向本地替身走完整条链。
python3 "$ROOT/tests/mock_oauth.py" "$OAUTH_PORT" > "$WORK/mock_oauth.log" 2>&1 &
MOCK_PID=$!
disown "$MOCK_PID" 2>/dev/null
sleep 1

sql "DELETE account_lockout" > /dev/null
OAUTH_BASE="http://127.0.0.1:${OAUTH_PORT}" restart_app

# 走一趟登录入口拿到配对的 state 与 cookie nonce（机制已在第 8 组验过）
oauth_callback() {   # $1=provider  $2=code  → 打印状态码
    local hdrs state nonce
    hdrs="$(curl -sS --max-time 20 -o /dev/null -D - "${APP}/api/auth/login/$1" 2>/dev/null)"
    state="$(printf '%s' "$hdrs" | grep -io 'state=[^&[:space:]]*' | head -1 | cut -d= -f2 | tr -d '\r')"
    nonce="$(printf '%s' "$hdrs" | grep -io 'soulauth_oauth_state=[^;]*' | head -1 | cut -d= -f2 | tr -d '\r')"
    req GET "/api/auth/callback/$1?code=$2&state=${state}" \
        -H "Cookie: soulauth_oauth_state=${nonce}" -D "$WORK/cb_headers"
}

# 回调成功走的是 303 See Other（axum `Redirect::to` 的既定状态码），不是 302。
redirected() {   # $1=描述
    local status="$2"
    if [ "$status" != 303 ]; then
        bad "$1" "期望 303 See Other，实际 $status"
        return
    fi
    # 重定向目标必须落在本服务的 app_url 之内。登录入口只接受本服务签发的
    # state，任意 return_to 进不来 —— 这条断言就是把该性质钉住，
    # 免得哪天入口放宽了、签名反而成了对攻击者 URL 的背书。
    local loc
    loc="$(grep -i '^location:' "$WORK/cb_headers" | head -1 | cut -d' ' -f2- | tr -d '\r')"
    case "$loc" in
        "$APP"/*) ok "$1（→ ${loc#$APP})" ;;
        *)        bad "$1" "重定向到了本服务之外：$loc" ;;
    esac
}

user_count() { sql_count "SELECT count() FROM user WHERE email='$1' GROUP ALL"; }
link_count() {
    sql_count "SELECT count() FROM identity_provider WHERE provider='$1' AND provider_user_id='$2' GROUP ALL"
}

# —— Google：新用户 ——
redirected "Google 回调成功后重定向" "$(oauth_callback google google-ok)"
eq 1 "$(user_count oauth-new@test.local)" "为新的 Google 用户建了账号"
eq 1 "$(link_count google google-uid-1)" "建立了 identity_provider 关联"

# 同一账号再来一次：必须复用，不能又建一个
redirected "同一 Google 账号二次登录" "$(oauth_callback google google-ok)"
eq 1 "$(user_count oauth-new@test.local)" "二次登录不重复建号"
eq 1 "$(link_count google google-uid-1)" "二次登录不重复建关联"

# —— Google：邮箱未验证必须拒绝 ——
# 放行的话，任何人在 provider 侧填一个未验证的他人邮箱就能顶号
eq 403 "$(oauth_callback google google-unverified)" "Google 邮箱未验证 → 拒绝"
eq 0 "$(user_count oauth-unverified@test.local)" "被拒的登录不留下账号"
eq 0 "$(link_count google google-uid-2)" "被拒的登录不留下关联"

# —— Google：邮箱撞上既有本地账号 → 关联，不新建 ——
BEFORE_ADMIN="$(user_count admin@test.local)"
redirected "邮箱已存在的 Google 登录成功" "$(oauth_callback google google-existing)"
eq "$BEFORE_ADMIN" "$(user_count admin@test.local)" "关联到既有账号而非新建重复账号"
eq 1 "$(link_count google google-uid-3)" "为既有账号补上了 Google 关联"

# —— GitHub：登录入口与回调 ——
# 入口要下发 state cookie 并重定向到（被覆盖后的）授权端点
GH_HDRS="$(curl -sS --max-time 20 -o /dev/null -D - "${APP}/api/auth/login/github" 2>/dev/null)"
has 'soulauth_oauth_state' "$GH_HDRS" "GitHub 登录入口下发 state cookie"
case "$GH_HDRS" in
    *"127.0.0.1:${OAUTH_PORT}/login/oauth/authorize"*)
        ok "GitHub 授权地址走的是被覆盖的端点（路径形状与真实 GitHub 一致）" ;;
    *)  bad "GitHub 授权地址走的是被覆盖的端点" "$(printf '%s' "$GH_HDRS" | grep -i '^location:')" ;;
esac

# —— GitHub：主邮箱取自 /user/emails ——
redirected "GitHub 回调成功后重定向" "$(oauth_callback github github-ok)"
eq 1 "$(user_count oauth-gh@test.local)" "取的是 primary+verified 那个邮箱"
eq 0 "$(user_count noreply@users.github.test)" "非 primary 的邮箱未被采用"
eq 1 "$(link_count github 4001)" "建立了 GitHub 关联"

# —— GitHub：无已验证主邮箱必须拒绝 ——
# 回调路径：/api/auth/callback/github（由 oauth_callback 拼出）
eq 403 "$(oauth_callback github github-unverified)" "GitHub 无已验证主邮箱 → 拒绝"
eq 0 "$(user_count gh-unverified@test.local)" "被拒的 GitHub 登录不留下账号"

# —— 无效授权码：上游 400，本服务不得当成成功 ——
STATUS="$(oauth_callback google definitely-not-a-code)"
[ "$STATUS" != 303 ] && ok "上游拒绝授权码时本服务不放行（${STATUS}）" ||
    bad "上游拒绝授权码时本服务不放行" "竟然签发了会话并重定向"

kill -9 "$MOCK_PID" 2>/dev/null; MOCK_PID=""

group "15. 登出与会话吊销"

# 「登出返回 200」什么也证明不了 —— 要证明的是**那个令牌真的不能再用了**。
# 这一段直接关系 OS 接入：OS 拿 sid 指向的会话做判断，注销做不干净就是安全洞。
restart_app
sql "DELETE account_lockout" > /dev/null

login_token() {   # $1=邮箱 $2=密码 → 打印 access_token（拿不到则空）
    req POST /api/auth/login -H 'Content-Type: application/json' \
        -d "{\"email\":\"$1\",\"password\":\"$2\"}" > /dev/null
    jget token
}

TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
[ -n "$TOK_A" ] && ok "登录拿到令牌" || bad "登录拿到令牌" "$(body)"
eq 200 "$(req GET /api/auth/me -H "Authorization: Bearer ${TOK_A}")" "令牌可用"
eq 200 "$(req GET /api/auth/sessions -H "Authorization: Bearer ${TOK_A}")" "可列出自己的会话"
eq 401 "$(req GET /api/auth/sessions)" "无令牌列会话 → 401"

eq 200 "$(req POST /api/auth/logout -H "Authorization: Bearer ${TOK_A}")" "登出返回成功"
eq 401 "$(req GET /api/auth/me -H "Authorization: Bearer ${TOK_A}")" "登出后原令牌立即失效（不等缓存 TTL）"

# logout-all：签两个令牌，注销后两个都得死
TOK_B="$(login_token admin@test.local "CorrectHorse42!")"
TOK_C="$(login_token admin@test.local "CorrectHorse42!")"
[ -n "$TOK_B" ] && [ -n "$TOK_C" ] && [ "$TOK_B" != "$TOK_C" ] &&
    ok "两次登录得到两个不同令牌" || bad "两次登录得到两个不同令牌" "B=${TOK_B:0:12} C=${TOK_C:0:12}"

eq 200 "$(req POST /api/auth/logout-all -H "Authorization: Bearer ${TOK_B}")" "全端登出返回成功"
eq 401 "$(req GET /api/auth/me -H "Authorization: Bearer ${TOK_B}")" "发起方令牌失效"
eq 401 "$(req GET /api/auth/me -H "Authorization: Bearer ${TOK_C}")" "另一条会话的令牌同样失效"

group "16. MFA 全生命周期（真实 TOTP）"

# 之前只有单测级的 last_totp_step 水位线，整条链路没端到端跑过。
# 这里用 RFC 6238 算真码（tests/totp.py，已用标准向量自校）。
restart_app

MFA_MAIL="mfa@test.local"
MFA_PW="CorrectHorse42!"
req POST /api/auth/register -H 'Content-Type: application/json' \
    -d "{\"email\":\"${MFA_MAIL}\",\"password\":\"${MFA_PW}\",\"username\":\"mfauser\"}" > /dev/null
TOK="$(login_token "$MFA_MAIL" "$MFA_PW")"
[ -n "$TOK" ] && ok "MFA 测试账号登录成功" || bad "MFA 测试账号登录成功" "$(body)"

req GET /api/auth/mfa/status -H "Authorization: Bearer ${TOK}" > /dev/null
eq false "$(jget enabled)" "初始未开启 MFA"

eq 200 "$(req POST /api/auth/mfa/setup -H "Authorization: Bearer ${TOK}")" "setup 返回成功"
SECRET="$(jget secret)"
BACKUP="$(python3 -c "
import json;d=json.load(open('$WORK/body'));c=d.get('backup_codes') or [];print(c[0] if c else '')" 2>/dev/null)"
[ -n "$SECRET" ] && ok "setup 下发了 TOTP 密钥" || bad "setup 下发了 TOTP 密钥" "$(body)"
[ -n "$BACKUP" ] && ok "setup 下发了备用码" || bad "setup 下发了备用码" "$(body)"

# 还没 enable 时不算开启 —— setup 只是备好，别把「拿到密钥」当成「已启用」
req GET /api/auth/mfa/status -H "Authorization: Bearer ${TOK}" > /dev/null
eq false "$(jget enabled)" "仅 setup 尚未启用"

eq 400 "$(req POST /api/auth/mfa/enable -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' -d '{"totp_code":"000000"}')" "错误验证码不能启用"

# 用**上一个**时间窗的码启用，把水位线压在 S-1；
# 这样下面用当前窗口的码登录时不会被自己的水位线挡住，且全程无需 sleep。
# 避开时间窗边界。守卫必须紧挨着取码：中间若还夹着几个 HTTP 往返而恰好跨了窗口，
# CODE_PREV 就落到当前窗口的 2 个之外，会被 ±1 的容差挡掉，测试变成偶发失败。
INTO="$(python3 "$ROOT/tests/totp.py" --seconds-into-step)"
awk -v v="$INTO" 'BEGIN{exit !(v > 22)}' && sleep 9

CODE_PREV="$(python3 "$ROOT/tests/totp.py" "$SECRET" -1)"
eq 200 "$(req POST /api/auth/mfa/enable -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' -d "{\"totp_code\":\"${CODE_PREV}\"}")" "真实验证码启用 MFA"

req GET /api/auth/mfa/status -H "Authorization: Bearer ${TOK}" > /dev/null
eq true "$(jget enabled)" "状态显示已启用"

# 开启后登录必须停在 MFA 挑战，而不是直接发会话令牌
req POST /api/auth/login -H 'Content-Type: application/json' \
    -d "{\"email\":\"${MFA_MAIL}\",\"password\":\"${MFA_PW}\"}" > /dev/null
eq true "$(jget mfa_required)" "开启后登录要求补 MFA"
TEMP="$(jget temp_token)"
[ -n "$TEMP" ] && ok "下发了挑战令牌" || bad "下发了挑战令牌" "$(body)"
[ -z "$(jget token)" ] && ok "挑战阶段不下发会话令牌" || bad "挑战阶段不下发会话令牌" "竟然直接给了 token"

eq 401 "$(req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP}\",\"totp_code\":\"000000\"}")" "错误验证码不能过 MFA"

CODE_NOW="$(python3 "$ROOT/tests/totp.py" "$SECRET" 0)"
req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP}\",\"totp_code\":\"${CODE_NOW}\"}" > /dev/null
[ -n "$(jget token)" ] && ok "真实验证码完成 MFA 登录" || bad "真实验证码完成 MFA 登录" "$(body)"

# 重放：同一个码不得再用一次（last_totp_step 水位线）
req POST /api/auth/login -H 'Content-Type: application/json' \
    -d "{\"email\":\"${MFA_MAIL}\",\"password\":\"${MFA_PW}\"}" > /dev/null
TEMP2="$(jget temp_token)"
eq 401 "$(req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP2}\",\"totp_code\":\"${CODE_NOW}\"}")" "同一验证码不可重放"
eq 401 "$(req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP2}\",\"totp_code\":\"${CODE_PREV}\"}")" "更早窗口的码同样被水位线挡住"

# 备用码：能用一次，且只能用一次
req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP2}\",\"backup_code\":\"${BACKUP}\"}" > /dev/null
TOK_MFA="$(jget token)"
[ -n "$TOK_MFA" ] && ok "备用码可完成登录" || bad "备用码可完成登录" "$(body)"

restart_app   # login / login-verify 共用登录限流，前面已用满，不重启就测成 429
req POST /api/auth/login -H 'Content-Type: application/json' \
    -d "{\"email\":\"${MFA_MAIL}\",\"password\":\"${MFA_PW}\"}" > /dev/null
TEMP3="$(jget temp_token)"
eq 401 "$(req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP3}\",\"backup_code\":\"${BACKUP}\"}")" "同一备用码不可复用"

CODE_OFF="$(python3 "$ROOT/tests/totp.py" "$SECRET" 1)"
eq 200 "$(req POST /api/auth/mfa/disable -H "Authorization: Bearer ${TOK_MFA}" \
    -H 'Content-Type: application/json' -d "{\"totp_code\":\"${CODE_OFF}\"}")" "可用验证码关闭 MFA"
req GET /api/auth/mfa/status -H "Authorization: Bearer ${TOK_MFA}" > /dev/null
eq false "$(jget enabled)" "关闭后状态归位"

group "17. 用户资料与偏好"

restart_app
sql "DELETE account_lockout" > /dev/null

TOK_P="$(login_token plain@test.local "CorrectHorse42!")"
TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
PLAIN_UID="$(user_id_of plain@test.local)"
ADMIN_UID="$(user_id_of admin@test.local)"

# 已知缺陷：资料/偏好在 POST 建立之前读取返回 404 而不是空对象。
# 这里把现状钉住 —— 哪天改成返回空对象，这条会红，提醒同步前端与文档。
eq 404 "$(req GET /api/me/profile -H "Authorization: Bearer ${TOK_P}")" \
    "尚未建立时读资料 → 404（现状，非空对象）"

eq 200 "$(req POST /api/me/profile -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"display_name":"Plain User","bio":"hello"}')" "建立资料"
req GET /api/me/profile -H "Authorization: Bearer ${TOK_P}" > /dev/null
has 'Plain User' "$(body)" "读回自己的资料"

eq 200 "$(req PUT /api/me/profile -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"display_name":"Renamed","bio":"updated"}')" "更新资料"
req GET /api/me/profile -H "Authorization: Bearer ${TOK_P}" > /dev/null
has 'Renamed' "$(body)" "更新确实落库（不是只返回成功）"

eq 200 "$(req POST /api/me/preferences -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"language":"zh-CN","timezone":"Asia/Shanghai"}')" "建立偏好"
eq 200 "$(req PUT /api/me/preferences -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"language":"en-US","timezone":"UTC"}')" "更新偏好"
req GET /api/me/preferences -H "Authorization: Bearer ${TOK_P}" > /dev/null
has 'en-US' "$(body)" "偏好更新落库"

eq 200 "$(req GET /api/me/activity-log -H "Authorization: Bearer ${TOK_P}")" "可读自己的活动日志"
eq 401 "$(req GET /api/me/profile)" "无令牌读资料 → 401"

# 跨用户读取：本人之外一律要权限
eq 200 "$(req GET "/api/users/${PLAIN_UID}/profile" -H "Authorization: Bearer ${TOK_A}")" \
    "管理员可读他人资料（users.read）"
eq 403 "$(req GET "/api/users/${ADMIN_UID}/profile" -H "Authorization: Bearer ${TOK_P}")" \
    "无 users.read 读不了他人资料"
eq 403 "$(req GET "/api/users/${ADMIN_UID}/preferences" -H "Authorization: Bearer ${TOK_P}")" \
    "无 users.read 读不了他人偏好"
eq 403 "$(req GET "/api/users/${ADMIN_UID}/activity-log" -H "Authorization: Bearer ${TOK_P}")" \
    "无 audit.read 读不了他人活动日志"
eq 200 "$(req GET "/api/users/${PLAIN_UID}" -H "Authorization: Bearer ${TOK_A}")" "管理员可按 id 读用户"
eq 403 "$(req GET "/api/users/${ADMIN_UID}" -H "Authorization: Bearer ${TOK_P}")" "普通用户按 id 读不了他人"

group "18. 账号状态与会员等级：越权与即时失效"

restart_app

TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
VICTIM_TOKEN="$(signup victim@test.local victimtest)"
VICTIM_UID="$(user_id_of victim@test.local)"
[ -n "$VICTIM_TOKEN" ] && ok "受害账号建立并登录" || bad "受害账号建立并登录" "$(body)"

# 越权：普通用户不得改任何人的状态，包括自己
eq 403 "$(req PUT "/api/users/${VICTIM_UID}/status" -H "Authorization: Bearer ${VICTIM_TOKEN}" \
    -H 'Content-Type: application/json' -d '{"status":"Active","reason":"self"}')" \
    "无 users.write 改不了自己的状态"
eq 403 "$(req PUT "/api/users/${VICTIM_UID}/membership" -H "Authorization: Bearer ${VICTIM_TOKEN}" \
    -H 'Content-Type: application/json' -d '{"membership_level":"PRO"}')" \
    "无 users.write 不能自封会员等级"

# 会员等级由管理员改，且要真的落库
eq 200 "$(req PUT "/api/users/${VICTIM_UID}/membership" -H "Authorization: Bearer ${TOK_A}" \
    -H 'Content-Type: application/json' -d '{"membership_level":"PRO"}')" "管理员可改会员等级"
LEVEL="$(sql "SELECT VALUE membership_level FROM user WHERE email='victim@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r else '')")"
eq PRO "$LEVEL" "会员等级确实落库"

# 停用之后，**已经签发的令牌必须立刻失效**。
# 这是本组的核心：只清缓存而不在校验时看状态，被停用的人还能继续用到令牌自然过期。
eq 200 "$(req GET /api/auth/me -H "Authorization: Bearer ${VICTIM_TOKEN}")" "停用前令牌可用"
eq 200 "$(req PUT "/api/users/${VICTIM_UID}/status" -H "Authorization: Bearer ${TOK_A}" \
    -H 'Content-Type: application/json' -d '{"status":"Suspended","reason":"itest"}')" "管理员停用该账号"
# 停用后的判定用显式 if：`[ A ] || [ B ] && ok || bad` 在 shell 里是
# 左结合的等优先级串联，读起来像三元表达式，实际语义靠碰巧。
STATUS="$(req GET /api/auth/me -H "Authorization: Bearer ${VICTIM_TOKEN}")"
if [ "$STATUS" = 401 ] || [ "$STATUS" = 403 ]; then
    ok "停用后原令牌立即失效（${STATUS}）"
else
    bad "停用后原令牌立即失效" "竟然仍可用：${STATUS}"
fi

# 被停用的账号也不能重新登录
eq 403 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"victim@test.local","password":"CorrectHorse42!"}')" "被停用账号无法重新登录"

# 库里被写进未知状态时必须按不可用处理（fail-closed 白名单）
sql "UPDATE user SET account_status = 'SomeFutureStatus' WHERE email = 'victim@test.local'" > /dev/null
restart_app
eq 403 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"victim@test.local","password":"CorrectHorse42!"}')" \
    "未知账号状态按不可用处理（未列白名单即拒）"

group "19. RBAC 用户侧授权与权限查询"

restart_app

TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
TOK_P="$(login_token plain@test.local "CorrectHorse42!")"
PLAIN_UID="$(user_id_of plain@test.local)"

# 自查端点只看自己，不接受目标用户参数
req GET "/api/rbac/check/permission/soulauth:users.read" -H "Authorization: Bearer ${TOK_A}" > /dev/null
eq true "$(jget has_permission)" "管理员自查 users.read → 有"
req GET "/api/rbac/check/permission/soulauth:users.read" -H "Authorization: Bearer ${TOK_P}" > /dev/null
eq false "$(jget has_permission)" "普通用户自查 users.read → 无"
req GET "/api/rbac/check/role/admin" -H "Authorization: Bearer ${TOK_P}" > /dev/null
eq false "$(jget has_role)" "普通用户自查 admin 角色 → 无"
eq 401 "$(req GET "/api/rbac/check/role/admin")" "自查端点仍需登录"

eq 200 "$(req GET "/api/rbac/permissions/soulauth:users.read" -H "Authorization: Bearer ${TOK_A}")" "可按名读取权限详情"
eq 403 "$(req GET "/api/rbac/permissions/soulauth:users.read" -H "Authorization: Bearer ${TOK_P}")" \
    "无 permissions.read 读不了权限详情"

# 越权：普通用户不得给自己授角色
eq 403 "$(req POST "/api/rbac/users/${PLAIN_UID}/roles/assign" -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"role_name":"admin"}')" \
    "无 roles.write 不能给自己授 admin（提权面）"
eq 0 "$(sql_count "SELECT count() FROM user_role WHERE user_id = (SELECT VALUE subject_id FROM type::record('user','${PLAIN_UID}'))[0] AND role_id = role:admin GROUP ALL")" \
    "越权尝试没有留下任何授权记录"

# 管理员授角色，且要落库、可查、可撤
eq 204 "$(req POST "/api/rbac/users/${PLAIN_UID}/roles/assign" -H "Authorization: Bearer ${TOK_A}" \
    -H 'Content-Type: application/json' -d '{"role_name":"user"}')" "管理员给用户授角色"
eq 1 "$(sql_count "SELECT count() FROM user_role WHERE user_id = (SELECT VALUE subject_id FROM type::record('user','${PLAIN_UID}'))[0] AND role_id = role:user GROUP ALL")" \
    "授权确实落库"
req GET "/api/rbac/users/${PLAIN_UID}/roles" -H "Authorization: Bearer ${TOK_A}" > /dev/null
has 'user' "$(body)" "角色列表里能查到"
eq 200 "$(req GET "/api/rbac/users/${PLAIN_UID}/permissions" -H "Authorization: Bearer ${TOK_A}")" "可查该用户的权限集合"
# 查自己的角色不需要额外权限（handler 里有 self 放行），查别人才要 users.read
eq 200 "$(req GET "/api/rbac/users/${PLAIN_UID}/roles" -H "Authorization: Bearer ${TOK_P}")" \
    "查自己的角色无需额外权限"
ADMIN_UID="$(user_id_of admin@test.local)"
eq 403 "$(req GET "/api/rbac/users/${ADMIN_UID}/roles" -H "Authorization: Bearer ${TOK_P}")" \
    "无 users.read 查不了他人角色"

eq 204 "$(req POST "/api/rbac/users/${PLAIN_UID}/roles/remove" -H "Authorization: Bearer ${TOK_A}" \
    -H 'Content-Type: application/json' -d '{"role_name":"user"}')" "管理员撤销角色"
eq 0 "$(sql_count "SELECT count() FROM user_role WHERE user_id = (SELECT VALUE subject_id FROM type::record('user','${PLAIN_UID}'))[0] AND role_id = role:user GROUP ALL")" \
    "撤销确实生效（不是只返回成功）"

group "20. 限流跨副本合账"

# 这条性质**只能用两个真实进程验**：单进程里怎么测都测不出「各副本各算各的」。
# 起第二个副本，与第一个共用同一个数据库，配置完全一致 —— 就是生产上
# 挂在负载均衡后面的样子。
restart_app
sql "DELETE account_lockout" > /dev/null
sql "DELETE rate_limit" > /dev/null

APP2="http://127.0.0.1:${APP2_PORT}"
(
    cd "$ROOT"
    DATABASE_URL="127.0.0.1:${SURREAL_PORT}" \
    DATABASE_USER=root DATABASE_PASS=root \
    DATABASE_NAMESPACE=auth DATABASE_NAME=main \
    JWT_SECRET=0123456789abcdef0123456789abcdef \
    GOOGLE_CLIENT_ID=dummy GOOGLE_CLIENT_SECRET=dummy \
    GITHUB_CLIENT_ID=dummy GITHUB_CLIENT_SECRET=dummy \
    OAUTH_REDIRECT_URL="${APP2}/api/auth/callback" \
    SMTP_HOST=127.0.0.1 SMTP_PORT="${SINK_PORT}" SMTP_FROM=noreply@example.com \
    SMTP_INSECURE=true APP_URL="$APP2" \
    BIND_ADDR="127.0.0.1:${APP2_PORT}" RUST_LOG=soulauth=warn \
    exec ./target/debug/soulauth
) > "$WORK/app2.log" 2>&1 &
APP2_PID=$!
disown "$APP2_PID" 2>/dev/null
for _ in $(seq 1 40); do
    curl -sS --max-time 2 -o /dev/null "${APP2}/api/oidc/jwks" 2>/dev/null && break
    sleep 0.5
done
curl -sS --max-time 2 -o /dev/null "${APP2}/api/oidc/jwks" 2>/dev/null &&
    ok "第二副本已就绪" || { bad "第二副本已就绪" "$(tail -5 "$WORK/app2.log")"; }

# 在副本 1 上把登录配额打满（5 次/5 分钟）
CODES1=""
for i in 1 2 3 4 5; do
    CODES1="$CODES1 $(req POST /api/auth/login -H 'Content-Type: application/json' \
        -d '{"email":"nobody@test.local","password":"WrongPassword999!"}')"
done
case "$CODES1" in *429*) bad "副本1 前 5 次不该被限流" "$CODES1" ;; *) ok "副本1 用满 5 次配额" ;; esac
eq 429 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"nobody@test.local","password":"WrongPassword999!"}')" "副本1 第 6 次被限流"

# 核心断言：换到副本 2 也必须被拦。
# 不共享的话副本 2 的计数是 0，会照常放行 —— 攻击者摊到 N 个副本上就有 N 倍配额。
CODE2="$(curl -sS --max-time 25 -o /dev/null -w '%{http_code}' \
    -X POST "${APP2}/api/auth/login" -H 'Content-Type: application/json' \
    -d '{"email":"nobody@test.local","password":"WrongPassword999!"}' 2>/dev/null)"
eq 429 "$CODE2" "换到第二副本同样被拦（配额跨副本合账）"

# 计数确实落在共享表里，而不是各存各的
SHARED_ROWS="$(sql_count "SELECT count() FROM rate_limit WHERE endpoint = '/api/auth/login' GROUP ALL")"
eq 1 "$SHARED_ROWS" "两个副本共用同一个计数桶（只有一条记录）"

# 一般 API 走进程内，不该在共享表里留记录 —— 否则等于给每个请求加一次库写
req GET /api/auth/me > /dev/null
eq 0 "$(sql_count "SELECT count() FROM rate_limit WHERE endpoint = '/api/auth/me' GROUP ALL")" \
    "默认规则的端点不写共享表（热路径不加数据库往返）"

kill -9 "$APP2_PID" 2>/dev/null; APP2_PID=""

group "21. 审计 / OIDC userinfo / 管理端剩余端点"

# 这批端点此前只手工 curl 验过（当时还从中揪出过 security-report 的 500），
# 一直没进自动化 = 没有回归保护。补上。
#
# 关键：**必须在有数据的情况下验**。空表上跑这些统计接口一律返回 200，
# 什么也证明不了 —— 上次那个 500 正是把表填上之后才暴露的。
restart_app
sql "DELETE account_lockout" > /dev/null

TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
TOK_P="$(login_token plain@test.local "CorrectHorse42!")"

# 造点审计数据：几次失败登录 + 几次成功请求
for _ in 1 2 3; do
    req POST /api/auth/login -H 'Content-Type: application/json' \
        -d '{"email":"admin@test.local","password":"WrongPassword999!"}' > /dev/null
done
sleep 1   # 审计是异步落库的，给它一点时间
ACT_ROWS="$(sql_count "SELECT count() FROM user_activity GROUP ALL")"
[ "${ACT_ROWS:-0}" -gt 0 ] && ok "审计表里确实有数据（${ACT_ROWS} 条），统计接口不是在空集上跑" ||
    bad "审计表里确实有数据" "仍是空表，后面的断言证明不了任何事"

restart_app   # 上面把登录配额用掉了
TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
TOK_P="$(login_token plain@test.local "CorrectHorse42!")"

eq 200 "$(req GET /api/audit/dashboard -H "Authorization: Bearer ${TOK_A}")" "审计看板"
eq 200 "$(req GET /api/audit/activity-summary -H "Authorization: Bearer ${TOK_A}")" "活动摘要"
eq 200 "$(req GET /api/audit/security-report -H "Authorization: Bearer ${TOK_A}")" "安全报告（有数据时）"
eq 200 "$(req GET /api/audit/security-metrics -H "Authorization: Bearer ${TOK_A}")" "安全指标"
eq 200 "$(req GET /api/audit/system-health -H "Authorization: Bearer ${TOK_A}")" "系统健康"

eq 403 "$(req GET /api/audit/activity-summary -H "Authorization: Bearer ${TOK_P}")" "无 audit.read 看不了活动摘要"
eq 403 "$(req GET /api/audit/security-metrics -H "Authorization: Bearer ${TOK_P}")" "无 security.read 看不了安全指标"
eq 403 "$(req GET /api/audit/system-health -H "Authorization: Bearer ${TOK_P}")" "无 security.read 看不了系统健康"
eq 401 "$(req GET /api/audit/security-report)" "无令牌看不了安全报告"

# system-health 报的运行时长必须是真的（曾经写死过 3600）
req GET /api/audit/system-health -H "Authorization: Bearer ${TOK_A}" > /dev/null
case "$(body)" in *3600*) bad "运行时长不是写死的 3600" "$(body)" ;; *) ok "运行时长不是写死的 3600" ;; esac

eq 200 "$(req GET /api/ops/memberships/overview -H "Authorization: Bearer ${TOK_A}")" "会员总览"
eq 403 "$(req GET /api/ops/memberships/overview -H "Authorization: Bearer ${TOK_P}")" "无 users.read 看不了会员总览"

# OIDC userinfo：只认 OIDC 访问令牌，不认普通会话令牌
eq 401 "$(req GET /api/oidc/userinfo)" "userinfo 无令牌 → 401"
eq 401 "$(req GET /api/oidc/userinfo -H "Authorization: Bearer ${TOK_A}")" \
    "userinfo 不接受普通会话令牌（两套令牌不可混用）"
eq 401 "$(req GET /api/oidc/userinfo -H 'Authorization: Bearer not-a-real-token')" "userinfo 拒伪造令牌"

# OIDC 登出端点：无参数也应给出可用响应，不得 5xx
LOGOUT_CODE="$(req GET /api/oidc/logout)"
case "$LOGOUT_CODE" in 5*) bad "OIDC 登出端点不 5xx" "返回 $LOGOUT_CODE" ;; *) ok "OIDC 登出端点不 5xx（${LOGOUT_CODE}）" ;; esac

# 管理后台登录：普通用户即使密码对也不得放行
eq 200 "$(req POST /api/auth/admin/login -H 'Content-Type: application/json' \
    -d '{"email":"admin@test.local","password":"CorrectHorse42!"}')" "管理员可走后台登录"
ADMIN_ONLY="$(req POST /api/auth/admin/login -H 'Content-Type: application/json' \
    -d '{"email":"plain@test.local","password":"CorrectHorse42!"}')"
[ "$ADMIN_ONLY" = 403 ] || [ "$ADMIN_ONLY" = 401 ] &&
    ok "普通用户走不了后台登录（${ADMIN_ONLY}）" ||
    bad "普通用户走不了后台登录" "竟然返回 ${ADMIN_ONLY}"

# initialize-password 只为「OAuth 建号、尚无密码」的用户设首个密码。
# 已经有密码的账号必须拒绝 —— 否则拿到一个会话就能绕过旧密码校验直接改密。
restart_app
TOK_P="$(login_token plain@test.local "CorrectHorse42!")"
eq 401 "$(req POST /api/auth/initialize-password -H 'Content-Type: application/json' \
    -d '{"password":"BrandNewHorse43!"}')" "initialize-password 需要登录"
STATUS_IP="$(req POST /api/auth/initialize-password -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"password":"BrandNewHorse43!"}')"
if [ "$STATUS_IP" != 200 ]; then
    ok "已有密码的账号不能走 initialize-password（${STATUS_IP}）"
else
    bad "已有密码的账号不能走 initialize-password" "竟然放行了，等于绕过旧密码校验改密"
fi
# 确认旧密码仍然有效 —— 上面那次调用不得产生任何副作用
restart_app
eq 200 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"plain@test.local","password":"CorrectHorse42!"}')" "被拒的调用没有改掉原密码"

group "22. 不配第三方登录也能独立跑"

# 以前这四个凭证是硬必填，只用邮箱密码的部署被迫在配置里填 dummy ——
# 而配置里的假数据一旦被当真就是事故。这组验「不填也能跑」。
kill -9 "$APP_PID" 2>/dev/null
sleep 0.5
sql "DELETE rate_limit" > /dev/null 2>&1
(
    cd "$ROOT"
    DATABASE_URL="127.0.0.1:${SURREAL_PORT}" \
    DATABASE_USER=root DATABASE_PASS=root \
    DATABASE_NAMESPACE=auth DATABASE_NAME=main \
    JWT_SECRET=0123456789abcdef0123456789abcdef \
    SMTP_HOST=127.0.0.1 SMTP_PORT="${SINK_PORT}" SMTP_FROM=noreply@example.com \
    SMTP_INSECURE=true APP_URL="$APP" \
    BIND_ADDR="127.0.0.1:${APP_PORT}" RUST_LOG=soulauth=warn \
    exec ./target/debug/soulauth
) > "$WORK/app_nooauth.log" 2>&1 &
APP_PID=$!
disown "$APP_PID" 2>/dev/null
wait_for "${APP}/api/oidc/jwks" "SoulAuth(无 OAuth 配置)" || {
    bad "不配 GOOGLE_/GITHUB_ 凭证时服务仍能启动" "$(tail -5 "$WORK/app_nooauth.log")"
}

ok "不配 GOOGLE_/GITHUB_ 凭证时服务仍能启动"
eq 200 "$(req POST /api/auth/register -H 'Content-Type: application/json' \
    -d '{"email":"solo@test.local","password":"CorrectHorse42!","username":"solouser"}')" \
    "邮箱密码注册照常可用"
eq 200 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"solo@test.local","password":"CorrectHorse42!"}')" "邮箱密码登录照常可用"
eq 200 "$(req GET /.well-known/openid-configuration)" "OIDC 发现文档照常可用"

# 未配置的 provider：501「本部署没开」，而不是拿假凭证去换令牌后吐 OAuth 错误
eq 501 "$(req GET /api/auth/login/google)" "Google 登录入口 → 501 未启用"
eq 501 "$(req GET /api/auth/login/github)" "GitHub 登录入口 → 501 未启用"
req GET /api/auth/login/google > /dev/null
has 'not enabled' "$(body)" "501 的说明是「本部署未启用」而非 OAuth 库的报错"

restart_app   # 交还给带 dummy 凭证的标准配置

group "23. BFF 要走的那条路：confidential 客户端"

# 此前全部 OIDC 覆盖用的都是 public 客户端、换令牌不带 client_secret。
# 而 SoulSeedOS 接入的实际形态是 BFF 持有 secret 的 confidential 客户端 ——
# 那条路一次都没跑过。这组把它跑通，顺带把 BFF 作者会踩的坑先踩掉。
restart_app

ADMIN_TOKEN="$(login_token admin@test.local "CorrectHorse42!")"
# authorize 端点认的是**浏览器会话 cookie**，不是 Bearer —— 单独取一份
curl -sS --max-time 20 -c "$WORK/bff_ck" -o /dev/null \
    -X POST "${APP}/api/auth/login" -H 'Content-Type: application/json' \
    -d '{"email":"admin@test.local","password":"CorrectHorse42!"}' 2>/dev/null

req POST /api/oidc/clients -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H 'Content-Type: application/json' \
    -d '{"client_name":"bff","client_type":"confidential",
         "redirect_uris":["http://localhost:9000/cb"],
         "allowed_scopes":["openid"],
         "allowed_grant_types":["authorization_code","refresh_token"],
         "allowed_response_types":["code"],"require_pkce":true,
         "id_token_lifetime":300}' > /dev/null
C_ID="$(jget client_id)"; C_SECRET="$(jget client_secret)"
[ -n "$C_ID" ] && [ -n "$C_SECRET" ] && ok "创建 confidential 客户端并拿到 secret" ||
    bad "创建 confidential 客户端并拿到 secret" "$(body)"

# secret 只在创建时返回这一次；之后查到的是掩码而不是真值
req GET "/api/oidc/clients/${C_ID}" -H "Authorization: Bearer ${ADMIN_TOKEN}" > /dev/null
MASKED="$(jget client_secret)"
[ "$MASKED" != "$C_SECRET" ] && ok "之后再查客户端拿到的是掩码（${MASKED}）而非真 secret" ||
    bad "之后再查客户端拿不到真 secret" "secret 被二次泄露"

VERIFIER='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
CHALLENGE="$(python3 -c "
import hashlib,base64
print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")"

bff_code() {   # 每次取一个全新的授权码
    local loc
    loc="$(curl -sS --max-time 20 -b "$WORK/bff_ck" -o /dev/null -D - \
        "${APP}/api/oidc/authorize?response_type=code&client_id=${C_ID}&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcb&scope=openid&state=st&code_challenge=${CHALLENGE}&code_challenge_method=S256" \
        2>/dev/null | grep -i '^location:' | tr -d '\r')"
    printf '%s' "$loc" | sed -n 's/.*code=\([^&]*\).*/\1/p'
}

exchange() {   # $1=code  $2..=额外 curl 参数
    local code="$1"; shift
    req POST /api/oidc/token -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode 'grant_type=authorization_code' \
        --data-urlencode "code=${code}" \
        --data-urlencode 'redirect_uri=http://localhost:9000/cb' \
        --data-urlencode "client_id=${C_ID}" \
        --data-urlencode "code_verifier=${VERIFIER}" "$@"
}

CODE="$(bff_code)"
[ -n "$CODE" ] && ok "拿到授权码" || bad "拿到授权码" "authorize 未下发 code"

# —— 机密客户端不带 secret 必须被拒（fail-closed 的核心）——
eq 400 "$(exchange "$(bff_code)")" "机密客户端不带 secret → 拒绝"
eq 400 "$(exchange "$(bff_code)" --data-urlencode 'client_secret=wrong-secret')" "secret 错误 → 拒绝"

# —— 客户端认证失败是否消耗授权码 ——
# BFF 的错误处理要按这条写：若消耗，secret 配错一次就得让用户重新登录；
# 若不消耗，改对 secret 即可重试。
CODE_R="$(bff_code)"
exchange "$CODE_R" --data-urlencode 'client_secret=wrong-secret' > /dev/null
RETRY="$(exchange "$CODE_R" --data-urlencode "client_secret=${C_SECRET}")"
if [ "$RETRY" = 200 ]; then
    ok "客户端认证失败不消耗授权码（改对 secret 可重试）"
else
    ok "客户端认证失败会消耗授权码（${RETRY}）—— BFF 须重新发起授权"
fi

# —— client_secret_post：凭证放表单 ——
eq 200 "$(exchange "$(bff_code)" --data-urlencode "client_secret=${C_SECRET}")" \
    "client_secret_post 换令牌成功"
REFRESH="$(jget refresh_token)"
ID_TOKEN="$(jget id_token)"

LIFE="$(python3 -c "
import base64,json
p='${ID_TOKEN}'.split('.')[1]; p += '='*(-len(p)%4)
c = json.loads(base64.urlsafe_b64decode(p))
print(c['exp'] - c['iat'])" 2>/dev/null)"
eq 300 "$LIFE" "ID Token 寿命为 300 秒（BFF 的续期周期）"

# —— client_secret_basic：凭证放 Authorization 头 ——
# 发现文档一直声明支持它，而令牌端点原来只解析表单。大多数 OIDC 客户端库
# 默认走 Basic —— 不通的话接入方会在自己那边反复查配置，而配置是对的。
req GET /.well-known/openid-configuration > /dev/null
has 'client_secret_basic' "$(body)" "发现文档声明支持 client_secret_basic"

BASIC="$(printf '%s:%s' "$C_ID" "$C_SECRET" | base64 -w0)"
eq 200 "$(exchange "$(bff_code)" -H "Authorization: Basic ${BASIC}")" \
    "client_secret_basic 换令牌成功（声明与实现一致）"

BAD_BASIC="$(printf '%s:%s' "$C_ID" "wrong" | base64 -w0)"
eq 400 "$(exchange "$(bff_code)" -H "Authorization: Basic ${BAD_BASIC}")" "Basic 里的 secret 错误 → 拒绝"

# 两处同时带凭证 = 无效请求，不"挑一个用"
exchange "$(bff_code)" -H "Authorization: Basic ${BASIC}" \
    --data-urlencode "client_secret=${C_SECRET}" > /dev/null
has 'invalid_request' "$(body)" "Basic 与表单同时带凭证 → invalid_request"

group "24. 刷新令牌的轮换与复用检测（BFF 必须知道）"

# BFF 长期持有 refresh token，每 300 秒换一次 ID Token。这两条行为直接
# 决定 BFF 该怎么写，写错的代价是把用户会话整个打掉。
refresh_with() {
    req POST /api/oidc/token -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode 'grant_type=refresh_token' \
        --data-urlencode "refresh_token=$1" \
        --data-urlencode "client_id=${C_ID}" \
        --data-urlencode "client_secret=${C_SECRET}"
}

[ -n "$REFRESH" ] && ok "换令牌时一并下发了 refresh token" ||
    bad "换令牌时一并下发了 refresh token" "$(body)"

eq 200 "$(refresh_with "$REFRESH")" "用 refresh token 换到新令牌"
REFRESH2="$(jget refresh_token)"
NEW_ID="$(jget id_token)"
[ -n "$REFRESH2" ] && [ "$REFRESH2" != "$REFRESH" ] &&
    ok "刷新令牌确实轮换了（返回的是新的）" ||
    bad "刷新令牌确实轮换了" "旧=${REFRESH:0:10} 新=${REFRESH2:0:10}"
[ -n "$NEW_ID" ] && ok "刷新同时下发新的 ID Token" || bad "刷新同时下发新的 ID Token" "$(body)"

# 复用旧的：不只是失败，还会把该用户在该客户端上的全部令牌一起吊销。
# BFF 若因超时重试而重放同一个 refresh token，代价是整个会话被打掉 ——
# 所以 BFF 必须按会话串行化刷新，不能并发刷。
eq 400 "$(refresh_with "$REFRESH")" "复用已轮换的刷新令牌 → 拒绝"
eq 400 "$(refresh_with "$REFRESH2")" "复用检测触发后新令牌也失效（整个会话被吊销）"

group "25. 安全回归：停用生效范围 / PKCE 下限 / 跨 provider 顶号"

# 这一组的三条都对应**已实测复现过的缺陷**，且三条都曾经在这套用例全绿的情况下
# 存在 —— 因为前面 24 组恰好没有在这些交界处取过样。所以它们不是"补充覆盖"，
# 是把三个真实漏洞钉死。

restart_app
sql "DELETE account_lockout" > /dev/null

# ───────── 25.1 停用必须同时切断 OIDC 那一侧 ─────────
#
# 第 17 组已经验过「停用后原生令牌立即失效」。但原生令牌只是其中一条路：
# 接入方手里的是 OIDC access / refresh token，浏览器手里还有会话 cookie。
# 曾经的实际行为是：停用之后 userinfo 照常返回身份、refresh 照常换到全新令牌
# （且每次刷新还会轮换出新的一张，等于永远续得下去）、authorize 照常发授权码。
TOK_ADMIN="$(login_token admin@test.local "CorrectHorse42!")"
SUSP_TOKEN="$(signup suspend-oidc@test.local suspoidc)"
SUSP_UID="$(user_id_of suspend-oidc@test.local)"

# 该用户的浏览器会话（authorize 认的是 cookie，不是 Bearer）
curl -sS --max-time 20 -c "$WORK/susp_ck" -o /dev/null \
    -X POST "${APP}/api/auth/login" -H 'Content-Type: application/json' \
    -d '{"email":"suspend-oidc@test.local","password":"CorrectHorse42!"}' 2>/dev/null

req POST /api/oidc/clients -H "Authorization: Bearer ${TOK_ADMIN}" \
    -H 'Content-Type: application/json' \
    -d '{"client_name":"susp-probe","client_type":"confidential",
         "redirect_uris":["http://localhost:9000/cb"],
         "allowed_scopes":["openid","email"],
         "allowed_grant_types":["authorization_code","refresh_token"],
         "allowed_response_types":["code"],"require_pkce":true}' > /dev/null
SC_ID="$(jget client_id)"; SC_SECRET="$(jget client_secret)"

SV='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
SCH="$(python3 -c "
import hashlib,base64
print(base64.urlsafe_b64encode(hashlib.sha256('$SV'.encode()).digest()).rstrip(b'=').decode())")"

susp_code() {
    curl -sS --max-time 20 -b "$WORK/susp_ck" -o /dev/null -D - \
        "${APP}/api/oidc/authorize?response_type=code&client_id=${SC_ID}&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcb&scope=openid+email&state=st&code_challenge=${SCH}&code_challenge_method=S256" \
        2>/dev/null | grep -i '^location:' | tr -d '\r' | sed -n 's/.*code=\([^&]*\).*/\1/p'
}

SUSP_CODE="$(susp_code)"
[ -n "$SUSP_CODE" ] && ok "停用前可取得授权码" || bad "停用前可取得授权码" "authorize 未下发 code"

req POST /api/oidc/token -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' --data-urlencode "code=${SUSP_CODE}" \
    --data-urlencode 'redirect_uri=http://localhost:9000/cb' \
    --data-urlencode "client_id=${SC_ID}" --data-urlencode "client_secret=${SC_SECRET}" \
    --data-urlencode "code_verifier=${SV}" > /dev/null
SUSP_AT="$(jget access_token)"; SUSP_RT="$(jget refresh_token)"
# 这条流程申请的是 scope=openid+email，与前面 scope=openid 那条构成对照：
# 申请了才给，没申请不给，且 email scope 不得顺带放行档案属性。
# 必须在下一个请求之前取 —— jget 读的是最后一次响应。
SUSP_IDT="$(jget id_token)"
[ -n "$SUSP_AT" ] && [ -n "$SUSP_RT" ] && ok "停用前换到 OIDC 令牌" ||
    bad "停用前换到 OIDC 令牌" "$(body)"
eq 200 "$(req GET /api/oidc/userinfo -H "Authorization: Bearer ${SUSP_AT}")" "停用前 userinfo 可用"

[ -n "$(claim "$SUSP_IDT" email)" ] && ok "scope=openid+email 的 ID Token 含 email" ||
    bad "scope=openid+email 的 ID Token 含 email" "email 为空"
eq "" "$(claim "$SUSP_IDT" preferred_username)" "email scope 不放行 preferred_username"

eq 200 "$(req PUT "/api/users/${SUSP_UID}/status" -H "Authorization: Bearer ${TOK_ADMIN}" \
    -H 'Content-Type: application/json' -d '{"status":"Suspended","reason":"regression"}')" \
    "管理员停用该账号"

# 原生那侧（第 17 组已覆盖，这里只做锚点）
NATIVE="$(req GET /api/auth/me -H "Authorization: Bearer ${SUSP_TOKEN}")"
if [ "$NATIVE" = 401 ] || [ "$NATIVE" = 403 ]; then
    ok "停用后原生令牌失效（${NATIVE}）"
else bad "停用后原生令牌失效" "竟然仍可用：${NATIVE}"; fi

# —— 以下三条是本次修复的核心 ——
UI="$(req GET /api/oidc/userinfo -H "Authorization: Bearer ${SUSP_AT}")"
if [ "$UI" = 401 ] || [ "$UI" = 403 ]; then
    ok "停用后 OIDC userinfo 被拒（${UI}）"
else bad "停用后 OIDC userinfo 被拒" "仍返回 ${UI}，身份照常吐出"; fi

RF="$(req POST /api/oidc/token -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=refresh_token' --data-urlencode "refresh_token=${SUSP_RT}" \
    --data-urlencode "client_id=${SC_ID}" --data-urlencode "client_secret=${SC_SECRET}")"
eq 400 "$RF" "停用后 refresh_token 换不到新令牌"
eq "" "$(jget access_token)" "停用后刷新不下发 access token"
eq "" "$(jget id_token)" "停用后刷新不签发 ID Token"

AFTER_CODE="$(susp_code)"
eq "" "$AFTER_CODE" "停用后浏览器 cookie 换不到新授权码"

# 停用同时要把已发凭证一并作废，而不是只改字段等下次校验
eq 0 "$(sql_count "SELECT count() FROM session WHERE user_id = (SELECT VALUE subject_id FROM type::record('user','${SUSP_UID}'))[0] GROUP ALL")" \
    "停用后该用户的 session 行被清空"
eq 0 "$(sql_count "SELECT count() FROM oidc_refresh_token WHERE user_id = (SELECT VALUE subject_id FROM type::record('user','${SUSP_UID}'))[0] GROUP ALL")" \
    "停用后该用户的 OIDC 刷新令牌被吊销"
eq 0 "$(sql_count "SELECT count() FROM oidc_access_token WHERE user_id = (SELECT VALUE subject_id FROM type::record('user','${SUSP_UID}'))[0] GROUP ALL")" \
    "停用后该用户的 OIDC 访问令牌被吊销"

# 被停用的账号也不该还能走密码重置（且必须与"账号不存在"同样静默，不能成为枚举信道）
eq 200 "$(req POST /api/auth/request-password-reset -H 'Content-Type: application/json' \
    -d '{"email":"suspend-oidc@test.local"}')" "对停用账号请求重置：静默返回 200（不泄露状态）"
eq 0 "$(sql_count "SELECT count() FROM password_reset_token WHERE email='suspend-oidc@test.local' AND used=false GROUP ALL")" \
    "但不为停用账号签发重置令牌"

# ───────── 25.2 public 客户端不得关掉 PKCE ─────────
#
# 曾经可以：注册时传 require_pkce:false，之后 /token 在既无 code_verifier
# 也无 client_secret 的情况下直接换到整套令牌 —— 谁截获 URL 里那串 code
# 谁就接管账号。public 客户端没有 secret，PKCE 是它唯一的绑定手段。
restart_app

eq 200 "$(req POST /api/oidc/clients -H "Authorization: Bearer ${TOK_ADMIN}" \
    -H 'Content-Type: application/json' \
    -d '{"client_name":"nopkce","client_type":"public",
         "redirect_uris":["http://localhost:9000/cb"],"allowed_scopes":["openid"],
         "allowed_grant_types":["authorization_code"],
         "allowed_response_types":["code"],"require_pkce":false}')" \
    "可以注册 public 客户端"
eq true "$(jget require_pkce)" "public 客户端的 require_pkce 被强制为 true（传 false 不作数）"
NP_ID="$(jget client_id)"

curl -sS --max-time 20 -c "$WORK/np_ck" -o /dev/null -X POST "${APP}/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"email":"admin@test.local","password":"CorrectHorse42!"}' 2>/dev/null
# 缺 PKCE 是在 `validate_authorize_request` 里被挡下的，返回 400 JSON，
# **不是** error 重定向 —— 重定向只用于"客户端和 redirect_uri 都合法、
# 但这次授权不能给"的情形。这里连请求本身都不合法，没有可信的回跳目标。
eq 400 "$(req GET "/api/oidc/authorize?response_type=code&client_id=${NP_ID}&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcb&scope=openid&state=s")" \
    "不带 code_challenge 的授权请求被拒（400）"
has 'PKCE' "$(body)" "错误信息点明缺的是 PKCE"

NP_LOC="$(curl -sS --max-time 20 -b "$WORK/np_ck" -o /dev/null -D - \
    "${APP}/api/oidc/authorize?response_type=code&client_id=${NP_ID}&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcb&scope=openid&state=s" \
    2>/dev/null | grep -i '^location:' | tr -d '\r')"
eq "" "$(printf '%s' "$NP_LOC" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')" \
    "不带 PKCE 时不下发授权码"

# ───────── 25.3 跨 provider 同号不得顶号 ─────────
#
# 两家 provider 给出数值相同的用户 id（Google "4100" / GitHub 4100）。
# 身份查找若只按 provider_user_id 单列匹配，后一家登录会命中前一家的记录，
# 直接登进别人的账号 —— 不建新号、不建新关联、HTTP 303 成功，全程无报错。
python3 "$ROOT/tests/mock_oauth.py" "$OAUTH_PORT" > "$WORK/mock_oauth2.log" 2>&1 &
MOCK_PID=$!
disown "$MOCK_PID" 2>/dev/null
sleep 1
sql "DELETE account_lockout" > /dev/null
OAUTH_BASE="http://127.0.0.1:${OAUTH_PORT}" restart_app

redirected "Google 侧建号（sub=4100）" "$(oauth_callback google google-collide)"
eq 1 "$(user_count collide-google@test.local)" "Google 侧账号已建立"
eq 1 "$(link_count google 4100)" "建立了 (google, 4100) 关联"

sql "DELETE session" > /dev/null      # 清空，好让下面的归属计数无歧义
redirected "GitHub 侧同号登录（id=4100）" "$(oauth_callback github github-collide)"
eq 1 "$(user_count collide-github@test.local)" "GitHub 侧建立了**自己的**账号，而不是顶掉 Google 那个"
eq 1 "$(link_count github 4100)" "建立了独立的 (github, 4100) 关联"
eq 1 "$(link_count google 4100)" "Google 侧的关联未被改写"

# 最直接的判据：这次登录建出来的会话属于谁
# 最直接的判据：这次 GitHub 登录建出来的会话，到底挂在谁名下。
#
# 会话自 Stage 3 起挂在**身份根**上（session.user_id 是 record<actor_identity>），
# 所以要先由 user 行取出它的 subject_id —— 直接按 type::record('user',...) 查
# 会一条也数不到，看起来像顶号防护失效，实际是查错了表。
# 用 type::record + count 这套本文件里到处在用的写法，不用 record 链接穿透
# （`SELECT VALUE user_id.email` 在这里取不到值）。
GH_UID="$(user_id_of collide-github@test.local)"
GOOGLE_UID="$(user_id_of collide-google@test.local)"
eq 1 "$(sql_count "SELECT count() FROM session WHERE user_id = (SELECT VALUE subject_id FROM type::record('user','${GH_UID}'))[0] GROUP ALL")" \
    "GitHub 登录建立的会话挂在 GitHub 那个账号名下"
eq 0 "$(sql_count "SELECT count() FROM session WHERE user_id = (SELECT VALUE subject_id FROM type::record('user','${GOOGLE_UID}'))[0] GROUP ALL")" \
    "Google 那个账号没有因为 GitHub 登录而多出会话（顶号的判据）"

kill -9 "$MOCK_PID" 2>/dev/null; MOCK_PID=""

group "26. 回归：会话列表 / 审计窗口 / 验证信重发 / 回收"

# 本组四条同样都对应实测复现过的缺陷，且都发生在前 24 组的取样盲区里。

restart_app
sql "DELETE account_lockout" > /dev/null

# ───────── 25.1 会话列表只列仍然有效的会话 ─────────
#
# 曾经的行为：SQL 只按 user_id 过滤，不看 expires_at，也没有 LIMIT。
# 实测库里 4 条会话（3 条已过期）→ 接口原样返回 4 条。这个接口是给用户
# 核对"我还在哪些设备上登录着"的，列错了就起反作用。
SESS_TOKEN="$(signup sesslist@test.local sesslist)"
SESS_UID="$(user_id_of sesslist@test.local)"
[ -n "$SESS_TOKEN" ] && ok "会话列表用例账号就绪" || bad "会话列表用例账号就绪" "$(body)"

# 再登录两次，凑够多条会话
login_token sesslist@test.local "CorrectHorse42!" > /dev/null
login_token sesslist@test.local "CorrectHorse42!" > /dev/null
TOTAL_SESS="$(sql_count "SELECT count() FROM session WHERE user_id = (SELECT VALUE subject_id FROM type::record('user','${SESS_UID}'))[0] GROUP ALL")"
[ "$TOTAL_SESS" -ge 3 ] && ok "库中已有 ${TOTAL_SESS} 条会话" || bad "库中已有多条会话" "只有 ${TOTAL_SESS} 条"

# 把当前令牌以外的全部改成早已过期
# 库里存的是指纹，所以"当前这条之外"要按指纹排除。
sql "UPDATE session SET expires_at = 1000 \
     WHERE user_id = (SELECT VALUE subject_id FROM type::record('user','${SESS_UID}'))[0] \
       AND token_hash != '$(bearer_hash "$SESS_TOKEN")'" > /dev/null

eq 200 "$(req GET /api/auth/sessions -H "Authorization: Bearer ${SESS_TOKEN}")" "GET /api/auth/sessions"
LISTED="$(python3 -c "
import json
try: d = json.load(open('$WORK/body'))
except Exception: d = None
print(len(d) if isinstance(d, list) else -1)" 2>/dev/null)"
eq 1 "$LISTED" "只列出仍然有效的那 1 条（过期的不算活跃会话）"

# ───────── 25.2 审计时间窗被钳制，且不再 panic ─────────
#
# `?days=` / `?hours=` 曾经直接喂给 chrono::Duration::days()，越界即 panic：
# 连接被丢弃、客户端拿到的是网络错误而不是 HTTP 错误。实测 99999999 就够了 ——
# 那不是攻击输入，是手滑能打出来的值。
# 前面几次登录已经吃掉了 5 次/5 分钟的配额，这里先要一份干净的
restart_app
TOK_AUDIT="$(login_token admin@test.local "CorrectHorse42!")"

for D in 99999999 9223372036854775807 -1 0; do
    eq 200 "$(req GET "/api/audit/dashboard?days=${D}" -H "Authorization: Bearer ${TOK_AUDIT}")" \
        "dashboard?days=${D} 被钳制而不是 panic"
done
for H in 9223372036854775807 -1; do
    eq 200 "$(req GET "/api/audit/security-metrics?hours=${H}" -H "Authorization: Bearer ${TOK_AUDIT}")" \
        "security-metrics?hours=${H} 被钳制而不是 panic"
done
eq 200 "$(req GET "/api/audit/security-report?days=9223372036854775807" -H "Authorization: Bearer ${TOK_AUDIT}")" \
    "security-report 的窗口同样被钳制"

# 越界值必须落到上限而不是被当成 0：报表期字符串里应当出现 366 天
req GET "/api/audit/dashboard?days=99999999" -H "Authorization: Bearer ${TOK_AUDIT}" > /dev/null
has '366' "$(body)" "超出上限的窗口被夹到 366 天，而不是退化成空窗口"

# ───────── 25.3 会员总览走库内聚合 ─────────
#
# 曾经是 `SELECT * FROM user`：把每一行（连密码哈希）反序列化进 Vec 再遍历计数。
eq 200 "$(req GET /api/ops/memberships/overview -H "Authorization: Bearer ${TOK_AUDIT}")" "会员总览可读"
OV_TOTAL="$(python3 -c "
import json
print(json.load(open('$WORK/body')).get('total_users',-1))" 2>/dev/null)"
DB_TOTAL="$(sql_count "SELECT count() FROM user WHERE account_status != 'Deleted' GROUP ALL")"
eq "$DB_TOTAL" "$OV_TOTAL" "聚合出来的 total_users 与库中实际行数一致"

# ───────── 25.4 邮箱验证信可以重发 ─────────
#
# 曾经的死局：令牌 24 小时过期后，点链接 401 / 登录 403 / 重注册 409 /
# 密码重置也救不了（不改 is_email_verified），且没有任何重发入口。
# 叠加"注册时 SMTP 失败被静默吞掉"，一次发信抖动就造出一个永久无法登录的账号。
python3 "$ROOT/tests/smtp_sink.py" "$SINK_PORT" "$MAILBOX" > "$WORK/sink2.log" 2>&1 &
SINK_PID=$!
disown "$SINK_PID" 2>/dev/null
sleep 1
sql "DELETE account_lockout" > /dev/null
VERIFY_EMAIL=true restart_app

req POST /api/auth/register -H 'Content-Type: application/json' \
    -d '{"email":"resend@test.local","password":"CorrectHorse42!","username":"resenduser"}' > /dev/null
sleep 2
OLD_VTOKEN="$(sql "SELECT VALUE verification_token_hash FROM user WHERE email='resend@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r else '')")"
[ -n "$OLD_VTOKEN" ] && ok "注册后签发了验证令牌" || bad "注册后签发了验证令牌" "未取到"

# 模拟 24 小时后：令牌过期
sql "UPDATE user SET verification_token_expires_at = 1000 WHERE email='resend@test.local'" > /dev/null
eq 401 "$(req GET "/api/auth/verify-email/${OLD_VTOKEN}")" "过期令牌不再被接受"
eq 403 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"resend@test.local","password":"CorrectHorse42!"}')" "未验证时无法登录"

BEFORE_MAIL="$(mail_count)"
eq 200 "$(req POST /api/auth/resend-verification -H 'Content-Type: application/json' \
    -d '{"email":"resend@test.local"}')" "重发验证信接口可用"
sleep 2
eq "$((BEFORE_MAIL + 1))" "$(mail_count)" "确实又发出了一封"
eq 'Verify your email address' "$(mail_header Subject)" "主题为邮箱验证"

# 比的是**指纹**换没换 —— 明文只存在于邮件里。
NEW_VHASH="$(sql "SELECT VALUE verification_token_hash FROM user WHERE email='resend@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r else '')")"
[ -n "$NEW_VHASH" ] && [ "$NEW_VHASH" != "$OLD_VTOKEN" ] && ok "换发了一枚新的验证令牌" ||
    bad "换发了一枚新的验证令牌" "旧=${OLD_VTOKEN:0:8} 新=${NEW_VHASH:0:8}"

# 明文只能从信里取。这本身就是一条有价值的断言：库被读走也拿不到可用链接。
NEW_VTOKEN="$(mail_body | grep -oE 'token=[A-Za-z0-9-]+' | head -1 | cut -d= -f2)"
eq "$(bearer_hash "$NEW_VTOKEN")" "$NEW_VHASH" "信里的新令牌与库中指纹对应"
eq 200 "$(req GET "/api/auth/verify-email/${NEW_VTOKEN}")" "用新令牌可以完成验证"
eq true "$(sql "SELECT VALUE verified FROM user WHERE email='resend@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(str(r[0]).lower() if r else '')")" \
    "验证状态已落库"

# 防枚举：未注册邮箱、已验证账号，都必须是同样的静默 200
eq 200 "$(req POST /api/auth/resend-verification -H 'Content-Type: application/json' \
    -d '{"email":"definitely-not-registered@test.local"}')" "未注册邮箱同样返回 200（不泄露账号是否存在）"
COUNT_BEFORE="$(mail_count)"
eq 200 "$(req POST /api/auth/resend-verification -H 'Content-Type: application/json' \
    -d '{"email":"resend@test.local"}')" "对已验证账号同样返回 200"
sleep 2
eq "$COUNT_BEFORE" "$(mail_count)" "但不给已验证账号再发信（否则成了对任意邮箱的发信器）"

kill -9 "$SINK_PID" 2>/dev/null; SINK_PID=""
restart_app

# ───────── 25.5 过期会话与已用重置令牌可被回收 ─────────
#
# 后台任务每小时跑一次，集成测试等不了，所以这里直接执行与
# `Database::cleanup_expired_auth_artifacts` **完全相同**的两条语句。
# 覆盖的是这两条 SQL 本身是否成立（类型对不对、语法对不对）——
# 那正是它们最可能出错的地方：`session.expires_at` 是 number，
# 而 `password_reset_token.expires_at` 是 datetime，两者不能用同一种写法比较。
# 自己造现场，不依赖前面小节的残留状态 —— 那样这条用例的成立与否
# 会取决于中间有没有别的小节顺手清掉了会话，读起来像 flaky。
NOW_TS="$(date +%s)"
CLEAN_UID="$(user_id_of sesslist@test.local)"
sql "CREATE session CONTENT {
       user_id: (SELECT VALUE subject_id FROM type::record('user','${CLEAN_UID}'))[0],
       token_hash: 'stale-token-hash-for-cleanup-regression',
       expires_at: 1000, created_at: 1000,
       user_agent: 'itest', ip_address: '127.0.0.1'
     }" > /dev/null
sql "CREATE password_reset_token CONTENT {
       email: 'sesslist@test.local', token_hash: 'stale-reset-token-hash',
       expires_at: type::datetime('2020-01-01T00:00:00Z'),
       used: true, created_at: type::datetime('2020-01-01T00:00:00Z')
     }" > /dev/null

eq 1 "$(sql_count "SELECT count() FROM session WHERE expires_at < ${NOW_TS} GROUP ALL")" \
    "现场就绪：一条过期会话"
eq 1 "$(sql_count "SELECT count() FROM password_reset_token WHERE used = true GROUP ALL")" \
    "现场就绪：一枚已使用的重置令牌"

sql "DELETE session WHERE expires_at < ${NOW_TS}" > /dev/null
eq 0 "$(sql_count "SELECT count() FROM session WHERE expires_at < ${NOW_TS} GROUP ALL")" \
    "过期会话被回收"

sql "DELETE password_reset_token WHERE used = true OR expires_at < type::datetime('$(date -u +%Y-%m-%dT%H:%M:%SZ)')" > /dev/null
eq 0 "$(sql_count "SELECT count() FROM password_reset_token WHERE used = true GROUP ALL")" \
    "已使用的重置令牌被回收"

# ───────── 25.6 契约收缩：PendingDeletion 与 membership_expiry ─────────
#
# 两条都是对外契约的收紧，容易在后续改动里被无意放开，所以钉住。

# PendingDeletion 已从 AccountStatus 移除：管理员不能再设置它。
# 它此前的行为与 Deleted 完全同义，却对外宣告了一条不存在的删除流水线。
CONTRACT_UID="$(user_id_of sesslist@test.local)"
STATUS_CODE="$(req PUT "/api/users/${CONTRACT_UID}/status" -H "Authorization: Bearer ${TOK_AUDIT}" \
    -H 'Content-Type: application/json' -d '{"status":"PendingDeletion","reason":"x"}')"
case "$STATUS_CODE" in
    400|422) ok "PendingDeletion 已不被接受（${STATUS_CODE}）" ;;
    *)       bad "PendingDeletion 已不被接受" "竟然返回 ${STATUS_CODE}" ;;
esac

# 库里遗留的 PendingDeletion 行必须 fail-closed（解析成 Inactive，不可用），
# 而不是因为不认识就放行。
LEGACY_TOKEN="$(signup legacy-status@test.local legacystatus)"
LEGACY_UID="$(user_id_of legacy-status@test.local)"
eq 200 "$(req GET /api/auth/me -H "Authorization: Bearer ${LEGACY_TOKEN}")" "存量用例账号可用"
sql "UPDATE user SET account_status = 'PendingDeletion' \
     WHERE id = type::record('user','${LEGACY_UID}')" > /dev/null
# 这里是直接改库，绕过了应用，所以鉴权缓存里还留着旧的 Active。
# 走 API 改状态的路径会主动清缓存（第 17 组验的就是那条），
# 这一组模拟的是"升级前就存在于库里的遗留行"，只能等缓存自然过期。
sleep 6
LEGACY_CODE="$(req GET /api/auth/me -H "Authorization: Bearer ${LEGACY_TOKEN}")"
case "$LEGACY_CODE" in
    401|403) ok "库中遗留的 PendingDeletion 行被判为不可用（${LEGACY_CODE}）" ;;
    *)       bad "库中遗留的 PendingDeletion 行被判为不可用" "竟然放行：${LEGACY_CODE}" ;;
esac

# membership_expiry 现在是时间点：非法字符串在反序列化阶段就被拒。
BAD_EXPIRY="$(req PUT "/api/users/${CONTRACT_UID}/membership" -H "Authorization: Bearer ${TOK_AUDIT}" \
    -H 'Content-Type: application/json' -d '{"membership_level":"PRO","membership_expiry":"下个月"}')"
case "$BAD_EXPIRY" in
    400|422) ok "非法的 membership_expiry 被拒（${BAD_EXPIRY}）" ;;
    *)       bad "非法的 membership_expiry 被拒" "竟然收下了：${BAD_EXPIRY}" ;;
esac

eq 200 "$(req PUT "/api/users/${CONTRACT_UID}/membership" -H "Authorization: Bearer ${TOK_AUDIT}" \
    -H 'Content-Type: application/json' \
    -d '{"membership_level":"PRO","membership_expiry":"2030-01-01T00:00:00Z"}')" \
    "合法的 RFC3339 时间点被接受"

# SoulAuth 不解释这个字段：即使已经"过期"，等级也不会被自动降级
# （P0-DECISION-09 §4.7：membership 归 Entitlement 侧，不由本服务判断）。
eq 200 "$(req PUT "/api/users/${CONTRACT_UID}/membership" -H "Authorization: Bearer ${TOK_AUDIT}" \
    -H 'Content-Type: application/json' \
    -d '{"membership_level":"PRO","membership_expiry":"2020-01-01T00:00:00Z"}')" \
    "过去的时间点同样被接受（形状合法即可）"
req GET "/api/users/${CONTRACT_UID}" -H "Authorization: Bearer ${TOK_AUDIT}" > /dev/null
has 'PRO' "$(body)" "已过期的会员等级不被本服务自动降级（解释权在消费方）"

# ───────── 25.7 角色列表返回真实权限 / 拒绝实现不了的 grant ─────────
#
# 曾经：GET /api/rbac/roles 里每个角色都显示 0 条权限，而 GET /roles/{name}
# 对同一个角色能返回 18 条 —— From<Role> 拿不到数据库只能置空，列表接口原样返回。
# 管理后台的角色列表据此渲染，看到的是"所有角色都没有任何权限"。
req GET "/api/rbac/roles/admin" -H "Authorization: Bearer ${TOK_AUDIT}" > /dev/null
ONE_PERMS="$(python3 -c "
import json
try: print(len(json.load(open('$WORK/body')).get('permissions',[])))
except Exception: print(-1)" 2>/dev/null)"
[ "$ONE_PERMS" -gt 0 ] && ok "单角色查询返回 ${ONE_PERMS} 条权限" ||
    bad "单角色查询返回权限" "拿到 ${ONE_PERMS}"

req GET "/api/rbac/roles" -H "Authorization: Bearer ${TOK_AUDIT}" > /dev/null
LIST_PERMS="$(python3 -c "
import json
try:
    d=json.load(open('$WORK/body'))
    print(next((len(r.get('permissions',[])) for r in d if r.get('name')=='admin'), -1))
except Exception: print(-1)" 2>/dev/null)"
eq "$ONE_PERMS" "$LIST_PERMS" "角色列表里 admin 的权限数与单角色查询一致（不再恒空）"

# client_credentials 在令牌端点没有实现分支、发现文档也不宣告。
# 以前注册时照收，之后每次换令牌都失败 —— 故障点与病因隔了一步。
CC="$(req POST /api/oidc/clients -H "Authorization: Bearer ${TOK_AUDIT}" \
    -H 'Content-Type: application/json' \
    -d '{"client_name":"m2m","client_type":"confidential",
         "redirect_uris":["https://app.example/cb"],"allowed_scopes":["openid"],
         "allowed_grant_types":["client_credentials"],
         "allowed_response_types":["code"]}')"
eq 400 "$CC" "注册时拒收 client_credentials（令牌端点实现不了它）"

# ───────── 25.8 审计口径与 RBAC 名称校验 ─────────
#
# 空系统不得报高风险：窗口内一次登录都没有时 success_rate 是 0.0 而非"无数据"，
# 不加判断就会让一个刚装好的部署在执行摘要里显示 risk_level=High，
# 外加一条"认证成功率 0.0%"的高优先级告警。第一天就喊狼来了。
restart_app
sql "DELETE user_activity" > /dev/null
TOK_R="$(login_token admin@test.local "CorrectHorse42!")"

# 上面这次登录本身会写一条 login_success，先清掉，制造真正的"零数据"窗口
sql "DELETE user_activity" > /dev/null
req GET "/api/audit/security-report?days=1" -H "Authorization: Bearer ${TOK_R}" > /dev/null
RISK="$(python3 -c "
import json
try: print(json.load(open('$WORK/body')).get('executive_summary',{}).get('risk_level',''))
except Exception: print('')" 2>/dev/null)"
eq Low "$RISK" "零登录数据的窗口不报高风险"

HIGH_RECS="$(python3 -c "
import json
try:
    r=json.load(open('$WORK/body')).get('recommendations',[])
    print(sum(1 for x in r if x.get('priority')=='High'))
except Exception: print(-1)" 2>/dev/null)"
eq 0 "$HIGH_RECS" "零数据时不发高优先级告警"

# 限流违规改为数真实的审计事件，而不是估算"失败登录超过 10 次的 IP 个数"
sql "DELETE user_activity" > /dev/null
sql "CREATE user_activity CONTENT { user_id: NONE, action: 'rate_limit_violation',
     category: 'Security', ip_address: '203.0.113.9', user_agent: 'itest',
     details: {}, status: 'Warning', timestamp: time::now().unix() }" > /dev/null
req GET "/api/audit/security-metrics?hours=1" -H "Authorization: Bearer ${TOK_R}" > /dev/null
RLV="$(python3 -c "
import json
try: print(json.load(open('$WORK/body')).get('rate_limit_violations',-1))
except Exception: print(-1)" 2>/dev/null)"
eq 1 "$RLV" "限流违规数来自真实的 rate_limit_violation 事件"

# RBAC 名称校验：空名字建出来就再也按名字找不回去
eq 400 "$(req POST /api/rbac/roles -H "Authorization: Bearer ${TOK_R}" \
    -H 'Content-Type: application/json' \
    -d '{"name":"","display_name":"空名字","description":null}')" \
    "拒绝空角色名"
eq 400 "$(req POST /api/rbac/roles -H "Authorization: Bearer ${TOK_R}" \
    -H 'Content-Type: application/json' \
    -d '{"name":"has space","display_name":"带空格","description":null}')" \
    "拒绝含空白的角色名"
eq 200 "$(req POST /api/rbac/roles -H "Authorization: Bearer ${TOK_R}" \
    -H 'Content-Type: application/json' \
    -d '{"name":"itest_role","display_name":"正常","description":null}')" \
    "正常角色名可创建"

# ───────── 25.9 响应形状：裸对象，无 ApiResponse 信封 ─────────
#
# 曾经是一半对一半：rbac / user_management / ops 套 {success,data,message}，
# auth / audit / oidc 直接返回裸对象。客户端得逐端点记住用哪种 ——
# 写本套件时就因此踩过一次（按 data 取审计报告字段，拿到空值）。
req GET /api/auth/me -H "Authorization: Bearer ${TOK_AUDIT}" > /dev/null
python3 -c "
import json,sys
d=json.load(open('$WORK/body'))
sys.exit(0 if ('email' in d and 'data' not in d and 'success' not in d) else 1)" \
  && ok "/api/auth/me 返回裸对象" || bad "/api/auth/me 返回裸对象" "$(body | head -c 90)"

req GET /api/rbac/roles -H "Authorization: Bearer ${TOK_AUDIT}" > /dev/null
python3 -c "
import json,sys
d=json.load(open('$WORK/body'))
sys.exit(0 if isinstance(d,list) and d and 'name' in d[0] else 1)" \
  && ok "/api/rbac/roles 直接返回数组（信封已移除）" || bad "/api/rbac/roles 直接返回数组" "$(body | head -c 90)"

req GET /api/users -H "Authorization: Bearer ${TOK_AUDIT}" > /dev/null
python3 -c "
import json,sys
d=json.load(open('$WORK/body'))
sys.exit(0 if ('users' in d and 'data' not in d) else 1)" \
  && ok "/api/users 返回裸对象" || bad "/api/users 返回裸对象" "$(body | head -c 90)"

req GET /api/ops/memberships/overview -H "Authorization: Bearer ${TOK_AUDIT}" > /dev/null
python3 -c "
import json,sys
d=json.load(open('$WORK/body'))
sys.exit(0 if ('total_users' in d and 'data' not in d) else 1)" \
  && ok "/api/ops 返回裸对象" || bad "/api/ops 返回裸对象" "$(body | head -c 90)"

# 错误体统一为 {"error": <机器码>, "message": <人话>}
#
# `error` 必须是 snake_case 机器码而不是英文散文 —— 调用方按它分支。
req GET /api/auth/me -H "Authorization: Bearer not-a-token" > /dev/null
python3 -c "
import json,re,sys
d=json.load(open('$WORK/body'))
sys.exit(0 if {'error','message'} <= set(d) and re.fullmatch(r'[a-z0-9_]+', d['error']) else 1)" \
  && ok "错误体是 error(码)+message(人话)" || bad "错误体形状" "$(body | head -c 120)"

req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"nobody@test.local","password":"WrongPass99!"}' > /dev/null
python3 -c "
import json,sys
d=json.load(open('$WORK/body'))
sys.exit(0 if d.get('error')=='invalid_credentials' and 'message' in d else 1)" \
  && ok "登录失败给出 invalid_credentials" || bad "登录失败错误体" "$(body | head -c 120)"

# 曾经的空响应体：/api/rbac/* 与 /api/ops/* 用裸 StatusCode 当错误，
# 权限不足时 403 不带任何内容。现在必须与全站同形。
TOK_NOPERM="$(login_token plain@test.local "CorrectHorse42!")"
req GET /api/rbac/roles -H "Authorization: Bearer ${TOK_NOPERM}" > /dev/null
python3 -c "
import json,sys
d=json.load(open('$WORK/body'))
sys.exit(0 if d.get('error')=='missing_permission' and d.get('required_permission') else 1)" \
  && ok "rbac 权限不足给出 missing_permission + required_permission" \
  || bad "rbac 403 形状" "$(body | head -c 120)"

# OIDC 是有意的例外：形状由规范规定
req GET /api/oidc/.well-known/openid-configuration > /dev/null
python3 -c "
import json,sys
d=json.load(open('$WORK/body'))
sys.exit(0 if ('issuer' in d and 'data' not in d) else 1)" \
  && ok "OIDC 发现文档保持规范形状" || bad "OIDC 发现文档形状"

# ───────── 25.10 管理员解锁 / 锁定阈值可配 ─────────
#
# 这两项此前是真实的运维缺口：AccountLockoutService 的 unlock_user / unlock_ip
# 实现好了却没有任何路由暴露（四个方法全是死代码），账号被锁只能等 15 分钟
# 或者改库；而阈值硬编码在 LockoutConfig::default()，构造函数收了 Config 却丢掉。
restart_app
sql "DELETE account_lockout" > /dev/null
TOK_SEC="$(login_token admin@test.local "CorrectHorse42!")"

# 造一个锁定中的记录（走登录会先被限流挡住，触发不到阈值）
# 记录 ID 必须与生产一致：AccountLockoutService::lockout_record_id 生成
# `<类型小写>:<标识>`，而 (identifier, lockout_type) 上有唯一索引 ——
# 用随机 ID 造夹具的话，服务写回时会撞索引，测的就不是真实路径了。
sql "CREATE type::record('account_lockout', 'user:locked-user@test.local') CONTENT {
       identifier: 'locked-user@test.local', lockout_type: 'User', failed_attempts: 9,
       status: 'Locked', locked_at: time::now(), locked_until: time::now() + 1h,
       last_attempt_at: time::now(), created_at: time::now(), updated_at: time::now() }" > /dev/null

# 查询：管理员能看到锁定状态，且与登录链路看到的是同一份判定
eq 200 "$(req GET "/api/security/lockout?scope=user&identifier=locked-user%40test.local" \
    -H "Authorization: Bearer ${TOK_SEC}")" "可查询锁定状态"
has '"is_locked":true' "$(body)" "状态显示为锁定中"

# 越权：普通用户既查不了也解不了
TOK_NOSEC="$(signup nosec@test.local nosecuser)"
eq 403 "$(req GET "/api/security/lockout?scope=user&identifier=locked-user%40test.local" \
    -H "Authorization: Bearer ${TOK_NOSEC}")" "无 security.read 查不了锁定状态"
eq 403 "$(req POST /api/security/unlock -H "Authorization: Bearer ${TOK_NOSEC}" \
    -H 'Content-Type: application/json' \
    -d '{"scope":"user","identifier":"locked-user@test.local"}')" "无 security.write 解不了锁"

# 解锁
eq 200 "$(req POST /api/security/unlock -H "Authorization: Bearer ${TOK_SEC}" \
    -H 'Content-Type: application/json' \
    -d '{"scope":"user","identifier":"locked-user@test.local"}')" "管理员可解锁"
has '"unlocked":true' "$(body)" "报告确实解除了一个锁定中的记录"

# 幂等：再解一次返回 false 而不是报错
req POST /api/security/unlock -H "Authorization: Bearer ${TOK_SEC}" \
    -H 'Content-Type: application/json' \
    -d '{"scope":"user","identifier":"locked-user@test.local"}' > /dev/null
has '"unlocked":false' "$(body)" "重复解锁是幂等的（返回 false 而非报错）"

req GET "/api/security/lockout?scope=user&identifier=locked-user%40test.local" \
    -H "Authorization: Bearer ${TOK_SEC}" > /dev/null
has '"is_locked":false' "$(body)" "解锁后状态归位"

# 解锁必须留审计 —— 只记上锁不记解锁的话，审计里会留下一串没有下文的锁定事件
sleep 1
# 上面调了两次解锁（第二次验幂等），两次都该留痕 —— 审计要记的是
# "谁在什么时候试图解锁了什么"，第二次是空操作这件事本身也值得记下来。
eq 2 "$(sql_count "SELECT count() FROM user_activity WHERE action = 'lockout_cleared' GROUP ALL")" \
    "两次解锁各写了一条 lockout_cleared 审计（含空操作那次）"

# IP 维度同样可解
sql "CREATE type::record('account_lockout', 'ipaddress:203.0.113.44') CONTENT {
       identifier: '203.0.113.44', lockout_type: 'IpAddress', failed_attempts: 9,
       status: 'Locked', locked_at: time::now(), locked_until: time::now() + 1h,
       last_attempt_at: time::now(), created_at: time::now(), updated_at: time::now() }" > /dev/null
req POST /api/security/unlock -H "Authorization: Bearer ${TOK_SEC}" \
    -H 'Content-Type: application/json' -d '{"scope":"ip","identifier":"203.0.113.44"}' > /dev/null
has '"unlocked":true' "$(body)" "IP 维度同样可解锁"

# 输入校验：空标识与控制字符都要挡（后者会进审计详情与日志）
eq 400 "$(req POST /api/security/unlock -H "Authorization: Bearer ${TOK_SEC}" \
    -H 'Content-Type: application/json' -d '{"scope":"user","identifier":"  "}')" "空标识被拒"

# 解锁之后必须真的能重新登录 —— 这才是这组端点存在的意义
LOCKED_TOKEN="$(signup relock@test.local relockuser)"
sql "CREATE type::record('account_lockout', 'user:relock@test.local') CONTENT {
       identifier: 'relock@test.local', lockout_type: 'User', failed_attempts: 9,
       status: 'Locked', locked_at: time::now(), locked_until: time::now() + 1h,
       last_attempt_at: time::now(), created_at: time::now(), updated_at: time::now() }" > /dev/null
eq 429 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"relock@test.local","password":"CorrectHorse42!"}')" "被锁账号登录返回 429"
req POST /api/security/unlock -H "Authorization: Bearer ${TOK_SEC}" \
    -H 'Content-Type: application/json' -d '{"scope":"user","identifier":"relock@test.local"}' > /dev/null
eq 200 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"relock@test.local","password":"CorrectHorse42!"}')" "解锁后可以重新登录"

group "27. 运行期无 panic"








# ═════════ 30 AIActor 原生认证（挑战—应答） ═════════
#
# 这一组回答一个此前在 Runtime 上完全空白的问题：一个非人主体能不能不伪装成
# 人类账户就完成认证。`ActorKind::AiActor` 一直只是个从未被构造的枚举变体。

# 先复位，再取令牌。紧挨着的上一组是锁定测试，它会留下 account_lockout 记录
# 与登录端点的限流计数 —— 不清掉的话这里 login_token 拿到空串，
# 后面二十条断言全部级联成 401，看起来像 AIActor 路径坏了，其实是脏现场。
# 这是本脚本各小节的既有惯例（见第 12/16/20 组）。
sql "DELETE account_lockout" > /dev/null
sql "DELETE rate_limit" > /dev/null 2>&1
restart_app

TOK_ADMIN_A="$(login_token admin@test.local "CorrectHorse42!")"
TOK_NOPERM="$(login_token plain@test.local "CorrectHorse42!")"

# Ed25519 密钥对（固定种子，可复现）。私钥只存在于这个脚本里 —— 与生产一致：
# SoulAuth 永远不接触它。
python3 - > "$WORK/agentkey.json" <<'PYKEY'
import base64, hashlib, json, sys
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except Exception:
    json.dump({"skip": 1}, sys.stdout); sys.exit()
seed = hashlib.sha256(b"soulauth-integration-agent").digest()
sk = Ed25519PrivateKey.from_private_bytes(seed)
pk = sk.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
json.dump({"public_key": b64(pk)}, sys.stdout)
PYKEY

# 签名工具：把 payload 原样喂给私钥。
sign_payload() {
    python3 - "$1" <<'PYSIG'
import base64, hashlib, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
seed = hashlib.sha256(b"soulauth-integration-agent").digest()
sk = Ed25519PrivateKey.from_private_bytes(seed)
print(base64.urlsafe_b64encode(sk.sign(sys.argv[1].encode())).decode().rstrip("="))
PYSIG
}

if python3 -c "import json,sys; sys.exit(0 if 'skip' in json.load(open('$WORK/agentkey.json')) else 1)"; then
    printf '  %s AIActor 组已跳过（缺 python cryptography）\n' "$(c_dim ○)"
else

AGENT_PK="$(python3 -c "import json;print(json.load(open('$WORK/agentkey.json'))['public_key'])")"

# ── 注册 ──
eq 403 "$(req POST /api/actors -H "Authorization: Bearer ${TOK_NOPERM}" \
    -H 'Content-Type: application/json' \
    -d "{\"public_key\":\"${AGENT_PK}\",\"label\":\"it-agent\"}")" \
    "无 actors.write 不能注册非人主体"

eq 200 "$(req POST /api/actors -H "Authorization: Bearer ${TOK_ADMIN_A}" \
    -H 'Content-Type: application/json' \
    -d "{\"public_key\":\"${AGENT_PK}\",\"label\":\"it-agent\"}")" \
    "管理员可注册 AIActor"

AGENT_ID="$(python3 -c "
import json
d=json.load(open('$WORK/body'))
print(d['actor']['id'])" 2>/dev/null)"

python3 -c "
import json,sys
d=json.load(open('$WORK/body'))
sys.exit(0 if d['actor']['actor_kind']=='ai_actor' else 1)" \
  && ok "新主体的 actor_kind 是 ai_actor" || bad "actor_kind" "$(body|head -c 120)"

# 最要紧的存储层不变式：这个主体名下**没有** human_account。
eq 0 "$(sql_count "SELECT count() FROM human_account WHERE actor_identity_id = ${AGENT_ID} GROUP ALL")" \
    "AIActor 名下没有 human_account"

# 同一枚公钥不得注册两次 —— 两个 Actor 共用一把钥匙会让审计归因失效。
eq 400 "$(req POST /api/actors -H "Authorization: Bearer ${TOK_ADMIN_A}" \
    -H 'Content-Type: application/json' \
    -d "{\"public_key\":\"${AGENT_PK}\",\"label\":\"dup\"}")" \
    "同一公钥不得重复注册"

# 畸形公钥在注册时就被拒，而不是留到第一次认证才以"签名不通过"暴露。
eq 400 "$(req POST /api/actors -H "Authorization: Bearer ${TOK_ADMIN_A}" \
    -H 'Content-Type: application/json' -d '{"public_key":"not-base64!!","label":"x"}')" \
    "畸形公钥在注册时被拒"

# ── 认证 ──
eq 200 "$(req POST /api/actors/challenge -H 'Content-Type: application/json' \
    -d "{\"actor_id\":\"${AGENT_ID}\"}")" "可领取挑战（公开端点）"
NONCE="$(jget nonce)"
PAYLOAD="$(jget payload)"

# 服务端给出的 payload 必须与按规范拼出来的逐字节一致，否则每个 SDK 都得靠猜。
python3 - "$APP" "$AGENT_ID" "$NONCE" "$PAYLOAD" <<'PYCHK'
import sys
app, actor, nonce, payload = sys.argv[1:5]
expected = "soulauth-ai-actor-auth/v1\n" + app.rstrip("/") + "\n" + actor + "\n" + nonce
sys.exit(0 if expected == payload else 1)
PYCHK
[ $? -eq 0 ] && ok "被签名内容与规范逐字节一致" || bad "canonical payload" "$PAYLOAD"

SIG="$(sign_payload "$PAYLOAD")"
eq 200 "$(req POST /api/actors/authenticate -H 'Content-Type: application/json' \
    -d "{\"actor_id\":\"${AGENT_ID}\",\"nonce\":\"${NONCE}\",\"algorithm\":\"ed25519\",\"signature\":\"${SIG}\"}")" \
    "签名正确即可换到会话"
AGENT_TOK="$(jget token)"

# 挑战一次性。
eq 401 "$(req POST /api/actors/authenticate -H 'Content-Type: application/json' \
    -d "{\"actor_id\":\"${AGENT_ID}\",\"nonce\":\"${NONCE}\",\"algorithm\":\"ed25519\",\"signature\":\"${SIG}\"}")" \
    "重放同一 nonce 被拒"

# 算法不接受协商。
req POST /api/actors/challenge -H 'Content-Type: application/json' \
    -d "{\"actor_id\":\"${AGENT_ID}\"}" > /dev/null
N2="$(jget nonce)"; P2="$(jget payload)"; S2="$(sign_payload "$P2")"
eq 400 "$(req POST /api/actors/authenticate -H 'Content-Type: application/json' \
    -d "{\"actor_id\":\"${AGENT_ID}\",\"nonce\":\"${N2}\",\"algorithm\":\"rsa\",\"signature\":\"${S2}\"}")" \
    "算法白名单外的取值被拒"

# 错误签名被拒。
req POST /api/actors/challenge -H 'Content-Type: application/json' \
    -d "{\"actor_id\":\"${AGENT_ID}\"}" > /dev/null
N3="$(jget nonce)"
BAD_SIG="$(sign_payload "wrong-payload")"
eq 401 "$(req POST /api/actors/authenticate -H 'Content-Type: application/json' \
    -d "{\"actor_id\":\"${AGENT_ID}\",\"nonce\":\"${N3}\",\"algorithm\":\"ed25519\",\"signature\":\"${BAD_SIG}\"}")" \
    "错误签名被拒"

# 一次失败也会烧掉挑战：允许对同一枚 nonce 反复试签名等于把它变成爆破靶子。
P3_RETRY="soulauth-ai-actor-auth/v1
${APP}
${AGENT_ID}
${N3}"
S3_RETRY="$(sign_payload "$P3_RETRY")"
eq 401 "$(req POST /api/actors/authenticate -H 'Content-Type: application/json' \
    -d "{\"actor_id\":\"${AGENT_ID}\",\"nonce\":\"${N3}\",\"algorithm\":\"ed25519\",\"signature\":\"${S3_RETRY}\"}")" \
    "失败过的挑战不能再用正确签名补救"

# ── 会话边界 ──
eq 200 "$(req GET /api/actors/me -H "Authorization: Bearer ${AGENT_TOK}")" \
    "Agent 可以自省 /api/actors/me"

# 整组里最要紧的一条：Agent 令牌不得在人类端点上通过。
eq 403 "$(req GET /api/auth/me -H "Authorization: Bearer ${AGENT_TOK}")" \
    "Agent 令牌在人类端点上被明确拒绝"
eq 403 "$(req GET /api/me/profile -H "Authorization: Bearer ${AGENT_TOK}")" \
    "Agent 令牌拿不到人类档案"
eq 403 "$(req GET /api/actors/me -H "Authorization: Bearer ${TOK_ADMIN_A}")" \
    "人类令牌被 /api/actors/me 拒绝"

# ── 密钥轮换与吊销 ──
req GET "/api/actors/${AGENT_ID}/credentials" -H "Authorization: Bearer ${TOK_ADMIN_A}" > /dev/null
CRED_ID="$(python3 -c "import json;print(json.load(open('$WORK/body'))[0]['id'])" 2>/dev/null)"

python3 -c "
import json,sys
d=json.load(open('$WORK/body'))
leaked = [k for c in d for k in c if 'private' in k or 'secret' in k]
sys.exit(0 if not leaked else 1)" \
  && ok "凭证列表不含任何私有材料" || bad "凭证列表泄露" "$(body|head -c 120)"

eq 200 "$(req DELETE "/api/actors/${AGENT_ID}/credentials/${CRED_ID}" \
    -H "Authorization: Bearer ${TOK_ADMIN_A}")" "可吊销密钥"

# 吊销之后同一把钥匙再也认证不了。
req POST /api/actors/challenge -H 'Content-Type: application/json' \
    -d "{\"actor_id\":\"${AGENT_ID}\"}" > /dev/null
N4="$(jget nonce)"; P4="$(jget payload)"; S4="$(sign_payload "$P4")"
eq 401 "$(req POST /api/actors/authenticate -H 'Content-Type: application/json' \
    -d "{\"actor_id\":\"${AGENT_ID}\",\"nonce\":\"${N4}\",\"algorithm\":\"ed25519\",\"signature\":\"${S4}\"}")" \
    "已吊销的密钥无法再认证"

# 吊销是改状态而不是删记录 —— 否则历史审计追不回"这次用的是哪把钥匙"。
eq 1 "$(sql_count "SELECT count() FROM ai_actor_credential WHERE status = 'revoked' GROUP ALL")" \
    "吊销保留记录，只改状态"

# 拿人类的 actor_id 走这条免口令路径必须失败，否则它就是人类认证的后门。
HUMAN_ACTOR="$(sql "SELECT VALUE type::string(id) FROM actor_identity WHERE actor_kind = 'human' AND status = 'active' LIMIT 1" | grep -oP 'actor_identity:[A-Za-z0-9_-]+' | head -1)"
# 取不到就必须红，不能静默跳过。
#
# 这条断言原本只包在 `if [ -n ... ]` 里、没有 else：某一轮 HUMAN_ACTOR 取空，
# 它一声不响地没有执行，而汇总照样打「全部通过」—— 唯一的痕迹是通过数从 353
# 变成 352。一条守着「人类账号不能走 AIActor 免口令通道」的断言，静默跳过与
# 不存在没有区别，而它看起来还像是过了。
if [ -z "$HUMAN_ACTOR" ]; then
    bad "人类主体不能走 AIActor 认证路径" \
        "取不到活跃的人类 actor_identity，这条断言没能执行 —— 前置数据或 sql 助手有问题"
else
    eq 401 "$(req POST /api/actors/challenge -H 'Content-Type: application/json' \
        -d "{\"actor_id\":\"${HUMAN_ACTOR}\"}")" \
        "人类主体不能走 AIActor 认证路径"
fi

fi

# ── 27. 优雅关闭：SIGTERM 不该丢审计事件 ──
#
# 审计写入是队列 + 专用写入任务，`record` 投完队列就返回。这带来一个新的失败
# 模式：进程在写入任务把队列消费完之前退出，排队中的事件就没了。
#
# 这一组是唯一验证那条关闭路径的地方 —— 其余每一处停服务用的都是 `kill -9`，
# 走不到它。断言建在两件可观测的事实上，不建在日志文案上（这里
# RUST_LOG=soulauth=warn，关闭那两行 info 根本不会打出来）：
#   ① 进程收到 SIGTERM 后自己退出，而不是被拖住；
#   ② 关闭前那一刻提交的事件，关闭之后能在库里查到。
#
# ② 是必要条件而不是充分条件：那条事件也可能在信号到达之前就已经写完了，
# 那样这条断言只是空转。它拦得住的是「关闭路径把队列整个丢掉」这类改动，
# 拦不住「排空只完成了一半」。要拦后者得能控制写入任务的时序，
# 那需要一个测试专用的注入点 —— 目前没有，写在这里免得有人高估它。
printf '\n%s\n' "$(c_dim "── 27. 优雅关闭 ──")"

SHUT_EMAIL="shutdown-$(date +%s%N | tail -c 7)@example.com"
BEFORE="$(sql_count "SELECT count() AS count FROM user_activity WHERE action = 'login_failed' GROUP ALL")"

# 一次注定失败的登录 = 一条 login_failed 审计事件，然后立刻发 SIGTERM。
req POST /api/auth/login -H 'Content-Type: application/json' \
    -d "{\"email\":\"${SHUT_EMAIL}\",\"password\":\"WrongPassword1!\"}" > /dev/null
kill -TERM "$APP_PID" 2>/dev/null

# 等它自己退出。上限给 15 秒：排空的超时是 5 秒，留足余量。
n=0
while [ $n -lt 30 ] && kill -0 "$APP_PID" 2>/dev/null; do sleep 0.5; n=$((n+1)); done
if kill -0 "$APP_PID" 2>/dev/null; then
    bad "SIGTERM 后进程自行退出" "15 秒后仍在运行，优雅关闭卡住了"
    kill -9 "$APP_PID" 2>/dev/null
else
    ok "SIGTERM 后进程自行退出"
fi

AFTER="$(sql_count "SELECT count() AS count FROM user_activity WHERE action = 'login_failed' GROUP ALL")"
if [ "$AFTER" -gt "$BEFORE" ]; then
    ok "关闭前提交的审计事件已落库"
else
    bad "关闭前提交的审计事件已落库" "关闭前 ${BEFORE} 条，关闭后 ${AFTER} 条 —— 事件在退出时丢了"
fi

# 后面还有断言要读日志，这里不重启；APP_PID 已经退出，cleanup 的 kill -9 是空操作。

PANICS="$(grep -c 'panicked' "$WORK/app.log" 2>/dev/null)"; PANICS="${PANICS:-0}"
eq 0 "$PANICS" "服务日志中无 panic"

# ═══════════════════════════════ 汇总 ═══════════════════════════════

printf '\n%s\n' "────────────────────────────────"

# 通过数的下界。
#
# 零失败不等于跑全了：一条被条件跳过的断言既不计通过、也不计失败，汇总看起来
# 与全绿一模一样。上面那条 AIActor 后门断言就这样消失过一次，而当时唯一能看出
# 异常的，是通过数比前一轮少了 1 —— 那需要有人恰好记得前一轮是多少。
#
# 所以把它写下来。加断言时把这个数一起改大，这跟文档站那份读数是同一条纪律：
# 数字要么是跑出来的，要么就不该出现。
MIN_PASS=355
if [ "$PASS" -lt "$MIN_PASS" ]; then
    printf '%s  通过 %d 项，少于下界 %d —— 有断言被静默跳过了\n' \
        "$(c_red 覆盖不足)" "$PASS" "$MIN_PASS"
    printf '%s\n' "$(c_dim "对比上一轮的 ✓ 清单可定位是哪一条；若确实新增/删除了断言，请同步改 MIN_PASS")"
    exit 1
fi

if [ "$FAIL" -eq 0 ]; then
    printf '%s  通过 %d 项\n' "$(c_grn 全部通过)" "$PASS"
    exit 0
else
    printf '%s  通过 %d 项，失败 %s 项\n' "$(c_red 存在失败)" "$PASS" "$(c_red "$FAIL")"
    printf '%s\n' "$(c_dim "用 KEEP_WORK=1 重跑可保留服务日志与信箱现场")"
    exit 1
fi
