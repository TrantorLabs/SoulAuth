#!/usr/bin/env bash
#
# 照 DEPLOYMENT.md「部署步骤」1-7 从零走一遍，验证文档本身是可执行的。
#
# 为什么需要这个脚本：部署文档只靠读是审不出来的。这份文档曾经通不过 ——
# `surreal import` 的参数写成了不存在的 `--conn`，schema 被导进
# `ns=production/db=auth` 而应用默认连 `ns=auth/db=main`，
# 于是进程照常启动、/health 照常返回 ok，直到注册第一个管理员时 500。
# 三处失败全是照着文档做出来的，读十遍也发现不了。
#
# 用法：cargo build && ./tests/deployment_walkthrough.sh
# 退出码：0 表示照文档能从零部署到「拿到一个可用的管理员」。
# 从脚本自身位置推导仓库根，与 integration.sh 同一写法。
#
# 这里曾经写死成某台机器上的绝对路径（`/home/ubuntu/…`）。后果不只是
# 「别人跑不了」：`$ROOT/schema.sql` 不存在时 import 失败，而失败被下面的
# `>/dev/null 2>&1` 吞掉，屏幕上只剩「schema.sql 导入失败」，不给原因 ——
# 一个专门用来证明「文档是可执行的」的脚本，自己不可执行，且不说为什么。
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; SP=8123; AP=8203
export no_proxy="localhost,127.0.0.1" NO_PROXY="localhost,127.0.0.1"
WORK="$(mktemp -d)"; FAIL=0
cleanup(){ kill -9 ${AP_PID:-0} ${DB_PID:-0} 2>/dev/null; rm -rf "$WORK"; }; trap cleanup EXIT
step(){ printf '\n\033[1m[步骤 %s]\033[0m %s\n' "$1" "$2"; }
bad(){ FAIL=$((FAIL+1)); printf '  \033[31m✗ %s\033[0m\n' "$1"; }
ok(){ printf '  \033[32m✓ %s\033[0m\n' "$1"; }

step 1 "启动 SurrealDB 并确认可达"
# 用文件存储，不用 memory。
#
# 这个脚本守的是「照部署文档能不能从零跑到一个可用管理员」，而文档让读者用持久化
# 存储。用 memory 跑，等于永远测不到 datastore 那一行 —— 实际发生过：文档里写的
# `file:soulauth.db` 是 SurrealDB 1.x 的写法，3.x 上直接以
# 「Unable to load the specified datastore」退出，而三道测试全用 memory，
# 一道都没发现，是外部试跑的人撞出来的。
surreal start --bind "127.0.0.1:${SP}" --user root --pass root "surrealkv://$WORK/walkthrough.db" >/dev/null 2>&1 &
DB_PID=$!; disown $DB_PID
for i in $(seq 40); do curl -sSf -o /dev/null --max-time 2 "http://127.0.0.1:${SP}/health" 2>/dev/null && break; sleep 0.5; done
curl -sSf -o /dev/null --max-time 3 "http://127.0.0.1:${SP}/health" 2>/dev/null && ok "SurrealDB OK" || { bad "起不来"; exit 1; }

step 2 "准备环境变量（照文档，含 ns/db）"
export DATABASE_URL=127.0.0.1:${SP}
export DATABASE_NAMESPACE=auth
export DATABASE_NAME=main
export DATABASE_USER=root
export DATABASE_PASS=root
export JWT_SECRET=$(openssl rand -hex 32)
export APP_URL=http://localhost:${AP}
export SMTP_HOST=127.0.0.1
export SMTP_FROM=noreply@example.com
export BIND_ADDR=127.0.0.1:${AP}
ok "已导出（APP_URL 用 loopback，故不需要生产两项）"

step 3 "准备数据库（复用同一组变量）"
# 导入失败必须把 surreal 的原话打出来。以前这两条是 `>/dev/null 2>&1`，
# 于是「OPTION IMPORT 缺失」「文件不存在」「ns/db 打错」三种完全不同的原因
# 在屏幕上长得一模一样：一句「导入失败」。而这个脚本存在的全部意义，
# 就是让照文档做不出来的时候能立刻知道是哪一步、为什么。
import_sql() {
    local file="$1"
    if surreal import --endpoint "http://$DATABASE_URL" \
        --user "$DATABASE_USER" --pass "$DATABASE_PASS" \
        --namespace "$DATABASE_NAMESPACE" --database "$DATABASE_NAME" \
        "$ROOT/$file" > "$WORK/import.log" 2>&1
    then
        ok "$file 导入成功"
    else
        bad "$file 导入失败"
        sed 's/^/      /' "$WORK/import.log" >&2
    fi
}
import_sql schema.sql
import_sql initial_data.sql

step 5 "启动应用程序"
( cd "$ROOT"; RUST_LOG=soulauth=warn exec ./target/debug/soulauth ) > "$WORK/app.log" 2>&1 &
AP_PID=$!; disown $AP_PID
# 等 90 秒而不是 15：首次访问会现场生成一把 2048 位 RSA 密钥，生成时间方差很大，
# 共享 runner 上会比本机慢一个量级。
for i in $(seq 180); do curl -sSf -o /dev/null --max-time 2 "http://127.0.0.1:${AP}/health" 2>/dev/null && break; sleep 0.5; done

step 6 "验证部署 curl /health"
H=$(curl -sSf --max-time 5 "http://127.0.0.1:${AP}/health" 2>/dev/null)
[ -n "$H" ] && ok "$H" || { bad "无响应: $(tail -3 "$WORK/app.log")"; exit 1; }

step "7①" "从启动日志取引导令牌"
BT=$(grep -oP 'Bootstrap token for this process: \K\S+' "$WORK/app.log" | head -1)
[ -n "$BT" ] && ok "取到令牌" || { bad "启动日志里没有引导令牌"; sed 's/^/      /' "$WORK/app.log" | tail -5 >&2; }

step "7②" "用它建第一个管理员"
C=$(curl -sS --max-time 10 -o "$WORK/r" -w '%{http_code}' -X POST "http://127.0.0.1:${AP}/api/bootstrap/admin" \
   -H "Content-Type: application/json" \
   -d "{\"token\":\"${BT}\",\"email\":\"admin@your-domain.com\",\"username\":\"admin\",\"password\":\"CorrectHorse42!\"}" 2>/dev/null)
if [ "$C" = 200 ]; then
  grep -q '"is_admin":true' "$WORK/r" && ok "引导响应直接断言 is_admin" || bad "引导成功但 is_admin 不为 true: $(head -c 120 "$WORK/r")"
else
  bad "返回 $C: $(head -c 160 "$WORK/r")"
fi

step "7②b" "这道门是一次性的"
C2=$(curl -sS --max-time 10 -o "$WORK/r2" -w '%{http_code}' -X POST "http://127.0.0.1:${AP}/api/bootstrap/admin" \
   -H "Content-Type: application/json" \
   -d "{\"token\":\"${BT}\",\"email\":\"second@your-domain.com\",\"username\":\"second\",\"password\":\"CorrectHorse42!\"}" 2>/dev/null)
[ "$C2" = 403 ] && ok "已有管理员后同一令牌被拒（403）" || bad "期望 403，实际 $C2"

step "7③④" "登录并确认 is_admin"
TOK=$(curl -sS --max-time 10 -X POST "http://127.0.0.1:${AP}/api/auth/login" -H "Content-Type: application/json" \
   -d '{"email":"admin@your-domain.com","password":"CorrectHorse42!"}' 2>/dev/null \
   | python3 -c "import json,sys;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [ -z "$TOK" ]; then bad "登录拿不到令牌"; else
  IS=$(curl -sS --max-time 10 "http://127.0.0.1:${AP}/api/auth/me" -H "Authorization: Bearer $TOK" 2>/dev/null \
     | python3 -c "import json,sys;print(json.load(sys.stdin).get('is_admin'))" 2>/dev/null)
  [ "$IS" = "True" ] && ok "is_admin = true —— 部署完成且可用" || bad "is_admin = $IS"
fi

printf '\n\033[1m照修订后文档执行的失败步骤数: %s\033[0m\n' "$FAIL"
