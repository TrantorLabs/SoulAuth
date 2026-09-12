#!/usr/bin/env bash
#
# 照 CHANGELOG.md「Upgrade steps」里的 SQL，对一个**上一版形状**的数据库走一遍升级。
#
# 为什么需要这个脚本：集成测试与部署演练都从空库起。CHANGELOG 里的迁移 SQL 操作的
# 是旧形状的数据 —— 口令还在 `user.password` 列上、`identity_provider` 还在、
# `user_activity.user_id` 还是旧名 —— 而 CI 里从来不存在这种状态。于是那些 SQL 只能
# 凭语法写，没有一条真跑过。这个脚本第一次跑的时候，**三段里有两段是错的**：
# `FOR … CREATE` 在 SurrealDB 3.0 上对含 record 字段的行报
# "Cannot execute statement using value"，`record::id(subject_id)` 在子查询里拿不到值。
# 运维照抄会在最关键的一步失败。
#
# SQL **直接从 CHANGELOG.md 里提取**，不另抄一份 —— 否则文档与脚本又会各说各话。
#
# 上一版的 schema 存在 `tests/fixtures/schema.previous.sql`，不从 git tag 读：
# CI 的 checkout 是 fetch-depth 1，拿不到 tag；而且「上一版是什么形状」本身就该
# 是仓库里一个可审的文件，而不是对 git 历史的一次解引用。发新版时更新它。
#
# 用法：./tests/migration_walkthrough.sh      （需要 surreal 在 PATH）
# 退出码：0 全过；1 有断言失败；2 前置条件不满足。

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export no_proxy="localhost,127.0.0.1" NO_PROXY="localhost,127.0.0.1"

readonly PORT="${MIGRATION_DB_PORT:-8301}"
readonly DB="http://127.0.0.1:${PORT}"
readonly PREVIOUS_SCHEMA="$ROOT/tests/fixtures/schema.previous.sql"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ✓ %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  ✗ %s\n      %s\n' "$1" "${2:-}"; }
eq()  { [ "$1" = "$2" ] && ok "$3" || bad "$3" "期望 [$1]，实际 [$2]"; }

command -v surreal >/dev/null || { echo "surreal 不在 PATH"; exit 2; }
[ -f "$PREVIOUS_SCHEMA" ] || { echo "缺少 $PREVIOUS_SCHEMA"; exit 2; }

WORK="$(mktemp -d)"
cleanup() { [ -n "${DB_PID:-}" ] && kill "$DB_PID" 2>/dev/null; [ -z "${KEEP_WORK:-}" ] && rm -rf "$WORK"; }
trap cleanup EXIT

sql() {
    curl -sS --max-time 30 -u root:root \
        -H 'Accept: application/json' -H 'surreal-ns: auth' -H 'surreal-db: main' \
        --data-binary "$1" "${DB}/sql" 2>/dev/null
}
# 执行并断言每一条语句都 OK
sql_ok() {   # $1=描述 $2=sql
    local out; out="$(sql "$2")"
    local bad_n
    bad_n="$(printf '%s' "$out" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    bad=[x for x in d if x.get('status')!='OK']
    print(len(bad))
    for x in bad[:2]: print('      ', str(x.get('result'))[:200], file=sys.stderr)
except Exception as e:
    print(99); print('      非 JSON 响应:', str(e)[:120], file=sys.stderr)")"
    [ "$bad_n" = 0 ] && ok "$1" || bad "$1" "有 ${bad_n} 条语句失败（见上）"
}
count() {   # $1=sql（GROUP ALL 的计数）
    sql "$1" | python3 -c "
import json,sys
try:
    r=json.load(sys.stdin)[0]['result']
    print(r[0]['count'] if r else 0)
except Exception: print(-1)"
}

# 从 CHANGELOG 的「Upgrade steps」里提取第 N 步的 sql 代码块（按顺序取第 K 个）
changelog_sql() {   # $1=步骤号 $2=该步骤内第几个 sql 块（从 1 起）
    python3 - "$1" "$2" <<'PY'
import re,sys
step,k=sys.argv[1],int(sys.argv[2])
t=open('CHANGELOG.md',encoding='utf-8').read()
# 只看第一个 Upgrade steps 节（Unreleased）
sec=t.split('### Upgrade steps',1)[1].split('\n## ',1)[0]
# 定位步骤：行首 "N. **"
m=re.search(r'^'+re.escape(step)+r'\. \*\*.*?(?=^\d+\. \*\*|\Z)', sec, re.S|re.M)
if not m: sys.exit(1)
blocks=re.findall(r'```sql\n(.*?)```', m.group(0), re.S)
if len(blocks)<k: sys.exit(1)
print(blocks[k-1])
PY
}

echo "── 起一个空库，导入上一版的 schema ──"
surreal start --bind "127.0.0.1:${PORT}" --user root --pass root memory > "$WORK/db.log" 2>&1 &
DB_PID=$!
for _ in $(seq 1 40); do curl -sS -o /dev/null "${DB}/health" 2>/dev/null && break; sleep 0.5; done
OLD_FAILS="$(curl -sS -u root:root -H 'Accept: application/json' -H 'surreal-ns: auth' -H 'surreal-db: main' \
    --data-binary @"$PREVIOUS_SCHEMA" "${DB}/sql" | python3 -c "
import json,sys
d=json.load(sys.stdin); print(len([x for x in d if x.get('status')!='OK' and 'namespace' not in str(x.get('result'))]))")"
eq 0 "$OLD_FAILS" "上一版 schema 导入无误"

echo "── 造上一版形状的数据 ──"
# 2 个有口令的用户、1 个 OAuth 用户（无口令、有 identity_provider）、2 条审计、1 条 profile
sql_ok "写入旧形状的种子数据" "
CREATE actor_identity:a1 CONTENT { subject_key:'sk-a1', actor_kind:'human', identity_source:'local', status:'active', created_at:1, updated_at:1 };
CREATE actor_identity:a2 CONTENT { subject_key:'sk-a2', actor_kind:'human', identity_source:'local', status:'active', created_at:1, updated_at:1 };
CREATE actor_identity:a3 CONTENT { subject_key:'sk-a3', actor_kind:'human', identity_source:'local', status:'active', created_at:1, updated_at:1 };
CREATE user:u1 CONTENT { subject_id: actor_identity:a1, email:'u1@e.com', username:'u1', username_normalized:'u1', password:'\$argon2id\$h1', verified:true, account_status:'Active', membership_level:'FREE', created_at:1, updated_at:1 };
CREATE user:u2 CONTENT { subject_id: actor_identity:a2, email:'u2@e.com', username:'u2', username_normalized:'u2', password:'\$argon2id\$h2', verified:true, account_status:'Active', membership_level:'FREE', created_at:1, updated_at:1 };
CREATE user:u3 CONTENT { subject_id: actor_identity:a3, email:'u3@e.com', username:'u3', username_normalized:'u3', password: NONE, verified:true, account_status:'Active', membership_level:'FREE', created_at:1, updated_at:1 };
CREATE identity_provider CONTENT { provider:'google', provider_user_id:'g-3', user_id: actor_identity:a3, created_at:1, updated_at:1 };
CREATE user_activity CONTENT { user_id: actor_identity:a1, action:'login_success', category:'Authentication', ip_address:'1', user_agent:'u', details:{}, status:'Success', timestamp:1, chain_id:'c', seq:1, previous_hash:'0', event_hash:'h1' };
CREATE user_activity CONTENT { user_id: NONE, action:'login_failed', category:'Authentication', ip_address:'1', user_agent:'u', details:{}, status:'Failed', timestamp:2, chain_id:'c', seq:2, previous_hash:'h1', event_hash:'h2' };
CREATE user_profile CONTENT { user_id: actor_identity:a1, display_name:'U One', created_at:1, updated_at:1 };"

echo "── 导入当前 schema（新表、新列、ASSERT）──"
NEW_FAILS="$(curl -sS -u root:root -H 'Accept: application/json' -H 'surreal-ns: auth' -H 'surreal-db: main' \
    --data-binary @schema.sql "${DB}/sql" | python3 -c "
import json,sys
d=json.load(sys.stdin); print(len([x for x in d if x.get('status')!='OK']))")"
eq 0 "$NEW_FAILS" "当前 schema 叠加到旧库上无误（IF NOT EXISTS 幂等）"

echo "── 步骤 3：会员分布的替代查询 ──"
# 端点删了，CHANGELOG 给运维的替代查询也要能跑 —— 否则那段建议与没有一样。
S3="$(changelog_sql 3 1)" && sql_ok "步骤 3 的替代查询可执行" "$S3"

echo "── 步骤 4：口令 → credential ──"
S4="$(changelog_sql 4 1)" || { bad "从 CHANGELOG 提取步骤 4 的 SQL" "没找到"; }
[ -n "${S4:-}" ] && sql_ok "步骤 4 的 SQL 可执行（逐字取自 CHANGELOG）" "$S4"
eq "$(count "SELECT count() FROM user WHERE password != NONE GROUP ALL")" \
   "$(count "SELECT count() FROM credential WHERE kind = 'password' GROUP ALL")" \
   "步骤 4 的计数核对：有口令的用户数 = 凭证行数"
eq 2 "$(count "SELECT count() FROM credential WHERE kind = 'password' AND status = 'active' GROUP ALL")" "两把口令凭证都是 active"
S4B="$(changelog_sql 4 3)" && sql_ok "步骤 4 收尾：REMOVE FIELD password" "$S4B"

echo "── 步骤 5：user_activity.user_id → actor_identity_id ──"
S5="$(changelog_sql 5 1)" && sql_ok "步骤 5 的 SQL 可执行" "$S5"
eq 1 "$(count "SELECT count() FROM user_activity WHERE actor_identity_id != NONE GROUP ALL")" "有归因的审计行迁过来了"
eq 1 "$(count "SELECT count() FROM user_activity WHERE actor_identity_id = NONE GROUP ALL")" "无归因的审计行保持 NONE"

echo "── 步骤 6：old_sub → new_sub 导出 ──"
S6="$(changelog_sql 6 1)" && sql_ok "步骤 6 的导出查询可执行" "$S6"
MAPPED="$(sql "$S6" | python3 -c "
import json,sys
r=json.load(sys.stdin)[0]['result']
print(len([x for x in r if x.get('new_sub')]))")"
eq 3 "$MAPPED" "三个账号都导出了 old_sub → new_sub"

echo "── 步骤 7：identity_provider → identity_binding ──"
S7="$(changelog_sql 7 1)" && sql_ok "步骤 7 的 SQL 可执行" "$S7"
eq 1 "$(count "SELECT count() FROM identity_binding WHERE provider = 'google' AND provider_subject = 'g-3' AND verification_state = 'verified' GROUP ALL")" \
   "identity_provider 那一行变成了 verified 的 identity_binding"
TABLE_GONE="$(sql "SELECT count() FROM identity_provider GROUP ALL" | python3 -c "
import json,sys
d=json.load(sys.stdin)[0]; print('gone' if d.get('status')!='OK' else 'still-there')")"
eq gone "$TABLE_GONE" "identity_provider 表已删除"

echo "── 步骤 8：预检越界值，然后用 OVERWRITE 套上 ASSERT ──"
# `DEFINE FIELD IF NOT EXISTS` 对已存在的列不更新定义 —— 所以重导 schema 之后
# ASSERT 根本没生效。这就是这个脚本第一次跑时最后一条断言红掉的原因。
S8CHECK="$(changelog_sql 8 2)" && sql_ok "步骤 8 的预检查询可执行" "$S8CHECK"
eq 0 "$(sql "$S8CHECK" | python3 -c "import json,sys;print(len(json.load(sys.stdin)[0]['result']))")" "没有越界的枚举值"
S8="$(changelog_sql 8 1)" && sql_ok "步骤 8 的 OVERWRITE 重定义可执行" "$S8"

echo "── 步骤 10：user_profile.user_id → actor_identity_id ──"
S10="$(changelog_sql 10 1)" && sql_ok "步骤 10 的 SQL 可执行" "$S10"
eq 1 "$(count "SELECT count() FROM user_profile WHERE actor_identity_id != NONE GROUP ALL")" "profile 的引用迁过来了"

echo "── 迁完之后：新 schema 的约束真的在管事 ──"
BAD="$(sql "UPDATE actor_identity:a1 SET status = 'bogus'" | python3 -c "
import json,sys;d=json.load(sys.stdin)[0];print('rejected' if d.get('status')!='OK' else 'accepted')")"
eq rejected "$BAD" "迁移后的库拒绝非法的 actor status（ASSERT 生效）"

printf '\n────────────────────────────────\n'
if [ "$FAIL" -eq 0 ]; then
    printf '全部通过  通过 %d 项\n' "$PASS"; exit 0
else
    printf '存在失败  通过 %d 项，失败 %d 项\n' "$PASS" "$FAIL"; exit 1
fi
