//! 首个管理员的引导路径。
//!
//! # 为什么需要它
//!
//! 一个全新实例存在死锁：注册 OIDC Client 需要 `soulauth:oidc_clients.write`，
//! 该权限来自 `admin` 角色，而第一个 admin 此前**只能直接写数据库**授予。
//! 于是「跑通第一次认证」这条最基本的开发者路径，必须绕过公开接口。
//!
//! 公开文档把这一条定成了硬要求：
//!
//! - 03｜Quickstart：「一个全新的 SoulAuth 实例，应该让开发者在**不直接修改
//!   数据库**的情况下，从零走到第一份经过验证的 Actor 身份。」
//! - 10｜Register a Client：「Client Registration ≠ Direct Database Mutation」，
//!   并要求存在受支持的 Bootstrap Mechanism。
//!
//! # 为什么不落库
//!
//! 引导令牌只存在于进程内存，不进 schema。理由是这个门的**成功条件恰好就是
//! 它的停用条件**：一旦系统里有了 admin，这个端点就永久拒绝服务，与令牌是否
//! 还「有效」无关。既然如此就没有「已消费」这个状态要持久化 —— 少一张表，
//! 也少一处 Stage 1 重写 schema 时要跟着改的地方。
//!
//! 代价是重启会换一枚新令牌。这不构成问题：令牌只在「尚无 admin」的窗口里
//! 有意义，而那个窗口一旦关闭就不会重新打开。
//!
//! 多副本部署下每个副本会各自生成一枚。需要确定值时用
//! `SOULAUTH_BOOTSTRAP_TOKEN` 显式指定；设为空串则完全关闭这条路径。

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, Extension},
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use crate::{
    config::Config,
    error::AuthError,
    models::{
        user::CreateUserRequest,
        user_activity::{ActivityCategory, ActivityStatus},
    },
    routes::auth::request_context,
    services::{
        audit_logger::{AuditEvent, AuditLogger},
        auth::AuthService,
        database::Database,
        rbac::RBACService,
    },
    AppState,
};

/// 引导端点两种失败共用的对外文案。
///
/// 「令牌错」与「门已关」必须逐字节相同，否则状态码统一了、信道搬到 body 里。
/// 措辞刻意不提管理员是否存在：它要能同时诚实地描述这两种情况。
const BOOTSTRAP_UNAVAILABLE: &str = "Bootstrap is not available";

/// 引导令牌所需的字符数。
///
/// 32 个 base62 字符约 190 bit。它在「尚无 admin」的窗口里保护的是整个实例的
/// 管理权，而这个窗口通常没有限流之外的其它防护，所以不吝啬熵。
const TOKEN_LEN: usize = 32;

/// 引导门。
///
/// 只负责「这枚令牌对不对」。「现在还该不该放行」由请求时的 admin 存在性判定，
/// 两者分开：前者是静态秘密，后者是动态系统状态。
pub struct BootstrapGate {
    /// `None` 表示这条路径被显式关闭。
    token: Option<String>,
}

impl BootstrapGate {
    /// 依配置建门。
    ///
    /// - 显式给了非空值：用它（多副本或自动化部署需要确定值）
    /// - 显式给了空串：关闭这条路径
    /// - 没给：随机生成一枚
    pub fn new(configured: Option<&str>) -> Self {
        let token = match configured {
            Some("") => None,
            Some(value) => Some(value.to_string()),
            None => Some(
                rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(TOKEN_LEN)
                    .map(char::from)
                    .collect(),
            ),
        };
        Self { token }
    }

    /// 供启动时打印。关闭状态下返回 `None`。
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// 常量时间比对。
    ///
    /// 这里用等时比较不是形式主义：引导窗口期内，令牌就是整个实例的管理权，
    /// 而攻击者可以不受限地重试。
    fn verify(&self, presented: &str) -> bool {
        match &self.token {
            None => false,
            Some(expected) => {
                crate::utils::crypto::constant_time_eq(expected.as_bytes(), presented.as_bytes())
            }
        }
    }
}

pub fn router() -> Router {
    Router::new().route("/admin", post(bootstrap_admin))
}

#[derive(Debug, Deserialize)]
pub struct BootstrapAdminRequest {
    /// 启动日志里打印的那枚令牌。
    pub token: String,
    pub email: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct BootstrapAdminResponse {
    pub user_id: String,
    pub email: String,
    /// 恒为 `true`。写出来是为了让调用方能直接断言，而不必再查一次
    /// `/api/auth/me` 才知道这次引导到底有没有生效。
    pub is_admin: bool,
}

/// 引导端点对外唯一的拒绝答复。
///
/// 常量管住文案，这个构造器管住状态码 —— 两样都只有一处来源。只有常量的话，
/// `AuthError::Forbidden(...)` 仍然写了两遍，其中一遍被改成 `Unauthorized`
/// 就够重新打开信道；那种漂移只能靠测试去数，而这里让它压根写不出来。
///
/// 两种失败的区分留在 `warn!` 与审计行里 —— 运维看得到，匿名调用方看不到。
fn bootstrap_rejected() -> AuthError {
    AuthError::Forbidden(BOOTSTRAP_UNAVAILABLE.to_string())
}

/// 建立第一个管理员。
///
/// 前置条件有两条，缺一不可：令牌正确，且系统中**尚无**任何管理员。
/// 任何一条不满足都返回 403 —— 它不是一个可以反复调用的提权入口，
/// 而是一次性的开机门。
///
/// 两种失败共用同一个状态码和同一段文案，都经 `bootstrap_rejected()` 构造，
/// 见下面 ① ② 的说明。
async fn bootstrap_admin(
    Extension(db): Extension<Arc<Database>>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(audit): Extension<Arc<AuditLogger>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<BootstrapAdminRequest>,
) -> Result<Json<BootstrapAdminResponse>, AuthError> {
    let ctx = request_context(&addr, &headers, &config);

    // ① 先看系统状态，再看令牌。
    //
    // 顺序是刻意的：已经有 admin 之后，无论令牌对不对都必须拒绝，而且两种情况
    // 要给同一个答复。反过来先验令牌的话，「令牌错」与「已初始化」会返回不同
    // 状态码，等于把一枚失效令牌变成探测实例是否已初始化的信道。
    //
    // 但只调顺序堵不住这条信道 —— 它只统一了「已初始化」那一侧。**未**初始化时
    // 令牌错如果返回 401，拿一枚废令牌打一次就够了：401 = 未初始化、403 = 已初始化，
    // 探针照常工作。所以两种失败必须共用同一个状态码**和同一段文案**（见 ②），
    // 文案里也不能出现 "an administrator already exists" 这种泄露状态的措辞。
    if admin_exists(&db).await? {
        warn!(
            ip = %ctx.ip_address,
            "Bootstrap rejected: an administrator already exists"
        );
        audit.record(
            AuditEvent::new(
                "bootstrap_rejected",
                ActivityCategory::Security,
                ActivityStatus::Failed,
                ctx.ip_address.clone(),
                ctx.user_agent.clone(),
            )
            .with_details(serde_json::json!({ "reason": "already_initialized" })),
        );
        return Err(bootstrap_rejected());
    }

    // ② 校验令牌。失败也要留审计 —— 引导窗口期的爆破尝试正是要留痕的事。
    //
    // 对外的答复与 ① 逐字节相同。代价是运维把令牌敲错时，客户端那侧看不出
    // 「是令牌错了」还是「门已经关了」—— 所以真实原因写进日志和审计行，
    // 留在服务端。排错线索一点没少，只是不再对匿名调用方开放。
    if !app_state.bootstrap.verify(&request.token) {
        warn!(
            ip = %ctx.ip_address,
            "Bootstrap rejected: invalid token (no administrator exists yet)"
        );
        audit.record(
            AuditEvent::new(
                "bootstrap_rejected",
                ActivityCategory::Security,
                ActivityStatus::Failed,
                ctx.ip_address.clone(),
                ctx.user_agent.clone(),
            )
            .with_details(serde_json::json!({ "reason": "invalid_bootstrap_token" })),
        );
        return Err(bootstrap_rejected());
    }

    // ③ 抢占这道门。
    //
    // ① 的 `admin_exists` 是一次读，它和后面的写之间隔着两步 —— 两个并发请求
    // 可以都读到「还没有管理员」、都往下走、都建出一个管理员。整个流程里必须有
    // 一个**原子**的判据，就是这一步：`CREATE` 到一个固定的 record id 上，
    // 已存在就直接报错，谁先谁赢。
    //
    // ① 那次读并没有因此变得多余：它负责的是「已初始化」与「令牌错」两条路径
    // 返回逐字相同的答复，那是防探测，不是防并发。
    //
    // ④ 建账号，或者认领一次没做完的引导。走与普通注册完全相同的路径 ——
    //    密码策略、邮箱校验、唯一约束一个都不能因为「这是第一个用户」而放宽。
    //    拿到 `Resumed(user_id)` 说明上一次卡在「账号建好了、角色没授上」，
    //    这次带同一枚令牌、同一个邮箱回来，接着把角色补上就行。
    let rbac = RBACService::new(db.clone());
    let user_id = match claim_bootstrap(&db, &request.email).await? {
        Claim::Fresh => {
            let registered = auth_service
                .register(
                    CreateUserRequest {
                        email: request.email.clone(),
                        username: Some(request.username.clone()),
                        password: request.password.clone(),
                    },
                    &ctx,
                )
                .await;

            match registered {
                Ok((auth_response, _verification)) => {
                    let user_id = auth_response.user.id.clone();
                    // 账号一建出来就立刻记进 claim 行。
                    //
                    // 放在这里而不是「授予角色失败之后」，是因为进程可能在这两步
                    // 之间**崩掉** —— 那种情况下没有任何错误分支会跑，claim 行会
                    // 停在 `claiming` 且没有 user_id，重试认不出来，实例就卡在
                    // 「邮箱被占、门被占、还是没有管理员」上。
                    mark_role_pending(&db, &user_id).await;
                    user_id
                }
                Err(e) => {
                    // 账号都没建出来，这一行留着没有意义，删掉让运维原样重来。
                    release_bootstrap(&db).await;
                    return Err(e);
                }
            }
        }
        Claim::Resumed(user_id) => {
            warn!(
                user_id = %user_id,
                "Resuming a bootstrap that stopped after the account was created"
            );
            user_id
        }
    };

    // ⑤ 授予 admin。
    //
    // 走 `assign_role_as_system`：这次授予没有人类操作者，伪造一个空壳 User
    // 去冒充操作者会污染日志与归因。
    if let Err(e) = rbac.assign_role_as_system(&user_id, "admin").await {
        // 这里**不删** claim 行。删了就退回「邮箱被一个没有角色的账号占着，
        // 而且没法恢复」。它在上一步已经被记成 `role_pending`，
        // 带同一枚令牌、同一个邮箱再来一次即可从这里续上。
        error!(
            user_id = %user_id,
            "Bootstrap failed while granting the admin role. Retry the same request \
             with the same token and email — it will resume from here."
        );
        return Err(e);
    }

    // 这道门本来就已经关上了（`admin_exists` 从此为真），标一下只是让运维
    // 看这张表时能读懂它停在哪。失败无所谓，所以不上抛。
    finish_bootstrap(&db).await;

    audit.record(
        AuditEvent::new(
            "bootstrap_admin_created",
            ActivityCategory::Security,
            ActivityStatus::Success,
            ctx.ip_address,
            ctx.user_agent,
        )
        .with_user(user_id.clone())
        .with_details(serde_json::json!({ "email": request.email })),
    );

    tracing::warn!(
        "Bootstrap consumed: administrator {} created. \
         This endpoint is now permanently closed on this instance.",
        request.email
    );

    Ok(Json(BootstrapAdminResponse {
        user_id,
        email: request.email,
        is_admin: true,
    }))
}

/// 抢占的结果。
enum Claim {
    /// 门是新占下的，账号还得建。
    Fresh,
    /// 上一次卡在「账号建好了、角色没授上」，接着给这个 user_id 补授即可。
    Resumed(String),
}

/// 抢占引导闸门，或者认领一次没做完的引导。
///
/// `CREATE` 打在固定 record id `bootstrap_claim:singleton` 上：SurrealDB 对
/// 已存在的 record id 直接报 `already exists`，于是「检查 + 占用」压成一条语句。
/// 这是整个流程里唯一的原子判据。
///
/// 占不到的时候还要再看一眼那一行：如果它停在 `role_pending`、而且邮箱与这次
/// 请求一致，那就是同一个人在重试同一次引导，放行去补授角色。
///
/// **恢复只认那一行里记着的 `user_id`，不按邮箱查用户。** 注册是开放的，
/// 按邮箱认领等于让人抢注 `admin@公司.com`，等运维引导时白捡一个管理员。
async fn claim_bootstrap(db: &Database, email: &str) -> Result<Claim, AuthError> {
    let create = "CREATE type::record('bootstrap_claim', 'singleton') \
                  SET claimed_at = time::now(), email = $email, stage = 'claiming'";
    if db
        .raw_query(
            "bootstrap_claim",
            create,
            serde_json::json!({ "email": email }),
        )
        .await
        .is_ok()
    {
        return Ok(Claim::Fresh);
    }

    let sql = "SELECT stage, email, user_id FROM type::record('bootstrap_claim', 'singleton')";
    let rows: Vec<serde_json::Value> = db
        .query_take0_vec_no_bind("bootstrap_claim_read", sql)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    let row = rows.first().ok_or_else(|| {
        warn!("Bootstrap gate is claimed but the claim row could not be read");
        bootstrap_rejected()
    })?;

    let stage = row.get("stage").and_then(|v| v.as_str()).unwrap_or("");
    let claimed_email = row.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let user_id = row.get("user_id").and_then(|v| v.as_str()).unwrap_or("");

    if stage == "role_pending" && claimed_email == email && !user_id.is_empty() {
        return Ok(Claim::Resumed(user_id.to_string()));
    }

    warn!(
        stage,
        "Bootstrap gate is already claimed and this request cannot resume it"
    );
    Err(bootstrap_rejected())
}

/// 放开引导闸门，让运维原样重来。只在账号都没建出来时调用。
///
/// 失败只记日志不上抛：调用它的时候手上已经有一个更该返回给调用方的错误了，
/// 用「清理失败」把「引导失败」盖掉，只会让排错更难。
async fn release_bootstrap(db: &Database) {
    let sql = "DELETE type::record('bootstrap_claim', 'singleton')";
    if let Err(e) = db.raw_query_no_bind("bootstrap_release", sql).await {
        error!(
            "Failed to release the bootstrap gate: {e}. \
             This instance now has no administrator and the gate is stuck; \
             delete bootstrap_claim:singleton by hand to retry."
        );
    }
}

/// 记下「账号已建、角色未授」，让同一枚令牌 + 同一个邮箱的重试能续上。
async fn mark_role_pending(db: &Database, user_id: &str) {
    let sql = "UPDATE type::record('bootstrap_claim', 'singleton') \
               SET stage = 'role_pending', user_id = $user_id";
    if let Err(e) = db
        .raw_query(
            "bootstrap_mark_pending",
            sql,
            serde_json::json!({ "user_id": user_id }),
        )
        .await
    {
        error!(
            "Failed to record the half-finished bootstrap: {e}. \
             Account {user_id} exists without the admin role and cannot be resumed \
             automatically; grant it by hand or clear bootstrap_claim:singleton."
        );
    }
}

/// 标记引导完成。纯粹是给运维看的，门早已由 `admin_exists` 关上。
async fn finish_bootstrap(db: &Database) {
    let sql = "UPDATE type::record('bootstrap_claim', 'singleton') SET stage = 'done'";
    if let Err(e) = db.raw_query_no_bind("bootstrap_finish", sql).await {
        warn!("Failed to mark the bootstrap claim as done: {e}");
    }
}

/// 系统中是否已经存在任何管理员。
///
/// 查的是 `user_role` 而不是某个具体用户：这个端点关心的是「这个实例是否已经
/// 被引导过」，不是「某人是不是 admin」。
pub async fn admin_exists(db: &Database) -> Result<bool, AuthError> {
    // `role_id` 是 record 类型。经 JSON 绑定传入的 record ID 会退化成字符串，
    // 于是 `role_id = $x` 恒不成立 —— 这个坑在本仓多处都有注释。用
    // `type::record()` 在库内构造，两侧类型一致。
    //
    // 取值走 `serde_json::Value` 而不是直接反序列化成 `i64`：这是本仓既有
    // count 查询的统一写法（见 `services::audit` 与 `routes::ops`）。
    let sql = "SELECT count() AS count FROM user_role \
               WHERE role_id = type::record('role', 'admin') GROUP ALL";
    let rows: Vec<serde_json::Value> = db
        .query_take0_vec_no_bind("bootstrap_admin_exists", sql)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    let count = rows
        .first()
        .and_then(|row| row.get("count"))
        .and_then(|c| c.as_i64())
        .unwrap_or(0);
    Ok(count > 0)
}

#[cfg(test)]
mod tests {
    use super::BootstrapGate;

    #[test]
    fn generated_token_has_expected_entropy() {
        let gate = BootstrapGate::new(None);
        let token = gate.token().expect("未配置时应当生成一枚");
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn two_gates_do_not_share_a_token() {
        // 生成必须是随机的。固定值会让「重启换一枚」这个前提失效。
        let a = BootstrapGate::new(None);
        let b = BootstrapGate::new(None);
        assert_ne!(a.token(), b.token());
    }

    #[test]
    fn explicit_value_is_used_verbatim() {
        let gate = BootstrapGate::new(Some("fixed-value-for-replicas"));
        assert_eq!(gate.token(), Some("fixed-value-for-replicas"));
        assert!(gate.verify("fixed-value-for-replicas"));
    }

    #[test]
    fn empty_string_disables_the_path_entirely() {
        let gate = BootstrapGate::new(Some(""));
        assert_eq!(gate.token(), None);
        // 关闭之后任何输入都不放行，包括空串本身。
        assert!(!gate.verify(""));
        assert!(!gate.verify("anything"));
    }

    #[test]
    fn verify_rejects_near_misses() {
        let gate = BootstrapGate::new(Some("correct-token"));
        assert!(!gate.verify("correct-toke"));
        assert!(!gate.verify("correct-tokenx"));
        assert!(!gate.verify("Correct-token"));
        assert!(gate.verify("correct-token"));
    }
}
