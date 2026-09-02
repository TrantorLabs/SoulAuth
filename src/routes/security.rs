//! 账号 / IP 锁定的查询与解除。
//!
//! # 为什么单独有这一组端点
//!
//! `AccountLockoutService` 从一开始就实现了 `unlock_user` / `unlock_ip` /
//! `check_user_lockout` / `check_ip_lockout`，种子数据里也一直有
//! `soulauth:security.write` 这条权限（授予 admin 与 security_manager）——
//! 但**没有任何路由把它们暴露出来**，四个方法全是死代码。
//!
//! 后果是一个真实的运维缺口：账号被暴力破解防护锁上之后，管理员做不了任何事，
//! 只能等锁定时间自然过期，或者直接改数据库。对一个把「账号锁定」作为卖点的
//! 认证服务，这一条是缺的。

use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Extension, Query},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::{
    config::Config,
    error::AuthError,
    models::{
        account_lockout::LockoutCheckResult,
        permission::names::{SECURITY_READ, SECURITY_WRITE},
        user_activity::{ActivityCategory, ActivityStatus},
    },
    require_permission,
    routes::auth::request_context,
    services::{
        audit_logger::{actions, AuditEvent, AuditLogger},
        database::Database,
    },
    utils::jwt::AuthedUser,
    AppState,
};

pub fn router() -> Router {
    Router::new()
        .route("/lockout", get(get_lockout_status))
        .route("/unlock", post(unlock))
}

/// 锁定作用域。
///
/// 用户维度的标识是**邮箱**（锁定计数在登录失败时按邮箱累加，那时还没有
/// 用户记录可言 —— 不存在的邮箱同样会被计数，否则「有没有留下锁定记录」
/// 本身就成了账号枚举信道）。IP 维度的标识就是 IP 字符串。
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LockoutScope {
    User,
    Ip,
}

#[derive(Debug, Deserialize)]
pub struct LockoutQuery {
    pub scope: LockoutScope,
    /// 用户维度传邮箱，IP 维度传 IP。
    pub identifier: String,
}

#[derive(Debug, Deserialize)]
pub struct UnlockRequest {
    pub scope: LockoutScope,
    pub identifier: String,
}

#[derive(Debug, Serialize)]
pub struct UnlockResponse {
    /// 这次调用是否真的解除了一个**处于锁定中**的记录。
    ///
    /// `false` 表示该标识本来就没有被锁（可能从未失败过，也可能锁已到期）。
    /// 这不是错误：解锁是幂等的，重复调用第二次就会拿到 `false`。
    pub unlocked: bool,
}

/// 查询某个账号 / IP 当前的锁定状态。
///
/// 走 `check_*_lockout` 而不是直接读表：那两个方法会顺带把「已过期的锁定」
/// 归位成正常状态，与登录链路看到的是同一份判定。管理员查到的状态因此
/// 与用户实际遇到的一致，而不是一个仅供观赏的快照。
async fn get_lockout_status(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(app_state): Extension<Arc<AppState>>,
    Query(query): Query<LockoutQuery>,
) -> Result<Json<LockoutCheckResult>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, SECURITY_READ);

    let identifier = normalise(&query.identifier)?;
    let result = match query.scope {
        LockoutScope::User => {
            app_state
                .lockout_service
                .check_user_lockout(&identifier)
                .await?
        }
        LockoutScope::Ip => {
            app_state
                .lockout_service
                .check_ip_lockout(&identifier)
                .await?
        }
    };

    Ok(Json(result))
}

/// 解除锁定。
///
/// 这是一个安全敏感动作 —— 它让一个正在被暴力破解防护挡住的标识重新可以尝试
/// 登录，所以必须留审计。审计事件里记的是操作者与被解锁的标识，
/// 不记任何凭据。
async fn unlock(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(audit): Extension<Arc<AuditLogger>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<UnlockRequest>,
) -> Result<Json<UnlockResponse>, AuthError> {
    let operator_id = user.id()?;
    require_permission!(&db, &operator_id, SECURITY_WRITE);

    let identifier = normalise(&request.identifier)?;
    let unlocked = match request.scope {
        LockoutScope::User => app_state.lockout_service.unlock_user(&identifier).await?,
        LockoutScope::Ip => app_state.lockout_service.unlock_ip(&identifier).await?,
    };

    let ctx = request_context(&addr, &headers, &config);
    audit.record(
        AuditEvent::new(
            actions::LOCKOUT_CLEARED,
            ActivityCategory::Security,
            ActivityStatus::Success,
            ctx.ip_address,
            ctx.user_agent,
        )
        .with_user(operator_id)
        .with_details(serde_json::json!({
            "scope": match request.scope { LockoutScope::User => "user", LockoutScope::Ip => "ip" },
            "identifier": identifier,
            "was_locked": unlocked,
        })),
    );

    Ok(Json(UnlockResponse { unlocked }))
}

/// 标识不能为空，也不能夹带控制字符。
///
/// 控制字符这一条与 `validate_email` 同源：这个值会进审计详情与日志，
/// 放过去等于给了一条 ANSI 注入的入口。
fn normalise(raw: &str) -> Result<String, AuthError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AuthError::ValidationError(
            "identifier is required".to_string(),
        ));
    }
    if trimmed.chars().any(|ch| ch.is_control()) {
        return Err(AuthError::ValidationError(
            "identifier must not contain control characters".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::{normalise, LockoutScope};

    #[test]
    fn identifier_rejects_empty_and_control_characters() {
        assert!(normalise("  ").is_err());
        assert!(normalise("a\u{1b}[31mb@example.com").is_err());
        assert_eq!(
            normalise("  user@example.com  ").unwrap(),
            "user@example.com"
        );
        assert_eq!(normalise("203.0.113.7").unwrap(), "203.0.113.7");
    }

    #[test]
    fn scope_parses_from_lowercase_json() {
        // 查询串与请求体都用小写 —— 这是对外契约，写死在测试里免得被无意改掉。
        let s: LockoutScope = serde_json::from_str("\"user\"").expect("user");
        assert_eq!(s, LockoutScope::User);
        let s: LockoutScope = serde_json::from_str("\"ip\"").expect("ip");
        assert_eq!(s, LockoutScope::Ip);
        assert!(serde_json::from_str::<LockoutScope>("\"User\"").is_err());
    }
}
