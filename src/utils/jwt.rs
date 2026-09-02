use std::sync::Arc;

use crate::{
    error::{AuthError, Result},
    models::{actor_identity::ActorIdentity, subject::SubjectType, user::User},
    services::{auth_cache::AuthCache, database::Database},
};
use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::request::Parts,
    RequestPartsExt,
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub subject_type: Option<SubjectType>,
}

/// MFA 两步登录中的临时令牌。
///
/// 它**不对应任何会话记录**，因此永远无法通过 `Claims` 提取器 —— 只能被
/// `/api/auth/mfa/login-verify` 用 `decode_mfa_token` 单独解析。
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaChallengeClaims {
    pub sub: String,
    /// 账号邮箱。带上它是为了让 MFA 这一步能沿用**与第一步同一个**账号锁定计数器
    /// （锁定记录以邮箱为标识），不必再查一次库。
    pub email: String,
    pub exp: i64,
    pub iat: i64,
    /// 固定为 `"mfa_challenge"`，防止普通访问令牌被当作 MFA 令牌复用。
    pub purpose: String,
}

/// 解析出来的 MFA 挑战信息。
#[derive(Debug, Clone)]
pub struct MfaChallenge {
    pub user_id: String,
    pub email: String,
}

pub const MFA_CHALLENGE_PURPOSE: &str = "mfa_challenge";
pub const MFA_CHALLENGE_TTL_SECONDS: i64 = 300;

fn jwt_secret() -> Result<String> {
    std::env::var("JWT_SECRET").map_err(|_| AuthError::InvalidToken)
}

/// 只校验签名与有效期，**不校验会话是否仍然存在**。
///
/// 仅供确实不需要吊销语义的场合使用（例如解析刚签发、尚未落库的令牌）。
/// 面向请求的鉴权一律走 `Claims` 提取器或 `decode_and_verify_token`。
pub fn decode_token_claims(token: &str) -> Result<Claims> {
    let jwt_secret = jwt_secret()?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| AuthError::InvalidToken)?;

    Ok(token_data.claims)
}

/// 校验令牌背后的会话是否仍然有效。
///
/// 这是登出能够真正生效的关键：`logout` 删除 session 行之后，对应的 JWT
/// 会立刻在这里被拒绝，而不是继续可用到 24 小时后自然过期。
pub async fn verify_session_active(db: &Database, token: &str) -> Result<()> {
    let rows: Vec<serde_json::Value> = db
        .query_take0_vec(
            "verify_session_active",
            "SELECT count() AS count FROM session WHERE token_hash = $session_token_hash AND expires_at > $now GROUP ALL",
            json!({
                "session_token_hash": crate::utils::crypto::hash_bearer(token),
                "now": Utc::now().timestamp()
            }),
        )
        .await?;

    let active = rows
        .first()
        .and_then(|row| row.get("count"))
        .and_then(|count| count.as_u64())
        .unwrap_or(0)
        > 0;

    if active {
        Ok(())
    } else {
        Err(AuthError::InvalidToken)
    }
}

/// 完整鉴权：验签 + 验有效期 + 验会话未被吊销。
pub async fn decode_and_verify_token(db: &Database, token: &str) -> Result<Claims> {
    let claims = decode_token_claims(token)?;
    verify_session_active(db, token).await?;
    Ok(claims)
}

/// 签发 MFA 两步登录用的短期临时令牌。
pub fn create_mfa_challenge_token(user_id: &str, email: &str, jwt_secret: &str) -> Result<String> {
    let now = Utc::now().timestamp();
    let claims = MfaChallengeClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        exp: now + MFA_CHALLENGE_TTL_SECONDS,
        iat: now,
        purpose: MFA_CHALLENGE_PURPOSE.to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AuthError::TokenError(e.to_string()))
}

/// 解析 MFA 临时令牌。
pub fn decode_mfa_challenge_token(token: &str, jwt_secret: &str) -> Result<MfaChallenge> {
    let token_data = decode::<MfaChallengeClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| AuthError::InvalidToken)?;

    if token_data.claims.purpose != MFA_CHALLENGE_PURPOSE {
        return Err(AuthError::InvalidToken);
    }

    Ok(MfaChallenge {
        user_id: token_data.claims.sub,
        email: token_data.claims.email,
    })
}

fn db_from_parts(parts: &Parts) -> Result<Arc<Database>> {
    parts
        .extensions
        .get::<Arc<Database>>()
        .cloned()
        .ok_or_else(|| AuthError::ServerError("Database extension is not configured".to_string()))
}

fn cache_from_parts(parts: &Parts) -> Option<Arc<AuthCache>> {
    parts.extensions.get::<Arc<AuthCache>>().cloned()
}

fn bearer_token(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(strip_bearer_scheme)
        .map(|token| token.trim().to_string())
}

/// 剥掉 `Bearer ` 前缀。**大小写不敏感**：RFC 7235 规定认证方案名不区分大小写，
/// 而 `Claims` 提取器走的 `TypedHeader` 本来就是不敏感的。这里如果只认
/// `"Bearer "`，同一个 `authorization: bearer xxx` 会在走 `AuthedUser` 的路由上
/// 401、在走 `Claims` 的路由上通过——同一个客户端有一半接口能用。
pub fn strip_bearer_scheme(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("Bearer").then_some(token)
}

/// 账号状态检查：被停用 / 删除的账号，已签发的令牌也应立即失效。
///
/// 判定本身在 [`User::ensure_usable`] —— 全库唯一一处。这里以前是它的逐字副本，
/// `services::auth` 里还有第三份；三份各自演进的结果是 OIDC 那侧一份都没有。
fn ensure_account_usable(user: &User) -> Result<()> {
    user.ensure_usable()
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        let db = db_from_parts(parts)?;
        decode_and_verify_token(&db, bearer.token()).await
    }
}

/// 已认证用户提取器。
///
/// 取代原来"由中间件往 extension 里塞 `User`"的写法 —— 那个中间件从未被挂载，
/// 导致所有依赖它的路由在运行时直接 500。
/// 已认证的调用方。
///
/// # 为什么还叫 `AuthedUser`
///
/// 身份根已经是 `actor_identity`，但这个类型名暂时不动 —— 69 处消费点里
/// 绝大多数只调 `.id()`，改名会制造一次纯噪声的大 diff，而 GA-03 §3 明确
/// 「Canonical Semantic Label 不规定代码标识符」。Stage 4 拆掉 `user` 表时
/// 一并改名，那时改动才有实际内容。
pub struct AuthedUser(pub User);

impl AuthedUser {
    pub fn user(&self) -> &User {
        &self.0
    }

    /// 返回不带表名前缀的用户 ID（RBAC 查询统一使用这种形式）。
    pub fn id(&self) -> Result<String> {
        let rid = self.0.id.as_ref().ok_or(AuthError::UserNotFound)?;
        Ok(crate::utils::record_id::record_id_key_to_string(rid))
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthedUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
        let token = bearer_token(parts).ok_or(AuthError::InvalidToken)?;
        let cache = cache_from_parts(parts);

        // 命中缓存就跳过两次数据库往返。缓存项只在本实例的登出 / 改密 /
        // 停用时被主动清除，跨副本的吊销最多滞后一个 TTL。
        if let Some(cache) = &cache {
            if let Some(user) = cache.get(&token).await {
                ensure_account_usable(&user)?;
                return Ok(AuthedUser(user));
            }
        }

        let claims = Claims::from_request_parts(parts, state).await?;

        // Agent 令牌背后没有 `user` 行，也**不应该**有。
        //
        // 明确挡在这里，而不是让它掉进 `load_user_from_claims` 去 —— 那里会
        // 以「用户不存在」的形式失败，语义完全是错的，而且一旦将来某个
        // 查询路径碰巧能解析到一行，Agent 就悄悄拿到了人类端点的访问权。
        if matches!(claims.subject_type, Some(SubjectType::Agent)) {
            return Err(AuthError::Forbidden(
                "This endpoint is for human accounts; AI actor sessions cannot access it".into(),
            ));
        }

        let db = db_from_parts(parts)?;
        let user = load_user_from_claims(&db, &claims).await?;

        ensure_account_usable(&user)?;

        if let Some(cache) = &cache {
            let user_id = crate::utils::record_id::record_id_key_to_string(
                user.id.as_ref().ok_or(AuthError::UserNotFound)?,
            );
            cache.insert(&token, &user_id, &user).await;
        }

        Ok(AuthedUser(user))
    }
}

/// 已认证的 **AIActor**。
///
/// 元组字段是 `pub`，消费方直接取 `.0`。这里不放访问器 —— 加了就是 dead code，
/// 而本仓库靠 `dead_code` 警告顶住「先写着以后可能用」。
///
/// 与 [`AuthedUser`] 是两个提取器而不是一个枚举：人类端点写 `AuthedUser`、
/// Agent 端点写 `AuthedActor`，「这个端点给谁用」在函数签名上就看得见，
/// 不需要在函数体里再判一次主体类型（那种判断迟早会有人忘记写）。
pub struct AuthedActor(pub ActorIdentity);

#[async_trait]
impl<S> FromRequestParts<S> for AuthedActor
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
        let claims = Claims::from_request_parts(parts, state).await?;

        // 只认 Agent 令牌。人类令牌走到这里是调用错了端点，不是权限不足。
        if !matches!(claims.subject_type, Some(SubjectType::Agent)) {
            return Err(AuthError::Forbidden(
                "This endpoint is for AI actor sessions".into(),
            ));
        }

        let db = db_from_parts(parts)?;
        let address = format!("actor_identity:{}", claims.sub);
        let actor = db
            .find_record_by_field::<ActorIdentity>("actor_identity", "id", &address)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        // 会话还在不等于身份还能用：停用 / 退役之后在途令牌必须立刻失效。
        if !actor.can_authenticate() {
            return Err(AuthError::AccountSuspended);
        }

        Ok(AuthedActor(actor))
    }
}

/// 从 claims 解析出用户记录，兼容 `sub` 为 `subject:xxx` 的令牌。
pub async fn load_user_from_claims(db: &Database, claims: &Claims) -> Result<User> {
    if claims.sub.starts_with("subject:") {
        let users: Vec<User> = db
            .query_take0_vec(
                "load_user_by_subject_id",
                // 同样必须两参：单参会在 UUID 的第一个连字符处截断。
                "SELECT * FROM user WHERE subject_id = type::record('subject', $subject_key) LIMIT 1",
                json!({
                    "subject_key": crate::utils::record_id::normalize_record_id_key(
                        claims.sub.strip_prefix("subject:").unwrap_or(&claims.sub),
                    ),
                }),
            )
            .await?;
        users.into_iter().next().ok_or(AuthError::UserNotFound)
    } else {
        db.find_record_by_field::<User>("user", "id", &claims.sub)
            .await?
            .ok_or(AuthError::UserNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        create_mfa_challenge_token, decode_mfa_challenge_token, strip_bearer_scheme, Claims,
        MFA_CHALLENGE_PURPOSE,
    };

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        assert_eq!(strip_bearer_scheme("Bearer abc"), Some("abc"));
        assert_eq!(strip_bearer_scheme("bearer abc"), Some("abc"));
        assert_eq!(strip_bearer_scheme("BEARER abc"), Some("abc"));
        assert_eq!(strip_bearer_scheme("Basic abc"), None);
        assert_eq!(strip_bearer_scheme("abc"), None);
    }
    use crate::models::subject::SubjectType;

    #[test]
    fn claims_deserialize_old_tokens_without_subject_type() {
        let old_claims = serde_json::json!({
            "sub": "user:legacy",
            "exp": 1,
            "iat": 1,
            "session_id": "session:legacy"
        });

        let claims: Claims =
            serde_json::from_value(old_claims).expect("old claims should deserialize");
        assert_eq!(claims.sub, "user:legacy");
        assert_eq!(claims.subject_type, None);
    }

    #[test]
    fn claims_deserialize_new_tokens_with_subject_type() {
        let new_claims = serde_json::json!({
            "sub": "user:new",
            "exp": 1,
            "iat": 1,
            "session_id": "session:new",
            "subject_type": "human"
        });

        let claims: Claims =
            serde_json::from_value(new_claims).expect("new claims should deserialize");
        assert_eq!(claims.subject_type, Some(SubjectType::Human));
    }

    #[test]
    fn mfa_challenge_token_round_trips_user_and_email() {
        let token =
            create_mfa_challenge_token("user-1", "a@example.com", "test-secret").expect("token");
        let challenge = decode_mfa_challenge_token(&token, "test-secret").expect("challenge");
        assert_eq!(challenge.user_id, "user-1");
        assert_eq!(challenge.email, "a@example.com");
    }

    #[test]
    fn mfa_challenge_token_rejects_wrong_secret() {
        let token =
            create_mfa_challenge_token("user-1", "a@example.com", "secret-a").expect("token");
        assert!(decode_mfa_challenge_token(&token, "secret-b").is_err());
    }

    #[test]
    fn access_token_is_not_accepted_as_mfa_challenge() {
        // 普通访问令牌没有 purpose 字段，必须被 MFA 端点拒绝。
        let claims = serde_json::json!({ "sub": "user-1", "exp": 9_999_999_999i64, "iat": 1 });
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
        )
        .expect("token");

        assert!(decode_mfa_challenge_token(&token, "test-secret").is_err());
        assert_eq!(MFA_CHALLENGE_PURPOSE, "mfa_challenge");
    }
}
