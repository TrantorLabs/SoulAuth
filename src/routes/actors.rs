//! AIActor：注册、密钥管理、认证。
//!
//! 端点分成两组，权限模型完全不同：
//!
//! * **管理组**（`POST /`、`GET /`、密钥增删）要求 `soulauth:actors.write` /
//!   `.read` —— 注册一个非人主体等于凭空造出一个可认证的身份，是特权操作；
//! * **认证组**（`/challenge`、`/authenticate`）**公开**，与人类的
//!   `/api/auth/login` 同级 —— Agent 用自己的私钥证明身份，不需要先有权限。
//!
//! `/me` 是第三种：只有 Agent 自己的会话令牌能进（`AuthedActor` 提取器）。

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, Extension, Path},
    http::HeaderMap,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};

use crate::models::user_activity::{ActivityCategory, ActivityStatus};
use crate::{
    config::Config,
    error::AuthError,
    models::{
        actor_identity::ActorIdentity,
        ai_actor::AiActorCredential,
        permission::names::{ACTORS_READ, ACTORS_WRITE},
    },
    require_permission,
    services::{
        ai_actor::{AiActorService, IssuedChallenge},
        audit_logger::{actions, AuditEvent, AuditLogger},
        database::Database,
    },
    utils::{
        jwt::{AuthedActor, AuthedUser},
        record_id::record_id_key_to_string,
    },
};

pub fn router() -> Router {
    Router::new()
        // 认证（公开）
        .route("/challenge", post(challenge))
        .route("/authenticate", post(authenticate))
        // 自省（Agent 自己的会话）
        .route("/me", get(me))
        // 管理（需权限）
        .route("/", post(register).get(list_actors))
        .route("/:actor_id", get(get_actor))
        .route(
            "/:actor_id/credentials",
            get(list_credentials).post(add_credential),
        )
        .route(
            "/:actor_id/credentials/:credential_id",
            delete(revoke_credential),
        )
}

// ───────────────────────── 线上形状 ─────────────────────────

#[derive(Serialize)]
struct ActorResponse {
    /// 带表名前缀的完整 record id —— 认证时原样回传。
    id: String,
    /// 稳定主体标识。它与 `id` 是**两个命名空间**（GA-04 §5）。
    subject_key: String,
    actor_kind: String,
    identity_source: String,
    status: String,
    created_at: i64,
}

impl From<ActorIdentity> for ActorResponse {
    fn from(a: ActorIdentity) -> Self {
        let id =
            a.id.as_ref()
                .map(|t| format!("actor_identity:{}", record_id_key_to_string(t)))
                .unwrap_or_default();
        Self {
            id,
            subject_key: a.subject_key,
            actor_kind: a.actor_kind,
            identity_source: a.identity_source,
            status: a.status,
            created_at: a.created_at,
        }
    }
}

/// 凭证的对外形状。
///
/// `public_key` 照实返回 —— 它是公钥，不是秘密。能读到它的人也读不出私钥，
/// 而运维需要它来核对"库里这枚是不是我手上那枚"。
#[derive(Serialize)]
struct CredentialResponse {
    id: String,
    public_key: String,
    algorithm: String,
    label: String,
    status: String,
    created_at: i64,
    revoked_at: Option<i64>,
    last_used_at: Option<i64>,
}

impl From<AiActorCredential> for CredentialResponse {
    fn from(c: AiActorCredential) -> Self {
        Self {
            id: c
                .id
                .as_ref()
                .map(|t| format!("ai_actor_credential:{}", record_id_key_to_string(t)))
                .unwrap_or_default(),
            public_key: c.public_key,
            algorithm: c.algorithm,
            label: c.label,
            status: c.status,
            created_at: c.created_at,
            revoked_at: c.revoked_at,
            last_used_at: c.last_used_at,
        }
    }
}

#[derive(Deserialize)]
struct RegisterRequest {
    /// base64url-no-pad 的 32 字节 Ed25519 公钥。
    public_key: String,
    /// 运维标签。不参与认证判定。
    #[serde(default)]
    label: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    actor: ActorResponse,
    credential: CredentialResponse,
}

#[derive(Deserialize)]
struct ChallengeRequest {
    actor_id: String,
}

#[derive(Deserialize)]
struct AuthenticateRequest {
    actor_id: String,
    nonce: String,
    algorithm: String,
    /// base64url-no-pad 的 64 字节 Ed25519 签名。
    signature: String,
}

#[derive(Serialize)]
struct AuthenticateResponse {
    token: String,
    token_type: &'static str,
    actor_id: String,
    expires_at: i64,
    /// 这次认证用的是哪枚密钥。轮换期间用来确认 Agent 确实换到新钥了。
    credential_label: String,
}

// ───────────────────────── 管理 ─────────────────────────

async fn register(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(actors): Extension<Arc<AiActorService>>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, ACTORS_WRITE);

    let label = normalize_label(&request.label);
    let (actor, credential) = actors.register(&request.public_key, &label).await?;

    Ok(Json(RegisterResponse {
        actor: actor.into(),
        credential: credential.into(),
    }))
}

async fn list_actors(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(actors): Extension<Arc<AiActorService>>,
) -> Result<Json<Vec<ActorResponse>>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, ACTORS_READ);
    Ok(Json(
        actors
            .list_actors()
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

async fn get_actor(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(actors): Extension<Arc<AiActorService>>,
    Path(actor_id): Path<String>,
) -> Result<Json<ActorResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, ACTORS_READ);

    let key = strip_actor_prefix(&actor_id);
    actors
        .find_actor(&key)
        .await?
        .map(|a| Json(a.into()))
        .ok_or_else(|| AuthError::NotFound("Actor not found".into()))
}

async fn list_credentials(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(actors): Extension<Arc<AiActorService>>,
    Path(actor_id): Path<String>,
) -> Result<Json<Vec<CredentialResponse>>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, ACTORS_READ);

    let key = strip_actor_prefix(&actor_id);
    Ok(Json(
        actors
            .list_credentials(&key)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

async fn add_credential(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(actors): Extension<Arc<AiActorService>>,
    Path(actor_id): Path<String>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<CredentialResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, ACTORS_WRITE);

    let key = strip_actor_prefix(&actor_id);
    let label = normalize_label(&request.label);
    Ok(Json(
        actors
            .add_credential(&key, &request.public_key, &label)
            .await?
            .into(),
    ))
}

async fn revoke_credential(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(actors): Extension<Arc<AiActorService>>,
    Path((actor_id, credential_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, ACTORS_WRITE);

    let actor_key = strip_actor_prefix(&actor_id);
    let credential_key = credential_id
        .strip_prefix("ai_actor_credential:")
        .unwrap_or(&credential_id)
        .to_string();

    actors
        .revoke_credential(&actor_key, &credential_key)
        .await?;
    Ok(Json(serde_json::json!({ "revoked": true })))
}

// ───────────────────────── 认证 ─────────────────────────

/// 第一步：领一枚一次性挑战。
///
/// 公开端点。它不区分「actor 不存在」与「actor 已停用」—— 两者都回
/// `invalid_credentials`，否则它就成了枚举 actor 的信道。
async fn challenge(
    Extension(actors): Extension<Arc<AiActorService>>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<IssuedChallenge>, AuthError> {
    let key = strip_actor_prefix(&request.actor_id);
    Ok(Json(actors.issue_challenge(&key).await?))
}

/// 第二步：交签名换会话。
async fn authenticate(
    Extension(actors): Extension<Arc<AiActorService>>,
    Extension(audit): Extension<Arc<AuditLogger>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<AuthenticateRequest>,
) -> Result<Json<AuthenticateResponse>, AuthError> {
    let key = strip_actor_prefix(&request.actor_id);
    // 复用人类登录链路那套上下文提取：IP 是否信任代理头、User-Agent 的
    // 截断与控制字符净化，都不该在这里再写一遍。
    let ctx = crate::routes::auth::request_context(&addr, &headers, &config);
    let (ip, ua) = (ctx.ip_address.clone(), ctx.user_agent.clone());

    match actors
        .authenticate(
            &key,
            &request.nonce,
            &request.algorithm,
            &request.signature,
            &ua,
            &ip,
        )
        .await
    {
        Ok(session) => {
            // 归因到**身份根**。审计里"谁做的"从第一天起就是那个 Agent，
            // 而不是某个为了让它能登录而伪造出来的人类账户。
            audit.record(
                AuditEvent::new(
                    actions::LOGIN_SUCCESS,
                    ActivityCategory::Authentication,
                    ActivityStatus::Success,
                    ip.clone(),
                    ua.clone(),
                )
                .with_details(serde_json::json!({
                    "subject_type": "agent",
                    "actor_id": session.actor_id,
                    "credential_label": session.credential_label,
                })),
            );

            Ok(Json(AuthenticateResponse {
                token: session.token,
                token_type: "Bearer",
                actor_id: session.actor_id,
                expires_at: session.expires_at,
                credential_label: session.credential_label,
            }))
        }
        Err(e) => {
            audit.record(
                AuditEvent::new(
                    actions::LOGIN_FAILED,
                    ActivityCategory::Authentication,
                    ActivityStatus::Failed,
                    ip,
                    ua,
                )
                .with_details(serde_json::json!({
                    "subject_type": "agent",
                    "actor_id": request.actor_id,
                    "reason": e.code(),
                })),
            );
            Err(e)
        }
    }
}

/// Agent 自省。人类令牌到这里会被 `AuthedActor` 明确拒绝。
async fn me(actor: AuthedActor) -> Result<Json<ActorResponse>, AuthError> {
    Ok(Json(actor.0.into()))
}

// ───────────────────────── 小工具 ─────────────────────────

/// 接受 `actor_identity:xxx` 与裸 `xxx` 两种写法。
///
/// 对外一律返回带前缀的完整形式，但要求调用方原样回传太脆 —— URL 里带冒号
/// 会被各种客户端库转义成 `%3A`，而两种写法在语义上没有区别。
fn strip_actor_prefix(value: &str) -> String {
    value
        .strip_prefix("actor_identity:")
        .unwrap_or(value)
        .to_string()
}

/// 空标签补一个占位值。
///
/// schema 上 `label` 是 `TYPE string`（非 option），空串会让"这枚是哪把钥匙"
/// 在运维界面上完全无法分辨。
fn normalize_label(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed.chars().take(64).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_prefix_is_optional_on_input() {
        assert_eq!(strip_actor_prefix("actor_identity:abc"), "abc");
        assert_eq!(strip_actor_prefix("abc"), "abc");
    }

    #[test]
    fn empty_label_gets_a_placeholder_and_long_labels_are_capped() {
        assert_eq!(normalize_label("   "), "unnamed");
        assert_eq!(normalize_label(" ci-runner "), "ci-runner");
        assert_eq!(normalize_label(&"x".repeat(200)).len(), 64);
    }
}
