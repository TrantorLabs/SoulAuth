use std::{future::Future, net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, Path, Query, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{header, HeaderMap, HeaderValue},
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info, warn};

use crate::{
    config::Config,
    error::{AuthError, Result},
    models::user_activity::{ActivityCategory, ActivityStatus},
    models::{
        account_lockout::LockoutCheckResult,
        authentication::{AuthenticationResult, CredentialKind},
        mfa::{
            EnableTotpRequest, MfaMethod, MfaStatusResponse, TotpSetupResponse,
            UseBackupCodeRequest, VerifyTotpRequest,
        },
        password_reset::{RequestPasswordResetRequest, ResetPasswordRequest},
        session::SessionInfo,
        user::{
            AuthResponse, CreateUserRequest, InitializePasswordRequest, LoginRequest, UserResponse,
        },
    },
    routes::oidc::{
        build_cookie, build_expired_cookie, cookie_value, create_browser_session_token,
        create_oauth_state_token, decode_oauth_state_token, decode_oidc_return_token,
        IssuedOAuthState, OAUTH_STATE_COOKIE, OAUTH_STATE_COOKIE_TTL_SECONDS, OIDC_RETURN_COOKIE,
        SESSION_TTL_SECONDS, SOULAUTH_SESSION_COOKIE,
    },
    services::{
        audit_logger::{actions, AuditEvent, AuditLogger},
        auth::{AuthService, IssuedSession, LoginOutcome, RequestContext},
        auth_cache::AuthCache,
        credential::CredentialService,
        database::Database,
        oidc::OidcService,
        rbac::RBACService,
    },
    utils::{
        jwt::{decode_mfa_challenge_token, AuthedUser},
        rate_limit_middleware::client_ip,
    },
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct OAuthCallback {
    code: String,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthLoginQuery {
    /// 由 `/api/oidc/authorize` 透传过来的已签名 state。
    state: Option<String>,
}

/// 登录响应：正常放行，或要求补一步 MFA。
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    Authenticated(AuthResponse),
    MfaRequired {
        mfa_required: bool,
        temp_token: String,
        method: MfaMethod,
    },
}

#[derive(Debug, Deserialize)]
pub struct MfaLoginVerifyRequest {
    pub temp_token: String,
    #[serde(default)]
    pub totp_code: Option<String>,
    #[serde(default)]
    pub backup_code: Option<String>,
    /// 来自管理后台登录时置 true，验证通过后会重新校验后台准入权限。
    #[serde(default)]
    pub admin: bool,
}

#[derive(Debug, Deserialize)]
pub struct DisableMfaRequest {
    pub totp_code: String,
}

/// 把一次认证的事实摊进审计详情。
///
/// 记「用什么证明的」而不只是「登录成功了」：同一个主体用口令登录、用备用恢复码
/// 过 MFA、还是走外部 IdP，在安全上是三件不同的事。归因用身份根地址而不是 user
/// 行 —— 账户实现可以变，身份根不变。
fn authentication_details(auth: &AuthenticationResult) -> serde_json::Value {
    let mut details = serde_json::Map::new();
    details.insert(
        "actor_identity_id".to_string(),
        json!(auth.actor_identity_id),
    );
    details.insert("actor_kind".to_string(), json!(auth.actor_kind.as_str()));
    details.insert(
        "credential_kind".to_string(),
        json!(auth.credential_kind.as_str()),
    );
    // 没有标识时**不写这个键**，而不是写一个 null：口令凭证没有标识可言，
    // 而数据库未必会把 null 存下来 —— 读回来少一个键，摘要就对不上了。
    if let Some(label) = &auth.credential_label {
        details.insert("credential_label".to_string(), json!(label));
    }
    serde_json::Value::Object(details)
}

/// 把两个对象合成一个。用于已经带了自己详情（`provider`、`mfa`）的那几处。
fn merge_details(mut base: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}

pub(crate) fn request_context(
    addr: &SocketAddr,
    headers: &HeaderMap,
    config: &Config,
) -> RequestContext {
    let ip = client_ip(addr, headers, config.trust_proxy_headers);
    // 截断之外还要滤掉控制字符：User-Agent 会进会话记录、审计日志和 tracing
    // 输出。HTTP 头值本身不允许原始控制字符（协议层已挡住 ESC 这类），
    // 但这里不依赖上游的严格程度 —— 净化的成本是一次 filter。
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .chars()
                .filter(|ch| !ch.is_control())
                .take(256)
                .collect::<String>()
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Unknown".to_string());

    RequestContext::new(ip, user_agent)
}

/// 错误响应体。
///
/// 执行锁定检查；数据库鉴权态过期时先重连再试一次。
///
/// 与旧实现的关键区别：重试后仍失败**不再放行**。登录本来就要读写数据库，
/// 此时放行既救不了可用性，又等于在数据库抖动窗口内关闭了暴力破解防护。
async fn run_lockout_check_with_reauth<C, CFut, R, RFut>(
    scope: &str,
    check: C,
    reauth: R,
) -> std::result::Result<LockoutCheckResult, AuthError>
where
    C: Fn() -> CFut,
    CFut: Future<Output = Result<LockoutCheckResult>>,
    R: Fn() -> RFut,
    RFut: Future<Output = Result<()>>,
{
    if let Ok(result) = check().await {
        return Ok(result);
    }

    match reauth().await {
        Ok(_) => match check().await {
            Ok(result) => Ok(result),
            Err(retry_err) => {
                error!(
                    "{} lockout check failed after reauth: {:?}",
                    scope, retry_err
                );
                Err(AuthError::ServiceUnavailable(
                    "Please retry in a moment".to_string(),
                ))
            }
        },
        Err(reauth_err) => {
            error!(
                "{} lockout check failed while reauthing: {:?}",
                scope, reauth_err
            );
            Err(AuthError::ServiceUnavailable(
                "Please retry in a moment".to_string(),
            ))
        }
    }
}

/// 把登录失败归类成可聚合的原因，绝不带出凭据内容。
fn failure_reason(error: &AuthError) -> &'static str {
    match error {
        AuthError::InvalidCredentials | AuthError::UserNotFound => "invalid_credentials",
        AuthError::EmailNotVerified => "email_not_verified",
        AuthError::AccountSuspended => "account_suspended",
        AuthError::AccountInactive => "account_inactive",
        AuthError::AccountDeleted => "account_deleted",
        _ => "internal_error",
    }
}

/// 账号/IP 被锁定时的 429。
///
/// `locked_until_seconds` 由 `AuthError::details()` 统一挂上 —— 契约里写着
/// 「仅 `account_locked` 携带」，这里只负责把值填进去。
fn locked_response(result: &LockoutCheckResult) -> AuthError {
    AuthError::AccountLocked {
        message: result.message.clone(),
        locked_until_seconds: result.remaining_lockout_seconds,
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/admin/login", post(admin_login))
        .route("/verify-email/:token", get(verify_email))
        .route("/resend-verification", post(resend_verification))
        .route("/me", get(get_current_user))
        .route("/initialize-password", post(initialize_password))
        .route("/request-password-reset", post(request_password_reset))
        .route("/reset-password", post(reset_password))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/sessions", get(get_sessions))
        // 多因素认证
        .route("/mfa/status", get(mfa_status))
        .route("/mfa/setup", post(mfa_setup))
        .route("/mfa/enable", post(mfa_enable))
        .route("/mfa/disable", post(mfa_disable))
        .route("/mfa/login-verify", post(mfa_login_verify))
        // OAuth
        .route("/login/google", get(google_login))
        .route("/callback/google", get(google_callback))
        .route("/login/github", get(github_login))
        .route("/callback/github", get(github_callback))
}

/// 管理后台准入判断：拥有 admin 角色，或任一后台只读权限。
async fn is_admin_console_user(
    db: Arc<Database>,
    user_id: &str,
) -> std::result::Result<bool, AuthError> {
    let rbac_service = RBACService::new(db);

    if rbac_service.check_user_role(user_id, "admin").await? {
        return Ok(true);
    }

    // 列表定义在 models::permission::names，不在这里就地铺开：
    // 「哪些权限算后台准入」应当只有一个答案。
    for permission in crate::models::permission::names::ADMIN_CONSOLE_READ {
        if rbac_service
            .check_user_permission(user_id, permission)
            .await
            .unwrap_or(false)
        {
            return Ok(true);
        }
    }

    Ok(false)
}

// ===== 注册 / 登录 =====

async fn register(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> std::result::Result<Json<AuthResponse>, AuthError> {
    let ctx = request_context(&addr, &headers, &config);

    // 这里原本重写了一遍状态码与文案。码取的是 `e.code()`，状态码却是手抄的
    // —— 两份映射并排放着，改一处漏一处只是时间问题。现在直接把 `AuthError`
    // 交出去，状态码、码、文案全部由 `error.rs` 那一份决定。
    let (result, _session_key) = auth_service.register(req, &ctx).await.inspect_err(|e| {
        error!("Registration failed: {:?}", e);
    })?;

    Ok(Json(result))
}

async fn login(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(audit): Extension<Arc<AuditLogger>>,
    Extension(config): Extension<Config>,
    Extension(db): Extension<Arc<Database>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> std::result::Result<axum::response::Response, AuthError> {
    let ctx = request_context(&addr, &headers, &config);
    let (outcome, session_key) =
        perform_login(&auth_service, &app_state, &audit, &db, &req, &ctx).await?;
    login_response(&config, outcome, session_key.as_deref())
}

async fn admin_login(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(audit): Extension<Arc<AuditLogger>>,
    Extension(config): Extension<Config>,
    Extension(db): Extension<Arc<Database>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> std::result::Result<axum::response::Response, AuthError> {
    let ctx = request_context(&addr, &headers, &config);
    let (outcome, session_key) =
        perform_login(&auth_service, &app_state, &audit, &db, &req, &ctx).await?;

    if let LoginResponse::Authenticated(response) = &outcome {
        ensure_admin_console_access(db, &response.user.id).await?;
    }

    login_response(&config, outcome, session_key.as_deref())
}

/// 把登录结果转成 HTTP 响应。
///
/// 登录成功时**同时下发 `soulauth_session` cookie** —— 这是让邮箱密码账号也能
/// 走通 OIDC SSO 的关键：以前只有 Google 回调那条路径会设置它，
/// 密码用户在 `/api/oidc/authorize` 永远被判为未登录。
fn login_response(
    config: &Config,
    outcome: LoginResponse,
    session_key: Option<&str>,
) -> std::result::Result<axum::response::Response, AuthError> {
    let session_cookie = match (&outcome, session_key) {
        (LoginResponse::Authenticated(auth), Some(session_key)) => Some(
            create_browser_session_token(&auth.user.id, session_key, &config.jwt_secret).map_err(
                |e| {
                    error!("Failed to create browser session token: {:?}", e);
                    AuthError::ServerError("Failed to establish session".to_string())
                },
            )?,
        ),
        // 还没过 MFA（或没有会话记录）就不下发会话 cookie。
        _ => None,
    };

    let mut response = Json(outcome).into_response();

    if let Some(token) = session_cookie {
        let cookie = build_cookie(
            SOULAUTH_SESSION_COOKIE,
            &token,
            SESSION_TTL_SECONDS,
            config.cookies_secure(),
        );
        let value = HeaderValue::from_str(&cookie).map_err(|e| {
            error!("Invalid session cookie: {e}");
            AuthError::ServerError("Failed to establish session".to_string())
        })?;
        response.headers_mut().append(header::SET_COOKIE, value);
    }

    Ok(response)
}

async fn ensure_admin_console_access(
    db: Arc<Database>,
    user_id: &str,
) -> std::result::Result<(), AuthError> {
    let allowed = is_admin_console_user(db, user_id).await.map_err(|e| {
        error!("Admin permission check failed after login: {:?}", e);
        AuthError::ServerError("Failed to verify admin permissions".to_string())
    })?;

    if !allowed {
        return Err(AuthError::Forbidden(
            "Current account does not have admin console access".to_string(),
        ));
    }

    Ok(())
}

/// 登录主流程：IP / 账号锁定检查 → 校验凭据 → 成功后清零失败计数。
async fn perform_login(
    auth_service: &Arc<AuthService>,
    app_state: &Arc<AppState>,
    audit: &Arc<AuditLogger>,
    db: &Arc<Database>,
    req: &LoginRequest,
    ctx: &RequestContext,
) -> std::result::Result<(LoginResponse, Option<String>), AuthError> {
    ensure_not_locked_out(app_state, &req.email, &ctx.ip_address).await?;

    let outcome = auth_service
        .login(req.email.clone(), req.password.clone(), ctx)
        .await
        .map_err(|e| {
            warn!("Login failed: {}", e);

            if matches!(e, AuthError::InvalidCredentials | AuthError::UserNotFound) {
                record_lockout_failure(app_state, &req.email, &ctx.ip_address);
            }

            audit.record(
                AuditEvent::new(
                    actions::LOGIN_FAILED,
                    ActivityCategory::Authentication,
                    ActivityStatus::Failed,
                    ctx.ip_address.clone(),
                    ctx.user_agent.clone(),
                )
                // 只记失败类别，不记邮箱以外的任何凭据信息。
                .with_details(json!({ "reason": failure_reason(&e) })),
            );

            // 「用户不存在」对外与「口令错」变成同一个错误，避免账号枚举。
            // 这是本函数唯一需要**改写**错误的地方；其余变体的状态码与文案
            // 一律由 `AuthError` 那一份映射决定，不在这里抄第二遍。
            match e {
                AuthError::UserNotFound => AuthError::InvalidCredentials,
                other => other,
            }
        })?;

    Ok(match outcome {
        LoginOutcome::Authenticated(issued) => {
            // 只有走完整个登录流程才清零失败计数。
            reset_lockout_counters(app_state, &req.email, &ctx.ip_address);
            let mut issued = *issued;
            // `From<User>` 拿不到角色表，is_admin 默认是 false。/api/auth/me 早就
            // 在这里查了一次 RBAC，登录这条路径当时漏了 —— 而前端拿登录响应决定
            // 要不要露出管理后台入口，是所有写法里最自然的那一个，那个字段就摆在
            // 返回体里。结果是管理员登录后永远看到普通用户视图。
            //
            // 这不是权限漏洞：真正的授权判定始终在服务端按权限做，客户端改这个
            // 字段改不出任何权限。它是一个「照文档做、结果是错的」的功能缺陷。
            issued.response.user.is_admin = fill_is_admin(db, &issued.response.user.id).await;
            audit.record(
                AuditEvent::new(
                    actions::LOGIN_SUCCESS,
                    ActivityCategory::Authentication,
                    ActivityStatus::Success,
                    ctx.ip_address.clone(),
                    ctx.user_agent.clone(),
                )
                .with_user(issued.response.user.id.clone())
                .with_details(authentication_details(&issued.authentication)),
            );
            (
                LoginResponse::Authenticated(issued.response),
                Some(issued.session_key),
            )
        }
        // 密码对了但 MFA 还没过 —— 计数保持不动，否则拿到正确密码的攻击者
        // 可以借"每次登录都重置计数"来无限次爆破 TOTP。
        LoginOutcome::MfaRequired { temp_token, method } => (
            LoginResponse::MfaRequired {
                mfa_required: true,
                temp_token,
                method,
            },
            None,
        ),
    })
}

/// 清零某个账号 / IP 的失败计数（异步执行，不阻塞响应）。
fn reset_lockout_counters(app_state: &Arc<AppState>, email: &str, ip: &str) {
    let lockout_service = app_state.lockout_service.clone();
    let email = email.to_string();
    let ip = ip.to_string();
    tokio::spawn(async move {
        if let Err(e) = lockout_service.reset_user_attempts(&email).await {
            error!("Failed to reset user attempts: {:?}", e);
        }
        if let Err(e) = lockout_service.reset_ip_attempts(&ip).await {
            error!("Failed to reset IP attempts: {:?}", e);
        }
    });
}

/// 记录一次失败尝试（异步执行）。
fn record_lockout_failure(app_state: &Arc<AppState>, email: &str, ip: &str) {
    let lockout_service = app_state.lockout_service.clone();
    let email = email.to_string();
    let ip = ip.to_string();
    tokio::spawn(async move {
        if let Err(e) = lockout_service.record_failed_user_attempt(&email).await {
            error!("Failed to record user lockout attempt: {:?}", e);
        }
        if let Err(e) = lockout_service.record_failed_ip_attempt(&ip).await {
            error!("Failed to record IP lockout attempt: {:?}", e);
        }
    });
}

/// 登录前的 IP + 账号双维度锁定检查。
async fn ensure_not_locked_out(
    app_state: &Arc<AppState>,
    email: &str,
    ip: &str,
) -> std::result::Result<(), AuthError> {
    let ip_lockout = run_lockout_check_with_reauth(
        "ip lockout",
        || app_state.lockout_service.check_ip_lockout(ip),
        || async { app_state.db.reauth().await },
    )
    .await?;
    if ip_lockout.is_locked {
        return Err(locked_response(&ip_lockout));
    }

    let user_lockout = run_lockout_check_with_reauth(
        "user lockout",
        || app_state.lockout_service.check_user_lockout(email),
        || async { app_state.db.reauth().await },
    )
    .await?;
    if user_lockout.is_locked {
        return Err(locked_response(&user_lockout));
    }

    Ok(())
}

async fn verify_email(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<AuthResponse>> {
    let ctx = request_context(&addr, &headers, &config);
    let issued = auth_service.verify_email(token, &ctx).await?;
    Ok(Json(issued.response))
}

/// 重新发送邮箱验证信。
///
/// 无条件返回 200：邮箱是否存在、是否已验证、账号是否可用都不通过状态码透露，
/// 与 `request_password_reset` 同一套防枚举语义。
async fn resend_verification(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Json(request): Json<RequestPasswordResetRequest>,
) -> Result<Json<serde_json::Value>> {
    auth_service
        .resend_verification_email(request.email)
        .await?;
    Ok(Json(json!({
        "message": "Verification email sent if the address is registered and still unverified"
    })))
}

async fn get_current_user(
    Extension(db): Extension<Arc<Database>>,
    user: AuthedUser,
) -> Result<Json<UserResponse>> {
    // `From<User>` 拿不到角色表，只能把 is_admin 填成 false。前端靠这个字段决定
    // 要不要露出管理后台入口，所以这里必须真查一次 RBAC，否则管理员看到的
    // 永远是普通用户视图。
    let user_id = crate::utils::record_id::normalize_user_id(
        &user
            .0
            .id
            .as_ref()
            .map(crate::utils::record_id::record_id_key_to_string)
            .unwrap_or_default(),
    );

    // `has_password` 只能问凭证：口令不在账户行上。
    //
    // 查不到身份根时报 false 而不是向上抛错 —— 这个端点是「看我自己的资料」，
    // 不该因为一个附带字段查不到就整个失败；而 false 的后果只是前端显示
    // 「设置口令」而不是「修改口令」。
    let has_password = match db.actor_ref_of_user(&user_id).await {
        Ok(actor) => CredentialService::new(db.clone())
            .has_password(&actor)
            .await
            .unwrap_or(false),
        Err(_) => false,
    };

    let mut response = UserResponse::of(user.0, has_password);
    response.is_admin = fill_is_admin(&db, &user_id).await;

    Ok(Json(response))
}

/// 查一次 RBAC，回答「这个账号是不是管理员」。
///
/// 登录响应与 `/api/auth/me` 都要用，走同一个函数而不是两处各写一遍 ——
/// 两处各写一遍正是它们曾经漂开的原因。
///
/// 查不到时返回 false：这个字段只用于决定前端要不要露出管理入口，
/// 判错的代价是少显示一个入口，而不是多授予一份权限。
async fn fill_is_admin(db: &Arc<Database>, user_id: &str) -> bool {
    let user_id = crate::utils::record_id::normalize_user_id(user_id);
    RBACService::new(db.clone())
        .check_user_role(&user_id, "admin")
        .await
        .unwrap_or(false)
}

// ===== 多因素认证 =====

async fn mfa_status(
    user: AuthedUser,
    Extension(auth_service): Extension<Arc<AuthService>>,
) -> Result<Json<MfaStatusResponse>> {
    let user_id = user.id()?;
    Ok(Json(auth_service.mfa().get_mfa_status(&user_id).await?))
}

async fn mfa_setup(
    user: AuthedUser,
    Extension(auth_service): Extension<Arc<AuthService>>,
) -> Result<Json<TotpSetupResponse>> {
    let user_id = user.id()?;
    Ok(Json(auth_service.mfa().setup_totp(&user_id).await?))
}

async fn mfa_enable(
    user: AuthedUser,
    Extension(auth_service): Extension<Arc<AuthService>>,
    Json(request): Json<EnableTotpRequest>,
) -> Result<Json<serde_json::Value>> {
    let user_id = user.id()?;
    let enabled = auth_service.mfa().enable_totp(&user_id, request).await?;

    if !enabled {
        return Err(AuthError::ValidationError("Invalid TOTP code".to_string()));
    }

    Ok(Json(json!({ "enabled": true })))
}

async fn mfa_disable(
    user: AuthedUser,
    Extension(auth_service): Extension<Arc<AuthService>>,
    Json(request): Json<DisableMfaRequest>,
) -> Result<Json<serde_json::Value>> {
    let user_id = user.id()?;

    // 关闭 MFA 属于降低账号安全等级的操作，必须先验证一次当前的 TOTP。
    let verification = auth_service
        .mfa()
        .verify_totp(
            &user_id,
            VerifyTotpRequest {
                totp_code: request.totp_code,
            },
        )
        .await?;

    if !verification.verified {
        return Err(AuthError::ValidationError("Invalid TOTP code".to_string()));
    }

    auth_service.mfa().disable_mfa(&user_id).await?;
    Ok(Json(json!({ "enabled": false })))
}

/// MFA 两步登录的第二步：用临时令牌 + TOTP（或备用码）换取正式访问令牌。
///
/// 这一步和第一步共用同一套账号 / IP 锁定计数器：验证码试错同样会累计失败次数，
/// 只有走到这里成功才清零。否则拿到正确密码的人可以反复重新登录来刷新计数，
/// 从而不受限制地爆破 6 位 TOTP。
async fn mfa_login_verify(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(audit): Extension<Arc<AuditLogger>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<MfaLoginVerifyRequest>,
) -> std::result::Result<axum::response::Response, AuthError> {
    let challenge = decode_mfa_challenge_token(&request.temp_token, &config.jwt_secret)
        .map_err(|_| AuthError::TokenError("Invalid or expired MFA token".to_string()))?;

    let ctx = request_context(&addr, &headers, &config);
    ensure_not_locked_out(&app_state, &challenge.email, &ctx.ip_address).await?;

    // 记下验的是哪一类第二因子。用掉一枚备用恢复码与验一次 TOTP 在安全上不是
    // 一回事 —— 前者一次性，而且通常意味着用户丢了验证器 —— 审计要分得开。
    let mut second_factor = CredentialKind::Totp;
    let verification = match (request.totp_code, request.backup_code) {
        (Some(totp_code), _) => {
            auth_service
                .mfa()
                .verify_totp(&challenge.user_id, VerifyTotpRequest { totp_code })
                .await
        }
        (None, Some(backup_code)) => {
            second_factor = CredentialKind::BackupCode;
            auth_service
                .mfa()
                .use_backup_code(&challenge.user_id, UseBackupCodeRequest { backup_code })
                .await
        }
        (None, None) => {
            return Err(AuthError::ValidationError(
                "Either totp_code or backup_code is required".to_string(),
            ))
        }
    }
    .map_err(|e| {
        error!("MFA verification failed: {:?}", e);
        AuthError::ServerError("MFA verification failed".to_string())
    })?;

    if !verification.verified {
        record_lockout_failure(&app_state, &challenge.email, &ctx.ip_address);
        audit.record(
            AuditEvent::new(
                actions::MFA_FAILED,
                ActivityCategory::Authentication,
                ActivityStatus::Failed,
                ctx.ip_address.clone(),
                ctx.user_agent.clone(),
            )
            .with_user(challenge.user_id.clone()),
        );
        warn!("MFA verification rejected for {}", challenge.email);
        return Err(AuthError::InvalidCredentials);
    }

    if request.admin {
        let allowed = is_admin_console_user(db, &challenge.user_id)
            .await
            .map_err(|e| {
                error!("Admin permission check failed after MFA: {:?}", e);
                AuthError::ServerError("Failed to verify admin permissions".to_string())
            })?;
        if !allowed {
            return Err(AuthError::Forbidden(
                "Current account does not have admin console access".to_string(),
            ));
        }
    }

    let issued = auth_service
        .complete_mfa_login(&challenge.user_id, &ctx, second_factor)
        .await
        .inspect_err(|e| {
            error!("Failed to complete MFA login: {:?}", e);
        })?;

    // 走完两步才清零。
    reset_lockout_counters(&app_state, &challenge.email, &ctx.ip_address);
    audit.record(
        AuditEvent::new(
            actions::LOGIN_SUCCESS,
            ActivityCategory::Authentication,
            ActivityStatus::Success,
            ctx.ip_address.clone(),
            ctx.user_agent.clone(),
        )
        .with_user(challenge.user_id.clone())
        .with_details(merge_details(
            json!({ "mfa": true }),
            authentication_details(&issued.authentication),
        )),
    );

    login_response(
        &config,
        LoginResponse::Authenticated(issued.response),
        Some(&issued.session_key),
    )
}

// ===== 密码 / 会话 =====

async fn initialize_password(
    user: AuthedUser,
    Extension(auth_service): Extension<Arc<AuthService>>,
    Json(request): Json<InitializePasswordRequest>,
) -> Result<Json<UserResponse>> {
    let user_id = user.id()?;
    let updated = auth_service
        .initialize_password(&user_id, &request.password)
        .await?;
    // 口令刚在上一行写进 credential，不必再查一次。
    Ok(Json(UserResponse::of(updated, true)))
}

async fn request_password_reset(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Json(request): Json<RequestPasswordResetRequest>,
) -> Result<Json<serde_json::Value>> {
    auth_service.request_password_reset(request.email).await?;
    Ok(Json(
        json!({ "message": "Password reset email sent if account exists" }),
    ))
}

async fn reset_password(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(audit): Extension<Arc<AuditLogger>>,
    Extension(oidc_service): Extension<Arc<OidcService>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ResetPasswordRequest>,
) -> Result<Json<serde_json::Value>> {
    let ctx = request_context(&addr, &headers, &config);
    let user_id = auth_service
        .reset_password(request.token, request.new_password)
        .await?;

    // 改密只清了本站的 session 行。已经发给各 RP 的 OIDC 访问 / 刷新令牌是独立的，
    // 不一起吊销的话，"账号被盗 → 重置密码"根本赶不走攻击者：他从 RP 那一侧的
    // 访问照旧有效，刷新令牌还能一直续期。和 `logout_all` 用同一套处理。
    // 撤销失败必须让这次请求失败。
    //
    // 以前只记日志：接口回「密码已重置」，而各 RP 手上的访问与刷新令牌仍然
    // 有效 —— 「账号被盗 → 重置密码」赶不走攻击者，而用户以为赶走了。
    oidc_service
        .revoke_all_tokens_for_user(&user_id)
        .await
        .map_err(|e| {
            error!("Failed to revoke OIDC tokens after password reset: {e}");
            AuthError::ServerError(
                "Password was reset but issued tokens could not be revoked; \
                 retry or revoke them from the admin surface"
                    .to_string(),
            )
        })?;

    audit.record(
        AuditEvent::new(
            actions::PASSWORD_RESET,
            ActivityCategory::Security,
            ActivityStatus::Success,
            ctx.ip_address,
            ctx.user_agent,
        )
        .with_user(user_id),
    );
    Ok(Json(json!({ "message": "Password reset successfully" })))
}

async fn logout(
    user: AuthedUser,
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(auth_cache): Extension<Arc<AuthCache>>,
    Extension(audit): Extension<Arc<AuditLogger>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse> {
    let secure_cookies = config.cookies_secure();
    let ctx = request_context(&addr, &headers, &config);
    if let Ok(user_id) = user.id() {
        audit.record(
            AuditEvent::new(
                actions::LOGOUT,
                ActivityCategory::Authentication,
                ActivityStatus::Success,
                ctx.ip_address.clone(),
                ctx.user_agent.clone(),
            )
            .with_user(user_id),
        );
    }
    auth_service.logout(bearer.token().to_string()).await?;
    // 立刻清缓存，本实例上的吊销就是即时的。
    auth_cache.invalidate_token(bearer.token()).await;

    // 同时清掉浏览器会话 cookie，避免 OIDC 侧继续认为用户已登录。
    let mut response = Json(json!({ "message": "Logged out successfully" })).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&build_expired_cookie(
            SOULAUTH_SESSION_COOKIE,
            secure_cookies,
        ))
        .map_err(|e| AuthError::ServerError(format!("Invalid session cookie: {e}")))?,
    );
    Ok(response)
}

async fn logout_all(
    user: AuthedUser,
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(auth_cache): Extension<Arc<AuthCache>>,
    Extension(oidc_service): Extension<Arc<OidcService>>,
    Extension(config): Extension<Config>,
) -> Result<impl IntoResponse> {
    let secure_cookies = config.cookies_secure();
    let user_id = user.id()?;
    auth_service.logout_all_sessions(&user_id).await?;
    auth_cache.invalidate_user(&user_id).await;

    // "登出所有会话"必须也把已经发出去的 OIDC 访问 / 刷新令牌一起吊销，
    // 否则各 RP 侧的会话还能继续用。
    oidc_service
        .revoke_all_tokens_for_user(&user_id)
        .await
        .map_err(|e| {
            error!("Failed to revoke OIDC tokens on logout-all: {e}");
            AuthError::ServerError(
                "Sessions were ended but issued tokens could not be revoked; \
                 retry logout-all"
                    .to_string(),
            )
        })?;

    let mut response =
        Json(json!({ "message": "All sessions logged out successfully" })).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&build_expired_cookie(
            SOULAUTH_SESSION_COOKIE,
            secure_cookies,
        ))
        .map_err(|e| AuthError::ServerError(format!("Invalid session cookie: {e}")))?,
    );
    Ok(response)
}

async fn get_sessions(
    user: AuthedUser,
    Extension(auth_service): Extension<Arc<AuthService>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<Vec<SessionInfo>>> {
    let user_id = user.id()?;
    let sessions = auth_service
        .get_user_sessions(&user_id, bearer.token())
        .await?;
    Ok(Json(sessions))
}

// ===== OAuth =====

/// 跳转到 Google 授权页。
///
/// `state` 一律由本服务签发：要么原样透传 `/api/oidc/authorize` 生成的那个，
/// 要么现签一个（不携带回跳目标）。回调时必须验签通过，以此防 CSRF。
async fn google_login(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Config>,
    Query(query): Query<OAuthLoginQuery>,
) -> Result<axum::response::Response> {
    let state = resolve_login_state(query.state, &config)?;
    let auth_url = auth_service.get_google_auth_url_with_state(&state.token)?;
    oauth_login_redirect(&config, &auth_url, &state.nonce)
}

async fn github_login(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Config>,
    Query(query): Query<OAuthLoginQuery>,
) -> Result<axum::response::Response> {
    let state = resolve_login_state(query.state, &config)?;
    let auth_url = auth_service.get_github_auth_url_with_state(&state.token)?;
    oauth_login_redirect(&config, &auth_url, &state.nonce)
}

/// 跳去 IdP 的同时，把 state 的 nonce 写进 cookie。
///
/// 回调时要求两边一致，`state` 才真正起到 CSRF 防护作用。cookie 是 `SameSite=Lax`，
/// 而 OAuth 回调是顶级 GET 跳转，浏览器会照常带上。
fn oauth_login_redirect(
    config: &Config,
    auth_url: &str,
    nonce: &str,
) -> Result<axum::response::Response> {
    let cookie = build_cookie(
        OAUTH_STATE_COOKIE,
        nonce,
        OAUTH_STATE_COOKIE_TTL_SECONDS,
        config.cookies_secure(),
    );

    let mut response = axum::response::Redirect::to(auth_url).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|e| AuthError::ServerError(format!("Invalid oauth state cookie: {e}")))?,
    );
    Ok(response)
}

fn resolve_login_state(incoming: Option<String>, config: &Config) -> Result<IssuedOAuthState> {
    match incoming {
        // 只有本服务签发的 state 才允许透传；透传时沿用它自己的 nonce，
        // 这样 cookie 和 state 仍然是配对的。
        Some(state) => match decode_oauth_state_token(&state, &config.jwt_secret) {
            Ok(decoded) => Ok(IssuedOAuthState {
                token: state,
                nonce: decoded.nonce,
            }),
            Err(_) => Err(AuthError::BadRequest("Invalid state parameter".to_string())),
        },
        None => create_oauth_state_token(None, &config.jwt_secret),
    }
}

async fn google_callback(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(audit): Extension<Arc<AuditLogger>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<OAuthCallback>,
    headers: HeaderMap,
) -> Result<axum::response::Response> {
    let ctx = request_context(&addr, &headers, &config);
    let state_return_target = verify_callback_state(params.state.as_deref(), &headers, &config)?;

    let issued = auth_service
        .handle_google_callback(params.code, &ctx)
        .await
        .map_err(|e| {
            error!("Google callback failed: {:?}", e);
            e
        })?;

    audit.record(
        AuditEvent::new(
            actions::OAUTH_LOGIN,
            ActivityCategory::Authentication,
            ActivityStatus::Success,
            ctx.ip_address.clone(),
            ctx.user_agent.clone(),
        )
        .with_user(issued.response.user.id.clone())
        .with_details(merge_details(
            json!({ "provider": "google" }),
            authentication_details(&issued.authentication),
        )),
    );

    build_oauth_redirect(&config, &headers, &issued, state_return_target)
}

async fn github_callback(
    Extension(auth_service): Extension<Arc<AuthService>>,
    Extension(audit): Extension<Arc<AuditLogger>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(params): Query<OAuthCallback>,
    headers: HeaderMap,
) -> Result<axum::response::Response> {
    let ctx = request_context(&addr, &headers, &config);
    let state_return_target = verify_callback_state(params.state.as_deref(), &headers, &config)?;

    let issued = auth_service
        .handle_github_callback(params.code, &ctx)
        .await
        .map_err(|e| {
            error!("GitHub callback failed: {:?}", e);
            e
        })?;

    audit.record(
        AuditEvent::new(
            actions::OAUTH_LOGIN,
            ActivityCategory::Authentication,
            ActivityStatus::Success,
            ctx.ip_address.clone(),
            ctx.user_agent.clone(),
        )
        .with_user(issued.response.user.id.clone())
        .with_details(merge_details(
            json!({ "provider": "github" }),
            authentication_details(&issued.authentication),
        )),
    );

    build_oauth_redirect(&config, &headers, &issued, state_return_target)
}

/// 校验回调里的 `state`，返回其中携带的 OIDC 回跳目标。
///
/// 三道判定缺一不可：
/// 1. `state` 必须存在；
/// 2. 必须验签通过且未过期；
/// 3. 其中的 nonce 必须与浏览器 cookie 里的一致。
///
/// 第 3 条是真正防 CSRF 的那条。只做 1、2 的话，攻击者自己访问一次
/// `/api/auth/login/google` 就能拿到一个合法 `state`，再配上自己账号的 `code`
/// 诱导受害者访问回调 —— 受害者的浏览器会被登进攻击者的账号，之后录入的一切
/// 都进了对方的账户。
fn verify_callback_state(
    state: Option<&str>,
    headers: &HeaderMap,
    config: &Config,
) -> Result<Option<String>> {
    let state = state.ok_or_else(|| {
        warn!("OAuth callback rejected: missing state parameter");
        AuthError::BadRequest("Missing state parameter".to_string())
    })?;

    let decoded = decode_oauth_state_token(state, &config.jwt_secret).map_err(|_| {
        warn!("OAuth callback rejected: invalid or expired state parameter");
        AuthError::BadRequest("Invalid or expired state parameter".to_string())
    })?;

    let cookie_nonce = cookie_value(headers, OAUTH_STATE_COOKIE).ok_or_else(|| {
        warn!("OAuth callback rejected: missing state cookie");
        AuthError::BadRequest("Invalid or expired state parameter".to_string())
    })?;

    // 定长比较，避免按字符早退。
    if !crate::utils::crypto::constant_time_eq(cookie_nonce.as_bytes(), decoded.nonce.as_bytes()) {
        warn!("OAuth callback rejected: state nonce does not match the browser cookie");
        return Err(AuthError::BadRequest(
            "Invalid or expired state parameter".to_string(),
        ));
    }

    Ok(decoded.return_target)
}

fn build_oauth_redirect(
    config: &Config,
    headers: &HeaderMap,
    issued: &IssuedSession,
    state_return_target: Option<String>,
) -> Result<axum::response::Response> {
    let frontend_base = config.app_url.trim_end_matches('/').to_string();

    let session_token = create_browser_session_token(
        &issued.response.user.id,
        &issued.session_key,
        &config.jwt_secret,
    )?;
    let session_cookie = build_cookie(
        SOULAUTH_SESSION_COOKIE,
        &session_token,
        SESSION_TTL_SECONDS,
        config.cookies_secure(),
    );

    let cookie_return_target = cookie_value(headers, OIDC_RETURN_COOKIE)
        .and_then(|token| decode_oidc_return_token(&token, &config.jwt_secret).ok());

    let (redirect_url, clear_return_cookie, redirect_kind) =
        match state_return_target.or(cookie_return_target) {
            Some(return_url) => (return_url, true, "oidc_return"),
            None => {
                let target = if issued.response.user.has_password {
                    format!("{frontend_base}/oauth/callback")
                } else {
                    format!("{frontend_base}/initialize-password")
                };
                (target, false, "frontend_callback")
            }
        };

    info!(redirect_kind, "OAuth callback completed, redirecting user");

    let mut response = axum::response::Redirect::to(&redirect_url).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&session_cookie)
            .map_err(|e| AuthError::ServerError(format!("Invalid session cookie: {e}")))?,
    );
    if clear_return_cookie {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&build_expired_cookie(
                OIDC_RETURN_COOKIE,
                config.cookies_secure(),
            ))
            .map_err(|e| AuthError::ServerError(format!("Invalid return cookie: {e}")))?,
        );
    }

    // state 已经用掉了，cookie 立刻作废：同一个 nonce 不该能配第二次回调。
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&build_expired_cookie(
            OAUTH_STATE_COOKIE,
            config.cookies_secure(),
        ))
        .map_err(|e| AuthError::ServerError(format!("Invalid oauth state cookie: {e}")))?,
    );

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::{verify_callback_state, LoginResponse, MfaLoginVerifyRequest};
    use crate::models::mfa::MfaMethod;
    use crate::routes::oidc::{create_oauth_state_token, OAUTH_STATE_COOKIE};
    use axum::http::{header, HeaderMap, HeaderValue};

    fn test_config(secret: &str) -> crate::config::Config {
        let mut config = crate::config::Config::test_default();
        config.jwt_secret = secret.to_string();
        config
    }

    fn headers_with_state_cookie(nonce: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{OAUTH_STATE_COOKIE}={nonce}")).unwrap(),
        );
        headers
    }

    #[test]
    fn callback_state_requires_a_matching_browser_cookie() {
        let secret = "0123456789abcdef0123456789abcdef";
        let config = test_config(secret);
        let state = create_oauth_state_token(None, secret).expect("state");

        // nonce 对得上：放行。
        assert!(verify_callback_state(
            Some(&state.token),
            &headers_with_state_cookie(&state.nonce),
            &config
        )
        .is_ok());

        // 没有 cookie：这正是攻击者能做到的全部 —— 他拿得到合法 state，
        // 但拿不到受害者浏览器里的 nonce。
        assert!(verify_callback_state(Some(&state.token), &HeaderMap::new(), &config).is_err());

        // cookie 里是别的 nonce：同样拒绝。
        let other = create_oauth_state_token(None, secret).expect("other");
        assert!(verify_callback_state(
            Some(&state.token),
            &headers_with_state_cookie(&other.nonce),
            &config
        )
        .is_err());
    }

    #[test]
    fn callback_state_is_mandatory() {
        let secret = "0123456789abcdef0123456789abcdef";
        let config = test_config(secret);
        assert!(verify_callback_state(None, &HeaderMap::new(), &config).is_err());
    }

    #[test]
    fn mfa_required_response_is_distinguishable_by_clients() {
        let response = LoginResponse::MfaRequired {
            mfa_required: true,
            temp_token: "temp".to_string(),
            method: MfaMethod::Totp,
        };

        let value = serde_json::to_value(&response).expect("serialize");
        assert_eq!(value["mfa_required"], serde_json::json!(true));
        assert_eq!(value["temp_token"], serde_json::json!("temp"));
        assert!(value.get("token").is_none());
    }

    #[test]
    fn mfa_login_verify_request_defaults_are_optional() {
        let request: MfaLoginVerifyRequest =
            serde_json::from_str(r#"{"temp_token":"t","totp_code":"123456"}"#).expect("parse");

        assert_eq!(request.temp_token, "t");
        assert_eq!(request.totp_code.as_deref(), Some("123456"));
        assert!(request.backup_code.is_none());
        assert!(!request.admin);
    }
}
