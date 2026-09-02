use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Extension, Form, OriginalUri, Query},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Json, Redirect, Response},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    config::Config,
    error::AuthError,
    models::{
        oidc_client::{OidcClient, ResponseType},
        oidc_token::{AuthorizeRequest, TokenRequest, UserInfoResponse},
        user::User,
    },
    services::{
        database::Database,
        oidc::{JwksResponse, OidcConfiguration, OidcService},
    },
    utils::{
        jwt::{decode_and_verify_token, load_user_from_claims},
        record_id::{normalize_user_id, record_id_key_to_string},
    },
};

pub(crate) const SOULAUTH_SESSION_COOKIE: &str = "soulauth_session";
pub(crate) const OIDC_RETURN_COOKIE: &str = "soulauth_oidc_return";
/// 存放 OAuth `state` 里那个 nonce 的 cookie，用来把 state 绑到发起登录的浏览器上。
///
/// 只验 state 的签名是挡不住 OAuth 登录 CSRF 的：攻击者自己访问一次
/// `/api/auth/login/google`，从跳转地址里就能白拿一个"本服务签发"的合法 state，
/// 再配上自己账号的 `code` 诱导受害者访问回调，受害者的浏览器就被登进了
/// 攻击者的账号。必须要求回调时浏览器能拿出同一个 nonce（double-submit）。
pub(crate) const OAUTH_STATE_COOKIE: &str = "soulauth_oauth_state";
pub(crate) const SESSION_TTL_SECONDS: i64 = 86400;
const OAUTH_STATE_TTL_SECONDS: i64 = 600;

/// 浏览器会话 cookie 的载荷。
///
/// `sid` 是 `session` 表记录的主键。以前这个 cookie 是个纯自包含 JWT，
/// `/api/oidc/authorize` 只验签名就发授权码 —— 用户登出（甚至改密）之后，
/// 只要 cookie 还在，24 小时内照样能换到 access token / ID token，
/// 把"登出真正生效"整个绕过去了。现在它必须对应一条仍然有效的会话记录。
#[derive(Debug, serde::Serialize, Deserialize)]
struct BrowserSessionClaims {
    sub: String,
    sid: String,
    exp: i64,
    iat: i64,
}

#[derive(Debug, serde::Serialize, Deserialize)]
struct OidcReturnClaims {
    target: String,
    exp: i64,
    iat: i64,
}

/// OAuth `state` 的载荷。
///
/// 以前 `state` 里塞的要么是一个用完即弃的随机串（回调时根本不校验），要么直接是
/// OIDC return token；两种都无法防 CSRF。现在 `state` 统一是一个由服务端签名、
/// 带随机 nonce 与过期时间的 JWT：伪造不出来，过期即失效。
#[derive(Debug, serde::Serialize, Deserialize)]
struct OAuthStateClaims {
    nonce: String,
    #[serde(default)]
    return_target: Option<String>,
    exp: i64,
    iat: i64,
}

/// 浏览器会话信息：用户 ID、绑定的会话记录、建立时间（用于 `max_age`）。
pub(crate) struct BrowserSession {
    pub user_id: String,
    pub session_key: String,
    pub issued_at: i64,
}

/// 构造 Set-Cookie。
///
/// `secure` 由部署协议决定（见 `Config::cookies_secure`）：以前这里恒定带
/// `Secure`，导致 `http://localhost` 本地开发时浏览器直接丢弃 cookie，
/// OIDC 流程根本走不通。
pub(crate) fn build_cookie(name: &str, value: &str, max_age_seconds: i64, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; Path=/; Max-Age={}; HttpOnly{}; SameSite=Lax",
        name,
        urlencoding::encode(value),
        max_age_seconds,
        secure_attr
    )
}

pub(crate) fn build_expired_cookie(name: &str, secure: bool) -> String {
    build_cookie(name, "", 0, secure)
}

pub(crate) fn create_browser_session_token(
    user_id: &str,
    session_key: &str,
    jwt_secret: &str,
) -> Result<String, AuthError> {
    create_browser_session_token_with_ttl(user_id, session_key, jwt_secret, SESSION_TTL_SECONDS)
}

fn create_browser_session_token_with_ttl(
    user_id: &str,
    session_key: &str,
    jwt_secret: &str,
    ttl_seconds: i64,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let claims = BrowserSessionClaims {
        sub: user_id.to_string(),
        sid: session_key.to_string(),
        exp: now + ttl_seconds,
        iat: now,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AuthError::TokenError(e.to_string()))
}

pub(crate) fn decode_browser_session_token(
    token: &str,
    jwt_secret: &str,
) -> Result<BrowserSession, AuthError> {
    let mut validation = Validation::default();
    validation.leeway = 0;
    let token_data = decode::<BrowserSessionClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AuthError::InvalidToken)?;

    // 没有 sid 的旧 cookie 一律拒绝（fail-closed）。
    if token_data.claims.sid.trim().is_empty() {
        return Err(AuthError::InvalidToken);
    }

    Ok(BrowserSession {
        user_id: token_data.claims.sub,
        session_key: token_data.claims.sid,
        issued_at: token_data.claims.iat,
    })
}

/// 该浏览器会话对应的 `session` 记录是否仍然有效。
///
/// 登出 / 全端登出 / 改密都会删掉这条记录，于是 cookie 立刻失效。
async fn browser_session_is_active(db: &Arc<Database>, session_key: &str) -> bool {
    let rows: Result<Vec<serde_json::Value>, _> = db
        .query_take0_vec(
            "browser_session_is_active",
            "SELECT count() AS count FROM session \
             WHERE id = type::record('session', $session_key) AND expires_at > $now GROUP ALL",
            json!({ "session_key": session_key, "now": Utc::now().timestamp() }),
        )
        .await;

    match rows {
        Ok(rows) => {
            rows.first()
                .and_then(|row| row.get("count"))
                .and_then(|count| count.as_u64())
                .unwrap_or(0)
                > 0
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to verify browser session; treating as invalid");
            false
        }
    }
}

pub(crate) fn create_oidc_return_token(
    target: &str,
    jwt_secret: &str,
) -> Result<String, AuthError> {
    create_oidc_return_token_with_ttl(target, jwt_secret, OAUTH_STATE_TTL_SECONDS)
}

fn create_oidc_return_token_with_ttl(
    target: &str,
    jwt_secret: &str,
    ttl_seconds: i64,
) -> Result<String, AuthError> {
    if !is_valid_oidc_return_target(target) {
        return Err(AuthError::BadRequest(
            "Invalid OIDC return target".to_string(),
        ));
    }

    sign_oidc_return_token_unchecked(target, jwt_secret, ttl_seconds)
}

fn sign_oidc_return_token_unchecked(
    target: &str,
    jwt_secret: &str,
    ttl_seconds: i64,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let claims = OidcReturnClaims {
        target: target.to_string(),
        exp: now + ttl_seconds,
        iat: now,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AuthError::TokenError(e.to_string()))
}

pub(crate) fn decode_oidc_return_token(token: &str, jwt_secret: &str) -> Result<String, AuthError> {
    let mut validation = Validation::default();
    validation.leeway = 0;
    let token_data = decode::<OidcReturnClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AuthError::InvalidToken)?;

    if !is_valid_oidc_return_target(&token_data.claims.target) {
        return Err(AuthError::InvalidToken);
    }

    Ok(token_data.claims.target)
}

/// 签发 OAuth `state`。`return_target` 只允许是本服务内部的 authorize 路径。
/// 一个刚签发的 OAuth `state`：令牌本身，以及要写进 cookie 的 nonce。
pub(crate) struct IssuedOAuthState {
    pub token: String,
    pub nonce: String,
}

pub(crate) fn create_oauth_state_token(
    return_target: Option<&str>,
    jwt_secret: &str,
) -> Result<IssuedOAuthState, AuthError> {
    if let Some(target) = return_target {
        if !is_valid_oidc_return_target(target) {
            return Err(AuthError::BadRequest(
                "Invalid OIDC return target".to_string(),
            ));
        }
    }

    let now = Utc::now().timestamp();
    let nonce = Uuid::new_v4().to_string();
    let claims = OAuthStateClaims {
        nonce: nonce.clone(),
        return_target: return_target.map(ToOwned::to_owned),
        exp: now + OAUTH_STATE_TTL_SECONDS,
        iat: now,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AuthError::TokenError(e.to_string()))?;

    Ok(IssuedOAuthState { token, nonce })
}

/// state 的 cookie 有效期，与 state 本身一致。
pub(crate) const OAUTH_STATE_COOKIE_TTL_SECONDS: i64 = OAUTH_STATE_TTL_SECONDS;

/// 解析出来的 `state` 内容。
pub(crate) struct DecodedOAuthState {
    /// 必须与浏览器 cookie 里的值一致，否则这次回调不是本浏览器发起的。
    pub nonce: String,
    pub return_target: Option<String>,
}

/// 校验回调带回来的 `state`，返回其中的 nonce 与 OIDC 回跳目标。
///
/// **只验签名不足以防 CSRF** —— 签名只证明"是本服务签的"，而任何人都能向
/// `/api/auth/login/google` 要一个。调用方拿到 nonce 后必须再和 cookie 比对，
/// 见 [`OAUTH_STATE_COOKIE`]。
pub(crate) fn decode_oauth_state_token(
    token: &str,
    jwt_secret: &str,
) -> Result<DecodedOAuthState, AuthError> {
    let mut validation = Validation::default();
    validation.leeway = 0;
    let token_data = decode::<OAuthStateClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AuthError::InvalidToken)?;

    if let Some(target) = &token_data.claims.return_target {
        if !is_valid_oidc_return_target(target) {
            return Err(AuthError::InvalidToken);
        }
    }

    Ok(DecodedOAuthState {
        nonce: token_data.claims.nonce,
        return_target: token_data.claims.return_target,
    })
}

fn is_valid_oidc_return_target(target: &str) -> bool {
    target.starts_with("/api/oidc/authorize?") && !target.starts_with("//")
}

pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|cookie_header| cookie_header.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(cookie_name, cookie_value)| {
            if cookie_name == name {
                urlencoding::decode(cookie_value)
                    .ok()
                    .map(|value| value.into_owned())
            } else {
                None
            }
        })
}

/// 只包含 `/.well-known/openid-configuration` 的路由，挂在站点根路径上。
pub fn discovery_routes() -> Router {
    Router::new().route(
        "/.well-known/openid-configuration",
        get(openid_configuration),
    )
}

pub fn oidc_routes() -> Router {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .route("/logout", get(logout))
}

// OIDC Discovery Endpoint
async fn openid_configuration(
    Extension(oidc_service): Extension<Arc<OidcService>>,
) -> Result<Json<OidcConfiguration>, AuthError> {
    Ok(Json(oidc_service.get_configuration()))
}

/// JSON Web Key Set：暴露 ID Token 的 RS256 验签公钥。
async fn jwks(Extension(oidc_service): Extension<Arc<OidcService>>) -> Json<JwksResponse> {
    Json(oidc_service.jwks())
}

// 授权端点
async fn authorize(
    Query(params): Query<HashMap<String, String>>,
    OriginalUri(original_uri): OriginalUri,
    Extension(oidc_service): Extension<Arc<OidcService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
    let request = AuthorizeRequest {
        response_type: params
            .get("response_type")
            .ok_or_else(|| AuthError::BadRequest("Missing response_type".to_string()))?
            .clone(),
        client_id: params
            .get("client_id")
            .ok_or_else(|| AuthError::BadRequest("Missing client_id".to_string()))?
            .clone(),
        redirect_uri: params
            .get("redirect_uri")
            .ok_or_else(|| AuthError::BadRequest("Missing redirect_uri".to_string()))?
            .clone(),
        scope: params.get("scope").cloned(),
        state: params.get("state").cloned(),
        nonce: params.get("nonce").cloned(),
        code_challenge: params.get("code_challenge").cloned(),
        code_challenge_method: params.get("code_challenge_method").cloned(),
        prompt: params.get("prompt").cloned(),
        max_age: params.get("max_age").and_then(|s| s.parse().ok()),
    };

    validate_authorize_request(&db, &request).await?;

    let now = Utc::now().timestamp();
    let prompt_login = request
        .prompt
        .as_deref()
        .map(|prompt| prompt.split_whitespace().any(|value| value == "login"))
        .unwrap_or(false);
    let prompt_none = request
        .prompt
        .as_deref()
        .map(|prompt| prompt.split_whitespace().any(|value| value == "none"))
        .unwrap_or(false);

    // `prompt=login` 要求强制重新认证，直接跳过已有会话。
    if !prompt_login {
        if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                // 认证方案名按 RFC 7235 不区分大小写，和 `utils::jwt` 用同一个解析函数。
                // 这里如果只认 "Bearer "，一个发 `authorization: bearer xxx` 的客户端
                // 会被判为未登录、被丢去登录页，而它在别的接口上是能正常认证的。
                if let Some(token) = crate::utils::jwt::strip_bearer_scheme(auth_str) {
                    let token = token.trim();
                    // 先解 Claims 再取 user：ID Token 的 `sid` 需要 `session_id`，
                    // 而 `get_user_from_token` 只返回 User，把它丢掉了。
                    if let Ok(claims) = decode_and_verify_token(&db, token).await {
                        // 账号状态同样要看：`decode_and_verify_token` 只验签名、有效期
                        // 与会话是否还在，对停用一无所知。不可用就当作未登录往下走到
                        // 登录页，而不是在这里签授权码。
                        if let Ok(user) = load_user_from_claims(&db, &claims)
                            .await
                            .and_then(|user| user.ensure_usable().map(|_| user))
                        {
                            let user_id = record_id_key_to_string(
                                user.id.as_ref().ok_or(AuthError::UserNotFound)?,
                            );
                            // 没有 session_id 的令牌无法提供 `sid`，按 fail-closed
                            // 处理：不在此处签授权码，继续往下走到登录页。
                            if let Some(session_id) = claims.session_id.as_deref() {
                                return create_authorize_response(
                                    &oidc_service,
                                    &request,
                                    &user_id,
                                    session_id,
                                )
                                .await;
                            }
                        }
                    }
                }
            }
        }

        if let Some(session_token) = cookie_value(&headers, SOULAUTH_SESSION_COOKIE) {
            if let Ok(session) = decode_browser_session_token(&session_token, &config.jwt_secret) {
                // max_age：会话过旧时必须重新认证。
                let session_too_old = request
                    .max_age
                    .map(|max_age| now - session.issued_at > max_age)
                    .unwrap_or(false);

                if !session_too_old && browser_session_is_active(&db, &session.session_key).await {
                    if let Ok(user_id) = resolve_existing_user_id(&db, &session.user_id).await {
                        return create_authorize_response(
                            &oidc_service,
                            &request,
                            &user_id,
                            &session.session_key,
                        )
                        .await;
                    }
                }
            }
        }
    }

    // 用户未登录。`prompt=none` 明确要求不得展示任何交互界面，按规范回错误。
    if prompt_none {
        return Ok(Redirect::to(&create_error_redirect(
            &request.redirect_uri,
            "login_required",
            Some("No active session for prompt=none"),
            request.state.as_deref(),
        ))
        .into_response());
    }

    // 保存原始 OIDC 请求，再把用户送去登录页。
    //
    // 以前这里直接 302 到 Google —— 用邮箱密码注册的账号根本无法完成 SSO。
    // 现在跳到前端登录页（`LOGIN_PAGE_URL`，默认 `{app_url}/login`），
    // 由它决定用密码登录还是走第三方；登录成功后前端带着 `return_to` 回到
    // 这个 authorize 请求即可。`return_to` 是签名过的，篡改不了。
    let return_target = original_uri.to_string();
    let return_token = create_oidc_return_token(&return_target, &config.jwt_secret)?;
    let return_cookie = build_cookie(
        OIDC_RETURN_COOKIE,
        &return_token,
        OAUTH_STATE_TTL_SECONDS,
        config.cookies_secure(),
    );

    let login_page = config.login_page_url();
    let separator = if login_page.contains('?') { '&' } else { '?' };
    let login_url = format!(
        "{login_page}{separator}return_to={}",
        urlencoding::encode(&return_token)
    );

    let mut response = Redirect::to(&login_url).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&return_cookie)
            .map_err(|e| AuthError::BadRequest(format!("Invalid return cookie: {e}")))?,
    );
    Ok(response)
}

async fn load_client(db: &Arc<Database>, client_id: &str) -> Result<OidcClient, AuthError> {
    let query = r#"
        SELECT
            type::string(id) AS id,
            client_id,
            client_secret_hash,
            client_name,
            client_type,
            redirect_uris,
            post_logout_redirect_uris,
            allowed_scopes,
            allowed_grant_types,
            allowed_response_types,
            require_pkce,
            access_token_lifetime,
            refresh_token_lifetime,
            id_token_lifetime,
            is_active,
            type::string(created_by) AS created_by,
            created_at,
            updated_at
        FROM oidc_client
        WHERE client_id = $client_id AND is_active = true
        LIMIT 1
    "#;

    let mut result = db
        .raw_query("load_oidc_client", query, json!({ "client_id": client_id }))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to load OIDC client: {e}")))?;

    let clients: Vec<serde_json::Value> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse OIDC client: {e}")))?;
    let clients: Vec<OidcClient> = clients
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse OIDC client: {e}")))?;

    clients
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::BadRequest("Invalid OIDC client".to_string()))
}

async fn validate_authorize_request(
    db: &Arc<Database>,
    request: &AuthorizeRequest,
) -> Result<(), AuthError> {
    let client = load_client(db, &request.client_id).await?;

    if !client.redirect_uris.contains(&request.redirect_uri) {
        return Err(AuthError::BadRequest("Invalid redirect URI".to_string()));
    }

    let response_types = parse_response_types(&request.response_type)?;
    for response_type in response_types {
        if !client.allowed_response_types.contains(&response_type) {
            return Err(AuthError::BadRequest(
                "Response type not allowed".to_string(),
            ));
        }
    }

    if client.require_pkce && request.code_challenge.is_none() {
        return Err(AuthError::BadRequest("PKCE is required".to_string()));
    }

    Ok(())
}

/// 只认 `code`。
///
/// 这里以前也认 `id_token`，可授权端没有第二条分支 —— 认下来之后照样返回
/// `?code=`。注册侧现在会把非 `code` 的配置挡在门外
/// （`oidc_client::reject_unsupported_response_types`），但库里可能已经存着
/// 旧值，所以这一层也要拒：宁可让接入方拿到一个说得清的错误，也不能让它以为
/// 自己跑的是 implicit。
fn parse_response_types(response_type: &str) -> Result<Vec<ResponseType>, AuthError> {
    let response_types: Vec<ResponseType> = response_type
        .split_whitespace()
        .map(|value| match value {
            "code" => Ok(ResponseType::Code),
            _ => Err(AuthError::BadRequest(
                "unsupported response type; this endpoint implements response_type=code only"
                    .to_string(),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;

    if response_types.is_empty() {
        return Err(AuthError::BadRequest("Missing response type".to_string()));
    }

    Ok(response_types)
}

/// 解析浏览器会话背后的用户，并要求账号仍然可用。
///
/// 状态校验不能省：`browser_session_is_active` 只确认 `session` 行还在、还没过期，
/// 它对账号被停用一无所知。少了这一步，被停用的用户拿着仍未过期的 cookie
/// 就能继续换到新的授权码 —— 停用于是只挡住了原生 API，挡不住 SSO。
async fn resolve_existing_user_id(db: &Arc<Database>, user_id: &str) -> Result<String, AuthError> {
    let users: Vec<User> = db
        .query_take0_vec(
            "resolve_session_user",
            "SELECT * FROM user WHERE id = type::record('user', $user_key) LIMIT 1",
            json!({ "user_key": normalize_user_id(user_id) }),
        )
        .await?;

    let user = users.into_iter().next().ok_or(AuthError::UserNotFound)?;
    user.ensure_usable()?;
    let user_id = user.id.as_ref().ok_or(AuthError::UserNotFound)?;

    Ok(record_id_key_to_string(user_id))
}

async fn create_authorize_response(
    oidc_service: &OidcService,
    request: &AuthorizeRequest,
    user_id: &str,
    auth_session_ref: &str,
) -> Result<Response, AuthError> {
    match oidc_service
        .create_authorization_code(request, user_id, auth_session_ref)
        .await
    {
        Ok(code) => {
            let separator = if request.redirect_uri.contains('?') {
                '&'
            } else {
                '?'
            };
            let mut redirect_url = format!(
                "{}{}code={}",
                request.redirect_uri,
                separator,
                urlencoding::encode(&code)
            );
            if let Some(state) = &request.state {
                redirect_url.push_str(&format!("&state={}", urlencoding::encode(state)));
            }
            Ok(Redirect::to(&redirect_url).into_response())
        }
        Err(e) => Ok(Redirect::to(&create_error_redirect(
            &request.redirect_uri,
            "invalid_request",
            Some(&e.to_string()),
            request.state.as_deref(),
        ))
        .into_response()),
    }
}

/// 客户端认证阶段的错误响应。按 RFC 6749 §5.2 返回标准错误体。
fn client_auth_error(code: &'static str, description: &str) -> Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": code, "error_description": description })),
    )
        .into_response()
}

/// 从 `Authorization: Basic base64(client_id:client_secret)` 取客户端凭证。
///
/// RFC 6749 §2.3.1 把这条列为授权服务器**必须**支持，大多数 OIDC 客户端库
/// 也默认走它。发现文档一直声明支持 `client_secret_basic`，但令牌端点原来
/// 只解析表单 —— 声明与实现对不上。
///
/// 后果不是"少一种可选方式"：BFF 一类的机密客户端用标准库接入时，库按 Basic
/// 发凭证，这边在表单里找不到 `client_secret`，报的是
/// 「Client secret required for confidential clients」。接入方于是反复检查
/// 自己的配置 —— 而配置是对的。**病因与故障形态对不上，是最难查的一类。**
///
/// 按 RFC 6749 §2.3.1，两处都出现凭证时视为无效请求，不做"挑一个用"。
fn basic_client_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;

    Some((percent_decode(id), percent_decode(secret)))
}

/// 解 `%XX` 转义。RFC 6749 §2.3.1 要求 Basic 里的两段先做 form-urlencoded 编码。
///
/// 为这一处引入 `percent-encoding` 依赖不划算：这里只需要处理 `%XX`，
/// 而多一个依赖是长期成本。解不开的转义原样保留 —— 凭证里出现孤立的 `%`
/// 时，宁可让它去和存储的密钥比对失败（结果是拒绝），也不要在这里报错，
/// 那会把"密钥不对"和"编码不对"混成同一个故障。
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| raw.to_string())
}

// 令牌端点
async fn token(
    Extension(oidc_service): Extension<Arc<OidcService>>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Response {
    let mut request = request;

    if let Some((basic_id, basic_secret)) = basic_client_credentials(&headers) {
        // 两处都带凭证 = 无效请求。这里不"挑一个用"：那会让
        // 「表单里的 secret 和头里的 secret 不一致」这种明显异常被静默接受。
        if request.client_secret.is_some() {
            return client_auth_error(
                "invalid_request",
                "client credentials must not be sent in both the Authorization header                  and the request body",
            );
        }
        // 带了就仍然校验一致性；没带就用头里的补齐 —— 后者正是 RFC 允许的写法。
        match &request.client_id {
            Some(form_id) if form_id != &basic_id => {
                return client_auth_error(
                    "invalid_client",
                    "client_id in the Authorization header does not match the request body",
                );
            }
            _ => request.client_id = Some(basic_id),
        }
        request.client_secret = Some(basic_secret);
    }

    // 既没走 Basic，表单里也没有 client_id —— 这才是真正缺少身份的情况。
    // 返回规范的 OAuth 错误体，而不是让它在更深处以别的形式失败。
    if request.client_id.is_none() {
        return client_auth_error(
            "invalid_request",
            "client_id is required when the client does not authenticate with the Authorization header",
        );
    }

    match oidc_service.exchange_code_for_tokens(&request).await {
        Ok(token_response) => {
            ([(header::CACHE_CONTROL, "no-store")], Json(token_response)).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "OIDC token exchange failed");
            // 按 RFC 6749 §5.2 返回标准错误体，而不是把它塞进 message 字符串里。
            (
                axum::http::StatusCode::BAD_REQUEST,
                [(header::CACHE_CONTROL, "no-store")],
                Json(json!({
                    "error": "invalid_grant",
                    "error_description": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

// 用户信息端点
async fn userinfo(
    Extension(oidc_service): Extension<Arc<OidcService>>,
    headers: HeaderMap,
) -> Result<Json<UserInfoResponse>, AuthError> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| AuthError::Unauthorized("Missing authorization header".to_string()))?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| AuthError::Unauthorized("Invalid authorization header".to_string()))?;

    // 和 `utils::jwt` 用同一个解析函数：认证方案名按 RFC 7235 不区分大小写。
    let access_token = crate::utils::jwt::strip_bearer_scheme(auth_str)
        .map(str::trim)
        .ok_or_else(|| AuthError::Unauthorized("Invalid token type".to_string()))?;

    match oidc_service.get_userinfo(access_token).await {
        Ok(userinfo) => Ok(Json(userinfo)),
        Err(e) => {
            // 底层错误可能带着 SurrealQL 语句原文，不能直接回给调用方。
            tracing::warn!(error = %e, "OIDC userinfo lookup failed");
            Err(AuthError::Unauthorized("Invalid access token".to_string()))
        }
    }
}

/// RP 发起的登出。
///
/// 以前这个端点只做重定向：既不撤销任何令牌，也不校验 `post_logout_redirect_uri`
/// （等于一个开放重定向）。现在：
/// 1. 校验 `id_token_hint` 的签名，确定要登出的用户与客户端；
/// 2. 吊销对应的 OIDC 访问 / 刷新令牌；
/// 3. 清掉浏览器会话 cookie；
/// 4. `post_logout_redirect_uri` 必须在该客户端登记的白名单里，否则回落到首页。
async fn logout(
    Query(params): Query<HashMap<String, String>>,
    Extension(oidc_service): Extension<Arc<OidcService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<Response, AuthError> {
    let post_logout_redirect_uri = params.get("post_logout_redirect_uri");
    let id_token_hint = params.get("id_token_hint");
    let state = params.get("state");

    let hint = id_token_hint.and_then(|token| match oidc_service.verify_id_token_hint(token) {
        Ok(parsed) => Some(parsed),
        Err(e) => {
            tracing::warn!(error = %e, "Ignoring invalid id_token_hint on logout");
            None
        }
    });

    if let Some((user_id, client_id)) = &hint {
        if let Err(e) = oidc_service
            .revoke_client_tokens_for_user(client_id, user_id)
            .await
        {
            tracing::error!(error = %e, "Failed to revoke OIDC tokens on logout");
        }
        // 同时结束该用户在本 IdP 上的 API 会话。
        if let Err(e) = db.delete_sessions_by_user_id(user_id).await {
            tracing::error!(error = %e, "Failed to revoke sessions on logout");
        }
    }

    let redirect_url = match (post_logout_redirect_uri, &hint) {
        (Some(requested), Some((_, client_id))) => {
            let client = load_client(&db, client_id).await.ok();
            let allowed = client
                .map(|client| client.post_logout_redirect_uris.contains(requested))
                .unwrap_or(false);

            if allowed {
                let mut url = requested.clone();
                if let Some(state_value) = state {
                    let separator = if url.contains('?') { '&' } else { '?' };
                    url.push_str(&format!(
                        "{separator}state={}",
                        urlencoding::encode(state_value)
                    ));
                }
                url
            } else {
                tracing::warn!("Rejected unregistered post_logout_redirect_uri");
                config.app_url.clone()
            }
        }
        // 没有可信的 id_token_hint 就无从判断白名单，一律回首页。
        _ => config.app_url.clone(),
    };

    let mut response = Redirect::to(&redirect_url).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&build_expired_cookie(
            SOULAUTH_SESSION_COOKIE,
            config.cookies_secure(),
        ))
        .map_err(|e| AuthError::BadRequest(format!("Invalid session cookie: {e}")))?,
    );
    Ok(response)
}

/// 构造 OAuth 错误回跳 URL。
fn create_error_redirect(
    redirect_uri: &str,
    error: &str,
    description: Option<&str>,
    state: Option<&str>,
) -> String {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut url = format!("{redirect_uri}{separator}error={error}");

    if let Some(desc) = description {
        url.push_str(&format!("&error_description={}", urlencoding::encode(desc)));
    }

    if let Some(state_value) = state {
        url.push_str(&format!("&state={}", urlencoding::encode(state_value)));
    }

    url
}

#[cfg(test)]
mod tests {
    use super::{
        build_cookie, build_expired_cookie, create_browser_session_token,
        create_browser_session_token_with_ttl, create_error_redirect, create_oauth_state_token,
        create_oidc_return_token, decode_browser_session_token, decode_oauth_state_token,
        decode_oidc_return_token, sign_oidc_return_token_unchecked, OAUTH_STATE_COOKIE,
        OIDC_RETURN_COOKIE, SOULAUTH_SESSION_COOKIE,
    };

    #[test]
    fn build_cookie_encodes_value_and_sets_browser_security_attributes() {
        let cookie = build_cookie(
            OIDC_RETURN_COOKIE,
            "/api/oidc/authorize?state=a b",
            60,
            true,
        );

        assert_eq!(
            cookie,
            "soulauth_oidc_return=%2Fapi%2Foidc%2Fauthorize%3Fstate%3Da%20b; Path=/; Max-Age=60; HttpOnly; Secure; SameSite=Lax"
        );
    }

    #[test]
    fn build_cookie_omits_secure_over_plain_http() {
        let cookie = build_cookie(SOULAUTH_SESSION_COOKIE, "token", 60, false);

        assert_eq!(
            cookie,
            "soulauth_session=token; Path=/; Max-Age=60; HttpOnly; SameSite=Lax"
        );
        assert!(!cookie.contains("Secure"));
    }

    #[test]
    fn build_expired_cookie_clears_value() {
        let cookie = build_expired_cookie(OIDC_RETURN_COOKIE, true);

        assert_eq!(
            cookie,
            "soulauth_oidc_return=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
        );
    }

    #[test]
    fn browser_session_token_round_trips_user_and_session() {
        let secret = "test-secret";
        let token = create_browser_session_token("user-123", "sess-abc", secret).expect("token");

        let session = decode_browser_session_token(&token, secret).expect("decoded session");

        assert_eq!(session.user_id, "user-123");
        assert_eq!(session.session_key, "sess-abc");
        assert!(session.issued_at > 0);
    }

    #[test]
    fn browser_session_token_rejects_wrong_secret() {
        let token =
            create_browser_session_token("user-123", "sess-abc", "correct-secret").expect("token");

        assert!(decode_browser_session_token(&token, "wrong-secret").is_err());
    }

    #[test]
    fn browser_session_token_rejects_expired_token() {
        let token =
            create_browser_session_token_with_ttl("user-123", "sess-abc", "test-secret", -1)
                .expect("token");

        assert!(decode_browser_session_token(&token, "test-secret").is_err());
    }

    #[test]
    fn legacy_browser_session_cookie_without_sid_is_rejected() {
        // 升级前签发的 cookie 没有 sid，无法绑定到会话记录，必须拒绝。
        let legacy = serde_json::json!({
            "sub": "user-123",
            "exp": 9_999_999_999i64,
            "iat": 1,
        });
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &legacy,
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
        )
        .expect("token");

        assert!(decode_browser_session_token(&token, "test-secret").is_err());
    }

    #[test]
    fn signed_return_cookie_round_trips_internal_authorize_target() {
        let target =
            "/api/oidc/authorize?client_id=client&redirect_uri=https%3A%2F%2Fapp.example%2Fcb";
        let token = create_oidc_return_token(target, "test-secret").expect("token");

        let decoded = decode_oidc_return_token(&token, "test-secret").expect("target");

        assert_eq!(decoded, target);
    }

    #[test]
    fn tampered_return_cookie_is_rejected() {
        let target = "/api/oidc/authorize?client_id=client";
        let mut token = create_oidc_return_token(target, "test-secret").expect("token");
        token.push_str("tampered");

        assert!(decode_oidc_return_token(&token, "test-secret").is_err());
    }

    #[test]
    fn expired_return_cookie_is_rejected() {
        let target = "/api/oidc/authorize?client_id=client";
        let token = sign_oidc_return_token_unchecked(target, "test-secret", -1).expect("token");

        assert!(decode_oidc_return_token(&token, "test-secret").is_err());
    }

    #[test]
    fn external_return_cookie_target_is_rejected() {
        let token = sign_oidc_return_token_unchecked(
            "https://evil.example/api/oidc/authorize",
            "test-secret",
            600,
        )
        .expect("token");

        assert!(decode_oidc_return_token(&token, "test-secret").is_err());
    }

    #[test]
    fn browser_session_cookie_name_is_stable() {
        assert_eq!(SOULAUTH_SESSION_COOKIE, "soulauth_session");
    }

    #[test]
    fn oauth_state_round_trips_return_target() {
        let target = "/api/oidc/authorize?client_id=client";
        let state = create_oauth_state_token(Some(target), "test-secret").expect("state");

        let decoded = decode_oauth_state_token(&state.token, "test-secret").expect("decoded");

        assert_eq!(decoded.return_target.as_deref(), Some(target));
        // nonce 必须原样带回来：登录入口把它写进 cookie，回调时要拿它比对。
        assert_eq!(decoded.nonce, state.nonce);
    }

    #[test]
    fn oauth_state_without_return_target_is_still_verified() {
        let state = create_oauth_state_token(None, "test-secret").expect("state");

        let decoded = decode_oauth_state_token(&state.token, "test-secret").expect("decoded");
        assert!(decoded.return_target.is_none());
        assert!(!decoded.nonce.is_empty());
    }

    #[test]
    fn forged_oauth_state_is_rejected() {
        let state = create_oauth_state_token(None, "real-secret").expect("state");

        assert!(decode_oauth_state_token(&state.token, "attacker-secret").is_err());
        assert!(decode_oauth_state_token("not-a-jwt", "real-secret").is_err());
    }

    #[test]
    fn oauth_state_rejects_external_return_target() {
        assert!(create_oauth_state_token(Some("https://evil.example/"), "test-secret").is_err());
    }

    #[test]
    fn oauth_state_nonce_differs_per_request() {
        let a = create_oauth_state_token(None, "test-secret").expect("a");
        let b = create_oauth_state_token(None, "test-secret").expect("b");

        assert_ne!(a.nonce, b.nonce, "each state must carry a fresh nonce");
        assert_ne!(a.token, b.token);
    }

    #[test]
    fn oauth_state_cookie_name_is_stable() {
        // 名字变了会让上一批还在途中的登录全部失败，改动要有意识。
        assert_eq!(OAUTH_STATE_COOKIE, "soulauth_oauth_state");
    }

    #[test]
    fn error_redirect_preserves_existing_query_string() {
        let url = create_error_redirect(
            "https://app.example/cb?tenant=1",
            "login_required",
            Some("no session"),
            Some("xyz"),
        );

        assert!(url.starts_with("https://app.example/cb?tenant=1&error=login_required"));
        assert!(url.contains("&state=xyz"));
    }
}

#[cfg(test)]
mod client_auth_tests {
    use super::{basic_client_credentials, percent_decode};
    use axum::http::{header, HeaderMap, HeaderValue};
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn headers_with(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        h
    }

    fn basic(raw: &str) -> HeaderMap {
        headers_with(&format!("Basic {}", STANDARD.encode(raw)))
    }

    #[test]
    fn reads_credentials_from_the_basic_header() {
        // 发现文档一直声明支持 client_secret_basic，而令牌端点原来只解析表单。
        // 大多数 OIDC 客户端库默认走 Basic —— 这条不通，接入方会在自己那边
        // 反复查配置，而配置是对的。
        let got = basic_client_credentials(&basic("os-client:s3cret")).expect("credentials");
        assert_eq!(got, ("os-client".to_string(), "s3cret".to_string()));
    }

    #[test]
    fn scheme_is_case_insensitive() {
        // RFC 7235：认证方案名不区分大小写。
        let raw = STANDARD.encode("a:b");
        for scheme in ["Basic", "basic", "BASIC", "BaSiC"] {
            assert!(
                basic_client_credentials(&headers_with(&format!("{scheme} {raw}"))).is_some(),
                "{scheme} should be accepted"
            );
        }
    }

    #[test]
    fn other_schemes_and_malformed_values_are_ignored() {
        // 忽略而不是报错：Bearer 头是别的用途，不该在这里把请求打回。
        assert!(basic_client_credentials(&headers_with("Bearer abc")).is_none());
        assert!(basic_client_credentials(&headers_with("Basic !!!not-base64")).is_none());
        assert!(basic_client_credentials(&basic("no-colon-here")).is_none());
        assert!(basic_client_credentials(&HeaderMap::new()).is_none());
    }

    #[test]
    fn percent_escapes_are_decoded() {
        // RFC 6749 §2.3.1 要求两段先做 form-urlencoded 编码；
        // 含 `:` 或空格的密钥不解码就永远比对不上。
        assert_eq!(percent_decode("a%3Ab"), "a:b");
        assert_eq!(percent_decode("s%20p"), "s p");
        assert_eq!(percent_decode("plain"), "plain");
        // 孤立的 % 原样保留，不报错 —— 见函数文档
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn a_colon_inside_the_secret_is_preserved() {
        // 只在第一个 `:` 处切分：密钥里可以合法地含冒号。
        let got = basic_client_credentials(&basic("id:pa:ss:word")).expect("credentials");
        assert_eq!(got, ("id".to_string(), "pa:ss:word".to_string()));
    }
}
