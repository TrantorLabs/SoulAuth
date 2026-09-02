use std::sync::Arc;

use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, Validation};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::Config,
    models::{
        oidc_client::{ClientType, GrantType, OidcClient, ResponseType},
        oidc_token::{
            AuthorizeRequest, IdTokenClaims, OidcAccessToken, OidcAuthorizationCode,
            OidcRefreshToken, TokenRequest, TokenResponse, UserInfoResponse,
        },
        user::User,
    },
    services::{database::Database, oidc_keys::OidcSigningKey},
    utils::record_id::normalize_user_id,
};

pub use crate::services::oidc_keys::JwksResponse;

#[derive(Clone)]
pub struct OidcService {
    db: Arc<Database>,
    config: Config,
    signing_key: Arc<OidcSigningKey>,
}

/// 身份 claim 的披露判定。
///
/// # 为什么要收成一个类型
///
/// ID Token 与 UserInfo 输出的是同一批 claim，因此必须服从同一套披露规则。
/// 此前两条通路各写各的：UserInfo 按 scope 裁剪，`generate_id_token` 却连
/// `scope` 参数都没有，无条件放 `email` / `email_verified` /
/// `preferred_username`。于是只申请 `openid` 的客户端，从 UserInfo 拿不到邮箱，
/// 从 ID Token 却拿得到 —— 同一台服务器，同一份 claim，两套规则。
///
/// 把判定收在这里，两条通路就不可能再分叉：想改规则只有一个地方可改。
///
/// 注意它只管**身份属性**。`sub` / `iss` / `aud` / `exp` / `iat` /
/// `auth_time` / `sid` 是协议骨架，任何 scope 下都必须存在，不归它管。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClaimDisclosure {
    /// `email` scope：放行 `email` 与 `email_verified`。
    email: bool,
    /// `profile` scope：放行 `preferred_username`、`updated_at` 等档案属性。
    profile: bool,
}

impl ClaimDisclosure {
    fn from_scope(scope: &str) -> Self {
        let scopes: Vec<&str> = scope.split_whitespace().collect();
        Self {
            email: scopes.contains(&"email"),
            profile: scopes.contains(&"profile"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub end_session_endpoint: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

impl OidcService {
    pub fn new(
        db: Arc<Database>,
        config: Config,
        signing_key: Arc<OidcSigningKey>,
    ) -> Result<Self> {
        Ok(Self {
            db,
            config,
            signing_key,
        })
    }

    // OIDC Discovery Endpoint
    pub fn get_configuration(&self) -> OidcConfiguration {
        let base_url = self.config.app_url.trim_end_matches('/');

        OidcConfiguration {
            issuer: base_url.to_string(),
            authorization_endpoint: format!("{}/api/oidc/authorize", base_url),
            token_endpoint: format!("{}/api/oidc/token", base_url),
            userinfo_endpoint: format!("{}/api/oidc/userinfo", base_url),
            jwks_uri: format!("{}/api/oidc/jwks", base_url),
            end_session_endpoint: format!("{}/api/oidc/logout", base_url),
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            subject_types_supported: vec!["public".to_string()],
            // 与实际签名算法保持一致：公钥通过 jwks_uri 暴露。
            id_token_signing_alg_values_supported: vec!["RS256".to_string()],
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_post".to_string(),
                "client_secret_basic".to_string(),
                "none".to_string(),
            ],
            // 只保留 S256：plain 起不到防授权码拦截的作用。
            code_challenge_methods_supported: vec!["S256".to_string()],
        }
    }

    pub fn jwks(&self) -> JwksResponse {
        self.signing_key.jwks()
    }

    // 授权码流程 - 生成授权码
    pub async fn create_authorization_code(
        &self,
        request: &AuthorizeRequest,
        user_id: &str,
        auth_session_ref: &str,
    ) -> Result<String> {
        // 验证客户端
        let client = self
            .get_client(&request.client_id)
            .await
            .map_err(|e| anyhow!("get client failed: {e}"))?;
        if !client.is_active {
            return Err(anyhow!("Client is not active"));
        }

        // 验证重定向URI
        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err(anyhow!("Invalid redirect URI"));
        }

        // 验证响应类型。只认 `code` —— 与发现文档的
        // `response_types_supported: ["code"]` 以及授权端唯一的那条分支保持一致。
        let response_types: Vec<ResponseType> = request
            .response_type
            .split_whitespace()
            .map(|rt| match rt {
                "code" => Ok(ResponseType::Code),
                _ => Err(anyhow!(
                    "unsupported response type; this endpoint implements response_type=code only"
                )),
            })
            .collect::<Result<Vec<_>>>()?;

        for rt in &response_types {
            if !client.allowed_response_types.contains(rt) {
                return Err(anyhow!("Response type not allowed for this client"));
            }
        }

        // 验证 PKCE (如果客户端要求)
        if client.require_pkce && request.code_challenge.is_none() {
            return Err(anyhow!("PKCE is required for this client"));
        }

        // 只收 S256。发现文档里 `code_challenge_methods_supported` 就只列了 S256，
        // 但这里以前不校验 method，缺省会按 `plain` 处理 —— plain 的 challenge 等于
        // verifier 本身，谁能看到授权请求（Referer、浏览器历史、同设备的其他 App）
        // 谁就直接拿到了 verifier，PKCE 等于没有。不认下发时就拒，别留到兑换阶段。
        if request.code_challenge.is_some() {
            match request.code_challenge_method.as_deref() {
                Some("S256") => {}
                Some(other) => {
                    return Err(anyhow!(
                        "Unsupported code_challenge_method '{other}': only S256 is supported"
                    ))
                }
                None => {
                    return Err(anyhow!(
                        "code_challenge_method is required and must be S256"
                    ))
                }
            }
        }

        // 生成授权码
        let code = generate_random_string(32);
        let expires_at = Utc::now().timestamp() + 600; // 10分钟过期
        let scope = self.resolve_scope(&client, request.scope.as_deref())?;

        let auth_code = OidcAuthorizationCode {
            id: None,
            code_hash: crate::utils::crypto::hash_bearer(&code),
            client_id: request.client_id.clone(),
            user_id: user_id.to_string(),
            redirect_uri: request.redirect_uri.clone(),
            scope,
            state: request.state.clone(),
            nonce: request.nonce.clone(),
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method.clone(),
            auth_session_ref: Some(auth_session_ref.to_string()),
            used: false,
            expires_at,
            created_at: Utc::now().timestamp(),
        };

        // 保存授权码
        self.save_authorization_code(&auth_code).await?;

        Ok(code)
    }

    /// 把请求的 scope 收敛到客户端被允许的集合内，未申请时回落到 `openid`。
    fn resolve_scope(&self, client: &OidcClient, requested: Option<&str>) -> Result<String> {
        let requested = requested.unwrap_or("openid").trim();
        if requested.is_empty() {
            return Ok("openid".to_string());
        }

        let mut granted: Vec<String> = Vec::new();
        for scope in requested.split_whitespace() {
            if !client
                .allowed_scopes
                .iter()
                .any(|allowed| allowed.as_str() == scope)
            {
                return Err(anyhow!("Scope not allowed for this client: {scope}"));
            }
            if !granted.iter().any(|existing| existing.as_str() == scope) {
                granted.push(scope.to_string());
            }
        }

        Ok(granted.join(" "))
    }

    // 令牌端点 - 交换授权码获取令牌
    pub async fn exchange_code_for_tokens(&self, request: &TokenRequest) -> Result<TokenResponse> {
        match request.grant_type.as_str() {
            "authorization_code" => self.handle_authorization_code_grant(request).await,
            "refresh_token" => self.handle_refresh_token_grant(request).await,
            _ => Err(anyhow!("Unsupported grant type")),
        }
    }

    /// 统一的客户端认证：机密客户端必须提供且校验通过 client_secret。
    async fn authenticate_client(&self, request: &TokenRequest) -> Result<OidcClient> {
        let client = self.get_client(request.client_id()).await?;

        match (&client.client_type, request.client_secret.as_deref()) {
            (ClientType::Confidential, None) => {
                Err(anyhow!("Client secret required for confidential clients"))
            }
            (_, Some(secret)) => {
                if self.verify_client_secret(&client, secret)? {
                    Ok(client)
                } else {
                    Err(anyhow!("Invalid client credentials"))
                }
            }
            (ClientType::Public, None) => Ok(client),
        }
    }

    async fn handle_authorization_code_grant(
        &self,
        request: &TokenRequest,
    ) -> Result<TokenResponse> {
        let code = request
            .code
            .as_ref()
            .ok_or_else(|| anyhow!("Missing authorization code"))?;
        let redirect_uri = request
            .redirect_uri
            .as_ref()
            .ok_or_else(|| anyhow!("Missing redirect URI"))?;

        let client = self.authenticate_client(request).await?;
        if !client
            .allowed_grant_types
            .contains(&GrantType::AuthorizationCode)
        {
            return Err(anyhow!("Grant type not allowed for this client"));
        }

        // 获取并验证授权码
        let mut auth_code = self
            .get_authorization_code(code)
            .await
            .map_err(|e| anyhow!("get authorization code failed: {e}"))?;
        if auth_code.used {
            return Err(anyhow!("Authorization code already used"));
        }
        if auth_code.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Authorization code expired"));
        }
        if auth_code.client_id != request.client_id() {
            return Err(anyhow!("Authorization code was not issued to this client"));
        }
        if auth_code.redirect_uri != *redirect_uri {
            return Err(anyhow!("Redirect URI mismatch"));
        }

        // 验证 PKCE。
        //
        // public 客户端**必须**有 code_challenge，没有就拒绝兑换。注册那一侧已经
        // 把 require_pkce 对 public 强制为 true（见 `resolve_require_pkce`），
        // 这里是第二道：存量里可能还留着改动之前建的 require_pkce=false 的客户端，
        // 以及它们已经发出去的授权码。少了这一道，那些客户端仍然是
        // 「无 verifier 无 secret 即可兑换」—— 谁截获授权码谁就接管账号。
        if matches!(client.client_type, ClientType::Public) && auth_code.code_challenge.is_none() {
            return Err(anyhow!(
                "PKCE is required for public clients; this authorization code was issued without a code_challenge"
            ));
        }

        if let Some(code_challenge) = &auth_code.code_challenge {
            let code_verifier = request
                .code_verifier
                .as_ref()
                .ok_or_else(|| anyhow!("Code verifier required"))?;

            if !self.verify_pkce(
                code_challenge,
                &auth_code.code_challenge_method,
                code_verifier,
            )? {
                return Err(anyhow!("Invalid code verifier"));
            }
        }

        // 标记授权码为已使用. The guarded update prevents concurrent redemptions.
        auth_code.used = true;
        self.update_authorization_code(&auth_code)
            .await
            .map_err(|e| anyhow!("mark authorization code used failed: {e}"))?;

        // 生成令牌
        self.generate_tokens(
            &client,
            &auth_code.user_id,
            &auth_code.scope,
            auth_code.nonce.as_deref(),
            auth_code.auth_session_ref.as_deref(),
        )
        .await
        .map_err(|e| anyhow!("generate tokens failed: {e}"))
    }

    async fn handle_refresh_token_grant(&self, request: &TokenRequest) -> Result<TokenResponse> {
        let refresh_token = request
            .refresh_token
            .as_ref()
            .ok_or_else(|| anyhow!("Missing refresh token"))?;

        let client = self.authenticate_client(request).await?;
        if !client
            .allowed_grant_types
            .contains(&GrantType::RefreshToken)
        {
            return Err(anyhow!("Grant type not allowed for this client"));
        }

        // 获取并验证刷新令牌
        let stored_refresh_token = self.get_refresh_token(refresh_token).await?;
        if stored_refresh_token.client_id != request.client_id() {
            return Err(anyhow!("Refresh token was not issued to this client"));
        }
        if stored_refresh_token.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Refresh token expired"));
        }
        if stored_refresh_token.used {
            // 复用已轮换过的刷新令牌通常意味着令牌泄露：直接吊销该用户在该客户端上的全部令牌。
            self.revoke_client_tokens_for_user(
                &stored_refresh_token.client_id,
                &stored_refresh_token.user_id,
            )
            .await?;
            return Err(anyhow!("Refresh token already used"));
        }

        // 原子地标记旧刷新令牌为已使用，避免并发重放
        if !self
            .consume_refresh_token_by_hash(&stored_refresh_token.token_hash)
            .await?
        {
            return Err(anyhow!("Refresh token already used"));
        }

        // 使旧的访问令牌失效
        self.revoke_access_token_by_hash(&stored_refresh_token.access_token_hash)
            .await?;

        // 刷新时不允许提权：新 scope 必须是原 scope 的子集
        let scope = match request.scope.as_deref() {
            None => stored_refresh_token.scope.clone(),
            Some(requested) => {
                let original: Vec<&str> = stored_refresh_token.scope.split_whitespace().collect();
                for scope in requested.split_whitespace() {
                    if !original.contains(&scope) {
                        return Err(anyhow!("Requested scope exceeds the original grant"));
                    }
                }
                requested.to_string()
            }
        };

        self.generate_tokens(
            &client,
            &stored_refresh_token.user_id,
            &scope,
            None,
            stored_refresh_token.auth_session_ref.as_deref(),
        )
        .await
    }

    async fn generate_tokens(
        &self,
        client: &OidcClient,
        user_id: &str,
        scope: &str,
        nonce: Option<&str>,
        auth_session_ref: Option<&str>,
    ) -> Result<TokenResponse> {
        let now = Utc::now().timestamp();

        // 账号闸门放在**签发之前**，且不依赖 scope。
        // 放在下面"scope 含 openid 才取用户"那一段里是不够的：不带 openid 的
        // 请求同样会拿到 access token，而停用的账号一张都不该再拿到。
        let user = self
            .load_active_user(user_id)
            .await
            .map_err(|e| anyhow!("refusing to issue tokens: {e}"))?;

        // 生成访问令牌
        let access_token = generate_random_string(32);
        let access_token_expires_at = now + client.access_token_lifetime;

        let oidc_access_token = OidcAccessToken {
            id: None,
            token_hash: crate::utils::crypto::hash_bearer(&access_token),
            token_type: "Bearer".to_string(),
            client_id: client.client_id.clone(),
            user_id: user_id.to_string(),
            scope: scope.to_string(),
            expires_at: access_token_expires_at,
            created_at: now,
        };

        self.save_access_token(&oidc_access_token)
            .await
            .map_err(|e| anyhow!("save access token failed: {e}"))?;

        // 生成刷新令牌
        let refresh_token = if client
            .allowed_grant_types
            .contains(&GrantType::RefreshToken)
        {
            let token = generate_random_string(48);
            let refresh_token_expires_at = now + client.refresh_token_lifetime;

            let oidc_refresh_token = OidcRefreshToken {
                id: None,
                token_hash: crate::utils::crypto::hash_bearer(&token),
                client_id: client.client_id.clone(),
                user_id: user_id.to_string(),
                access_token_hash: crate::utils::crypto::hash_bearer(&access_token),
                scope: scope.to_string(),
                auth_session_ref: auth_session_ref.map(ToOwned::to_owned),
                used: false,
                expires_at: refresh_token_expires_at,
                created_at: now,
            };

            self.save_refresh_token(&oidc_refresh_token)
                .await
                .map_err(|e| anyhow!("save refresh token failed: {e}"))?;
            Some(token)
        } else {
            None
        };

        // 生成 ID 令牌（如果 scope 包含 openid）。用户在上面已经取过并校验过状态。
        //
        // `scope` 必须传下去：它不只决定**发不发** ID Token，还决定里面**放什么**。
        // 此前只用它判断了前者，于是只申请 `openid` 的客户端照样拿到邮箱与用户名 ——
        // 而同一台服务器的 UserInfo 是按 scope 裁剪的。同一份 claim 两套披露规则。
        let id_token = if scope.split_whitespace().any(|value| value == "openid") {
            Some(
                self.generate_id_token(client, &user, nonce, auth_session_ref, scope)
                    .await?,
            )
        } else {
            None
        };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: client.access_token_lifetime,
            refresh_token,
            id_token,
            scope: scope.to_string(),
        })
    }

    /// 签发 ID Token。
    ///
    /// `auth_session_ref` 是必需的：`sid` 按 P0-DECISION-10 DEC-10-06 为必填 claim。
    /// 取不到会话引用时**拒签**，不签一张没有 `sid` 的 ID Token —— OS 的每条审计
    /// 链路都要求 `auth_session_ref`，缺了下游只能编或留空，两者都比失败更糟。
    ///
    /// 影响：升级前签发的刷新令牌没有该字段，首次刷新会失败，用户需重新登录一次。
    /// 签发 ID Token。
    ///
    /// 身份 claim 的披露由 [`ClaimDisclosure`] 判定，与 UserInfo 同一处口径。
    ///
    /// `sub`、`iss`、`aud`、`exp`、`iat`、`auth_time`、`sid` 是协议骨架，
    /// 不受 scope 约束；`email` / `profile` 这类身份属性受约束。
    async fn generate_id_token(
        &self,
        client: &OidcClient,
        user: &User,
        nonce: Option<&str>,
        auth_session_ref: Option<&str>,
        scope: &str,
    ) -> Result<String> {
        let sid = auth_session_ref
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("Missing auth session reference; refusing to issue ID token"))?
            .to_string();

        let now = Utc::now().timestamp();
        let exp = now + client.id_token_lifetime;

        let disclose = ClaimDisclosure::from_scope(scope);

        let claims = IdTokenClaims {
            iss: self.issuer(),
            sub: crate::utils::record_id::record_id_key_to_string(
                user.id.as_ref().ok_or_else(|| anyhow!("User has no id"))?,
            ),
            aud: client.client_id.clone(),
            exp,
            iat: now,
            auth_time: user.last_login_at.unwrap_or(now),
            sid,
            nonce: nonce.map(|n| n.to_string()),
            email: disclose.email.then(|| user.email.clone()),
            email_verified: disclose.email.then_some(user.is_email_verified),
            name: None, // 需要从用户档案获取
            preferred_username: disclose.profile.then(|| user.username.clone()),
            profile: None,
            picture: None,
        };

        encode(
            &self.signing_key.jwt_header(),
            &claims,
            self.signing_key.encoding_key(),
        )
        .map_err(|e| anyhow!("Failed to generate ID token: {}", e))
    }

    fn issuer(&self) -> String {
        self.config.app_url.trim_end_matches('/').to_string()
    }

    /// 校验 RP 在登出请求里带上的 `id_token_hint`，返回 (user_id, client_id)。
    pub fn verify_id_token_hint(&self, id_token: &str) -> Result<(String, String)> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer()]);
        // 登出时 ID Token 通常已经过期，这里只关心签名与归属；
        // `aud` 不设置即表示不校验（jsonwebtoken 只在 `validation.aud` 存在时比对）。
        validation.validate_exp = false;

        let token_data =
            decode::<IdTokenClaims>(id_token, self.signing_key.decoding_key(), &validation)
                .map_err(|e| anyhow!("Invalid id_token_hint: {e}"))?;

        Ok((token_data.claims.sub, token_data.claims.aud))
    }

    // UserInfo 端点
    pub async fn get_userinfo(&self, access_token: &str) -> Result<UserInfoResponse> {
        let token = self.get_access_token(access_token).await?;
        if token.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Access token expired"));
        }

        let scopes: Vec<&str> = token.scope.split_whitespace().collect();
        if !scopes.contains(&"openid") {
            return Err(anyhow!("Access token does not carry the openid scope"));
        }

        // 停用之后，此前签发的 access token 不该还能换出身份。
        let user = self.load_active_user(&token.user_id).await?;
        let disclose = ClaimDisclosure::from_scope(&token.scope);

        Ok(UserInfoResponse {
            sub: crate::utils::record_id::record_id_key_to_string(
                user.id.as_ref().ok_or_else(|| anyhow!("User has no id"))?,
            ),
            email: disclose.email.then(|| user.email.clone()),
            email_verified: disclose.email.then_some(user.is_email_verified),
            name: None, // 需要从用户档案获取
            preferred_username: disclose.profile.then(|| user.username.clone()),
            profile: None,
            picture: None,
            updated_at: disclose.profile.then_some(user.updated_at),
        })
    }

    // 辅助方法
    fn verify_client_secret(&self, client: &OidcClient, provided_secret: &str) -> Result<bool> {
        Ok(verify_client_secret_hash(
            &client.client_secret_hash,
            provided_secret,
        ))
    }

    fn verify_pkce(
        &self,
        code_challenge: &str,
        method: &Option<String>,
        code_verifier: &str,
    ) -> Result<bool> {
        Self::verify_pkce_value(code_challenge, method.as_deref(), code_verifier)
    }

    pub(crate) fn verify_pkce_value(
        code_challenge: &str,
        method: Option<&str>,
        code_verifier: &str,
    ) -> Result<bool> {
        if !(43..=128).contains(&code_verifier.len()) {
            return Err(anyhow!(
                "Invalid code verifier: length must be between 43 and 128 characters"
            ));
        }

        if !code_verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
        {
            return Err(anyhow!(
                "Invalid code verifier: contains characters outside RFC 7636 charset"
            ));
        }

        // 授权阶段已经把非 S256 拦在门外了，这里不再兜底 `plain`：
        // 留着它，存量的 plain 授权码或将来某条绕过下发校验的路径就还能降级。
        match method {
            Some("S256") => {
                let hash = Sha256::digest(code_verifier.as_bytes());
                let encoded = general_purpose::URL_SAFE_NO_PAD.encode(hash);
                Ok(constant_time_eq(
                    encoded.as_bytes(),
                    code_challenge.as_bytes(),
                ))
            }
            Some(other) => Err(anyhow!("Unsupported code challenge method: {}", other)),
            None => Err(anyhow!("Missing code_challenge_method; S256 is required")),
        }
    }

    pub async fn get_client(&self, client_id: &str) -> Result<OidcClient> {
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

        let mut result = self
            .db
            .raw_query(
                "oidc_get_client",
                query,
                serde_json::json!({ "client_id": client_id }),
            )
            .await?;

        let clients: Vec<serde_json::Value> = result.take(0)?;
        let clients: Vec<OidcClient> = clients
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        clients
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Client not found"))
    }

    /// 由**身份根**引用取回 user 行。
    ///
    /// 授权码与令牌里的 `user_id` 自 Stage 3 起存的是 actor ref，所以这里按
    /// `subject_id` 反查。按 `user.id` 查会一行也找不到 —— 授权码签发成功、
    /// 兑换却返回 400，集成测试抓到的正是这个。
    ///
    /// 兼容旧值：Stage 3 之前签发、仍在有效期内的授权码与刷新令牌里存的是
    /// user id。两种都试，直到那批令牌自然过期。
    async fn get_user_by_id(&self, user_id: &str) -> Result<User> {
        // 传进来的可能是 actor ref（Stage 3 起的新令牌）或 user id（旧令牌），
        // 两种前缀都要能剥掉。
        let key = crate::utils::record_id::normalize_actor_id(&normalize_user_id(user_id));
        let users: Vec<User> = self
            .db
            .query_take0_vec(
                "oidc_get_user_by_actor_ref",
                "SELECT * FROM user \
                 WHERE subject_id = type::record('actor_identity', $user_key) \
                    OR id = type::record('user', $user_key) \
                 LIMIT 1",
                serde_json::json!({ "user_key": key }),
            )
            .await?;

        users
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("User not found"))
    }

    /// 取用户，并要求账号当前可用。
    ///
    /// OIDC 这一侧此前**一个关口都没有校验账号状态**：停用一个账号之后，
    /// userinfo 照常返回身份、刷新令牌照常换到新的 access + ID Token、
    /// 浏览器 cookie 照常换到新授权码。而刷新令牌每次刷新都会轮换出新的一张，
    /// 所以那不是"一小时的窗口"，是只要接入方持续刷新、停用就永远不会到达。
    ///
    /// 判定共用 [`User::ensure_usable`]，与登录闸门、令牌闸门是同一份。
    async fn load_active_user(&self, user_id: &str) -> Result<User> {
        let user = self.get_user_by_id(user_id).await?;
        user.ensure_usable()
            .map_err(|e| anyhow!("Account is not active: {e}"))?;
        Ok(user)
    }

    async fn save_authorization_code(&self, code: &OidcAuthorizationCode) -> Result<()> {
        let query = r#"
            CREATE oidc_authorization_code CONTENT {
                code_hash: $code_hash,
                client_id: $client_id,
                user_id: (SELECT VALUE subject_id FROM type::record('user', $user_key))[0],
                redirect_uri: $redirect_uri,
                scope: $scope,
                -- `Option::None` 经 JSON 绑定会变成 NULL，而 `option<string>` 列
                -- 只接受 NONE（报 "Expected `none | string` but found `NULL`"）。
                -- `?? NONE` 把两者归一。
                state: $state ?? NONE,
                nonce: $nonce ?? NONE,
                code_challenge: $code_challenge ?? NONE,
                code_challenge_method: $code_challenge_method ?? NONE,
                auth_session_ref: $auth_session_ref ?? NONE,
                used: $used,
                expires_at: $expires_at,
                created_at: $created_at
            }
        "#;

        self.db
            .raw_query(
                "oidc_save_authorization_code",
                query,
                serde_json::json!({
                    "code_hash": code.code_hash,
                    "client_id": code.client_id,
                    "user_key": normalize_user_id(&code.user_id),
                    "redirect_uri": code.redirect_uri,
                    "scope": code.scope,
                    "state": code.state,
                    "nonce": code.nonce,
                    "code_challenge": code.code_challenge,
                    "code_challenge_method": code.code_challenge_method,
                    "auth_session_ref": code.auth_session_ref,
                    "used": code.used,
                    "expires_at": code.expires_at,
                    "created_at": code.created_at,
                }),
            )
            .await?;

        Ok(())
    }

    /// 按**指纹**取授权码。入参仍是来件原文，指纹在这里算。
    async fn get_authorization_code(&self, code: &str) -> Result<OidcAuthorizationCode> {
        let query = r#"
            SELECT
                type::string(id) AS id,
                code_hash,
                client_id,
                type::string(user_id) AS user_id,
                redirect_uri,
                scope,
                state,
                nonce,
                code_challenge,
                code_challenge_method,
                auth_session_ref,
                used,
                expires_at,
                created_at
            FROM oidc_authorization_code
            WHERE code_hash = $code_hash
            LIMIT 1
        "#;

        let mut result = self
            .db
            .raw_query(
                "oidc_get_authorization_code",
                query,
                serde_json::json!({ "code_hash": crate::utils::crypto::hash_bearer(code) }),
            )
            .await?;

        let codes: Vec<serde_json::Value> = result.take(0)?;
        codes
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<OidcAuthorizationCode>, _>>()?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Authorization code not found"))
    }

    async fn update_authorization_code(&self, code: &OidcAuthorizationCode) -> Result<()> {
        let query =
            "UPDATE oidc_authorization_code SET used = true WHERE code_hash = $code_hash AND used = false RETURN VALUE code_hash";
        let mut result = self
            .db
            .raw_query(
                "oidc_update_authorization_code",
                query,
                serde_json::json!({ "code_hash": code.code_hash }),
            )
            .await?;

        let updated_codes: Vec<String> = result.take(0)?;
        if updated_codes.len() == 1 {
            Ok(())
        } else {
            Err(anyhow!("Authorization code already used"))
        }
    }

    async fn save_access_token(&self, token: &OidcAccessToken) -> Result<()> {
        let query = r#"
            CREATE oidc_access_token CONTENT {
                token_hash: $access_token_hash,
                token_type: $token_type,
                client_id: $client_id,
                user_id: type::record('actor_identity', $user_key),
                scope: $scope,
                expires_at: $expires_at,
                created_at: $created_at
            }
        "#;

        self.db
            .raw_query(
                "oidc_save_access_token",
                query,
                serde_json::json!({
                    "access_token_hash": token.token_hash,
                    "token_type": token.token_type,
                    "client_id": token.client_id,
                    "user_key": crate::utils::record_id::normalize_actor_id(&token.user_id),
                    "scope": token.scope,
                    "expires_at": token.expires_at,
                    "created_at": token.created_at,
                }),
            )
            .await?;

        Ok(())
    }

    async fn get_access_token(&self, token: &str) -> Result<OidcAccessToken> {
        let query = r#"
            SELECT
                type::string(id) AS id,
                token_hash,
                token_type,
                client_id,
                type::string(user_id) AS user_id,
                scope,
                expires_at,
                created_at
            FROM oidc_access_token
            WHERE token_hash = $access_token_hash
            LIMIT 1
        "#;

        let mut result = self
            .db
            .raw_query(
                "oidc_get_access_token",
                query,
                serde_json::json!({ "access_token_hash": crate::utils::crypto::hash_bearer(token) }),
            )
            .await?;

        let tokens: Vec<serde_json::Value> = result.take(0)?;
        tokens
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<OidcAccessToken>, _>>()?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Access token not found"))
    }

    /// 按指纹吊销访问令牌。
    ///
    /// 收指纹而不是原文：唯一调用方是刷新流程，它手上只有刷新令牌记录里
    /// 存的那份指纹，原文早就交给客户端了。
    async fn revoke_access_token_by_hash(&self, token_hash: &str) -> Result<()> {
        self.db
            .raw_query(
                "oidc_revoke_access_token",
                "DELETE oidc_access_token WHERE token_hash = $access_token_hash",
                serde_json::json!({ "access_token_hash": token_hash }),
            )
            .await?;

        Ok(())
    }

    async fn save_refresh_token(&self, token: &OidcRefreshToken) -> Result<()> {
        let query = r#"
            CREATE oidc_refresh_token CONTENT {
                token_hash: $refresh_token_hash,
                client_id: $client_id,
                user_id: type::record('actor_identity', $user_key),
                access_token_hash: $access_token_hash,
                scope: $scope,
                auth_session_ref: $auth_session_ref ?? NONE,
                used: $used,
                expires_at: $expires_at,
                created_at: $created_at
            }
        "#;

        self.db
            .raw_query(
                "oidc_save_refresh_token",
                query,
                serde_json::json!({
                    "refresh_token_hash": token.token_hash,
                    "client_id": token.client_id,
                    "user_key": crate::utils::record_id::normalize_actor_id(&token.user_id),
                    "access_token_hash": token.access_token_hash,
                    "auth_session_ref": token.auth_session_ref,
                    "scope": token.scope,
                    "used": token.used,
                    "expires_at": token.expires_at,
                    "created_at": token.created_at,
                }),
            )
            .await?;

        Ok(())
    }

    async fn get_refresh_token(&self, token: &str) -> Result<OidcRefreshToken> {
        let query = r#"
            SELECT
                type::string(id) AS id,
                token_hash,
                client_id,
                type::string(user_id) AS user_id,
                access_token_hash,
                scope,
                auth_session_ref,
                used,
                expires_at,
                created_at
            FROM oidc_refresh_token
            WHERE token_hash = $refresh_token_hash
            LIMIT 1
        "#;

        let mut result = self
            .db
            .raw_query(
                "oidc_get_refresh_token",
                query,
                serde_json::json!({ "refresh_token_hash": crate::utils::crypto::hash_bearer(token) }),
            )
            .await?;

        let tokens: Vec<serde_json::Value> = result.take(0)?;
        tokens
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<OidcRefreshToken>, _>>()?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Refresh token not found"))
    }

    /// 原子地把刷新令牌标记为已使用；返回 false 表示已经被别的请求消费掉了。
    /// 按指纹原子地把刷新令牌标记为已用。收指纹，理由同 `revoke_access_token_by_hash`。
    async fn consume_refresh_token_by_hash(&self, token_hash: &str) -> Result<bool> {
        let query = "UPDATE oidc_refresh_token SET used = true WHERE token_hash = $refresh_token_hash AND used = false RETURN VALUE token_hash";

        let mut result = self
            .db
            .raw_query(
                "oidc_consume_refresh_token",
                query,
                serde_json::json!({ "refresh_token_hash": token_hash }),
            )
            .await?;

        let updated: Vec<String> = result.take(0)?;
        Ok(updated.len() == 1)
    }

    /// 吊销某用户在某客户端上的全部访问 / 刷新令牌（单点登出、令牌泄露时使用）。
    pub async fn revoke_client_tokens_for_user(
        &self,
        client_id: &str,
        user_id: &str,
    ) -> Result<()> {
        let bindings = serde_json::json!({
            "client_id": client_id,
            // 调用方可能传 user id（路由层从 session 拿的），也可能传 actor ref
            // （复用检测从存储的令牌读回的）。两种前缀都剥掉成裸 key，
            // 由 SQL 那边同时按两种解释匹配 —— 在 Rust 侧猜是哪一种不可靠，
            // 猜错的后果是令牌族没被吊销，而那是个安全缺陷。
            "user_key": crate::utils::record_id::normalize_actor_id(&normalize_user_id(user_id)),
        });

        self.db
            .raw_query(
                "oidc_revoke_access_tokens_for_client",
                "DELETE oidc_access_token WHERE client_id = $client_id AND user_id IN [type::record('actor_identity', $user_key), (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]]",
                bindings.clone(),
            )
            .await?;
        self.db
            .raw_query(
                "oidc_revoke_refresh_tokens_for_client",
                "DELETE oidc_refresh_token WHERE client_id = $client_id AND user_id IN [type::record('actor_identity', $user_key), (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]]",
                bindings,
            )
            .await?;

        Ok(())
    }

    /// 吊销某用户在**所有**客户端上的令牌（全局登出）。
    pub async fn revoke_all_tokens_for_user(&self, user_id: &str) -> Result<()> {
        let bindings = serde_json::json!({
            "user_key": crate::utils::record_id::normalize_actor_id(&normalize_user_id(user_id)),
        });

        self.db
            .raw_query(
                "oidc_revoke_all_access_tokens",
                "DELETE oidc_access_token WHERE user_id IN [type::record('actor_identity', $user_key), (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]]",
                bindings.clone(),
            )
            .await?;
        self.db
            .raw_query(
                "oidc_revoke_all_refresh_tokens",
                "DELETE oidc_refresh_token WHERE user_id IN [type::record('actor_identity', $user_key), (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]]",
                bindings,
            )
            .await?;

        Ok(())
    }

    /// 清理过期的授权码与令牌，由后台定时任务调用。
    pub async fn cleanup_expired_artifacts(&self) -> Result<()> {
        let now = serde_json::json!({ "now": Utc::now().timestamp() });

        for (op, sql) in [
            (
                "oidc_cleanup_codes",
                "DELETE oidc_authorization_code WHERE expires_at < $now",
            ),
            (
                "oidc_cleanup_access_tokens",
                "DELETE oidc_access_token WHERE expires_at < $now",
            ),
            (
                "oidc_cleanup_refresh_tokens",
                "DELETE oidc_refresh_token WHERE expires_at < $now",
            ),
        ] {
            self.db.raw_query(op, sql, now.clone()).await?;
        }

        Ok(())
    }
}

/// 生成 client_secret 的存储哈希（Argon2id）。
pub fn hash_client_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| anyhow!("Failed to hash client secret: {e}"))
}

/// 校验 client_secret。
///
/// 兼容历史上用裸 SHA-256 存储的记录（走常量时间比较），新写入一律是 Argon2。
pub fn verify_client_secret_hash(stored_hash: &str, provided_secret: &str) -> bool {
    if stored_hash.starts_with("$argon2") {
        return PasswordHash::new(stored_hash)
            .map(|parsed| {
                Argon2::default()
                    .verify_password(provided_secret.as_bytes(), &parsed)
                    .is_ok()
            })
            .unwrap_or(false);
    }

    let legacy = format!("{:x}", Sha256::digest(provided_secret.as_bytes()));
    constant_time_eq(legacy.as_bytes(), stored_hash.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn generate_random_string(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        constant_time_eq, hash_client_secret, verify_client_secret_hash, ClaimDisclosure,
        OidcService,
    };
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};

    #[test]
    fn verifies_s256_pkce_challenge() {
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        let challenge =
            general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let result = OidcService::verify_pkce_value(&challenge, Some("S256"), verifier);
        assert!(result.expect("pkce verification should succeed"));
    }

    #[test]
    fn rejects_wrong_s256_pkce_challenge() {
        let result = OidcService::verify_pkce_value(
            "wrong",
            Some("S256"),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~",
        );
        assert!(!result.expect("pkce verification should return false"));
    }

    #[test]
    fn rejects_plain_pkce_challenge() {
        // plain 的 challenge 就是 verifier 本身，等于没有 PKCE；发现文档也只宣告 S256。
        let verifier = "plain-verifier-abcdefghijklmnopqrstuvwxyz012345";
        let err = OidcService::verify_pkce_value(verifier, Some("plain"), verifier)
            .expect_err("plain must be rejected");
        assert!(err
            .to_string()
            .contains("Unsupported code challenge method"));
    }

    #[test]
    fn rejects_pkce_without_challenge_method() {
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        let err = OidcService::verify_pkce_value(verifier, None, verifier)
            .expect_err("missing method must be rejected");
        assert!(err.to_string().contains("Missing code_challenge_method"));
    }

    #[test]
    fn rejects_pkce_verifier_shorter_than_rfc_minimum() {
        let result =
            OidcService::verify_pkce_value("short-verifier", Some("S256"), "short-verifier");
        assert!(result
            .expect_err("short verifier should be rejected")
            .to_string()
            .contains("Invalid code verifier"));
    }

    #[test]
    fn rejects_pkce_verifier_with_invalid_charset() {
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._!";
        let result = OidcService::verify_pkce_value(verifier, Some("S256"), verifier);
        assert!(result
            .expect_err("invalid verifier charset should be rejected")
            .to_string()
            .contains("Invalid code verifier"));
    }

    #[test]
    fn argon2_client_secret_round_trips() {
        let hash = hash_client_secret("super-secret-value").expect("hash");
        assert!(hash.starts_with("$argon2"));
        assert!(verify_client_secret_hash(&hash, "super-secret-value"));
        assert!(!verify_client_secret_hash(&hash, "wrong-value"));
    }

    #[test]
    fn legacy_sha256_client_secret_still_verifies() {
        let legacy = format!("{:x}", Sha256::digest(b"legacy-secret"));
        assert!(verify_client_secret_hash(&legacy, "legacy-secret"));
        assert!(!verify_client_secret_hash(&legacy, "other-secret"));
    }

    #[test]
    fn constant_time_eq_matches_semantics_of_plain_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn openid_alone_discloses_no_identity_attributes() {
        // 这是回归测试：ID Token 曾经无条件放 email 与 preferred_username，
        // 而 UserInfo 是裁剪的。只申请 openid 的客户端不该拿到任何身份属性。
        let d = ClaimDisclosure::from_scope("openid");
        assert!(!d.email);
        assert!(!d.profile);
    }

    #[test]
    fn each_scope_opens_only_its_own_claims() {
        let d = ClaimDisclosure::from_scope("openid email");
        assert!(d.email);
        assert!(!d.profile, "email scope 不得顺带放行档案属性");

        let d = ClaimDisclosure::from_scope("openid profile");
        assert!(!d.email, "profile scope 不得顺带放行邮箱");
        assert!(d.profile);

        let d = ClaimDisclosure::from_scope("openid email profile");
        assert!(d.email);
        assert!(d.profile);
    }

    #[test]
    fn scope_matching_is_exact_and_whitespace_tolerant() {
        // 子串匹配会让 `emailish` 或 `not-profile` 意外放行。
        assert!(!ClaimDisclosure::from_scope("openid emailish").email);
        assert!(!ClaimDisclosure::from_scope("openid xprofile").profile);
        // scope 是空格分隔的列表，多余空白不应改变判定。
        let d = ClaimDisclosure::from_scope("  openid   email  ");
        assert!(d.email);
        assert!(!d.profile);
        // 空 scope 什么都不放行。
        let d = ClaimDisclosure::from_scope("");
        assert!(!d.email);
        assert!(!d.profile);
    }
}
