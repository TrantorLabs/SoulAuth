use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OidcAuthorizationCode {
    pub id: Option<String>,
    /// 授权码的 SHA-256 指纹，不是授权码本身。
    pub code_hash: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// 签发这张授权码时用户所处的 SoulAuth 认证会话（`session` 表主键）。
    ///
    /// 用来把 `sid` 一路带到 ID Token（P0-DECISION-10 DEC-10-06）。
    /// 存量行没有该列，故为 `Option`；但兑换时若为空会 fail-closed。
    #[serde(default)]
    pub auth_session_ref: Option<String>,
    pub used: bool,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OidcAccessToken {
    pub id: Option<String>,
    /// 访问令牌的 SHA-256 指纹，不是令牌本身。
    pub token_hash: String,
    pub token_type: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OidcRefreshToken {
    pub id: Option<String>,
    /// 刷新令牌的 SHA-256 指纹，不是令牌本身。
    pub token_hash: String,
    pub client_id: String,
    pub user_id: String,
    /// 关联访问令牌的指纹（刷新时据此吊销旧访问令牌）。
    pub access_token_hash: String,
    pub scope: String,
    /// 同 `OidcAuthorizationCode::auth_session_ref`。
    ///
    /// 刷新同样会签发 ID Token，所以 `sid` 必须能从刷新令牌继续传下去，
    /// 否则刷新出来的 ID Token 就没有 `sid`。
    #[serde(default)]
    pub auth_session_ref: Option<String>,
    pub used: bool,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: String,
}

impl TokenRequest {
    /// 客户端标识。
    ///
    /// 令牌端点在进入服务层之前已经保证它有值：要么表单里带了，要么从
    /// `Authorization: Basic` 补齐，两者都没有时端点直接返回 `invalid_request`。
    /// 这里退化成空串而不是 panic —— 空串查不到任何客户端，最终以
    /// `invalid_client` 收场，与「身份不对」是同一个答复。
    pub fn client_id(&self) -> &str {
        self.client_id.as_deref().unwrap_or_default()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    /// 可选：按 RFC 6749 §4.1.3，客户端**已经向授权服务器认证过**时不必再带。
    ///
    /// 曾经是 `String`。于是用 `client_secret_basic` 的客户端（凭证在
    /// Authorization 头里）只要不在表单里再抄一份 client_id，请求就在反序列化阶段
    /// 挂掉，返回 422 加一句 axum 的内部报错 —— 既不是本站的错误信封，也不是
    /// RFC 6749 §5.2 的 OAuth 错误体，接入方拿不到任何可分支的码。
    /// 而 `client_secret_basic` 恰好是多数 OIDC 客户端库的默认。
    #[serde(default)]
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    /// 认证会话引用（OIDC `sid`，见 OpenID Connect Front-Channel Logout）。
    ///
    /// P0-DECISION-10 DEC-10-06 定为**必填**：OS 的每条审计链路都要求
    /// `auth_session_ref`，缺了就没有来源。因此这里不是 `Option` ——
    /// 取不到会话引用时宁可拒签，不签一张残缺的 ID Token。
    ///
    /// 边界：`sid` 只表示认证会话，OS 不得把它当成 Kernel Session、
    /// Second Wing Session、Browser Runtime Session、ConnectorSession
    /// 或 AccessTicket。
    pub sid: String,
    pub nonce: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub updated_at: Option<i64>,
}
