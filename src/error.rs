use axum::http::header;
use surrealdb::Error as SurrealDBError;
use thiserror::Error;

/// `enum_variant_names`：这里多数变体都以 `Error` 结尾，clippy 会提示改名。
/// 不改 —— `DatabaseError` / `TokenError` / `OAuthError` 这套命名在错误类型里
/// 是通行读法，去掉后缀（`Database` / `Token`）反而看不出是错误；
/// 而重命名要动两百多个调用点，换来的只是少一条 lint。
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Email not verified")]
    EmailNotVerified,

    #[error("Token error: {0}")]
    TokenError(String),

    #[error("User not found")]
    UserNotFound,

    #[error("Email already exists")]
    EmailExists,

    #[error("Username already exists")]
    UsernameExists,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("OAuth error: {0}")]
    OAuthError(String),

    #[error("Password already set")]
    PasswordAlreadySet,

    #[error("Invalid user ID")]
    InvalidUserId,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Insufficient permissions")]
    InsufficientPermissions,

    /// 缺少某个具名权限。
    ///
    /// 与 `Forbidden(String)` 分开是因为它能给出**机器可读的缺失项**：
    /// 调用方拿到 `required_permission` 就知道该去申请哪一条，不必解析文案。
    #[error("Missing permission: {0}")]
    MissingPermission(String),

    #[error("Account suspended")]
    AccountSuspended,

    #[error("Account inactive")]
    AccountInactive,

    #[error("Account deleted")]
    AccountDeleted,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Bad request: {0}")]
    BadRequest(String),
    /// 该功能未在本部署中启用（例如没有配置第三方登录的凭证）。
    ///
    /// 与 404 的区别：路由存在、语义明确，只是本实例没开。运维看到 501
    /// 就知道该去补配置，而 404 会让人以为版本不对或路由写错了。
    #[error("Not configured: {0}")]
    NotConfigured(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// 账号或 IP 被暴力破解防护锁定。
    ///
    /// 单列一个变体是因为它要带 `locked_until_seconds` —— 契约里写着
    /// 「仅 `account_locked` 携带」，客户端拿它显示倒计时。塞进 `message`
    /// 让人用正则去抠更糟。
    #[error("{message}")]
    AccountLocked {
        message: String,
        /// 与 `LockoutCheckResult::remaining_lockout_seconds` 同型。
        /// `None` 序列化成 `null`，与收口前的响应体逐字一致。
        locked_until_seconds: Option<i64>,
    },

    /// 依赖的组件暂时不可用，重试可能成功。
    ///
    /// 与 `DatabaseError` 的区别在语义而不在成因：这条告诉调用方「等一下再来」，
    /// 那条是「这次请求本身出了问题」。登录路径上的锁定检查失败走这里 ——
    /// 它既不能放行（等于在数据库抖动窗口内关掉暴力破解防护），也不该报 500。
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
}

impl From<reqwest::Error> for AuthError {
    fn from(err: reqwest::Error) -> Self {
        AuthError::OAuthError(err.to_string())
    }
}

impl From<serde_json::Error> for AuthError {
    fn from(err: serde_json::Error) -> Self {
        AuthError::ServerError(format!("JSON error: {}", err))
    }
}

impl From<header::InvalidHeaderValue> for AuthError {
    fn from(err: header::InvalidHeaderValue) -> Self {
        AuthError::ServerError(format!("Invalid header value: {}", err))
    }
}

impl From<SurrealDBError> for AuthError {
    fn from(err: SurrealDBError) -> Self {
        AuthError::DatabaseError(err.to_string())
    }
}

impl AuthError {
    /// 稳定的机器可读错误码。
    ///
    /// **这是契约的一部分**：调用方按 HTTP 状态码 + 这个字符串分支，
    /// 不按 `message` 的文案分支。文案可以随时改进措辞，码不会动。
    pub fn code(&self) -> &'static str {
        match self {
            // 内部故障对外一律收敛成同一个码：泄露 SQL / 连接串没有意义，
            // 而区分「数据库挂了」和「序列化失败」是运维的事，不是调用方的事。
            AuthError::DatabaseError(_) | AuthError::ServerError(_) => "internal_error",
            AuthError::InvalidCredentials => "invalid_credentials",
            AuthError::EmailNotVerified => "email_not_verified",
            AuthError::TokenError(_) | AuthError::InvalidToken => "invalid_token",
            AuthError::UserNotFound => "user_not_found",
            AuthError::EmailExists => "email_exists",
            AuthError::UsernameExists => "username_exists",
            AuthError::OAuthError(_) => "oauth_error",
            AuthError::PasswordAlreadySet => "password_already_set",
            AuthError::InvalidUserId => "invalid_user_id",
            AuthError::NotFound(_) => "not_found",
            AuthError::ValidationError(_) => "validation_error",
            AuthError::PermissionDenied => "permission_denied",
            AuthError::InsufficientPermissions => "insufficient_permissions",
            AuthError::MissingPermission(_) => "missing_permission",
            AuthError::AccountSuspended => "account_suspended",
            AuthError::AccountInactive => "account_inactive",
            AuthError::AccountDeleted => "account_deleted",
            AuthError::Forbidden(_) => "forbidden",
            AuthError::BadRequest(_) => "bad_request",
            AuthError::NotConfigured(_) => "not_configured",
            AuthError::Unauthorized(_) => "unauthorized",
            AuthError::AccountLocked { .. } => "account_locked",
            AuthError::ServiceUnavailable(_) => "service_unavailable",
        }
    }

    /// 对应的 HTTP 状态码。
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            AuthError::DatabaseError(_) | AuthError::ServerError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AuthError::InvalidCredentials
            | AuthError::TokenError(_)
            | AuthError::InvalidToken
            | AuthError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AuthError::EmailNotVerified
            | AuthError::PermissionDenied
            | AuthError::InsufficientPermissions
            | AuthError::MissingPermission(_)
            | AuthError::AccountSuspended
            | AuthError::AccountInactive
            | AuthError::AccountDeleted
            | AuthError::Forbidden(_) => StatusCode::FORBIDDEN,
            AuthError::UserNotFound | AuthError::NotFound(_) => StatusCode::NOT_FOUND,
            AuthError::EmailExists | AuthError::UsernameExists | AuthError::PasswordAlreadySet => {
                StatusCode::CONFLICT
            }
            AuthError::OAuthError(_)
            | AuthError::InvalidUserId
            | AuthError::ValidationError(_)
            | AuthError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AuthError::NotConfigured(_) => StatusCode::NOT_IMPLEMENTED,
            AuthError::AccountLocked { .. } => StatusCode::TOO_MANY_REQUESTS,
            AuthError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// 面向人的说明。可以改措辞，不进契约。
    fn message(&self) -> String {
        match self {
            // 内部故障不外泄细节。
            AuthError::DatabaseError(_) | AuthError::ServerError(_) => {
                "Internal server error".to_string()
            }
            AuthError::NotFound(msg)
            | AuthError::ValidationError(msg)
            | AuthError::Forbidden(msg)
            | AuthError::BadRequest(msg)
            | AuthError::NotConfigured(msg)
            | AuthError::Unauthorized(msg)
            | AuthError::ServiceUnavailable(msg) => msg.clone(),
            AuthError::AccountLocked { message, .. } => message.clone(),
            other => other.to_string(),
        }
    }

    /// 该错误附带的机器可读补充字段。
    ///
    /// 契约是「`error` 与 `message` 恒在，个别错误另带**已文档化**的补充字段」。
    /// 这里集中一处返回，免得各路由自己往响应体里塞临时字段 —— 那正是
    /// 收口之前的老毛病。
    fn details(&self) -> Vec<(&'static str, serde_json::Value)> {
        match self {
            AuthError::MissingPermission(p) => {
                vec![("required_permission", serde_json::Value::String(p.clone()))]
            }
            AuthError::AccountLocked {
                locked_until_seconds,
                ..
            } => vec![(
                "locked_until_seconds",
                serde_json::json!(locked_until_seconds),
            )],
            _ => Vec::new(),
        }
    }
}

impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        use axum::Json;

        if matches!(
            self,
            AuthError::DatabaseError(_) | AuthError::ServerError(_)
        ) {
            tracing::error!("AuthError response: {}", self);
        }

        let mut body = serde_json::Map::new();
        body.insert(
            "error".into(),
            serde_json::Value::String(self.code().into()),
        );
        body.insert("message".into(), serde_json::Value::String(self.message()));
        for (k, v) in self.details() {
            body.insert(k.into(), v);
        }

        (self.status(), Json(serde_json::Value::Object(body))).into_response()
    }
}

/// 命名空间用错时归为 `InvalidUserId`（400）。
///
/// 不新增错误变体：调用方送来一个属于别的命名空间的标识符，本质上就是
/// 「这个用户引用无效」。对外沿用既有文案，不透露那个前缀属于哪个命名空间 ——
/// GA-04 §43 允许为防枚举而保持 generic。
impl From<crate::utils::record_id::ForeignNamespace> for AuthError {
    fn from(e: crate::utils::record_id::ForeignNamespace) -> Self {
        tracing::debug!("namespace mismatch: {e}");
        AuthError::InvalidUserId
    }
}

pub type Result<T> = std::result::Result<T, AuthError>;

// 为了兼容，添加 AppError 别名
pub type AppError = AuthError;
