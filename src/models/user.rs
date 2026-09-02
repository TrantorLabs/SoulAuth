use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

use crate::error::AuthError;

fn default_membership_level() -> String {
    "FREE".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct User {
    pub id: Option<Thing>,
    pub subject_id: Option<Thing>,
    pub email: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub username_normalized: String,
    #[surreal(rename = "password")]
    #[serde(rename = "password")]
    pub password_hash: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    #[surreal(rename = "verified")]
    #[serde(rename = "verified")]
    pub is_email_verified: bool,
    /// 邮箱验证令牌的 SHA-256 指纹。
    pub verification_token_hash: Option<String>,
    /// 验证令牌的过期时间（Unix 秒）。以前的验证令牌永不过期。
    #[serde(default)]
    pub verification_token_expires_at: Option<i64>,
    pub account_status: String,
    #[serde(default = "default_membership_level")]
    pub membership_level: String,
    /// 会员到期时间。
    ///
    /// **SoulAuth 只持有与透传，不解释它。** 会员状态归 Product Entitlement /
    /// Billing（P0-DECISION-09 §4.7 已把 `membership_level` 归到那一侧，
    /// 不归 P3 Canonical Permission），所以"过期了没有"不由本服务判断 ——
    /// 那是消费方的事。
    ///
    /// 但**形状**必须由持有方保证。这里以前是 `Option<String>` 且写入不做校验，
    /// `"2026-13-45"` / `"下个月"` / `"asdf"` 都能照单全收再原样发出去，
    /// 等于把一个本该在写入时挡下的错误顺延给每一个消费方去防御性解析。
    /// 换成时间类型之后，非法输入在反序列化阶段就被拒。
    #[serde(default)]
    pub membership_expiry: Option<DateTime<Utc>>,
    pub last_login_at: Option<i64>,
    pub last_login_ip: Option<String>,
}

/// 账号状态。
///
/// 这里**刻意没有** `PendingDeletion`。它曾经存在，但全代码库对它的处理只有
/// "判定为不可用"一条，与 `Deleted` 完全同义：没有宽限期计时、没有到期推进、
/// 没有级联清除、也没有撤销入口。而它是对外暴露的（管理员可设置、可按它筛选、
/// 会出现在响应里），`PendingDeletion` 又恰好是删除权实现里的标准状态名 ——
/// 一个认证服务对外宣告这个状态却不删除任何数据，会让接入方以为删除义务
/// 已经履行。承诺一件不做的事比没有这个能力更糟，所以删掉。
///
/// 将来真要做删除流水线（宽限期 + 到期级联清除 + 撤销 + 审计留痕），
/// 再把它作为一个有内容的状态加回来。
///
/// 存量数据：库里遗留的 `"PendingDeletion"` 字符串会被 [`AccountStatus::parse`]
/// 归入 `Inactive`（不可用），方向是 fail-closed，不会误放行。
#[derive(Debug, Clone, PartialEq, Eq, SurrealValue, Default)]
pub enum AccountStatus {
    #[default]
    Active,
    Inactive,
    Suspended,
    Deleted,
}

impl AccountStatus {
    /// 由库中存的字符串还原状态。
    ///
    /// **未知值一律落到 `Inactive`（不可用）**，而不是 `Active`。以前三处调用点
    /// 各写各的 match，且都以「没被列为坏的就算好的」收尾；只要 `AccountStatus`
    /// 新增一个变体而漏改其中一处，那处就静默放行 —— 没有任何编译错误或运行时
    /// 报错会提示这件事。放行的集合必须是闭的，且只能有一份。
    pub fn parse(raw: &str) -> Self {
        match raw {
            "Active" => AccountStatus::Active,
            "Inactive" => AccountStatus::Inactive,
            "Suspended" => AccountStatus::Suspended,
            "Deleted" => AccountStatus::Deleted,
            _ => AccountStatus::Inactive,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AccountStatus::Active => "Active",
            AccountStatus::Inactive => "Inactive",
            AccountStatus::Suspended => "Suspended",
            AccountStatus::Deleted => "Deleted",
        }
    }
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for AccountStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AccountStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "Active" => Ok(AccountStatus::Active),
            "Inactive" => Ok(AccountStatus::Inactive),
            "Suspended" => Ok(AccountStatus::Suspended),
            "Deleted" => Ok(AccountStatus::Deleted),
            other => Err(serde::de::Error::custom(format!(
                "invalid account status: {other}"
            ))),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(rename = "verified")]
    pub is_email_verified: bool,
    pub membership_level: String,
    pub membership_expiry: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub has_password: bool,
    pub account_status: AccountStatus,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializePasswordRequest {
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAccountStatusRequest {
    pub status: AccountStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountStatusResponse {
    pub user_id: String,
    pub status: AccountStatus,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserListRequest {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub status: Option<AccountStatus>,
    pub search: Option<String>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserListResponse {
    pub users: Vec<UserResponse>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
    pub total_pages: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMembershipRequest {
    pub membership_level: String,
    /// RFC3339 时间点。格式非法时 serde 直接拒收（400），
    /// 不再像以前那样把任意字符串存进去。
    pub membership_expiry: Option<DateTime<Utc>>,
}

impl User {
    /// 账号是否处于可用状态。鉴权闸门与登录闸门都走这里，不各写各的。
    pub fn account_status_parsed(&self) -> AccountStatus {
        AccountStatus::parse(&self.account_status)
    }

    /// 账号当前是否允许执行任何需要"这个人还在"的操作。
    ///
    /// **这是全库唯一的一处状态闸门判定**，所有入口共用：
    /// 令牌校验（`utils::jwt`）、登录（`services::auth`）、密码重置、
    /// 以及 OIDC 的三个关口（userinfo / 签发令牌 / authorize 复用会话）。
    ///
    /// 收成一处的原因是它此前不是：判定逐处抄写，于是"哪些路径要看状态"
    /// 变成了每加一条路径就要重新想一次的事。实际结果是原生 API 那侧看了、
    /// OIDC 那侧一处都没看 —— 停用一个账号，它在接入方那里照旧能用刷新令牌
    /// 无限续期。判定只有一份，新路径就只会忘记调用（编译期能靠 review 抓到），
    /// 而不会出现"抄了但抄漏一个分支"这种不报错的偏差。
    ///
    /// 放行集合是闭的：只有 `Active` 通过，其余一律拒。
    pub fn ensure_usable(&self) -> Result<(), AuthError> {
        match self.account_status_parsed() {
            AccountStatus::Active => Ok(()),
            AccountStatus::Suspended => Err(AuthError::AccountSuspended),
            AccountStatus::Inactive => Err(AuthError::AccountInactive),
            AccountStatus::Deleted => Err(AuthError::AccountDeleted),
        }
    }
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        let account_status = AccountStatus::parse(&user.account_status);

        let created_at =
            DateTime::<Utc>::from_timestamp(user.created_at, 0).unwrap_or_else(Utc::now);
        let last_login_at = user
            .last_login_at
            .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0));

        Self {
            // `id` 是 Option（新建时还没有），这里用 unwrap 会把一条缺 id 的记录
            // 变成整个 handler 线程 panic。降级成空串，交由上层按“找不到用户”处理。
            id: user
                .id
                .as_ref()
                .map(crate::utils::record_id::record_id_key_to_string)
                .unwrap_or_default(),
            email: user.email,
            username: user.username,
            is_admin: false,
            is_email_verified: user.is_email_verified,
            membership_level: user.membership_level,
            membership_expiry: user.membership_expiry,
            created_at,
            has_password: user.password_hash.is_some(),
            account_status,
            last_login_at,
        }
    }
}

#[cfg(test)]
mod account_status_tests {
    use super::AccountStatus;

    #[test]
    fn an_unknown_status_is_not_usable() {
        // 这是本文件最重要的一条：未知值必须落到不可用。
        // 反过来（未知 → Active）意味着任何一次拼写错误、数据迁移遗漏或
        // 新增变体漏改，都会变成一个不报错的放行漏洞。
        for raw in ["", "active", "ACTIVE", "Locked", "Banned", "已停用"] {
            assert_ne!(
                AccountStatus::parse(raw),
                AccountStatus::Active,
                "{raw:?} must not be treated as an active account"
            );
        }
    }

    #[test]
    fn only_active_maps_to_active() {
        assert_eq!(AccountStatus::parse("Active"), AccountStatus::Active);
        for raw in ["Inactive", "Suspended", "Deleted"] {
            assert_ne!(AccountStatus::parse(raw), AccountStatus::Active, "{raw}");
        }
    }

    #[test]
    fn ensure_usable_admits_only_active() {
        use crate::error::AuthError;
        use crate::models::user::User;

        fn user_with(status: &str) -> User {
            User {
                id: None,
                subject_id: None,
                email: "a@example.com".to_string(),
                username: "a".to_string(),
                username_normalized: "a".to_string(),
                password_hash: None,
                created_at: 0,
                updated_at: 0,
                is_email_verified: true,
                verification_token_hash: None,
                verification_token_expires_at: None,
                account_status: status.to_string(),
                membership_level: "FREE".to_string(),
                membership_expiry: None,
                last_login_at: None,
                last_login_ip: None,
            }
        }

        assert!(user_with("Active").ensure_usable().is_ok());
        assert!(matches!(
            user_with("Suspended").ensure_usable(),
            Err(AuthError::AccountSuspended)
        ));
        assert!(matches!(
            user_with("Inactive").ensure_usable(),
            Err(AuthError::AccountInactive)
        ));
        assert!(matches!(
            user_with("Deleted").ensure_usable(),
            Err(AuthError::AccountDeleted)
        ));
        // 已删除的变体：作为未知值落到 Inactive，仍然不可用（fail-closed）。
        assert!(matches!(
            user_with("PendingDeletion").ensure_usable(),
            Err(AuthError::AccountInactive)
        ));
        // 未知值同样不可用 —— 与 AccountStatus::parse 的 fail-closed 一致。
        assert!(user_with("whatever").ensure_usable().is_err());
    }

    #[test]
    fn parse_round_trips_every_variant() {
        // as_str 与 parse 必须互逆。任一侧漏掉一个变体，这条就会红 ——
        // 而漏掉的那个变体在 parse 里会落进未知分支，变成永久不可用。
        for v in [
            AccountStatus::Active,
            AccountStatus::Inactive,
            AccountStatus::Suspended,
            AccountStatus::Deleted,
        ] {
            assert_eq!(
                AccountStatus::parse(v.as_str()),
                v,
                "{} did not round-trip",
                v.as_str()
            );
        }
    }
}
