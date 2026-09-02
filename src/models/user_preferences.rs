use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

/// 注意：持久化字段的时间一律用 Unix 秒（i64），与 `schema.sql` 里的
/// `TYPE number` 对齐。以前这里用 `DateTime<Utc>`，写进 SCHEMAFULL 的
/// number 列会被数据库拒绝。对外的 Response 结构仍然返回 RFC3339 时间。
#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
/// 用户偏好。
///
/// **SoulAuth 只负责存取，不解释其中任何一项。** 这些是给前端用的展示与通知偏好，
/// 服务端没有、也不打算有对应的执行逻辑。写清楚是因为它此前不清楚：
/// 这张表原本还有 `two_factor_required` 与 `session_timeout` 两个字段，
/// 名字读起来像是服务端强制项，实际上全代码库没有任何地方读过它们 ——
/// 用户把"要求二次验证"打开，登录链路照旧只看 MFA 是否配置。
/// 一个永远不生效的安全开关比没有这个开关更糟，所以两个都已删除。
///
/// 通知类字段（`email_notifications` / `security_emails` / `marketing_emails` /
/// `newsletter` / `sms_notifications`）同理：本服务只发验证信与密码重置信两种
/// 事务邮件，两者都必须无条件送达，不受这些开关影响。它们留在这里是给接入方
/// 存偏好用的。
pub struct UserPreferences {
    pub id: Option<Thing>,
    pub user_id: Thing,
    pub theme: String,
    pub language: String,
    pub email_notifications: bool,
    pub sms_notifications: bool,
    pub marketing_emails: bool,
    pub security_emails: bool,
    pub newsletter: bool,
    pub timezone: String,
    pub date_format: String,
    pub time_format: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserPreferencesRequest {
    pub theme: Option<String>,
    pub language: Option<String>,
    pub email_notifications: Option<bool>,
    pub sms_notifications: Option<bool>,
    pub marketing_emails: Option<bool>,
    pub security_emails: Option<bool>,
    pub newsletter: Option<bool>,
    pub timezone: Option<String>,
    pub date_format: Option<String>,
    pub time_format: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserPreferencesRequest {
    pub theme: Option<String>,
    pub language: Option<String>,
    pub email_notifications: Option<bool>,
    pub sms_notifications: Option<bool>,
    pub marketing_emails: Option<bool>,
    pub security_emails: Option<bool>,
    pub newsletter: Option<bool>,
    pub timezone: Option<String>,
    pub date_format: Option<String>,
    pub time_format: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPreferencesResponse {
    pub id: String,
    pub user_id: String,
    pub theme: String,
    pub language: String,
    pub email_notifications: bool,
    pub sms_notifications: bool,
    pub marketing_emails: bool,
    pub security_emails: bool,
    pub newsletter: bool,
    pub timezone: String,
    pub date_format: String,
    pub time_format: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<UserPreferences> for UserPreferencesResponse {
    fn from(prefs: UserPreferences) -> Self {
        Self {
            id: prefs
                .id
                .map(|id| crate::utils::record_id::record_id_key_to_string(&id))
                .unwrap_or_default(),
            user_id: crate::utils::record_id::record_id_key_to_string(&prefs.user_id),
            theme: prefs.theme,
            language: prefs.language,
            email_notifications: prefs.email_notifications,
            sms_notifications: prefs.sms_notifications,
            marketing_emails: prefs.marketing_emails,
            security_emails: prefs.security_emails,
            newsletter: prefs.newsletter,
            timezone: prefs.timezone,
            date_format: prefs.date_format,
            time_format: prefs.time_format,
            created_at: chrono::DateTime::<Utc>::from_timestamp(prefs.created_at, 0)
                .unwrap_or_else(Utc::now),
            updated_at: chrono::DateTime::<Utc>::from_timestamp(prefs.updated_at, 0)
                .unwrap_or_else(Utc::now),
        }
    }
}

impl Default for UserPreferences {
    fn default() -> Self {
        let now = Utc::now().timestamp();
        Self {
            id: None,
            user_id: Thing::new("user", "default"),
            theme: "light".to_string(),
            language: "en".to_string(),
            email_notifications: true,
            sms_notifications: false,
            marketing_emails: false,
            security_emails: true,
            newsletter: false,
            timezone: "UTC".to_string(),
            date_format: "YYYY-MM-DD".to_string(),
            time_format: "24h".to_string(),
            created_at: now,
            updated_at: now,
        }
    }
}
