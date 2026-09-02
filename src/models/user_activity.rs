use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub enum ActivityCategory {
    Authentication,
    Profile,
    Security,
    Permissions,
    Data,
    System,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub enum ActivityStatus {
    Success,
    Failed,
    Warning,
    Info,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserActivityResponse {
    pub id: String,
    pub user_id: String,
    pub action: String,
    pub category: ActivityCategory,
    pub ip_address: String,
    pub user_agent: String,
    pub details: serde_json::Value,
    pub status: ActivityStatus,
    pub timestamp: DateTime<Utc>,
}

/// 从数据库读回来的一行活动记录。
///
/// `user_activity` 的写入统一走 serde（枚举存成纯字符串、record 链接投影成
/// 字符串），因此读取也必须走 serde。`UserActivity` 里的 `id` / `user_id` 是
/// `RecordId`，serde 无法从投影出来的字符串还原，所以单独定义这个行结构。
#[derive(Debug, Deserialize)]
pub struct UserActivityRow {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    pub action: String,
    pub category: ActivityCategory,
    pub ip_address: String,
    pub user_agent: String,
    #[serde(default)]
    pub details: serde_json::Value,
    pub status: ActivityStatus,
    pub timestamp: i64,
}

impl From<UserActivityRow> for UserActivityResponse {
    fn from(row: UserActivityRow) -> Self {
        // 投影出来的形如 `user_activity:⟨uuid⟩` / `user:`uuid``，这里只取键。
        let strip = |value: Option<String>| {
            value
                .map(|v| {
                    crate::utils::record_id::normalize_record_id_key(
                        v.split_once(':').map(|(_, key)| key).unwrap_or(&v),
                    )
                })
                .unwrap_or_default()
        };

        Self {
            id: strip(row.id),
            user_id: strip(row.user_id),
            action: row.action,
            category: row.category,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            details: row.details,
            status: row.status,
            timestamp: chrono::DateTime::<Utc>::from_timestamp(row.timestamp, 0)
                .unwrap_or_else(Utc::now),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityLogRequest {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub category: Option<ActivityCategory>,
    pub status: Option<ActivityStatus>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityLogResponse {
    pub activities: Vec<UserActivityResponse>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
    pub total_pages: u32,
}
