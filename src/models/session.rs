use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct Session {
    pub id: Option<Thing>,
    pub user_id: Thing,
    /// 会话令牌的 SHA-256 指纹，**不是令牌本身**。
    ///
    /// 以前这里存的是完整签名 JWT，与客户端手里那枚逐字节相同 —— 一次数据库
    /// 读泄露就等于交出全站在线会话。指纹同样能满足吊销查询的全部需要。
    pub token_hash: String,
    pub expires_at: i64, // Unix timestamp
    pub created_at: i64, // Unix timestamp
    pub user_agent: String,
    pub ip_address: String,
}

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub user_agent: String,
    pub ip_address: String,
    pub is_current: bool,
}
