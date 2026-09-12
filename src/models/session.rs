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

    /// 建立这个会话时**实际验证了哪一类凭证**。
    ///
    /// 没有它，系统回答不了几个本该能回答的问题：这个会话是口令建立的还是
    /// 过了 MFA？吊销某一枚凭证应该影响哪些会话？当前认证有多新？
    #[serde(default)]
    pub credential_kind: Option<String>,

    /// 凭证的可读标识（AI 主体是密钥标签，外部身份是 provider 名）。
    ///
    /// 有了它，「吊销这把钥匙」才能精确地只打掉由它建立的会话，而不是
    /// 「这个主体的全部会话」。
    #[serde(default)]
    pub credential_label: Option<String>,

    /// 这次认证发生的时刻。
    ///
    /// OIDC 的 `auth_time` 必须取自**建立该会话的那次认证**。以前它取的是
    /// `user.last_login_at` —— 那个字段会被**后来的**任何一次登录更新，于是一个
    /// 旧会话签出的 ID Token 可能携带一个比它自己更晚的认证时间。那是明确的
    /// 认证事实错置：依赖 `auth_time` 做重认证判断的 RP 会被骗过去。
    #[serde(default)]
    pub authenticated_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub user_agent: String,
    pub ip_address: String,
    pub is_current: bool,
}
