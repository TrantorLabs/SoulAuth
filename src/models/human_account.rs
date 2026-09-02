//! Human Account —— Human-specific account extension。
//!
//! **它不是身份根。**
//!
//! ```text
//! ActorIdentity
//!       │
//! Human-specific extension
//!       │
//! HumanAccount
//! ```
//!
//! Human 修改 Email，不意味着 ActorIdentity 发生变化；Username 或其它账户
//! 属性变化，也不产生新的 Stable Subject。
//!
//! AIActor **不需要**这个对象。它可以拥有独立的 ActorIdentity 而完全不必
//! 伪造 Email、Username 或其它人类账户结构 —— 这是 Actor-native 的第一道硬门。
//!
//! # Password 为什么不在这里
//!
//! `Account metadata ≠ Authentication secret`（GA-01 §4）。Password、
//! Recovery Secret、Verification Token 属于 Credential 或 Security Domain，
//! 不因为服务于 Human Account 就被塞回账户本体。
//!
//! 当前它们仍暂留在 V1 `user` 表上，Stage 2 收口到 Credential Domain。

use chrono::Utc;
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb_types::SurrealValue;

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct HumanAccount {
    pub id: Option<Thing>,

    /// 所属身份根。一个 Human ActorIdentity 至多一个账户（唯一索引保证）。
    pub actor_identity_id: Thing,

    pub email: String,
    pub username: String,

    /// 用于唯一性判定的规范化用户名。
    ///
    /// 单独存一列而不是查询时现算：唯一索引必须建在一个确定的值上，
    /// 否则 `Alice` 与 `alice` 会被当成两个账户。
    pub username_normalized: String,

    /// 邮箱是否已验证。
    ///
    /// 这是**账户属性**，不是身份属性：邮箱没验证不代表这个 Actor 不存在。
    pub email_verified: bool,

    pub created_at: i64,
    pub updated_at: i64,
}

impl HumanAccount {
    pub fn new(
        actor_identity_id: Thing,
        email: impl Into<String>,
        username: impl Into<String>,
        username_normalized: impl Into<String>,
    ) -> Self {
        let now = Utc::now().timestamp();
        Self {
            id: None,
            actor_identity_id,
            email: email.into(),
            username: username.into(),
            username_normalized: username_normalized.into(),
            email_verified: false,
            created_at: now,
            updated_at: now,
        }
    }
}
