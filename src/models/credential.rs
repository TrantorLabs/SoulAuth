//! Credential —— Actor 用什么证明自己。
//!
//! # 为什么它必须是一个独立对象
//!
//! Human 的口令哈希曾经是 `user` 表的一列。那样写有三个后果，而且三个都不是
//! 「不够优雅」这一类的问题：
//!
//! * **凭证没有生命周期。** 改口令就是改账户行；「这把凭证已被吊销、但主体
//!   仍然存在」这个状态写不出来。
//! * **吊销单把凭证无法表达。** 唯一的手段是把列清空，而那与「从来没设过
//!   口令」在库里长得一模一样。
//! * **「是谁」与「用什么证明」被迫共享一行的生死。** 删账户行就删掉了凭证
//!   历史，而身份根本该比它的任何一把凭证活得更久。
//!
//! `a2`（ActorIdentity ≠ Credential）与 `b2`（身份不依赖任一凭证存续）断言的
//! 正是这两件事。
//!
//! # 每个 (actor, kind) 至多一行
//!
//! 轮换是**更新同一行**并记下 `rotated_at`，不是追加一行。理由是
//! 「当前有效的口令是哪一个」必须只有一个答案 —— 多行加上「取最新那行」的
//! 约定，是一条迟早有人读错的规则。需要历史的话那属于审计。
//!
//! # 不在这张表里的东西
//!
//! **AIActor 的 Ed25519 公钥**仍在 `ai_actor_credential`：它天然一对多（一个
//! 身份挂多把钥匙、各自独立吊销），与这里的唯一约束不同。合并两张表要先决定
//! 多钥匙语义怎样表达，那是独立的一次改动。
//!
//! **TOTP 密钥**仍在 `user_mfa`：它必须可逆（要用它算验证码），因此有自己的
//! 加密密钥与轮换代价。这张表的 `secret_hash` 只存不可逆的东西。

use chrono::Utc;
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb_types::SurrealValue;

/// 凭证的类别。
///
/// 每加一类都要先回答「它的轮换与吊销语义是什么」，而不是因为往 enum 里加一个
/// 变体很容易就加上。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// 口令（Argon2id 哈希）。
    #[default]
    Password,
}

impl CredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialKind::Password => "password",
        }
    }
}

/// 凭证当前能不能用来认证。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    #[default]
    Active,
    Revoked,
}

impl CredentialStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialStatus::Active => "active",
            CredentialStatus::Revoked => "revoked",
        }
    }

    /// 读不懂的取值按 `Revoked` 处理（fail-closed）。
    ///
    /// 反过来写会让一个拼错的状态值变成可以登录 —— 而拼错的那一行往往正是
    /// 某次手工干预留下的。
    pub fn parse(raw: &str) -> Self {
        match raw {
            "active" => CredentialStatus::Active,
            _ => CredentialStatus::Revoked,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct Credential {
    pub id: Option<Thing>,

    /// 凭证属于**身份根**，不属于 `user` 行。
    pub actor_identity_id: Thing,

    /// 落库形态是字符串，与 schema 的 `TYPE string` 对齐。
    pub kind: String,

    /// 不可逆形式的密材。
    pub secret_hash: Option<String>,
    pub status: String,
    pub created_at: i64,

    /// 最后一次轮换的时刻。`None` 表示从未轮换过。
    pub rotated_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

impl Credential {
    /// 新建一把口令凭证。
    pub fn new_password(actor_identity_id: Thing, secret_hash: String) -> Self {
        Self {
            id: None,
            actor_identity_id,
            kind: CredentialKind::Password.as_str().to_string(),
            secret_hash: Some(secret_hash),
            status: CredentialStatus::Active.as_str().to_string(),
            created_at: Utc::now().timestamp(),
            rotated_at: None,
            revoked_at: None,
        }
    }

    /// 这把凭证现在能用来认证吗。
    ///
    /// 同时看状态与密材：`active` 但 `secret_hash` 为空的行不是「可以空口令
    /// 登录」，是一条坏数据，必须当作不可用。
    pub fn is_usable(&self) -> bool {
        CredentialStatus::parse(&self.status) == CredentialStatus::Active
            && self.secret_hash.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thing() -> Thing {
        Thing::new("actor_identity", "abc")
    }

    #[test]
    fn a_fresh_password_credential_is_usable() {
        let c = Credential::new_password(thing(), "hash".to_string());
        assert!(c.is_usable());
        assert_eq!(c.kind, "password");
        assert!(c.rotated_at.is_none(), "新建的凭证不该声称轮换过");
        assert!(c.revoked_at.is_none());
    }

    #[test]
    fn an_unreadable_status_is_treated_as_revoked() {
        // fail-closed：拼错的状态值不得变成「可以登录」。
        for raw in ["", "ACTIVE", "activ", "disabled", "null"] {
            assert_eq!(
                CredentialStatus::parse(raw),
                CredentialStatus::Revoked,
                "`{raw}` 应当按吊销处理"
            );
        }
        assert_eq!(CredentialStatus::parse("active"), CredentialStatus::Active);
    }

    #[test]
    fn an_active_row_without_material_is_not_usable() {
        let mut c = Credential::new_password(thing(), "hash".to_string());
        c.secret_hash = None;
        assert!(
            !c.is_usable(),
            "密材为空的 active 行是坏数据，不是空口令可登录"
        );
    }
}
