//! Identity Binding —— 连接身份，不创造身份。
//!
//! 它回答：
//!
//! > 另一个 Identity Source 中的身份，与当前 SoulAuth ActorIdentity 之间
//! > 存在什么**经过验证的**对应关系？
//!
//! ```text
//! External Identity
//!       │
//! IdentityBinding
//!       ↓
//! ActorIdentity
//! ```
//!
//! # 三条边界
//!
//! **Binding 不创造上游主体。** Google Identity 由 Google 定义，企业身份由
//! 企业 IdP 定义，Canonical AIActor 由 SoulseedAGI 定义。SoulAuth 可以验证
//! 并维护这条关系，但不因此获得重新定义上游主体的权力。
//!
//! **Binding ≠ Credential。** 外部 IdP 里 Human 使用的 Password 或 Passkey，
//! 不会因为建立了绑定就成为 SoulAuth 的 Actor Credential。SoulAuth 消费的是
//! 经过协议验证的外部**认证结果**，再通过 Binding 把 External Subject 解析
//! 到对应的 ActorIdentity —— 这是两个问题（GA-05 §4）。
//!
//! **不为 Canonical 绑定另造一套。** Social Login 与 Soulseed Canonical
//! Binding 共享这一个模型，区别只在 [`BindingType`]。GA-01 §18 明确禁止
//! 长出一个 `CanonicalActorBinding` 第二本体。

use chrono::Utc;
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb_types::SurrealValue;

/// 这条绑定连接的是哪一类外部身份。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BindingType {
    /// 外部 IdP：Google、GitHub、企业 IdP。
    #[default]
    Federated,
    /// SoulseedAGI 已经成立的 Canonical Actor。
    Canonical,
}

impl BindingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BindingType::Federated => "federated",
            BindingType::Canonical => "canonical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    #[default]
    Verified,
    Pending,
    Revoked,
}

impl VerificationState {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationState::Verified => "verified",
            VerificationState::Pending => "pending",
            VerificationState::Revoked => "revoked",
        }
    }

    /// 未知取值归入 `Pending`（fail-closed）：读不懂就不放行解析。
    pub fn parse(raw: &str) -> Self {
        match raw {
            "verified" => VerificationState::Verified,
            "revoked" => VerificationState::Revoked,
            _ => VerificationState::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct IdentityBinding {
    pub id: Option<Thing>,
    pub actor_identity_id: Thing,

    /// 外部身份来源的标识，例如 `google` / `github` / `soulseed`。
    pub provider: String,

    /// 该 provider 命名空间内的主体标识。
    ///
    /// **必须与 `provider` 联合唯一。** 只按它唯一是一个真实的跨 provider
    /// 账号接管：数字 id 为 `4001` 的 GitHub 账号会匹配上 sub 为字符串
    /// `"4001"` 的 Google 用户，并拿到那个用户的会话。
    pub provider_subject: String,

    /// 落库形态是字符串，与 schema 的 `TYPE string` 对齐。
    pub binding_type: String,
    pub verification_state: String,
    pub bound_at: i64,

    /// 绑定被撤销的时间。
    ///
    /// 撤销绑定 ≠ 撤销 ActorIdentity，也 ≠ 改写历史的联合认证事实
    /// （GA-06 §16）：过去那次通过该绑定完成的认证仍然发生过。
    pub revoked_at: Option<i64>,
}

impl IdentityBinding {
    pub fn new_federated(
        actor_identity_id: Thing,
        provider: impl Into<String>,
        provider_subject: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            actor_identity_id,
            provider: provider.into(),
            provider_subject: provider_subject.into(),
            binding_type: BindingType::Federated.as_str().to_string(),
            verification_state: VerificationState::Verified.as_str().to_string(),
            bound_at: Utc::now().timestamp(),
            revoked_at: None,
        }
    }

    /// 这条绑定当前是否可用于解析身份。
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
            && VerificationState::parse(&self.verification_state) == VerificationState::Verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use surrealdb::types::RecordId;

    fn actor() -> RecordId {
        RecordId::new("actor_identity", "a1")
    }

    #[test]
    fn revoked_binding_no_longer_resolves() {
        let mut b = IdentityBinding::new_federated(actor(), "google", "4001");
        assert!(b.is_active());
        b.revoked_at = Some(1);
        assert!(!b.is_active(), "已撤销的绑定不得再用于解析身份");
    }

    #[test]
    fn pending_binding_does_not_resolve_either() {
        let mut b = IdentityBinding::new_federated(actor(), "github", "4001");
        b.verification_state = VerificationState::Pending.as_str().to_string();
        assert!(!b.is_active(), "未验证的绑定不得用于解析身份");
    }

    #[test]
    fn wire_values_are_stable() {
        // 验 serde：落库走的是它。
        // 落库走的是 as_str()，不是 serde —— schema 上这两列是 TYPE string，
        // 而 SurrealValue derive 会把枚举编码成 `{ Variant: {} }`，与之冲突。
        // 集成测试第一次跑就撞上了这个（actor_kind 报
        // "Expected `string` but found `{ Human: {} }`"）。
        assert_eq!(BindingType::Canonical.as_str(), "canonical");
        assert_eq!(VerificationState::Revoked.as_str(), "revoked");
        assert_eq!(
            VerificationState::parse("verified"),
            VerificationState::Verified
        );
        // 未知取值 fail-closed。
        assert_eq!(
            VerificationState::parse("garbage"),
            VerificationState::Pending
        );
    }
}
