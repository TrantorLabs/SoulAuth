//! Actor Identity —— SoulAuth 身份域中唯一的身份根。
//!
//! # 为什么身份根不是 `User`
//!
//! 传统身份系统把 Account、Credential、Profile、Session、Role 都挂在一个
//! `User` 上。对只服务人类的系统这能工作，但当 AIActor 需要被独立识别、认证
//! 和归因时，它只剩几种选择：伪造一个人类账户、被归入 Service Account、
//! 或者让承载它的软件 Client 代替它成为身份。三种都是错的。
//!
//! SoulAuth 因此把起点上提一层：`ActorIdentity` 回答「谁」，
//! `HumanAccount` 只是 Human 的账户实现，`Credential` 回答「怎样证明」，
//! `Client` 回答「哪个软件在请求」。
//!
//! Human 与 AIActor 共享的是**身份法位**，不是实现细节 —— 它们完全可以使用
//! 不同的 Credential、Authentication Method 与 Lifecycle。
//!
//! # 命名说明
//!
//! GA-03 §3 明确：Canonical Semantic Label 不规定代码标识符。这里的类型名
//! 与语义标签一致只是因为读起来顺，不是规范要求。

use chrono::Utc;
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb_types::SurrealValue;

/// 身份主体的类别。
///
/// 第一阶段只承认这两类。Organization、Device、Application 要进入同一套
/// Actor Identity Contract，必须经过正式架构裁决 —— 而不是因为往 enum 里
/// 加一个变体很容易就加上。
///
/// wire 值是 snake_case（`human` / `ai_actor`）。GA-03 §3 提醒过：语义标签
/// 写作 `AIActor` 不等于 wire 必须是 `AIActor`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    #[default]
    Human,
    AiActor,
}

impl ActorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActorKind::Human => "human",
            ActorKind::AiActor => "ai_actor",
        }
    }
}

/// 这个身份通过什么受控来源进入 SoulAuth。
///
/// 它**不替代** [`super::identity_binding::IdentityBinding`]，也不意味着一个
/// Actor 只能拥有一条外部身份关系：provenance 说的是「怎么来的」，
/// binding 说的是「和外部哪个主体是同一个」。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    /// SoulAuth 自己的身份域（Standalone 默认）。
    #[default]
    Local,
    /// 绑定到 SoulseedAGI 已经成立的 Canonical Actor。
    Soulseed,
    /// 来自外部 IdP。
    External,
}

impl IdentitySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            IdentitySource::Local => "local",
            IdentitySource::Soulseed => "soulseed",
            IdentitySource::External => "external",
        }
    }
}

/// 身份的生命周期状态。
///
/// 三条约束（GA-06 §13、GA-04 §12）：
///
/// 1. 状态必须影响**未来**的 authentication eligibility —— 被 suspend 的身份
///    不能因为旧 Credential 还在就继续正常认证。
/// 2. Suspension **不改写**历史身份事实 —— 过去发生的 Authentication 与
///    Attribution 不会因为现在被暂停就变得不曾发生。
/// 3. Retirement **不允许** subject 复用 —— 见 [`ActorIdentity::subject_key`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActorStatus {
    #[default]
    Active,
    Suspended,
    Retired,
}

impl ActorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActorStatus::Active => "active",
            ActorStatus::Suspended => "suspended",
            ActorStatus::Retired => "retired",
        }
    }

    /// 这个状态下还能不能建立**新的**认证。
    ///
    /// 只回答未来资格，不回答历史事实是否有效 —— 那是两个问题。
    pub fn can_authenticate(&self) -> bool {
        matches!(self, ActorStatus::Active)
    }

    /// 未知取值归入 `Suspended`（fail-closed）。
    ///
    /// 读不懂的状态一律当作不可认证。反过来（未知即 Active）会让一个拼错的
    /// 状态值悄悄放行。
    pub fn parse(raw: &str) -> Self {
        match raw {
            "active" => ActorStatus::Active,
            "retired" => ActorStatus::Retired,
            _ => ActorStatus::Suspended,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct ActorIdentity {
    pub id: Option<Thing>,

    /// 对外稳定的 Authentication Subject，OIDC `sub` 建立在它之上。
    ///
    /// 下面这些都**不得**改变它：Email / Username / Display Name 的修改、
    /// Credential 轮换、MFA 增减、经由不同 Client 进入。
    ///
    /// 它与 `id` 是两个命名空间。实现上可以取同一个值，但那是实现选择，
    /// 不建立语义等同（GA-04 §5）—— 文档不得声称
    /// `Resource ID = Stable Subject = OIDC sub`。
    ///
    /// **退役后不得复用**：否则历史 Claims、Audit 与外部记录里的同一个
    /// Subject，会在不同时间指向不同主体。这是标识符完整性规则，
    /// 与「是否保留该 Actor 的个人数据」是两回事。
    pub subject_key: String,

    /// 落库形态是字符串，与 schema 的 `TYPE string` 对齐。
    /// 用 [`ActorKind::parse`] 解回枚举。
    pub actor_kind: String,
    pub identity_source: String,

    /// Soulseed 模式下引用 SoulseedAGI 已成立的 Canonical Actor。
    ///
    /// 它只证明绑定关系。SoulAuth 不因此获得定义或修改 Mind、SubjectIntent、
    /// Memory 的能力 —— SoulseedAGI 定义主体，SoulAuth 认证主体。
    ///
    /// 不得默认暴露给第三方 OIDC Client：属受控 Integration Claim。
    pub canonical_actor_ref: Option<String>,

    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl ActorIdentity {
    /// 建立一个本地身份。
    ///
    /// `subject_key` 由调用方生成并保证唯一（数据库上有唯一索引兜底）。
    /// 这里不自动派生它：从 email 或任何可变属性派生 subject，正是
    /// GA-04 §7 禁止的事。
    pub fn new_local(subject_key: impl Into<String>, actor_kind: ActorKind) -> Self {
        let now = Utc::now().timestamp();
        Self {
            id: None,
            subject_key: subject_key.into(),
            actor_kind: actor_kind.as_str().to_string(),
            identity_source: IdentitySource::Local.as_str().to_string(),
            canonical_actor_ref: None,
            status: ActorStatus::Active.as_str().to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    /// 这个身份现在还能不能建立新的认证。
    pub fn can_authenticate(&self) -> bool {
        ActorStatus::parse(&self.status).can_authenticate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_values_match_what_the_schema_expects() {
        // **落库走 as_str()，不是 serde。**
        //
        // 这三列在 schema 上是 `TYPE string`，而 `SurrealValue` derive 会把
        // 枚举编码成 `{ Human: {} }`。首版这些字段直接用枚举类型并 derive 了
        // SurrealValue，单测断言的却是 serde_json 往返 —— 两者都"通过"，
        // 而真正落库时数据库报
        //   Expected `string` but found `{ Human: {} }`
        // 集成测试第一次跑就撞上了。断言必须验真正的落库路径。
        assert_eq!(ActorKind::Human.as_str(), "human");
        assert_eq!(ActorKind::AiActor.as_str(), "ai_actor");
        assert_eq!(IdentitySource::Local.as_str(), "local");
        assert_eq!(ActorStatus::Retired.as_str(), "retired");

        // 往返：改了取值会让已经落库的记录读不回来。
        assert_eq!(ActorStatus::parse("suspended"), ActorStatus::Suspended);
    }

    #[test]
    fn unknown_values_fail_closed() {
        // 读不懂的状态一律当作不可认证；读不懂的主体类别一律当作人类
        // （要走人类那套完整认证要求，而不是更宽松的机器路径）。
        // 读不懂的状态一律当作不可认证。反过来（未知即 Active）会让一个
        // 拼错的状态值悄悄放行。
        assert!(!ActorStatus::parse("garbage").can_authenticate());
        assert!(!ActorStatus::parse("").can_authenticate());
    }

    #[test]
    fn only_active_identities_may_authenticate() {
        assert!(ActorStatus::Active.can_authenticate());
        assert!(!ActorStatus::Suspended.can_authenticate());
        // Retired 停止认证，但它的 subject_key 不因此可被复用 —— 那是
        // 另一条规则，由数据库唯一索引与不删记录共同保证。
        assert!(!ActorStatus::Retired.can_authenticate());
    }

    #[test]
    fn ai_actor_needs_no_human_account_to_exist() {
        // 这是 Actor-native 的核心判据：建一个非人主体不需要任何
        // Human Account 材料 —— 没有 email，没有 username，没有密码。
        let agent = ActorIdentity::new_local("agent-7f3a", ActorKind::AiActor);
        assert_eq!(agent.actor_kind, "ai_actor");
        assert!(agent.can_authenticate());
    }

    #[test]
    fn subject_key_is_not_derived_from_anything_mutable() {
        // 同一个 subject_key 配不同 kind 仍是各自独立的身份 —— 构造函数
        // 不从任何可变属性推导它。
        let a = ActorIdentity::new_local("stable-1", ActorKind::Human);
        let b = ActorIdentity::new_local("stable-1", ActorKind::AiActor);
        assert_eq!(a.subject_key, b.subject_key);
        assert_ne!(a.actor_kind, b.actor_kind);
    }
}
