//! 一次成功认证的**事实**。
//!
//! # 认证事实不是令牌
//!
//! 这个类型回答的是「谁、用什么方法、在什么时候被认证了」。它**不拥有**令牌，也
//! 不拥有令牌的过期时间 —— 那两样是把事实投影成协议的产物，由会话签发路径负责。
//! 把它们放进同一个对象，等于让「认证成立」这件事依赖「签出了一枚 bearer」，而
//! 审计要记的是前者，OIDC 要投影的是前者，会话只是前者的一种延续形态。
//!
//! ```text
//! Authentication
//!     ↓
//! AuthenticationFact          ← 这个类型
//!     ├── Audit
//!     └── optional AuthSession
//!              ↓
//!         Token / OIDC Projection
//! ```
//!
//! # 方法是集合，不是单值
//!
//! `password + totp` 的登录不是「一次 totp 登录」。第一因子已经成立，它是事实的
//! 一部分；只记最后一步会把它丢掉，而任何按方法集合做判断的策略（重认证、
//! step-up）都会因此把两因子当成一因子。所以是 `methods: Vec<_>`。
//!
//! # 方法不是凭证
//!
//! `external_identity` 不是 SoulAuth 的 Credential —— 外部主体用什么证明自己是外部
//! 的事，SoulAuth 验证的是「本次外部认证结果成立」。邮件链接同理。所以这里的
//! 枚举叫 `AuthenticationMethod`，不叫 `CredentialKind`；本地凭证由 `credential_refs`
//! 单独引用，而且允许为空。
//!
//! 这些先是语义目标：没有 `authentication_fact` 表，也没有它的 Repository。

use serde::{Deserialize, Serialize};

use super::actor_identity::ActorKind;

/// 本次认证实际通过的一种方法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethod {
    /// 口令（Argon2 校验）。
    Password,
    /// TOTP 第二因子。
    Totp,
    /// 一次性备用恢复码。
    BackupCode,
    /// 外部 IdP 的认证结果。不是本地凭证。
    ExternalIdentity,
    /// 邮件里的一次性链接（邮箱验证完成即登录）。不是本地凭证。
    EmailLink,
    /// AIActor 的 Ed25519 挑战—应答。
    Ed25519Key,
}

impl AuthenticationMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthenticationMethod::Password => "password",
            AuthenticationMethod::Totp => "totp",
            AuthenticationMethod::BackupCode => "backup_code",
            AuthenticationMethod::ExternalIdentity => "external_identity",
            AuthenticationMethod::EmailLink => "email_link",
            AuthenticationMethod::Ed25519Key => "ed25519_key",
        }
    }
}

/// 认证成立后的事实。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFact {
    /// 身份根引用，形如 `actor_identity:xxx`。
    ///
    /// 归因到身份根而不是 `user` 行：同一个主体的账户实现可以变，身份根不变。
    pub actor_identity_id: String,
    /// 这是哪一类主体。来自已经过闸门的身份根，不由调用方另造。
    pub actor_kind: ActorKind,
    /// 本次**实际通过**的方法集合，按通过顺序。
    pub methods: Vec<AuthenticationMethod>,
    /// 事实成立的时刻（unix 秒）。
    ///
    /// 不是 `session.created_at` 的替代：新鲜度由使用方按 `now - authenticated_at`
    /// 现算，这里不存一个会随时间失真的 freshness 值。
    pub authenticated_at: i64,
    /// 支撑本次认证的**本地**凭证的稳定引用（record id 字符串）。
    ///
    /// 只服务三件事：精确的撤销传播、审计归因、历史解释。外部联合与邮件链接没有
    /// 本地凭证，不为了填满它造假引用 —— 所以允许为空。
    pub credential_refs: Vec<String>,
}

impl AuthenticationFact {
    /// Human 侧的构造口。
    pub fn human(
        actor_identity_id: String,
        methods: Vec<AuthenticationMethod>,
        credential_refs: Vec<String>,
        authenticated_at: i64,
    ) -> Self {
        Self {
            actor_identity_id,
            actor_kind: ActorKind::Human,
            methods,
            authenticated_at,
            credential_refs,
        }
    }

    /// AIActor 侧的构造口。凭证引用是必有的：一个身份可以挂多把钥匙，撤销要能
    /// 精确到那一把。
    pub fn ai_actor(
        actor_identity_id: String,
        credential_ref: String,
        authenticated_at: i64,
    ) -> Self {
        Self {
            actor_identity_id,
            actor_kind: ActorKind::AiActor,
            methods: vec![AuthenticationMethod::Ed25519Key],
            authenticated_at,
            credential_refs: vec![credential_ref],
        }
    }

    /// 方法集合的 wire 形式，给审计详情用。
    pub fn method_names(&self) -> Vec<&'static str> {
        self.methods
            .iter()
            .map(AuthenticationMethod::as_str)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fact_owns_no_token() {
        // 编译期就成立：结构体没有 token / expires_at 字段。这个测试守的是
        // 「有人把它们加回来」—— serde 输出里不该出现这两个键。
        let fact = AuthenticationFact::human(
            "actor_identity:abc".to_string(),
            vec![AuthenticationMethod::Password],
            vec!["credential:c1".to_string()],
            100,
        );
        let json = serde_json::to_value(&fact).unwrap();
        assert!(json.get("token").is_none(), "认证事实不得拥有令牌");
        assert!(
            json.get("expires_at").is_none(),
            "认证事实不得拥有令牌过期时间"
        );
    }

    #[test]
    fn mfa_keeps_the_first_factor() {
        // password + totp 是两个方法，不是「一次 totp 登录」。
        let fact = AuthenticationFact::human(
            "actor_identity:abc".to_string(),
            vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
            vec!["credential:c1".to_string()],
            100,
        );
        assert_eq!(fact.methods.len(), 2);
        assert_eq!(fact.methods[0], AuthenticationMethod::Password);
        assert_eq!(fact.method_names(), vec!["password", "totp"]);
    }

    #[test]
    fn federation_needs_no_local_credential() {
        // 外部联合没有本地凭证；不造假引用。
        let fact = AuthenticationFact::human(
            "actor_identity:abc".to_string(),
            vec![AuthenticationMethod::ExternalIdentity],
            vec![],
            100,
        );
        assert!(fact.credential_refs.is_empty());
    }

    #[test]
    fn both_paths_produce_the_same_shape() {
        let human = AuthenticationFact::human(
            "actor_identity:abc".to_string(),
            vec![AuthenticationMethod::Password],
            vec![],
            100,
        );
        let ai = AuthenticationFact::ai_actor(
            "actor_identity:def".to_string(),
            "ai_actor_credential:k1".to_string(),
            100,
        );
        assert_eq!(human.actor_kind, ActorKind::Human);
        assert_eq!(ai.actor_kind, ActorKind::AiActor);
        assert_eq!(ai.methods, vec![AuthenticationMethod::Ed25519Key]);
        assert_eq!(ai.credential_refs, vec!["ai_actor_credential:k1"]);
    }

    #[test]
    fn method_wire_values_are_snake_case() {
        // 这些值会进审计记录，改动等于改既有审计行的含义。
        for (m, wire) in [
            (AuthenticationMethod::Password, "password"),
            (AuthenticationMethod::Totp, "totp"),
            (AuthenticationMethod::BackupCode, "backup_code"),
            (AuthenticationMethod::ExternalIdentity, "external_identity"),
            (AuthenticationMethod::EmailLink, "email_link"),
            (AuthenticationMethod::Ed25519Key, "ed25519_key"),
        ] {
            assert_eq!(m.as_str(), wire);
            assert_eq!(serde_json::to_value(m).unwrap(), serde_json::json!(wire));
        }
    }
}
