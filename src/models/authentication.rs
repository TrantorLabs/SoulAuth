//! 一次成功认证的**统一产物**。
//!
//! # 为什么两条认证路径必须产出同一个形状
//!
//! Human 用口令、MFA 或外部身份证明自己，AIActor 用 Ed25519 挑战—应答。凭证
//! 不同是应该的 —— 它们是不同性质的主体。但如果两条路径各自产出一个不同形状
//! 的结果，那么「Human 与 AIActor 进入同一套 Actor Identity Contract」就只是
//! 一句数据建模上的说法：下游每多一类主体，就要多写一个分支。
//!
//! 真正成立的判据是：**认证成功之后，系统手里拿到的事实是同一种东西** ——
//! 谁（身份根）、哪类主体、用什么证明的、凭证的标识、以及这次签发的令牌。
//! 这个类型就是那个事实，`tests/conformance.rs::b3` 断言它存在且两条路径都产出它。
//!
//! # 它不是响应体
//!
//! 线上响应形状是对外契约（AI 主体那一侧还被 `j8` 冻结），不能因为内部统一就
//! 改。所以这个类型只在进程内流转，各自的 wire 结构由它派生 —— 人类那侧还要
//! 带上账户字段（邮箱、用户名），那些是 Account 的属性，不属于身份事实。

use serde::{Deserialize, Serialize};

use super::actor_identity::ActorKind;

/// 这次认证实际验证了哪一类凭证。
///
/// 记下「用什么证明的」而不只是「通过了」，是审计归因要用的东西：同一个主体
/// 用口令登录和用备用恢复码登录，在安全上不是一回事。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// 口令（Argon2 校验）。
    Password,
    /// TOTP 第二因子。
    Totp,
    /// 一次性备用恢复码。
    BackupCode,
    /// 外部 IdP 的认证结果。`credential_label` 记 provider 名。
    ///
    /// 注意它**不是** SoulAuth 的 Credential：外部主体用什么证明自己是外部的事，
    /// SoulAuth 验证的是「本次外部认证结果成立」。见 `h3`。
    ExternalIdentity,
    /// 邮件里的一次性链接（邮箱验证完成即登录）。
    EmailLink,
    /// AIActor 的 Ed25519 挑战—应答。`credential_label` 记用的是哪把钥匙。
    Ed25519Key,
}

impl CredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialKind::Password => "password",
            CredentialKind::Totp => "totp",
            CredentialKind::BackupCode => "backup_code",
            CredentialKind::ExternalIdentity => "external_identity",
            CredentialKind::EmailLink => "email_link",
            CredentialKind::Ed25519Key => "ed25519_key",
        }
    }
}

/// 认证成立后的身份事实。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResult {
    /// 身份根引用，形如 `actor_identity:xxx`。
    ///
    /// 归因到身份根而不是 `user` 行：同一个主体的账户实现可以变，身份根不变。
    pub actor_identity_id: String,
    /// 这是哪一类主体。
    pub actor_kind: ActorKind,
    /// 本次验证的凭证类别。
    pub credential_kind: CredentialKind,
    /// 凭证的可读标识：AI 主体是密钥标签，外部身份是 provider 名。
    ///
    /// 口令没有标识可言 —— 一个主体只有一份口令，所以这里是 `None`。
    pub credential_label: Option<String>,
    /// 本次签发的令牌。
    pub token: String,
    /// 令牌过期时间（unix 秒）。
    pub expires_at: i64,
}

impl AuthenticationResult {
    /// Human 侧的构造口。
    pub fn human(
        actor_identity_id: String,
        credential_kind: CredentialKind,
        credential_label: Option<String>,
        token: String,
        expires_at: i64,
    ) -> Self {
        Self {
            actor_identity_id,
            actor_kind: ActorKind::Human,
            credential_kind,
            credential_label,
            token,
            expires_at,
        }
    }

    /// AIActor 侧的构造口。密钥标签是必有的 —— 一个身份可以挂多把钥匙，
    /// 审计要能看出是哪一把认证的。
    pub fn ai_actor(
        actor_identity_id: String,
        credential_label: String,
        token: String,
        expires_at: i64,
    ) -> Self {
        Self {
            actor_identity_id,
            actor_kind: ActorKind::AiActor,
            credential_kind: CredentialKind::Ed25519Key,
            credential_label: Some(credential_label),
            token,
            expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_paths_produce_the_same_shape() {
        let human = AuthenticationResult::human(
            "actor_identity:abc".to_string(),
            CredentialKind::Password,
            None,
            "tok".to_string(),
            100,
        );
        let ai = AuthenticationResult::ai_actor(
            "actor_identity:def".to_string(),
            "laptop".to_string(),
            "tok".to_string(),
            100,
        );

        // 同一套字段，差别只在取值 —— 这正是 b3 要的那件事。
        assert_eq!(human.actor_kind, ActorKind::Human);
        assert_eq!(ai.actor_kind, ActorKind::AiActor);
        assert_eq!(human.credential_kind, CredentialKind::Password);
        assert_eq!(ai.credential_kind, CredentialKind::Ed25519Key);
        assert!(human.credential_label.is_none());
        assert_eq!(ai.credential_label.as_deref(), Some("laptop"));
    }

    #[test]
    fn credential_kind_wire_values_are_snake_case() {
        // 这些值会进审计记录，改动等于改既有审计行的含义。
        for (kind, wire) in [
            (CredentialKind::Password, "password"),
            (CredentialKind::Totp, "totp"),
            (CredentialKind::BackupCode, "backup_code"),
            (CredentialKind::ExternalIdentity, "external_identity"),
            (CredentialKind::EmailLink, "email_link"),
            (CredentialKind::Ed25519Key, "ed25519_key"),
        ] {
            assert_eq!(kind.as_str(), wire);
            assert_eq!(serde_json::to_value(kind).unwrap(), serde_json::json!(wire));
        }
    }
}
