//! AIActor 的凭证与认证证明。
//!
//! # 这一层在回答什么
//!
//! `ActorKind::AiActor` 从第一天起就在 [`super::actor_identity`] 里，但它
//! **只是一个枚举变体** —— 全生产代码没有任何地方构造它，也没有任何路径能让
//! 一个非人主体完成认证。于是「Actor-native」这句话在 Runtime 上是空的：
//! 想给一个 Agent 建身份，唯一办法是去注册一个假的人类账户。
//!
//! 这个模块补上缺的那条路：**AIActor 拥有独立的 ActorIdentity 与自己的
//! 密码学凭证，不需要 HumanAccount，不需要 Email，不需要口令。**
//!
//! # 为什么是挑战—应答，不是长期密钥
//!
//! 给 Agent 发一枚长期 bearer token，等于把「凭证」和「证明」合成同一个东西：
//! 它一旦出现在日志、环境变量或某次转发里就永久可用。挑战—应答里在网络上
//! 流动的只有一次性签名，私钥从不离开 Agent。
//!
//! # 冻结项
//!
//! V3《24｜Authentication & Sessions》§2 列了 13 项：在它们全部冻结之前，
//! signed proof 不得被描述为完整的 Public Authentication Method。逐项对应：
//!
//! | 冻结项 | 本实现 |
//! |---|---|
//! | credential representation | Ed25519 公钥，32 原始字节 |
//! | verification key format | base64url-no-pad |
//! | algorithm allowlist | 仅 `ed25519`，单元素 |
//! | signed payload | [`AiActorProof::canonical_payload`] |
//! | canonicalization | 固定四行，`\n` 连接，不用 JSON |
//! | encoding | payload UTF-8；密钥/nonce/签名均 base64url-no-pad |
//! | domain separation | 首行常量 [`AI_ACTOR_AUTH_DOMAIN`] |
//! | challenge / nonce | 服务端签发，32 字节 CSPRNG |
//! | timestamp | 服务端 `issued_at`，客户端不传时间 |
//! | expiry | [`CHALLENGE_TTL_SECONDS`] |
//! | replay semantics | nonce 一次性，原子消费 |
//! | actor binding | nonce 绑定 actor；payload 含 actor_id |
//! | error contract | 统一 `AuthError` |
//!
//! ## 为什么不用 JSON 做被签名内容
//!
//! JSON 没有唯一的字节表示：键序、空白、Unicode 转义、数字写法都可以变，
//! 而签名校验的是**字节**。任何"先序列化再签名"的方案都要额外引入一套
//! canonicalization 规范（JCS 之类），那是纯粹的攻击面。固定四行文本没有
//! 这个问题 —— 生成方和校验方只能得到同一串字节。
//!
//! ## 为什么 payload 里要有 issuer
//!
//! 没有它，从部署 A 抓到的一次应答可以拿去部署 B 重放（只要两边碰巧有同名
//! actor）。把 issuer 钉进被签名内容，签名就只对签发它的那个部署有效。

use chrono::Utc;
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb_types::SurrealValue;

/// 域分隔前缀。
///
/// 它保证这枚签名**只能**用于「AIActor 向 SoulAuth 证明身份」这一件事：
/// 即便将来出现别的签名用途，只要各自的域串不同，一处的签名就不可能在
/// 另一处通过校验。版本号在串里 —— 改动 payload 结构必须同时改它。
pub const AI_ACTOR_AUTH_DOMAIN: &str = "soulauth-ai-actor-auth/v1";

/// 挑战有效期。
///
/// 短到足以让抓到的挑战几乎没有利用窗口，长到能容忍一次网络往返和合理的
/// 时钟偏移。它不是会话时长 —— 换到的会话另有自己的 TTL。
pub const CHALLENGE_TTL_SECONDS: i64 = 120;

/// 允许的签名算法。**单元素是刻意的。**
///
/// 算法可协商是签名协议里最经典的一类漏洞（"alg: none"、降级到弱曲线）。
/// 这里不接受协商：客户端声明的算法必须逐字等于唯一这一个值。
pub const ALLOWED_ALGORITHMS: [&str; 1] = ["ed25519"];

/// Ed25519 公钥的原始字节数。
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 签名的原始字节数。
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// AIActor 的一枚验证密钥。
///
/// 一个 Actor 可以同时持有多枚 —— 轮换期间新旧并存，是安全轮换的前提。
/// 这里存的是**公钥**：SoulAuth 从不接触 Agent 的私钥，因此库泄露不会让
/// 任何人能够冒充一个 Agent（与口令哈希不同，这里连离线爆破的目标都没有）。
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct AiActorCredential {
    pub id: Option<Thing>,

    /// 所属身份根。
    pub actor_identity_id: Thing,

    /// base64url-no-pad 的 32 字节 Ed25519 公钥。
    pub public_key: String,

    /// 落库为字符串，取值受 [`ALLOWED_ALGORITHMS`] 约束。
    pub algorithm: String,

    /// 人给的标签，用来在多枚密钥里认出这一枚（"laptop-agent"、"ci-runner"）。
    /// 它是**运维便利**，不参与任何认证判定。
    pub label: String,

    /// `active` | `revoked`
    pub status: String,

    pub created_at: i64,
    pub revoked_at: Option<i64>,

    /// 最近一次成功用它完成认证的时间。用于识别僵尸密钥。
    pub last_used_at: Option<i64>,
}

/// 凭证状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
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

    /// 未知取值一律当作已吊销。
    ///
    /// fail-closed：如果有人往库里写了个拼错的状态，正确的行为是拒绝认证，
    /// 而不是因为「它不等于 revoked」就放行。
    pub fn parse(raw: &str) -> Self {
        match raw {
            "active" => CredentialStatus::Active,
            _ => CredentialStatus::Revoked,
        }
    }

    pub fn can_authenticate(&self) -> bool {
        matches!(self, CredentialStatus::Active)
    }
}

impl AiActorCredential {
    pub fn new(
        actor_identity_id: Thing,
        public_key: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            actor_identity_id,
            public_key: public_key.into(),
            algorithm: ALLOWED_ALGORITHMS[0].to_string(),
            label: label.into(),
            status: CredentialStatus::Active.as_str().to_string(),
            created_at: Utc::now().timestamp(),
            revoked_at: None,
            last_used_at: None,
        }
    }

    pub fn can_authenticate(&self) -> bool {
        CredentialStatus::parse(&self.status).can_authenticate()
            && ALLOWED_ALGORITHMS.contains(&self.algorithm.as_str())
    }
}

/// 一枚待应答的挑战。
///
/// 它绑定到具体 actor：拿 A 的挑战去证明 B 的身份不成立，因为被签名内容里
/// 写着 actor_id，签名会对不上。
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct AiActorChallenge {
    pub id: Option<Thing>,
    pub actor_identity_id: Thing,

    /// base64url-no-pad 的 32 字节随机数。唯一索引保证不重复。
    pub nonce: String,

    pub issued_at: i64,
    pub expires_at: i64,

    /// 一次性。消费走条件更新，不是先读后写。
    pub consumed: bool,
}

/// 认证证明的规范化被签名内容。
///
/// 生成方与校验方各自独立构造这串字节，任何一处不一致签名就通不过 ——
/// 因此它必须**只有一种写法**。
pub struct AiActorProof;

impl AiActorProof {
    /// 构造被签名的字节。
    ///
    /// ```text
    /// soulauth-ai-actor-auth/v1
    /// https://auth.example.com
    /// actor_identity:7f3a...
    /// K3nCq...
    /// ```
    ///
    /// 四行，`\n` 连接，**结尾无换行**。顺序固定为
    /// 域 → issuer → actor → nonce，不可调换。
    pub fn canonical_payload(issuer: &str, actor_id: &str, nonce: &str) -> String {
        format!(
            "{AI_ACTOR_AUTH_DOMAIN}\n{}\n{}\n{}",
            issuer.trim_end_matches('/'),
            actor_id,
            nonce
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> String {
        AiActorProof::canonical_payload("https://auth.example.com", "actor_identity:abc", "nonce1")
    }

    #[test]
    fn canonical_payload_is_four_lines_in_a_fixed_order() {
        let p = payload();
        let lines: Vec<&str> = p.split('\n').collect();
        assert_eq!(lines.len(), 4, "被签名内容必须恰好四行");
        assert_eq!(lines[0], AI_ACTOR_AUTH_DOMAIN);
        assert_eq!(lines[1], "https://auth.example.com");
        assert_eq!(lines[2], "actor_identity:abc");
        assert_eq!(lines[3], "nonce1");
        assert!(!p.ends_with('\n'), "结尾不得有换行 —— 那会成为第五行");
    }

    #[test]
    fn issuer_trailing_slash_does_not_change_the_bytes() {
        // 否则同一个部署会因为 APP_URL 写没写斜杠而产生两串不同的字节，
        // 客户端与服务端各写一种，签名永远对不上，而且极难排查。
        assert_eq!(
            AiActorProof::canonical_payload("https://a.example/", "x", "n"),
            AiActorProof::canonical_payload("https://a.example", "x", "n")
        );
    }

    #[test]
    fn different_issuer_yields_different_bytes() {
        // 跨部署重放的防线。
        assert_ne!(
            AiActorProof::canonical_payload("https://a.example", "x", "n"),
            AiActorProof::canonical_payload("https://b.example", "x", "n")
        );
    }

    #[test]
    fn different_actor_yields_different_bytes() {
        assert_ne!(
            AiActorProof::canonical_payload("https://a.example", "x", "n"),
            AiActorProof::canonical_payload("https://a.example", "y", "n")
        );
    }

    #[test]
    fn domain_separation_prefix_is_versioned() {
        // payload 结构一旦变化，域串必须一起变，否则新旧格式的签名会互相通过。
        assert!(AI_ACTOR_AUTH_DOMAIN.contains("/v"));
        assert!(payload().starts_with(AI_ACTOR_AUTH_DOMAIN));
    }

    #[test]
    fn algorithm_allowlist_has_exactly_one_entry() {
        // 可协商的算法列表是签名协议里最经典的一类漏洞。
        assert_eq!(ALLOWED_ALGORITHMS.len(), 1);
        assert_eq!(ALLOWED_ALGORITHMS[0], "ed25519");
    }

    #[test]
    fn unknown_credential_status_fails_closed() {
        assert!(!CredentialStatus::parse("actíve").can_authenticate());
        assert!(!CredentialStatus::parse("").can_authenticate());
        assert!(CredentialStatus::parse("active").can_authenticate());
    }

    #[test]
    fn credential_with_unlisted_algorithm_cannot_authenticate() {
        let mut c = AiActorCredential::new(Thing::new("actor_identity", "a"), "pk", "l");
        assert!(c.can_authenticate());
        c.algorithm = "rsa".to_string();
        assert!(!c.can_authenticate(), "算法不在白名单内必须拒绝");
    }
}
