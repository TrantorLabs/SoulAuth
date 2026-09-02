//! 审计完整性：哈希链与 checkpoint 签名。
//!
//! 审计表在此之前是一张普通表 —— 拿到数据库写权限就能改、能删、能插，
//! 而且不留痕。文档只好挂一条「不防篡改，对运维有用，不是证据」的告示。
//!
//! 这里补的是 F4 要求的两层，缺一层都不成立：
//!
//! * **哈希链**挡单条改写。每行的 `event_hash` 覆盖它自己的内容与
//!   `previous_hash`，改一行它自己对不上，删一行下一行的前驱指向空缺，
//!   `seq` 也会缺号。
//! * **签名 checkpoint** 挡整段重写。只有链的话，拥有全库写权限的人可以从被改
//!   那一行起把后面整条链重算一遍，链自洽如初。checkpoint 把某个时刻的链头用
//!   一把**不在数据库里**的私钥签下来，重算过的链头对不上已签发的签名。
//!
//! 签名用 Ed25519：公钥随 checkpoint 一起存，任何人都可以离线验，不需要
//! 拿到私钥。这与 `hash_bearer` 那类内部指纹不是一回事，所以不放进
//! `utils::crypto`。

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::services::database::Database;

/// 链首的前驱。64 个 0，与 hex 摘要等宽，读日志时一眼能认出来。
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 一条审计事件参与摘要计算的字段。
///
/// 与 `user_activity` 的列一一对应，顺序固定。加列时**必须**同步加进来，
/// 否则新列可以被随意改动而链不断 —— 那样链就只覆盖了一部分事实。
pub struct DigestInput<'a> {
    /// 写下这一行的副本。进摘要是必须的：不盖住它，一行就可以被从一条链
    /// 搬到另一条链而摘要不变。
    pub chain_id: &'a str,
    pub seq: i64,
    pub previous_hash: &'a str,
    pub action: &'a str,
    pub category: &'a str,
    pub status: &'a str,
    pub user_id: &'a str,
    pub ip_address: &'a str,
    pub user_agent: &'a str,
    pub details_json: &'a str,
    pub timestamp: i64,
}

/// 计算一条事件的 `event_hash`（小写 hex）。
///
/// 每个字段按 `长度:内容|` 喂进去，不是简单拼接。拼接会有歧义：
/// `("ab", "c")` 与 `("a", "bc")` 拼出来是同一串，于是两条不同的事件可以
/// 撞出同一个摘要。带长度前缀就不会。
pub fn event_hash(input: &DigestInput<'_>) -> String {
    let seq = input.seq.to_string();
    let timestamp = input.timestamp.to_string();
    let fields: [&str; 11] = [
        input.chain_id,
        &seq,
        input.previous_hash,
        input.action,
        input.category,
        input.status,
        input.user_id,
        input.ip_address,
        input.user_agent,
        input.details_json,
        &timestamp,
    ];

    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update(field.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(field.as_bytes());
        hasher.update(b"|");
    }
    hex(&hasher.finalize())
}

/// checkpoint 的签名密钥。
///
/// 私钥来自 `AUDIT_INTEGRITY_KEY`，与 `JWT_SECRET`、`MFA_SECRET_ENCRYPTION_KEY`
/// 是三把不同的钥匙。共用一把意味着轮换其中一个用途会连带作废另外两个 ——
/// 而审计完整性恰恰是最不该被「顺手轮换」破坏的那一个。
pub struct CheckpointSigner {
    key: SigningKey,
}

impl CheckpointSigner {
    /// 从 base64 的 32 字节种子建密钥。
    pub fn from_seed_b64(seed: &str) -> Result<Self> {
        let raw = B64
            .decode(seed.trim())
            .map_err(|e| anyhow!("AUDIT_INTEGRITY_KEY is not valid base64: {e}"))?;
        let seed: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow!("AUDIT_INTEGRITY_KEY must decode to exactly 32 bytes"))?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// 公钥（base64）。随 checkpoint 一起存，供离线验证。
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.key.verifying_key().to_bytes())
    }

    /// 签一个 checkpoint，返回 base64 签名。
    pub fn sign(&self, chain_id: &str, seq_to: i64, head_hash: &str, created_at: i64) -> String {
        B64.encode(
            self.key
                .sign(&checkpoint_message(chain_id, seq_to, head_hash, created_at))
                .to_bytes(),
        )
    }
}

/// 离线验证一个 checkpoint。校验端点用它，不需要私钥。
pub fn verify_checkpoint(
    public_key_b64: &str,
    signature_b64: &str,
    chain_id: &str,
    seq_to: i64,
    head_hash: &str,
    created_at: i64,
) -> bool {
    let Ok(pk_raw) = B64.decode(public_key_b64.trim()) else {
        return false;
    };
    let Ok(pk_bytes): std::result::Result<[u8; 32], _> = pk_raw.try_into() else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
    let Ok(sig_raw) = B64.decode(signature_b64.trim()) else {
        return false;
    };
    let Ok(sig_bytes): std::result::Result<[u8; 64], _> = sig_raw.try_into() else {
        return false;
    };
    verifying
        .verify(
            &checkpoint_message(chain_id, seq_to, head_hash, created_at),
            &Signature::from_bytes(&sig_bytes),
        )
        .is_ok()
}

/// 签发一个 checkpoint：读当前链头，签名，落库。
///
/// 链上没有新事件就什么都不做 —— 每小时签一条内容相同的 checkpoint 只会让
/// 这张表变长，不增加任何证据。
pub async fn issue_checkpoint(
    db: &Database,
    signer: &CheckpointSigner,
    chain_id: &str,
) -> Result<Option<i64>> {
    // 只签**本副本自己那条链**。签别人的链没有意义：那条链的后续事件由
    // 另一个进程写，本副本读到的链头随时可能已经不是最新的。
    let head: Vec<serde_json::Value> = db
        .raw_query(
            "audit_checkpoint_head",
            "SELECT seq, event_hash FROM user_activity \
             WHERE chain_id = $chain_id AND seq != NONE ORDER BY seq DESC LIMIT 1",
            serde_json::json!({ "chain_id": chain_id }),
        )
        .await
        .and_then(|mut r| r.take(0).map_err(Into::into))
        .map_err(|e| anyhow!("failed to read the audit chain head: {e}"))?;

    let Some(row) = head.first() else {
        return Ok(None);
    };
    let seq_to = row
        .get("seq")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let head_hash = row
        .get("event_hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    if head_hash.is_empty() {
        return Ok(None);
    }

    let last: Vec<serde_json::Value> = db
        .raw_query(
            "audit_checkpoint_last",
            "SELECT seq_to FROM audit_checkpoint WHERE chain_id = $chain_id \
             ORDER BY seq_to DESC LIMIT 1",
            serde_json::json!({ "chain_id": chain_id }),
        )
        .await
        .and_then(|mut r| r.take(0).map_err(Into::into))
        .map_err(|e| anyhow!("failed to read the last checkpoint: {e}"))?;
    let last_seq = last
        .first()
        .and_then(|r| r.get("seq_to"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    if seq_to <= last_seq {
        return Ok(None);
    }

    let created_at = chrono::Utc::now().timestamp();
    db.raw_query(
        "audit_checkpoint_create",
        "CREATE audit_checkpoint CONTENT { \
             chain_id: $chain_id, seq_to: $seq_to, head_hash: $head_hash, \
             created_at: $created_at, public_key: $public_key, signature: $signature }",
        serde_json::json!({
            "chain_id": chain_id,
            "seq_to": seq_to,
            "head_hash": head_hash,
            "created_at": created_at,
            "public_key": signer.public_key_b64(),
            "signature": signer.sign(chain_id, seq_to, &head_hash, created_at),
        }),
    )
    .await
    .map_err(|e| anyhow!("failed to write the checkpoint: {e}"))?;

    Ok(Some(seq_to))
}

/// 被签名的字节。带域分隔前缀，免得这把钥匙签出来的东西在别处被当作别的语义。
fn checkpoint_message(chain_id: &str, seq_to: i64, head_hash: &str, created_at: i64) -> Vec<u8> {
    format!("soulauth-audit-checkpoint/v1|{chain_id}|{seq_to}|{head_hash}|{created_at}")
        .into_bytes()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(seq: i64, prev: &'a str, action: &'a str) -> DigestInput<'a> {
        DigestInput {
            chain_id: "replica-a",
            seq,
            previous_hash: prev,
            action,
            category: "Authentication",
            status: "Success",
            user_id: "abc",
            ip_address: "203.0.113.7",
            user_agent: "curl/8.0",
            details_json: "{}",
            timestamp: 1_756_694_400,
        }
    }

    #[test]
    fn the_same_event_always_hashes_the_same() {
        let a = event_hash(&input(1, GENESIS_HASH, "login_success"));
        let b = event_hash(&input(1, GENESIS_HASH, "login_success"));
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn changing_any_field_changes_the_hash() {
        let base = event_hash(&input(1, GENESIS_HASH, "login_success"));
        assert_ne!(base, event_hash(&input(2, GENESIS_HASH, "login_success")));
        assert_ne!(base, event_hash(&input(1, GENESIS_HASH, "login_failed")));

        let mut moved = input(1, GENESIS_HASH, "login_success");
        moved.ip_address = "203.0.113.8";
        assert_ne!(base, event_hash(&moved));
    }

    /// 字段边界必须无歧义。不带长度前缀的话，把一个字符从 action 末尾挪到
    /// category 开头，摘要不变 —— 两条不同的事件就能共用一个 hash。
    #[test]
    fn moving_a_character_across_a_field_boundary_changes_the_hash() {
        let mut a = input(1, GENESIS_HASH, "ab");
        a.category = "cd";
        let mut b = input(1, GENESIS_HASH, "a");
        b.category = "bcd";
        assert_ne!(event_hash(&a), event_hash(&b));
    }

    #[test]
    fn a_checkpoint_verifies_with_its_own_public_key() {
        let signer = CheckpointSigner::from_seed_b64(&B64.encode([7u8; 32])).unwrap();
        let sig = signer.sign("replica-a", 42, "deadbeef", 1_756_694_400);
        assert!(verify_checkpoint(
            &signer.public_key_b64(),
            &sig,
            "replica-a",
            42,
            "deadbeef",
            1_756_694_400
        ));
    }

    /// 同一条 checkpoint 换个 chain_id 就该验不过。多副本下每条链各自成立，
    /// 把 A 副本的 checkpoint 挪到 B 副本名下是一种明确的伪造。
    #[test]
    fn a_checkpoint_does_not_verify_under_another_chain() {
        let signer = CheckpointSigner::from_seed_b64(&B64.encode([7u8; 32])).unwrap();
        let sig = signer.sign("replica-a", 42, "deadbeef", 1);
        assert!(!verify_checkpoint(
            &signer.public_key_b64(),
            &sig,
            "replica-b",
            42,
            "deadbeef",
            1
        ));
    }

    /// 同一行搬到另一条链，摘要必须变 —— 否则「按副本分链」只是个标签。
    #[test]
    fn moving_a_row_to_another_chain_changes_the_hash() {
        let a = input(1, GENESIS_HASH, "login_success");
        let mut b = input(1, GENESIS_HASH, "login_success");
        b.chain_id = "replica-b";
        assert_ne!(event_hash(&a), event_hash(&b));
    }

    /// 改动被签名的任何一项，签名就该失效 —— 这正是「整段历史被替换」的检出点。
    #[test]
    fn a_rewritten_head_fails_verification() {
        let signer = CheckpointSigner::from_seed_b64(&B64.encode([7u8; 32])).unwrap();
        let sig = signer.sign("replica-a", 42, "deadbeef", 1_756_694_400);
        let pk = signer.public_key_b64();
        let c = "replica-a";

        assert!(!verify_checkpoint(
            &pk,
            &sig,
            c,
            43,
            "deadbeef",
            1_756_694_400
        ));
        assert!(!verify_checkpoint(
            &pk,
            &sig,
            c,
            42,
            "cafebabe",
            1_756_694_400
        ));
        assert!(!verify_checkpoint(
            &pk,
            &sig,
            c,
            42,
            "deadbeef",
            1_756_694_401
        ));
    }

    /// 另一把钥匙签的 checkpoint 不能通过。写这条是因为「公钥随记录一起存」
    /// 意味着攻击者可以连公钥一起换掉 —— 校验端点因此还要比对公钥是否是
    /// 本实例配置的那一把，光验签名不够。
    #[test]
    fn another_key_does_not_verify() {
        let mine = CheckpointSigner::from_seed_b64(&B64.encode([7u8; 32])).unwrap();
        let theirs = CheckpointSigner::from_seed_b64(&B64.encode([9u8; 32])).unwrap();
        let sig = theirs.sign("replica-a", 42, "deadbeef", 1);
        assert!(!verify_checkpoint(
            &mine.public_key_b64(),
            &sig,
            "replica-a",
            42,
            "deadbeef",
            1
        ));
    }

    #[test]
    fn a_malformed_key_is_rejected_rather_than_panicking() {
        assert!(CheckpointSigner::from_seed_b64("not base64!!").is_err());
        assert!(CheckpointSigner::from_seed_b64(&B64.encode([1u8; 16])).is_err());
    }
}
