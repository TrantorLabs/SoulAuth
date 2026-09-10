//! MFA 机密数据的静态保护。
//!
//! 之前 `user_mfa` 表里 `totp_secret` 与 `backup_codes` 都是明文：数据库一旦泄露，
//! 攻击者可以直接算出任何账号的 TOTP，二次验证形同虚设。现在：
//!
//! * TOTP 密钥必须可逆（要用它算验证码），因此用 ChaCha20-Poly1305 加密后落库；
//! * 备用恢复码不需要可逆，改为 Argon2 哈希存储，校验时逐条比对。
//!
//! 加密密钥只来自 `MFA_SECRET_ENCRYPTION_KEY`（base64 的 32 字节），**没有回落**。
//! 未配置时 MFA 明确不可用（503），而不是从 `jwt_secret` 派生一把出来：派生能让
//! 部署跑起来，代价是轮换 `JWT_SECRET` 会让所有已登记用户的 TOTP 密钥永久解不开。

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::{
    config::Config,
    error::{AuthError, Result},
};

/// 密文前缀，用来和历史上的明文记录区分。
const CIPHERTEXT_PREFIX: &str = "enc.v1.";
const NONCE_LEN: usize = 12;

pub struct SecretCipher {
    cipher: ChaCha20Poly1305,
}

impl SecretCipher {
    /// `Ok(None)` 表示没有配置专用的 MFA 加密密钥。
    ///
    /// 这里**没有**回落路径。原先缺失时会从 `JWT_SECRET` 派生一把出来，带着一行
    /// 警告继续跑 —— 那是个静默的陷阱：JWT_SECRET 是会被轮换的（泄露、定期轮换、
    /// 换签名算法都会轮），而轮换它就让每一个已登记用户的 TOTP 密钥永久解不开。
    /// 故障面貌是「所有开了 MFA 的人同时登不进来」，而运维手上唯一的线索是一条
    /// 几个月前滚走的启动日志。
    ///
    /// 三类密钥（Token 签名 / 凭证加密 / 审计完整性）互不派生，是 `b5` 断言的
    /// 不变式。宁可让 MFA 明确不可用，也不让它可用但不可轮换。
    pub fn from_config(config: &Config) -> Result<Option<Self>> {
        let Some(encoded) = &config.mfa_encryption_key else {
            return Ok(None);
        };

        let decoded = STANDARD.decode(encoded.trim()).map_err(|e| {
            AuthError::ServerError(format!(
                "MFA_SECRET_ENCRYPTION_KEY is not valid base64: {e}"
            ))
        })?;
        if decoded.len() != 32 {
            return Err(AuthError::ServerError(format!(
                "MFA_SECRET_ENCRYPTION_KEY must decode to 32 bytes, got {}",
                decoded.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);

        Ok(Some(Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
        }))
    }

    /// 加密并编码为 `enc.v1.<base64(nonce||ciphertext)>`。
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| AuthError::ServerError("Failed to encrypt secret".to_string()))?;

        let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);

        Ok(format!("{CIPHERTEXT_PREFIX}{}", STANDARD.encode(payload)))
    }

    /// 解密。没有密文前缀的值按历史明文处理，原样返回，
    /// 以便存量记录在下一次保存时被自动加密。
    pub fn decrypt(&self, stored: &str) -> Result<String> {
        let Some(encoded) = stored.strip_prefix(CIPHERTEXT_PREFIX) else {
            return Ok(stored.to_string());
        };

        let payload = STANDARD
            .decode(encoded)
            .map_err(|_| AuthError::ServerError("Stored secret is not valid base64".to_string()))?;

        if payload.len() <= NONCE_LEN {
            return Err(AuthError::ServerError(
                "Stored secret is truncated".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext) = payload.split_at(NONCE_LEN);
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| {
                AuthError::ServerError(
                    "Failed to decrypt secret (wrong MFA encryption key?)".to_string(),
                )
            })?;

        String::from_utf8(plaintext)
            .map_err(|_| AuthError::ServerError("Decrypted secret is not valid UTF-8".to_string()))
    }

    /// 该值是否已经是密文。
    pub fn is_encrypted(stored: &str) -> bool {
        stored.starts_with(CIPHERTEXT_PREFIX)
    }
}

/// 备用恢复码的哈希（Argon2id）。
pub fn hash_backup_code(code: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(code.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| AuthError::ServerError(format!("Failed to hash backup code: {e}")))
}

/// 校验一个备用恢复码。
///
/// 兼容历史上的明文记录：不是 PHC 串时退化为常量时间比较。
pub fn verify_backup_code(stored: &str, provided: &str) -> bool {
    if stored.starts_with("$argon2") {
        return PasswordHash::new(stored)
            .map(|parsed| {
                Argon2::default()
                    .verify_password(provided.as_bytes(), &parsed)
                    .is_ok()
            })
            .unwrap_or(false);
    }

    constant_time_eq(stored.as_bytes(), provided.as_bytes())
}

/// 定长字节比较：长度不同直接假，长度相同时不按位早退。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> SecretCipher {
        SecretCipher {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&[7u8; 32])),
        }
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let c = cipher();
        let sealed = c.encrypt("JBSWY3DPEHPK3PXP").expect("encrypt");

        assert!(SecretCipher::is_encrypted(&sealed));
        assert!(!sealed.contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(c.decrypt(&sealed).expect("decrypt"), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let c = cipher();
        assert_ne!(
            c.encrypt("same-secret").expect("a"),
            c.encrypt("same-secret").expect("b")
        );
    }

    #[test]
    fn legacy_plaintext_is_passed_through() {
        let c = cipher();
        assert_eq!(
            c.decrypt("JBSWY3DPEHPK3PXP").expect("legacy"),
            "JBSWY3DPEHPK3PXP"
        );
        assert!(!SecretCipher::is_encrypted("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let sealed = cipher().encrypt("top-secret").expect("encrypt");

        let other = SecretCipher {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&[9u8; 32])),
        };

        assert!(other.decrypt(&sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let c = cipher();
        let mut sealed = c.encrypt("top-secret").expect("encrypt");
        sealed.push('A');

        assert!(c.decrypt(&sealed).is_err());
    }

    #[test]
    fn backup_code_hash_round_trips() {
        let hash = hash_backup_code("ABCDEFGH").expect("hash");

        assert!(hash.starts_with("$argon2"));
        assert!(!hash.contains("ABCDEFGH"));
        assert!(verify_backup_code(&hash, "ABCDEFGH"));
        assert!(!verify_backup_code(&hash, "HGFEDCBA"));
    }

    #[test]
    fn legacy_plaintext_backup_code_still_verifies() {
        assert!(verify_backup_code("ABCDEFGH", "ABCDEFGH"));
        assert!(!verify_backup_code("ABCDEFGH", "ABCDEFGX"));
    }

    #[test]
    fn a_cipher_is_only_built_from_a_dedicated_key() {
        let mut config = Config::test_default();

        // 没有专用密钥 —— 不构造 cipher，也不从别的钥匙派生一把出来。
        config.mfa_encryption_key = None;
        assert!(SecretCipher::from_config(&config).unwrap().is_none());

        // 有专用密钥 —— 正常构造。
        config.mfa_encryption_key = Some(STANDARD.encode([7u8; 32]));
        assert!(SecretCipher::from_config(&config).unwrap().is_some());

        // 长度不对 —— 明确报错，而不是截断或补零。
        config.mfa_encryption_key = Some(STANDARD.encode([7u8; 16]));
        assert!(SecretCipher::from_config(&config).is_err());
    }
}

/// 长效 bearer 凭证的落库指纹。
///
/// 会话 JWT、OIDC 访问/刷新令牌、授权码此前都是**明文**落库：拿到一次数据库
/// 读权限就等于拿到全站在线用户的可用令牌。现在库里只留指纹，比对时把来件
/// 同样算一遍。
///
/// 用 SHA-256 而不是 Argon2 是刻意的：这些值都是 48 字符随机串或已签名 JWT，
/// 熵足够高，不存在离线爆破空间；而它们在每个请求上都要查一次，慢哈希会
/// 直接压垮鉴权路径。口令与备用码走的仍然是 Argon2。
///
/// 编码沿用 PKCE 校验那套 base64url-no-pad，全仓一种写法。
pub fn hash_bearer(secret: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

#[cfg(test)]
mod bearer_hash_tests {
    use super::hash_bearer;

    #[test]
    fn is_deterministic_and_collision_free_on_close_inputs() {
        assert_eq!(hash_bearer("abc"), hash_bearer("abc"));
        assert_ne!(hash_bearer("abc"), hash_bearer("abd"));
    }

    #[test]
    fn output_never_contains_the_input() {
        // 防止有人把它换成「加个前缀」之类的伪实现。
        let secret = "sk-live-0123456789abcdef";
        assert!(!hash_bearer(secret).contains(secret));
        assert_eq!(hash_bearer(secret).len(), 43); // 32 字节 base64url-no-pad
    }
}
