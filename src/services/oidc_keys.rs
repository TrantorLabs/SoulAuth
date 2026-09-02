//! OIDC ID Token 的签名密钥管理。
//!
//! 以前 ID Token 用 `jwt_secret` 做 HS256 对称签名，同时 `/api/oidc/jwks` 返回空数组 ——
//! 任何第三方 RP 都无法独立验签（除非共享服务端密钥，这本身就是个安全问题）。
//! 现在统一改成 RS256：
//!
//! * `OIDC_RSA_PRIVATE_KEY_PEM` 或 `OIDC_RSA_PRIVATE_KEY_PATH` 提供私钥（PKCS#8 或 PKCS#1）；
//! * 都没配置时启动阶段临时生成一把并打 WARN —— 进程重启后 kid 会变、已签发的
//!   ID Token 无法再验签，所以生产环境必须显式配置。

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use rsa::{
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    traits::PublicKeyParts,
    RsaPrivateKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::config::Config;

const RSA_KEY_BITS: usize = 2048;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwkKey {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

pub struct OidcSigningKey {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    kid: String,
    jwk: JwkKey,
}

impl OidcSigningKey {
    pub fn load(config: &Config) -> Result<Self> {
        let (private_key, source) = match load_configured_pem(config)? {
            Some(pem) => (parse_private_key(&pem)?, "configured"),
            None => {
                warn!(
                    "Neither OIDC_RSA_PRIVATE_KEY_PEM nor OIDC_RSA_PRIVATE_KEY_PATH is set; \
                     generating an ephemeral RSA key. ID tokens signed with it become \
                     unverifiable after a restart — configure a persistent key in production."
                );
                let mut rng = rand::thread_rng();
                (
                    RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)
                        .context("Failed to generate ephemeral RSA key")?,
                    "ephemeral",
                )
            }
        };

        let public_key = private_key.to_public_key();

        let private_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .context("Failed to encode RSA private key as PKCS#8 PEM")?;
        let public_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .context("Failed to encode RSA public key as PEM")?;

        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .context("Failed to build JWT encoding key from RSA private key")?;
        let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .context("Failed to build JWT decoding key from RSA public key")?;

        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
        let kid = compute_kid(&public_key)?;

        info!(source, kid = %kid, "OIDC ID token signing key ready (RS256)");

        Ok(Self {
            encoding_key,
            decoding_key,
            kid: kid.clone(),
            jwk: JwkKey {
                kty: "RSA".to_string(),
                use_: "sig".to_string(),
                alg: "RS256".to_string(),
                kid,
                n,
                e,
            },
        })
    }

    pub fn encoding_key(&self) -> &EncodingKey {
        &self.encoding_key
    }

    pub fn decoding_key(&self) -> &DecodingKey {
        &self.decoding_key
    }

    /// ID Token 的 JOSE 头：RS256 + kid，让 RP 能从 JWKS 里定位公钥。
    pub fn jwt_header(&self) -> Header {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        header
    }

    pub fn jwks(&self) -> JwksResponse {
        JwksResponse {
            keys: vec![self.jwk.clone()],
        }
    }
}

fn load_configured_pem(config: &Config) -> Result<Option<String>> {
    if let Some(pem) = &config.oidc_rsa_private_key_pem {
        // 便于用单行环境变量承载 PEM。
        return Ok(Some(pem.replace("\\n", "\n")));
    }

    if let Some(path) = &config.oidc_rsa_private_key_path {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read OIDC RSA private key from {path}"))?;
        return Ok(Some(pem));
    }

    Ok(None)
}

fn parse_private_key(pem: &str) -> Result<RsaPrivateKey> {
    let pem = pem.trim();

    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(pem) {
        return Ok(key);
    }

    RsaPrivateKey::from_pkcs1_pem(pem)
        .map_err(|e| anyhow!("Failed to parse OIDC RSA private key (PKCS#8 or PKCS#1 PEM): {e}"))
}

fn compute_kid(public_key: &rsa::RsaPublicKey) -> Result<String> {
    let der = public_key
        .to_public_key_der()
        .context("Failed to encode RSA public key as DER")?;
    let digest = Sha256::digest(der.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(&digest[..16]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(pem: Option<String>) -> Config {
        Config {
            oidc_rsa_private_key_pem: pem,
            ..Config::test_default()
        }
    }

    #[test]
    fn generates_ephemeral_key_and_exposes_single_jwk() {
        let key = OidcSigningKey::load(&test_config(None)).expect("signing key");
        let jwks = key.jwks();

        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[0].alg, "RS256");
        assert!(!jwks.keys[0].n.is_empty());
        assert!(!jwks.keys[0].kid.is_empty());
        assert_eq!(key.jwt_header().alg, Algorithm::RS256);
        assert_eq!(key.jwt_header().kid, Some(jwks.keys[0].kid.clone()));
    }

    #[test]
    fn loads_configured_pkcs8_pem_and_is_stable_across_loads() {
        let mut rng = rand::thread_rng();
        let generated = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS).expect("key");
        let pem = generated
            .to_pkcs8_pem(LineEnding::LF)
            .expect("pem")
            .to_string();

        let first = OidcSigningKey::load(&test_config(Some(pem.clone()))).expect("first");
        let second = OidcSigningKey::load(&test_config(Some(pem))).expect("second");

        assert_eq!(first.jwks().keys[0].kid, second.jwks().keys[0].kid);
        assert_eq!(first.jwks().keys[0].n, second.jwks().keys[0].n);
    }

    #[test]
    fn rejects_garbage_pem() {
        let result = OidcSigningKey::load(&test_config(Some("not a pem".to_string())));
        assert!(result.is_err());
    }
}
