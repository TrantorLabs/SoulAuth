//! AIActor 的注册与认证。
//!
//! 认证是两步：
//!
//! ```text
//! ① POST /api/actors/challenge      {actor_id}
//!    ← {nonce, expires_at}          服务端签发，一次性，绑定到该 actor
//!
//! ② POST /api/actors/authenticate   {actor_id, nonce, algorithm, signature}
//!    ← {token, ...}                 签名通过则换到一枚会话令牌
//! ```
//!
//! 被签名的字节由 [`AiActorProof::canonical_payload`] 唯一确定，13 项冻结内容
//! 见 `models::ai_actor` 的模块文档。
//!
//! # 与人类登录路径的关系
//!
//! 完全不共用。这里不碰 `user`、`human_account`、口令、MFA、账号锁定。
//! 共用的只有最后一步 —— 都往 `session` 表落一行、都签一枚 JWT ——
//! 因为「会话」本来就该是主体无关的。
//!
//! # 本 Release 的边界
//!
//! Agent 换到的会话令牌**只能**用于 `/api/actors/me`。RBAC 仍然建立在 `user`
//! 行之上（`user_role.user_id`），把它扩展到 Actor 是另一件事。这条边界是
//! 明写的，不是遗漏：宁可让 Agent 令牌在人类端点上被明确拒绝，也不要让它
//! 因为某个提取器碰巧能解析而拿到不该有的访问。

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use surrealdb::types::RecordId as Thing;
use tracing::{debug, warn};

use crate::{
    config::Config,
    error::{AuthError, Result},
    models::{
        actor_identity::ActorIdentity,
        ai_actor::{
            AiActorChallenge, AiActorCredential, AiActorProof, CredentialStatus,
            ALLOWED_ALGORITHMS, CHALLENGE_TTL_SECONDS, ED25519_PUBLIC_KEY_LEN,
            ED25519_SIGNATURE_LEN,
        },
        session::Session,
    },
    services::{database::Database, identity::IdentityService},
    utils::record_id::record_id_key_to_string,
};

/// 一枚刚签发的挑战，交给调用方去签名。
#[derive(Debug, Clone, serde::Serialize)]
pub struct IssuedChallenge {
    pub actor_id: String,
    pub nonce: String,
    pub expires_at: i64,
    /// 被签名的**完整字节**，原样回给调用方。
    ///
    /// 让客户端自己拼这四行是可以的，但那意味着每个 SDK 都要正确实现一遍
    /// canonicalization，而拼错的表现是「签名莫名其妙不通过」——最难排查的
    /// 那类问题。直接给出来，客户端只需签名，不需要理解格式。
    ///
    /// 这不降低安全性：payload 里没有任何秘密，服务端**仍然独立重算一遍**
    /// 再验签，绝不使用客户端回传的 payload。
    pub payload: String,
    pub algorithm: &'static str,
}

/// 认证成功后的产物。
pub struct ActorSession {
    pub token: String,
    pub actor_id: String,
    pub expires_at: i64,
    pub credential_label: String,
}

#[derive(Clone)]
pub struct AiActorService {
    db: Arc<Database>,
    identity: IdentityService,
    config: Config,
}

impl AiActorService {
    pub fn new(db: Arc<Database>, config: Config) -> Self {
        Self {
            identity: IdentityService::new(db.clone()),
            db,
            config,
        }
    }

    // ───────────────────────── 注册 ─────────────────────────

    /// 注册一个 AIActor 并挂上它的第一枚密钥。
    ///
    /// 顺序是先建身份、再建凭证：反过来的话，公钥格式不合法时会留下一个
    /// 没有任何凭证、永远无法认证的孤儿身份。
    pub async fn register(
        &self,
        public_key: &str,
        label: &str,
    ) -> Result<(ActorIdentity, AiActorCredential)> {
        Self::validate_public_key(public_key)?;

        let actor = self.identity.create_ai_actor().await?;
        let actor_id = actor
            .id
            .clone()
            .ok_or_else(|| AuthError::DatabaseError("actor_identity 落库后没有 id".into()))?;

        let credential = self.add_credential_for(actor_id, public_key, label).await?;
        Ok((actor, credential))
    }

    /// 给一个已有 Actor 追加密钥。
    ///
    /// 允许多枚并存正是为了安全轮换：先加新的，确认 Agent 用新钥能认证，
    /// 再吊销旧的。不允许并存就只能"停机换钥"。
    pub async fn add_credential(
        &self,
        actor_key: &str,
        public_key: &str,
        label: &str,
    ) -> Result<AiActorCredential> {
        Self::validate_public_key(public_key)?;
        let actor = self.require_ai_actor(actor_key).await?;
        let actor_id = actor
            .id
            .clone()
            .ok_or_else(|| AuthError::DatabaseError("actor_identity 没有 id".into()))?;
        self.add_credential_for(actor_id, public_key, label).await
    }

    async fn add_credential_for(
        &self,
        actor_id: Thing,
        public_key: &str,
        label: &str,
    ) -> Result<AiActorCredential> {
        let credential = AiActorCredential::new(actor_id, public_key, label);
        self.db
            .create_record("ai_actor_credential", &credential)
            .await
            .map_err(|e| {
                // 唯一索引挡住的是「同一枚公钥注册两次」。两个 Actor 共用一把
                // 钥匙会让审计里的归因失去意义，所以这是**冲突**不是内部错误 ——
                // 调用方收到 500 会以为是服务故障然后重试，再撞一次。
                //
                // 识别方式与 `services::auth::translate_unique_violation` 一致：
                // SurrealDB 报的是
                //   Database index `xxx_idx` already contains '...', with record `...`
                let AuthError::DatabaseError(message) = &e else {
                    return e;
                };
                if message.contains("already contains")
                    && message.contains("ai_actor_credential_key_idx")
                {
                    AuthError::BadRequest("This public key is already registered".into())
                } else {
                    e
                }
            })
    }

    /// 吊销一枚密钥。
    ///
    /// 不删记录：删掉之后，历史审计里"这次认证用的是哪把钥匙"就无从追溯了。
    /// 状态改成 `revoked` 即可让它再也无法通过 [`Self::authenticate`]。
    pub async fn revoke_credential(&self, actor_key: &str, credential_key: &str) -> Result<()> {
        let updated: Vec<serde_json::Value> = self
            .db
            .query_take0_vec(
                "ai_actor_revoke_credential",
                "UPDATE type::record('ai_actor_credential', $cred) \
                 SET status = $revoked, revoked_at = $now \
                 WHERE actor_identity_id = type::record('actor_identity', $actor) \
                   AND status = $active \
                 RETURN type::string(id) AS id",
                serde_json::json!({
                    "cred": credential_key,
                    "actor": actor_key,
                    "revoked": CredentialStatus::Revoked.as_str(),
                    "active": CredentialStatus::Active.as_str(),
                    "now": Utc::now().timestamp(),
                }),
            )
            .await?;

        if updated.is_empty() {
            // 不存在、不属于这个 actor、已经吊销过 —— 对外同一个答复。
            // 区分它们等于给调用方一条枚举别人凭证的信道。
            return Err(AuthError::NotFound("Credential not found".into()));
        }
        Ok(())
    }

    /// 列出某个 Actor 的密钥。返回的只有公钥，没有任何秘密。
    pub async fn list_credentials(&self, actor_key: &str) -> Result<Vec<AiActorCredential>> {
        self.db
            .query_take0_vec(
                "ai_actor_list_credentials",
                "SELECT * FROM ai_actor_credential \
                 WHERE actor_identity_id = type::record('actor_identity', $actor) \
                 ORDER BY created_at DESC",
                serde_json::json!({ "actor": actor_key }),
            )
            .await
    }

    pub async fn list_actors(&self) -> Result<Vec<ActorIdentity>> {
        self.identity.list_ai_actors().await
    }

    pub async fn find_actor(&self, actor_key: &str) -> Result<Option<ActorIdentity>> {
        self.identity.find_actor_by_id(actor_key).await
    }

    // ───────────────────────── 认证 ─────────────────────────

    /// 第一步：签发挑战。
    ///
    /// 这个端点是公开的，因此它**不能**成为「这个 actor 存不存在」的探测信道 ——
    /// 但它也必须把 nonce 绑定到具体 actor 才有意义。折中是：actor 不存在或
    /// 不可认证时返回与"签名失败"同族的 401，而不是 404。
    pub async fn issue_challenge(&self, actor_key: &str) -> Result<IssuedChallenge> {
        let actor = self
            .require_ai_actor(actor_key)
            .await
            .map_err(|_| AuthError::InvalidCredentials)?;

        if !actor.can_authenticate() {
            return Err(AuthError::InvalidCredentials);
        }

        let actor_id = actor
            .id
            .clone()
            .ok_or_else(|| AuthError::DatabaseError("actor_identity 没有 id".into()))?;

        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let nonce = URL_SAFE_NO_PAD.encode(raw);

        let now = Utc::now();
        let expires_at = (now + Duration::seconds(CHALLENGE_TTL_SECONDS)).timestamp();

        let challenge = AiActorChallenge {
            id: None,
            actor_identity_id: actor_id,
            nonce: nonce.clone(),
            issued_at: now.timestamp(),
            expires_at,
            consumed: false,
        };
        self.db
            .create_record("ai_actor_challenge", &challenge)
            .await?;

        let actor_address = format!("actor_identity:{actor_key}");
        Ok(IssuedChallenge {
            payload: AiActorProof::canonical_payload(self.issuer(), &actor_address, &nonce),
            actor_id: actor_address,
            nonce,
            expires_at,
            algorithm: ALLOWED_ALGORITHMS[0],
        })
    }

    /// 第二步：校验签名，换会话。
    ///
    /// 顺序是刻意的：**先原子消费挑战，再验签**。
    ///
    /// 反过来（先验签、成功后再标记已用）会留下一个并发窗口 —— 同一枚 nonce
    /// 的两个并发请求都能验签通过，都拿到会话。授权码与刷新令牌用的是同一套
    /// 写法，这里没有理由例外。
    ///
    /// 代价是一次失败的尝试也会烧掉这枚挑战。那正是想要的：挑战本来就是
    /// 一次性的，允许对同一枚 nonce 反复试签名等于把它变成了爆破靶子。
    pub async fn authenticate(
        &self,
        actor_key: &str,
        nonce: &str,
        algorithm: &str,
        signature_b64: &str,
        user_agent: &str,
        ip_address: &str,
    ) -> Result<ActorSession> {
        // 算法不接受协商。放在最前是因为它最便宜，且不需要碰数据库。
        if !ALLOWED_ALGORITHMS.contains(&algorithm) {
            return Err(AuthError::BadRequest(format!(
                "Unsupported algorithm; only {} is accepted",
                ALLOWED_ALGORITHMS[0]
            )));
        }

        let signature = Self::decode_signature(signature_b64)?;

        // ① 原子消费。抢不到就说明这枚 nonce 不存在 / 已用过 / 已过期。
        let consumed: Vec<serde_json::Value> = self
            .db
            .query_take0_vec(
                "ai_actor_consume_challenge",
                "UPDATE ai_actor_challenge SET consumed = true \
                 WHERE nonce = $nonce \
                   AND consumed = false \
                   AND expires_at > $now \
                   AND actor_identity_id = type::record('actor_identity', $actor) \
                 RETURN type::string(actor_identity_id) AS actor_identity_id",
                serde_json::json!({
                    "nonce": nonce,
                    "actor": actor_key,
                    "now": Utc::now().timestamp(),
                }),
            )
            .await?;

        if consumed.len() != 1 {
            // 四种失败对外同一个答复：不存在、已消费、已过期、绑的是别的 actor。
            // 区分它们会泄露「这枚 nonce 曾经存在过」之类的信息。
            debug!("AIActor challenge not claimable for actor {actor_key}");
            return Err(AuthError::InvalidCredentials);
        }

        // ② 身份仍须可认证。挑战可能是在停用之前签发的。
        let actor = self
            .require_ai_actor(actor_key)
            .await
            .map_err(|_| AuthError::InvalidCredentials)?;
        if !actor.can_authenticate() {
            return Err(AuthError::InvalidCredentials);
        }

        // ③ 服务端**独立重算** payload，绝不使用客户端回传的任何 payload。
        let actor_address = format!("actor_identity:{actor_key}");
        let payload = AiActorProof::canonical_payload(self.issuer(), &actor_address, nonce);

        // ④ 逐枚可用密钥验签。多枚并存是轮换的前提。
        let credentials = self.list_credentials(actor_key).await?;
        let mut matched: Option<AiActorCredential> = None;
        for credential in credentials.into_iter().filter(|c| c.can_authenticate()) {
            if Self::verify_with(&credential.public_key, payload.as_bytes(), &signature) {
                matched = Some(credential);
                break;
            }
        }

        let Some(credential) = matched else {
            warn!("AIActor {actor_key} presented an unverifiable proof");
            return Err(AuthError::InvalidCredentials);
        };

        self.touch_credential(&credential).await;

        // ⑤ 换会话。
        self.issue_session(&actor, &credential, user_agent, ip_address)
            .await
    }

    // ─────────────────────── 内部 ───────────────────────

    fn issuer(&self) -> &str {
        &self.config.app_url
    }

    /// 只接受 32 字节、能真正解析成 Ed25519 点的公钥。
    ///
    /// 长度对但不在曲线上的字节串会在这里被拒绝，而不是留到第一次认证时
    /// 才以「签名不通过」的形式暴露 —— 那时候没人知道是钥匙注册错了。
    fn validate_public_key(public_key: &str) -> Result<()> {
        let raw = URL_SAFE_NO_PAD.decode(public_key).map_err(|_| {
            AuthError::BadRequest("public_key must be base64url (no padding)".into())
        })?;

        let bytes: [u8; ED25519_PUBLIC_KEY_LEN] = raw.try_into().map_err(|_| {
            AuthError::BadRequest(format!(
                "public_key must decode to exactly {ED25519_PUBLIC_KEY_LEN} bytes"
            ))
        })?;

        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| AuthError::BadRequest("public_key is not a valid Ed25519 key".into()))?;
        Ok(())
    }

    fn decode_signature(signature_b64: &str) -> Result<Signature> {
        let raw = URL_SAFE_NO_PAD.decode(signature_b64).map_err(|_| {
            AuthError::BadRequest("signature must be base64url (no padding)".into())
        })?;
        let bytes: [u8; ED25519_SIGNATURE_LEN] = raw.try_into().map_err(|_| {
            AuthError::BadRequest(format!(
                "signature must decode to exactly {ED25519_SIGNATURE_LEN} bytes"
            ))
        })?;
        Ok(Signature::from_bytes(&bytes))
    }

    /// 单枚密钥验签。任何解析失败都当作"这枚钥匙不匹配"，不当作错误 ——
    /// 一枚坏掉的历史密钥不该让整次认证失败，它只是验不过。
    fn verify_with(public_key: &str, payload: &[u8], signature: &Signature) -> bool {
        let Ok(raw) = URL_SAFE_NO_PAD.decode(public_key) else {
            return false;
        };
        let Ok(bytes) = <[u8; ED25519_PUBLIC_KEY_LEN]>::try_from(raw) else {
            return false;
        };
        let Ok(key) = VerifyingKey::from_bytes(&bytes) else {
            return false;
        };
        key.verify(payload, signature).is_ok()
    }

    /// 记录最近使用时间。失败只打日志 —— 它是运维信息，不该让认证失败。
    async fn touch_credential(&self, credential: &AiActorCredential) {
        let Some(id) = credential.id.as_ref() else {
            return;
        };
        let result = self
            .db
            .raw_query(
                "ai_actor_touch_credential",
                "UPDATE type::record('ai_actor_credential', $key) SET last_used_at = $now",
                serde_json::json!({
                    "key": record_id_key_to_string(id),
                    "now": Utc::now().timestamp(),
                }),
            )
            .await;
        if let Err(e) = result {
            warn!("failed to update credential last_used_at: {e}");
        }
    }

    /// 取身份根，并确认它确实是个 AIActor。
    ///
    /// 拿人类的 actor_id 走这条路必须失败：否则这条不需要口令的路径就成了
    /// 绕过人类认证的后门。
    async fn require_ai_actor(&self, actor_key: &str) -> Result<ActorIdentity> {
        let actor = self
            .identity
            .find_actor_by_id(actor_key)
            .await?
            .ok_or_else(|| AuthError::NotFound("Actor not found".into()))?;

        if actor.actor_kind != crate::models::actor_identity::ActorKind::AiActor.as_str() {
            return Err(AuthError::NotFound("Actor not found".into()));
        }
        Ok(actor)
    }

    /// 给 Actor 签一枚会话令牌。
    ///
    /// `session.user_id` 本来就是 `record<actor_identity>`，所以这里不需要任何
    /// 特殊表 —— 会话是主体无关的。区别只在 claims：`sub` 是 actor 的 record key，
    /// `subject_type` 是 `Agent`。人类端点的提取器据此明确拒绝它。
    async fn issue_session(
        &self,
        actor: &ActorIdentity,
        credential: &AiActorCredential,
        user_agent: &str,
        ip_address: &str,
    ) -> Result<ActorSession> {
        use jsonwebtoken::{encode, EncodingKey, Header};

        let actor_id = actor
            .id
            .clone()
            .ok_or_else(|| AuthError::DatabaseError("actor_identity 没有 id".into()))?;
        let actor_key = record_id_key_to_string(&actor_id);

        let now = Utc::now();
        let ttl = if self.config.jwt_expiration > 0 {
            self.config.jwt_expiration
        } else {
            86_400
        };
        let exp = now + Duration::seconds(ttl);

        let session_id = Thing::new("session", uuid::Uuid::new_v4().to_string());
        let session_key = record_id_key_to_string(&session_id);

        let claims = crate::utils::jwt::Claims {
            sub: actor_key.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            session_id: Some(session_key),
            subject_type: Some(crate::models::subject::SubjectType::Agent),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthError::TokenError(e.to_string()))?;

        let session = Session {
            id: Some(session_id),
            user_id: actor_id,
            token_hash: crate::utils::crypto::hash_bearer(&token),
            expires_at: exp.timestamp(),
            created_at: now.timestamp(),
            user_agent: user_agent.to_string(),
            ip_address: ip_address.to_string(),
        };
        self.db.create_record("session", &session).await?;

        Ok(ActorSession {
            token,
            actor_id: format!("actor_identity:{actor_key}"),
            expires_at: exp.timestamp(),
            credential_label: credential.label.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> (SigningKey, String) {
        // 固定种子：单测不需要随机性，可复现更重要。
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let public = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
        (signing, public)
    }

    #[test]
    fn a_correct_signature_verifies() {
        let (signing, public) = keypair();
        let payload =
            AiActorProof::canonical_payload("https://auth.example", "actor_identity:a1", "nonce-1");
        let sig = signing.sign(payload.as_bytes());
        assert!(AiActorService::verify_with(
            &public,
            payload.as_bytes(),
            &sig
        ));
    }

    #[test]
    fn a_signature_over_a_different_nonce_does_not_verify() {
        // 重放到另一枚挑战上必须失败。
        let (signing, public) = keypair();
        let signed =
            AiActorProof::canonical_payload("https://a.example", "actor_identity:a1", "n1");
        let checked =
            AiActorProof::canonical_payload("https://a.example", "actor_identity:a1", "n2");
        let sig = signing.sign(signed.as_bytes());
        assert!(!AiActorService::verify_with(
            &public,
            checked.as_bytes(),
            &sig
        ));
    }

    #[test]
    fn a_signature_from_another_deployment_does_not_verify() {
        // 跨部署重放：同一个 actor、同一枚 nonce，只有 issuer 不同。
        let (signing, public) = keypair();
        let signed = AiActorProof::canonical_payload("https://a.example", "actor_identity:a1", "n");
        let checked =
            AiActorProof::canonical_payload("https://b.example", "actor_identity:a1", "n");
        let sig = signing.sign(signed.as_bytes());
        assert!(!AiActorService::verify_with(
            &public,
            checked.as_bytes(),
            &sig
        ));
    }

    #[test]
    fn a_signature_bound_to_another_actor_does_not_verify() {
        let (signing, public) = keypair();
        let signed = AiActorProof::canonical_payload("https://a.example", "actor_identity:a1", "n");
        let checked =
            AiActorProof::canonical_payload("https://a.example", "actor_identity:a2", "n");
        let sig = signing.sign(signed.as_bytes());
        assert!(!AiActorService::verify_with(
            &public,
            checked.as_bytes(),
            &sig
        ));
    }

    #[test]
    fn another_keys_signature_does_not_verify() {
        let (_, public) = keypair();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let payload =
            AiActorProof::canonical_payload("https://a.example", "actor_identity:a1", "n");
        let sig = attacker.sign(payload.as_bytes());
        assert!(!AiActorService::verify_with(
            &public,
            payload.as_bytes(),
            &sig
        ));
    }

    #[test]
    fn malformed_public_keys_are_rejected_at_registration() {
        for bad in [
            "not base64!!",
            "",
            // 长度不对（16 字节）
            &URL_SAFE_NO_PAD.encode([0u8; 16]),
            // 带 padding 的 base64
            "AAAA=",
        ] {
            assert!(
                AiActorService::validate_public_key(bad).is_err(),
                "应当拒绝 {bad:?}"
            );
        }
        let (_, good) = keypair();
        assert!(AiActorService::validate_public_key(&good).is_ok());
    }

    #[test]
    fn malformed_signatures_are_rejected_before_any_db_work() {
        assert!(AiActorService::decode_signature("nope!!").is_err());
        assert!(AiActorService::decode_signature(&URL_SAFE_NO_PAD.encode([0u8; 8])).is_err());
        assert!(AiActorService::decode_signature(&URL_SAFE_NO_PAD.encode([0u8; 64])).is_ok());
    }

    #[test]
    fn a_broken_stored_key_does_not_blow_up_verification() {
        // 库里存了一枚坏公钥时，它只是"验不过"，不该让整次认证报错。
        let (signing, _) = keypair();
        let payload =
            AiActorProof::canonical_payload("https://a.example", "actor_identity:a1", "n");
        let sig = signing.sign(payload.as_bytes());
        assert!(!AiActorService::verify_with(
            "garbage",
            payload.as_bytes(),
            &sig
        ));
    }
}
