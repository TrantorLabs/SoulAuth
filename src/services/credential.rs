//! 凭证的读写。
//!
//! 这一层存在的意义是：**除了它，没有别的地方知道口令哈希存在哪。** 口令曾经是
//! `user` 表的一列，于是注册、登录、首次设密、重置口令四条路径各自碰那一列；
//! 任何一条漏改（比如吊销时只清空了列）就成了一个谁都看不见的缺口。
//!
//! 见 `models::credential` 的模块文档与 `tests/conformance.rs` 的 `a2` / `b2`。

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;
use surrealdb::types::RecordId as Thing;

use crate::{
    error::{AuthError, Result},
    models::credential::{Credential, CredentialKind, CredentialStatus},
    services::database::Database,
};

#[derive(Clone)]
pub struct CredentialService {
    db: Arc<Database>,
}

impl CredentialService {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// 取这个身份的口令凭证，无论它当前什么状态。
    pub async fn find_password(&self, actor: &Thing) -> Result<Option<Credential>> {
        let rows: Vec<Credential> = self
            .db
            .query_take0_vec(
                "credential_find_password",
                "SELECT * FROM credential \
                 WHERE actor_identity_id = type::record('actor_identity', $actor_key) \
                   AND kind = $kind \
                 LIMIT 1",
                json!({
                    "actor_key": crate::utils::record_id::record_id_key_to_string(actor),
                    "kind": CredentialKind::Password.as_str(),
                }),
            )
            .await?;
        Ok(rows.into_iter().next())
    }

    /// 可用的口令哈希。`None` 表示这个身份现在不能用口令认证 —— 没设过、
    /// 被吊销了、或者那一行的密材是空的，三种情况对调用方是同一件事。
    pub async fn active_password_hash(&self, actor: &Thing) -> Result<Option<String>> {
        Ok(self
            .find_password(actor)
            .await?
            .filter(Credential::is_usable)
            .and_then(|c| c.secret_hash))
    }

    /// 这个身份现在能不能用口令认证。
    ///
    /// 响应里的 `has_password` 由它回答。调用方拿到的是布尔值而不是哈希 ——
    /// 只是为了回答一个是非题，没有理由让密材流经那条路径。
    pub async fn has_password(&self, actor: &Thing) -> Result<bool> {
        Ok(self.active_password_hash(actor).await?.is_some())
    }

    /// 设置或轮换口令。
    ///
    /// 先试更新：命中就是轮换，记下 `rotated_at` 并把状态拉回 `active`
    /// （吊销过的口令重新设置是一次有意的恢复，不该留着 `revoked` 状态）。
    /// 没命中才创建。两者都走唯一索引 `(actor_identity_id, kind)`，所以
    /// 并发的首次设置至多有一个成功，另一个会在这里重试到更新分支。
    pub async fn set_password(&self, actor: &Thing, secret_hash: String) -> Result<()> {
        let now = Utc::now().timestamp();
        let actor_key = crate::utils::record_id::record_id_key_to_string(actor);

        if self.rotate_password(&actor_key, &secret_hash, now).await? {
            return Ok(());
        }

        let credential = Credential::new_password(actor.clone(), secret_hash.clone());
        match self.db.create_record("credential", &credential).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // 唯一索引挡下来说明刚好有另一个请求创建了同一把凭证。
                // 这不是错误，按轮换再走一次即可。
                if self.rotate_password(&actor_key, &secret_hash, now).await? {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// 条件更新。返回 `true` 表示确实有一行被更新。
    async fn rotate_password(&self, actor_key: &str, secret_hash: &str, now: i64) -> Result<bool> {
        let updated: Vec<String> = self
            .db
            .query_take0_vec(
                "credential_rotate_password",
                "UPDATE credential SET \
                    secret_hash = $hash, \
                    status = $active, \
                    rotated_at = $now, \
                    revoked_at = NONE \
                 WHERE actor_identity_id = type::record('actor_identity', $actor_key) \
                   AND kind = $kind \
                 RETURN VALUE type::string(id)",
                json!({
                    "actor_key": actor_key,
                    "kind": CredentialKind::Password.as_str(),
                    "hash": secret_hash,
                    "active": CredentialStatus::Active.as_str(),
                    "now": now,
                }),
            )
            .await?;
        Ok(!updated.is_empty())
    }

    /// 吊销口令凭证。
    ///
    /// 吊销是**改状态**，不是删行或清空密材：清空之后「吊销过」与「从来没设过」
    /// 在库里长得一模一样，而这两件事在安全上完全不同。
    pub async fn revoke_password(&self, actor: &Thing) -> Result<()> {
        self.db
            .raw_query(
                "credential_revoke_password",
                "UPDATE credential SET status = $revoked, revoked_at = $now \
                 WHERE actor_identity_id = type::record('actor_identity', $actor_key) \
                   AND kind = $kind",
                json!({
                    "actor_key": crate::utils::record_id::record_id_key_to_string(actor),
                    "kind": CredentialKind::Password.as_str(),
                    "revoked": CredentialStatus::Revoked.as_str(),
                    "now": Utc::now().timestamp(),
                }),
            )
            .await?;
        Ok(())
    }

    /// 一次问清一批身份里谁有可用口令。
    ///
    /// 用户列表要对每一行回答 `has_password`。逐行查是 N+1：一页 50 个用户就是
    /// 50 次往返，而这个字段只是用来决定前端显示「设置口令」还是「修改口令」。
    pub async fn identities_with_password(&self, actor_keys: &[String]) -> Result<Vec<String>> {
        if actor_keys.is_empty() {
            return Ok(Vec::new());
        }
        self.db
            .query_take0_vec(
                "credential_identities_with_password",
                "SELECT VALUE type::string(actor_identity_id) FROM credential \
                 WHERE kind = $kind \
                   AND status = $active \
                   AND secret_hash != NONE \
                   AND type::string(actor_identity_id) IN $wanted",
                json!({
                    "kind": CredentialKind::Password.as_str(),
                    "active": CredentialStatus::Active.as_str(),
                    "wanted": actor_keys
                        .iter()
                        .map(|k| format!("actor_identity:{k}"))
                        .collect::<Vec<_>>(),
                }),
            )
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
}
