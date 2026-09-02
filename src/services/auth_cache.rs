//! 已认证请求的短时缓存。
//!
//! 每个带 Bearer 的请求原本要打两次库：查 `session` 表确认令牌未被吊销，
//! 再把 `user` 记录读出来。这是"登出能真正生效"的代价，但在高 QPS 下是实打实的开销。
//!
//! 这里用一个进程内的短 TTL 缓存把它摊薄，同时保证吊销依然及时：
//!
//! * 本实例发生的登出 / 全端登出 / 改密 / 账号停用会**立即**清掉对应缓存项，
//!   所以单实例部署下吊销仍是即时的；
//! * 多副本部署时，其它副本最多滞后一个 TTL（默认 5 秒）才感知到吊销；
//! * `AUTH_SESSION_CACHE_TTL_SECONDS=0` 可完全关闭缓存，回到每请求校验。

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::models::user::User;

/// 缓存项上限，超过后在写入时清理过期项。
const MAX_ENTRIES: usize = 10_000;

struct CacheEntry {
    user: User,
    /// 用于按用户批量失效。
    user_id: String,
    expires_at: Instant,
}

pub struct AuthCache {
    ttl: Option<Duration>,
    entries: RwLock<HashMap<[u8; 32], CacheEntry>>,
}

impl AuthCache {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            ttl: (ttl_seconds > 0).then(|| Duration::from_secs(ttl_seconds)),
            entries: RwLock::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.ttl.is_some()
    }

    fn key(token: &str) -> [u8; 32] {
        // 不用原始令牌当键，避免明文令牌散落在内存结构里。
        Sha256::digest(token.as_bytes()).into()
    }

    pub async fn get(&self, token: &str) -> Option<User> {
        self.ttl?;

        let key = Self::key(token);
        let entries = self.entries.read().await;
        let entry = entries.get(&key)?;

        if entry.expires_at <= Instant::now() {
            return None;
        }

        Some(entry.user.clone())
    }

    pub async fn insert(&self, token: &str, user_id: &str, user: &User) {
        let Some(ttl) = self.ttl else {
            return;
        };

        let mut entries = self.entries.write().await;

        if entries.len() >= MAX_ENTRIES {
            let now = Instant::now();
            entries.retain(|_, entry| entry.expires_at > now);
            // 清理后仍然满，就整体丢弃：缓存只是优化，宁可少命中也不无限增长。
            if entries.len() >= MAX_ENTRIES {
                entries.clear();
            }
        }

        entries.insert(
            Self::key(token),
            CacheEntry {
                user: user.clone(),
                user_id: user_id.to_string(),
                expires_at: Instant::now() + ttl,
            },
        );
    }

    /// 单个令牌失效（登出）。
    pub async fn invalidate_token(&self, token: &str) {
        if self.ttl.is_none() {
            return;
        }
        self.entries.write().await.remove(&Self::key(token));
    }

    /// 某个用户的所有令牌失效（全端登出、改密、账号停用）。
    pub async fn invalidate_user(&self, user_id: &str) {
        if self.ttl.is_none() {
            return;
        }
        self.entries
            .write()
            .await
            .retain(|_, entry| entry.user_id != user_id);
    }

    /// 清理过期项，由后台任务定期调用。
    pub async fn purge_expired(&self) {
        if self.ttl.is_none() {
            return;
        }
        let now = Instant::now();
        self.entries
            .write()
            .await
            .retain(|_, entry| entry.expires_at > now);
    }

    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::User;

    fn test_user(id: &str) -> User {
        User {
            id: Some(surrealdb::types::RecordId::new("user", id)),
            subject_id: None,
            email: format!("{id}@example.com"),
            username: id.to_string(),
            username_normalized: id.to_string(),
            password_hash: None,
            created_at: 0,
            updated_at: 0,
            is_email_verified: true,
            verification_token_hash: None,
            verification_token_expires_at: None,
            account_status: "Active".to_string(),
            membership_level: "FREE".to_string(),
            membership_expiry: None,
            last_login_at: None,
            last_login_ip: None,
        }
    }

    #[tokio::test]
    async fn caches_and_returns_user() {
        let cache = AuthCache::new(60);
        assert!(cache.enabled());
        assert!(cache.get("token-a").await.is_none());

        cache.insert("token-a", "alice", &test_user("alice")).await;

        assert_eq!(cache.get("token-a").await.expect("hit").username, "alice");
        assert!(cache.get("token-b").await.is_none());
    }

    #[tokio::test]
    async fn disabled_cache_never_stores_anything() {
        let cache = AuthCache::new(0);
        assert!(!cache.enabled());

        cache.insert("token-a", "alice", &test_user("alice")).await;

        assert!(cache.get("token-a").await.is_none());
        assert_eq!(cache.len().await, 0);
    }

    #[tokio::test]
    async fn logout_invalidates_only_that_token() {
        let cache = AuthCache::new(60);
        cache.insert("token-a", "alice", &test_user("alice")).await;
        cache.insert("token-b", "alice", &test_user("alice")).await;

        cache.invalidate_token("token-a").await;

        assert!(cache.get("token-a").await.is_none());
        assert!(cache.get("token-b").await.is_some());
    }

    #[tokio::test]
    async fn invalidating_a_user_drops_all_of_their_tokens() {
        let cache = AuthCache::new(60);
        cache.insert("token-a", "alice", &test_user("alice")).await;
        cache.insert("token-b", "alice", &test_user("alice")).await;
        cache.insert("token-c", "bob", &test_user("bob")).await;

        cache.invalidate_user("alice").await;

        assert!(cache.get("token-a").await.is_none());
        assert!(cache.get("token-b").await.is_none());
        assert!(cache.get("token-c").await.is_some());
    }

    #[tokio::test]
    async fn expired_entries_are_not_returned_and_get_purged() {
        let cache = AuthCache::new(1);
        cache.insert("token-a", "alice", &test_user("alice")).await;

        // 手动把过期时间推到过去，避免测试真的 sleep。
        {
            let mut entries = cache.entries.write().await;
            for entry in entries.values_mut() {
                entry.expires_at = Instant::now() - Duration::from_secs(1);
            }
        }

        assert!(cache.get("token-a").await.is_none());
        cache.purge_expired().await;
        assert_eq!(cache.len().await, 0);
    }
}
