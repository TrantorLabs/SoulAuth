use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::services::database::Database;

/// 撞上乐观并发时的重试次数。与账号锁定服务同口径。
const WRITE_CONFLICT_RETRIES: u32 = 4;

/// 速率限制规则
#[derive(Debug, Clone)]
pub struct RateLimitRule {
    /// 时间窗口大小
    pub window_duration: Duration,
    /// 时间窗口内最大请求数
    pub max_requests: u32,
    /// 阻塞时长
    pub block_duration: Duration,
}

impl Default for RateLimitRule {
    fn default() -> Self {
        Self {
            window_duration: Duration::from_secs(60), // 1分钟窗口
            max_requests: 10,                         // 最多10次请求
            block_duration: Duration::from_secs(300), // 阻塞5分钟
        }
    }
}

/// 请求记录
#[derive(Debug, Clone)]
struct RequestRecord {
    /// 请求时间戳列表
    timestamps: Vec<Instant>,
    /// 阻塞开始时间
    blocked_until: Option<Instant>,
}

impl RequestRecord {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            blocked_until: None,
        }
    }

    /// 检查是否被阻塞
    fn is_blocked(&self) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            Instant::now() < blocked_until
        } else {
            false
        }
    }

    /// 清理过期的时间戳
    fn cleanup_expired(&mut self, window_duration: Duration) {
        let cutoff = Instant::now() - window_duration;
        self.timestamps.retain(|&timestamp| timestamp > cutoff);
    }

    /// 添加请求时间戳
    fn add_request(&mut self) {
        self.timestamps.push(Instant::now());
    }

    /// 设置阻塞
    fn block(&mut self, block_duration: Duration) {
        self.blocked_until = Some(Instant::now() + block_duration);
    }

    /// 检查请求数是否超限
    fn is_rate_limited(&self, max_requests: u32) -> bool {
        self.timestamps.len() >= max_requests as usize
    }
}

/// 一次限流判定的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// 放行。
    Allowed,
    /// 这次请求正好把配额用超，阻塞由它触发。值得记一条审计。
    JustBlocked,
    /// 已经在阻塞期内。不必重复记审计，否则被限流的流量有多大、审计写入就有多大。
    StillBlocked,
}

impl RateLimitDecision {
    pub fn allowed(self) -> bool {
        matches!(self, RateLimitDecision::Allowed)
    }
}

/// 速率限制器
pub struct RateLimiter {
    /// 默认规则
    default_rule: RateLimitRule,
    /// 特定端点的规则
    endpoint_rules: HashMap<String, RateLimitRule>,
    /// 请求记录存储（本进程内）
    records: Arc<RwLock<HashMap<String, RequestRecord>>>,
    /// 跨副本共享的计数后端。为 `None` 时退化成纯进程内限流。
    ///
    /// **只对显式配了端点规则的端点生效**，默认规则（一般 API）仍走进程内。
    /// 这条线不是随意划的：显式配规则的恰好是登录 / 注册 / 改密 / 验邮箱这些
    /// 会被暴力破解的端点，它们本身是低频的 —— 高频就是攻击本身；
    /// 而一般 API 是每个请求都要过的热路径，给它加一次数据库往返
    /// 是把限流器变成新的瓶颈。以后新增敏感端点只要配上端点规则，
    /// 就自动获得跨副本计数，不需要再维护第二份名单。
    shared: Option<Arc<Database>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    /// 创建新的速率限制器
    pub fn new() -> Self {
        Self {
            default_rule: RateLimitRule::default(),
            endpoint_rules: HashMap::new(),
            records: Arc::new(RwLock::new(HashMap::new())),
            shared: None,
        }
    }

    /// 接上跨副本共享的计数后端。
    ///
    /// 不接的话，限流状态只在本进程内存里：部署 N 个副本，攻击者把尝试摊到
    /// 各副本上就能拿到 N 倍配额，暴力破解防护被直接稀释 N 倍。
    pub fn with_shared_backend(mut self, db: Arc<Database>) -> Self {
        self.shared = Some(db);
        self
    }

    /// 设置默认规则
    pub fn with_default_rule(mut self, rule: RateLimitRule) -> Self {
        self.default_rule = rule;
        self
    }

    /// 为特定端点设置规则
    pub fn with_endpoint_rule(mut self, endpoint: String, rule: RateLimitRule) -> Self {
        self.endpoint_rules.insert(endpoint, rule);
        self
    }

    /// 获取端点的规则
    fn get_rule(&self, endpoint: &str) -> &RateLimitRule {
        self.endpoint_rules
            .get(endpoint)
            .unwrap_or(&self.default_rule)
    }

    /// 计数桶的键：**必须**按 (客户端, 端点) 组合。
    ///
    /// 以前只用客户端 IP 做键：规则按端点挑，计数桶却是全局共用的。后果是
    /// 所有端点共享同一个配额，而生效的上限取决于你恰好打到哪个端点；
    /// 任何一个端点触发阻塞，该 IP 的**全部**端点一起被封。
    fn record_key(client_key: &str, endpoint: &str) -> String {
        format!("{client_key}\u{1}{endpoint}")
    }

    /// 检查速率限制。放行返回 `true`。
    ///
    /// 只关心"能不能过"的调用方用这个；需要区分"刚被封"和"封着呢"的用
    /// [`Self::check_rate_limit_verbose`]。
    pub async fn check_rate_limit(
        &self,
        key: &str,
        endpoint: &str,
    ) -> Result<bool, crate::error::AppError> {
        Ok(self
            .check_rate_limit_verbose(key, endpoint)
            .await?
            .allowed())
    }

    /// 同 [`Self::check_rate_limit`]，但会告诉调用方这次是不是**刚**触发阻塞。
    ///
    /// 中间件靠它决定要不要写审计：被限流的请求每一个都记一条的话，洪水打过来
    /// 时返回 429 很便宜、每条 429 却换来一次数据库写入 —— 限流器反倒成了放大器。
    pub async fn check_rate_limit_verbose(
        &self,
        key: &str,
        endpoint: &str,
    ) -> Result<RateLimitDecision, crate::error::AppError> {
        let rule = self.get_rule(endpoint);
        let mut records = self.records.write().await;

        // 获取或创建记录
        let record = records
            .entry(Self::record_key(key, endpoint))
            .or_insert_with(RequestRecord::new);

        // 检查是否被阻塞
        if record.is_blocked() {
            debug!(
                "Rate limit blocked for key: {}, endpoint: {}",
                key, endpoint
            );
            return Ok(RateLimitDecision::StillBlocked);
        }

        // 清理过期记录
        record.cleanup_expired(rule.window_duration);

        // 检查是否超过限制
        if record.is_rate_limited(rule.max_requests) {
            // 触发阻塞
            record.block(rule.block_duration);
            warn!(
                "Rate limit exceeded for key: {}, endpoint: {}, blocking for {:?}",
                key, endpoint, rule.block_duration
            );
            return Ok(RateLimitDecision::JustBlocked);
        }

        // 记录请求
        record.add_request();
        // 每个请求都会走到这里，放 info 会把日志淹掉（也拖慢高 QPS 下的写入）。
        debug!(
            "Rate limit check passed for key: {}, endpoint: {}, requests: {}/{}",
            key,
            endpoint,
            record.timestamps.len(),
            rule.max_requests
        );

        // 进程内这一关过了，还要过跨副本这一关。锁在这里就得放掉：
        // 共享计数要走一次数据库往返，攥着写锁会把本进程的所有请求串起来。
        let rule = rule.clone();
        drop(records);

        self.check_shared(key, endpoint, &rule).await
    }

    /// 跨副本计数。未接后端、或该端点走默认规则时直接放行（判定已由进程内那层给出）。
    ///
    /// 共享层出错时**降级为放行**，只留一条 error 日志：进程内那层仍在生效，
    /// 而反过来做（数据库一抖就拒登录）等于给自己造一个拒绝服务开关。
    /// 这是一次明确的取舍，不是疏忽。
    async fn check_shared(
        &self,
        key: &str,
        endpoint: &str,
        rule: &RateLimitRule,
    ) -> Result<RateLimitDecision, crate::error::AppError> {
        let Some(db) = self.shared.as_ref() else {
            return Ok(RateLimitDecision::Allowed);
        };
        if !self.endpoint_rules.contains_key(endpoint) {
            return Ok(RateLimitDecision::Allowed);
        }

        match self.shared_decision(db, key, endpoint, rule).await {
            Ok(decision) => Ok(decision),
            Err(e) => {
                error!(
                    "Shared rate-limit backend unavailable for {endpoint}; \
                     falling back to per-process limiting only: {e}"
                );
                Ok(RateLimitDecision::Allowed)
            }
        }
    }

    /// 固定窗口的共享计数，语义与进程内那层对齐：超过 `max_requests` 即封禁
    /// `block_duration`。
    ///
    /// 四条语句一次往返，全部原子，不做读-改-写：
    ///   1. 窗口号变了就清零（条件 UPDATE，无需先读旧值）
    ///   2. `hits += 1` 自增（UPSERT 在新记录上得 1）
    ///   3. 超限且当前未封禁才写封禁时间，`RETURN VALUE` 非空即"这次刚封"
    ///      —— 条件里带 `blocked_until < time::now()`，所以封禁不会被后续请求无限续期
    ///   4. 读回最终值，**是否封禁在库内比较**：datetime 与其他类型在
    ///      SurrealDB 里按类型序比较而非值序，把 now 传进去比会得到恒真的结果
    async fn shared_decision(
        &self,
        db: &Arc<Database>,
        key: &str,
        endpoint: &str,
        rule: &RateLimitRule,
    ) -> Result<RateLimitDecision, crate::error::AppError> {
        let window_secs = rule.window_duration.as_secs().max(1);
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let window_index = now_secs / window_secs;

        let query = r#"
            UPDATE type::record('rate_limit', $bucket) SET
                hits = 0, window_index = $window_index
            WHERE window_index != $window_index;

            UPSERT type::record('rate_limit', $bucket) SET
                hits += 1,
                window_index = $window_index,
                client_key = $client_key,
                endpoint = $endpoint,
                updated_at = time::now();

            UPDATE type::record('rate_limit', $bucket) SET
                blocked_until = time::now() + type::duration($block_duration)
            WHERE hits > $max_requests
              AND (blocked_until IS NONE OR blocked_until < time::now())
            RETURN VALUE hits;

            SELECT
                hits,
                (blocked_until != NONE AND blocked_until > time::now()) AS blocked
            FROM type::record('rate_limit', $bucket);
        "#;

        let bindings = serde_json::json!({
            "bucket": Self::shared_bucket_id(key, endpoint),
            "window_index": window_index,
            "client_key": key,
            "endpoint": endpoint,
            "max_requests": rule.max_requests,
            "block_duration": format!("{}s", rule.block_duration.as_secs().max(1)),
        });

        let mut last_error = None;
        for attempt in 0..WRITE_CONFLICT_RETRIES {
            match db
                .raw_query("rate_limit_shared", query, bindings.clone())
                .await
            {
                Ok(mut response) => {
                    let just_blocked: Vec<u32> = response.take(2).unwrap_or_default();
                    let rows: Vec<serde_json::Value> = response.take(3).unwrap_or_default();
                    let blocked = rows
                        .first()
                        .and_then(|row| row.get("blocked"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    return Ok(if !just_blocked.is_empty() {
                        warn!("Shared rate limit exceeded for {key} on {endpoint}");
                        RateLimitDecision::JustBlocked
                    } else if blocked {
                        RateLimitDecision::StillBlocked
                    } else {
                        RateLimitDecision::Allowed
                    });
                }
                // 纯粹的乐观并发撞车。不重试就会静默少记一次 ——
                // 实测 20 个并发里有 3 个会撞上，等于白送 3 次尝试。
                Err(e) if Self::is_write_conflict(&e) && attempt + 1 < WRITE_CONFLICT_RETRIES => {
                    tokio::time::sleep(Duration::from_millis(5 * (attempt as u64 + 1))).await;
                    last_error = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_error.expect("retry loop always records the last error"))
    }

    fn is_write_conflict(error: &crate::error::AppError) -> bool {
        error.to_string().contains("Transaction conflict")
    }

    /// 共享桶的记录 ID。客户端标识可能含 `:` 等在记录 ID 里有含义的字符，
    /// 所以取摘要而不是直接拼接。
    fn shared_bucket_id(client_key: &str, endpoint: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        client_key.hash(&mut hasher);
        0u8.hash(&mut hasher); // 分隔，免得 ("ab","c") 与 ("a","bc") 撞同一个桶
        endpoint.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// 重置某个客户端在所有端点上的限制
    pub async fn reset_limit(&self, key: &str) {
        let prefix = format!("{key}\u{1}");
        let mut records = self.records.write().await;
        records.retain(|record_key, _| !record_key.starts_with(&prefix));
        info!("Rate limit reset for key: {}", key);
    }

    /// 获取剩余请求数
    pub async fn get_remaining_requests(&self, key: &str, endpoint: &str) -> u32 {
        let rule = self.get_rule(endpoint);
        let records = self.records.read().await;

        if let Some(record) = records.get(&Self::record_key(key, endpoint)) {
            if record.is_blocked() {
                return 0;
            }
            rule.max_requests
                .saturating_sub(record.timestamps.len() as u32)
        } else {
            rule.max_requests
        }
    }

    /// 清理过期记录 (定期清理任务)
    pub async fn cleanup_expired_records(&self) {
        let mut records = self.records.write().await;
        let now = Instant::now();

        // 清理超过1小时没有活动的记录
        let cleanup_threshold = Duration::from_secs(3600);

        records.retain(|_, record| {
            // 如果有阻塞且未过期，保留
            if let Some(blocked_until) = record.blocked_until {
                if now < blocked_until {
                    return true;
                }
            }

            // 如果有最近的请求，保留
            if let Some(&last_request) = record.timestamps.last() {
                now - last_request < cleanup_threshold
            } else {
                false
            }
        });

        info!(
            "Cleaned up rate limiter records, remaining: {}",
            records.len()
        );
        drop(records);

        self.cleanup_shared_records().await;
    }

    /// 清理共享计数表。不清的话它只增不减：每个 (客户端, 端点) 组合留一条，
    /// 而客户端标识来自 IP，长期跑下来就是一张无界增长的表。
    ///
    /// 只删「既不在封禁中、又已经很久没动」的行，避免把正封着的记录删掉
    /// 而变相解封。
    async fn cleanup_shared_records(&self) {
        let Some(db) = self.shared.as_ref() else {
            return;
        };
        let query = r#"
            DELETE rate_limit
            WHERE (blocked_until IS NONE OR blocked_until < time::now())
              AND (updated_at IS NONE OR updated_at < time::now() - 1h);
        "#;
        if let Err(e) = db
            .raw_query("rate_limit_cleanup", query, serde_json::json!({}))
            .await
        {
            warn!("Failed to clean up shared rate-limit records: {e}");
        }
    }
}

/// 预定义的速率限制规则。
///
/// 规则表按端点字符串精确匹配，而中间件传进来的是**路由模板**
/// （见 `utils::rate_limit_middleware::rate_limit_endpoint`）。所以带路径参数的
/// 端点要按 `/api/auth/verify-email/:token` 这样登记，写成具体路径不会命中。
pub struct RateLimitRules;

impl RateLimitRules {
    /// 登录端点规则 (严格限制)
    pub fn login() -> RateLimitRule {
        RateLimitRule {
            window_duration: Duration::from_secs(300), // 5分钟窗口
            max_requests: 5,                           // 最多5次尝试
            block_duration: Duration::from_secs(900),  // 阻塞15分钟
        }
    }

    /// 注册端点规则
    pub fn register() -> RateLimitRule {
        RateLimitRule {
            window_duration: Duration::from_secs(300), // 5分钟窗口
            max_requests: 3,                           // 最多3次注册
            block_duration: Duration::from_secs(600),  // 阻塞10分钟
        }
    }

    /// 密码重置规则
    pub fn password_reset() -> RateLimitRule {
        RateLimitRule {
            window_duration: Duration::from_secs(900), // 15分钟窗口
            max_requests: 3,                           // 最多3次重置
            block_duration: Duration::from_secs(1800), // 阻塞30分钟
        }
    }

    /// 一般API规则
    pub fn general_api() -> RateLimitRule {
        RateLimitRule {
            window_duration: Duration::from_secs(60), // 1分钟窗口
            max_requests: 30,                         // 最多30次请求
            block_duration: Duration::from_secs(60),  // 阻塞1分钟
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new().with_default_rule(RateLimitRule {
            window_duration: Duration::from_secs(60),
            max_requests: 3,
            block_duration: Duration::from_secs(120),
        });

        let key = "test_user";
        let endpoint = "test_endpoint";

        // 前3次请求应该成功
        for i in 1..=3 {
            let allowed = limiter.check_rate_limit(key, endpoint).await.unwrap();
            assert!(allowed, "Request {} should be allowed", i);
        }

        // 第4次请求应该被阻塞
        let allowed = limiter.check_rate_limit(key, endpoint).await.unwrap();
        assert!(!allowed, "Request 4 should be blocked");

        // 再次请求仍应被阻塞
        let allowed = limiter.check_rate_limit(key, endpoint).await.unwrap();
        assert!(!allowed, "Request 5 should still be blocked");
    }

    #[tokio::test]
    async fn just_blocked_is_reported_exactly_once() {
        // 中间件靠这个区分来决定要不要写审计：阻塞期内每个请求都记一条的话，
        // 被限流的流量有多大、审计写入就有多大。
        let limiter = RateLimiter::new().with_default_rule(RateLimitRule {
            window_duration: Duration::from_secs(60),
            max_requests: 2,
            block_duration: Duration::from_secs(120),
        });

        assert_eq!(
            limiter.check_rate_limit_verbose("k", "/e").await.unwrap(),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_rate_limit_verbose("k", "/e").await.unwrap(),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_rate_limit_verbose("k", "/e").await.unwrap(),
            RateLimitDecision::JustBlocked
        );
        for _ in 0..5 {
            assert_eq!(
                limiter.check_rate_limit_verbose("k", "/e").await.unwrap(),
                RateLimitDecision::StillBlocked
            );
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_reset() {
        let limiter = RateLimiter::new().with_default_rule(RateLimitRule {
            window_duration: Duration::from_secs(60),
            max_requests: 2,
            block_duration: Duration::from_secs(120),
        });

        let key = "test_user";
        let endpoint = "test_endpoint";

        // 触发限制
        limiter.check_rate_limit(key, endpoint).await.unwrap();
        limiter.check_rate_limit(key, endpoint).await.unwrap();
        let allowed = limiter.check_rate_limit(key, endpoint).await.unwrap();
        assert!(!allowed, "Should be blocked");

        // 重置限制
        limiter.reset_limit(key).await;

        // 重置后应该允许请求
        let allowed = limiter.check_rate_limit(key, endpoint).await.unwrap();
        assert!(allowed, "Should be allowed after reset");
    }

    #[tokio::test]
    async fn limits_are_tracked_per_endpoint_not_globally_per_client() {
        let limiter = RateLimiter::new().with_default_rule(RateLimitRule {
            window_duration: Duration::from_secs(60),
            max_requests: 2,
            block_duration: Duration::from_secs(120),
        });

        // 打满 /a 的配额
        assert!(limiter.check_rate_limit("1.2.3.4", "/a").await.unwrap());
        assert!(limiter.check_rate_limit("1.2.3.4", "/a").await.unwrap());
        assert!(!limiter.check_rate_limit("1.2.3.4", "/a").await.unwrap());

        // /b 必须仍然可用 —— 以前 /a 被封会连坐 /b
        assert!(limiter.check_rate_limit("1.2.3.4", "/b").await.unwrap());

        // 另一个客户端也不受影响
        assert!(limiter.check_rate_limit("5.6.7.8", "/a").await.unwrap());
    }

    #[tokio::test]
    async fn test_remaining_requests() {
        let limiter = RateLimiter::new().with_default_rule(RateLimitRule {
            window_duration: Duration::from_secs(60),
            max_requests: 5,
            block_duration: Duration::from_secs(120),
        });

        let key = "test_user";
        let endpoint = "test_endpoint";

        // 初始应有5个剩余请求
        let remaining = limiter.get_remaining_requests(key, endpoint).await;
        assert_eq!(remaining, 5);

        // 使用2个请求
        limiter.check_rate_limit(key, endpoint).await.unwrap();
        limiter.check_rate_limit(key, endpoint).await.unwrap();

        // 应剩余3个请求
        let remaining = limiter.get_remaining_requests(key, endpoint).await;
        assert_eq!(remaining, 3);
    }
}
