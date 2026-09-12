//! 认证事件埋点。
//!
//! 审计子系统一直在查这些 action：`login_success` / `login_failed` /
//! `oauth_login` / `password_reset` / `permission_denied` / `rate_limit_violation`，
//! 但**全代码库没有任何地方写过它们** —— `log_user_activity` 只有 5 个调用点，
//! 全在用户档案/偏好/账号状态那几个接口上。结果就是审计报表永远是空的。
//!
//! 这个模块负责在认证链路上补齐埋点。三条硬性约束：
//!
//! * **绝不影响主流程**：`record` 不落库，只把事件投进队列就返回；
//! * **尽力不丢，丢了必须可观察**：队列由一个专用写入任务消费，写失败会重试，
//!   进程关闭时先把队列排空再退出（见 `flush`）。但这**不是**「绝不丢事件」：
//!   队列满、重试用尽、排空超时这三种情况都会丢。所以丢弃会被计数，并且把审计
//!   子系统标记为不健康 —— `/api/audit/system-health` 能看到。
//!
//!   这里曾经写着「绝不丢事件」。那句话是错的，而错得有代价：读者据此以为
//!   身份与凭证管理类操作的审计是可靠的，于是不会去做持久化 outbox。
//! * **绝不记录凭据**：只记 action / 分类 / 状态 / IP / UA 和少量非敏感上下文。
//!
//! 这里以前是 `tokio::spawn` 一个一次性任务直接写库：写失败只打一行日志，
//! 而进程一退出，还没跑起来的那些任务连日志都不会留。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, warn};

use crate::{
    models::user_activity::{ActivityCategory, ActivityStatus},
    services::{audit_integrity, database::Database},
};

/// 审计事件的 action 常量。审计查询按这些字符串聚合，改名要两边一起改。
pub mod actions {
    pub const LOGIN_SUCCESS: &str = "login_success";
    pub const LOGIN_FAILED: &str = "login_failed";
    pub const OAUTH_LOGIN: &str = "oauth_login";
    pub const LOGOUT: &str = "logout";
    pub const PASSWORD_RESET: &str = "password_reset";
    pub const MFA_FAILED: &str = "mfa_failed";
    pub const PERMISSION_DENIED: &str = "permission_denied";
    pub const RATE_LIMIT_VIOLATION: &str = "rate_limit_violation";
    pub const ACCOUNT_LOCKED: &str = "account_locked";
    /// 管理员手工解除锁定。与 ACCOUNT_LOCKED 成对 —— 只记上锁不记解锁的话，
    /// 审计里会留下一串永远没有下文的锁定事件。
    pub const LOCKOUT_CLEARED: &str = "lockout_cleared";
}

/// 队列容量。
///
/// 满了不是丢事件，而是让 `record` 退化成「起一个任务等队列」——
/// 也就是改动前的行为。给得宽一点，正常负载下走不到那条分支。
const QUEUE_CAPACITY: usize = 4096;

/// 单条事件的写入重试次数。数据库抖一下不该让事件消失。
const WRITE_ATTEMPTS: u32 = 3;

/// 关闭时等待队列排空的上限。超时宁可退出，也不能把进程挂在这里。
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

enum Msg {
    Event(Box<AuditEvent>),
    /// 排空信号：写入任务处理到它时，说明它前面的事件都已落库。
    Flush(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct AuditLogger {
    tx: mpsc::Sender<Msg>,
}

/// 进程内唯一的那个 logger。
///
/// 存在的理由是一个真实踩过的坑：`permission_middleware` 与 `user_management`
/// 拿不到 Extension，于是写成 `AuditLogger::new(db).record(...)` —— 每记一条
/// 事件就现造一个。改成队列之后这意味着**每条事件 spawn 一个写入任务**，
/// 各自从库里读链头、各自在内存里递增 seq，必然撞号。而 `new` 的签名没变，
/// 编译器一句话都不会说。
///
/// 现在写入任务只可能有一个：`start` 建它并登记到这里，别处一律用 `global`。
static GLOBAL: std::sync::OnceLock<AuditLogger> = std::sync::OnceLock::new();

/// 一条待写入的审计事件。
pub struct AuditEvent {
    pub action: &'static str,
    pub category: ActivityCategory,
    pub status: ActivityStatus,
    /// 用户 ID（不含表名前缀）。登录失败等场景可能为空。
    /// Human 的账户 id。写入时由它解析出身份根 —— 调用方手上往往只有这个。
    pub user_id: Option<String>,

    /// **已经解析过的**身份根。
    ///
    /// AIActor 没有 `user` 行，`with_user` 对它无效：它的认证事件此前只把
    /// actor id 塞进自由格式的 `details`，于是归因是一个可变的字符串，而不是
    /// 一条外键 —— 没法按主体稳定地查它的认证历史。
    ///
    /// 只接受**已经认证成功后**拿到的身份根。失败事件里的「对方声称自己是谁」
    /// 属于 `details.claimed_actor_id`，两者不能混：后者来自未经验证的请求参数。
    pub actor_identity_id: Option<String>,
    pub ip_address: String,
    pub user_agent: String,
    pub details: serde_json::Value,
}

impl AuditEvent {
    pub fn new(
        action: &'static str,
        category: ActivityCategory,
        status: ActivityStatus,
        ip_address: impl Into<String>,
        user_agent: impl Into<String>,
    ) -> Self {
        Self {
            action,
            category,
            status,
            user_id: None,
            actor_identity_id: None,
            ip_address: ip_address.into(),
            user_agent: user_agent.into(),
            details: json!({}),
        }
    }

    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// 归因到一个**已经解析成功**的身份根。
    pub fn with_actor(mut self, actor_identity_id: impl Into<String>) -> Self {
        self.actor_identity_id = Some(actor_identity_id.into());
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

impl AuditLogger {
    /// 建队列并起写入任务。写入任务与进程同生命周期。
    ///
    /// `chain_id` 标识本副本那条哈希链。多副本各写各的链 —— seq 在进程内存里
    /// 递增，两个副本共用一个 chain_id 会撞唯一索引，后来者的每一条事件都
    /// 写不进去。
    pub fn start(db: Arc<Database>, chain_id: String) -> Self {
        let (tx, mut rx) = mpsc::channel::<Msg>(QUEUE_CAPACITY);

        tokio::spawn(async move {
            // 链头缓存在写入任务里。这是唯一的写入者，所以 seq 单调、
            // previous_hash 连续这两件事不需要任何锁 —— 顺序由队列保证。
            //
            // 首次写入前从库里读一次当前链头：进程重启不该让链断开。
            let mut head: Option<ChainHead> = None;

            while let Some(msg) = rx.recv().await {
                match msg {
                    Msg::Event(event) => {
                        if head.is_none() {
                            head = load_chain_head(&db, &chain_id).await;
                        }
                        match head.as_mut() {
                            Some(at) => write_with_retry(&db, *event, at, &chain_id).await,
                            // 链头读不出来：**不写**。从创世重写会撞唯一索引，
                            // 并让这个进程此后再也写不进任何事件。
                            None => mark_dropped("chain head unavailable", event.action),
                        }
                    }
                    // 排空信号按序到达：能收到它，就说明它前面排队的事件
                    // 都已经写完了。回执发不出去只意味着等待方先走了。
                    Msg::Flush(ack) => {
                        let _ = ack.send(());
                    }
                }
            }
        });

        let logger = Self { tx };
        // 已经建过就保持第一个 —— 重复调用是配置错误，不该悄悄换掉链的写入者。
        let _ = GLOBAL.set(logger.clone());
        logger
    }

    /// 进程内那个唯一的 logger。拿不到 Extension 的地方用它。
    ///
    /// 返回 `None` 只发生在 `start` 之前，也就是单元测试里。那种情况下丢一条
    /// 审计事件不影响任何断言，所以调用方直接跳过即可。
    pub fn global() -> Option<&'static AuditLogger> {
        GLOBAL.get()
    }

    /// 记录一条事件。不落库，只投队列，因此不阻塞调用方。
    pub fn record(&self, event: AuditEvent) {
        let msg = Msg::Event(Box::new(event));
        match self.tx.try_send(msg) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(msg)) => {
                // 队列满说明写入任务被数据库拖住了。这时**不丢**事件：
                // 起一个任务去等位置，代价是这一条的顺序可能落到后面。
                warn!("Audit queue is full; the writer is falling behind");
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    if tx.send(msg).await.is_err() {
                        mark_dropped("writer stopped", "unknown");
                    }
                });
            }
            Err(mpsc::error::TrySendError::Closed(msg)) => {
                let action = match &msg {
                    Msg::Event(event) => event.action,
                    Msg::Flush(_) => "flush",
                };
                mark_dropped("writer stopped", action);
            }
        }
    }

    /// 等队列里已排队的事件全部落库。
    ///
    /// 关闭流程在停止接受新请求之后调用它 —— 这一步是「进程退出不丢事件」
    /// 的全部依据。超时就放弃等待：卡住不退出比丢几条事件更糟。
    pub async fn flush(&self) {
        let (ack, wait) = oneshot::channel();
        if self.tx.send(Msg::Flush(ack)).await.is_err() {
            return;
        }
        if tokio::time::timeout(FLUSH_TIMEOUT, wait).await.is_err() {
            // 没排空就退出 —— 剩下的那些事件会丢。标记出来，别让它只是一行 warn。
            mark_dropped("flush timed out", "flush");
            warn!("Audit queue did not drain within {FLUSH_TIMEOUT:?}");
        }
    }
}

/// 链头：下一条事件要接在哪里。
struct ChainHead {
    seq: i64,
    hash: String,
}

/// 一条事件在链上的位置，以及所有进过摘要的派生值。
///
/// 存在的理由是「算摘要」与「写库」必须用同一份值。`timestamp` 尤其容易出错：
/// 两处各调一次 `Utc::now()` 就会差出几毫秒，落库的事实与被哈希的事实不一致，
/// 链在写下的那一刻就已经是断的。
struct ChainLink {
    seq: i64,
    previous_hash: String,
    hash: String,
    timestamp: i64,
    /// 归因到的身份根，**裸 record key**（不带表名、不带 ⟨⟩）；无归因时是空串。
    ///
    /// 为什么是裸 key 而不是 `actor_identity:xxx` 这样的地址形式：摘要两侧必须
    /// 喂进逐字节相同的串，而地址形式经 `type::string()` 读回来可能带上 ⟨⟩
    /// （key 需要转义时），也可能不带 —— 那取决于 key 长什么样。把两侧都先用
    /// `normalize_actor_id` 归一成裸 key，就不依赖这个行为。
    ///
    /// 摘要以前喂的是归一化后的 **user** key，而行里存的是解析后的 actor 记录
    /// —— 两个不同的主体的 key。于是任何带归因的行都被报成「链已断」。
    actor_key: String,
}

/// 读当前链头。空表返回创世位置。
///
/// 进程重启后必须接着上一次的 seq 往下写，否则唯一索引会撞，而且链上会出现
/// 两段互不相接的历史。
/// 读当前链头。
///
/// `None` 表示**读不出来**（数据库出错），不是「表里没有」—— 后者返回创世位置。
/// 调用方必须区分这两者：把读失败当成空表会让 seq 从 1 重新开始。
async fn load_chain_head(db: &Database, chain_id: &str) -> Option<ChainHead> {
    // 只读**本副本自己那条链**的链头。读全表最大 seq 会让两个副本互相接续，
    // 而它们各自在内存里递增，接续出来的号很快就撞。
    let sql = "SELECT seq, event_hash FROM user_activity \
               WHERE chain_id = $chain_id AND seq != NONE ORDER BY seq DESC LIMIT 1";
    let rows: crate::error::Result<Vec<serde_json::Value>> = db
        .raw_query(
            "audit_chain_head",
            sql,
            serde_json::json!({ "chain_id": chain_id }),
        )
        .await
        .and_then(|mut r| {
            r.take::<Vec<serde_json::Value>>(0usize).map_err(|e| {
                crate::error::AuthError::DatabaseError(format!("chain head parse: {e}"))
            })
        });

    // **读失败与「表里没有」必须分开。**
    //
    // 这里以前是 `.unwrap_or_default()`：一次数据库报错被当成「空表」，于是链头
    // 回到创世、seq 从 1 重新开始，而库里已经有 1..N —— 唯一索引
    // `(chain_id, seq)` 把后面每一次写入都挡掉。表现是这个进程从此再也写不进
    // 任何审计事件，而日志里只有一行读失败。
    let rows: Vec<serde_json::Value> = match rows {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to read audit chain head: {e:?}");
            return None;
        }
    };

    match rows.first() {
        Some(row) => {
            let seq = row
                .get("seq")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            let hash = row
                .get("event_hash")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(audit_integrity::GENESIS_HASH)
                .to_string();
            Some(ChainHead { seq, hash })
        }
        // 这条链上确实还没有任何行 —— 全新实例或全新副本，从创世开始是对的。
        None => Some(ChainHead {
            seq: 0,
            hash: audit_integrity::GENESIS_HASH.to_string(),
        }),
    }
}

/// 审计子系统是否还在可靠地落库。
///
/// 一旦丢过事件或读不到链头，它就变成 `false` 并且**不会自己恢复** ——
/// 恢复需要人看一眼到底丢了什么。`/api/audit/system-health` 暴露它。
static AUDIT_HEALTHY: AtomicBool = AtomicBool::new(true);
/// 丢弃的事件数。
static AUDIT_DROPPED: AtomicU64 = AtomicU64::new(0);

/// 把审计子系统标记为不健康，并记一次丢弃。
fn mark_dropped(reason: &str, action: &str) {
    AUDIT_HEALTHY.store(false, Ordering::Relaxed);
    let total = AUDIT_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
    error!("Audit event dropped ({reason}) action={action}; total dropped={total}");
}

/// 审计落库是否健康，以及累计丢弃数。
pub fn audit_health() -> (bool, u64) {
    (
        AUDIT_HEALTHY.load(Ordering::Relaxed),
        AUDIT_DROPPED.load(Ordering::Relaxed),
    )
}

/// 取 serde 序列化后的字符串值，与落库那一路同源。
///
/// 不能用 `{:?}`：Debug 与 serde 对同一个枚举可能给出不同的字面量，
/// 那样摘要覆盖的就不是真正存进去的那个词。
fn serde_string<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// 把 user id 解析成身份根的**裸 record key**。
///
/// 解析不出来返回空串，与「这条事件没有归因主体」同一种表示。这里**不**向上
/// 报错：审计写入失败不该阻塞任何东西，而一条归因为空的记录仍然比没有记录好。
/// 解析失败本身也会被下一次校验看见 —— 那一行的归因是空的。
///
/// 这一次多出来的往返发生在审计写入任务里，不在请求路径上：队列把它吸收掉了。
async fn resolve_actor_key(db: &Database, user_id: Option<&str>) -> String {
    let Some(raw) = user_id else {
        return String::new();
    };
    let user_key = crate::utils::record_id::normalize_user_id(raw);
    if user_key.is_empty() {
        return String::new();
    }

    db.query_take0_option::<String>(
        "audit_resolve_actor",
        "SELECT VALUE type::string(subject_id) FROM type::record('user', $user_key) LIMIT 1",
        json!({ "user_key": user_key }),
    )
    .await
    .ok()
    .flatten()
    .map(|addr| crate::utils::record_id::normalize_actor_id(&addr))
    .unwrap_or_default()
}

/// 写一条事件，失败重试。
///
/// 重试的是数据库抖动这类瞬时故障。用尽仍失败才记日志 —— 那一行是最后的线索，
/// 所以要带上 action，不能只有一句 "Failed to write audit event"。
async fn write_with_retry(db: &Database, event: AuditEvent, head: &mut ChainHead, chain_id: &str) {
    let action = event.action;
    let mut last_err = None;

    // 链上的位置在重试之间保持不变：重试的是同一条事件，不该因为重试而占掉
    // 两个 seq，那会在链上留下一个永远补不上的空号。
    let seq = head.seq + 1;
    let timestamp = Utc::now().timestamp();
    // 规范化而不是直接 to_string：键顺序与 null 在两侧不保证一致，
    // 详见 `audit_integrity::canonical_json`。
    let details_json = audit_integrity::canonical_json(&event.details);
    // 先把 user id 解析成身份根地址，**然后**再算摘要。
    //
    // 顺序是这条链能不能被验证的关键：行里存的是身份根引用，而校验端点只能
    // 读到行里的东西。在解析之前算摘要，等于对一个不在行里的值签名。
    // 已经解析过的身份根优先；只有拿不到时才从 user 行解析。
    //
    // 顺序重要：AIActor 的事件没有 user 行，而 Human 的调用方通常只有 user id。
    let actor_key = match event.actor_identity_id.as_deref() {
        Some(raw) => crate::utils::record_id::normalize_actor_id(raw),
        None => resolve_actor_key(db, event.user_id.as_deref()).await,
    };
    let hash = audit_integrity::event_hash(&audit_integrity::DigestInput {
        chain_id,
        seq,
        previous_hash: &head.hash,
        action: event.action,
        category: &serde_string(&event.category),
        status: &serde_string(&event.status),
        actor_identity_id: &actor_key,
        ip_address: &event.ip_address,
        user_agent: &event.user_agent,
        details_json: &details_json,
        timestamp,
    });
    let link = ChainLink {
        seq,
        previous_hash: head.hash.clone(),
        hash: hash.clone(),
        timestamp,
        actor_key,
    };

    for attempt in 1..=WRITE_ATTEMPTS {
        match write_event(db, &event, &link, chain_id).await {
            Ok(()) => {
                head.seq = seq;
                head.hash = hash;
                return;
            }
            Err(e) => {
                last_err = Some(e);
                if attempt < WRITE_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(50 * u64::from(attempt))).await;
                }
            }
        }
    }

    error!(
        action,
        "Failed to write audit event after {WRITE_ATTEMPTS} attempts: {}",
        last_err.map(|e| e.to_string()).unwrap_or_default()
    );
    mark_dropped("write retries exhausted", action);
}

async fn write_event(
    db: &Database,
    event: &AuditEvent,
    link: &ChainLink,
    chain_id: &str,
) -> crate::error::Result<()> {
    // `actor_identity_id` 是 `option<record<actor_identity>>`：没有归因主体时写 NONE。
    //
    // 审计归因到**身份根**而不是 user 行 —— 归因主体要跨 user 行的生命周期保持
    // 稳定。列名曾经叫 `user_id`，而类型一直是 `record<actor_identity>`：指向是
    // 对的，名字在说谎（`f1` 断言的正是这个）。
    //
    // 解析在算摘要之前就做完了，所以这里写的是 `link.actor_address` 本身，
    // 不再在 SQL 里现算 —— 在 SQL 里现算就会出现「签的值」与「存的值」不同。
    let sql = if !link.actor_key.is_empty() {
        r#"
            CREATE user_activity CONTENT {
                actor_identity_id: type::record('actor_identity', $actor_key),
                action: $action,
                category: $category,
                ip_address: $ip_address,
                user_agent: $user_agent,
                details: $details,
                status: $status,
                timestamp: $timestamp,
                chain_id: $chain_id,
                seq: $seq,
                previous_hash: $previous_hash,
                event_hash: $event_hash
            }
        "#
    } else {
        r#"
            CREATE user_activity CONTENT {
                actor_identity_id: NONE,
                action: $action,
                category: $category,
                ip_address: $ip_address,
                user_agent: $user_agent,
                details: $details,
                status: $status,
                timestamp: $timestamp,
                chain_id: $chain_id,
                seq: $seq,
                previous_hash: $previous_hash,
                event_hash: $event_hash
            }
        "#
    };

    db.raw_query(
        "audit_write_event",
        sql,
        json!({
            // 这些值全部取自 `link`，而 `link` 里的每一项都进过摘要。
            // 若在这里另算一遍（例如再调一次 `Utc::now()`），落库的事实就会与
            // 被签名的事实错开，链当场就是断的。
            "actor_key": link.actor_key,
            "action": event.action,
            "category": event.category,
            "status": event.status,
            "ip_address": event.ip_address,
            "user_agent": event.user_agent,
            "details": event.details,
            "timestamp": link.timestamp,
            "chain_id": chain_id,
            "seq": link.seq,
            "previous_hash": link.previous_hash,
            "event_hash": link.hash,
        }),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_builder_sets_optional_fields() {
        let event = AuditEvent::new(
            actions::LOGIN_FAILED,
            ActivityCategory::Authentication,
            ActivityStatus::Failed,
            "203.0.113.7",
            "curl/8.0",
        );

        assert_eq!(event.action, "login_failed");
        assert!(event.user_id.is_none());
        assert_eq!(event.details, json!({}));

        let event = event
            .with_user("user-1")
            .with_details(json!({ "reason": "invalid_password" }));

        assert_eq!(event.user_id.as_deref(), Some("user-1"));
        assert_eq!(event.details["reason"], json!("invalid_password"));
    }

    #[test]
    fn action_names_match_what_the_audit_queries_look_for() {
        // 审计服务里硬编码了这些字符串，改名必须同步。
        assert_eq!(actions::LOGIN_SUCCESS, "login_success");
        assert_eq!(actions::LOGIN_FAILED, "login_failed");
        assert_eq!(actions::OAUTH_LOGIN, "oauth_login");
        assert_eq!(actions::PASSWORD_RESET, "password_reset");
        assert_eq!(actions::PERMISSION_DENIED, "permission_denied");
        assert_eq!(actions::RATE_LIMIT_VIOLATION, "rate_limit_violation");
    }
}
