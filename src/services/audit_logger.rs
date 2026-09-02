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
//! * **绝不丢事件**：队列由一个专用写入任务消费，写失败会重试，
//!   进程关闭时先把队列排空再退出（见 `flush`）；
//! * **绝不记录凭据**：只记 action / 分类 / 状态 / IP / UA 和少量非敏感上下文。
//!
//! 这里以前是 `tokio::spawn` 一个一次性任务直接写库：写失败只打一行日志，
//! 而进程一退出，还没跑起来的那些任务连日志都不会留。

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
    pub user_id: Option<String>,
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
            ip_address: ip_address.into(),
            user_agent: user_agent.into(),
            details: json!({}),
        }
    }

    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
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
                            head = Some(load_chain_head(&db, &chain_id).await);
                        }
                        let at = head.as_mut().expect("just seeded");
                        write_with_retry(&db, *event, at, &chain_id).await;
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
                        error!("Audit event dropped: the writer has stopped");
                    }
                });
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("Audit event dropped: the writer has stopped");
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
    user_key: String,
}

/// 读当前链头。空表返回创世位置。
///
/// 进程重启后必须接着上一次的 seq 往下写，否则唯一索引会撞，而且链上会出现
/// 两段互不相接的历史。
async fn load_chain_head(db: &Database, chain_id: &str) -> ChainHead {
    // 只读**本副本自己那条链**的链头。读全表最大 seq 会让两个副本互相接续，
    // 而它们各自在内存里递增，接续出来的号很快就撞。
    let sql = "SELECT seq, event_hash FROM user_activity \
               WHERE chain_id = $chain_id AND seq != NONE ORDER BY seq DESC LIMIT 1";
    let rows: Vec<serde_json::Value> = db
        .raw_query(
            "audit_chain_head",
            sql,
            serde_json::json!({ "chain_id": chain_id }),
        )
        .await
        .and_then(|mut r| r.take(0).map_err(Into::into))
        .unwrap_or_default();

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
            ChainHead { seq, hash }
        }
        // 读不出来时从创世重新开始，而不是 panic。代价是链上多一处断点，
        // 校验端点会把它报出来 —— 比服务起不来好。
        None => ChainHead {
            seq: 0,
            hash: audit_integrity::GENESIS_HASH.to_string(),
        },
    }
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
    let details_json = serde_json::to_string(&event.details).unwrap_or_else(|_| "{}".to_string());
    let user_key = event
        .user_id
        .as_deref()
        .map(crate::utils::record_id::normalize_user_id)
        .unwrap_or_default();
    let hash = audit_integrity::event_hash(&audit_integrity::DigestInput {
        chain_id,
        seq,
        previous_hash: &head.hash,
        action: event.action,
        category: &serde_string(&event.category),
        status: &serde_string(&event.status),
        user_id: &user_key,
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
        user_key,
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
}

async fn write_event(
    db: &Database,
    event: &AuditEvent,
    link: &ChainLink,
    chain_id: &str,
) -> crate::error::Result<()> {
    // user_id 是 `option<record<actor_identity>>`：没有对应主体时写 NONE。
    //
    // 审计归因到**身份根**而不是 user 行 —— 这也是 GA-06 要求的方向：
    // 归因主体要跨 user 行的生命周期保持稳定。传进来的仍是 user id，
    // 所以这里用子查询把它解析成 actor ref，与会话查询同一种写法。
    let sql = if event.user_id.is_some() {
        r#"
            CREATE user_activity CONTENT {
                user_id: (SELECT VALUE subject_id FROM type::record('user', $user_key))[0],
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
                user_id: NONE,
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
            "user_key": link.user_key,
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
