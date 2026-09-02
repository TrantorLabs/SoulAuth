use crate::{
    config::Config,
    error::{AuthError, Result},
    models::{
        account_lockout::{
            AccountLockout, LockoutCheckResult, LockoutConfig, LockoutStatus, LockoutType,
        },
        user_activity::{ActivityCategory, ActivityStatus},
    },
    services::{
        audit_logger::{actions, AuditEvent, AuditLogger},
        database::Database,
    },
};
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// 撞上写冲突时的最大重试次数。
const WRITE_CONFLICT_RETRIES: usize = 5;
/// 重试退避基数（毫秒），实际等待随重试次数线性增长。
const WRITE_CONFLICT_BACKOFF_MS: u64 = 10;

/// 一次失败尝试记录完之后的结果。
struct AttemptOutcome {
    failed_attempts: u32,
    /// 是否**正是这一次**把账号 / IP 锁上的。只有它为真才需要写审计，
    /// 免得锁定期内每次尝试都重复记一条。
    just_locked: bool,
}

/// SurrealDB 的乐观并发在真撞车时会返回这个错误，它是可重试的。
fn is_write_conflict(error: &AuthError) -> bool {
    error.to_string().contains("Transaction conflict")
}

/// 账户锁定服务
pub struct AccountLockoutService {
    db: Arc<Database>,
    config: LockoutConfig,
    audit: Arc<AuditLogger>,
}

impl AccountLockoutService {
    /// 创建新的账户锁定服务实例
    /// 从应用配置构造。
    ///
    /// 此前这里的第二个参数叫 `_config` —— 收下之后直接丢掉，用的是
    /// `LockoutConfig::default()`。于是 5 次 / 15 分钟这组阈值无论怎么配都不变。
    /// 那个下划线本身就是接缝留过的证据。
    pub fn new(db: Arc<Database>, config: Config, audit: Arc<AuditLogger>) -> Result<Self> {
        Ok(Self {
            db,
            config: LockoutConfig {
                max_attempts: config.lockout_max_attempts,
                lockout_duration_minutes: config.lockout_duration_minutes,
                reset_window_minutes: config.lockout_reset_window_minutes,
                enable_ip_lockout: config.lockout_ip_enabled,
                enable_user_lockout: config.lockout_user_enabled,
            },
            audit,
        })
    }

    /// 使用自定义配置创建服务
    pub fn with_config(
        db: Arc<Database>,
        config: LockoutConfig,
        audit: Arc<AuditLogger>,
    ) -> Result<Self> {
        Ok(Self { db, config, audit })
    }

    /// 账号 / IP 被锁定是安全事件，必须进审计。
    fn record_lockout_event(&self, identifier: &str, lockout_type: &LockoutType, attempts: u32) {
        let is_ip = matches!(lockout_type, LockoutType::IpAddress);
        let event = AuditEvent::new(
            actions::ACCOUNT_LOCKED,
            ActivityCategory::Security,
            ActivityStatus::Warning,
            if is_ip {
                identifier.to_string()
            } else {
                String::new()
            },
            String::new(),
        )
        .with_details(serde_json::json!({
            "scope": if is_ip { "ip" } else { "account" },
            "failed_attempts": attempts,
        }));

        // 账号维度的 identifier 是邮箱，不是用户 ID，所以不往 user_id 上挂。
        self.audit.record(event);
    }

    pub fn max_attempts(&self) -> u32 {
        self.config.max_attempts
    }

    /// 检查账户是否被锁定（用户维度）
    pub async fn check_user_lockout(&self, user_id: &str) -> Result<LockoutCheckResult> {
        if !self.config.enable_user_lockout {
            return Ok(LockoutCheckResult::normal(self.config.max_attempts));
        }

        match self.get_lockout_record(user_id, LockoutType::User).await {
            Ok(mut lockout) => {
                // 检查锁定是否已过期
                if lockout.is_lock_expired() && lockout.status != LockoutStatus::Normal {
                    lockout.unlock_account();
                    self.save_lockout_record(&lockout).await?;
                    return Ok(LockoutCheckResult::normal(self.config.max_attempts));
                }

                // 检查是否应该重置失败尝试计数
                if lockout.should_reset_attempts(&self.config)
                    && lockout.status == LockoutStatus::Normal
                {
                    lockout.failed_attempts = 0;
                    lockout.updated_at = Utc::now();
                    self.save_lockout_record(&lockout).await?;
                }

                if lockout.is_locked() {
                    Ok(LockoutCheckResult::locked(
                        LockoutType::User,
                        lockout.remaining_lockout_seconds(),
                    ))
                } else {
                    let remaining = self
                        .config
                        .max_attempts
                        .saturating_sub(lockout.failed_attempts);
                    Ok(LockoutCheckResult::normal(remaining))
                }
            }
            Err(AuthError::UserNotFound) => {
                // 没有锁定记录，返回正常状态
                Ok(LockoutCheckResult::normal(self.config.max_attempts))
            }
            Err(e) => Err(e),
        }
    }

    /// 检查IP地址是否被锁定
    pub async fn check_ip_lockout(&self, ip_address: &str) -> Result<LockoutCheckResult> {
        if !self.config.enable_ip_lockout {
            return Ok(LockoutCheckResult::normal(self.config.max_attempts));
        }

        match self
            .get_lockout_record(ip_address, LockoutType::IpAddress)
            .await
        {
            Ok(mut lockout) => {
                // 检查锁定是否已过期
                if lockout.is_lock_expired() && lockout.status != LockoutStatus::Normal {
                    lockout.unlock_account();
                    self.save_lockout_record(&lockout).await?;
                    return Ok(LockoutCheckResult::normal(self.config.max_attempts));
                }

                // 检查是否应该重置失败尝试计数
                if lockout.should_reset_attempts(&self.config)
                    && lockout.status == LockoutStatus::Normal
                {
                    lockout.failed_attempts = 0;
                    lockout.updated_at = Utc::now();
                    self.save_lockout_record(&lockout).await?;
                }

                if lockout.is_locked() {
                    Ok(LockoutCheckResult::locked(
                        LockoutType::IpAddress,
                        lockout.remaining_lockout_seconds(),
                    ))
                } else {
                    let remaining = self
                        .config
                        .max_attempts
                        .saturating_sub(lockout.failed_attempts);
                    Ok(LockoutCheckResult::normal(remaining))
                }
            }
            Err(AuthError::UserNotFound) => {
                // 没有锁定记录，返回正常状态
                Ok(LockoutCheckResult::normal(self.config.max_attempts))
            }
            Err(e) => Err(e),
        }
    }

    /// 记录失败的登录尝试（用户维度）
    pub async fn record_failed_user_attempt(&self, user_id: &str) -> Result<()> {
        if !self.config.enable_user_lockout {
            return Ok(());
        }

        let outcome = self
            .increment_failed_attempts(user_id, LockoutType::User)
            .await?;

        if outcome.just_locked {
            warn!(
                "User account locked: {} (attempts: {})",
                user_id, outcome.failed_attempts
            );
            self.record_lockout_event(user_id, &LockoutType::User, outcome.failed_attempts);
        } else {
            debug!(
                "Failed attempt recorded for user: {} (attempts: {}/{})",
                user_id, outcome.failed_attempts, self.config.max_attempts
            );
        }

        Ok(())
    }

    /// 记录失败的登录尝试（IP维度）
    pub async fn record_failed_ip_attempt(&self, ip_address: &str) -> Result<()> {
        if !self.config.enable_ip_lockout {
            return Ok(());
        }

        let outcome = self
            .increment_failed_attempts(ip_address, LockoutType::IpAddress)
            .await?;

        if outcome.just_locked {
            warn!(
                "IP address locked: {} (attempts: {})",
                ip_address, outcome.failed_attempts
            );
            self.record_lockout_event(ip_address, &LockoutType::IpAddress, outcome.failed_attempts);
        } else {
            debug!(
                "Failed attempt recorded for IP: {} (attempts: {}/{})",
                ip_address, outcome.failed_attempts, self.config.max_attempts
            );
        }

        Ok(())
    }

    /// 在数据库里原子地累加失败次数，并在越过阈值时上锁。
    ///
    /// 以前这里是"读一条 → 内存里 +1 → 整条写回"。读和写是**两个独立的 HTTP 请求、
    /// 两个独立事务**，读集不重叠，数据库无从发现冲突，于是并发失败登录会静默丢计数。
    /// 实测：同一账号 10 个并发失败请求，计数只从 0 涨到 1，一条错误都不报 ——
    /// 攻击者把并发拉高就能让锁定阈值几乎永远够不着。
    ///
    /// 现在改成三条语句一次发过去：
    /// 1. `failed_attempts += 1` —— 单事务内读改写，冲突由数据库负责发现；
    /// 2. 上锁条件写进 `WHERE`，判据取库里的真实值，不依赖应用侧读到的旧值；
    /// 3. 回读最终状态，用来决定要不要记审计。
    ///
    /// SurrealDB 用乐观并发：真撞上会返回 "Transaction conflict"。那种情况必须重试，
    /// 否则这次失败尝试就没被计上，等于换个方式漏计。
    async fn increment_failed_attempts(
        &self,
        identifier: &str,
        lockout_type: LockoutType,
    ) -> Result<AttemptOutcome> {
        let record_id = Self::lockout_record_id(identifier, &lockout_type);
        let lockout_type_value = format!("{:?}", lockout_type);

        let query = r#"
            UPSERT type::record('account_lockout', $record_id) SET
                identifier = $identifier,
                lockout_type = $lockout_type,
                failed_attempts += 1,
                last_attempt_at = time::now(),
                updated_at = time::now();

            UPDATE type::record('account_lockout', $record_id) SET
                status = 'Locked',
                locked_at = time::now(),
                locked_until = time::now() + type::duration($lockout_duration)
            WHERE failed_attempts >= $max_attempts AND status != 'Locked'
            RETURN VALUE failed_attempts;

            SELECT failed_attempts, status FROM type::record('account_lockout', $record_id);
        "#;

        let bindings = serde_json::json!({
            "record_id": record_id,
            "identifier": identifier,
            "lockout_type": lockout_type_value,
            "max_attempts": self.config.max_attempts,
            "lockout_duration": format!("{}m", self.config.lockout_duration_minutes),
        });

        let mut last_error = None;
        for attempt in 0..WRITE_CONFLICT_RETRIES {
            match self
                .db
                .raw_query("lockout_increment_attempts", query, bindings.clone())
                .await
            {
                Ok(mut response) => {
                    // 第 1 条语句的返回值用不上；第 2 条只在"这次刚好把它锁上"时非空
                    // （`status != 'Locked'` 挡住了已经锁着的重复上锁）；第 3 条给最终值。
                    let newly_locked: Vec<u32> = response.take(1).unwrap_or_default();
                    let rows: Vec<serde_json::Value> = response.take(2).unwrap_or_default();

                    let failed_attempts = rows
                        .first()
                        .and_then(|row| row.get("failed_attempts"))
                        .and_then(|value| value.as_u64())
                        .unwrap_or(0) as u32;

                    return Ok(AttemptOutcome {
                        failed_attempts,
                        just_locked: !newly_locked.is_empty(),
                    });
                }
                Err(e) if is_write_conflict(&e) && attempt + 1 < WRITE_CONFLICT_RETRIES => {
                    // 纯粹的乐观并发撞车，退避一点再来。退避时长随重试次数递增，
                    // 避免所有并发请求在同一时刻再撞一次。
                    debug!(
                        "Lockout counter write conflict on '{identifier}', retry {}/{}",
                        attempt + 1,
                        WRITE_CONFLICT_RETRIES
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(
                        WRITE_CONFLICT_BACKOFF_MS * (attempt as u64 + 1),
                    ))
                    .await;
                    last_error = Some(e);
                }
                Err(e) => return Err(e),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            AuthError::DatabaseError("Failed to record login attempt".to_string())
        }))
    }

    /// 锁定记录的确定性 ID。
    ///
    /// 必须和 `save_lockout_record` 用同一套规则，否则解锁 / 重置会打到另一条记录上。
    fn lockout_record_id(identifier: &str, lockout_type: &LockoutType) -> String {
        format!(
            "{}:{}",
            format!("{:?}", lockout_type).to_lowercase(),
            identifier.replace(' ', "_")
        )
    }

    /// 重置用户的失败尝试计数
    pub async fn reset_user_attempts(&self, user_id: &str) -> Result<()> {
        info!("Resetting failed attempts for user: {}", user_id);

        match self.get_lockout_record(user_id, LockoutType::User).await {
            Ok(mut lockout) => {
                lockout.unlock_account();
                self.save_lockout_record(&lockout).await?;
            }
            Err(AuthError::UserNotFound) => {
                // 没有记录，无需重置
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// 重置IP的失败尝试计数
    pub async fn reset_ip_attempts(&self, ip_address: &str) -> Result<()> {
        info!("Resetting failed attempts for IP: {}", ip_address);

        match self
            .get_lockout_record(ip_address, LockoutType::IpAddress)
            .await
        {
            Ok(mut lockout) => {
                lockout.unlock_account();
                self.save_lockout_record(&lockout).await?;
            }
            Err(AuthError::UserNotFound) => {
                // 没有记录，无需重置
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// 手动解锁用户账户
    pub async fn unlock_user(&self, user_id: &str) -> Result<bool> {
        info!("Manually unlocking user: {}", user_id);

        match self.get_lockout_record(user_id, LockoutType::User).await {
            Ok(mut lockout) => {
                if lockout.is_locked() {
                    lockout.unlock_account();
                    self.save_lockout_record(&lockout).await?;
                    info!("User unlocked successfully: {}", user_id);
                    Ok(true)
                } else {
                    Ok(false) // 用户本来就没有被锁定
                }
            }
            Err(AuthError::UserNotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 手动解锁IP地址
    pub async fn unlock_ip(&self, ip_address: &str) -> Result<bool> {
        info!("Manually unlocking IP: {}", ip_address);

        match self
            .get_lockout_record(ip_address, LockoutType::IpAddress)
            .await
        {
            Ok(mut lockout) => {
                if lockout.is_locked() {
                    lockout.unlock_account();
                    self.save_lockout_record(&lockout).await?;
                    info!("IP unlocked successfully: {}", ip_address);
                    Ok(true)
                } else {
                    Ok(false) // IP本来就没有被锁定
                }
            }
            Err(AuthError::UserNotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 获取锁定配置
    pub fn get_config(&self) -> &LockoutConfig {
        &self.config
    }

    /// 清理过期的锁定记录
    pub async fn cleanup_expired_lockouts(&self) -> Result<u32> {
        // 两类都要清：
        //
        // 1. 锁定已经到期的记录（老逻辑）。
        // 2. **停在 `Normal` 状态、且早已超出重置窗口的记录**。这类以前从不清理：
        //    每一次失败登录都会建一条计数记录，连**不存在的邮箱**也会建
        //    （这是对的，否则"有没有留下锁定记录"本身就成了账号枚举信道），于是
        //    每个被试过的地址都在表里永久留一行，只增不减。反正超出重置窗口后
        //    `check_*_lockout` 也会把计数清零，留着没有意义。
        //
        // `locked_until != NONE` 这个显式判空是必要的：`NONE < datetime` 不报错，
        // 靠它挡住"没锁过、locked_until 为空"的记录被误判成"锁定已过期"。
        let query = r#"
            DELETE account_lockout
            WHERE (
                status IN ['Locked', 'TemporaryLocked']
                AND locked_until != NONE
                AND locked_until < type::datetime($now)
            ) OR (
                status = 'Normal'
                AND (last_attempt_at = NONE OR last_attempt_at < type::datetime($stale_before))
            )
        "#;

        // `Utc::now().to_string()` 产出 "2026-08-05 08:43:36.837 UTC"，
        // 不是 RFC3339，`type::datetime()` 转不了 —— 定时清理任务因此每小时报错一次。
        let now = Utc::now();
        let stale_before = now - chrono::Duration::minutes(self.config.reset_window_minutes as i64);

        let _result = self
            .db
            .raw_query(
                "cleanup_expired_lockouts",
                query,
                serde_json::json!({
                    "now": now.to_rfc3339(),
                    "stale_before": stale_before.to_rfc3339(),
                }),
            )
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        info!("Cleaned up expired lockout records");
        Ok(0) // SurrealDB DELETE 不返回删除计数，这里返回0
    }

    /// 从数据库获取锁定记录
    async fn get_lockout_record(
        &self,
        identifier: &str,
        lockout_type: LockoutType,
    ) -> Result<AccountLockout> {
        // 时间列必须投影成字符串：SDK 无法把原生 `Value::Datetime` 转成
        // `serde_json::Value`（报 "Expected any, got datetime"）。
        let query = r#"
            SELECT
                identifier,
                lockout_type,
                failed_attempts,
                status,
                type::string(created_at) AS created_at,
                type::string(updated_at) AS updated_at,
                type::string(last_attempt_at) AS last_attempt_at,
                IF locked_at = NONE { NONE } ELSE { type::string(locked_at) } AS locked_at,
                IF locked_until = NONE { NONE } ELSE { type::string(locked_until) } AS locked_until
            FROM account_lockout
            WHERE identifier = $identifier AND lockout_type = $lockout_type
            LIMIT 1
        "#;

        // 写路径用 serde（枚举存成 "User" / "IpAddress" 字符串），
        // 读路径若用 SurrealValue 解码则对不上（"no variants matched"）。
        // 两边必须一致，所以这里也走 serde。
        let mut result = self
            .db
            .raw_query(
                "get_lockout_record",
                query,
                serde_json::json!({
                    "identifier": identifier,
                    "lockout_type": lockout_type,
                }),
            )
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let rows: Vec<serde_json::Value> = result
            .take(0)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        rows.into_iter()
            .next()
            .map(serde_json::from_value::<AccountLockout>)
            .transpose()
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse lockout record: {e}")))?
            .ok_or(AuthError::UserNotFound)
    }

    /// 保存锁定记录到数据库
    async fn save_lockout_record(&self, lockout: &AccountLockout) -> Result<()> {
        // 时间列是 `datetime`，而 raw_query 的 JSON 绑定给出的是 RFC3339 字符串，
        // 必须显式转换 —— 否则整条写入被拒，账号锁定计数永远停在 0，
        // 暴力破解防护实际上从未生效过。
        // SurrealQL doesn't support `REPLACE` in this position.
        // Use a deterministic record id so we can UPDATE (create-or-replace semantics).
        // Example: account_lockout:user:foo@example.com
        // 注意必须用 `type::record(table, id)` 两参形式。
        // 单参形式 `type::record("account_lockout:user:a@b.com")` 会在第一个冒号处
        // 截断，得到 `account_lockout:user` —— 于是所有账号共用一条记录、
        // 所有 IP 共用另一条，锁定计数根本不按对象累加。
        let record_id = Self::lockout_record_id(&lockout.identifier, &lockout.lockout_type);

        let query = r#"
            UPSERT type::record('account_lockout', $record_id) CONTENT {
                identifier: $identifier,
                lockout_type: $lockout_type,
                failed_attempts: $failed_attempts,
                status: $status,
                locked_at: IF $locked_at = NONE OR $locked_at = NULL {
                    NONE
                } ELSE {
                    type::datetime($locked_at)
                },
                locked_until: IF $locked_until = NONE OR $locked_until = NULL {
                    NONE
                } ELSE {
                    type::datetime($locked_until)
                },
                last_attempt_at: IF $last_attempt_at = NONE OR $last_attempt_at = NULL {
                    NONE
                } ELSE {
                    type::datetime($last_attempt_at)
                },
                created_at: type::datetime($created_at),
                updated_at: type::datetime($updated_at)
            }
        "#;

        let identifier_value = lockout.identifier.clone();
        let lockout_type_value = lockout.lockout_type.clone();
        let status_value = lockout.status.clone();
        let failed_attempts_value = lockout.failed_attempts;
        let locked_at_value = lockout.locked_at;
        let locked_until_value = lockout.locked_until;
        let last_attempt_at_value = lockout.last_attempt_at;
        let created_at_value = lockout.created_at;
        let updated_at_value = lockout.updated_at;

        let save = self
            .db
            .raw_query(
                "save_lockout_record",
                query,
                serde_json::json!({
                    "record_id": record_id,
                    "identifier": identifier_value,
                    "lockout_type": lockout_type_value,
                    "failed_attempts": failed_attempts_value,
                    "status": status_value,
                    "locked_at": locked_at_value,
                    "locked_until": locked_until_value,
                    "last_attempt_at": last_attempt_at_value,
                    "created_at": created_at_value,
                    "updated_at": updated_at_value,
                }),
            )
            .await;

        if let Err(err) = save {
            return Err(AuthError::DatabaseError(err.to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lockout_config_default() {
        let config = LockoutConfig::default();

        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.lockout_duration_minutes, 15);
        assert_eq!(config.reset_window_minutes, 60);
        assert!(config.enable_ip_lockout);
        assert!(config.enable_user_lockout);
    }

    #[test]
    fn test_lockout_check_result_creation() {
        let normal = LockoutCheckResult::normal(3);
        assert!(!normal.is_locked);
        assert_eq!(normal.remaining_attempts, 3);

        let locked = LockoutCheckResult::locked(LockoutType::User, Some(300));
        assert!(locked.is_locked);
        assert_eq!(locked.remaining_lockout_seconds, Some(300));
    }
}
