use chrono::{DateTime, Utc};
use serde_json::json;
use serde_json::Value;
use std::collections::HashMap;
use tracing::error;

use crate::{
    error::{AuthError, Result as ApiResult},
    routes::audit::{
        AuthenticationStats, CategoryMetric, ExecutiveSummary, HourlyActivity, IpActivityMetric,
        LockoutStats, SecurityRecommendation, StatusMetric, SuspiciousActivity, UserActivityMetric,
    },
    services::database::Database,
};

#[derive(Clone)]
pub struct AuditService {
    db: Database,
}

impl AuditService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // Authentication Statistics
    pub async fn get_authentication_stats(
        &self,
        start_time: DateTime<Utc>,
    ) -> ApiResult<AuthenticationStats> {
        let successful_query = "SELECT count() as count FROM user_activity WHERE action IN ['login_success', 'oauth_login'] AND timestamp >= $start_time GROUP ALL";
        let failed_query = "SELECT count() as count FROM user_activity WHERE action = 'login_failed' AND timestamp >= $start_time GROUP ALL";
        let oauth_query = "SELECT count() as count FROM user_activity WHERE action = 'oauth_login' AND timestamp >= $start_time GROUP ALL";
        let reset_query = "SELECT count() as count FROM user_activity WHERE action = 'password_reset' AND timestamp >= $start_time GROUP ALL";

        let successful_logins = self
            .execute_count_query(successful_query, start_time)
            .await?;
        let failed_logins = self.execute_count_query(failed_query, start_time).await?;
        let oauth_logins = self.execute_count_query(oauth_query, start_time).await?;
        let password_resets = self.execute_count_query(reset_query, start_time).await?;

        let total_attempts = successful_logins + failed_logins;
        let success_rate = if total_attempts > 0 {
            (successful_logins as f64 / total_attempts as f64) * 100.0
        } else {
            0.0
        };

        Ok(AuthenticationStats {
            successful_logins,
            failed_logins,
            oauth_logins,
            password_resets,
            success_rate,
        })
    }

    // Lockout Statistics
    pub async fn get_lockout_stats(&self, start_time: DateTime<Utc>) -> ApiResult<LockoutStats> {
        // `locked_at` 是 datetime 列，**必须**用 `type::datetime()` 转过再比。
        // 直接拿它跟数字比不会报错，但 SurrealDB 是按**类型序**排的：任何 datetime
        // 都大于任何数字，于是 `locked_at >= <时间戳>` 恒为真 —— 这两个统计以前
        // 完全无视时间窗口，报的是有史以来的总数，只增不减。
        // （实测：`time::now() >= <未来时间戳>` 返回 true。）
        let user_lockouts_query = "SELECT count() as count FROM account_lockout WHERE lockout_type = 'User' AND locked_at >= type::datetime($start_time) GROUP ALL";
        let ip_lockouts_query = "SELECT count() as count FROM account_lockout WHERE lockout_type = 'IpAddress' AND locked_at >= type::datetime($start_time) GROUP ALL";
        let active_lockouts_query = "SELECT count() as count FROM account_lockout WHERE status = 'Locked' AND locked_until > $now GROUP ALL";

        let user_lockouts = self
            .execute_count_query_since(user_lockouts_query, start_time)
            .await?;
        let ip_lockouts = self
            .execute_count_query_since(ip_lockouts_query, start_time)
            .await?;

        let mut active_result = self
            .db
            .client
            .query(active_lockouts_query)
            .bind(("now", Utc::now()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get active lockouts count: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let active_lockouts: Option<i64> = active_result.take("count").map_err(|e| {
            error!("Failed to extract active lockouts count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

        // Calculate average lockout duration
        let duration_query = "SELECT type::string(locked_at) AS locked_at, \
             type::string(locked_until) AS locked_until FROM account_lockout \
             WHERE locked_at >= $start_time AND locked_until != NONE";
        let mut duration_result = self
            .db
            .client
            .query(duration_query)
            .bind(("start_time", start_time))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get lockout durations: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        // 时间列以字符串投影出来（SDK 无法把 Value::Datetime 转成 serde_json::Value）。
        let duration_rows = take_rows(&mut duration_result, "lockout durations")?;
        let spans: Vec<i64> = duration_rows
            .iter()
            .filter_map(|r| {
                let start = DateTime::parse_from_rfc3339(&row::str_field(r, "locked_at")).ok()?;
                let end = DateTime::parse_from_rfc3339(&row::str_field(r, "locked_until")).ok()?;
                Some((end - start).num_minutes())
            })
            .collect();
        let average_lockout_duration_minutes = if spans.is_empty() {
            0.0
        } else {
            spans.iter().sum::<i64>() as f64 / spans.len() as f64
        };

        Ok(LockoutStats {
            user_lockouts,
            ip_lockouts,
            active_lockouts: active_lockouts.unwrap_or(0),
            average_lockout_duration_minutes,
        })
    }

    /// 窗口内的限流违规次数。
    ///
    /// 这里以前是**估算**：数"失败登录超过 10 次的 IP 有几个"，
    /// 注释写着「Since we don't store rate limit violations directly」。
    /// 那句话已经不成立 —— 限流中间件在触发阻塞的那一刻就会写一条
    /// `rate_limit_violation` 审计事件（见 `utils::rate_limit_middleware`）。
    /// 也就是说真值一直躺在同一张表里，而这个接口报的是另一个量纲
    /// （IP 个数，不是违规次数），且与限流是否真的触发过毫无关系。
    pub async fn get_rate_limit_violations(&self, start_time: DateTime<Utc>) -> ApiResult<i64> {
        let query = "SELECT count() as count FROM user_activity \
                     WHERE action = 'rate_limit_violation' AND timestamp >= $start_time GROUP ALL";
        self.execute_count_query(query, start_time).await
    }

    // Permission Denials
    pub async fn get_permission_denials(&self, start_time: DateTime<Utc>) -> ApiResult<i64> {
        let query = "SELECT count() as count FROM user_activity WHERE action = 'permission_denied' AND timestamp >= $start_time GROUP ALL";
        self.execute_count_query(query, start_time).await
    }

    // Failed Login by IP
    pub async fn get_failed_login_by_ip(
        &self,
        start_time: DateTime<Utc>,
    ) -> ApiResult<Vec<IpActivityMetric>> {
        let query = "SELECT ip_address, count() as failed_attempts, math::max(timestamp) as last_attempt FROM user_activity WHERE action = 'login_failed' AND timestamp >= $start_time GROUP BY ip_address ORDER BY failed_attempts DESC LIMIT 20";

        let mut result = self
            .db
            .client
            .query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get failed login by IP: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let ip_rows = take_rows(&mut result, "lockout IP counts")?;

        // 先把窗口内所有仍在锁定中的 IP 一次取回来。
        //
        // 以前是在下面的循环里逐个 IP 查一次 —— 最多 20 个 IP 就是 21 次往返，
        // 与 `list_users` 的 N+1 是同一类问题。
        let locked_ips: Vec<Value> = {
            let mut r = self
                .db
                .client
                .query(
                    "SELECT identifier FROM account_lockout \
                     WHERE lockout_type = 'IpAddress' AND locked_until > $now",
                )
                .bind(("now", Utc::now()))
                .await
                .and_then(|response| response.check())
                .map_err(|e| {
                    error!("Failed to load locked IPs: {}", e);
                    AuthError::DatabaseError("Query execution failed".to_string())
                })?;
            take_rows(&mut r, "currently locked IPs")?
        };
        let locked: std::collections::HashSet<String> = locked_ips
            .iter()
            .map(|r| row::str_field(r, "identifier"))
            .collect();

        let mut metrics = Vec::new();
        for r in &ip_rows {
            let ip_address = row::str_field(r, "ip_address");
            let failed_attempts = row::i64_field(r, "failed_attempts");
            let last_attempt_timestamp = row::i64_field(r, "last_attempt");
            let last_attempt =
                DateTime::from_timestamp(last_attempt_timestamp, 0).unwrap_or_else(Utc::now);

            metrics.push(IpActivityMetric {
                is_locked: locked.contains(&ip_address),
                ip_address,
                failed_attempts,
                last_attempt,
            });
        }

        Ok(metrics)
    }

    // Suspicious Activities Detection
    pub async fn get_suspicious_activities(
        &self,
        start_time: DateTime<Utc>,
    ) -> ApiResult<Vec<SuspiciousActivity>> {
        // Multiple criteria for suspicious activity:
        // 1. High frequency failed logins from same IP
        // 2. Login attempts from unusual locations
        // 3. Multiple account access attempts

        // `user_id` 必须投影成字符串。它是 `record<actor_identity>`，SDK 转不成
        // `serde_json::Value`，整个结果集会解析失败 —— 而这个函数同时喂给
        // `/api/audit/security-report` 与 `/security-metrics` 两个端点。
        //
        // 这条以前被 `.take(0).unwrap_or_default()` 吞掉，两个端点一直返回
        // 200 加一份空的可疑活动列表。同文件里 `get_top_active_users` 的同类
        // 查询从一开始就写的是 `type::string(user_id)`，只有这里漏了。
        let query = "SELECT ip_address, type::string(user_id) AS user_id, action, count() as count, math::min(timestamp) as first_seen, math::max(timestamp) as last_seen FROM user_activity WHERE timestamp >= $start_time AND (action = 'login_failed' OR action = 'permission_denied') GROUP BY ip_address, user_id, action ORDER BY count DESC LIMIT 50";

        let mut result = self
            .db
            .client
            .query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get suspicious activities: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let activity_rows = take_rows(&mut result, "suspicious activities")?;

        let mut suspicious = Vec::new();
        for r in &activity_rows {
            let ip_address = row::str_field(r, "ip_address");
            let user_id = row::opt_str_field(r, "user_id");
            let activity_type = row::str_field(r, "action");
            let count = row::i64_field(r, "count");
            let first_seen_ts = row::i64_field(r, "first_seen");
            let last_seen_ts = row::i64_field(r, "last_seen");
            if count <= 5 {
                continue;
            }
            let risk_score = self.calculate_risk_score(count, &activity_type);
            let first_seen = DateTime::from_timestamp(first_seen_ts, 0).unwrap_or_else(Utc::now);
            let last_seen = DateTime::from_timestamp(last_seen_ts, 0).unwrap_or_else(Utc::now);

            suspicious.push(SuspiciousActivity {
                user_id,
                ip_address,
                activity_type,
                count,
                risk_score,
                first_seen,
                last_seen,
            });
        }

        Ok(suspicious)
    }

    // Activities by Category
    pub async fn get_activities_by_category(
        &self,
        start_time: DateTime<Utc>,
    ) -> ApiResult<Vec<CategoryMetric>> {
        let query = "SELECT category, count() as count FROM user_activity WHERE timestamp >= $start_time GROUP BY category ORDER BY count DESC";
        let mut result = self
            .db
            .client
            .query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get activities by category: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let rows = take_rows(&mut result, "activity categories")?;
        let categories: Vec<(String, i64)> = rows
            .iter()
            .map(|r| (row::str_field(r, "category"), row::i64_field(r, "count")))
            .collect();
        let total: i64 = categories.iter().map(|(_, count)| count).sum();

        Ok(categories
            .into_iter()
            .map(|(category, count)| CategoryMetric {
                category,
                count,
                percentage: if total > 0 {
                    (count as f64 / total as f64) * 100.0
                } else {
                    0.0
                },
            })
            .collect())
    }

    // Activities by Status
    pub async fn get_activities_by_status(
        &self,
        start_time: DateTime<Utc>,
    ) -> ApiResult<Vec<StatusMetric>> {
        let query = "SELECT status, count() as count FROM user_activity WHERE timestamp >= $start_time GROUP BY status ORDER BY count DESC";
        let mut result = self
            .db
            .client
            .query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get activities by status: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let rows = take_rows(&mut result, "activity statuses")?;
        let statuses: Vec<(String, i64)> = rows
            .iter()
            .map(|r| (row::str_field(r, "status"), row::i64_field(r, "count")))
            .collect();
        let total: i64 = statuses.iter().map(|(_, count)| count).sum();

        Ok(statuses
            .into_iter()
            .map(|(status, count)| StatusMetric {
                status,
                count,
                percentage: if total > 0 {
                    (count as f64 / total as f64) * 100.0
                } else {
                    0.0
                },
            })
            .collect())
    }

    // Top Active Users
    pub async fn get_top_active_users(
        &self,
        start_time: DateTime<Utc>,
    ) -> ApiResult<Vec<UserActivityMetric>> {
        // SurrealDB 3.x: avoid JOIN; aggregate first, then resolve user email map.
        let query = "SELECT type::string(user_id) as user_id, count() as activity_count, math::max(timestamp) as last_activity FROM user_activity WHERE timestamp >= $start_time AND user_id != NONE GROUP BY user_id ORDER BY activity_count DESC LIMIT 20";

        let mut result = self
            .db
            .client
            .query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get top active users: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let rows = take_rows(&mut result, "top users")?;

        let mut compact_rows: Vec<(String, i64, i64)> = Vec::new();
        let mut user_keys: Vec<String> = Vec::new();
        for row in rows {
            let obj = match row {
                Value::Object(o) => o,
                _ => continue,
            };

            let user_id = obj
                .get("user_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if user_id.is_empty() {
                continue;
            }

            let activity_count = obj
                .get("activity_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let last_activity_ts = obj
                .get("last_activity")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            // Normalize to `user:<uuid>` for lookup in user table.
            let normalized = user_id
                .trim_start_matches("user:")
                .trim_matches(|c| c == '⟨' || c == '⟩');
            user_keys.push(format!("user:{}", normalized));
            compact_rows.push((user_id, activity_count, last_activity_ts));
        }

        let mut email_map: HashMap<String, String> = HashMap::new();
        if !user_keys.is_empty() {
            let user_query = "SELECT type::string(id) as id, email FROM user WHERE type::string(id) IN $user_ids";
            let mut user_result = self
                .db
                .client
                .query(user_query)
                .bind(("user_ids", user_keys))
                .await
                .and_then(|response| response.check())
                .map_err(|e| {
                    error!("Failed to query user emails: {}", e);
                    AuthError::DatabaseError("Query execution failed".to_string())
                })?;

            let user_rows = take_rows(&mut user_result, "user activity")?;
            for row in user_rows {
                let obj = match row {
                    Value::Object(o) => o,
                    _ => continue,
                };
                let id = obj
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let email = obj
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !id.is_empty() {
                    email_map.insert(id, email);
                }
            }
        }

        let users = compact_rows
            .into_iter()
            .map(|(user_id, activity_count, last_activity_ts)| {
                let normalized = user_id
                    .trim_start_matches("user:")
                    .trim_matches(|c| c == '⟨' || c == '⟩');
                let lookup_id = format!("user:{}", normalized);
                let email = email_map.get(&lookup_id).cloned().unwrap_or_default();
                let last_activity =
                    DateTime::from_timestamp(last_activity_ts, 0).unwrap_or_else(Utc::now);

                UserActivityMetric {
                    user_id,
                    email,
                    activity_count,
                    last_activity,
                }
            })
            .collect();

        Ok(users)
    }

    // Hourly Activity Distribution
    pub async fn get_hourly_activity_distribution(
        &self,
        start_time: DateTime<Utc>,
    ) -> ApiResult<Vec<HourlyActivity>> {
        // `timestamp` 是 Unix 秒（number）。`time::hour()` 只接受 datetime，
        // 对数字列不会报错但恒返回 NONE —— 实测确认。这里直接用算术取 UTC 小时。
        let query = "SELECT math::floor((timestamp % 86400) / 3600) as hour, count() as count \
                     FROM user_activity WHERE timestamp >= $start_time \
                     GROUP BY hour ORDER BY hour";

        let mut result = self
            .db
            .client
            .query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get hourly activity distribution: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let hourly_rows = take_rows(&mut result, "hourly activity")?;
        let hourly_data: Vec<(i32, i64)> = hourly_rows
            .iter()
            .map(|r| (row::i64_field(r, "hour") as i32, row::i64_field(r, "count")))
            .collect();

        // Fill in missing hours with 0 count
        let hourly_map: HashMap<i32, i64> = hourly_data.into_iter().collect();
        let mut distribution = Vec::new();

        for hour in 0..24 {
            distribution.push(HourlyActivity {
                hour,
                count: *hourly_map.get(&hour).unwrap_or(&0),
            });
        }

        Ok(distribution)
    }

    // Generate Executive Summary
    pub async fn generate_executive_summary(
        &self,
        start_time: DateTime<Utc>,
    ) -> ApiResult<ExecutiveSummary> {
        let total_users = self.get_total_users().await?;
        let active_users = self.get_active_users_count(start_time).await?;
        let security_incidents = self.get_security_incidents_count(start_time).await?;
        let auth_stats = self.get_authentication_stats(start_time).await?;

        let has_attempts = auth_stats.successful_logins + auth_stats.failed_logins > 0;
        let risk_level =
            self.calculate_risk_level(security_incidents, auth_stats.success_rate, has_attempts);

        Ok(ExecutiveSummary {
            total_users,
            active_users,
            security_incidents,
            success_rate: auth_stats.success_rate,
            risk_level,
        })
    }

    // Security Recommendations
    pub async fn generate_security_recommendations(
        &self,
        start_time: DateTime<Utc>,
    ) -> ApiResult<Vec<SecurityRecommendation>> {
        let mut recommendations = Vec::new();

        // Check authentication success rate
        let auth_stats = self.get_authentication_stats(start_time).await?;
        // 同 `calculate_risk_level`：窗口内一次登录都没有时，成功率是 0.0 而非
        // "无数据"，不加这个判断就会对一个空系统发出高优先级告警。
        let has_attempts = auth_stats.successful_logins + auth_stats.failed_logins > 0;
        if has_attempts && auth_stats.success_rate < 90.0 {
            recommendations.push(SecurityRecommendation {
                priority: "High".to_string(),
                category: "Authentication".to_string(),
                title: "Low Authentication Success Rate".to_string(),
                description: format!(
                    "Authentication success rate is {:.1}%, which is below the recommended 90%. Consider investigating failed login patterns and implementing additional security measures.",
                    auth_stats.success_rate
                ),
                estimated_impact: "High".to_string(),
            });
        }

        // Check for suspicious activities
        let suspicious = self.get_suspicious_activities(start_time).await?;
        if !suspicious.is_empty() {
            let high_risk_count = suspicious.iter().filter(|s| s.risk_score > 7).count();
            if high_risk_count > 0 {
                recommendations.push(SecurityRecommendation {
                    priority: "High".to_string(),
                    category: "Security".to_string(),
                    title: "High-Risk Suspicious Activities Detected".to_string(),
                    description: format!(
                        "Detected {} high-risk suspicious activities. Review and investigate these activities immediately.",
                        high_risk_count
                    ),
                    estimated_impact: "Critical".to_string(),
                });
            }
        }

        // Check lockout patterns
        let lockout_stats = self.get_lockout_stats(start_time).await?;
        if lockout_stats.user_lockouts > 10 {
            recommendations.push(SecurityRecommendation {
                priority: "Medium".to_string(),
                category: "Security".to_string(),
                title: "High Number of Account Lockouts".to_string(),
                description: format!(
                    "There have been {} user account lockouts in the analysis period. Consider reviewing password policies and user education.",
                    lockout_stats.user_lockouts
                ),
                estimated_impact: "Medium".to_string(),
            });
        }

        // Default recommendation if no issues found
        if recommendations.is_empty() {
            recommendations.push(SecurityRecommendation {
                priority: "Low".to_string(),
                category: "General".to_string(),
                title: "Security Status Normal".to_string(),
                description: "No critical security issues detected in the analysis period. Continue monitoring and maintain current security practices.".to_string(),
                estimated_impact: "Low".to_string(),
            });
        }

        Ok(recommendations)
    }

    // Helper methods
    /// 同 [`Self::execute_count_query`]，但把 `$start_time` 绑成 **RFC3339 字符串**，
    /// 供 SQL 里的 `type::datetime($start_time)` 使用。
    ///
    /// 两个版本必须分开：`user_activity.timestamp` 是 number 列，要绑数字；
    /// `account_lockout.locked_at` 是 datetime 列，绑数字会因为类型序而恒真。
    async fn execute_count_query_since(
        &self,
        query: &str,
        start_time: DateTime<Utc>,
    ) -> ApiResult<i64> {
        let count_result: Vec<serde_json::Value> = self
            .db
            .query_take0_vec(
                "audit_execute_count_query_since",
                query,
                json!({ "start_time": start_time.to_rfc3339() }),
            )
            .await
            .map_err(|e| {
                error!("Failed to execute count query: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        Ok(count_result
            .first()
            .and_then(|c| c.get("count"))
            .and_then(|c| c.as_i64())
            .unwrap_or(0))
    }

    /// 按 `user_activity.timestamp`（number 列）统计。
    async fn execute_count_query(&self, query: &str, start_time: DateTime<Utc>) -> ApiResult<i64> {
        let count_result: Vec<serde_json::Value> = self
            .db
            .query_take0_vec(
                "audit_execute_count_query",
                query,
                json!({ "start_time": start_time.timestamp() }),
            )
            .await
            .map_err(|e| {
                error!("Failed to execute count query: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        Ok(count_result
            .first()
            .and_then(|c| c.get("count"))
            .and_then(|c| c.as_i64())
            .unwrap_or(0))
    }

    async fn get_total_users(&self) -> ApiResult<i64> {
        let query = "SELECT count() as count FROM user WHERE account_status != 'Deleted' GROUP ALL";
        let count_result: Vec<serde_json::Value> = self
            .db
            .query_take0_vec_no_bind("audit_get_total_users", query)
            .await
            .map_err(|e| {
                error!("Failed to get total users: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        Ok(count_result
            .first()
            .and_then(|c| c.get("count"))
            .and_then(|c| c.as_i64())
            .unwrap_or(0))
    }

    async fn get_active_users_count(&self, start_time: DateTime<Utc>) -> ApiResult<i64> {
        let query = "SELECT type::string(user_id) as user_id FROM user_activity WHERE timestamp >= $start_time AND user_id != NONE GROUP BY user_id";
        let rows: Vec<Value> = self
            .db
            .query_take0_vec(
                "audit_get_active_users_count",
                query,
                json!({ "start_time": start_time.timestamp() }),
            )
            .await
            .map_err(|e| {
                error!("Failed to get active users count: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;
        Ok(rows.len() as i64)
    }

    async fn get_security_incidents_count(&self, start_time: DateTime<Utc>) -> ApiResult<i64> {
        let query = "SELECT count() as count FROM user_activity WHERE category = 'Security' AND status IN ['Failed', 'Warning'] AND timestamp >= $start_time GROUP ALL";
        self.execute_count_query(query, start_time).await
    }

    fn calculate_risk_score(&self, count: i64, activity_type: &str) -> i32 {
        let base_score = match activity_type {
            "login_failed" => 2,
            "permission_denied" => 3,
            "account_locked" => 5,
            _ => 1,
        };

        let frequency_multiplier = match count {
            0..=5 => 1,
            6..=10 => 2,
            11..=20 => 3,
            _ => 4,
        };

        (base_score * frequency_multiplier).min(10)
    }

    /// 风险等级。
    ///
    /// `has_attempts` 不能省。没有任何登录尝试时 `success_rate` 是 0.0
    /// （`get_authentication_stats` 里 total_attempts == 0 就返回 0.0），
    /// 而 `0.0 < 80.0` 恒真 —— 于是**一个刚装好、还没有人登录过的部署，
    /// 执行摘要里的风险等级就是 High**。第一天就喊狼来了，
    /// 训练出来的结果是运维不再看这个字段。
    fn calculate_risk_level(
        &self,
        security_incidents: i64,
        success_rate: f64,
        has_attempts: bool,
    ) -> String {
        let rate_is_meaningful = has_attempts;

        if security_incidents > 20 || (rate_is_meaningful && success_rate < 80.0) {
            "High".to_string()
        } else if security_incidents > 10 || (rate_is_meaningful && success_rate < 90.0) {
            "Medium".to_string()
        } else {
            "Low".to_string()
        }
    }
}

/// 取结果集的第 0 组；反序列化失败**上抛**，不当成空数据。
///
/// 这个文件里原先一律写 `.take(0).unwrap_or_default()`：查询本身成功、行解析
/// 失败时接口照样 200，看板一片空白 —— 监控分不出「这段时间没有事件」和
/// 「这次读取失败了」。下面那段注释记着这个坑真的发生过一次。
fn take_rows(
    result: &mut surrealdb::IndexedResults,
    what: &str,
) -> ApiResult<Vec<serde_json::Value>> {
    result.take(0).map_err(|e| {
        error!("Failed to read {what}: {e}");
        AuthError::DatabaseError("Query result could not be read".to_string())
    })
}

/// SurrealDB 返回的每一行都是**对象**，不是元组。
///
/// 这个文件里原先有 8 处写成 `take::<Vec<(String, i64)>>(0)` 之类的元组解析，
/// 全部会失败（"Expected [string, int], got object"）。其中 7 处套了
/// `.unwrap_or_default()`，于是静默返回空数组 —— 接口照样 200，数据却是空的；
/// 剩下 1 处用 `?`，直接把 `/api/audit/dashboard` 打成 500。
mod row {
    use serde_json::Value;

    pub fn str_field(row: &Value, key: &str) -> String {
        row.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    pub fn opt_str_field(row: &Value, key: &str) -> Option<String> {
        row.get(key)
            .and_then(|v| v.as_str())
            .map(|v| v.to_string())
            .filter(|v| !v.is_empty())
    }

    pub fn i64_field(row: &Value, key: &str) -> i64 {
        row.get(key).and_then(|v| v.as_i64()).unwrap_or(0)
    }
}
