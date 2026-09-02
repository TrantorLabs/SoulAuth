use axum::{extract::Query, response::Json, routing::get, Extension, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cmp::Reverse;
use std::{collections::HashMap, sync::Arc};

use crate::{
    config::Config,
    error::{AuthError, Result as ApiResult},
    require_permission,
    services::{audit::AuditService, audit_integrity, database::Database},
    utils::jwt::AuthedUser,
};

pub fn audit_routes() -> Router {
    Router::new()
        .route("/dashboard", get(get_audit_dashboard))
        .route("/security-metrics", get(get_security_metrics))
        .route("/activity-summary", get(get_activity_summary))
        .route("/system-health", get(get_system_health))
        .route("/security-report", get(generate_security_report))
        .route("/integrity", get(verify_integrity))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub days: Option<i64>,
    pub hours: Option<i64>,
}

/// 报表窗口的上限。
///
/// 上限不是为了"合理"，是因为 `chrono::Duration::days()` **越界会 panic**：
/// `?days=99999999`（约 27 万年）就足以让 `Utc::now() - Duration::days(days)`
/// 溢出，handler 当场 panic、连接被丢弃、客户端收到的是网络错误而不是 HTTP 错误。
/// 实测 `?days=99999999` / `?days=<i64::MAX>` / `?hours=<i64::MAX>` 各打出一次 panic。
/// 这不是攻击性输入，是手滑就能打出来的值。
const MAX_REPORT_DAYS: i64 = 366;
const MAX_REPORT_HOURS: i64 = MAX_REPORT_DAYS * 24;

/// 天数窗口：非正值回落到默认，超出上限则夹住。
///
/// 负数同样要挡：`?days=-1` 会让 start_time 落在**未来**，
/// 查询恒空，于是报表安静地返回"这段时间什么都没发生"——
/// 比报错更难发现。
fn clamp_days(requested: Option<i64>, default_days: i64) -> i64 {
    match requested {
        Some(d) if d > 0 => d.min(MAX_REPORT_DAYS),
        _ => default_days,
    }
}

fn clamp_hours(requested: Option<i64>, default_hours: i64) -> i64 {
    match requested {
        Some(h) if h > 0 => h.min(MAX_REPORT_HOURS),
        _ => default_hours,
    }
}

#[derive(Serialize)]
pub struct AuditDashboard {
    pub period: String,
    pub total_users: i64,
    pub active_sessions: i64,
    pub failed_logins: i64,
    pub locked_accounts: i64,
    pub security_events: i64,
    pub top_activities: Vec<ActivityMetric>,
    pub login_trends: Vec<TimeseriesData>,
    pub security_trends: Vec<TimeseriesData>,
}

#[derive(Serialize)]
pub struct SecurityMetrics {
    pub period: String,
    pub authentication_stats: AuthenticationStats,
    pub lockout_stats: LockoutStats,
    pub rate_limit_violations: i64,
    pub permission_denials: i64,
    pub failed_login_by_ip: Vec<IpActivityMetric>,
    pub suspicious_activities: Vec<SuspiciousActivity>,
}

#[derive(Serialize)]
pub struct ActivitySummary {
    pub period: String,
    pub total_activities: i64,
    pub by_category: Vec<CategoryMetric>,
    pub by_status: Vec<StatusMetric>,
    pub top_users: Vec<UserActivityMetric>,
    pub hourly_distribution: Vec<HourlyActivity>,
}

#[derive(Serialize)]
pub struct SystemHealth {
    pub timestamp: DateTime<Utc>,
    pub database_status: DatabaseHealth,
    pub active_sessions_count: i64,
    pub pending_lockouts: i64,
    pub memory_usage: MemoryStats,
    pub uptime_seconds: i64,
}

#[derive(Serialize)]
pub struct SecurityReport {
    pub generated_at: DateTime<Utc>,
    pub period: String,
    pub executive_summary: ExecutiveSummary,
    pub authentication_analysis: AuthenticationAnalysis,
    pub security_incidents: Vec<SecurityIncident>,
    pub user_behavior_analysis: UserBehaviorAnalysis,
    pub recommendations: Vec<SecurityRecommendation>,
}

#[derive(Serialize)]
pub struct ActivityMetric {
    pub action: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct TimeseriesData {
    pub timestamp: DateTime<Utc>,
    pub value: i64,
}

#[derive(Serialize)]
pub struct AuthenticationStats {
    pub successful_logins: i64,
    pub failed_logins: i64,
    pub oauth_logins: i64,
    pub password_resets: i64,
    pub success_rate: f64,
}

#[derive(Serialize)]
pub struct LockoutStats {
    pub user_lockouts: i64,
    pub ip_lockouts: i64,
    pub active_lockouts: i64,
    pub average_lockout_duration_minutes: f64,
}

#[derive(Serialize)]
pub struct IpActivityMetric {
    pub ip_address: String,
    pub failed_attempts: i64,
    pub is_locked: bool,
    pub last_attempt: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct SuspiciousActivity {
    pub user_id: Option<String>,
    pub ip_address: String,
    pub activity_type: String,
    pub count: i64,
    pub risk_score: i32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct CategoryMetric {
    pub category: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct StatusMetric {
    pub status: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct UserActivityMetric {
    pub user_id: String,
    pub email: String,
    pub activity_count: i64,
    pub last_activity: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct HourlyActivity {
    pub hour: i32,
    pub count: i64,
}

#[derive(Serialize)]
pub struct DatabaseHealth {
    pub connected: bool,
    pub response_time_ms: i64,
}

#[derive(Serialize)]
pub struct MemoryStats {
    pub used_mb: f64,
    pub available_mb: f64,
    pub usage_percentage: f64,
}

#[derive(Serialize)]
pub struct ExecutiveSummary {
    pub total_users: i64,
    pub active_users: i64,
    pub security_incidents: i64,
    pub success_rate: f64,
    pub risk_level: String,
}

#[derive(Serialize)]
pub struct AuthenticationAnalysis {
    pub login_patterns: Vec<LoginPattern>,
    pub failure_analysis: Vec<FailureAnalysis>,
    pub geographic_distribution: Vec<GeographicMetric>,
}

#[derive(Serialize)]
pub struct SecurityIncident {
    pub id: String,
    pub incident_type: String,
    pub severity: String,
    pub affected_user: Option<String>,
    pub ip_address: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub resolved: bool,
}

#[derive(Serialize)]
pub struct UserBehaviorAnalysis {
    pub login_frequency_distribution: Vec<FrequencyMetric>,
    pub peak_activity_hours: Vec<i32>,
    pub user_retention_metrics: RetentionMetrics,
}

#[derive(Serialize)]
pub struct SecurityRecommendation {
    pub priority: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub estimated_impact: String,
}

#[derive(Serialize)]
pub struct LoginPattern {
    pub pattern_type: String,
    pub count: i64,
    pub trend: String,
}

#[derive(Serialize)]
pub struct FailureAnalysis {
    pub failure_reason: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct GeographicMetric {
    pub country: String,
    pub region: String,
    pub count: i64,
}

#[derive(Serialize)]
pub struct FrequencyMetric {
    pub frequency_range: String,
    pub user_count: i64,
    pub percentage: f64,
}

#[derive(Serialize)]
/// 活跃率。
///
/// 注意：这不是留存率（留存需要按注册队列做同期群分析）。这里给的是
/// "最近 N 天内有过活动的用户 / 全部有效用户"，字段名如实反映口径。
pub struct RetentionMetrics {
    pub daily_active_rate: f64,
    pub weekly_active_rate: f64,
    pub monthly_active_rate: f64,
}

pub async fn get_audit_dashboard(
    Extension(db): Extension<Arc<Database>>,
    authed_user: AuthedUser,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<AuditDashboard>> {
    let user_id = authed_user.id()?;
    require_permission!(&db, &user_id, crate::models::permission::names::AUDIT_READ);

    let days = clamp_days(query.days, 7);
    let start_time = Utc::now() - Duration::days(days);

    tracing::info!("Generating audit dashboard for {} days", days);

    // Get total users
    let total_users = get_total_users(&db).await?;

    // Get active sessions
    let active_sessions = get_active_sessions_count(&db).await?;

    // Get failed logins in period
    let failed_logins = get_failed_logins_count(&db, start_time).await?;

    // Get locked accounts
    let locked_accounts = get_locked_accounts_count(&db).await?;

    // Get security events count
    let security_events = get_security_events_count(&db, start_time).await?;

    // Get top activities using audit service
    let top_activities = get_top_activities(&db, start_time).await?;

    // Get login trends (daily aggregation)
    let login_trends = get_login_trends(&db, start_time, days).await?;

    // Get security trends
    let security_trends = get_security_trends(&db, start_time, days).await?;

    let dashboard = AuditDashboard {
        period: format!("Last {} days", days),
        total_users,
        active_sessions,
        failed_logins,
        locked_accounts,
        security_events,
        top_activities,
        login_trends,
        security_trends,
    };

    Ok(Json(dashboard))
}

pub async fn get_security_metrics(
    Extension(db): Extension<Arc<Database>>,
    authed_user: AuthedUser,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<SecurityMetrics>> {
    let user_id = authed_user.id()?;
    require_permission!(
        &db,
        &user_id,
        crate::models::permission::names::SECURITY_READ
    );

    let hours = clamp_hours(query.hours, 24);
    let start_time = Utc::now() - Duration::hours(hours);

    tracing::info!("Generating security metrics for {} hours", hours);

    let audit_service = AuditService::new(db.as_ref().clone());

    let authentication_stats = audit_service.get_authentication_stats(start_time).await?;
    let lockout_stats = audit_service.get_lockout_stats(start_time).await?;
    let rate_limit_violations = audit_service.get_rate_limit_violations(start_time).await?;
    let permission_denials = audit_service.get_permission_denials(start_time).await?;
    let failed_login_by_ip = audit_service.get_failed_login_by_ip(start_time).await?;
    let suspicious_activities = audit_service.get_suspicious_activities(start_time).await?;

    let metrics = SecurityMetrics {
        period: format!("Last {} hours", hours),
        authentication_stats,
        lockout_stats,
        rate_limit_violations,
        permission_denials,
        failed_login_by_ip,
        suspicious_activities,
    };

    Ok(Json(metrics))
}

pub async fn get_activity_summary(
    Extension(db): Extension<Arc<Database>>,
    authed_user: AuthedUser,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<ActivitySummary>> {
    let user_id = authed_user.id()?;
    require_permission!(&db, &user_id, crate::models::permission::names::AUDIT_READ);

    let days = clamp_days(query.days, 7);
    let start_time = Utc::now() - Duration::days(days);

    tracing::info!("Generating activity summary for {} days", days);

    let audit_service = AuditService::new(db.as_ref().clone());

    let total_activities = get_total_activities_count(&db, start_time).await?;
    let by_category = audit_service.get_activities_by_category(start_time).await?;
    let by_status = audit_service.get_activities_by_status(start_time).await?;
    let top_users = audit_service.get_top_active_users(start_time).await?;
    let hourly_distribution = audit_service
        .get_hourly_activity_distribution(start_time)
        .await?;

    let summary = ActivitySummary {
        period: format!("Last {} days", days),
        total_activities,
        by_category,
        by_status,
        top_users,
        hourly_distribution,
    };

    Ok(Json(summary))
}

pub async fn get_system_health(
    Extension(db): Extension<Arc<Database>>,
    authed_user: AuthedUser,
) -> ApiResult<Json<SystemHealth>> {
    let user_id = authed_user.id()?;
    require_permission!(
        &db,
        &user_id,
        crate::models::permission::names::SECURITY_READ
    );

    tracing::info!("Checking system health");

    let database_status = check_database_health(&db).await?;
    let active_sessions_count = get_active_sessions_count(&db).await?;
    let pending_lockouts = get_pending_lockouts_count(&db).await?;
    let memory_usage = get_memory_usage().await;
    let uptime_seconds = get_uptime_seconds();

    let health = SystemHealth {
        timestamp: Utc::now(),
        database_status,
        active_sessions_count,
        pending_lockouts,
        memory_usage,
        uptime_seconds,
    };

    Ok(Json(health))
}

pub async fn generate_security_report(
    Extension(db): Extension<Arc<Database>>,
    authed_user: AuthedUser,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<SecurityReport>> {
    let user_id = authed_user.id()?;
    require_permission!(&db, &user_id, crate::models::permission::names::AUDIT_READ);

    let days = clamp_days(query.days, 30);
    let start_time = Utc::now() - Duration::days(days);

    tracing::info!("Generating comprehensive security report for {} days", days);

    let audit_service = AuditService::new(db.as_ref().clone());

    let executive_summary = audit_service.generate_executive_summary(start_time).await?;
    let authentication_analysis = generate_authentication_analysis(&db, start_time).await?;
    let security_incidents = get_security_incidents(&db, start_time).await?;
    let user_behavior_analysis = generate_user_behavior_analysis(&db, start_time).await?;
    let recommendations = audit_service
        .generate_security_recommendations(start_time)
        .await?;

    let report = SecurityReport {
        generated_at: Utc::now(),
        period: format!("Last {} days", days),
        executive_summary,
        authentication_analysis,
        security_incidents,
        user_behavior_analysis,
        recommendations,
    };

    Ok(Json(report))
}

// Helper functions for data aggregation (implementation details)
async fn get_total_users(db: &Database) -> ApiResult<i64> {
    let query = "SELECT count() as total FROM user WHERE account_status != 'Deleted' GROUP ALL";
    let mut result = db
        .client
        .query(query)
        .await
        .and_then(|response| response.check())
        .map_err(|e| {
            tracing::error!("Failed to get total users: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

    let count: Option<i64> = result.take("total").map_err(|e| {
        tracing::error!("Failed to extract total users count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;

    Ok(count.unwrap_or(0))
}

async fn get_active_sessions_count(db: &Database) -> ApiResult<i64> {
    let query = "SELECT count() as total FROM session WHERE expires_at > $now GROUP ALL";
    let mut result = db
        .client
        .query(query)
        .bind(("now", Utc::now().timestamp()))
        .await
        .and_then(|response| response.check())
        .map_err(|e| {
            tracing::error!("Failed to get active sessions: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

    let count: Option<i64> = result.take("total").map_err(|e| {
        tracing::error!("Failed to extract active sessions count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;

    Ok(count.unwrap_or(0))
}

async fn get_failed_logins_count(db: &Database, start_time: DateTime<Utc>) -> ApiResult<i64> {
    let query = "SELECT count() as total FROM user_activity WHERE action = 'login_failed' AND timestamp >= $start_time GROUP ALL";
    let mut result = db
        .client
        .query(query)
        .bind(("start_time", start_time.timestamp()))
        .await
        .and_then(|response| response.check())
        .map_err(|e| {
            tracing::error!("Failed to get failed logins count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

    let count: Option<i64> = result.take("total").map_err(|e| {
        tracing::error!("Failed to extract failed logins count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;

    Ok(count.unwrap_or(0))
}

async fn get_locked_accounts_count(db: &Database) -> ApiResult<i64> {
    let query = "SELECT count() as total FROM account_lockout WHERE status = 'Locked' AND locked_until > $now GROUP ALL";
    let mut result = db
        .client
        .query(query)
        .bind(("now", Utc::now()))
        .await
        .and_then(|response| response.check())
        .map_err(|e| {
            tracing::error!("Failed to get locked accounts count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

    let count: Option<i64> = result.take("total").map_err(|e| {
        tracing::error!("Failed to extract locked accounts count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;

    Ok(count.unwrap_or(0))
}

async fn get_security_events_count(db: &Database, start_time: DateTime<Utc>) -> ApiResult<i64> {
    let query = "SELECT count() as total FROM user_activity WHERE category = 'Security' AND timestamp >= $start_time GROUP ALL";
    let mut result = db
        .client
        .query(query)
        .bind(("start_time", start_time.timestamp()))
        .await
        .and_then(|response| response.check())
        .map_err(|e| {
            tracing::error!("Failed to get security events count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

    let count: Option<i64> = result.take("total").map_err(|e| {
        tracing::error!("Failed to extract security events count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;

    Ok(count.unwrap_or(0))
}

async fn get_top_activities(
    db: &Database,
    start_time: DateTime<Utc>,
) -> ApiResult<Vec<ActivityMetric>> {
    let query = "SELECT action, count() as count FROM user_activity WHERE timestamp >= $start_time GROUP BY action ORDER BY count DESC LIMIT 10";
    let mut result = db
        .client
        .query(query)
        .bind(("start_time", start_time.timestamp()))
        .await
        .and_then(|response| response.check())
        .map_err(|e| {
            tracing::error!("Failed to get top activities: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

    // 每行是对象而非元组；原来的元组解析会失败，把 /api/audit/dashboard 打成 500。
    let rows: Vec<serde_json::Value> = result.take(0).map_err(|e| {
        tracing::error!("Failed to extract top activities: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;

    let activities: Vec<(String, i64)> = rows
        .iter()
        .map(|r| {
            (
                r.get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                r.get("count").and_then(|v| v.as_i64()).unwrap_or(0),
            )
        })
        .collect();

    let total: i64 = activities.iter().map(|(_, count)| count).sum();

    Ok(activities
        .into_iter()
        .map(|(action, count)| ActivityMetric {
            action,
            count,
            percentage: if total > 0 {
                (count as f64 / total as f64) * 100.0
            } else {
                0.0
            },
        })
        .collect())
}

async fn get_login_trends(
    db: &Database,
    start_time: DateTime<Utc>,
    _days: i64,
) -> ApiResult<Vec<TimeseriesData>> {
    // timestamp 是 Unix 秒（number），不能用 time::floor(_, 1d) —— 那是 datetime 函数。
    // 直接按 86400 取整分桶。
    let query = "SELECT math::floor(timestamp / 86400) * 86400 AS day, count() AS count \
                 FROM user_activity \
                 WHERE action IN ['login_success', 'oauth_login'] AND timestamp >= $start_time \
                 GROUP BY day ORDER BY day";

    let rows: Vec<serde_json::Value> = db
        .query_take0_vec(
            "audit_get_login_trends",
            query,
            json!({ "start_time": start_time.timestamp() }),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to get login trends: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let day = row.get("day")?.as_i64()?;
            let value = row.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            Some(TimeseriesData {
                timestamp: DateTime::<Utc>::from_timestamp(day, 0)?,
                value,
            })
        })
        .collect())
}

async fn get_security_trends(
    db: &Database,
    start_time: DateTime<Utc>,
    _days: i64,
) -> ApiResult<Vec<TimeseriesData>> {
    // timestamp 是 Unix 秒（number），不能用 time::floor(_, 1d) —— 那是 datetime 函数。
    // 直接按 86400 取整分桶。
    let query = "SELECT math::floor(timestamp / 86400) * 86400 AS day, count() AS count \
                 FROM user_activity \
                 WHERE category = 'Security' AND status IN ['Failed', 'Warning'] AND timestamp >= $start_time \
                 GROUP BY day ORDER BY day";

    let rows: Vec<serde_json::Value> = db
        .query_take0_vec(
            "audit_get_security_trends",
            query,
            json!({ "start_time": start_time.timestamp() }),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to get security trends: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let day = row.get("day")?.as_i64()?;
            let value = row.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            Some(TimeseriesData {
                timestamp: DateTime::<Utc>::from_timestamp(day, 0)?,
                value,
            })
        })
        .collect())
}

// Helper functions - simplified implementations for now

async fn get_total_activities_count(db: &Database, start_time: DateTime<Utc>) -> ApiResult<i64> {
    let query =
        "SELECT count() as count FROM user_activity WHERE timestamp >= $start_time GROUP ALL";
    let mut result = db
        .client
        .query(query)
        .bind(("start_time", start_time.timestamp()))
        .await
        .and_then(|response| response.check())
        .map_err(|e| {
            tracing::error!("Failed to get total activities count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

    let count: Option<i64> = result.take("count").map_err(|e| {
        tracing::error!("Failed to extract total activities count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;

    Ok(count.unwrap_or(0))
}

async fn check_database_health(db: &Database) -> ApiResult<DatabaseHealth> {
    let start = std::time::Instant::now();

    // Simple health check
    //
    // 这里也要 `.check()`：`query().await` 成功只说明请求送到了，语句本身失败
    // （比如鉴权态过期）仍然会被算成"连接正常"，健康检查就永远报绿。
    let query = "INFO FOR DB";
    let result = db
        .client
        .query(query)
        .await
        .and_then(|response| response.check());

    let response_time_ms = start.elapsed().as_millis() as i64;
    let connected = result.is_ok();
    if let Err(error) = &result {
        tracing::warn!(%error, "Database health check failed");
    }

    // SurrealDB 的 HTTP 客户端不暴露连接池指标，原来那两个"连接池"字段
    // 一直是写死的 1/10，已删除，避免把假数字当监控数据看。
    Ok(DatabaseHealth {
        connected,
        response_time_ms,
    })
}

async fn get_pending_lockouts_count(db: &Database) -> ApiResult<i64> {
    let query = "SELECT count() as count FROM account_lockout WHERE status = 'Locked' AND locked_until > $now GROUP ALL";
    let mut result = db
        .client
        .query(query)
        .bind(("now", Utc::now()))
        .await
        .and_then(|response| response.check())
        .map_err(|e| {
            tracing::error!("Failed to get pending lockouts count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

    let count: Option<i64> = result.take("count").map_err(|e| {
        tracing::error!("Failed to extract pending lockouts count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;

    Ok(count.unwrap_or(0))
}

/// 真实内存占用：本进程 RSS + 系统可用内存（读 /proc）。
///
/// 取不到时返回全 0，而不是像以前那样返回写死的 128MB / 512MB / 25%。
async fn get_memory_usage() -> MemoryStats {
    let used_mb = read_process_rss_mb().unwrap_or(0.0);
    let available_mb = read_mem_available_mb().unwrap_or(0.0);
    let total = used_mb + available_mb;
    let usage_percentage = if total > 0.0 {
        (used_mb / total) * 100.0
    } else {
        0.0
    };

    MemoryStats {
        used_mb,
        available_mb,
        usage_percentage,
    }
}

fn read_process_rss_mb() -> Option<f64> {
    // /proc/self/statm 的第二个字段是常驻页数。
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let resident_pages: f64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    let page_size = 4096.0; // Linux x86_64 / aarch64 常规页大小
    Some(resident_pages * page_size / (1024.0 * 1024.0))
}

fn read_mem_available_mb() -> Option<f64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = meminfo
        .lines()
        .find(|line| line.starts_with("MemAvailable:"))?;
    let kb: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024.0)
}

fn get_uptime_seconds() -> i64 {
    crate::process_uptime_seconds()
}

/// 认证行为分析。全部来自 `user_activity` 的真实记录。
///
/// 注意 `geographic_distribution` 恒为空：本服务没有接入任何 GeoIP 数据源，
/// 无法把 IP 映射到国家/地区。以前这里返回的是写死的 "US / California"。
async fn generate_authentication_analysis(
    db: &Arc<Database>,
    start_time: DateTime<Utc>,
) -> ApiResult<AuthenticationAnalysis> {
    let window_seconds = (Utc::now() - start_time).num_seconds().max(1);
    let previous_start = start_time - Duration::seconds(window_seconds);

    let current = count_actions_since(db, start_time, Some(Utc::now())).await?;
    let previous = count_actions_since(db, previous_start, Some(start_time)).await?;

    let mut login_patterns: Vec<LoginPattern> = current
        .iter()
        .map(|(action, count)| LoginPattern {
            pattern_type: action.clone(),
            count: *count,
            trend: trend_label(*count, previous.get(action).copied().unwrap_or(0)),
        })
        .collect();
    login_patterns.sort_by_key(|p| Reverse(p.count));

    // 失败分析：按 action 归类所有 status = Failed 的记录。
    let failures = count_failed_actions_since(db, start_time).await?;
    let total_failures: i64 = failures.values().sum();
    let mut failure_analysis: Vec<FailureAnalysis> = failures
        .into_iter()
        .map(|(reason, count)| FailureAnalysis {
            failure_reason: reason,
            count,
            percentage: if total_failures > 0 {
                (count as f64 / total_failures as f64) * 100.0
            } else {
                0.0
            },
        })
        .collect();
    failure_analysis.sort_by_key(|f| Reverse(f.count));

    Ok(AuthenticationAnalysis {
        login_patterns,
        failure_analysis,
        geographic_distribution: Vec::new(),
    })
}

/// 安全事件：来自真实的账号锁定记录 + 失败登录集中的 IP。
async fn get_security_incidents(
    db: &Arc<Database>,
    start_time: DateTime<Utc>,
) -> ApiResult<Vec<SecurityIncident>> {
    /// 单个 IP 在窗口内失败多少次算一条事件。
    const IP_FAILURE_THRESHOLD: i64 = 10;

    let mut incidents = Vec::new();

    // 1) 被锁定的账号 / IP
    let lockouts: Vec<serde_json::Value> = db
        .query_take0_vec(
            "audit_security_incident_lockouts",
            // `locked_at` 必须投影成字符串。SDK 无法把原生 `Value::Datetime` 转成
            // `serde_json::Value`（报 "Expected any, got datetime"），整个查询会直接
            // 失败 —— 而下面的代码本来也是按 RFC3339 字符串解析它的。
            //
            // 这个错以前不显形：只有窗口内确实存在锁定记录时才会返回行，表是空的
            // 就什么事都没有。也就是说 `/api/audit/security-report` 恰恰在
            // “有账号被锁”时才 500，而那正是最需要看这份报告的时候。
            "SELECT identifier, lockout_type, failed_attempts, \
             type::string(locked_at) AS locked_at, status \
             FROM account_lockout WHERE locked_at >= type::datetime($start_time)",
            json!({ "start_time": start_time.to_rfc3339() }),
        )
        .await?;

    for row in lockouts {
        let identifier = row
            .get("identifier")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let is_ip = row
            .get("lockout_type")
            .and_then(|v| v.as_str())
            .map(|kind| kind.eq_ignore_ascii_case("ipaddress"))
            .unwrap_or(false);
        let attempts = row
            .get("failed_attempts")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let timestamp = row
            .get("locked_at")
            .and_then(|v| v.as_str())
            .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(start_time);
        let resolved = row
            .get("status")
            .and_then(|v| v.as_str())
            .map(|status| status == "Normal")
            .unwrap_or(false);

        incidents.push(SecurityIncident {
            id: format!("lockout:{identifier}"),
            incident_type: "Account Lockout".to_string(),
            severity: if attempts >= 10 { "High" } else { "Medium" }.to_string(),
            affected_user: (!is_ip).then(|| identifier.clone()),
            ip_address: if is_ip { identifier } else { String::new() },
            description: format!("Locked after {attempts} failed authentication attempts"),
            timestamp,
            resolved,
        });
    }

    // 2) 失败登录集中的 IP（复用审计服务里已有的真实查询）
    let audit_service = AuditService::new(db.as_ref().clone());
    for ip_metric in audit_service.get_failed_login_by_ip(start_time).await? {
        if ip_metric.failed_attempts < IP_FAILURE_THRESHOLD {
            continue;
        }
        incidents.push(SecurityIncident {
            id: format!("failed-logins:{}", ip_metric.ip_address),
            incident_type: "Multiple Failed Logins".to_string(),
            severity: if ip_metric.failed_attempts >= 50 {
                "High"
            } else {
                "Medium"
            }
            .to_string(),
            affected_user: None,
            ip_address: ip_metric.ip_address,
            description: format!(
                "{} failed login attempts from a single IP",
                ip_metric.failed_attempts
            ),
            timestamp: ip_metric.last_attempt,
            resolved: !ip_metric.is_locked,
        });
    }

    incidents.sort_by_key(|i| Reverse(i.timestamp));
    Ok(incidents)
}

/// 用户行为分析，全部基于 `user_activity` 聚合。
async fn generate_user_behavior_analysis(
    db: &Arc<Database>,
    start_time: DateTime<Utc>,
) -> ApiResult<UserBehaviorAnalysis> {
    let audit_service = AuditService::new(db.as_ref().clone());

    // 峰值时段：取活动量最高的若干个小时。
    let mut hourly = audit_service
        .get_hourly_activity_distribution(start_time)
        .await?;
    hourly.sort_by_key(|h| Reverse(h.count));
    let peak_activity_hours: Vec<i32> = hourly
        .iter()
        .filter(|slot| slot.count > 0)
        .take(6)
        .map(|slot| slot.hour)
        .collect();

    // 登录频次分布：按每个用户在窗口内的登录次数分桶。
    let per_user_logins: Vec<serde_json::Value> = db
        .query_take0_vec(
            "audit_login_counts_per_user",
            // `user_id != NONE` 不能省：匿名活动（未知邮箱的登录失败、限流告警等）
            // 会聚成一个 `NONE` 分组，在"每用户登录次数"的直方图里凭空多出一个用户。
            "SELECT type::string(user_id) AS user_id, count() AS count FROM user_activity \
             WHERE action IN ['login_success', 'oauth_login'] AND timestamp >= $start_time \
             AND user_id != NONE GROUP BY user_id",
            json!({ "start_time": start_time.timestamp() }),
        )
        .await?;

    let mut buckets: [(&str, i64); 4] = [("1", 0), ("2-5", 0), ("6-20", 0), ("20+", 0)];
    for row in &per_user_logins {
        let count = row.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
        let idx = match count {
            c if c <= 1 => 0,
            c if c <= 5 => 1,
            c if c <= 20 => 2,
            _ => 3,
        };
        buckets[idx].1 += 1;
    }
    let counted_users: i64 = buckets.iter().map(|(_, n)| *n).sum();
    let login_frequency_distribution = buckets
        .iter()
        .map(|(range, user_count)| FrequencyMetric {
            frequency_range: (*range).to_string(),
            user_count: *user_count,
            percentage: if counted_users > 0 {
                (*user_count as f64 / counted_users as f64) * 100.0
            } else {
                0.0
            },
        })
        .collect();

    // 活跃率（不是留存率，口径见 RetentionMetrics 的说明）。
    let total_users = get_total_users(db).await?;
    let now = Utc::now();
    let user_retention_metrics = RetentionMetrics {
        daily_active_rate: active_user_rate(db, now - Duration::days(1), total_users).await?,
        weekly_active_rate: active_user_rate(db, now - Duration::days(7), total_users).await?,
        monthly_active_rate: active_user_rate(db, now - Duration::days(30), total_users).await?,
    };

    Ok(UserBehaviorAnalysis {
        login_frequency_distribution,
        peak_activity_hours,
        user_retention_metrics,
    })
}

/// 窗口内每种 action 的次数。
async fn count_actions_since(
    db: &Arc<Database>,
    from: DateTime<Utc>,
    until: Option<DateTime<Utc>>,
) -> ApiResult<HashMap<String, i64>> {
    let rows: Vec<serde_json::Value> = db
        .query_take0_vec(
            "audit_count_actions",
            "SELECT action, count() AS count FROM user_activity              WHERE timestamp >= $from AND timestamp < $until GROUP BY action",
            json!({
                "from": from.timestamp(),
                "until": until.unwrap_or_else(Utc::now).timestamp(),
            }),
        )
        .await?;

    Ok(rows_to_counts(rows, "action"))
}

/// 窗口内失败活动按 action 的分布。
async fn count_failed_actions_since(
    db: &Arc<Database>,
    from: DateTime<Utc>,
) -> ApiResult<HashMap<String, i64>> {
    let rows: Vec<serde_json::Value> = db
        .query_take0_vec(
            "audit_count_failed_actions",
            "SELECT action, count() AS count FROM user_activity              WHERE timestamp >= $from AND status = 'Failed' GROUP BY action",
            json!({ "from": from.timestamp() }),
        )
        .await?;

    Ok(rows_to_counts(rows, "action"))
}

fn rows_to_counts(rows: Vec<serde_json::Value>, key: &str) -> HashMap<String, i64> {
    rows.into_iter()
        .filter_map(|row| {
            let name = row.get(key)?.as_str()?.to_string();
            let count = row.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
            Some((name, count))
        })
        .collect()
}

fn trend_label(current: i64, previous: i64) -> String {
    // 上下浮动 10% 以内视为持平，避免噪声被读成趋势。
    let threshold = (previous as f64 * 0.1).max(1.0);
    let delta = current - previous;

    if (delta as f64).abs() <= threshold {
        "Stable".to_string()
    } else if delta > 0 {
        "Up".to_string()
    } else {
        "Down".to_string()
    }
}

/// 自 `since` 起有过活动的用户数占全部有效用户的比例。
async fn active_user_rate(
    db: &Arc<Database>,
    since: DateTime<Utc>,
    total_users: i64,
) -> ApiResult<f64> {
    if total_users <= 0 {
        return Ok(0.0);
    }

    let rows: Vec<serde_json::Value> = db
        .query_take0_vec(
            "audit_active_users",
            // 同上：不过滤的话 `NONE` 也算一个"活跃用户"，活跃率恒定虚高。
            // 匿名活动几乎总是存在，所以这个偏差是常态而非偶发。
            "SELECT type::string(user_id) AS user_id FROM user_activity \
             WHERE timestamp >= $since AND user_id != NONE GROUP BY user_id",
            json!({ "since": since.timestamp() }),
        )
        .await?;

    Ok((rows.len() as f64 / total_users as f64) * 100.0)
}

/// 审计完整性校验的结果。
#[derive(Serialize)]
pub struct AuditIntegrityReport {
    /// 链是否完整：既没有断链，也没有缺号，且至少有一个 checkpoint 验签通过。
    pub intact: bool,
    /// 本次检查覆盖的行数。
    pub checked: i64,
    /// 本次改动之前写入、没有链的行数。它们不算断链。
    pub unchained: i64,
    /// 覆盖的链条数。多副本部署每个副本一条链。
    pub chains: i64,
    /// 第一处对不上的位置：哪条链、哪个 `seq`。链完好时为 null。
    pub broken_chain: Option<String>,
    pub broken_at: Option<i64>,
    /// 断在哪一类上：`event_hash` / `previous_hash` / `missing_seq`。
    pub broken_reason: Option<String>,
    /// checkpoint 总数，以及其中签名与公钥都对得上的数量。
    pub checkpoints: i64,
    pub checkpoints_verified: i64,
}

/// 校验审计哈希链与 checkpoint 签名。
///
/// 两层缺一不可，所以两层都查：
///
/// * **链**：逐行重算 `event_hash`，并确认它的 `previous_hash` 等于前一行的
///   `event_hash`、`seq` 没有缺号。改一行、删一行、插一行都会在这里现形。
/// * **checkpoint**：验签名，**并且**比对公钥是不是本实例配置的那一把。
///   只验签名不够 —— 公钥是跟着记录存的，能改记录的人可以连公钥一起换成
///   自己的，那样一条伪造的 checkpoint 也能自洽。
async fn verify_integrity(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> ApiResult<Json<AuditIntegrityReport>> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, crate::models::permission::names::AUDIT_READ);

    // 时间列投影成字符串、record 列也投影成字符串：SDK 把 `Value::Datetime`
    // 与 record 转成 `serde_json::Value` 会失败，整个结果集一起解析不出来。
    // 按 (chain_id, seq) 排序：链是**按副本**分的，seq 只在一条链内单调。
    // 把所有行当成一条链，会在副本交界处误报断链。
    let sql = "SELECT chain_id, seq, previous_hash, event_hash, action, category, status, \
               type::string(user_id) AS user_id, ip_address, user_agent, details, timestamp \
               FROM user_activity WHERE seq != NONE ORDER BY chain_id ASC, seq ASC";
    let rows: Vec<serde_json::Value> = db
        .query_take0_vec_no_bind("audit_integrity_scan", sql)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    let total: Vec<serde_json::Value> = db
        .query_take0_vec_no_bind(
            "audit_integrity_total",
            "SELECT count() AS count FROM user_activity WHERE seq = NONE GROUP ALL",
        )
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    let unchained = total
        .first()
        .and_then(|r| r.get("count"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);

    let mut previous_hash = audit_integrity::GENESIS_HASH.to_string();
    let mut expected_seq = 1i64;
    let mut broken_at = None;
    let mut broken_chain = None;
    let mut broken_reason = None;
    let mut checked = 0i64;
    let mut current_chain = String::new();
    let mut chains = 0i64;

    for row in &rows {
        let str_of = |key: &str| {
            row.get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let chain_id = str_of("chain_id");
        let seq = row
            .get("seq")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        checked += 1;

        // 换链就从创世位置重新起算。
        if chain_id != current_chain {
            current_chain = chain_id.clone();
            previous_hash = audit_integrity::GENESIS_HASH.to_string();
            expected_seq = 1;
            chains += 1;
        }

        if seq != expected_seq {
            broken_chain = Some(chain_id);
            broken_at = Some(seq);
            broken_reason = Some("missing_seq".to_string());
            break;
        }
        if str_of("previous_hash") != previous_hash {
            broken_chain = Some(chain_id);
            broken_at = Some(seq);
            broken_reason = Some("previous_hash".to_string());
            break;
        }

        let details_json = row
            .get("details")
            .map(|d| serde_json::to_string(d).unwrap_or_default())
            .unwrap_or_else(|| "{}".to_string());
        let recomputed = audit_integrity::event_hash(&audit_integrity::DigestInput {
            chain_id: &chain_id,
            seq,
            previous_hash: &previous_hash,
            action: &str_of("action"),
            category: &str_of("category"),
            status: &str_of("status"),
            user_id: &str_of("user_id"),
            ip_address: &str_of("ip_address"),
            user_agent: &str_of("user_agent"),
            details_json: &details_json,
            timestamp: row
                .get("timestamp")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
        });
        let stored = str_of("event_hash");
        if recomputed != stored {
            broken_chain = Some(chain_id);
            broken_at = Some(seq);
            broken_reason = Some("event_hash".to_string());
            break;
        }

        previous_hash = stored;
        expected_seq = seq + 1;
    }

    // checkpoint 那一层。
    let cps: Vec<serde_json::Value> = db
        .query_take0_vec_no_bind(
            "audit_integrity_checkpoints",
            "SELECT chain_id, seq_to, head_hash, created_at, public_key, signature \
             FROM audit_checkpoint ORDER BY chain_id ASC, seq_to ASC",
        )
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    // 本实例配置的公钥。checkpoint 里存的公钥必须与它一致，否则那条 checkpoint
    // 是别人签的，验得过也不算数。
    let own_public_key = config
        .audit_integrity_key
        .as_deref()
        .and_then(|seed| audit_integrity::CheckpointSigner::from_seed_b64(seed).ok())
        .map(|signer| signer.public_key_b64());

    let mut verified = 0i64;
    for cp in &cps {
        let str_of = |key: &str| {
            cp.get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let public_key = str_of("public_key");
        if own_public_key.as_deref() != Some(public_key.as_str()) {
            continue;
        }
        let seq_to = cp
            .get("seq_to")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        let created_at = cp
            .get("created_at")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        if audit_integrity::verify_checkpoint(
            &public_key,
            &str_of("signature"),
            &str_of("chain_id"),
            seq_to,
            &str_of("head_hash"),
            created_at,
        ) {
            verified += 1;
        }
    }

    // 「完好」的判据要两层都满足。只有链而没有一个可验的 checkpoint 时，
    // 一个拥有全库写权限的人可以把整条链重算，因此不能报 intact。
    // 链上一条记录都没有时（全新实例）也不报 intact，那时无从证明什么。
    let chain_ok = broken_at.is_none() && checked > 0;
    Ok(Json(AuditIntegrityReport {
        intact: chain_ok && verified > 0,
        checked,
        unchained,
        chains,
        broken_chain,
        broken_at,
        broken_reason,
        checkpoints: cps.len() as i64,
        checkpoints_verified: verified,
    }))
}
