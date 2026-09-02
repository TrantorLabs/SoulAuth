use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    error::AuthError,
    models::{
        user::{
            AccountStatusResponse, UpdateAccountStatusRequest, UpdateMembershipRequest, User,
            UserListRequest, UserListResponse, UserResponse,
        },
        user_activity::{
            ActivityCategory, ActivityLogRequest, ActivityLogResponse, ActivityStatus,
            UserActivityResponse, UserActivityRow,
        },
        user_preferences::{
            CreateUserPreferencesRequest, UpdateUserPreferencesRequest, UserPreferences,
            UserPreferencesResponse,
        },
        user_profile::{
            CreateUserProfileRequest, UpdateUserProfileRequest, UserProfile, UserProfileResponse,
        },
    },
    services::{
        audit_logger::{AuditEvent, AuditLogger},
        auth::RequestContext,
        database::Database,
        rbac::RBACService,
    },
};

pub struct UserManagementService {
    db: Arc<Database>,
}

impl UserManagementService {
    fn normalize_membership_level(level: &str) -> Result<String, AuthError> {
        match level.trim().to_ascii_uppercase().as_str() {
            "FREE" | "PRO" | "PREMIUM" | "ULTIMATE" | "TEAM" => {
                Ok(level.trim().to_ascii_uppercase())
            }
            _ => Err(AuthError::ValidationError(
                "Invalid membership level".to_string(),
            )),
        }
    }

    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    // 用户档案管理
    pub async fn create_user_profile(
        &self,
        user_id: &str,
        request: CreateUserProfileRequest,
        ctx: &RequestContext,
    ) -> Result<UserProfileResponse, AuthError> {
        // profile / preferences 挂在**身份根**上（Stage 3 起外键指 actor_identity）。
        let user_thing = self.db.actor_ref_of_user(user_id).await?;

        // 检查用户是否存在
        let mut response = self
            .db
            .client
            // `user_thing` 自 Stage 3 起是**身份根**引用，不能拿它去 user 表查 ——
            // 那必然查不到，于是建资料返回 404。存在性判定改查 actor_identity。
            // `SELECT VALUE id` 而不是 `SELECT *`：整行里有 record 类型字段，
            // 用 serde_json::Value 接会报「Expected any, got record」。
            // 这里只需要判断有没有这一行，取 id 就够。
            .query("SELECT VALUE id FROM actor_identity WHERE id = $user_id LIMIT 1")
            .bind(("user_id", user_thing.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to check user existence: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        // 只判存在。取 RecordId 而不是整行：actor_identity 既没有 User 的
        // email / password 字段，整行里的 record 类型也接不进 serde_json::Value。
        let actors: Vec<surrealdb::types::RecordId> = response.take(0).map_err(|e| {
            error!("Failed to parse actor identity: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if actors.is_empty() {
            return Err(AuthError::NotFound("User not found".to_string()));
        }

        // 检查档案是否已存在
        let existing_profile = self.get_user_profile(user_id).await;
        if existing_profile.is_ok() {
            return Err(AuthError::ValidationError(
                "User profile already exists".to_string(),
            ));
        }

        let now = Utc::now().timestamp();
        let profile = UserProfile {
            id: None,
            user_id: user_thing,
            first_name: request.first_name,
            last_name: request.last_name,
            display_name: request.display_name,
            avatar_url: None,
            phone: request.phone,
            date_of_birth: request.date_of_birth,
            timezone: request.timezone,
            locale: request.locale,
            bio: request.bio,
            website: request.website,
            location: request.location,
            created_at: now,
            updated_at: now,
        };

        let query = "CREATE user_profile CONTENT $profile";
        let mut response = self
            .db
            .client
            .query(query)
            .bind(("profile", profile.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to create user profile: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created_profile: Vec<UserProfile> = response.take(0).map_err(|e| {
            error!("Failed to parse created profile: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created_profile.is_empty() {
            return Err(AuthError::DatabaseError(
                "Failed to create user profile".to_string(),
            ));
        }

        // 记录活动
        self.log_user_activity(
            user_id,
            "profile_created",
            ActivityCategory::Profile,
            ActivityStatus::Success,
            &ctx.ip_address,
            &ctx.user_agent,
            serde_json::json!({"action": "profile_created"}),
        )
        .await?;

        info!("User profile created for user '{}'", user_id);
        Ok(created_profile[0].clone().into())
    }

    pub async fn get_user_profile(&self, user_id: &str) -> Result<UserProfileResponse, AuthError> {
        // profile / preferences 挂在**身份根**上（Stage 3 起外键指 actor_identity）。
        let user_thing = self.db.actor_ref_of_user(user_id).await?;

        let query = "SELECT * FROM user_profile WHERE user_id = $user_id";
        let mut response = self
            .db
            .client
            .query(query)
            .bind(("user_id", user_thing.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get user profile: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let profiles: Vec<UserProfile> = response.take(0).map_err(|e| {
            error!("Failed to parse profile: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        profiles
            .into_iter()
            .next()
            .map(|profile| profile.into())
            .ok_or_else(|| AuthError::NotFound("User profile not found".to_string()))
    }

    pub async fn update_user_profile(
        &self,
        user_id: &str,
        request: UpdateUserProfileRequest,
        ctx: &RequestContext,
    ) -> Result<UserProfileResponse, AuthError> {
        // 档案不存在时先报 404，而不是让 UPDATE 静默命中 0 行。
        self.get_user_profile(user_id).await?;

        // 全部走绑定参数。以前这里把 bio / website / display_name 等用户可控字段
        // 直接内插进 SurrealQL，一个单引号就能改写整条语句。
        // `$x ?? field` 表示"传了就更新，没传就保持原值"。
        let query = r#"
            UPDATE user_profile SET
                first_name = $first_name ?? first_name,
                last_name = $last_name ?? last_name,
                display_name = $display_name ?? display_name,
                phone = $phone ?? phone,
                -- `date_of_birth` 是 datetime 列，不能用上面那种 `$x ?? field`：
                -- JSON 绑定给过来的是 RFC3339 字符串，直接赋值会因类型不符被拒。
                -- 这个字段以前**根本没写进 UPDATE**：请求结构体里有、响应里也返回，
                -- 客户端原样回传能拿到 200，值却从来不变——静默丢数据。
                date_of_birth = IF $date_of_birth = NONE OR $date_of_birth = NULL {
                    date_of_birth
                } ELSE {
                    type::datetime($date_of_birth)
                },
                timezone = $timezone ?? timezone,
                locale = $locale ?? locale,
                bio = $bio ?? bio,
                website = $website ?? website,
                location = $location ?? location,
                updated_at = $updated_at
            WHERE user_id = (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]
        "#;

        let bindings = serde_json::json!({
            "user_key": crate::utils::record_id::normalize_user_id(user_id),
            "first_name": request.first_name,
            "last_name": request.last_name,
            "display_name": request.display_name,
            "phone": request.phone,
            "date_of_birth": request.date_of_birth,
            "timezone": request.timezone,
            "locale": request.locale,
            "bio": request.bio,
            "website": request.website,
            "location": request.location,
            "updated_at": Utc::now().timestamp(),
        });

        let mut response = self
            .db
            .raw_query("update_user_profile", query, bindings)
            .await
            .map_err(|e| {
                error!("Failed to update user profile: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let updated_profile: Vec<UserProfile> = response.take(0).map_err(|e| {
            error!("Failed to parse updated profile: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if updated_profile.is_empty() {
            return Err(AuthError::DatabaseError(
                "Failed to update user profile".to_string(),
            ));
        }

        // 记录活动
        self.log_user_activity(
            user_id,
            "profile_updated",
            ActivityCategory::Profile,
            ActivityStatus::Success,
            &ctx.ip_address,
            &ctx.user_agent,
            serde_json::json!({"action": "profile_updated"}),
        )
        .await?;

        info!("User profile updated for user '{}'", user_id);
        Ok(updated_profile[0].clone().into())
    }

    // 用户偏好管理
    pub async fn create_user_preferences(
        &self,
        user_id: &str,
        request: CreateUserPreferencesRequest,
        ctx: &RequestContext,
    ) -> Result<UserPreferencesResponse, AuthError> {
        // profile / preferences 挂在**身份根**上（Stage 3 起外键指 actor_identity）。
        let user_thing = self.db.actor_ref_of_user(user_id).await?;

        // 检查偏好是否已存在
        let existing_prefs = self.get_user_preferences(user_id).await;
        if existing_prefs.is_ok() {
            return Err(AuthError::ValidationError(
                "User preferences already exist".to_string(),
            ));
        }

        let mut preferences = UserPreferences {
            user_id: user_thing,
            ..Default::default()
        };

        if let Some(theme) = request.theme {
            preferences.theme = theme;
        }
        if let Some(language) = request.language {
            preferences.language = language;
        }
        if let Some(email_notifications) = request.email_notifications {
            preferences.email_notifications = email_notifications;
        }
        if let Some(sms_notifications) = request.sms_notifications {
            preferences.sms_notifications = sms_notifications;
        }
        if let Some(marketing_emails) = request.marketing_emails {
            preferences.marketing_emails = marketing_emails;
        }
        if let Some(security_emails) = request.security_emails {
            preferences.security_emails = security_emails;
        }
        if let Some(newsletter) = request.newsletter {
            preferences.newsletter = newsletter;
        }
        if let Some(timezone) = request.timezone {
            preferences.timezone = timezone;
        }
        if let Some(date_format) = request.date_format {
            preferences.date_format = date_format;
        }
        if let Some(time_format) = request.time_format {
            preferences.time_format = time_format;
        }

        let query = "CREATE user_preferences CONTENT $preferences";
        let mut response = self
            .db
            .client
            .query(query)
            .bind(("preferences", preferences.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to create user preferences: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created_preferences: Vec<UserPreferences> = response.take(0).map_err(|e| {
            error!("Failed to parse created preferences: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created_preferences.is_empty() {
            return Err(AuthError::DatabaseError(
                "Failed to create user preferences".to_string(),
            ));
        }

        // 记录活动
        self.log_user_activity(
            user_id,
            "preferences_created",
            ActivityCategory::Profile,
            ActivityStatus::Success,
            &ctx.ip_address,
            &ctx.user_agent,
            serde_json::json!({"action": "preferences_created"}),
        )
        .await?;

        info!("User preferences created for user '{}'", user_id);
        Ok(created_preferences[0].clone().into())
    }

    pub async fn get_user_preferences(
        &self,
        user_id: &str,
    ) -> Result<UserPreferencesResponse, AuthError> {
        // profile / preferences 挂在**身份根**上（Stage 3 起外键指 actor_identity）。
        let user_thing = self.db.actor_ref_of_user(user_id).await?;

        let query = "SELECT * FROM user_preferences WHERE user_id = $user_id";
        let mut response = self
            .db
            .client
            .query(query)
            .bind(("user_id", user_thing.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get user preferences: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let preferences: Vec<UserPreferences> = response.take(0).map_err(|e| {
            error!("Failed to parse preferences: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        preferences
            .into_iter()
            .next()
            .map(|prefs| prefs.into())
            .ok_or_else(|| AuthError::NotFound("User preferences not found".to_string()))
    }

    pub async fn update_user_preferences(
        &self,
        user_id: &str,
        request: UpdateUserPreferencesRequest,
        ctx: &RequestContext,
    ) -> Result<UserPreferencesResponse, AuthError> {
        // 偏好不存在时先报 404。
        self.get_user_preferences(user_id).await?;

        // 同上：改为全绑定参数。
        let query = r#"
            UPDATE user_preferences SET
                theme = $theme ?? theme,
                language = $language ?? language,
                email_notifications = $email_notifications ?? email_notifications,
                sms_notifications = $sms_notifications ?? sms_notifications,
                marketing_emails = $marketing_emails ?? marketing_emails,
                security_emails = $security_emails ?? security_emails,
                newsletter = $newsletter ?? newsletter,
                timezone = $timezone ?? timezone,
                date_format = $date_format ?? date_format,
                time_format = $time_format ?? time_format,
                updated_at = $updated_at
            WHERE user_id = (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]
        "#;

        let bindings = serde_json::json!({
            "user_key": crate::utils::record_id::normalize_user_id(user_id),
            "theme": request.theme,
            "language": request.language,
            "email_notifications": request.email_notifications,
            "sms_notifications": request.sms_notifications,
            "marketing_emails": request.marketing_emails,
            "security_emails": request.security_emails,
            "newsletter": request.newsletter,
            "timezone": request.timezone,
            "date_format": request.date_format,
            "time_format": request.time_format,
            "updated_at": Utc::now().timestamp(),
        });

        let mut response = self
            .db
            .raw_query("update_user_preferences", query, bindings)
            .await
            .map_err(|e| {
                error!("Failed to update user preferences: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let updated_preferences: Vec<UserPreferences> = response.take(0).map_err(|e| {
            error!("Failed to parse updated preferences: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if updated_preferences.is_empty() {
            return Err(AuthError::DatabaseError(
                "Failed to update user preferences".to_string(),
            ));
        }

        // 记录活动
        self.log_user_activity(
            user_id,
            "preferences_updated",
            ActivityCategory::Profile,
            ActivityStatus::Success,
            &ctx.ip_address,
            &ctx.user_agent,
            serde_json::json!({"action": "preferences_updated"}),
        )
        .await?;

        info!("User preferences updated for user '{}'", user_id);
        Ok(updated_preferences[0].clone().into())
    }

    // 账户状态管理
    pub async fn update_account_status(
        &self,
        user_id: &str,
        request: UpdateAccountStatusRequest,
        updated_by: &User,
        ctx: &RequestContext,
    ) -> Result<AccountStatusResponse, AuthError> {
        let user_thing = crate::utils::record_id::user_record_id(user_id)?;

        // 检查用户是否存在
        let mut response = self
            .db
            .client
            .query("SELECT * FROM user WHERE id = $user_id LIMIT 1")
            .bind(("user_id", user_thing.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to check user existence: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let users: Vec<User> = response.take(0).map_err(|e| {
            error!("Failed to parse user: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if users.is_empty() {
            return Err(AuthError::NotFound("User not found".to_string()));
        }

        let now = Utc::now();

        self.db.client
            .query("UPDATE user SET account_status = $status, updated_at = $updated_at WHERE id = $user_id")
            .bind(("status", request.status.to_string()))
            .bind(("updated_at", now.timestamp()))
            .bind(("user_id", user_thing.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to update account status: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        // 同步到身份根。
        //
        // Stage 2 是过渡期，账号状态存在两处：V1 的 `user.account_status`
        // 与新身份根的 `actor_identity.status`。只改一处的话，停用会在另一条
        // 通路上完全不生效 —— 而这正是我们早先修过的那类缺陷（状态改了，
        // 但 refresh token 还在无限换新）。
        //
        // 映射：Active → active，其余一律 suspended。V1 的 Inactive / Deleted
        // 与身份根的 Retired 语义不同（Retired 还带「subject 不得复用」这条
        // 约束），过渡期不做这个等价，宁可保守。
        if let Some(actor_id) = users[0].subject_id.clone() {
            use crate::models::actor_identity::{ActorIdentity, ActorStatus};
            let actor_address = format!(
                "actor_identity:{}",
                crate::utils::record_id::record_id_key_to_string(&actor_id)
            );
            match self
                .db
                .find_record_by_field::<ActorIdentity>("actor_identity", "id", &actor_address)
                .await
            {
                Ok(Some(actor)) => {
                    let target = if request.status == crate::models::user::AccountStatus::Active {
                        ActorStatus::Active
                    } else {
                        ActorStatus::Suspended
                    };
                    let identity = crate::services::identity::IdentityService::new(self.db.clone());
                    if let Err(e) = identity.set_status(&actor, target).await {
                        // 这里不能只记日志就放过：V1 那侧已经写成新状态，
                        // 身份根还停在旧状态，两处不一致比两处都是旧的更危险。
                        error!("Failed to sync actor_identity status: {e:?}");
                        return Err(e);
                    }
                }
                // subject_id 指向 V1 的 subject 表，或身份根已被删除 ——
                // 都留给 Stage 3 的迁移处理。
                Ok(None) => {}
                Err(e) => error!("Failed to load actor for status sync: {e:?}"),
            }
        }

        // 记录活动
        self.log_user_activity(
            user_id,
            "account_status_changed",
            ActivityCategory::Security,
            ActivityStatus::Success,
            &ctx.ip_address,
            &ctx.user_agent,
            serde_json::json!({
                "action": "account_status_changed",
                "old_status": users[0].account_status,
                "new_status": request.status,
                "reason": request.reason
            }),
        )
        .await?;

        info!(
            "Account status updated for user '{}' to {:?} by '{}'",
            user_id, request.status, updated_by.email
        );

        Ok(AccountStatusResponse {
            user_id: user_id.to_string(),
            status: request.status,
            updated_at: now,
            updated_by: updated_by.email.clone(),
            reason: request.reason,
        })
    }

    // 用户活动日志
    /// 记录一条用户活动。
    ///
    /// 直接复用 `AuditLogger` 的写入路径，**不再自己拼一套**。以前这里用
    /// `.bind(("activity", ...))` 走 SurrealValue 编码，而 `audit_logger`
    /// 走 serde（枚举存成纯字符串），同一张 `user_activity` 表上出现了两种
    /// 互不兼容的编码：读取端只认其中一种，另一种写进去的行读不出来
    /// —— 而且 SurrealValue 编码的枚举很可能根本过不了 `TYPE string` 的校验。
    ///
    /// 写入是 fire-and-forget，失败只记日志：不能因为写不进审计日志
    /// 就让改档案 / 改状态这类业务操作整体失败。
    pub async fn log_user_activity(
        &self,
        user_id: &str,
        action: &'static str,
        category: ActivityCategory,
        status: ActivityStatus,
        ip_address: &str,
        user_agent: &str,
        details: serde_json::Value,
    ) -> Result<(), AuthError> {
        // 用进程内那个唯一的 logger，不要现造：`AuditLogger::start` 会 spawn
        // 一个写入任务并维护链头，每条事件造一个等于每条事件一条链。
        let Some(audit) = AuditLogger::global() else {
            return Ok(());
        };
        audit.record(
            AuditEvent::new(action, category, status, ip_address, user_agent)
                .with_user(user_id)
                .with_details(details),
        );

        Ok(())
    }

    /// 查询某用户的活动日志。
    ///
    /// 读取走 serde（与 `AuditLogger` 的写入编码一致）。以前这里用
    /// `take::<Vec<UserActivity>>` 走 SurrealValue 解码，而写入端存的是
    /// 纯字符串枚举，两边对不上会直接解码失败。
    ///
    /// 过滤条件全部走绑定参数：`category` / `status` 虽然是枚举（不可注入），
    /// 但没有理由再留一处字符串拼接。
    pub async fn get_user_activity_log(
        &self,
        user_id: &str,
        request: ActivityLogRequest,
    ) -> Result<ActivityLogResponse, AuthError> {
        let page = request.page.unwrap_or(1).max(1);
        let limit = request.limit.unwrap_or(50).clamp(1, 200);
        let offset = (page - 1).saturating_mul(limit);

        let mut where_clauses = vec![
            "user_id = (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]"
                .to_string(),
        ];
        if request.category.is_some() {
            where_clauses.push("category = $category".to_string());
        }
        if request.status.is_some() {
            where_clauses.push("status = $status".to_string());
        }
        if request.start_date.is_some() {
            where_clauses.push("timestamp >= $start_ts".to_string());
        }
        if request.end_date.is_some() {
            where_clauses.push("timestamp <= $end_ts".to_string());
        }
        let where_clause = where_clauses.join(" AND ");

        let bindings = json!({
            "user_key": crate::utils::record_id::normalize_user_id(user_id),
            "category": request.category.as_ref().map(|c| format!("{c:?}")),
            "status": request.status.as_ref().map(|s| format!("{s:?}")),
            "start_ts": request.start_date.map(|d| d.timestamp()),
            "end_ts": request.end_date.map(|d| d.timestamp()),
            "limit": limit,
            "offset": offset,
        });

        // id / user_id 是 record 链接，投影成字符串才能走 serde。
        let query = format!(
            "SELECT type::string(id) AS id, \
                    IF user_id = NONE {{ NONE }} ELSE {{ type::string(user_id) }} AS user_id, \
                    action, category, ip_address, user_agent, details, status, timestamp \
             FROM user_activity WHERE {where_clause} \
             ORDER BY timestamp DESC LIMIT $limit START $offset"
        );

        let rows: Vec<serde_json::Value> = self
            .db
            .query_take0_vec("user_activity_log", &query, bindings.clone())
            .await
            .map_err(|e| {
                error!("Failed to get user activity log: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let activities = rows
            .into_iter()
            .map(serde_json::from_value::<UserActivityRow>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                error!("Failed to parse activities: {}", e);
                AuthError::DatabaseError(format!("Failed to parse activities: {e}"))
            })?
            .into_iter()
            .map(UserActivityResponse::from)
            .collect::<Vec<_>>();

        let count_query =
            format!("SELECT count() AS total FROM user_activity WHERE {where_clause} GROUP ALL");
        let count_rows: Vec<serde_json::Value> = self
            .db
            .query_take0_vec("user_activity_log_count", &count_query, bindings)
            .await
            .map_err(|e| {
                error!("Failed to count activities: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let total = count_rows
            .first()
            .and_then(|c| c.get("total"))
            .and_then(|t| t.as_u64())
            .unwrap_or(0);

        Ok(ActivityLogResponse {
            activities,
            total,
            page,
            limit,
            total_pages: (total as f64 / limit as f64).ceil() as u32,
        })
    }

    // 用户列表管理
    pub async fn get_user_by_id(&self, user_id: &str) -> Result<UserResponse, AuthError> {
        // 这里走 `query_take0_vec`，绑定值是 JSON。RecordId 经 serde_json 会退化成
        // 字符串，`id = "user:xxx"` 永远匹配不到记录 ID，必须在 SQL 里用
        // type::record() 重新构造。
        let user_key = crate::utils::record_id::normalize_user_id(user_id);

        let users: Vec<User> = self
            .db
            .query_take0_vec(
                "user_management_get_user_by_id",
                "SELECT * FROM user WHERE id = type::record('user', $user_key) LIMIT 1",
                json!({ "user_key": user_key }),
            )
            .await
            .map_err(|e| {
                error!("Failed to get user by id: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let user = users
            .into_iter()
            .next()
            .ok_or_else(|| AuthError::NotFound("User not found".to_string()))?;

        let mut response: UserResponse = user.into();
        response.is_admin = self.user_has_admin_role(user_id).await?;
        Ok(response)
    }

    async fn user_has_admin_role(&self, user_id: &str) -> Result<bool, AuthError> {
        let rbac = RBACService::new(self.db.clone());
        rbac.check_user_role(user_id, "admin").await
    }

    pub async fn list_users(
        &self,
        request: UserListRequest,
    ) -> Result<UserListResponse, AuthError> {
        // `page` / `limit` 是 u32 且直接来自查询串：`page=0` 会让 `page - 1` 下溢
        // （debug 直接 panic，release 绕回 u32::MAX），`limit` 不设上限则
        // `?limit=4294967295` 等于一次性把整张 user 表拉进内存。
        let page = request.page.unwrap_or(1).max(1);
        let limit = request.limit.unwrap_or(50).clamp(1, 200);
        let offset = (page - 1).saturating_mul(limit);

        // 过滤条件全部走绑定参数：`search` 是用户可控的自由文本，以前直接拼进
        // `email CONTAINS '...'`，单引号即可改写语句。
        let mut where_clauses = Vec::new();
        if request.status.is_some() {
            where_clauses.push("account_status = $status");
        }
        if request.search.is_some() {
            where_clauses.push("string::contains(email, $search)");
        }

        let where_clause = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        // 排序字段无法参数化，因此只接受白名单内的取值。
        let sort_by = match request.sort_by.as_deref() {
            Some("email") => "email",
            Some("username") => "username",
            Some("updated_at") => "updated_at",
            Some("last_login_at") => "last_login_at",
            _ => "created_at",
        };
        let sort_order = match request.sort_order.as_deref() {
            Some(order) if order.eq_ignore_ascii_case("asc") => "ASC",
            _ => "DESC",
        };

        let bindings = json!({
            "status": request.status.as_ref().map(|status| format!("{status:?}")),
            "search": request.search,
            "limit": limit,
            "offset": offset,
        });

        let query = format!(
            "SELECT * FROM user {where_clause} ORDER BY {sort_by} {sort_order} LIMIT $limit START $offset"
        );

        let users: Vec<User> = self
            .db
            .query_take0_vec("user_management_list_users", &query, bindings.clone())
            .await
            .map_err(|e| {
                error!("Failed to list users: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        // 获取总数
        let count_query = format!("SELECT count() as total FROM user {where_clause} GROUP ALL");

        let count_result: Vec<serde_json::Value> = self
            .db
            .query_take0_vec("user_management_count_users", &count_query, bindings)
            .await
            .map_err(|e| {
                error!("Failed to count users: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let total = count_result
            .first()
            .and_then(|c| c.get("total"))
            .and_then(|t| t.as_u64())
            .unwrap_or(0);

        let total_pages = (total as f64 / limit as f64).ceil() as u32;

        let mut user_responses = Vec::with_capacity(users.len());
        for user in users {
            let user_id = crate::utils::record_id::record_id_key_to_string(
                user.id
                    .as_ref()
                    .ok_or_else(|| AuthError::DatabaseError("User missing id".to_string()))?,
            );
            let mut response: UserResponse = user.into();
            response.is_admin = self.user_has_admin_role(&user_id).await?;
            user_responses.push(response);
        }

        Ok(UserListResponse {
            users: user_responses,
            total,
            page,
            limit,
            total_pages,
        })
    }

    pub async fn update_membership(
        &self,
        user_id: &str,
        request: UpdateMembershipRequest,
    ) -> Result<UserResponse, AuthError> {
        let mut user = self
            .db
            .find_record_by_field::<User>("user", "id", user_id)
            .await?
            .ok_or_else(|| AuthError::NotFound("User not found".to_string()))?;

        user.membership_level = Self::normalize_membership_level(&request.membership_level)?;
        // 格式校验已经由 `Option<DateTime<Utc>>` 的反序列化完成：非法输入根本
        // 到不了这里。以前这里只做 trim + 空串过滤，任意字符串都能落库。
        user.membership_expiry = request.membership_expiry;
        user.updated_at = chrono::Utc::now().timestamp();

        let user_thing = user
            .id
            .as_ref()
            .ok_or_else(|| AuthError::DatabaseError("User missing id".to_string()))?;
        let updated = self
            .db
            .update_record(
                "user",
                &format!(
                    "{}:{}",
                    user_thing.table,
                    crate::utils::record_id::record_id_key_to_string(user_thing)
                ),
                &user,
            )
            .await?;

        let updated_id = crate::utils::record_id::record_id_key_to_string(
            updated
                .id
                .as_ref()
                .ok_or_else(|| AuthError::DatabaseError("Updated user missing id".to_string()))?,
        );
        let mut response: UserResponse = updated.into();
        response.is_admin = self.user_has_admin_role(&updated_id).await?;
        Ok(response)
    }
}
