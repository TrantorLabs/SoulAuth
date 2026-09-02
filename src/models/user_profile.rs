use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

/// 注意：持久化字段的时间一律用 Unix 秒（i64），与 `schema.sql` 里的
/// `TYPE number` 对齐。以前这里用 `DateTime<Utc>`，写进 SCHEMAFULL 的
/// number 列会被数据库拒绝。对外的 Response 结构仍然返回 RFC3339 时间。
#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct UserProfile {
    pub id: Option<Thing>,
    pub user_id: Thing,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub phone: Option<String>,
    pub date_of_birth: Option<DateTime<Utc>>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserProfileRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub date_of_birth: Option<DateTime<Utc>>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserProfileRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub date_of_birth: Option<DateTime<Utc>>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfileResponse {
    pub id: String,
    pub user_id: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub phone: Option<String>,
    pub date_of_birth: Option<DateTime<Utc>>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<UserProfile> for UserProfileResponse {
    fn from(profile: UserProfile) -> Self {
        Self {
            id: profile
                .id
                .map(|id| crate::utils::record_id::record_id_key_to_string(&id))
                .unwrap_or_default(),
            user_id: crate::utils::record_id::record_id_key_to_string(&profile.user_id),
            first_name: profile.first_name,
            last_name: profile.last_name,
            display_name: profile.display_name,
            avatar_url: profile.avatar_url,
            phone: profile.phone,
            date_of_birth: profile.date_of_birth,
            timezone: profile.timezone,
            locale: profile.locale,
            bio: profile.bio,
            website: profile.website,
            location: profile.location,
            created_at: chrono::DateTime::<Utc>::from_timestamp(profile.created_at, 0)
                .unwrap_or_else(Utc::now),
            updated_at: chrono::DateTime::<Utc>::from_timestamp(profile.updated_at, 0)
                .unwrap_or_else(Utc::now),
        }
    }
}
