use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
#[serde(rename_all = "snake_case")]
pub struct IdentityProvider {
    pub id: Thing,
    pub provider: String,
    pub provider_user_id: String,
    #[serde(rename = "user_id")]
    pub user_id: Thing,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub provider: String,
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
}
