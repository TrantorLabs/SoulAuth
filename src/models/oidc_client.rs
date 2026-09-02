use serde::{Deserialize, Serialize};
use surrealdb::types::SurrealValue;
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct OidcClient {
    pub id: Option<String>,
    pub client_id: String,
    pub client_secret_hash: String,
    pub client_name: String,
    pub client_type: ClientType,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_grant_types: Vec<GrantType>,
    pub allowed_response_types: Vec<ResponseType>,
    pub require_pkce: bool,
    pub access_token_lifetime: i64,
    pub refresh_token_lifetime: i64,
    pub id_token_lifetime: i64,
    pub is_active: bool,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    Public,
    Confidential,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
    ClientCredentials,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue, PartialEq)]
pub enum ResponseType {
    #[serde(rename = "code")]
    Code,
    #[serde(rename = "id_token")]
    IdToken,
    #[serde(rename = "code id_token")]
    CodeIdToken,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct CreateOidcClientRequest {
    #[validate(length(min = 1, max = 100))]
    pub client_name: String,
    pub client_type: ClientType,
    #[validate(length(min = 1))]
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub allowed_scopes: Option<Vec<String>>,
    pub allowed_grant_types: Option<Vec<GrantType>>,
    pub allowed_response_types: Option<Vec<ResponseType>>,
    pub require_pkce: Option<bool>,
    pub access_token_lifetime: Option<i64>,
    pub refresh_token_lifetime: Option<i64>,
    pub id_token_lifetime: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcClientResponse {
    pub client_id: String,
    pub client_secret: String, // 只在创建时返回
    pub client_name: String,
    pub client_type: ClientType,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_grant_types: Vec<GrantType>,
    pub allowed_response_types: Vec<ResponseType>,
    pub require_pkce: bool,
    pub access_token_lifetime: i64,
    pub refresh_token_lifetime: i64,
    pub id_token_lifetime: i64,
    pub is_active: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Default for CreateOidcClientRequest {
    fn default() -> Self {
        Self {
            client_name: String::new(),
            client_type: ClientType::Confidential,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Some(Vec::new()),
            allowed_scopes: Some(vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ]),
            allowed_grant_types: Some(vec![GrantType::AuthorizationCode, GrantType::RefreshToken]),
            allowed_response_types: Some(vec![ResponseType::Code]),
            require_pkce: Some(true),
            access_token_lifetime: Some(3600),
            refresh_token_lifetime: Some(86400),
            // 上限见 services::oidc_client_management::MAX_ID_TOKEN_LIFETIME_SECS。
            id_token_lifetime: Some(300),
        }
    }
}
