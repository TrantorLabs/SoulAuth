use anyhow::{anyhow, Result};
use chrono::Utc;
use rand::{distributions::Alphanumeric, Rng};
use std::sync::Arc;

use crate::{
    models::oidc_client::{
        ClientType, CreateOidcClientRequest, GrantType, OidcClient, OidcClientResponse,
        ResponseType,
    },
    services::{database::Database, oidc::hash_client_secret},
};

/// ID Token 的生命周期上限（秒）。
///
/// P0-DECISION-10 DEC-10-01：Phase 0 用 RS256 ID Token 本地验签，
/// OS 不回调 SoulAuth。代价是**令牌在有效期内无法吊销** ——
/// 用户登出、账号停用都要等它自然过期。所以寿命就是可接受的吊销延迟，
/// 裁定上限 300 秒（高安全部署建议 120）。
///
/// 这里是**硬上限**不是默认值：只改默认值挡不住管理员显式传一个 3600。
pub const MAX_ID_TOKEN_LIFETIME_SECS: i64 = 300;

/// 把 ID Token 寿命夹到上限内。非正数一律回落到上限。
fn clamp_id_token_lifetime(requested: i64) -> i64 {
    if requested <= 0 {
        return MAX_ID_TOKEN_LIFETIME_SECS;
    }
    requested.min(MAX_ID_TOKEN_LIFETIME_SECS)
}

/// public 客户端一律要求 PKCE，管理员传什么都不作数。
///
/// public 客户端按定义没有 client_secret，PKCE 是它**唯一**的绑定手段。
/// 两个都没有，就意味着谁拿到那串授权码谁就能换到令牌 —— 而授权码走在 URL 里，
/// 会落进 Referer、浏览器历史、反向代理日志，以及移动端上任何抢注了同一
/// custom scheme 的 App。OAuth 2.1 / RFC 9700 把「public 客户端必须用 PKCE」
/// 列为强制正是为此。
///
/// 这里和 `clamp_id_token_lifetime` 是同一种写法：**不接受管理员配歪**。
/// 只改默认值挡不住显式传 `false`，所以判据放在服务端而不是文档里。
/// confidential 客户端仍可自行决定（它有 secret 兜底），默认开。
fn resolve_require_pkce(client_type: &ClientType, requested: Option<bool>) -> bool {
    match client_type {
        ClientType::Public => true,
        ClientType::Confidential => requested.unwrap_or(true),
    }
}

#[derive(Clone)]
pub struct OidcClientService {
    db: Arc<Database>,
}

impl OidcClientService {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    // 创建新的 OIDC 客户端
    pub async fn create_client(
        &self,
        request: CreateOidcClientRequest,
        created_by: &str,
    ) -> Result<OidcClientResponse> {
        // 生成客户端ID和密钥
        let client_id = generate_client_id();
        let client_secret = generate_client_secret();
        let client_secret_hash = hash_client_secret(&client_secret)?;

        let now = Utc::now().timestamp();

        let client = OidcClient {
            id: None,
            client_id: client_id.clone(),
            client_secret_hash,
            client_name: request.client_name.clone(),
            client_type: request.client_type.clone(),
            redirect_uris: request.redirect_uris.clone(),
            post_logout_redirect_uris: request.post_logout_redirect_uris.unwrap_or_default(),
            allowed_scopes: request.allowed_scopes.unwrap_or_else(|| {
                vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ]
            }),
            allowed_grant_types: request
                .allowed_grant_types
                .unwrap_or_else(|| vec![GrantType::AuthorizationCode, GrantType::RefreshToken]),
            allowed_response_types: request
                .allowed_response_types
                .unwrap_or_else(|| vec![ResponseType::Code]),
            require_pkce: resolve_require_pkce(&request.client_type, request.require_pkce),
            access_token_lifetime: request.access_token_lifetime.unwrap_or(3600),
            refresh_token_lifetime: request.refresh_token_lifetime.unwrap_or(86400),
            id_token_lifetime: clamp_id_token_lifetime(
                request
                    .id_token_lifetime
                    .unwrap_or(MAX_ID_TOKEN_LIFETIME_SECS),
            ),
            is_active: true,
            created_by: created_by.to_string(),
            created_at: now,
            updated_at: now,
        };

        // 保存到数据库
        self.save_client(&client).await?;

        // 返回客户端信息（包含明文密钥，仅此一次）
        Ok(OidcClientResponse {
            client_id,
            client_secret, // 明文密钥仅在创建时返回
            client_name: client.client_name,
            client_type: client.client_type,
            redirect_uris: client.redirect_uris,
            post_logout_redirect_uris: client.post_logout_redirect_uris,
            allowed_scopes: client.allowed_scopes,
            allowed_grant_types: client.allowed_grant_types,
            allowed_response_types: client.allowed_response_types,
            require_pkce: client.require_pkce,
            access_token_lifetime: client.access_token_lifetime,
            refresh_token_lifetime: client.refresh_token_lifetime,
            id_token_lifetime: client.id_token_lifetime,
            is_active: client.is_active,
            created_at: client.created_at,
            updated_at: client.updated_at,
        })
    }

    // 获取客户端信息
    /// 客户端记录里三个枚举字段（client_type / grant / response）写入时是
    /// 纯字符串（见 `client_type_value` 等），因此读取必须走 serde。
    /// 用 `take::<OidcClient>` 走 SurrealValue 解码会对不上 —— 这与
    /// `LockoutType` 上实测到的 "no variants matched" 是同一类问题。
    const CLIENT_PROJECTION: &'static str = "type::string(id) AS id, client_id, client_secret_hash, client_name, client_type, redirect_uris, post_logout_redirect_uris, allowed_scopes, allowed_grant_types, allowed_response_types, require_pkce, access_token_lifetime, refresh_token_lifetime, id_token_lifetime, is_active, type::string(created_by) AS created_by, created_at, updated_at";

    pub async fn get_client(&self, client_id: &str) -> Result<OidcClient> {
        let query = format!(
            "SELECT {} FROM oidc_client WHERE client_id = $client_id AND is_active = true LIMIT 1",
            Self::CLIENT_PROJECTION
        );

        let rows: Vec<serde_json::Value> = self
            .db
            .query_take0_vec(
                "oidc_client_get",
                &query,
                serde_json::json!({ "client_id": client_id }),
            )
            .await?;

        rows.into_iter()
            .next()
            .map(serde_json::from_value::<OidcClient>)
            .transpose()?
            .ok_or_else(|| anyhow!("Client not found"))
    }

    // 获取客户端列表
    /// 活跃客户端总数 —— 与 `list_clients` 的 `WHERE` 保持同一个判据。
    ///
    /// 路由层以前拿 `clients.len()` 当 `total`。那是**当前这一页**的条数：
    /// 120 个客户端、每页 50，第一页报 50、第三页报 20，分页 UI 永远算不出
    /// 总页数。审计与活动那几个分页端点一直是真的 `count()` 查询，只有这里没有。
    pub async fn count_clients(&self) -> Result<i32> {
        let sql = "SELECT count() AS count FROM oidc_client WHERE is_active = true GROUP ALL";
        let rows: Vec<serde_json::Value> = self
            .db
            .query_take0_vec_no_bind("oidc_client_count", sql)
            .await?;
        Ok(rows
            .first()
            .and_then(|row| row.get("count"))
            .and_then(|c| c.as_i64())
            .unwrap_or(0) as i32)
    }

    pub async fn list_clients(
        &self,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<OidcClientResponse>> {
        let limit = limit.unwrap_or(50);
        let offset = offset.unwrap_or(0);

        let query = format!(
            "SELECT {} FROM oidc_client WHERE is_active = true LIMIT $limit START $offset",
            Self::CLIENT_PROJECTION
        );

        let rows: Vec<serde_json::Value> = self
            .db
            .query_take0_vec(
                "oidc_client_list",
                &query,
                serde_json::json!({ "limit": limit, "offset": offset }),
            )
            .await?;

        let clients = rows
            .into_iter()
            .map(serde_json::from_value::<OidcClient>)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(clients
            .into_iter()
            .map(|client| OidcClientResponse {
                client_id: client.client_id,
                client_secret: "***".to_string(), // 不返回密钥
                client_name: client.client_name,
                client_type: client.client_type,
                redirect_uris: client.redirect_uris,
                post_logout_redirect_uris: client.post_logout_redirect_uris,
                allowed_scopes: client.allowed_scopes,
                allowed_grant_types: client.allowed_grant_types,
                allowed_response_types: client.allowed_response_types,
                require_pkce: client.require_pkce,
                access_token_lifetime: client.access_token_lifetime,
                refresh_token_lifetime: client.refresh_token_lifetime,
                id_token_lifetime: client.id_token_lifetime,
                is_active: client.is_active,
                created_at: client.created_at,
                updated_at: client.updated_at,
            })
            .collect())
    }

    // 更新客户端
    pub async fn update_client(
        &self,
        client_id: &str,
        request: CreateOidcClientRequest,
    ) -> Result<OidcClientResponse> {
        let mut client = self.get_client(client_id).await?;

        // 更新字段
        client.client_name = request.client_name;
        client.client_type = request.client_type;
        client.redirect_uris = request.redirect_uris;
        client.post_logout_redirect_uris = request.post_logout_redirect_uris.unwrap_or_default();
        client.allowed_scopes = request.allowed_scopes.unwrap_or(client.allowed_scopes);
        client.allowed_grant_types = request
            .allowed_grant_types
            .unwrap_or(client.allowed_grant_types);
        client.allowed_response_types = request
            .allowed_response_types
            .unwrap_or(client.allowed_response_types);
        client.require_pkce = resolve_require_pkce(
            &client.client_type,
            request.require_pkce.or(Some(client.require_pkce)),
        );
        client.access_token_lifetime = request
            .access_token_lifetime
            .unwrap_or(client.access_token_lifetime);
        client.refresh_token_lifetime = request
            .refresh_token_lifetime
            .unwrap_or(client.refresh_token_lifetime);
        client.id_token_lifetime = clamp_id_token_lifetime(
            request
                .id_token_lifetime
                .unwrap_or(client.id_token_lifetime),
        );
        client.updated_at = Utc::now().timestamp();

        // 保存更新
        self.update_client_in_db(&client).await?;

        Ok(OidcClientResponse {
            client_id: client.client_id,
            client_secret: "***".to_string(),
            client_name: client.client_name,
            client_type: client.client_type,
            redirect_uris: client.redirect_uris,
            post_logout_redirect_uris: client.post_logout_redirect_uris,
            allowed_scopes: client.allowed_scopes,
            allowed_grant_types: client.allowed_grant_types,
            allowed_response_types: client.allowed_response_types,
            require_pkce: client.require_pkce,
            access_token_lifetime: client.access_token_lifetime,
            refresh_token_lifetime: client.refresh_token_lifetime,
            id_token_lifetime: client.id_token_lifetime,
            is_active: client.is_active,
            created_at: client.created_at,
            updated_at: client.updated_at,
        })
    }

    // 禁用客户端
    pub async fn disable_client(&self, client_id: &str) -> Result<()> {
        // `updated_at` 是 `TYPE number`，不能写 `time::now()`（datetime）。
        // 而且必须 .check()，否则语句级错误被吞：接口返回 204 但客户端根本没被禁用。
        //
        // `RETURN VALUE client_id` 是用来判断"有没有真的命中一行"的：WHERE 匹配不到
        // 任何记录时 UPDATE 一样成功，不看返回行数的话，对一个根本不存在的
        // client_id 调用也会返回 204，调用方以为禁用成功了。
        let query = "UPDATE oidc_client SET is_active = false, updated_at = $updated_at \
                     WHERE client_id = $client_id RETURN VALUE client_id";

        let mut response = self
            .db
            .client
            .query(query)
            .bind(("client_id", client_id.to_owned()))
            .bind(("updated_at", Utc::now().timestamp()))
            .await?
            .check()?;

        let updated: Vec<String> = response.take(0)?;
        if updated.is_empty() {
            return Err(anyhow!("Client not found"));
        }

        Ok(())
    }

    // 重新生成客户端密钥
    pub async fn regenerate_client_secret(&self, client_id: &str) -> Result<String> {
        let client_secret = generate_client_secret();
        let client_secret_hash = hash_client_secret(&client_secret)?;

        // 同上。这里尤其要命：不 check 的话密钥轮换会静默失败 ——
        // 调用方拿到新密钥并更新了自己的配置，服务端却还留着旧哈希，认证直接断。
        //
        // 同样要看返回行数：client_id 不存在时 UPDATE 也会"成功"，
        // 调用方会拿到一个从未落库的新密钥，然后用它去改自己的配置。
        let query = "UPDATE oidc_client SET client_secret_hash = $hash, updated_at = $updated_at \
                     WHERE client_id = $client_id RETURN VALUE client_id";

        let mut response = self
            .db
            .client
            .query(query)
            .bind(("hash", client_secret_hash))
            .bind(("client_id", client_id.to_owned()))
            .bind(("updated_at", Utc::now().timestamp()))
            .await?
            .check()?;

        let updated: Vec<String> = response.take(0)?;
        if updated.is_empty() {
            return Err(anyhow!("Client not found"));
        }

        Ok(client_secret)
    }

    // 私有方法：保存客户端到数据库
    async fn save_client(&self, client: &OidcClient) -> Result<()> {
        let query = r#"
            CREATE oidc_client CONTENT {
                client_id: $client_id,
                client_secret_hash: $client_secret_hash,
                client_name: $client_name,
                client_type: $client_type,
                redirect_uris: $redirect_uris,
                post_logout_redirect_uris: $post_logout_redirect_uris,
                allowed_scopes: $allowed_scopes,
                allowed_grant_types: $allowed_grant_types,
                allowed_response_types: $allowed_response_types,
                require_pkce: $require_pkce,
                access_token_lifetime: $access_token_lifetime,
                refresh_token_lifetime: $refresh_token_lifetime,
                id_token_lifetime: $id_token_lifetime,
                is_active: $is_active,
                created_by: $created_by,
                created_at: $created_at,
                updated_at: $updated_at
            }
        "#;

        self.db
            .client
            .query(query)
            .bind(("client_id", client.client_id.clone()))
            .bind(("client_secret_hash", client.client_secret_hash.clone()))
            .bind(("client_name", client.client_name.clone()))
            .bind(("client_type", client_type_value(&client.client_type)))
            .bind(("redirect_uris", client.redirect_uris.clone()))
            .bind((
                "post_logout_redirect_uris",
                client.post_logout_redirect_uris.clone(),
            ))
            .bind(("allowed_scopes", client.allowed_scopes.clone()))
            .bind((
                "allowed_grant_types",
                grant_type_values(&client.allowed_grant_types),
            ))
            .bind((
                "allowed_response_types",
                response_type_values(&client.allowed_response_types),
            ))
            .bind(("require_pkce", client.require_pkce))
            .bind(("access_token_lifetime", client.access_token_lifetime))
            .bind(("refresh_token_lifetime", client.refresh_token_lifetime))
            .bind(("id_token_lifetime", client.id_token_lifetime))
            .bind(("is_active", client.is_active))
            .bind(("created_by", client.created_by.clone()))
            .bind(("created_at", client.created_at))
            .bind(("updated_at", client.updated_at))
            .await?
            // `query().await` 只代表请求送到了，语句本身的错误藏在 Response 里。
            // 不 check 的话，写失败也会一路返回 Ok —— 管理员看到"已保存"，库里没变。
            .check()?;

        Ok(())
    }

    // 私有方法：更新客户端
    async fn update_client_in_db(&self, client: &OidcClient) -> Result<()> {
        let query = r#"
            UPDATE oidc_client SET
                client_name = $client_name,
                client_type = $client_type,
                redirect_uris = $redirect_uris,
                post_logout_redirect_uris = $post_logout_redirect_uris,
                allowed_scopes = $allowed_scopes,
                allowed_grant_types = $allowed_grant_types,
                allowed_response_types = $allowed_response_types,
                require_pkce = $require_pkce,
                access_token_lifetime = $access_token_lifetime,
                refresh_token_lifetime = $refresh_token_lifetime,
                id_token_lifetime = $id_token_lifetime,
                updated_at = $updated_at
            WHERE client_id = $client_id
        "#;

        self.db
            .client
            .query(query)
            .bind(("client_id", client.client_id.clone()))
            .bind(("client_name", client.client_name.clone()))
            .bind(("client_type", client_type_value(&client.client_type)))
            .bind(("redirect_uris", client.redirect_uris.clone()))
            .bind((
                "post_logout_redirect_uris",
                client.post_logout_redirect_uris.clone(),
            ))
            .bind(("allowed_scopes", client.allowed_scopes.clone()))
            .bind((
                "allowed_grant_types",
                grant_type_values(&client.allowed_grant_types),
            ))
            .bind((
                "allowed_response_types",
                response_type_values(&client.allowed_response_types),
            ))
            .bind(("require_pkce", client.require_pkce))
            .bind(("access_token_lifetime", client.access_token_lifetime))
            .bind(("refresh_token_lifetime", client.refresh_token_lifetime))
            .bind(("id_token_lifetime", client.id_token_lifetime))
            .bind(("updated_at", client.updated_at))
            .await?
            // `query().await` 只代表请求送到了，语句本身的错误藏在 Response 里。
            // 不 check 的话，写失败也会一路返回 Ok —— 管理员看到"已保存"，库里没变。
            .check()?;

        Ok(())
    }
}

// 辅助函数
fn generate_client_id() -> String {
    let timestamp = Utc::now().timestamp_millis();
    let random: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    format!("client_{}{}", timestamp, random)
}

fn generate_client_secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

fn client_type_value(value: &ClientType) -> &'static str {
    match value {
        ClientType::Public => "public",
        ClientType::Confidential => "confidential",
    }
}

fn grant_type_values(values: &[GrantType]) -> Vec<&'static str> {
    values
        .iter()
        .map(|value| match value {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::RefreshToken => "refresh_token",
            GrantType::ClientCredentials => "client_credentials",
        })
        .collect()
}

fn response_type_values(values: &[ResponseType]) -> Vec<&'static str> {
    values
        .iter()
        .map(|value| match value {
            ResponseType::Code => "code",
            ResponseType::IdToken => "id_token",
            ResponseType::CodeIdToken => "code id_token",
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{clamp_id_token_lifetime, resolve_require_pkce, MAX_ID_TOKEN_LIFETIME_SECS};
    use crate::models::oidc_client::ClientType;

    #[test]
    fn public_clients_cannot_turn_pkce_off() {
        // 这是本次修复的核心断言：public 客户端没有 secret，PKCE 是唯一的绑定手段。
        // 实测过关掉之后的后果 —— 无 verifier 无 secret 即可兑换授权码，
        // 截获 code 就等于接管账号。所以管理员传什么都不作数。
        for requested in [Some(false), Some(true), None] {
            assert!(
                resolve_require_pkce(&ClientType::Public, requested),
                "public client must require PKCE regardless of requested={requested:?}"
            );
        }
    }

    #[test]
    fn confidential_clients_keep_the_choice_and_default_to_on() {
        // confidential 有 client_secret 兜底，可以自己决定；缺省仍然是开。
        assert!(resolve_require_pkce(&ClientType::Confidential, None));
        assert!(resolve_require_pkce(&ClientType::Confidential, Some(true)));
        assert!(!resolve_require_pkce(
            &ClientType::Confidential,
            Some(false)
        ));
    }

    #[test]
    fn id_token_lifetime_is_clamped_not_defaulted() {
        // 与 resolve_require_pkce 同一种写法：只改默认值挡不住显式传一个大值。
        assert_eq!(clamp_id_token_lifetime(3600), MAX_ID_TOKEN_LIFETIME_SECS);
        assert_eq!(clamp_id_token_lifetime(0), MAX_ID_TOKEN_LIFETIME_SECS);
        assert_eq!(clamp_id_token_lifetime(-1), MAX_ID_TOKEN_LIFETIME_SECS);
        assert_eq!(clamp_id_token_lifetime(120), 120);
    }
}
