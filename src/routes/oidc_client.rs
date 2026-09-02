use std::sync::Arc;

use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    config::{host_of, is_loopback_host},
    error::AuthError,
    models::oidc_client::{CreateOidcClientRequest, GrantType, OidcClientResponse, ResponseType},
    require_permission,
    services::{database::Database, oidc_client_management::OidcClientService},
    utils::jwt::AuthedUser,
};

/// OIDC 客户端注册表是整个 SSO 的信任根：能改 redirect_uris 就能劫持任意登录。
/// 因此读写分别要求 `soulauth:oidc_clients.read` / `soulauth:oidc_clients.write`。
///
/// 权限名直接用 `models::permission::names` 的常量，不在本模块再起别名 ——
/// 同一个权限有两个名字，改动时必然漏掉一个。
use crate::models::permission::names::{OIDC_CLIENTS_READ, OIDC_CLIENTS_WRITE};

pub fn oidc_client_routes() -> Router {
    Router::new()
        .route("/clients", post(create_client))
        .route("/clients", get(list_clients))
        .route("/clients/:client_id", get(get_client))
        .route("/clients/:client_id", put(update_client))
        .route("/clients/:client_id", delete(disable_client))
        .route(
            "/clients/:client_id/regenerate-secret",
            post(regenerate_secret),
        )
}

#[derive(Deserialize)]
struct ListClientsQuery {
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize)]
struct ListClientsResponse {
    clients: Vec<OidcClientResponse>,
    total: i32,
    limit: i32,
    offset: i32,
}

#[derive(Serialize)]
struct RegenerateSecretResponse {
    client_secret: String,
    message: String,
}

// 创建 OIDC 客户端
async fn create_client(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Json(request): Json<CreateOidcClientRequest>,
) -> Result<Json<OidcClientResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, OIDC_CLIENTS_WRITE);

    request
        .validate()
        .map_err(|e| AuthError::BadRequest(format!("Validation error: {}", e)))?;
    validate_redirect_uris(&request)?;
    reject_unsupported_grant_types(&request)?;
    reject_unsupported_response_types(&request)?;

    // created_by 记录真实操作人，不再是硬编码的 "system"。
    match client_service.create_client(request, &user_id).await {
        Ok(client) => Ok(Json(client)),
        Err(e) => Err(AuthError::ServerError(e.to_string())),
    }
}

// 获取客户端列表
async fn list_clients(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Query(query): Query<ListClientsQuery>,
) -> Result<Json<ListClientsResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, OIDC_CLIENTS_READ);

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);

    // `total` 是**总数**，不是这一页的条数。以前写的是 `clients.len()`：
    // 120 个客户端、每页 50，第一页报 50、第三页报 20，分页 UI 算不出总页数。
    let clients = client_service
        .list_clients(Some(limit), Some(offset))
        .await
        .map_err(|e| AuthError::ServerError(e.to_string()))?;
    let total = client_service
        .count_clients()
        .await
        .map_err(|e| AuthError::ServerError(e.to_string()))?;

    Ok(Json(ListClientsResponse {
        clients,
        total,
        limit,
        offset,
    }))
}

/// 把服务层的 `anyhow` 错误映射成 HTTP 错误。
///
/// 这四个接口以前一律写成 `Err(_) => NotFound("Client not found")`：**任何**失败
/// 都以"没这个客户端"的面目出现。真正的写库失败因此被伪装成 404，管理员只会
/// 反复核对 client_id，永远查不到数据库那一侧 —— 补上的 `.check()` 好不容易把
/// 错误捞出来，又在这里被丢掉了。
///
/// 服务层用 `anyhow!("Client not found")` 表示确实不存在，只有这一种才是 404，
/// 其余一律按服务端错误处理并记日志（响应体由 `AuthError` 统一遮蔽，不外泄细节）。
fn client_error(operation: &str, error: anyhow::Error) -> AuthError {
    if error.to_string().contains("Client not found") {
        return AuthError::NotFound("Client not found".to_string());
    }

    tracing::error!(error = %error, operation, "OIDC client operation failed");
    AuthError::ServerError(error.to_string())
}

// 获取单个客户端
async fn get_client(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
) -> Result<Json<OidcClientResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, OIDC_CLIENTS_READ);

    match client_service.get_client(&client_id).await {
        Ok(client) => Ok(Json(OidcClientResponse {
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
        })),
        Err(e) => Err(client_error("get client", e)),
    }
}

// 更新客户端
async fn update_client(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
    Json(request): Json<CreateOidcClientRequest>,
) -> Result<Json<OidcClientResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, OIDC_CLIENTS_WRITE);

    request
        .validate()
        .map_err(|e| AuthError::BadRequest(format!("Validation error: {}", e)))?;
    validate_redirect_uris(&request)?;
    reject_unsupported_grant_types(&request)?;
    reject_unsupported_response_types(&request)?;

    match client_service.update_client(&client_id, request).await {
        Ok(client) => Ok(Json(client)),
        Err(e) => Err(client_error("update client", e)),
    }
}

// 禁用客户端
async fn disable_client(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
) -> Result<StatusCode, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, OIDC_CLIENTS_WRITE);

    match client_service.disable_client(&client_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err(client_error("disable client", e)),
    }
}

// 重新生成客户端密钥
async fn regenerate_secret(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
) -> Result<Json<RegenerateSecretResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, OIDC_CLIENTS_WRITE);

    match client_service.regenerate_client_secret(&client_id).await {
        Ok(new_secret) => Ok(Json(RegenerateSecretResponse {
            client_secret: new_secret,
            message:
                "Client secret has been regenerated. Please update your application configuration."
                    .to_string(),
        })),
        Err(e) => Err(client_error("regenerate client secret", e)),
    }
}

/// 拒绝令牌端点实现不了的 grant type。
///
/// `GrantType::ClientCredentials` 能被注册进 `allowed_grant_types`（枚举里有它、
/// 序列化成 "client_credentials"、注册返回 200），但 `/api/oidc/token` 只有
/// `authorization_code` 与 `refresh_token` 两个分支，发现文档也只宣告这两个。
/// 结果是：想接一个机器对机器客户端的人，注册那一步一切正常，
/// 之后**每一次**换令牌都拿到 "Unsupported grant type" —— 故障点与病因隔了一步，
/// 而配置看起来完全正确。
///
/// 与 `resolve_require_pkce` 同一个原则：不接受一个永远不会生效的配置。
fn reject_unsupported_grant_types(request: &CreateOidcClientRequest) -> Result<(), AuthError> {
    let Some(grants) = request.allowed_grant_types.as_ref() else {
        return Ok(());
    };

    if grants.contains(&GrantType::ClientCredentials) {
        return Err(AuthError::BadRequest(
            "client_credentials is not supported by this token endpoint; \
             only authorization_code and refresh_token are implemented"
                .to_string(),
        ));
    }

    Ok(())
}

/// 拒绝授权端点实现不了的 response type。
///
/// 与 `reject_unsupported_grant_types` 同一条原则，只是这一半一直没做。
///
/// `ResponseType` 里有 `id_token` 与 `code id_token`，注册得进去，发现文档却只
/// 宣告 `response_types_supported: ["code"]`，而授权端**无论请求哪种都返回
/// `?code=`**（`routes::oidc` 那句 `format!("{{}}{{}}code={{}}", …)` 没有分支）。
/// 于是管理员存下一份配置，它既不按 implicit 走、也不报错，只是安静地表现成
/// 授权码流 —— 接入方对着 fragment 里的 `id_token` 等一辈子。
///
/// `code id_token` 更彻底一点：它连匹配都匹配不上。授权端按空格拆词，只产出
/// `Code` 和 `IdToken` 两种，永远产不出 `CodeIdToken`，所以只注册了它的客户端
/// 一次都授权不了。
///
/// 枚举变体本身留着不删：库里可能已经存了这些值，删掉会让那些行反序列化失败，
/// 从「配置无效」变成「客户端读不出来」。
fn reject_unsupported_response_types(request: &CreateOidcClientRequest) -> Result<(), AuthError> {
    let Some(types) = request.allowed_response_types.as_ref() else {
        return Ok(());
    };

    if types.iter().any(|t| *t != ResponseType::Code) {
        return Err(AuthError::BadRequest(
            "only response_type=code is supported by this authorization endpoint; \
             implicit and hybrid flows are not implemented"
                .to_string(),
        ));
    }

    Ok(())
}

/// 回跳地址必须是绝对 https URL（环回地址放行以便本地开发），且不带 fragment。
///
/// 环回与否交给 `config::is_loopback_host` 判定，不在这里另写一套。
/// 这里原本写的是：
///
/// ```text
/// uri.starts_with("http://localhost") || uri.starts_with("http://127.0.0.1")
/// ```
///
/// 前缀匹配在两个方向上都是错的：
///
/// - **放进来的**：`http://localhost.evil.com/cb` 与
///   `http://localhost@evil.example/cb` 都以那个前缀开头，但主机分别是
///   `localhost.evil.com` 和 `evil.example` —— 授权码会明文发往远端。
/// - **挡在外面的**：`http://[::1]:3000/cb` 是合法环回，却一个前缀都不匹配。
///
/// `host_of` 会把 authority 整段取出来（含 `user@` 部分、正确处理 IPv6
/// 方括号），再拿去和环回白名单做**精确**比较，两个方向就都对了。
fn validate_redirect_uris(request: &CreateOidcClientRequest) -> Result<(), AuthError> {
    let all = request
        .redirect_uris
        .iter()
        .chain(request.post_logout_redirect_uris.iter().flatten());

    for uri in all {
        if uri.contains('#') {
            return Err(AuthError::BadRequest(format!(
                "Redirect URI must not contain a fragment: {uri}"
            )));
        }

        if uri.starts_with("https://") {
            continue;
        }

        match host_of(uri) {
            Some(host) if is_loopback_host(host) => continue,
            Some(_) => {
                return Err(AuthError::BadRequest(format!(
                    "Redirect URI must use https (http is only allowed for loopback \
                     hosts — an exact 127.0.0.1, localhost or [::1]): {uri}"
                )))
            }
            None => {
                return Err(AuthError::BadRequest(format!(
                    "Redirect URI must be an absolute URL starting with https:// or http://: {uri}"
                )))
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_redirect_uris;
    use crate::models::oidc_client::{ClientType, CreateOidcClientRequest};

    fn request(redirect_uris: Vec<&str>) -> CreateOidcClientRequest {
        CreateOidcClientRequest {
            client_name: "test".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: redirect_uris.into_iter().map(str::to_string).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn accepts_https_and_localhost_redirect_uris() {
        assert!(validate_redirect_uris(&request(vec![
            "https://app.example/cb",
            "http://localhost:3000/cb",
            "http://127.0.0.1:3000/cb",
        ]))
        .is_ok());
    }

    #[test]
    fn rejects_plain_http_and_fragments() {
        assert!(validate_redirect_uris(&request(vec!["http://app.example/cb"])).is_err());
        assert!(validate_redirect_uris(&request(vec!["https://app.example/cb#x"])).is_err());
    }

    /// 之前这里只测了 `http://localhost:3000/cb` 通过、`http://app.example/cb`
    /// 拒绝 —— 两个显而易见的端点，中间的边界一个没测，于是前缀匹配的漏洞
    /// 在两个绿色单测的掩护下活了下来。
    #[test]
    fn a_prefix_that_looks_like_loopback_is_not_loopback() {
        for uri in [
            "http://localhost.evil.com/cb",
            "http://localhost@evil.example/cb",
            "http://127.0.0.1.evil.com/cb",
            "http://127.0.0.1@evil.example/cb",
            "http://localhost-staging.example/cb",
        ] {
            assert!(
                validate_redirect_uris(&request(vec![uri])).is_err(),
                "{uri} 的主机不是环回地址，不该被当成本地开发地址放行"
            );
        }
    }

    /// 反方向：合法的环回写法一个都不能误杀。`[::1]` 在改动前是被拒的。
    #[test]
    fn every_spelling_of_loopback_is_accepted() {
        for uri in [
            "http://localhost:3000/cb",
            "http://127.0.0.1:3000/cb",
            "http://[::1]:3000/cb",
            "http://localhost/cb",
        ] {
            assert!(
                validate_redirect_uris(&request(vec![uri])).is_ok(),
                "{uri} 是合法的环回回跳地址"
            );
        }
    }

    #[test]
    fn a_relative_uri_is_rejected_rather_than_ignored() {
        assert!(validate_redirect_uris(&request(vec!["/cb"])).is_err());
        assert!(validate_redirect_uris(&request(vec!["app.example/cb"])).is_err());
    }
}
