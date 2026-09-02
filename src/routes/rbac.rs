use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Extension, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    error::AuthError,
    models::{
        permission::{CreatePermissionRequest, PermissionResponse},
        role::{CreateRoleRequest, RoleResponse, UpdateRoleRequest},
        user_role::{
            AssignPermissionToRoleRequest, AssignRoleRequest, RemovePermissionFromRoleRequest,
            RemoveRoleRequest, UserRoleResponse,
        },
    },
    require_permission_status,
    services::{database::Database, rbac::RBACService},
    utils::jwt::AuthedUser,
};

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

pub fn router() -> Router {
    Router::new()
        // 角色管理路由
        .route("/roles", get(list_roles).post(create_role))
        .route(
            "/roles/:role_name",
            get(get_role).post(update_role).delete(delete_role),
        )
        .route("/roles/:role_name/permissions", get(get_role_permissions))
        .route(
            "/roles/:role_name/permissions/assign",
            post(assign_permission_to_role),
        )
        .route(
            "/roles/:role_name/permissions/remove",
            post(remove_permission_from_role),
        )
        // 权限管理路由
        .route(
            "/permissions",
            get(list_permissions).post(create_permission),
        )
        .route("/permissions/:permission_name", get(get_permission))
        // 用户角色分配路由
        .route("/users/:user_id/roles", get(get_user_roles))
        .route("/users/:user_id/roles/assign", post(assign_role_to_user))
        .route("/users/:user_id/roles/remove", post(remove_role_from_user))
        .route("/users/:user_id/permissions", get(get_user_permissions))
        // 权限检查路由
        .route("/check/permission/:permission_name", get(check_permission))
        .route("/check/role/:role_name", get(check_role))
}

fn normalize_user_id(id: &str) -> String {
    crate::utils::record_id::normalize_user_id(id)
}

fn current_user_id(current_user: &AuthedUser) -> Result<String, AuthError> {
    current_user.id()
}

// ===== 角色管理 =====

async fn create_role(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Json(request): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>, AuthError> {
    let user_id = current_user_id(&current_user)?;
    require_permission_status!(db, &user_id, crate::models::permission::names::ROLES_WRITE);

    let rbac_service = RBACService::new(db);

    match rbac_service.create_role(request, current_user.user()).await {
        Ok(role) => {
            info!(
                "Role created successfully by user '{}'",
                current_user.user().email
            );
            Ok(Json(role))
        }
        Err(AuthError::ValidationError(msg)) => {
            error!("Role creation validation error: {}", msg);
            Err(AuthError::ValidationError(msg))
        }
        Err(e) => {
            error!("Failed to create role: {}", e);
            Err(e)
        }
    }
}

async fn list_roles(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Vec<RoleResponse>>, AuthError> {
    let user_id = current_user_id(&current_user)?;
    require_permission_status!(db, &user_id, crate::models::permission::names::ROLES_READ);

    let rbac_service = RBACService::new(db);

    match rbac_service
        .list_roles(pagination.page, pagination.limit)
        .await
    {
        Ok(roles) => Ok(Json(roles)),
        Err(e) => {
            error!("Failed to list roles: {}", e);
            Err(e)
        }
    }
}

async fn get_role(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(role_name): Path<String>,
) -> Result<Json<RoleResponse>, AuthError> {
    let user_id = current_user_id(&current_user)?;
    require_permission_status!(db, &user_id, crate::models::permission::names::ROLES_READ);

    let rbac_service = RBACService::new(db);

    match rbac_service.get_role_by_name(&role_name).await {
        Ok(Some(role)) => {
            let mut role_response: RoleResponse = role.into();
            // 获取角色权限
            if let Ok(permissions) = rbac_service.get_role_permissions(&role_name).await {
                role_response.permissions = permissions;
            }
            Ok(Json(role_response))
        }
        Ok(None) => Err(AuthError::NotFound(format!("Role '{role_name}' not found"))),
        Err(e) => {
            error!("Failed to get role: {}", e);
            Err(e)
        }
    }
}

async fn update_role(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(role_name): Path<String>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, AuthError> {
    let user_id = current_user_id(&current_user)?;
    require_permission_status!(db, &user_id, crate::models::permission::names::ROLES_WRITE);

    let rbac_service = RBACService::new(db);

    match rbac_service
        .update_role(&role_name, request, current_user.user())
        .await
    {
        Ok(role) => {
            info!(
                "Role '{}' updated successfully by user '{}'",
                role_name,
                current_user.user().email
            );
            Ok(Json(role))
        }
        Err(e @ AuthError::NotFound(_)) => Err(e),
        Err(AuthError::ValidationError(msg)) => {
            error!("Role update validation error: {}", msg);
            Err(AuthError::ValidationError(msg))
        }
        Err(e) => {
            error!("Failed to update role: {}", e);
            Err(e)
        }
    }
}

async fn delete_role(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(role_name): Path<String>,
) -> Result<StatusCode, AuthError> {
    let user_id = current_user_id(&current_user)?;
    require_permission_status!(db, &user_id, crate::models::permission::names::ROLES_DELETE);

    let rbac_service = RBACService::new(db);

    match rbac_service
        .delete_role(&role_name, current_user.user())
        .await
    {
        Ok(_) => {
            info!(
                "Role '{}' deleted by user '{}'",
                role_name,
                current_user.user().email
            );
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e @ AuthError::NotFound(_)) => Err(e),
        // 系统角色不可删、仍被用户占用时都归为 400。
        Err(AuthError::ValidationError(msg)) => {
            error!("Role deletion rejected: {}", msg);
            Err(AuthError::ValidationError(msg))
        }
        Err(e) => {
            error!("Failed to delete role: {}", e);
            Err(e)
        }
    }
}

// ===== 权限管理 =====

async fn create_permission(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Json(request): Json<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>, AuthError> {
    let user_id = current_user_id(&current_user)?;
    require_permission_status!(
        db,
        &user_id,
        crate::models::permission::names::PERMISSIONS_WRITE
    );

    let rbac_service = RBACService::new(db);

    match rbac_service
        .create_permission(request, current_user.user())
        .await
    {
        Ok(permission) => {
            info!(
                "Permission created successfully by user '{}'",
                current_user.user().email
            );
            Ok(Json(permission))
        }
        Err(AuthError::ValidationError(msg)) => {
            error!("Permission creation validation error: {}", msg);
            Err(AuthError::ValidationError(msg))
        }
        Err(e) => {
            error!("Failed to create permission: {}", e);
            Err(e)
        }
    }
}

async fn list_permissions(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Vec<PermissionResponse>>, AuthError> {
    let user_id = current_user_id(&current_user)?;
    require_permission_status!(
        db,
        &user_id,
        crate::models::permission::names::PERMISSIONS_READ
    );

    let rbac_service = RBACService::new(db);

    match rbac_service
        .list_permissions(pagination.page, pagination.limit)
        .await
    {
        Ok(permissions) => Ok(Json(permissions)),
        Err(e) => {
            error!("Failed to list permissions: {}", e);
            Err(e)
        }
    }
}

async fn get_permission(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(permission_name): Path<String>,
) -> Result<Json<PermissionResponse>, AuthError> {
    let user_id = current_user_id(&current_user)?;
    require_permission_status!(
        db,
        &user_id,
        crate::models::permission::names::PERMISSIONS_READ
    );

    let rbac_service = RBACService::new(db);

    match rbac_service.get_permission_by_name(&permission_name).await {
        Ok(Some(permission)) => Ok(Json(permission.into())),
        Ok(None) => Err(AuthError::NotFound(format!(
            "Permission '{permission_name}' not found"
        ))),
        Err(e) => {
            error!("Failed to get permission: {}", e);
            Err(e)
        }
    }
}

// ===== 角色权限分配 =====

async fn get_role_permissions(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(role_name): Path<String>,
) -> Result<Json<Vec<String>>, AuthError> {
    let user_id = current_user_id(&current_user)?;
    require_permission_status!(db, &user_id, crate::models::permission::names::ROLES_READ);

    let rbac_service = RBACService::new(db);

    match rbac_service.get_role_permissions(&role_name).await {
        Ok(permissions) => Ok(Json(permissions)),
        Err(e @ AuthError::NotFound(_)) => Err(e),
        Err(e) => {
            error!("Failed to get role permissions: {}", e);
            Err(e)
        }
    }
}

async fn assign_permission_to_role(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(role_name): Path<String>,
    Json(request): Json<AssignPermissionToRoleRequest>,
) -> Result<StatusCode, AuthError> {
    let user_id = current_user_id(&current_user)?;
    require_permission_status!(
        db,
        &user_id,
        crate::models::permission::names::PERMISSIONS_WRITE
    );

    let rbac_service = RBACService::new(db);

    match rbac_service
        .assign_permission_to_role(&role_name, &request.permission_name, current_user.user())
        .await
    {
        Ok(_) => {
            info!(
                "Permission '{}' assigned to role '{}' by user '{}'",
                request.permission_name,
                role_name,
                current_user.user().email
            );
            Ok(StatusCode::NO_CONTENT)
        }
        Err(AuthError::NotFound(msg)) => {
            error!("Assignment failed - not found: {}", msg);
            Err(AuthError::NotFound(msg))
        }
        Err(AuthError::ValidationError(msg)) => {
            error!("Assignment validation error: {}", msg);
            Err(AuthError::ValidationError(msg))
        }
        Err(e) => {
            error!("Failed to assign permission to role: {}", e);
            Err(e)
        }
    }
}

async fn remove_permission_from_role(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(role_name): Path<String>,
    Json(request): Json<RemovePermissionFromRoleRequest>,
) -> Result<StatusCode, AuthError> {
    let user_id = current_user_id(&current_user)?;
    require_permission_status!(
        db,
        &user_id,
        crate::models::permission::names::PERMISSIONS_WRITE
    );

    let rbac_service = RBACService::new(db);

    match rbac_service
        .remove_permission_from_role(&role_name, &request.permission_name, current_user.user())
        .await
    {
        Ok(_) => {
            info!(
                "Permission '{}' removed from role '{}' by user '{}'",
                request.permission_name,
                role_name,
                current_user.user().email
            );
            Ok(StatusCode::NO_CONTENT)
        }
        Err(AuthError::NotFound(msg)) => {
            error!("Removal failed - not found: {}", msg);
            Err(AuthError::NotFound(msg))
        }
        Err(e) => {
            error!("Failed to remove permission from role: {}", e);
            Err(e)
        }
    }
}

// ===== 用户角色分配 =====

async fn get_user_roles(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(target_user_id): Path<String>,
) -> Result<Json<UserRoleResponse>, AuthError> {
    let requester_id = current_user_id(&current_user)?;
    let target_user_id = normalize_user_id(&target_user_id);

    // 查自己的角色不需要额外权限，查别人的需要 users.read。
    if requester_id != target_user_id {
        let rbac_service = RBACService::new(db.clone());
        let allowed = rbac_service
            .check_user_permission(&requester_id, crate::models::permission::names::USERS_READ)
            .await
            .unwrap_or(false);
        if !allowed {
            return Err(AuthError::MissingPermission(
                crate::models::permission::names::USERS_READ.to_string(),
            ));
        }
    }

    let rbac_service = RBACService::new(db);

    match rbac_service.get_user_roles(&target_user_id).await {
        Ok(user_roles) => Ok(Json(user_roles)),
        Err(e) => {
            error!("Failed to get user roles: {}", e);
            Err(e)
        }
    }
}

async fn assign_role_to_user(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(user_id): Path<String>,
    Json(request): Json<AssignRoleRequest>,
) -> Result<StatusCode, AuthError> {
    let requester_id = current_user_id(&current_user)?;
    require_permission_status!(
        db,
        &requester_id,
        crate::models::permission::names::ROLES_WRITE
    );

    let target_user_id = normalize_user_id(&user_id);
    let rbac_service = RBACService::new(db);

    match rbac_service
        .assign_role_to_user(&target_user_id, &request.role_name, current_user.user())
        .await
    {
        Ok(_) => {
            info!(
                "Role '{}' assigned to user '{}' by user '{}'",
                request.role_name,
                target_user_id,
                current_user.user().email
            );
            Ok(StatusCode::NO_CONTENT)
        }
        Err(AuthError::NotFound(msg)) => {
            error!("Assignment failed - not found: {}", msg);
            Err(AuthError::NotFound(msg))
        }
        Err(AuthError::ValidationError(msg)) => {
            error!("Assignment validation error: {}", msg);
            Err(AuthError::ValidationError(msg))
        }
        Err(e) => {
            error!("Failed to assign role to user: {}", e);
            Err(e)
        }
    }
}

async fn remove_role_from_user(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(user_id): Path<String>,
    Json(request): Json<RemoveRoleRequest>,
) -> Result<StatusCode, AuthError> {
    let requester_id = current_user_id(&current_user)?;
    require_permission_status!(
        db,
        &requester_id,
        crate::models::permission::names::ROLES_WRITE
    );

    let target_user_id = normalize_user_id(&user_id);
    let rbac_service = RBACService::new(db);

    match rbac_service
        .remove_role_from_user(&target_user_id, &request.role_name, current_user.user())
        .await
    {
        Ok(_) => {
            info!(
                "Role '{}' removed from user '{}' by user '{}'",
                request.role_name,
                target_user_id,
                current_user.user().email
            );
            Ok(StatusCode::NO_CONTENT)
        }
        Err(AuthError::NotFound(msg)) => {
            error!("Removal failed - not found: {}", msg);
            Err(AuthError::NotFound(msg))
        }
        Err(e) => {
            error!("Failed to remove role from user: {}", e);
            Err(e)
        }
    }
}

async fn get_user_permissions(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(target_user_id): Path<String>,
) -> Result<Json<Vec<String>>, AuthError> {
    let requester_id = current_user_id(&current_user)?;
    let target_user_id = normalize_user_id(&target_user_id);

    if requester_id != target_user_id {
        let rbac_service = RBACService::new(db.clone());
        let allowed = rbac_service
            .check_user_permission(&requester_id, crate::models::permission::names::USERS_READ)
            .await
            .unwrap_or(false);
        if !allowed {
            return Err(AuthError::MissingPermission(
                crate::models::permission::names::USERS_READ.to_string(),
            ));
        }
    }

    let rbac_service = RBACService::new(db);

    match rbac_service.get_user_permissions(&target_user_id).await {
        Ok(permissions) => Ok(Json(permissions)),
        Err(e) => {
            error!("Failed to get user permissions: {}", e);
            Err(e)
        }
    }
}

// ===== 权限检查 =====

#[derive(Debug, Serialize)]
struct PermissionCheckResponse {
    has_permission: bool,
    user_id: String,
    permission: String,
}

#[derive(Debug, Serialize)]
struct RoleCheckResponse {
    has_role: bool,
    user_id: String,
    role: String,
}

async fn check_permission(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(permission_name): Path<String>,
) -> Result<Json<PermissionCheckResponse>, AuthError> {
    let rbac_service = RBACService::new(db);
    let user_id = current_user_id(&current_user)?;

    match rbac_service
        .check_user_permission(&user_id, &permission_name)
        .await
    {
        Ok(has_permission) => {
            let response = PermissionCheckResponse {
                has_permission,
                user_id: user_id.clone(),
                permission: permission_name,
            };
            Ok(Json(response))
        }
        Err(e) => {
            error!("Failed to check permission: {}", e);
            Err(e)
        }
    }
}

async fn check_role(
    Extension(db): Extension<Arc<Database>>,
    current_user: AuthedUser,
    Path(role_name): Path<String>,
) -> Result<Json<RoleCheckResponse>, AuthError> {
    let rbac_service = RBACService::new(db);
    let user_id = current_user_id(&current_user)?;

    match rbac_service.check_user_role(&user_id, &role_name).await {
        Ok(has_role) => {
            let response = RoleCheckResponse {
                has_role,
                user_id: user_id.clone(),
                role: role_name,
            };
            Ok(Json(response))
        }
        Err(e) => {
            error!("Failed to check role: {}", e);
            Err(e)
        }
    }
}
