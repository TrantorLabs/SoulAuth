use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use surrealdb_types::SurrealValue;
use tracing::{error, info};

use crate::{
    error::AuthError,
    models::{
        permission::{CreatePermissionRequest, Permission, PermissionResponse},
        role::{CreateRoleRequest, Role, RoleResponse, UpdateRoleRequest},
        user::User,
        user_role::{RolePermission, RoleWithPermissions, UserRole, UserRoleResponse},
    },
    services::database::Database,
};

/// 角色名 / 权限名的校验。
///
/// 以前完全不校验：`{"name": ""}` 能建出一个空名字的角色，而所有按名字寻址的
/// 接口（`/roles/{role_name}`、`check_user_role`）都拿它没办法 —— 建得出来、
/// 找不回去。名字同时也是 RBAC 判定的键，混入空白或控制字符会让
/// "看起来一样的两个角色"实际是两个。
fn validate_rbac_name(kind: &str, name: &str) -> Result<String, AuthError> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err(AuthError::ValidationError(format!(
            "{kind} name is required"
        )));
    }
    if trimmed.chars().count() > 64 {
        return Err(AuthError::ValidationError(format!(
            "{kind} name must be at most 64 characters"
        )));
    }
    // 权限名带 `soulauth:` 命名空间前缀，所以冒号要放行；
    // 其余只收字母数字与 `_ - . :`，把空白和控制字符挡在外面。
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
    {
        return Err(AuthError::ValidationError(format!(
            "{kind} name may only contain letters, digits and '_' '-' '.' ':'"
        )));
    }

    Ok(trimmed.to_string())
}

pub struct RBACService {
    db: Arc<Database>,
}

impl RBACService {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    // 角色管理
    pub async fn create_role(
        &self,
        mut request: CreateRoleRequest,
        created_by: &User,
    ) -> Result<RoleResponse, AuthError> {
        request.name = validate_rbac_name("Role", &request.name)?;

        // 检查角色名是否已存在
        if self.get_role_by_name(&request.name).await?.is_some() {
            return Err(AuthError::ValidationError(
                "Role name already exists".to_string(),
            ));
        }

        let now = Utc::now().timestamp();
        let role = Role {
            id: None,
            name: request.name.clone(),
            display_name: request.display_name.clone(),
            description: request.description.clone(),
            is_system: false,
            created_at: now,
            updated_at: now,
        };

        let query = "CREATE role CONTENT $role";
        let mut response = self
            .db
            .client
            .query(query)
            .bind(("role", role.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to create role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created_role: Vec<Role> = response.take(0).map_err(|e| {
            error!("Failed to parse created role: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created_role.is_empty() {
            return Err(AuthError::DatabaseError(
                "Failed to create role".to_string(),
            ));
        }

        info!(
            "Role '{}' created by user '{}'",
            request.name, created_by.email
        );
        Ok(created_role[0].clone().into())
    }

    pub async fn get_role_by_name(&self, name: &str) -> Result<Option<Role>, AuthError> {
        let query = "SELECT * FROM role WHERE name = $name";
        let mut response = self
            .db
            .client
            .query(query)
            .bind(("name", name.to_owned()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get role by name: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let roles: Vec<Role> = response.take(0).map_err(|e| {
            error!("Failed to parse role: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(roles.into_iter().next())
    }

    pub async fn update_role(
        &self,
        role_name: &str,
        request: UpdateRoleRequest,
        updated_by: &User,
    ) -> Result<RoleResponse, AuthError> {
        let role = self
            .get_role_by_name(role_name)
            .await?
            .ok_or_else(|| AuthError::NotFound("Role not found".to_string()))?;

        if role.is_system {
            return Err(AuthError::ValidationError(
                "Cannot update system role".to_string(),
            ));
        }

        let role_id = role
            .id
            .ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;

        if request.display_name.is_none() && request.description.is_none() {
            return Err(AuthError::ValidationError(
                "No fields to update".to_string(),
            ));
        }

        // 全部走绑定参数：以前这里把 display_name / description 直接内插进 SurrealQL，
        // 任何带引号的输入都能改写整条语句。
        let role_key = crate::utils::record_id::record_id_key_to_string(&role_id);
        let query = r#"
            UPDATE type::record('role', $role_key) SET
                display_name = $display_name ?? display_name,
                description = $description ?? description,
                updated_at = $updated_at
        "#;
        let mut response = self
            .db
            .raw_query(
                "rbac_update_role",
                query,
                json!({
                    "role_key": role_key,
                    "display_name": request.display_name,
                    "description": request.description,
                    "updated_at": Utc::now().timestamp(),
                }),
            )
            .await
            .map_err(|e| {
                error!("Failed to update role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let updated_role: Vec<Role> = response.take(0).map_err(|e| {
            error!("Failed to parse updated role: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if updated_role.is_empty() {
            return Err(AuthError::DatabaseError(
                "Failed to update role".to_string(),
            ));
        }

        info!(
            "Role '{}' updated by user '{}'",
            role_name, updated_by.email
        );
        // 同 list_roles：不补的话，改一次角色名就会拿到一个"权限为空"的响应，
        // 而权限其实一条没少。
        let mut responses: Vec<RoleResponse> = vec![updated_role[0].clone().into()];
        self.attach_permissions(&mut responses).await?;
        Ok(responses.remove(0))
    }

    pub async fn delete_role(&self, role_name: &str, deleted_by: &User) -> Result<(), AuthError> {
        let role = self
            .get_role_by_name(role_name)
            .await?
            .ok_or_else(|| AuthError::NotFound("Role not found".to_string()))?;

        if role.is_system {
            return Err(AuthError::ValidationError(
                "Cannot delete system role".to_string(),
            ));
        }

        let role_id = role
            .id
            .ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;

        // 检查是否有用户使用此角色
        let user_count_query =
            "SELECT count() as count FROM user_role WHERE role_id = $role_id GROUP ALL";
        let mut response = self
            .db
            .client
            .query(user_count_query)
            .bind(("role_id", role_id.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to check role usage: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let count_result: Vec<serde_json::Value> = response.take(0).map_err(|e| {
            error!("Failed to parse count result: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if !count_result.is_empty() {
            if let Some(count) = count_result[0].get("count") {
                if count.as_u64().unwrap_or(0) > 0 {
                    return Err(AuthError::ValidationError(
                        "Cannot delete role that is assigned to users".to_string(),
                    ));
                }
            }
        }

        // 删除角色的权限关联
        let delete_permissions_query = "DELETE FROM role_permission WHERE role_id = $role_id";
        self.db
            .client
            .query(delete_permissions_query)
            .bind(("role_id", role_id.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to delete role permissions: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        // 删除角色
        let role_key = crate::utils::record_id::record_id_key_to_string(&role_id);
        self.db
            .raw_query(
                "rbac_delete_role",
                "DELETE type::record('role', $role_key)",
                json!({ "role_key": role_key }),
            )
            .await
            .map_err(|e| {
                error!("Failed to delete role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        info!(
            "Role '{}' deleted by user '{}'",
            role_name, deleted_by.email
        );
        Ok(())
    }

    pub async fn list_roles(
        &self,
        page: Option<u32>,
        limit: Option<u32>,
    ) -> Result<Vec<RoleResponse>, AuthError> {
        // 同 `list_users`：page=0 会下溢，limit 不封顶等于允许全表拉取。
        let page = page.unwrap_or(1).max(1);
        let limit = limit.unwrap_or(50).clamp(1, 200);
        let offset = (page - 1).saturating_mul(limit);

        let mut response = self
            .db
            .raw_query(
                "rbac_list_roles",
                "SELECT * FROM role ORDER BY created_at DESC LIMIT $limit START $offset",
                json!({ "limit": limit, "offset": offset }),
            )
            .await
            .map_err(|e| {
                error!("Failed to list roles: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let roles: Vec<Role> = response.take(0).map_err(|e| {
            error!("Failed to parse roles: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        // 填上真实权限。
        //
        // `From<Role>` 只能把 permissions 置空（它拿不到数据库），此前列表接口
        // 就这么原样返回了 —— 于是 GET /api/rbac/roles 里每个角色都显示 0 条权限，
        // 而 GET /api/rbac/roles/{name} 对同一个角色能返回 18 条。管理后台的角色
        // 列表据此渲染，看到的是"所有角色都没有任何权限"。
        //
        // 用两次批量查询补齐，而不是逐角色查一次：角色数虽然不多，
        // 但 list_users 的 N+1 已经是本轮点过名的问题，不该在这里再造一个。
        let mut responses: Vec<RoleResponse> = roles.into_iter().map(Into::into).collect();
        self.attach_permissions(&mut responses).await?;
        Ok(responses)
    }

    /// 给一批 `RoleResponse` 批量填充权限名，固定两次查询。
    ///
    /// 两处都用**字符串形式**比较 record id，而不是把 `RecordId` 当绑定值传进去：
    /// `query_take0_vec` 走的是 JSON 绑定，`RecordId` 经 serde_json 会退化成
    /// 普通字符串，于是 `role_id IN ["role:admin"]` 变成 record 与 string 相比，
    /// 永远匹配不到 —— 这个坑本文件别处的注释已经记过一次。
    async fn attach_permissions(&self, roles: &mut [RoleResponse]) -> Result<(), AuthError> {
        if roles.is_empty() {
            return Ok(());
        }

        let role_keys: Vec<String> = roles.iter().map(|r| format!("role:{}", r.id)).collect();

        #[derive(Debug, serde::Deserialize, SurrealValue)]
        struct Link {
            role_id: String,
            permission_id: String,
        }

        let links: Vec<Link> = self
            .db
            .query_take0_vec(
                "rbac_list_role_permission_links",
                "SELECT type::string(role_id) AS role_id, \
                        type::string(permission_id) AS permission_id \
                 FROM role_permission WHERE type::string(role_id) IN $role_keys",
                json!({ "role_keys": role_keys }),
            )
            .await?;

        if links.is_empty() {
            return Ok(());
        }

        #[derive(Debug, serde::Deserialize, SurrealValue)]
        struct NamedPermission {
            id: String,
            name: String,
        }

        let mut permission_keys: Vec<String> =
            links.iter().map(|l| l.permission_id.clone()).collect();
        permission_keys.sort();
        permission_keys.dedup();

        let named: Vec<NamedPermission> = self
            .db
            .query_take0_vec(
                "rbac_list_permission_names",
                "SELECT type::string(id) AS id, name FROM permission \
                 WHERE type::string(id) IN $permission_keys",
                json!({ "permission_keys": permission_keys }),
            )
            .await?;

        let name_by_id: std::collections::HashMap<&str, &str> = named
            .iter()
            .map(|p| (p.id.as_str(), p.name.as_str()))
            .collect();

        let mut by_role: std::collections::HashMap<&str, Vec<String>> =
            std::collections::HashMap::new();
        for link in &links {
            if let Some(name) = name_by_id.get(link.permission_id.as_str()) {
                by_role
                    .entry(link.role_id.as_str())
                    .or_default()
                    .push((*name).to_string());
            }
        }

        for role in roles.iter_mut() {
            let key = format!("role:{}", role.id);
            if let Some(mut names) = by_role.remove(key.as_str()) {
                names.sort();
                role.permissions = names;
            }
        }

        Ok(())
    }

    pub async fn create_permission(
        &self,
        mut request: CreatePermissionRequest,
        created_by: &User,
    ) -> Result<PermissionResponse, AuthError> {
        request.name = validate_rbac_name("Permission", &request.name)?;

        // 检查权限名是否已存在
        if self.get_permission_by_name(&request.name).await?.is_some() {
            return Err(AuthError::ValidationError(
                "Permission name already exists".to_string(),
            ));
        }

        let now = Utc::now().timestamp();
        let permission = Permission {
            id: None,
            name: request.name.clone(),
            display_name: request.display_name.clone(),
            description: request.description.clone(),
            resource: request.resource.clone(),
            action: request.action.clone(),
            is_system: false,
            created_at: now,
            updated_at: now,
        };

        let query = "CREATE permission CONTENT $permission";
        let mut response = self
            .db
            .client
            .query(query)
            .bind(("permission", permission.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to create permission: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created_permission: Vec<Permission> = response.take(0).map_err(|e| {
            error!("Failed to parse created permission: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created_permission.is_empty() {
            return Err(AuthError::DatabaseError(
                "Failed to create permission".to_string(),
            ));
        }

        info!(
            "Permission '{}' created by user '{}'",
            request.name, created_by.email
        );
        Ok(created_permission[0].clone().into())
    }

    pub async fn get_permission_by_name(
        &self,
        name: &str,
    ) -> Result<Option<Permission>, AuthError> {
        let query = "SELECT * FROM permission WHERE name = $name";
        let mut response = self
            .db
            .client
            .query(query)
            .bind(("name", name.to_owned()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get permission by name: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let permissions: Vec<Permission> = response.take(0).map_err(|e| {
            error!("Failed to parse permission: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(permissions.into_iter().next())
    }

    pub async fn list_permissions(
        &self,
        page: Option<u32>,
        limit: Option<u32>,
    ) -> Result<Vec<PermissionResponse>, AuthError> {
        // 同 `list_users`：page=0 会下溢，limit 不封顶等于允许全表拉取。
        let page = page.unwrap_or(1).max(1);
        let limit = limit.unwrap_or(50).clamp(1, 200);
        let offset = (page - 1).saturating_mul(limit);

        let mut response = self
            .db
            .raw_query(
                "rbac_list_permissions",
                "SELECT * FROM permission ORDER BY resource, action LIMIT $limit START $offset",
                json!({ "limit": limit, "offset": offset }),
            )
            .await
            .map_err(|e| {
                error!("Failed to list permissions: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let permissions: Vec<Permission> = response.take(0).map_err(|e| {
            error!("Failed to parse permissions: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(permissions
            .into_iter()
            .map(|permission| permission.into())
            .collect())
    }

    // 用户角色分配
    pub async fn assign_role_to_user(
        &self,
        user_id: &str,
        role_name: &str,
        assigned_by: &User,
    ) -> Result<(), AuthError> {
        // `assigned_by` 也是外键，同样指身份根。
        let assigned_by_id = assigned_by
            .id
            .as_ref()
            .ok_or_else(|| AuthError::DatabaseError("Assigned by user ID not found".to_string()))?;
        let assigned_by_thing = self
            .db
            .actor_ref_of_user(&crate::utils::record_id::record_id_key_to_string(
                assigned_by_id,
            ))
            .await?;
        self.assign_role(user_id, role_name, &assigned_by_thing, &assigned_by.email)
            .await
    }

    /// 由系统自身发起的角色授予（没有人类操作者）。
    ///
    /// 目前唯一的调用方是首个管理员的引导路径。那一刻系统里还没有任何可以充当
    /// 操作者的账号，记一个真实用户 ID 反而是伪造归因，所以 `assigned_by` 落在
    /// `user:system` 上 —— 与部署文档里那段手工 SQL 用的是同一个约定。
    pub async fn assign_role_as_system(
        &self,
        user_id: &str,
        role_name: &str,
    ) -> Result<(), AuthError> {
        // 哨兵引用 `actor_identity:system`。
        //
        // 它是种子数据里一条**真实存在**的记录，不是悬空引用 —— 我最初以为
        // 「类型对上即可、记录不必存在」，集成测试当场证否：SurrealDB 在
        // SCHEMAFULL 表上会具体化被引用的记录，缺字段就以
        // 「Expected `string` but found `NONE`」拒绝整条导入。
        //
        // 那条哨兵的 status 是 retired：既占住标识符，又永远过不了
        // can_authenticate()。
        //
        // 用哨兵而不是某个真实管理员：这次授予没有人类操作者，记一个真实 id
        // 反而是伪造归因。种子数据里的 granted_by 用的是同一个约定。
        let system = surrealdb::types::RecordId::new("actor_identity", "system");
        self.assign_role(user_id, role_name, &system, "system")
            .await
    }

    /// 授予角色的共享实现。
    ///
    /// 拆出来是为了让引导路径不必伪造一个 `User` 才能调用 —— 那样既要给领域
    /// 类型加 `Default`，又会让一个空壳对象在日志和归因里冒充真实操作者。
    async fn assign_role(
        &self,
        user_id: &str,
        role_name: &str,
        assigned_by_thing: &surrealdb::types::RecordId,
        actor_label: &str,
    ) -> Result<(), AuthError> {
        let role = self
            .get_role_by_name(role_name)
            .await?
            .ok_or_else(|| AuthError::NotFound(format!("Role '{}' not found", role_name)))?;

        let role_id = role
            .id
            .ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;
        // 角色分配挂在**身份根**上，不是 user 行（Stage 3 起外键指 actor_identity）。
        let user_thing = self.db.actor_ref_of_user(user_id).await?;

        // 检查用户是否已经有此角色
        let check_query = "SELECT * FROM user_role WHERE user_id = $user_id AND role_id = $role_id";
        let mut response = self
            .db
            .client
            .query(check_query)
            .bind(("user_id", user_thing.clone()))
            .bind(("role_id", role_id.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to check user role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let existing: Vec<UserRole> = response.take(0).map_err(|e| {
            error!("Failed to parse user role: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if !existing.is_empty() {
            return Err(AuthError::ValidationError(
                "User already has this role".to_string(),
            ));
        }

        let user_role = UserRole {
            id: None,
            user_id: user_thing,
            role_id,
            assigned_at: Utc::now().timestamp(),
            assigned_by: assigned_by_thing.clone(),
        };

        let query = "CREATE user_role CONTENT $user_role";
        let mut create_response = self
            .db
            .client
            .query(query)
            .bind(("user_role", user_role.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to assign role to user: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created: Vec<UserRole> = create_response.take(0).map_err(|e| {
            error!("Failed to parse created user role: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created.is_empty() {
            return Err(AuthError::DatabaseError(
                "Failed to persist user role".to_string(),
            ));
        }

        info!(
            "Role '{}' assigned to user '{}' by '{}'",
            role_name, user_id, actor_label
        );
        Ok(())
    }

    pub async fn remove_role_from_user(
        &self,
        user_id: &str,
        role_name: &str,
        removed_by: &User,
    ) -> Result<(), AuthError> {
        let role = self
            .get_role_by_name(role_name)
            .await?
            .ok_or_else(|| AuthError::NotFound(format!("Role '{}' not found", role_name)))?;

        let role_id = role
            .id
            .ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;
        // 与写入侧同源：写的是 actor ref，删的时候按 user ref 找就一条也删不掉。
        let user_thing = self.db.actor_ref_of_user(user_id).await?;

        let delete_query = "DELETE FROM user_role WHERE user_id = $user_id AND role_id = $role_id";
        self.db
            .client
            .query(delete_query)
            .bind(("user_id", user_thing.clone()))
            .bind(("role_id", role_id.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to remove role from user: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        info!(
            "Role '{}' removed from user '{}' by '{}'",
            role_name, user_id, removed_by.email
        );
        Ok(())
    }

    pub async fn get_user_roles(&self, user_id: &str) -> Result<UserRoleResponse, AuthError> {
        #[derive(Debug, serde::Deserialize, SurrealValue)]
        struct UserRoleRow {
            role_id: String,
            assigned_at: Option<i64>,
        }

        let user_id = crate::utils::record_id::normalize_user_id(user_id);

        // 直接比较 record，不再拼字符串。此前这里只列了 `user:⟨id⟩` 和 `user:id`
        // 两种形式，而 `type::string(user_id)` 实际产出的是带反引号的
        // `` user:`id` `` —— 两种都匹配不上，导致「查用户角色」永远返回空。
        let query = r#"
            SELECT string::replace(type::string(role_id), 'role:', '') as role_id, assigned_at
            FROM user_role
            WHERE user_id = (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]
        "#;

        let mut response = self
            .db
            .client
            .query(query)
            .bind(("user_key", user_id.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get user roles: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let role_data: Vec<UserRoleRow> = response.take(0).map_err(|e| {
            error!("Failed to parse user roles: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if role_data.is_empty() {
            return Ok(UserRoleResponse {
                user_id: user_id.to_string(),
                roles: Vec::new(),
            });
        }

        let mut assigned_at_map: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        let mut role_ids: Vec<surrealdb::types::RecordId> = Vec::new();
        for data in &role_data {
            let role_id_str = data.role_id.trim();
            if role_id_str.is_empty() {
                continue;
            }
            let assigned_at = data.assigned_at.unwrap_or(0);

            assigned_at_map.insert(role_id_str.to_string(), assigned_at);
            role_ids.push(surrealdb::types::RecordId::new("role", role_id_str));
        }

        if role_ids.is_empty() {
            return Ok(UserRoleResponse {
                user_id: user_id.to_string(),
                roles: Vec::new(),
            });
        }

        let role_query = "SELECT * FROM role WHERE id IN $role_ids";
        let mut role_response = self
            .db
            .client
            .query(role_query)
            .bind(("role_ids", role_ids))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get roles: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let roles: Vec<Role> = role_response.take(0).map_err(|e| {
            error!("Failed to parse roles: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        let mut roles_with_permissions = Vec::new();
        for role in roles {
            let role_id = role
                .id
                .clone()
                .ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;
            let role_id_str = crate::utils::record_id::record_id_key_to_string(&role_id);
            let role_name = role.name.clone();
            let permissions = self.get_role_permissions(&role_name).await?;

            let assigned_at = assigned_at_map
                .get(role_id_str.as_str())
                .copied()
                .unwrap_or(0);
            roles_with_permissions.push(RoleWithPermissions {
                id: role_id_str,
                name: role_name,
                display_name: role.display_name.clone(),
                description: role.description.clone(),
                permissions,
                assigned_at: chrono::DateTime::from_timestamp(assigned_at, 0).unwrap_or_default(),
            });
        }

        Ok(UserRoleResponse {
            user_id: user_id.to_string(),
            roles: roles_with_permissions,
        })
    }

    pub async fn get_role_permissions(&self, role_name: &str) -> Result<Vec<String>, AuthError> {
        let role = self
            .get_role_by_name(role_name)
            .await?
            .ok_or_else(|| AuthError::NotFound(format!("Role '{}' not found", role_name)))?;

        let role_id = role
            .id
            .ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;

        // SurrealDB 2.x does not support JOIN; use subqueries
        let ids_query = "SELECT VALUE permission_id FROM role_permission WHERE role_id = $role_id";
        let mut ids_response = self
            .db
            .client
            .query(ids_query)
            .bind(("role_id", role_id.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get role permissions: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let permission_ids: Vec<surrealdb::types::RecordId> =
            ids_response.take(0).map_err(|e| {
                error!("Failed to parse role permission ids: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        if permission_ids.is_empty() {
            return Ok(Vec::new());
        }

        let names_query = "SELECT name FROM permission WHERE id IN $permission_ids";
        let mut names_response = self
            .db
            .client
            .query(names_query)
            .bind(("permission_ids", permission_ids))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get role permissions: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let permission_data: Vec<serde_json::Value> = names_response.take(0).map_err(|e| {
            error!("Failed to parse role permissions: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        let permissions = permission_data
            .into_iter()
            .map(|data| data["name"].as_str().unwrap_or("").to_string())
            .filter(|name| !name.is_empty())
            .collect();

        Ok(permissions)
    }

    pub async fn assign_permission_to_role(
        &self,
        role_name: &str,
        permission_name: &str,
        granted_by: &User,
    ) -> Result<(), AuthError> {
        let role = self
            .get_role_by_name(role_name)
            .await?
            .ok_or_else(|| AuthError::NotFound(format!("Role '{}' not found", role_name)))?;

        let permission = self
            .get_permission_by_name(permission_name)
            .await?
            .ok_or_else(|| {
                AuthError::NotFound(format!("Permission '{}' not found", permission_name))
            })?;

        let role_id = role
            .id
            .ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;
        let permission_id = permission
            .id
            .ok_or_else(|| AuthError::DatabaseError("Permission ID not found".to_string()))?;
        // `granted_by` 是外键，Stage 3 起指身份根。漏改这一处会让整条
        // role_permission 写入以 500 失败 —— 集成测试「给角色授权限」抓到了。
        let granted_by_id = granted_by
            .id
            .as_ref()
            .ok_or_else(|| AuthError::DatabaseError("Granted by user ID not found".to_string()))?;
        let granted_by_thing = self
            .db
            .actor_ref_of_user(&crate::utils::record_id::record_id_key_to_string(
                granted_by_id,
            ))
            .await?;

        // 检查是否已经分配
        let check_query = "SELECT * FROM role_permission WHERE role_id = $role_id AND permission_id = $permission_id";
        let mut response = self
            .db
            .client
            .query(check_query)
            .bind(("role_id", role_id.clone()))
            .bind(("permission_id", permission_id.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to check role permission: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let existing: Vec<RolePermission> = response.take(0).map_err(|e| {
            error!("Failed to parse role permission: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if !existing.is_empty() {
            return Err(AuthError::ValidationError(
                "Role already has this permission".to_string(),
            ));
        }

        let role_permission = RolePermission {
            id: None,
            role_id,
            permission_id,
            granted_at: Utc::now().timestamp(),
            granted_by: granted_by_thing,
        };

        let query = "CREATE role_permission CONTENT $role_permission";
        let mut create_response = self
            .db
            .client
            .query(query)
            .bind(("role_permission", role_permission.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to assign permission to role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created: Vec<RolePermission> = create_response.take(0).map_err(|e| {
            error!("Failed to parse created role permission: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created.is_empty() {
            return Err(AuthError::DatabaseError(
                "Failed to persist role permission".to_string(),
            ));
        }

        info!(
            "Permission '{}' assigned to role '{}' by '{}'",
            permission_name, role_name, granted_by.email
        );
        Ok(())
    }

    pub async fn remove_permission_from_role(
        &self,
        role_name: &str,
        permission_name: &str,
        removed_by: &User,
    ) -> Result<(), AuthError> {
        let role = self
            .get_role_by_name(role_name)
            .await?
            .ok_or_else(|| AuthError::NotFound(format!("Role '{}' not found", role_name)))?;

        let permission = self
            .get_permission_by_name(permission_name)
            .await?
            .ok_or_else(|| {
                AuthError::NotFound(format!("Permission '{}' not found", permission_name))
            })?;

        let role_id = role
            .id
            .ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;
        let permission_id = permission
            .id
            .ok_or_else(|| AuthError::DatabaseError("Permission ID not found".to_string()))?;

        let delete_query = "DELETE FROM role_permission WHERE role_id = $role_id AND permission_id = $permission_id";
        self.db
            .client
            .query(delete_query)
            .bind(("role_id", role_id.clone()))
            .bind(("permission_id", permission_id.clone()))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to remove permission from role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        info!(
            "Permission '{}' removed from role '{}' by '{}'",
            permission_name, role_name, removed_by.email
        );
        Ok(())
    }

    // 权限检查
    pub async fn check_user_permission(
        &self,
        user_id: &str,
        permission_name: &str,
    ) -> Result<bool, AuthError> {
        let user_id = crate::utils::record_id::normalize_user_id(user_id);

        let query = r#"
            SELECT count() as count
            FROM role_permission
            WHERE role_id IN (
                SELECT VALUE role_id
                FROM user_role
                WHERE user_id = (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]
            )
              AND permission_id IN (SELECT VALUE id FROM permission WHERE name = $permission_name)
            GROUP ALL
        "#;

        let mut response = self
            .db
            .raw_query(
                "check_user_permission",
                query,
                json!({
                    "user_key": user_id,
                    "permission_name": permission_name,
                }),
            )
            .await
            .map_err(|e| {
                error!("Failed to check user permission: {}", e);
                e
            })?;

        let count_result: Vec<serde_json::Value> = response.take(0).map_err(|e| {
            error!("Failed to parse permission check result: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if count_result.is_empty() {
            return Ok(false);
        }

        let count = count_result[0]
            .get("count")
            .and_then(|c| c.as_u64())
            .unwrap_or(0);

        Ok(count > 0)
    }

    pub async fn check_user_role(&self, user_id: &str, role_name: &str) -> Result<bool, AuthError> {
        let user_id = crate::utils::record_id::normalize_user_id(user_id);

        let query = r#"
            SELECT count() as count
            FROM user_role
            WHERE user_id = (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]
              AND role_id IN (SELECT VALUE id FROM role WHERE name = $role_name)
            GROUP ALL
        "#;

        let mut response = self
            .db
            .raw_query(
                "check_user_role",
                query,
                json!({
                    "user_key": user_id,
                    "role_name": role_name,
                }),
            )
            .await
            .map_err(|e| {
                error!("Failed to check user role: {}", e);
                e
            })?;

        let count_result: Vec<serde_json::Value> = response.take(0).map_err(|e| {
            error!("Failed to parse role check result: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if count_result.is_empty() {
            return Ok(false);
        }

        let count = count_result[0]
            .get("count")
            .and_then(|c| c.as_u64())
            .unwrap_or(0);

        Ok(count > 0)
    }

    pub async fn get_user_permissions(&self, user_id: &str) -> Result<Vec<String>, AuthError> {
        let user_id = crate::utils::record_id::normalize_user_id(user_id);

        let query = r#"
            SELECT name
            FROM permission
            WHERE id IN (
                SELECT VALUE permission_id FROM role_permission
                WHERE role_id IN (
                    SELECT VALUE role_id
                    FROM user_role
                    WHERE user_id = (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]
                )
            )
        "#;

        let mut response = self
            .db
            .client
            .query(query)
            .bind(("user_key", user_id))
            .await
            .and_then(|response| response.check())
            .map_err(|e| {
                error!("Failed to get user permissions: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let permission_data: Vec<serde_json::Value> = response.take(0).map_err(|e| {
            error!("Failed to parse user permissions: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        let mut permissions: Vec<String> = permission_data
            .into_iter()
            .map(|data| data["name"].as_str().unwrap_or("").to_string())
            .filter(|name| !name.is_empty())
            .collect();
        permissions.sort();
        permissions.dedup();

        Ok(permissions)
    }
}

#[cfg(test)]
mod name_validation_tests {
    use super::validate_rbac_name;

    #[test]
    fn rejects_names_that_cannot_be_addressed_later() {
        // 建得出来、按名字找不回去 —— 所有 /roles/{name} 形式的接口都拿它没办法。
        for bad in ["", "   ", "has space", "tab\there", "换行\n"] {
            assert!(
                validate_rbac_name("Role", bad).is_err(),
                "should reject {bad:?}"
            );
        }
        assert!(
            validate_rbac_name("Role", &"x".repeat(65)).is_err(),
            "过长应拒绝"
        );
    }

    #[test]
    fn accepts_seeded_shapes_including_the_namespace_prefix() {
        // 种子数据里的真实形状必须能通过，否则 initial_data.sql 与代码就对不上了。
        for ok in [
            "admin",
            "user_manager",
            "soulauth:users.read",
            "soulauth:oidc_clients.write",
        ] {
            assert!(
                validate_rbac_name("Permission", ok).is_ok(),
                "should accept {ok}"
            );
        }
        assert_eq!(validate_rbac_name("Role", "  admin  ").unwrap(), "admin");
    }
}
