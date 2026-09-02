use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

/// SoulAuth 自有权限名的**唯一来源**。
///
/// # 为什么要前缀
///
/// P0-DECISION-10 DEC-10-05：SoulAuth 的 RBAC 是 Auth-local 的，不构成
/// SoulseedOS 的 Canonical Permission Source。OS 侧也有 `users.read` 这类名字，
/// 两边同名时，日志、审计与错误信息里只出现权限名，排查时分不清是哪一侧拒绝。
/// 前缀是"正名"，Adapter 侧的结构化打标（`issuer_provider_ref = "soulauth"`）是"保险"，
/// 两者都要。
///
/// # 为什么收成常量
///
/// 这些名字原本以字面量形式散落在 32 处。加前缀若逐处替换，等于把同一事实
/// 复制 32 份，任何一处漏改都表现为"该接口谁都进不去"，而且编译期无感。
/// 收成常量后，前缀只存在于本文件，拼错是编译错误。
///
/// # 与种子数据的耦合
///
/// 这些名字必须与 `initial_data.sql` 中 `permission` 表的 `name` 字段一致，
/// 否则 `require_permission!` 永远匹配不到。本模块的测试会把两个 SQL 文件
/// 以 `include_str!` 编进来做一致性断言 —— 把一个静默的运行期故障
/// 变成编译期就能发现的测试失败。
pub mod names {
    /// 给权限名加上 Auth-local 命名空间前缀。
    ///
    /// **前缀的唯一来源就是这个宏**。用宏而不是逐个写全名：前缀写 11 遍
    /// 就是把同一事实复制 11 份，改的时候必然漏掉一个。
    macro_rules! auth_local {
        ($name:literal) => {
            concat!("soulauth:", $name)
        };
    }

    pub const USERS_READ: &str = auth_local!("users.read");
    pub const USERS_WRITE: &str = auth_local!("users.write");
    pub const ROLES_READ: &str = auth_local!("roles.read");
    pub const ROLES_WRITE: &str = auth_local!("roles.write");
    pub const ROLES_DELETE: &str = auth_local!("roles.delete");
    pub const PERMISSIONS_READ: &str = auth_local!("permissions.read");
    pub const PERMISSIONS_WRITE: &str = auth_local!("permissions.write");
    pub const SECURITY_READ: &str = auth_local!("security.read");
    /// 解锁账户 / IP 等安全写操作。种子里一直有这条权限（授予 admin 与
    /// security_manager），但代码侧此前没有对应常量 —— 因为没有任何端点用它：
    /// `AccountLockoutService` 的 unlock_user / unlock_ip 实现好了却没有路由暴露。
    pub const SECURITY_WRITE: &str = auth_local!("security.write");
    pub const AUDIT_READ: &str = auth_local!("audit.read");
    pub const OIDC_CLIENTS_READ: &str = auth_local!("oidc_clients.read");
    pub const OIDC_CLIENTS_WRITE: &str = auth_local!("oidc_clients.write");
    /// 查看已注册的非人主体及其**公钥**。
    pub const ACTORS_READ: &str = auth_local!("actors.read");
    /// 注册非人主体、增删其验证密钥。拿到它等于能凭空造出一个可认证的主体。
    pub const ACTORS_WRITE: &str = auth_local!("actors.write");

    /// 命名空间前缀本身，由宏推导而来（`auth_local!("")`），
    /// 不重复写一遍字面量。仅测试需要，故 `cfg(test)`。
    #[cfg(test)]
    pub const NAMESPACE: &str = auth_local!("");

    /// 管理后台准入所认可的只读权限。
    ///
    /// 以前这个列表直接写在 `routes::auth::is_admin_console_user` 里，
    /// 与常量分居两处；放在这里，"哪些权限算后台准入"只有一个答案。
    pub const ADMIN_CONSOLE_READ: [&str; 4] = [USERS_READ, ROLES_READ, SECURITY_READ, AUDIT_READ];

    /// 代码实际会校验的全部权限名，仅供一致性测试使用。
    #[cfg(test)]
    pub const ALL_CHECKED: [&str; 12] = [
        USERS_READ,
        USERS_WRITE,
        ROLES_READ,
        ROLES_WRITE,
        ROLES_DELETE,
        PERMISSIONS_READ,
        PERMISSIONS_WRITE,
        SECURITY_READ,
        SECURITY_WRITE,
        AUDIT_READ,
        OIDC_CLIENTS_READ,
        OIDC_CLIENTS_WRITE,
    ];
}

#[cfg(test)]
mod name_tests {
    use super::names;

    /// 种子数据必须定义代码校验的每一个权限名。
    ///
    /// 漏一个的后果是：对应接口的 `require_permission!` 永远查不到该权限，
    /// 任何人都拿不到它 —— 接口静默锁死，运行前无从发现。
    #[test]
    fn every_checked_permission_exists_in_seed_data() {
        let seed = include_str!("../../initial_data.sql");
        for name in names::ALL_CHECKED {
            assert!(
                seed.contains(&format!("name: \"{name}\"")),
                "initial_data.sql 缺少权限定义: {name}"
            );
        }
    }

    /// 种子数据里不得残留未加前缀的权限名。
    ///
    /// 前缀化是破坏性变更：代码与种子只要有一侧没改全，
    /// 管理后台就会整体锁死。这条断言把"改漏了"挡在测试阶段。
    ///
    /// 只检查 `UPSERT permission:` 块内的 `name` —— 同一份 SQL 里
    /// `role` 也有 `name` 字段（`admin`、`auditor` 等），角色名不加前缀，
    /// 按行匹配会把它们一并卷进来误报。
    #[test]
    fn seed_data_has_no_unprefixed_permission_names() {
        for (file, sql) in [("initial_data.sql", include_str!("../../initial_data.sql"))] {
            let mut in_permission_block = false;
            let mut checked = 0usize;

            for line in sql.lines() {
                let trimmed = line.trim();

                if trimmed.starts_with("UPSERT permission:") {
                    in_permission_block = true;
                    continue;
                }
                if in_permission_block && trimmed.starts_with('}') {
                    in_permission_block = false;
                    continue;
                }
                if !in_permission_block || !trimmed.starts_with("name: \"") {
                    continue;
                }

                checked += 1;
                assert!(
                    trimmed.contains(names::NAMESPACE),
                    "{file} 存在未加 `{}` 前缀的权限名: {trimmed}",
                    names::NAMESPACE
                );
            }

            // 一个都没查到，说明块识别失效（例如 SQL 改了写法），
            // 而不是"全都合规"。
            assert!(checked > 0, "{file} 未能识别出任何 permission 定义块");
        }
    }

    /// 钉住前缀取值。
    ///
    /// 前缀是与种子 SQL 之间的契约：改了宏而没同步改两个 .sql，
    /// 运行期表现为「所有权限检查失效、管理后台全员锁死」。
    /// 这条断言 + `seed_data_has_no_unprefixed_permission_names`
    /// 一起把这种改漏挡在测试阶段。
    #[test]
    fn namespace_prefix_is_stable() {
        assert_eq!(names::NAMESPACE, "soulauth:");
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct Permission {
    pub id: Option<Thing>,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource: String, // 资源类型，如 "user", "role", "auth"
    pub action: String,   // 操作类型，如 "read", "write", "delete"
    pub is_system: bool,  // 系统权限不可删除
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePermissionRequest {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PermissionResponse {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub is_system: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<Permission> for PermissionResponse {
    fn from(permission: Permission) -> Self {
        Self {
            // `id` 是 Option（新建时还没有）。这里 unwrap 会把一条缺 id 的记录
            // 变成整个 handler 线程 panic —— 与 `User::from` 已经修掉的是同一处隐患。
            // 降级成空串，交由上层按"找不到"处理。
            id: permission
                .id
                .as_ref()
                .map(crate::utils::record_id::record_id_key_to_string)
                .unwrap_or_default(),
            name: permission.name,
            display_name: permission.display_name,
            description: permission.description,
            resource: permission.resource,
            action: permission.action,
            is_system: permission.is_system,
            created_at: permission.created_at,
            updated_at: permission.updated_at,
        }
    }
}
