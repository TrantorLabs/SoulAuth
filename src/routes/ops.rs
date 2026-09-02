//! 运营看板。
//!
//! 原先这里还有群组 / 会话明细两组接口（社交功能，已随社交模块一并删除），
//! 并且**整组路由没有任何鉴权** —— 任何人都能拉全量用户与会话数据。
//! 现在只剩会员分布概览，且需要 `users.read` 权限。

use std::sync::Arc;

use axum::{response::Json, routing::get, Extension, Router};
use serde_json::json;

use crate::{
    error::AuthError, require_permission_status, services::database::Database,
    utils::jwt::AuthedUser,
};

pub fn router() -> Router {
    Router::new().route("/memberships/overview", get(get_membership_overview))
}

async fn get_membership_overview(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let user_id = user.id()?;
    require_permission_status!(db, &user_id, crate::models::permission::names::USERS_READ);

    // 在库里聚合，只取回几行。
    //
    // 以前这里是 `SELECT * FROM user`：无 LIMIT、无聚合，把每一行反序列化成
    // `User`（**连密码哈希一起**）装进 Vec 再在应用侧遍历计数。用户量上来之后
    // 这是一次可预期的 OOM，而且把全量口令哈希拉进了进程内存 —— 一个只需要
    // 几个计数的看板接口没有任何理由碰到它们。
    let rows: Vec<serde_json::Value> = db
        .query_take0_vec_no_bind(
            "membership_overview",
            "SELECT membership_level, count() AS total FROM user \
             WHERE account_status != 'Deleted' GROUP BY membership_level",
        )
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    let mut distribution = serde_json::Map::new();
    for level in ["FREE", "PRO", "PREMIUM", "ULTIMATE", "TEAM"] {
        distribution.insert(level.to_string(), json!(0));
    }

    let mut total_users: u64 = 0;
    for row in &rows {
        let count = row.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
        total_users += count;

        let level = row
            .get("membership_level")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_uppercase())
            .unwrap_or_else(|| "FREE".to_string());

        // 库里出现了预设档位之外的值时，仍然计入总数并单列一档，
        // 而不是悄悄丢掉 —— 看板的总数对不上账比多出一档更难查。
        let current = distribution
            .get(&level)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        distribution.insert(level, json!(current + count));
    }

    Ok(Json(json!({
        "total_users": total_users,
        "distribution": distribution,
        "limits": {
            "FREE": { "ai_limit": 1, "daily_messages": 10, "price": 0.0 },
            "PRO": { "ai_limit": 3, "daily_messages": 50, "price": 19.9 },
            "PREMIUM": { "ai_limit": 5, "daily_messages": 100, "price": 39.9 },
            "ULTIMATE": { "ai_limit": 7, "daily_messages": null, "price": 79.9 },
            "TEAM": { "ai_limit": 35, "daily_messages": null, "price": 299.9 }
        }
    })))
}
