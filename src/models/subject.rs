//! JWT `subject_type` claim 的取值。
//!
//! # 这里为什么只剩一个枚举
//!
//! V1 有一张 `subject` 表和对应的 `Subject` 结构体，用来表示「主体」。
//! Stage 1-3 之后主体由 `actor_identity` 表示，那张表已经零写入，结构体
//! 也就没有了存在理由 —— 留着它等于留一个永远不会有数据的对象。
//!
//! `SubjectType` 保留，因为它仍是**已签发令牌**里的一个 claim。改它会让
//! 在途令牌反序列化失败，属于 Stage 4 拆除 V1 令牌契约时一并处理的事。

use serde::{Deserialize, Serialize};
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, SurrealValue, Default)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    #[default]
    Human,
    Agent,
}
