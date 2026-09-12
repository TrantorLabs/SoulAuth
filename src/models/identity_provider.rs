//! 外部身份来源的 DTO。
//!
//! V1 的 `IdentityProvider` 记录已经删除：外部身份的解析权归
//! `identity_binding`。这里只剩 OAuth 回调解析出来的用户信息这一个传输对象。

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub provider: String,
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
}
