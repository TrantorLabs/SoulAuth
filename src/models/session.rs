use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct Session {
    pub id: Option<Thing>,
    pub user_id: Thing,
    /// 会话令牌的 SHA-256 指纹，**不是令牌本身**。
    ///
    /// 以前这里存的是完整签名 JWT，与客户端手里那枚逐字节相同 —— 一次数据库
    /// 读泄露就等于交出全站在线会话。指纹同样能满足吊销查询的全部需要。
    pub token_hash: String,
    pub expires_at: i64, // Unix timestamp
    pub created_at: i64, // Unix timestamp
    pub user_agent: String,
    pub ip_address: String,

    /// 建立这个会话时**实际验证了哪一类凭证**。
    ///
    /// 没有它，系统回答不了几个本该能回答的问题：这个会话是口令建立的还是
    /// 过了 MFA？吊销某一枚凭证应该影响哪些会话？当前认证有多新？
    #[serde(default)]
    pub credential_kind: Option<String>,

    /// 建立这个会话的本地凭证的**稳定引用**（`credential:xxx` /
    /// `ai_actor_credential:xxx`）。外部联合与邮件链接没有本地凭证，为 `None`。
    ///
    /// 撤销传播按它找会话。此前按 `credential_label` 找 —— label 是显示属性，
    /// 没有唯一性，两把同名钥匙会互相误伤。
    #[serde(default)]
    pub credential_ref: Option<String>,

    /// 凭证的可读标识，只做展示。**不得**作为撤销键。
    #[serde(default)]
    pub credential_label: Option<String>,

    /// 这次认证发生的时刻。
    ///
    /// OIDC 的 `auth_time` 必须取自**建立该会话的那次认证**。以前它取的是
    /// `user.last_login_at` —— 那个字段会被**后来的**任何一次登录更新，于是一个
    /// 旧会话签出的 ID Token 可能携带一个比它自己更晚的认证时间。那是明确的
    /// 认证事实错置：依赖 `auth_time` 做重认证判断的 RP 会被骗过去。
    #[serde(default)]
    pub authenticated_at: Option<i64>,

    /// 建立这个会话时**成立的全部认证方法**，按认证顺序（`["password", "totp"]`）。
    ///
    /// `credential_kind` 只记主方法，是投影；这里是事实本身的方法集合。
    /// `/api/auth/introspect` 把它原样交给依赖方，依赖方由此知道这个会话是
    /// 口令建立的还是过了第二因素 —— 而不是只知道「首因素是什么」。
    ///
    /// 0.3.0 之前建立的会话没有这一列；读取时按 `credential_kind` 退化成单元素。
    #[serde(default)]
    pub methods: Option<Vec<String>>,

    /// 支撑这次认证的**全部**本地凭证的稳定引用。`credential_ref` 是它的首项。
    /// 外部联合与邮件链接没有本地凭证，为空。
    #[serde(default)]
    pub credential_refs: Option<Vec<String>>,
}

impl Session {
    /// 建立该会话时成立的方法集合。旧会话（没有 `methods` 列）退化为主方法。
    pub fn method_names(&self) -> Vec<String> {
        match &self.methods {
            Some(m) if !m.is_empty() => m.clone(),
            _ => self.credential_kind.iter().cloned().collect(),
        }
    }

    /// 支撑该会话的本地凭证引用。旧会话退化为 `credential_ref` 单项。
    pub fn credential_ref_list(&self) -> Vec<String> {
        match &self.credential_refs {
            Some(r) => r.clone(),
            None => self.credential_ref.iter().cloned().collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub user_agent: String,
    pub ip_address: String,
    pub is_current: bool,
}
