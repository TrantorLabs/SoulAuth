//! Actor Identity 的创建与解析。
//!
//! # 为什么单独一层
//!
//! V1 里「建一个主体」这件事散在 `AuthService` 内部：注册时顺手 `create_subject`，
//! 社交登录时 `ensure_user_subject`，两处各写各的。身份根从 `user` 换成
//! `actor_identity` 之后这样行不通 —— 建一个身份现在要同时落 `actor_identity`
//! 与（对人类而言）`human_account` 两条记录，还要保证 `subject_key` 唯一。
//!
//! 收口到这里之后，「谁能创建身份」有唯一答案，Stage 2 的写路径切换也只需要
//! 改这一处的调用方，而不是每个流程各改一遍。
//!
//! # 这一层不做什么
//!
//! 不碰 Credential（Stage 2 后半段收口），不签发会话，不做鉴权判断。
//! 它只回答「这个主体存不存在、是谁」。
//!
//! # 为什么没有 `find_by_subject`
//!
//! 它要等 OIDC `sub` 从 `user` 行键切到 `subject_key` —— 那是一次会让全部
//! 在途令牌失效的迁移，需要单独规划。现在写出来它只会以 dead code 的形式
//! 躺在这里，而本仓库靠 clippy 顶住 dead code：一旦为它开 `allow`，
//! 这道闸门对整个模块就失效了。
//!
//! `create_ai_actor` 已经有了 —— AIActor 认证路径落地时补上的。

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::{
    error::{AuthError, Result},
    models::{
        actor_identity::{ActorIdentity, ActorKind, ActorStatus},
        human_account::HumanAccount,
        identity_binding::IdentityBinding,
    },
    services::database::Database,
};

/// 一个人类身份的两条记录。
///
/// 它们必须一起存在：`actor_identity` 回答「谁」，`human_account` 回答
/// 「这个人怎样管理自己的登录账户」。分开返回而不是合成一个结构体，是为了让
/// 调用方在类型上就看见这是两个对象 —— 合成一个很快就会退化回 V1 的 `User`。
#[derive(Debug, Clone)]
pub struct HumanIdentity {
    pub actor: ActorIdentity,
    pub account: HumanAccount,
}

#[derive(Clone)]
pub struct IdentityService {
    db: Arc<Database>,
}

impl IdentityService {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// 生成一个新的 stable subject。
    ///
    /// 用 UUID 而不是从 email、username 或任何账户属性派生：那些都会变，
    /// 而 subject 不能变（GA-04 §7）。也不复用 record id —— 两者是不同的
    /// 命名空间，物理取同值是实现选择，不是语义等同（GA-04 §5）。
    fn new_subject_key() -> String {
        Uuid::new_v4().to_string()
    }

    /// 建立一个人类身份：`actor_identity` + `human_account`。
    ///
    /// 邮箱与用户名的唯一性由数据库索引保证，冲突会以唯一约束错误返回，
    /// 由调用方翻译成 409 —— 这里不预先查一次再插入，那是 TOCTOU。
    pub async fn create_human(
        &self,
        email: &str,
        username: &str,
        username_normalized: &str,
    ) -> Result<HumanIdentity> {
        let actor = ActorIdentity::new_local(Self::new_subject_key(), ActorKind::Human);
        let actor: ActorIdentity = self.db.create_record("actor_identity", &actor).await?;

        let actor_id = actor
            .id
            .clone()
            .ok_or_else(|| AuthError::DatabaseError("actor_identity 落库后没有 id".into()))?;

        let account = HumanAccount::new(actor_id, email, username, username_normalized);
        let account: HumanAccount = self.db.create_record("human_account", &account).await?;

        Ok(HumanIdentity { actor, account })
    }

    /// 按邮箱找人类身份。
    ///
    /// 邮箱属于 `human_account`，所以要两跳：先账户，再身份根。这个多出来的
    /// 一跳正是拆分的代价，也正是拆分的意义 —— 邮箱变了，身份根不动。
    pub async fn find_human_by_email(&self, email: &str) -> Result<Option<HumanIdentity>> {
        let Some(account) = self
            .db
            .find_record_by_field::<HumanAccount>("human_account", "email", email)
            .await?
        else {
            return Ok(None);
        };

        let actor_address = format!(
            "actor_identity:{}",
            crate::utils::record_id::record_id_key_to_string(&account.actor_identity_id)
        );
        let Some(actor) = self
            .db
            .find_record_by_field::<ActorIdentity>("actor_identity", "id", &actor_address)
            .await?
        else {
            // 账户存在而身份根不存在，说明有人绕过这一层直接写了库，
            // 或者删除路径没有成对处理。这是数据完整性问题，不是「找不到」。
            return Err(AuthError::DatabaseError(format!(
                "human_account {} 指向了不存在的 actor_identity",
                account.email
            )));
        };

        Ok(Some(HumanIdentity { actor, account }))
    }

    /// 通过外部身份绑定解析到本地身份。
    ///
    /// `(provider, provider_subject)` 必须成对匹配。只按 subject 查是一个真实的
    /// 跨 provider 接管：数字 id 为 `4001` 的 GitHub 账号会匹配上 sub 为字符串
    /// `"4001"` 的 Google 用户。
    pub async fn resolve_binding(
        &self,
        provider: &str,
        provider_subject: &str,
    ) -> Result<Option<ActorIdentity>> {
        let bindings: Vec<IdentityBinding> = self
            .db
            .query_take0_vec(
                "identity_resolve_binding",
                "SELECT * FROM identity_binding \
                 WHERE provider = $provider AND provider_subject = $provider_subject LIMIT 1",
                serde_json::json!({
                    "provider": provider,
                    "provider_subject": provider_subject,
                }),
            )
            .await?;

        let Some(binding) = bindings.into_iter().next() else {
            return Ok(None);
        };

        // 已撤销或未验证的绑定不解析。它存在只是为了保留历史，
        // 不代表现在还能拿它换身份。
        if !binding.is_active() {
            return Ok(None);
        }

        let actor_address = format!(
            "actor_identity:{}",
            crate::utils::record_id::record_id_key_to_string(&binding.actor_identity_id)
        );
        self.db
            .find_record_by_field::<ActorIdentity>("actor_identity", "id", &actor_address)
            .await
    }

    /// 为一个已有身份建立外部绑定。
    pub async fn bind_external(
        &self,
        actor: &ActorIdentity,
        provider: &str,
        provider_subject: &str,
    ) -> Result<IdentityBinding> {
        let actor_id = actor
            .id
            .clone()
            .ok_or_else(|| AuthError::DatabaseError("actor_identity 没有 id".into()))?;
        let binding = IdentityBinding::new_federated(actor_id, provider, provider_subject);
        self.db.create_record("identity_binding", &binding).await
    }

    /// 建立一个 AIActor 身份。
    ///
    /// 与 [`Self::create_human`] 的差别就是这个方法的全部意义：**只落一条记录**。
    /// 没有 `human_account`，因为一个 Agent 不需要邮箱、用户名或口令
    /// （GA-01 §4 / `human_account` 模块头）。在此之前想给 Agent 一个身份，
    /// 唯一办法是去注册一个假的人类账户 —— 那会让审计里的「谁做的」
    /// 从第一天起就是错的。
    pub async fn create_ai_actor(&self) -> Result<ActorIdentity> {
        let actor = ActorIdentity::new_local(Self::new_subject_key(), ActorKind::AiActor);
        self.db.create_record("actor_identity", &actor).await
    }

    /// 按 record key 取身份根。
    pub async fn find_actor_by_id(&self, actor_key: &str) -> Result<Option<ActorIdentity>> {
        let address = format!("actor_identity:{actor_key}");
        self.db
            .find_record_by_field::<ActorIdentity>("actor_identity", "id", &address)
            .await
    }

    /// 列出全部 AIActor 身份。
    pub async fn list_ai_actors(&self) -> Result<Vec<ActorIdentity>> {
        self.db
            .query_take0_vec(
                "identity_list_ai_actors",
                "SELECT * FROM actor_identity WHERE actor_kind = $kind ORDER BY created_at DESC",
                serde_json::json!({ "kind": ActorKind::AiActor.as_str() }),
            )
            .await
    }

    /// 修改身份状态。
    ///
    /// 只影响**未来**的认证资格。历史的 Authentication、Audit 与 Attribution
    /// 不因为现在被暂停就变得不曾发生（GA-06 §13）。
    ///
    /// Retired 之后 `subject_key` 不得被重新分配 —— 这里不删记录正是为此：
    /// 记录留着，唯一索引就继续挡住复用。
    pub async fn set_status(&self, actor: &ActorIdentity, status: ActorStatus) -> Result<()> {
        let id = actor
            .id
            .as_ref()
            .ok_or_else(|| AuthError::DatabaseError("actor_identity 没有 id".into()))?;
        self.db
            .raw_query(
                "identity_set_status",
                "UPDATE type::record('actor_identity', $key) \
                 SET status = $status, updated_at = $now",
                serde_json::json!({
                    "key": crate::utils::record_id::record_id_key_to_string(id),
                    "status": status.as_str(),
                    "now": Utc::now().timestamp(),
                }),
            )
            .await?;
        Ok(())
    }
}
