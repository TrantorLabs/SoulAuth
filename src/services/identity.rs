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
use surrealdb::types::RecordId as Thing;
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

/// 一次认证请求解析出来的、**当前有资格继续认证**的主体。
///
/// 它是这个系统里唯一的「认证主体」。拿到它意味着三件事都已经成立：
///
/// 1. 身份根存在；
/// 2. 它的 `actor_kind` 与调用方声明的一致（Human 不能走 AIActor 的免口令通道，
///    反之亦然）；
/// 3. 它的 `status` 允许认证。
///
/// `account` 是 Human 的**扩展**，可以为 `None`（AIActor 没有账户）。它不是
/// 认证主体 —— 这正是 `user` 行长期以来越权承担的角色。
#[derive(Debug, Clone)]
pub struct AuthenticableActor {
    pub actor: ActorIdentity,
    pub account: Option<HumanAccount>,
}

impl AuthenticableActor {
    /// 对外稳定的 Authentication Subject。
    ///
    /// OIDC 的 `sub` 用它，而不是 record id，也不是 `user.id`：邮箱、用户名、
    /// 凭证轮换、经由哪个 Client 进入，都不得改变它（GA-04 §7）。
    pub fn subject_key(&self) -> &str {
        &self.actor.subject_key
    }

    /// 身份根的 record 引用。
    pub fn actor_ref(&self) -> Result<Thing> {
        self.actor
            .id
            .clone()
            .ok_or_else(|| AuthError::DatabaseError("actor_identity 没有 id".into()))
    }
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

    /// 一次事务建齐一个 Human 的**全部**落库对象。
    ///
    /// `actor_identity` + `human_account` + `user`，以及按需的口令凭证与外部绑定。
    ///
    /// # 为什么要一起建
    ///
    /// 这五张表以前是逐条写的，任何一步失败都会留下一种不会报错、只会在某天
    /// 表现为「这个账号坏了」的中间态：
    ///
    /// * 有身份根没有 `user` 行 → 登录按邮箱查 `user` 查不到，而重新注册又撞
    ///   `human_account` 的邮箱唯一索引：这个邮箱从此既登不进也注册不了；
    /// * 有账号没有凭证 → 口令永远验不过；
    /// * 社交首登建了账号没建绑定 → 下一次登录解析不到绑定，走到「同邮箱撞既有
    ///   账号」那一支被拒，于是这个账号再也登不进来。
    ///
    /// 返回身份根与 `user` 行的 key。记录本身在事务外按已知 key 重读 ——
    /// 事务的结果槽位包含 `BEGIN`/`COMMIT`，按下标取值换一条语句就会错位。
    #[allow(clippy::too_many_arguments)]
    pub async fn create_human_aggregate(
        &self,
        email: &str,
        username: &str,
        username_normalized: &str,
        email_verified: bool,
        verification_token_hash: Option<String>,
        verification_token_expires_at: Option<i64>,
        password_hash: Option<String>,
        binding: Option<(String, String)>,
    ) -> Result<(String, String)> {
        let now = chrono::Utc::now().timestamp();
        let actor_key = Uuid::new_v4().to_string();
        let user_key = Uuid::new_v4().to_string();

        let mut sql = String::from(
            "CREATE type::record('actor_identity', $actor_key) CONTENT { \
                 subject_key: $subject_key, \
                 actor_kind: 'human', \
                 identity_source: 'local', \
                 status: 'active', \
                 created_at: $now, \
                 updated_at: $now \
             }; \
             CREATE type::record('human_account', $account_key) CONTENT { \
                 actor_identity_id: type::record('actor_identity', $actor_key), \
                 email: $email, \
                 username: $username, \
                 username_normalized: $username_normalized, \
                 email_verified: $email_verified, \
                 created_at: $now, \
                 updated_at: $now \
             }; \
             CREATE type::record('user', $user_key) CONTENT { \
                 subject_id: type::record('actor_identity', $actor_key), \
                 email: $email, \
                 username: $username, \
                 username_normalized: $username_normalized, \
                 verified: $email_verified, \
                 verification_token_hash: $verification_token_hash ?? NONE, \
                 verification_token_expires_at: $verification_token_expires_at ?? NONE, \
                 account_status: 'Active', \
                 membership_level: 'FREE', \
                 created_at: $now, \
                 updated_at: $now \
             };",
        );
        if password_hash.is_some() {
            sql.push_str(
                " CREATE type::record('credential', $credential_key) CONTENT { \
                     actor_identity_id: type::record('actor_identity', $actor_key), \
                     kind: 'password', \
                     secret_hash: $password_hash, \
                     status: 'active', \
                     created_at: $now \
                 };",
            );
        }
        if binding.is_some() {
            sql.push_str(
                " CREATE type::record('identity_binding', $binding_key) CONTENT { \
                     actor_identity_id: type::record('actor_identity', $actor_key), \
                     provider: $provider, \
                     provider_subject: $provider_subject, \
                     binding_type: 'federated', \
                     verification_state: 'verified', \
                     bound_at: $now \
                 };",
            );
        }

        let (provider, provider_subject) = match binding {
            Some((p, s)) => (Some(p), Some(s)),
            None => (None, None),
        };

        self.db
            .transaction(
                "identity_create_human_aggregate",
                &sql,
                serde_json::json!({
                    "actor_key": actor_key,
                    "account_key": Uuid::new_v4().to_string(),
                    "user_key": user_key,
                    "credential_key": Uuid::new_v4().to_string(),
                    "binding_key": Uuid::new_v4().to_string(),
                    "subject_key": Self::new_subject_key(),
                    "email": email,
                    "username": username,
                    "username_normalized": username_normalized,
                    "email_verified": email_verified,
                    "verification_token_hash": verification_token_hash,
                    "verification_token_expires_at": verification_token_expires_at,
                    "password_hash": password_hash,
                    "provider": provider,
                    "provider_subject": provider_subject,
                    "now": now,
                }),
            )
            .await?;

        Ok((actor_key, user_key))
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

    /// 为一个**已有**身份建立外部绑定 —— 显式 Account Linking 的落库动作。
    ///
    /// 登录路径**不**调用它：首次联合登录在 [`Self::create_human_aggregate`] 的同一
    /// 事务里建绑定，而邮箱撞上既有账户时登录直接拒绝。这里服务的是另一条流程：
    /// 主体已认证、新 IdP 也已认证、用户明确确认之后，才把两者绑起来。那条流程
    /// 的 HTTP 入口尚未提供；提供时必须满足这三个前置条件，缺一不可 —— 否则它
    /// 就退化成登录路径上被删掉的那个「同邮箱自动挂接」。
    #[allow(dead_code)] // 显式 Account Linking 的落库动作；HTTP 入口尚未提供，见上方说明。
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
    /// **唯一的认证闸门。**
    ///
    /// 密码登录、MFA 第二步、OAuth 回调、Bearer 提取器、OIDC authorize /
    /// refresh / userinfo —— 每一条认证路径都必须经过这里，而不是各自去查
    /// `user.account_status`。
    ///
    /// 为什么必须收到一处：在这之前，Human 的多数路径只看 `user.account_status`，
    /// 于是直接暂停一个 Human 的 `actor_identity` 对认证**没有任何效果** ——
    /// 作为「规范身份边界」的身份根并不拥有最终裁决权。那不是某一条路径写漏了，
    /// 而是判据散在六处的必然结果。
    ///
    /// 一律 fail closed：身份根不存在、种类不符、状态不允许，全都拒绝，
    /// 不退回旧 `user` 语义。
    pub async fn authenticable_actor(
        &self,
        actor_key: &str,
        expect: ActorKind,
    ) -> Result<AuthenticableActor> {
        let key = crate::utils::record_id::normalize_actor_id(actor_key);
        let Some(actor) = self.find_actor_by_id(&key).await? else {
            // 身份根缺失不是「找不到用户」，是身份关系断裂。对外不区分，
            // 对内必须拒绝。
            return Err(AuthError::Unauthorized(
                "Identity root is missing or unresolvable".to_string(),
            ));
        };

        if actor.actor_kind_parsed() != Some(expect) {
            return Err(AuthError::Forbidden(format!(
                "This credential path is only for {} subjects",
                expect.as_str()
            )));
        }

        match actor.status_parsed() {
            ActorStatus::Active => {}
            ActorStatus::Suspended => return Err(AuthError::AccountSuspended),
            // Retired 不可恢复，也不得复用 subject。
            ActorStatus::Retired => return Err(AuthError::AccountDeleted),
        }

        // Human 的账户扩展。AIActor 没有账户，缺失是正常的。
        let account = if expect == ActorKind::Human {
            let actor_ref = actor
                .id
                .clone()
                .ok_or_else(|| AuthError::DatabaseError("actor_identity 没有 id".into()))?;
            let rows: Vec<HumanAccount> = self
                .db
                .query_take0_vec(
                    "identity_account_of_actor",
                    "SELECT * FROM human_account \
                     WHERE actor_identity_id = type::record('actor_identity', $key) LIMIT 1",
                    serde_json::json!({
                        "key": crate::utils::record_id::record_id_key_to_string(&actor_ref),
                    }),
                )
                .await?;
            let account = rows.into_iter().next();
            if account.is_none() {
                // Human 身份根没有账户扩展，说明创建过程中断过。fail closed：
                // 这种半成品不该能登录。
                return Err(AuthError::Unauthorized(
                    "Identity is incomplete and cannot authenticate".to_string(),
                ));
            }
            account
        } else {
            None
        };

        Ok(AuthenticableActor { actor, account })
    }

    /// 过渡期入口：从 `user` 行解析到身份根，再走同一个闸门。
    ///
    /// `user` 行仍是很多外键的载体，所以旧路径手上只有 user id。这里**不**让
    /// 它绕过闸门，只是把它翻译成身份根。
    pub async fn authenticable_actor_of_user(&self, user_id: &str) -> Result<AuthenticableActor> {
        let actor_ref = self.db.actor_ref_of_user(user_id).await?;
        let key = crate::utils::record_id::record_id_key_to_string(&actor_ref);
        self.authenticable_actor(&key, ActorKind::Human).await
    }

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
