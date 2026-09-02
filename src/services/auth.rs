use crate::{
    config::Config,
    error::{AuthError, Result},
    models::{
        identity_provider::{IdentityProvider, OAuthUserInfo},
        mfa::MfaMethod,
        password_reset::PasswordResetToken,
        session::{Session, SessionInfo},
        subject::SubjectType,
        user::{AuthResponse, CreateUserRequest, User},
    },
    services::{
        auth_cache::AuthCache, database::Database, email::EmailService, identity::IdentityService,
        mfa::MfaService, oauth::OAuthService,
    },
    utils::validation::{validate_email, validate_password, validate_username},
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use surrealdb::types::RecordId as Thing;
use tracing::{debug, error, info};
use uuid::Uuid;

/// 邮箱验证令牌有效期。
const VERIFICATION_TOKEN_TTL_HOURS: i64 = 24;
/// 会话有效期的兜底值（秒），仅在 `JWT_EXPIRATION` 不合法时使用。
///
/// 这里以前是写死的 `SESSION_TTL_HOURS = 24`，而 `Config::jwt_expiration`
/// 解析完之后**从来没有人读过** —— DEPLOYMENT.md 却把 `JWT_EXPIRATION`
/// 当成可用开关写进文档。后果是反向的：运维把它设成 900 以为拿到 15 分钟令牌，
/// 实际拿到的是 24 小时，而且没有任何反馈能让他发现。
const DEFAULT_SESSION_TTL_SECONDS: i64 = 86_400;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
    iat: i64,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    subject_type: Option<SubjectType>,
}

/// 请求上下文：真实来源 IP 与 User-Agent。
///
/// 以前这两个值在会话与登录记录里被硬编码成 `"0.0.0.0"` / `"Unknown"`，
/// 导致会话列表和审计报表里的数据全是假的。
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub ip_address: String,
    pub user_agent: String,
}

impl RequestContext {
    pub fn new(ip_address: String, user_agent: String) -> Self {
        Self {
            ip_address,
            user_agent,
        }
    }
}

/// 一次成功签发的会话。
///
/// `session_key` 是 `session` 表记录的主键，用来把浏览器会话 cookie 绑到具体
/// 会话行上 —— 否则那个 cookie 是个自包含 JWT，登出之后照样能在
/// `/api/oidc/authorize` 换到授权码。
pub struct IssuedSession {
    pub response: AuthResponse,
    pub session_key: String,
}

/// 登录结果：直接放行，或要求补一步 MFA。
pub enum LoginOutcome {
    Authenticated(Box<IssuedSession>),
    MfaRequired {
        temp_token: String,
        method: MfaMethod,
    },
}

pub struct AuthService {
    db: Arc<Database>,
    config: Config,
    email_service: EmailService,
    oauth_service: OAuthService,
    mfa_service: MfaService,
    /// 用于在会话被吊销时立刻同步清掉鉴权缓存。
    auth_cache: Arc<AuthCache>,
    /// Actor Identity 的创建与解析。
    ///
    /// 身份根从 `user` 换成 `actor_identity` 之后，「建一个主体」要同时落
    /// 两条记录并保证 subject_key 唯一 —— 收口在这里，而不是让每个流程
    /// 各写一遍。
    identity: IdentityService,
}

fn new_thing(table: &str) -> Thing {
    Thing::new(table, Uuid::new_v4().to_string())
}

fn record_key(thing: &Thing) -> String {
    crate::utils::record_id::record_id_key_to_string(thing)
}

fn record_address(thing: &Thing) -> String {
    format!("{}:{}", thing.table, record_key(thing))
}

/// 把唯一索引冲突翻译成对应的业务错误。
///
/// 注册走的是"先查重、再插入"，两步之间有窗口：并发注册同一邮箱时，
/// 两个请求都通过了查重，插入阶段由数据库的唯一索引挡下后来那个。
/// 数据完整性没问题（实测 8 个并发只建出 1 个账号），但错误会以
/// 裸 `DatabaseError` 冒出来 —— 调用方收到 **500 而不是 409**，
/// 看起来像服务器故障，于是重试，再撞一次。
///
/// 索引名来自 `schema.sql`：`email_idx` / `username_idx`。
fn translate_unique_violation(error: AuthError) -> AuthError {
    let AuthError::DatabaseError(message) = &error else {
        return error;
    };

    // SurrealDB 的报错形如：
    //   Database index `email_idx` already contains 'a@b.com', with record `user:...`
    if !message.contains("already contains") {
        return error;
    }
    if message.contains("email_idx") {
        return AuthError::EmailExists;
    }
    if message.contains("username_idx") {
        return AuthError::UsernameExists;
    }

    error
}

impl AuthService {
    pub fn new(db: Arc<Database>, config: Config, auth_cache: Arc<AuthCache>) -> Result<Self> {
        // 在启动阶段就把哑哈希算出来。留给第一个请求懒初始化的话，进程起来后
        // 第一次"邮箱不存在"的登录要额外背一次 Argon2 哈希（实测约 350ms），
        // 恰好是这个哑哈希本该消除的那种耗时差异 —— 方向相反、只发生一次，
        // 但没必要留着。这里多花的启动时间发生在监听端口之前。
        let _ = dummy_password_hash();

        let email_service = EmailService::new(config.clone());
        let oauth_service = OAuthService::new(config.clone())?;
        let mfa_service = MfaService::new(db.clone(), config.clone())?;
        let identity = IdentityService::new(db.clone());
        Ok(Self {
            db,
            config,
            email_service,
            oauth_service,
            mfa_service,
            auth_cache,
            identity,
        })
    }

    pub fn mfa(&self) -> &MfaService {
        &self.mfa_service
    }

    /// 确保这个 user 行挂着身份根。
    ///
    /// Stage 2 之前它写的是 V1 的 `subject` 表；现在改建 `actor_identity`，
    /// 因为 `user.subject_id` 是 Stage 3 把外键迁到身份根时唯一可追的线 ——
    /// 让它继续指向 `subject` 等于在制造下一批要迁移的数据。
    ///
    /// 老账号第一次登录时在这里补上。
    async fn ensure_user_subject(&self, user: User) -> Result<User> {
        if user.subject_id.is_some() {
            return Ok(user);
        }

        let human = self
            .identity
            .create_human(&user.email, &user.username, &user.username_normalized)
            .await?;

        let mut updated_user = user.clone();
        updated_user.subject_id = human.actor.id.clone();
        updated_user.updated_at = Utc::now().timestamp();

        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?;
        self.db
            .update_record("user", &record_address(user_thing), &updated_user)
            .await
    }

    fn normalize_username(username: &str) -> String {
        username.trim().to_ascii_lowercase()
    }

    async fn ensure_username_available(&self, username: &str) -> Result<String> {
        let normalized = Self::normalize_username(username);
        if normalized.is_empty() {
            return Err(AuthError::ValidationError(
                "Username is required".to_string(),
            ));
        }

        if self
            .db
            .find_record_by_field::<User>("user", "username_normalized", &normalized)
            .await?
            .is_some()
        {
            return Err(AuthError::UsernameExists);
        }

        Ok(normalized)
    }

    async fn generate_unique_username(&self, base: &str) -> Result<(String, String)> {
        let fallback = "user";
        let seed = base.trim();
        let seed = if seed.is_empty() { fallback } else { seed };
        let seed = seed
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
            .collect::<String>();
        let mut seed = if seed.is_empty() {
            fallback.to_string()
        } else {
            seed
        };
        // 用户名有最短长度要求，OAuth 昵称过短时补齐。
        while seed.len() < 3 {
            seed.push('0');
        }

        for attempt in 0..1000 {
            let candidate = if attempt == 0 {
                seed.clone()
            } else {
                format!("{seed}{attempt}")
            };
            let normalized = Self::normalize_username(&candidate);
            if self
                .db
                .find_record_by_field::<User>("user", "username_normalized", &normalized)
                .await?
                .is_none()
            {
                return Ok((candidate, normalized));
            }
        }

        Err(AuthError::ServerError(
            "Failed to generate a unique username".to_string(),
        ))
    }

    pub fn get_google_auth_url_with_state(&self, state: &str) -> Result<String> {
        self.oauth_service.get_google_auth_url_with_state(state)
    }

    pub fn get_github_auth_url_with_state(&self, state: &str) -> Result<String> {
        self.oauth_service.get_github_auth_url_with_state(state)
    }

    pub async fn handle_google_callback(
        &self,
        code: String,
        ctx: &RequestContext,
    ) -> Result<IssuedSession> {
        debug!("Starting Google OAuth callback process");

        let user_info = self.oauth_service.handle_google_callback(code).await?;
        let user = self.find_or_create_oauth_user(user_info).await?;
        let user = self.touch_last_login(user, ctx).await?;

        self.create_session_with_metadata(user, ctx).await
    }

    pub async fn handle_github_callback(
        &self,
        code: String,
        ctx: &RequestContext,
    ) -> Result<IssuedSession> {
        let user_info = self.oauth_service.handle_github_callback(code).await?;
        let user = self.find_or_create_oauth_user(user_info).await?;
        let user = self.touch_last_login(user, ctx).await?;

        self.create_session_with_metadata(user, ctx).await
    }

    /// 补上缺失的 identity_binding。
    ///
    /// 过渡期专用：Stage 1 之前建立的账号只有 V1 的 `identity_provider` 关联，
    /// 没有新的 `identity_binding`。每次这类账号登录时顺手补一条，
    /// Stage 3 迁移时就不必再扫一遍历史数据。
    ///
    /// 失败只记日志：这是回填，不是登录的前置条件 —— 让它挡住登录，
    /// 等于用一个数据整理动作换来一次拒绝服务。
    async fn backfill_binding(&self, user: &User, provider: &str, provider_subject: &str) {
        match self
            .identity
            .resolve_binding(provider, provider_subject)
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                let Some(actor_id) = user.subject_id.clone() else {
                    return;
                };
                let actor_address = format!("actor_identity:{}", record_key(&actor_id));
                match self
                    .db
                    .find_record_by_field::<crate::models::actor_identity::ActorIdentity>(
                        "actor_identity",
                        "id",
                        &actor_address,
                    )
                    .await
                {
                    Ok(Some(actor)) => {
                        if let Err(e) = self
                            .identity
                            .bind_external(&actor, provider, provider_subject)
                            .await
                        {
                            error!("Failed to backfill identity binding: {e:?}");
                        }
                    }
                    // subject_id 指向 V1 的 subject 表（Stage 1 之前的账号），
                    // 或者干脆没有 —— 这两种都留给 Stage 3 的迁移处理。
                    Ok(None) => {}
                    Err(e) => error!("Failed to load actor for binding backfill: {e:?}"),
                }
            }
            Err(e) => error!("Failed to check existing binding: {e:?}"),
        }
    }

    async fn find_or_create_oauth_user(&self, user_info: OAuthUserInfo) -> Result<User> {
        debug!(
            "Starting find_or_create_oauth_user for provider: {}",
            user_info.provider
        );

        // 下面三条分支都要用到这两个值，而 V1 的 IdentityProvider 构造会把
        // 它们 move 走，所以先各留一份。
        let provider = user_info.provider.clone();
        let provider_subject = user_info.provider_user_id.clone();

        // 首先通过 identity_provider 查找用户。
        //
        // **必须 (provider, provider_user_id) 两列一起查**，与 schema 上的唯一索引
        // 对齐。以前只按 provider_user_id 单列查并取第一条 —— 身份的定义在代码里
        // 是"这个 id"，在 schema 里却是"哪一家的这个 id"，两者不一致。
        //
        // 后果是跨 provider 顶号，已实测复现：给 Google 侧一个 sub 为 "4001" 的账号，
        // 再用 id 为 4001 的 GitHub 账号登录，命中的是那条 google 记录，于是 GitHub
        // 用户直接登进了 Google 用户的账号 —— 不建新号、不建新关联、HTTP 303 成功，
        // 全程没有任何一处报错。今天挡住它的只是"Google 的 sub 是 21 位、GitHub 的
        // id 是 8 位"这个恰好，而那是 provider 的 id 空间分配，不归我们管：
        // 代码里已经支持 GITHUB_OAUTH_BASE_URL 指向自建 GHE（id 从 1 重新计数）。
        let identities: Vec<IdentityProvider> = self
            .db
            .query_take0_vec(
                "find_identity_by_provider_and_subject",
                "SELECT * FROM identity_provider \
                 WHERE provider = $provider AND provider_user_id = $provider_user_id LIMIT 1",
                serde_json::json!({
                    "provider": &user_info.provider,
                    "provider_user_id": &user_info.provider_user_id,
                }),
            )
            .await?;

        if let Some(identity) = identities.into_iter().next() {
            // `identity.user_id` 自 Stage 3 起是**身份根**引用，不是 user 行 id。
            // 按 `user.id` 查必然找不到 —— 第二次社交登录于是报 UserNotFound
            // 并返回 404，看起来像「账号丢了」，实际是查错了字段。
            let users: Vec<User> = self
                .db
                .query_take0_vec(
                    "find_user_by_actor_ref",
                    "SELECT * FROM user WHERE subject_id = type::record('actor_identity', $key) \
                     LIMIT 1",
                    serde_json::json!({ "key": record_key(&identity.user_id) }),
                )
                .await?;
            let user = users.into_iter().next().ok_or(AuthError::UserNotFound)?;

            // 过渡期回填：V1 的 identity_provider 已经有这条关联，但新的
            // identity_binding 可能还没有（账号建于 Stage 1 之前）。补上，
            // 让 Stage 3 迁移时不必再扫一遍历史数据。
            self.backfill_binding(&user, &provider, &provider_subject)
                .await;

            return self.ensure_user_subject(user).await;
        }

        let email = validate_email(&user_info.email)?;

        // 邮箱已存在则把该身份源挂到既有账号上
        if let Some(existing_user) = self
            .db
            .find_record_by_field::<User>("user", "email", &email)
            .await?
        {
            let now_ts = Utc::now().timestamp();
            let identity = IdentityProvider {
                id: new_thing("identity_provider"),
                provider: user_info.provider,
                provider_user_id: user_info.provider_user_id,
                // 外键指身份根（Stage 3）。
                user_id: existing_user
                    .subject_id
                    .clone()
                    .ok_or(AuthError::UserNotFound)?,
                created_at: now_ts,
                updated_at: now_ts,
            };
            self.db
                .create_record("identity_provider", &identity)
                .await?;
            self.backfill_binding(&existing_user, &provider, &provider_subject)
                .await;
            return self.ensure_user_subject(existing_user).await;
        }

        // 创建新用户
        let now = Utc::now();
        let id = new_thing("user");
        let (username, username_normalized) = self
            .generate_unique_username(email.split('@').next().unwrap_or("user"))
            .await?;

        // 身份根先建，并立刻绑定外部身份 —— 社交登录的主体从第一刻起就有
        // 完整的 identity + binding，不留待日后回填。
        let human = self
            .identity
            .create_human(&email, &username, &username_normalized)
            .await?;
        if let Err(e) = self
            .identity
            .bind_external(&human.actor, &provider, &provider_subject)
            .await
        {
            error!("Failed to create identity binding for {provider}: {e:?}");
        }

        let user = User {
            id: Some(id.clone()),
            subject_id: human.actor.id.clone(),
            email,
            username,
            username_normalized,
            password_hash: None, // OAuth 用户没有密码
            created_at: now.timestamp(),
            updated_at: now.timestamp(),
            is_email_verified: true, // OAuth 邮箱已验证
            verification_token_hash: None,
            verification_token_expires_at: None,
            account_status: crate::models::user::AccountStatus::Active.to_string(),
            membership_level: "FREE".to_string(),
            membership_expiry: None,
            last_login_at: None,
            last_login_ip: None,
        };

        let created_user = self.db.create_record("user", &user).await?;

        let now_ts = Utc::now().timestamp();
        let identity = IdentityProvider {
            id: new_thing("identity_provider"),
            provider: user_info.provider,
            provider_user_id: user_info.provider_user_id,
            // 外键指身份根（Stage 3）。这条记录与上面刚建的 identity_binding
            // 表达同一件事 —— V1 的 identity_provider 会在 Stage 4 一并删掉。
            user_id: human.actor.id.clone().ok_or(AuthError::UserNotFound)?,
            created_at: now_ts,
            updated_at: now_ts,
        };
        self.db
            .create_record("identity_provider", &identity)
            .await?;

        Ok(created_user)
    }

    pub async fn register(
        &self,
        req: CreateUserRequest,
        ctx: &RequestContext,
    ) -> Result<(AuthResponse, Option<String>)> {
        let email = validate_email(&req.email)?;
        validate_password(&req.password, self.config.password_min_length)?;

        let username = validate_username(
            req.username
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| AuthError::ValidationError("Username is required".to_string()))?,
        )?;

        if self
            .db
            .find_record_by_field::<User>("user", "email", &email)
            .await?
            .is_some()
        {
            return Err(AuthError::EmailExists);
        }

        let username_normalized = self.ensure_username_available(&username).await?;
        let hashed_password = hash_password_blocking(req.password.clone()).await?;

        let now = Utc::now();
        let (verification_token, verification_expires_at) =
            if self.config.email_verification_enabled {
                (
                    Some(Uuid::new_v4().to_string()),
                    Some((now + Duration::hours(VERIFICATION_TOKEN_TTL_HOURS)).timestamp()),
                )
            } else {
                (None, None)
            };

        // 身份根：先建 actor_identity + human_account，再建 V1 的 user 行。
        //
        // Stage 2 是过渡期，两套并存：新表已经是权威身份根，`user` 仍承载
        // password 与各处外键（Stage 3 迁完外键、Stage 4 删表）。
        //
        // 顺序是刻意的 —— 先建新的。反过来的话，新表因唯一索引冲突失败时
        // 会留下一个没有身份根的 user 行，而那正是 Stage 3 要迁移的东西。
        let human = self
            .identity
            .create_human(&email, &username, &username_normalized)
            .await
            .map_err(translate_unique_violation)?;

        let user = User {
            id: Some(new_thing("user")),
            // V1 的 subject 表已被 actor_identity.actor_kind 取代。这里改指
            // 新身份根的 id，让两套记录之间有一条可追的线 —— Stage 3 迁移
            // 外键时要靠它把 user 行对应回 actor。
            subject_id: human.actor.id.clone(),
            email: email.clone(),
            username,
            username_normalized,
            password_hash: Some(hashed_password),
            created_at: now.timestamp(),
            updated_at: now.timestamp(),
            is_email_verified: !self.config.email_verification_enabled,
            verification_token_hash: verification_token
                .as_deref()
                .map(crate::utils::crypto::hash_bearer),
            verification_token_expires_at: verification_expires_at,
            account_status: crate::models::user::AccountStatus::Active.to_string(),
            membership_level: "FREE".to_string(),
            membership_expiry: None,
            last_login_at: None,
            last_login_ip: None,
        };

        let created_user = self
            .db
            .create_record("user", &user)
            .await
            .map_err(translate_unique_violation)?;

        if let Some(token) = verification_token {
            // 用户记录已经提交了，此时再抛错只会让调用方拿到 500、重试又撞 409，
            // 账号就永远卡在“已创建但没收到验证信”。发信失败只记日志。
            if let Err(e) = self
                .email_service
                .send_verification_email(&email, &token)
                .await
            {
                error!("Failed to send verification email to '{email}': {e}");
            }

            return Ok((
                AuthResponse {
                    token: String::new(),
                    user: created_user.into(),
                },
                None,
            ));
        }

        let created_user = self.touch_last_login(created_user, ctx).await?;
        let issued = self.create_session_with_metadata(created_user, ctx).await?;
        Ok((issued.response, Some(issued.session_key)))
    }

    pub async fn login(
        &self,
        email: String,
        password: String,
        ctx: &RequestContext,
    ) -> Result<LoginOutcome> {
        let email = validate_email(&email).map_err(|_| AuthError::InvalidCredentials)?;

        let user = match self
            .db
            .find_record_by_field::<User>("user", "email", &email)
            .await?
        {
            Some(user) => user,
            None => {
                // 邮箱没注册过也要把 Argon2 的时间花掉，否则响应快得多，
                // 等于告诉调用方"这个邮箱不存在"。
                spend_password_verification_time().await;
                return Err(AuthError::InvalidCredentials);
            }
        };

        // 验证密码
        let password_hash = match user.password_hash.clone() {
            Some(hash) => hash,
            None => {
                // 纯 OAuth 账号没有密码哈希，同理不能提前返回。
                spend_password_verification_time().await;
                return Err(AuthError::InvalidCredentials);
            }
        };

        verify_password_blocking(password_hash, password).await?;

        // 检查邮箱验证状态
        if self.config.email_verification_enabled && !user.is_email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        // 检查账户状态。
        //
        // 这里查两处，因为 Stage 2 是过渡期：`user.account_status` 是 V1 的，
        // `actor_identity.status` 是新身份根的。Stage 3 迁完外键之后只留后者。
        //
        // 两者都要过 —— 任一为不可用即拒。过渡期宁可多拒，不能少拒。
        Self::ensure_account_usable(&user)?;

        if let Some(human) = self.identity.find_human_by_email(&email).await? {
            if !human.actor.can_authenticate() {
                // 身份根说不能认证，就不能认证。它只影响**未来**的资格，
                // 不改写这个账号过去的认证事实。
                return Err(AuthError::AccountSuspended);
            }
            // 邮箱验证状态同样两处并存：V1 在 `user.is_email_verified`，
            // 新的在 `human_account.email_verified`。任一未验证即拒 ——
            // 过渡期宁可多拒。
            if self.config.email_verification_enabled && !human.account.email_verified {
                return Err(AuthError::EmailNotVerified);
            }
        }

        let user_id = record_key(user.id.as_ref().ok_or(AuthError::UserNotFound)?);

        // 启用了 MFA 的账号在这里止步，只发一个 5 分钟有效的挑战令牌。
        if let Some(method) = self.mfa_service.enabled_method(&user_id).await? {
            let temp_token = crate::utils::jwt::create_mfa_challenge_token(
                &user_id,
                &user.email,
                &self.config.jwt_secret,
            )?;
            return Ok(LoginOutcome::MfaRequired { temp_token, method });
        }

        let user = self.touch_last_login(user, ctx).await?;
        let response = self.create_session_with_metadata(user, ctx).await?;
        Ok(LoginOutcome::Authenticated(Box::new(response)))
    }

    /// MFA 第二步通过之后完成登录。
    pub async fn complete_mfa_login(
        &self,
        user_id: &str,
        ctx: &RequestContext,
    ) -> Result<IssuedSession> {
        let user = self
            .db
            .find_record_by_field::<User>("user", "id", user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        Self::ensure_account_usable(&user)?;

        let user = self.touch_last_login(user, ctx).await?;
        self.create_session_with_metadata(user, ctx).await
    }

    /// 登录闸门。判定在 [`User::ensure_usable`]，与令牌闸门、密码重置、
    /// OIDC 三关口共用同一份 —— 这里以前是一份逐字副本。
    fn ensure_account_usable(user: &User) -> Result<()> {
        user.ensure_usable()
    }

    async fn touch_last_login(&self, mut user: User, ctx: &RequestContext) -> Result<User> {
        let now = Utc::now().timestamp();
        user.last_login_at = Some(now);
        user.last_login_ip = Some(ctx.ip_address.clone());
        user.updated_at = now;

        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?.clone();
        self.db
            .update_record("user", &record_address(&user_thing), &user)
            .await
    }

    /// 会话与访问令牌的有效期，由 `JWT_EXPIRATION`（秒）决定。
    ///
    /// 非正值回落到兜底值：一个 0 或负数的有效期意味着签出来的令牌当场就过期，
    /// 与其让整站登录静默失效，不如按默认值走并保持可用。
    fn session_ttl_seconds(&self) -> i64 {
        if self.config.jwt_expiration > 0 {
            self.config.jwt_expiration
        } else {
            DEFAULT_SESSION_TTL_SECONDS
        }
    }

    async fn create_session_with_metadata(
        &self,
        user: User,
        ctx: &RequestContext,
    ) -> Result<IssuedSession> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.session_ttl_seconds());

        let session_id = new_thing("session");
        let session_key = record_key(&session_id);
        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?.clone();

        let claims = Claims {
            sub: record_key(&user_thing),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            session_id: Some(session_key.clone()),
            subject_type: Some(SubjectType::Human),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthError::TokenError(e.to_string()))?;

        // 会话归属**身份根**，不是 user 行。
        //
        // `claims.sub` 仍然是 user id：那是对外的令牌契约，改它会让所有在途
        // 令牌失效，属于 Stage 3 之后的事。这里改的是存储侧的归属关系。
        let actor_ref = user.subject_id.clone().ok_or_else(|| {
            AuthError::DatabaseError(format!("user {} 没有关联的 actor_identity", user.email))
        })?;

        let session = Session {
            id: Some(session_id),
            user_id: actor_ref,
            token_hash: crate::utils::crypto::hash_bearer(&token),
            expires_at: exp.timestamp(),
            created_at: now.timestamp(),
            user_agent: ctx.user_agent.clone(),
            ip_address: ctx.ip_address.clone(),
        };

        self.db.create_record("session", &session).await?;

        Ok(IssuedSession {
            response: AuthResponse {
                token,
                user: user.into(),
            },
            session_key,
        })
    }

    pub async fn verify_email(&self, token: String, ctx: &RequestContext) -> Result<IssuedSession> {
        // 与重置令牌同样的道理：先原子消费，再做有副作用的事。
        //
        // 原先是「读 → 判 is_email_verified → 写整条 user」。顺序重放确实会被
        // 那个判定挡住，但**并发**重放不会：两个请求都读到 false，都通过，
        // 而这个函数末尾会签发会话 —— 于是一枚验证令牌换出两个会话。
        //
        // 条件更新一次完成「校验 + 清令牌 + 置已验证」，令牌置空后重放不可能
        // 再命中。过期判定也一并放进库里：`verification_token_expires_at` 是
        // number（Unix 秒），与传入的整数同类型比较，不触发 SurrealDB
        // 的按类型序比较问题。
        let now_ts = Utc::now().timestamp();
        let mut claimed = self
            .db
            .raw_query(
                "claim_verification_token",
                // 列名是 `verified`，不是 `is_email_verified` —— 后者是 Rust
                // 侧的字段名，靠 `#[surreal(rename)]` 映射过来。写裸 SQL 时
                // 必须用库里的真实列名，否则整条语句失败（伪造 token 也返回
                // 500，因为 SQL 根本没执行成功）。
                "UPDATE user SET verified = true, verification_token_hash = NONE, \
                 verification_token_expires_at = NONE, updated_at = $now \
                 WHERE verification_token_hash = $token_hash AND verified = false \
                 AND verification_token_expires_at != NONE \
                 AND verification_token_expires_at > $now \
                 RETURN VALUE id",
                // 绑定名不能叫 `token`：SurrealDB 里 `$token` 是**保留变量**，
                // 设置它会以「'token' is a protected variable and cannot be set」
                // 整条语句失败 —— 于是伪造 token 也返回 500，因为 SQL 根本没跑成。
                serde_json::json!({ "token_hash": crate::utils::crypto::hash_bearer(&token), "now": now_ts }),
            )
            .await?;
        let claimed_ids: Vec<Thing> = claimed.take(0)?;
        if claimed_ids.len() != 1 {
            // 令牌不存在、已被使用、已过期 —— 对外同一个答复。
            return Err(AuthError::InvalidToken);
        }
        let user_thing = claimed_ids.into_iter().next().expect("已断言恰好一条");

        // 抢占成功后再读回，用于建立会话。
        //
        // `find_record_by_field` 对 `field == "id"` 有专门分支：它会把
        // `table:key` 还原成 `RecordId` 再用原生 bind，绕开了「RecordId 经
        // JSON 绑定退化成字符串导致恒不匹配」那个坑。所以这里直接传地址字符串
        // 即可，不需要另造一个 by-id 辅助。
        let verified_user = self
            .db
            .find_record_by_field::<User>("user", "id", &record_address(&user_thing))
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let verified_user = self.touch_last_login(verified_user, ctx).await?;
        self.create_session_with_metadata(verified_user, ctx).await
    }

    pub async fn initialize_password(&self, user_id: &str, password: &str) -> Result<User> {
        validate_password(password, self.config.password_min_length)?;

        let mut user: User = self
            .db
            .find_record_by_field("user", "id", user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        if user.password_hash.is_some() {
            return Err(AuthError::PasswordAlreadySet);
        }

        user.password_hash = Some(hash_password_blocking(password.to_string()).await?);
        user.updated_at = Utc::now().timestamp();

        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?.clone();
        self.db
            .update_record("user", &record_address(&user_thing), &user)
            .await
    }

    pub async fn request_password_reset(&self, email: String) -> Result<()> {
        // 邮箱不合法或用户不存在都静默返回成功，避免暴露账号是否存在。
        let email = match validate_email(&email) {
            Ok(email) => email,
            Err(_) => return Ok(()),
        };

        let user = self
            .db
            .find_record_by_field::<User>("user", "email", &email)
            .await?;

        // 停用 / 待删除的账号不发重置信。**必须和"账号不存在"走完全相同的
        // 静默成功**，不能返回 403：那会让这个端点变成"该邮箱是否被停用"的
        // 判别信道，把上面那段防枚举白做。
        match &user {
            None => return Ok(()),
            Some(user) if user.ensure_usable().is_err() => {
                info!("Password reset requested for a non-active account; ignoring silently");
                return Ok(());
            }
            Some(_) => {}
        }

        // 先作废该邮箱名下所有还没用掉的旧令牌，保证任一时刻只有最新那封邮件有效。
        // 否则每点一次"忘记密码"就多留一把可用的钥匙，全都活到各自的 1 小时到期为止。
        self.invalidate_password_reset_tokens(&email).await?;

        let reset_token = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::hours(1);

        let token_record = PasswordResetToken {
            id: Some(new_thing("password_reset_token")),
            email: email.clone(),
            token_hash: crate::utils::crypto::hash_bearer(&reset_token),
            expires_at,
            used: false,
            created_at: now,
        };

        self.db
            .create_record("password_reset_token", &token_record)
            .await?;

        // 发信失败不能往外抛。未知邮箱这条路径直接 `Ok(())`，若已知邮箱因 SMTP 挂了
        // 而返回 500，两者的差异就成了账号是否存在的判别信号 —— 上面那段防枚举的
        // 静默返回等于白做。SMTP 抖动也不该让用户流程断掉，令牌已经落库了。
        if let Err(e) = self
            .email_service
            .send_password_reset_email(&email, &reset_token)
            .await
        {
            error!("Failed to send password reset email: {e}");
        }

        Ok(())
    }

    /// 重新签发邮箱验证令牌并再发一封验证信。
    ///
    /// # 为什么必须有这个入口
    ///
    /// 验证令牌 24 小时过期，而在此之前**没有任何补发路径**：过期之后点链接得
    /// 401、登录得 403（Email not verified）、重新注册得 409（Email already
    /// registered）、走密码重置也救不了（重置不改 `is_email_verified`）。
    /// 四条路全堵，账号只能靠改库救。
    ///
    /// 而且这条路比看上去更容易走上：注册时 SMTP 发送失败是**刻意吞掉只记日志**的
    /// （见 `register`，那个取舍本身是对的——否则用户会拿到 500、重试又撞 409）。
    /// 两者叠加，一次短暂的 SMTP 抖动就能静默制造一个永久无法登录的账号。
    ///
    /// # 防枚举
    ///
    /// 与 `request_password_reset` 同一套语义：无论邮箱是否存在、是否已验证、
    /// 账号是否可用，**一律静默返回 Ok**。任何一种情况下回不同的错误码，
    /// 这个端点就成了账号状态的判别信道。
    pub async fn resend_verification_email(&self, email: String) -> Result<()> {
        if !self.config.email_verification_enabled {
            return Ok(());
        }

        let Ok(email) = validate_email(&email) else {
            return Ok(());
        };

        let Some(user) = self
            .db
            .find_record_by_field::<User>("user", "email", &email)
            .await?
        else {
            return Ok(());
        };

        // 已验证的账号不需要、也不应该再收到验证信：否则任何人都能靠这个端点
        // 反复给一个已注册邮箱发信。
        if user.is_email_verified || user.ensure_usable().is_err() {
            return Ok(());
        }

        let now = Utc::now();
        let token = Uuid::new_v4().to_string();

        let mut updated_user = user.clone();
        updated_user.verification_token_hash = Some(crate::utils::crypto::hash_bearer(&token));
        updated_user.verification_token_expires_at =
            Some((now + Duration::hours(VERIFICATION_TOKEN_TTL_HOURS)).timestamp());
        updated_user.updated_at = now.timestamp();

        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?.clone();
        self.db
            .update_record("user", &record_address(&user_thing), &updated_user)
            .await?;

        // 发信失败同样不外抛：令牌已经换了，再抛错只会让调用方拿到 500，
        // 而这个端点的整个意义就是"再试一次"。
        if let Err(e) = self
            .email_service
            .send_verification_email(&email, &token)
            .await
        {
            error!("Failed to resend verification email to '{email}': {e}");
        }

        Ok(())
    }

    /// 把某邮箱名下所有未使用的重置令牌标记为已用。
    ///
    /// 签发新令牌前、以及某个令牌被成功兑换后都要调用：这两条路径都必须让此前
    /// 发出去的链接立刻失效，否则攻击者事先触发的那封重置邮件在受害者改完密码
    /// 之后仍然能用来再改一次。
    async fn invalidate_password_reset_tokens(&self, email: &str) -> Result<()> {
        self.db
            .raw_query(
                "invalidate_password_reset_tokens",
                "UPDATE password_reset_token SET used = true WHERE email = $email AND used = false",
                serde_json::json!({ "email": email }),
            )
            .await?;
        Ok(())
    }

    /// 重置密码，返回受影响的用户 ID（供审计埋点使用）。
    pub async fn reset_password(&self, token: String, new_password: String) -> Result<String> {
        validate_password(&new_password, self.config.password_min_length)?;

        // 先**原子抢占**这枚令牌，再做任何有副作用的事。
        //
        // 原先是「读 → 判 used → 改密码 → 标记 used」，有两个问题：
        //
        // 一是并发。两个请求都在判定处读到 used = false，都通过，都改密码 ——
        // 后落地的那个赢。持有重置令牌的攻击者与本人竞速即可让自己的密码生效。
        //
        // 二是顺序。密码写在前、令牌消费在后，中间崩溃就留下「密码已改、令牌
        // 仍可用」的部分效果。
        //
        // 把消费提到最前并交给数据库做条件更新，两个问题一起消失：抢到才继续，
        // 没抢到说明已被消费。`RETURN VALUE` 让调用方能判断自己是不是赢家 ——
        // 与授权码、刷新令牌用的是同一套写法。
        let mut claimed = self
            .db
            .raw_query(
                "claim_password_reset_token",
                // 过期判定用库内的 `time::now()`，不传绑定值。
                //
                // `expires_at` 是 `datetime` 列，而经 JSON 绑定传进去的
                // `Utc::now()` 会变成字符串 —— SurrealDB 里 datetime 与字符串
                // 按**类型序**比较而非值序，条件因此不成立。这个坑在
                // rate_limiter.rs 的注释里已经记过一次。
                "UPDATE password_reset_token SET used = true \
                 WHERE token_hash = $token_hash AND used = false AND expires_at > time::now() \
                 RETURN VALUE token_hash",
                // 同上：`$token` 是 SurrealDB 保留变量。
                serde_json::json!({ "token_hash": crate::utils::crypto::hash_bearer(&token) }),
            )
            .await?;
        let claimed_tokens: Vec<String> = claimed.take(0)?;
        if claimed_tokens.len() != 1 {
            // 不存在、已被消费、已过期 —— 对外一律同一个答复，
            // 否则「令牌存不存在」与「是不是已经用过」就成了两条可区分的信道。
            return Err(AuthError::InvalidToken);
        }

        // 抢占成功后才去读它，拿邮箱。此时 used 已经是 true，重放不可能再走到这里。
        let reset_token = self
            .db
            .find_record_by_field::<PasswordResetToken>(
                "password_reset_token",
                "token_hash",
                &crate::utils::crypto::hash_bearer(&token),
            )
            .await?
            .ok_or(AuthError::InvalidToken)?;

        let mut user = self
            .db
            .find_record_by_field::<User>("user", "email", &reset_token.email)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // 令牌可能是停用之前签发的。这里可以回具体状态而不必含糊：
        // 能走到这一步说明对方已经持有一枚有效的重置令牌，
        // "该账号被停用"对他不是新信息。
        user.ensure_usable()?;

        user.password_hash = Some(hash_password_blocking(new_password.clone()).await?);
        user.updated_at = Utc::now().timestamp();

        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?.clone();
        self.db
            .update_record("user", &record_address(&user_thing), &user)
            .await?;

        // 这枚令牌在函数开头就已经被原子消费掉了，这里不需要再标记一次。

        // 同一邮箱名下可能还有别的未使用令牌（例如攻击者抢先申请、或用户连点了
        // 几次"忘记密码"）。密码既然已经改了，剩下那些一律作废。
        self.invalidate_password_reset_tokens(&reset_token.email)
            .await?;

        // 改密之后强制所有既有会话下线。
        let user_id = record_key(&user_thing);
        if let Err(e) = self.db.delete_sessions_by_user_id(&user_id).await {
            error!("Failed to revoke sessions after password reset: {:?}", e);
        }
        self.auth_cache.invalidate_user(&user_id).await;
        info!("Password reset completed; all sessions revoked");

        Ok(user_id)
    }

    pub async fn logout(&self, token: String) -> Result<()> {
        self.db.delete_session_by_token(&token).await?;
        self.auth_cache.invalidate_token(&token).await;
        Ok(())
    }

    pub async fn logout_all_sessions(&self, user_id: &str) -> Result<()> {
        self.db.delete_sessions_by_user_id(user_id).await?;
        self.auth_cache.invalidate_user(user_id).await;
        Ok(())
    }

    pub async fn get_user_sessions(
        &self,
        user_id: &str,
        current_token: &str,
    ) -> Result<Vec<SessionInfo>> {
        // 库里存的是指纹，来件也算一遍再比 —— 标记"当前会话"不需要明文。
        let current_token_hash = crate::utils::crypto::hash_bearer(current_token);
        let sessions = self.db.get_sessions_by_user_id(user_id).await?;

        let session_infos: Vec<SessionInfo> = sessions
            .into_iter()
            .filter_map(|session| {
                let id = session.id.as_ref().map(record_key)?;
                Some(SessionInfo {
                    id,
                    created_at: DateTime::<Utc>::from_timestamp(session.created_at, 0)
                        .unwrap_or_else(Utc::now),
                    user_agent: session.user_agent,
                    ip_address: session.ip_address,
                    is_current: session.token_hash == current_token_hash,
                })
            })
            .collect();

        Ok(session_infos)
    }
}

/// 一个固定的、谁也不知道原文的 Argon2 哈希，用来给"账号不存在"这条路径垫上
/// 等量的计算。
///
/// 参数必须和 `hash_password` 一致（都用 `Argon2::default()`），否则耗时对不上，
/// 垫了也白垫。只算一次。
static DUMMY_PASSWORD_HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn dummy_password_hash() -> &'static str {
    DUMMY_PASSWORD_HASH.get_or_init(|| {
        // 原文用随机值，保证没人能构造出匹配它的密码。
        let filler = Uuid::new_v4().to_string();
        hash_password(&filler).unwrap_or_default()
    })
}

/// 账号不存在 / 没有密码时，照样跑一次 Argon2 校验再丢掉结果。
///
/// 登录失败的文案两条路径是一样的，但耗时不是：命中账号要跑 Argon2（几十毫秒），
/// 没命中则立刻返回。这个差值在网络上很容易测出来，等于把"这个邮箱注册过没有"
/// 白送出去。这里把两条路径的计算量拉平。
async fn spend_password_verification_time() {
    let _ = verify_password_blocking(dummy_password_hash().to_string(), "invalid-password".into())
        .await;
}

/// Argon2 是几十毫秒的**纯 CPU** 运算，直接在 async fn 里跑会把 tokio 的工作
/// 线程整个占住。核数不多的机器上，几个并发登录就能把可用的工作线程吃光，
/// 连不相干的接口一起变慢。和 SMTP 发送同理，挪到阻塞线程池。
async fn verify_password_blocking(stored_hash: String, password: String) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let parsed =
            PasswordHash::new(&stored_hash).map_err(|e| AuthError::ServerError(e.to_string()))?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| AuthError::InvalidCredentials)
    })
    .await
    .map_err(|e| AuthError::ServerError(format!("Password verification task panicked: {e}")))?
}

/// 同上：哈希一次密码也要几十毫秒，注册 / 改密路径同样不能占着工作线程。
async fn hash_password_blocking(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| AuthError::ServerError(format!("Password hashing task panicked: {e}")))?
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hashed_password = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::ServerError(e.to_string()))?
        .to_string();
    Ok(hashed_password)
}

#[cfg(test)]
mod unique_violation_tests {
    use super::translate_unique_violation;
    use crate::error::AuthError;

    #[test]
    fn maps_index_violations_to_conflict_errors() {
        // 并发注册撞上唯一索引时，调用方该收到 409 而不是 500。
        let email = AuthError::DatabaseError(
            "Failed to create record: Database index `email_idx` already contains \
             'a@b.com', with record `user:abc`"
                .to_string(),
        );
        assert!(matches!(
            translate_unique_violation(email),
            AuthError::EmailExists
        ));

        let username = AuthError::DatabaseError(
            "Database index `username_idx` already contains 'alice'".to_string(),
        );
        assert!(matches!(
            translate_unique_violation(username),
            AuthError::UsernameExists
        ));
    }

    #[test]
    fn leaves_other_database_errors_alone() {
        // 不是索引冲突的库错误仍然是 500，不能被伪装成 409。
        let other = AuthError::DatabaseError("connection refused".to_string());
        assert!(matches!(
            translate_unique_violation(other),
            AuthError::DatabaseError(_)
        ));
        assert!(matches!(
            translate_unique_violation(AuthError::InvalidToken),
            AuthError::InvalidToken
        ));
    }
}
