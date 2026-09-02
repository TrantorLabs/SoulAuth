use serde::Deserialize;
use std::env;

/// 配置读取错误。
///
/// 以前这里对所有必填项直接 `expect` 导致进程 panic，堆栈里看不出到底缺哪个变量。
/// 现在统一走 `ConfigError`，由 `main` 打印后正常退出。
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    Missing(&'static str),
    #[error("Invalid value for environment variable {name}: {reason}")]
    Invalid { name: &'static str, reason: String },
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub database_user: String,
    pub database_pass: String,
    pub database_namespace: String,
    pub database_name: String,
    pub database_connection_timeout: u64,
    pub jwt_secret: String,
    pub jwt_expiration: i64,
    // 第三方登录的凭证是**可选**的：只用邮箱密码登录的部署不该被迫在配置里
    // 填四个假值。以前这四个是必填，运维只能写 dummy 混过去 —— 而配置里的
    // 假数据一旦哪天被当真就是事故。未配置时对应的登录入口返回 501，
    // 而不是拿假凭证去 Google 换令牌、再吐一个看不懂的 OAuth 错误。
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub oauth_redirect_url: Option<String>,
    /// Google OAuth 端点根地址覆盖。留空即用 Google 官方端点。
    ///
    /// 之所以存在：官方端点写死在代码里时，「换到令牌之后」那一整段
    /// —— 取用户信息、按 verified_email 放行、建号或关联既有账号 ——
    /// 完全无法端到端验证。有了它就能指向一个本地替身走通全流程。
    pub google_oauth_base_url: Option<String>,
    /// GitHub OAuth 端点根地址覆盖。留空即用 github.com / api.github.com。
    ///
    /// 除测试外这条在生产也有真实用途：自托管 GitHub Enterprise 的端点
    /// 正是 `{base}/login/oauth/*` 与 `{base}/api/v3/*` 这套路径。
    pub github_oauth_base_url: Option<String>,
    // 代理配置
    pub proxy_enabled: bool,
    pub proxy_url: Option<String>,
    // 邮件配置
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from: String,
    pub smtp_insecure: bool,
    pub app_url: String,
    pub email_verification_enabled: bool,
    /// 是否信任 `X-Forwarded-For` / `X-Real-IP`。
    /// 只有当服务确实跑在受控反向代理之后时才应打开：否则客户端可以任意伪造
    /// 来源 IP，从而绕过限流与 IP 维度的账号锁定。
    pub trust_proxy_headers: bool,
    /// 首个管理员的引导令牌。
    ///
    /// 不设置 → 每次启动随机生成一枚并打印到日志（单实例开发的默认路径）。
    /// 设为具体值 → 用它（多副本或自动化部署需要各副本一致时）。
    /// 设为空串 → 完全关闭这条路径。
    ///
    /// 无论取哪种，系统里一旦存在管理员，端点就永久拒绝服务 —— 它是一次性的
    /// 开机门，不是可反复调用的提权入口。
    pub bootstrap_token: Option<String>,
    /// CORS 白名单。为空表示只允许 `app_url` 自身。
    pub cors_allowed_origins: Vec<String>,
    /// OIDC ID Token 的 RSA 私钥（PEM，PKCS#8 或 PKCS#1）。
    pub oidc_rsa_private_key_pem: Option<String>,
    /// OIDC ID Token 的 RSA 私钥文件路径，与上面的 PEM 二选一。
    pub oidc_rsa_private_key_path: Option<String>,
    /// 密码最小长度。
    pub password_min_length: usize,
    /// MFA TOTP 密钥的加密密钥（base64 编码的 32 字节）。
    /// 不配置时从 `jwt_secret` 派生，并在启动时告警。
    pub mfa_encryption_key: Option<String>,
    /// 本副本的审计链标识。
    ///
    /// 审计哈希链按**副本**分：seq 由写入进程在内存里递增，多副本各写各的链。
    /// 两个副本用同一个 chain_id 会撞唯一索引，后来的那个副本每一条审计事件
    /// 都写不进去。默认值是 `BIND_ADDR`，只够本地单进程用；对外提供服务时
    /// **必须显式设置**，否则拒绝启动。
    pub instance_id: Option<String>,
    /// 审计 checkpoint 的 Ed25519 签名私钥（base64 的 32 字节种子）。
    ///
    /// 与 `jwt_secret`、`mfa_encryption_key` 是三把不同的钥匙，**不从任何一把派生**：
    /// 共用一把意味着轮换其中一个用途会连带作废另外两个，而审计完整性恰恰
    /// 最不该被顺手轮换破坏。
    pub audit_integrity_key: Option<String>,
    /// 前端登录页地址。`/api/oidc/authorize` 在用户未登录时跳到这里。
    /// 不配置时默认 `{app_url}/login`。
    pub login_page_url: Option<String>,
    /// 邮箱验证页地址（验证邮件里的链接指向它）。
    /// 不配置时默认 `{app_url}/verify-email`。
    pub verify_email_page_url: Option<String>,
    /// 密码重置页地址（重置邮件里的链接指向它）。
    /// 不配置时默认 `{app_url}/reset-password`。
    pub reset_password_page_url: Option<String>,
    /// HTTP 服务的监听地址。
    ///
    /// 以前写死在 `main.rs` 里的 `0.0.0.0:8080`：同一台机器起不了第二个实例，
    /// 端口冲突时无从规避，容器编排也改不了端口。
    pub bind_addr: String,
    /// 已认证请求的会话校验缓存时长（秒）。0 表示关闭缓存。
    pub session_cache_ttl_seconds: u64,
    /// 账号锁定策略。
    ///
    /// 这几项此前是写死的（5 次 / 15 分钟 / 60 分钟窗口）——
    /// `AccountLockoutService::new` 收了一个 `Config` 参数却直接丢掉，
    /// 用的是 `LockoutConfig::default()`。而这恰恰是认证产品里最需要按部署
    /// 调整的一组参数：面向公众的服务和内网工具对暴力破解的容忍度完全不同。
    pub lockout_max_attempts: u32,
    pub lockout_duration_minutes: u32,
    pub lockout_reset_window_minutes: u32,
    pub lockout_user_enabled: bool,
    pub lockout_ip_enabled: bool,
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// 同 [`optional`]，但**保留空串**。
///
/// 绝大多数配置项把「设成空串」和「没设置」当同一回事，所以 `optional` 直接
/// 把空串滤掉了。引导令牌不行：那里空串表示「关闭这条路径」，与「没设置」
/// （随机生成一枚）语义相反，滤掉就把显式关闭变成了显式开启。
fn optional_raw(name: &str) -> Option<String> {
    env::var(name).ok().map(|value| value.trim().to_string())
}

fn parse_with_default<T: std::str::FromStr>(
    name: &'static str,
    default: T,
) -> Result<T, ConfigError> {
    match optional(name) {
        None => Ok(default),
        Some(raw) => raw.parse::<T>().map_err(|_| ConfigError::Invalid {
            name,
            reason: format!("cannot parse `{raw}`"),
        }),
    }
}

fn parse_bool(name: &str, default: bool) -> bool {
    optional(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

/// 两个可选配置项是否都提供了非空值。
fn both_present(a: &Option<String>, b: &Option<String>) -> bool {
    let filled = |v: &Option<String>| v.as_deref().map(str::trim).is_some_and(|s| !s.is_empty());
    filled(a) && filled(b)
}

/// 取 URL 里 scheme 之后的主机名（含端口前的部分）。
///
/// IPv6 字面量必须单独处理：`http://[::1]:8080` 直接按 `:` 切会切在方括号里，
/// 得到 `"["`，于是 `[::1]` 被判成非环回。
pub(crate) fn host_of(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;

    if let Some(inner) = rest.strip_prefix('[') {
        // 方括号内整体是主机名，端口在 `]` 之后
        let end = inner.find(']')?;
        return Some(&rest[..end + 2]); // 含两侧方括号
    }

    rest.split(['/', ':']).next().filter(|h| !h.is_empty())
}

/// 是否为环回地址。**整个 crate 里只有这一处判定**：
/// 多写一份迟早会和这份走偏，出现「这里算生产、那里不算」的裂缝。
///
/// 这条注释一度只写「本文件里」，而 `routes::oidc_client` 就在文件之外
/// 手写了一个 `starts_with("http://localhost")` —— 于是
/// `http://localhost.evil.com/cb` 被当成本地地址放行，而合法的
/// `http://[::1]:3000/cb` 反而被拒。判定收回这一处之后两个方向都对了。
pub(crate) fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1")
}

/// 校验 OAuth 端点覆盖：明文 http 只许指向环回地址。
///
/// 覆盖端点等于改写「授权码换令牌」发往何处 —— 走明文就是把 client_secret
/// 和访问令牌交给链路上的任何人。测试需要明文（本地替身没有证书），
/// 所以放行环回，其余一律拒绝启动，而不是打条警告日志了事：
/// 配歪了要在启动时就炸，不能等到线上换令牌时才泄密。
fn check_oauth_base_url(name: &'static str, value: Option<&str>) -> Result<(), ConfigError> {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(());
    };

    if raw.ends_with('/') {
        return Err(ConfigError::Invalid {
            name,
            reason: "must not end with a trailing slash".to_string(),
        });
    }

    if raw.starts_with("https://") {
        return Ok(());
    }

    match host_of(raw) {
        Some(host) if is_loopback_host(host) => Ok(()),
        Some(_) => Err(ConfigError::Invalid {
            name,
            reason: "plaintext http is only allowed for loopback hosts; \
                    a remote OAuth endpoint must use https or the client secret \
                    and access tokens travel in the clear"
                .to_string(),
        }),
        None => Err(ConfigError::Invalid {
            name,
            reason: "must start with https:// or http://".to_string(),
        }),
    }
}

/// 校验回调地址：明文 http 只许指向环回地址。
///
/// 与 `check_oauth_base_url` 是同一条判据，只是少了「不得带尾斜杠」——
/// 那一条是给「拼接用的根地址」准备的，回调地址本身是一个完整 URL。
///
/// 之前这里只查了「配没配」：配成 `http://auth.example/api/auth/callback`
/// 一样启动，第三方 IdP 就会把授权码原样发到明文链路上。
fn check_oauth_redirect_url(value: Option<&str>) -> Result<(), ConfigError> {
    const NAME: &str = "OAUTH_REDIRECT_URL";
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(());
    };

    if raw.starts_with("https://") {
        return Ok(());
    }

    match host_of(raw) {
        Some(host) if is_loopback_host(host) => Ok(()),
        Some(_) => Err(ConfigError::Invalid {
            name: NAME,
            reason: "plaintext http is only allowed for loopback hosts; \
                    a remote callback URL must use https or the authorization code \
                    travels in the clear"
                .to_string(),
        }),
        None => Err(ConfigError::Invalid {
            name: NAME,
            reason: "must be an absolute URL starting with https:// or http://".to_string(),
        }),
    }
}

/// `*` 不是「宽松配置」，是一个 panic。
///
/// `AllowOrigin::list` 见到通配符会直接 `panic!`（tower-http 0.4.4
/// allow_origin.rs:54），而 `HeaderValue::from_str("*")` 是合法的，所以它一路
/// 穿过 `main.rs` 里那层 filter_map 才炸，栈里看不出是哪个环境变量的问题。
/// 这个文件里其它所有配置错误都返回 `ConfigError`，这一个不该例外。
fn check_cors_origins(origins: &[String]) -> Result<(), ConfigError> {
    if origins.iter().any(|o| o == "*") {
        return Err(ConfigError::Invalid {
            name: "CORS_ALLOWED_ORIGINS",
            reason: "`*` is not accepted: it would let any site call this service \
                    with the user's Authorization header. List the origins explicitly, \
                    or leave it empty to allow only APP_URL itself"
                .to_string(),
        });
    }
    Ok(())
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let app_url = required("APP_URL")?;

        let cors_allowed_origins = optional("CORS_ALLOWED_ORIGINS")
            .map(|raw| {
                raw.split(',')
                    .map(|origin| origin.trim().trim_end_matches('/').to_string())
                    .filter(|origin| !origin.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        check_cors_origins(&cors_allowed_origins)?;

        let config = Self {
            database_url: optional("DATABASE_URL")
                .unwrap_or_else(|| "http://localhost:8000".to_string()),
            database_user: optional("DATABASE_USER").unwrap_or_else(|| "root".to_string()),
            database_pass: optional("DATABASE_PASS").unwrap_or_else(|| "root".to_string()),
            database_namespace: optional("DATABASE_NAMESPACE")
                .unwrap_or_else(|| "auth".to_string()),
            database_name: optional("DATABASE_NAME").unwrap_or_else(|| "main".to_string()),
            database_connection_timeout: parse_with_default("DATABASE_CONNECTION_TIMEOUT", 30)?,
            jwt_secret: required("JWT_SECRET")?,
            jwt_expiration: parse_with_default("JWT_EXPIRATION", 86_400)?,
            google_client_id: optional("GOOGLE_CLIENT_ID"),
            google_client_secret: optional("GOOGLE_CLIENT_SECRET"),
            github_client_id: optional("GITHUB_CLIENT_ID"),
            github_client_secret: optional("GITHUB_CLIENT_SECRET"),
            oauth_redirect_url: optional("OAUTH_REDIRECT_URL"),
            google_oauth_base_url: optional("GOOGLE_OAUTH_BASE_URL"),
            github_oauth_base_url: optional("GITHUB_OAUTH_BASE_URL"),
            proxy_enabled: parse_bool("PROXY_ENABLED", false),
            proxy_url: optional("PROXY_URL"),
            smtp_host: required("SMTP_HOST")?,
            smtp_port: parse_with_default("SMTP_PORT", 587u16)?,
            smtp_username: env::var("SMTP_USERNAME").unwrap_or_default(),
            smtp_password: env::var("SMTP_PASSWORD").unwrap_or_default(),
            smtp_from: required("SMTP_FROM")?,
            smtp_insecure: parse_bool("SMTP_INSECURE", false),
            app_url,
            email_verification_enabled: parse_bool("EMAIL_VERIFICATION_ENABLED", false),
            trust_proxy_headers: parse_bool("TRUST_PROXY_HEADERS", false),
            // 用 optional() 而不是 unwrap_or_default()：这里必须能区分
            // 「没设置」（随机生成）与「设成空串」（关闭），两者语义相反。
            bootstrap_token: optional_raw("SOULAUTH_BOOTSTRAP_TOKEN"),
            cors_allowed_origins,
            oidc_rsa_private_key_pem: optional("OIDC_RSA_PRIVATE_KEY_PEM"),
            oidc_rsa_private_key_path: optional("OIDC_RSA_PRIVATE_KEY_PATH"),
            password_min_length: parse_with_default("PASSWORD_MIN_LENGTH", 12usize)?,
            mfa_encryption_key: optional("MFA_SECRET_ENCRYPTION_KEY"),
            login_page_url: optional("LOGIN_PAGE_URL"),
            verify_email_page_url: optional("VERIFY_EMAIL_PAGE_URL"),
            reset_password_page_url: optional("RESET_PASSWORD_PAGE_URL"),
            instance_id: optional("SOULAUTH_INSTANCE_ID"),
            audit_integrity_key: optional("AUDIT_INTEGRITY_KEY"),
            bind_addr: optional("BIND_ADDR").unwrap_or_else(|| "0.0.0.0:8080".to_string()),
            session_cache_ttl_seconds: parse_with_default("AUTH_SESSION_CACHE_TTL_SECONDS", 5u64)?,
            lockout_max_attempts: parse_with_default("LOCKOUT_MAX_ATTEMPTS", 5u32)?,
            lockout_duration_minutes: parse_with_default("LOCKOUT_DURATION_MINUTES", 15u32)?,
            lockout_reset_window_minutes: parse_with_default(
                "LOCKOUT_RESET_WINDOW_MINUTES",
                60u32,
            )?,
            lockout_user_enabled: parse_bool("LOCKOUT_USER_ENABLED", true),
            lockout_ip_enabled: parse_bool("LOCKOUT_IP_ENABLED", true),
        };

        if config.jwt_secret.len() < 32 {
            return Err(ConfigError::Invalid {
                name: "JWT_SECRET",
                reason: "must be at least 32 characters".to_string(),
            });
        }

        // 0 次尝试就锁定 = 任何人一登录就被锁死；0 分钟锁定 = 锁了等于没锁。
        // 这两种配置都不是"更严格"，是把服务配坏，所以在启动时拦下。
        if config.lockout_max_attempts == 0 {
            return Err(ConfigError::Invalid {
                name: "LOCKOUT_MAX_ATTEMPTS",
                reason: "must be at least 1; zero would lock every account on first attempt"
                    .to_string(),
            });
        }
        if config.lockout_duration_minutes == 0 {
            return Err(ConfigError::Invalid {
                name: "LOCKOUT_DURATION_MINUTES",
                reason: "must be at least 1; a zero-minute lockout is not a lockout".to_string(),
            });
        }

        check_oauth_base_url(
            "GOOGLE_OAUTH_BASE_URL",
            config.google_oauth_base_url.as_deref(),
        )?;
        check_oauth_base_url(
            "GITHUB_OAUTH_BASE_URL",
            config.github_oauth_base_url.as_deref(),
        )?;

        // 半配置状态要当场拦下：配了 provider 却没有回调地址，重定向 URI 会被
        // 拼成没有前缀的残缺地址，登录到第一步才失败，而且报错指向 OAuth 库。
        if config.any_oauth_provider_configured() && config.oauth_redirect_url.is_none() {
            return Err(ConfigError::Invalid {
                name: "OAUTH_REDIRECT_URL",
                reason: "must be set when any OAuth provider is configured".to_string(),
            });
        }
        check_oauth_redirect_url(config.oauth_redirect_url.as_deref())?;

        config.check_production_secrets()?;

        Ok(config)
    }

    /// 是否配置了任意一个第三方登录 provider。
    pub fn any_oauth_provider_configured(&self) -> bool {
        self.google_configured() || self.github_configured()
    }

    /// Google 登录是否可用：id 与 secret 必须同时具备。
    /// 只配一半比两个都不配更危险 —— 它看起来是开着的。
    pub fn google_configured(&self) -> bool {
        both_present(&self.google_client_id, &self.google_client_secret)
    }

    pub fn github_configured(&self) -> bool {
        both_present(&self.github_client_id, &self.github_client_secret)
    }

    /// 本实例是否面向环回地址之外提供服务。
    fn serves_remote_clients(&self) -> bool {
        host_of(self.app_url.trim()).is_none_or(|host| !is_loopback_host(host))
    }

    /// 生产部署必须显式配置的密钥。缺了就拒绝启动，而不是打条警告继续跑。
    ///
    /// 这两项以前只是启动警告。问题在于：它们的后果都**不在启动时显现**，
    /// 而是等到重启之后、或轮换密钥之后才爆，那时候已经是线上事故：
    ///   · 缺 OIDC 私钥 → 用临时密钥，进程一重启，已签发的 ID Token 全部
    ///     无法验证；多副本部署里每个副本各签各的，从第一天起就互不认账。
    ///   · 缺 MFA 密钥 → 从 JWT_SECRET 派生，哪天轮换 JWT_SECRET，
    ///     所有已存的 TOTP 密钥变成无法解密，全体 MFA 用户被锁在门外。
    ///
    /// 环回地址仍然放行：本地开发要能一条命令跑起来。
    fn check_production_secrets(&self) -> Result<(), ConfigError> {
        if !self.serves_remote_clients() {
            return Ok(());
        }

        // 对外提供服务就必须是 https。
        //
        // 之前这道闸门只看「是不是环回」，不看 scheme，于是
        // `APP_URL=http://auth.example.com` 一路放行，后果有三层，
        // 而且都不在启动时显现：
        //   · 会话 cookie 不带 `Secure`（`cookies_secure()` 按 scheme 判定），
        //     同一浏览器里任何一次明文请求都能把它带走；
        //   · 邮件里的验证 / 重置链接是明文地址；
        //   · OIDC `issuer` 是明文 —— 而 OpenID Connect Discovery 要求
        //     issuer 必须是 https，接入方按规范校验会直接拒绝。
        //
        // 没有开环境变量后门：这道闸门上面那两项密钥的注释里已经写过为什么
        // ——「否则会被人用环境变量绕过去」。TLS 在反向代理上终结的部署，
        // APP_URL 填的本来就应该是对外那个 https 地址。
        if !self
            .app_url
            .trim()
            .to_ascii_lowercase()
            .starts_with("https://")
        {
            return Err(ConfigError::Invalid {
                name: "APP_URL",
                reason: "must use https when it is not a loopback address; over plaintext \
                        the session cookie loses `Secure`, mail links are unencrypted, and \
                        the OIDC issuer violates the Discovery spec. Terminate TLS in front \
                        of SoulAuth and set APP_URL to the public https address"
                    .to_string(),
            });
        }

        if self.oidc_rsa_private_key_pem.is_none() && self.oidc_rsa_private_key_path.is_none() {
            return Err(ConfigError::Invalid {
                name: "OIDC_RSA_PRIVATE_KEY_PEM",
                reason: "a persistent OIDC signing key is required when APP_URL is not a \
                        loopback address; without it every restart invalidates all issued \
                        ID tokens and replicas sign with different keys. Set \
                        OIDC_RSA_PRIVATE_KEY_PEM or OIDC_RSA_PRIVATE_KEY_PATH"
                    .to_string(),
            });
        }

        if self.mfa_encryption_key.is_none() {
            return Err(ConfigError::Invalid {
                name: "MFA_SECRET_ENCRYPTION_KEY",
                reason: "a dedicated MFA encryption key is required when APP_URL is not a \
                        loopback address; deriving it from JWT_SECRET means rotating \
                        JWT_SECRET locks every MFA user out. Generate one with \
                        `openssl rand -base64 32`"
                    .to_string(),
            });
        }

        // 本副本的审计链标识。
        //
        // 不猜：默认值 `BIND_ADDR` 在编排环境里每个 Pod 都一样，两个副本会共用
        // 一条链，后者的审计事件被唯一索引静默拒绝。这类「静默丢事件」正是
        // 哈希链要消灭的东西，所以宁可让它在启动时就炸。
        if self
            .instance_id
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_none()
        {
            return Err(ConfigError::Invalid {
                name: "SOULAUTH_INSTANCE_ID",
                reason: "must be set explicitly when APP_URL is not a loopback address; \
                        it names this replica's audit hash chain, and two replicas sharing \
                        one name collide on the unique index, which silently drops the \
                        later replica's audit events. Use the pod or host name"
                    .to_string(),
            });
        }

        // 审计 checkpoint 的签名密钥。
        //
        // 没有它，哈希链仍然写，但没有任何 checkpoint 被签出来 —— 于是拥有全库
        // 写权限的人可以从任意一行起把链整段重算，而没有任何签名能拆穿它。
        // 这一项与上面两项同属「后果不在启动时显现」那一类，所以同样拒绝启动。
        if self.audit_integrity_key.is_none() {
            return Err(ConfigError::Invalid {
                name: "AUDIT_INTEGRITY_KEY",
                reason: "a dedicated audit integrity key is required when APP_URL is not a \
                        loopback address; without it no checkpoint is signed, and a hash \
                        chain alone can be recomputed by anyone holding database write \
                        access. Generate one with `openssl rand -base64 32`"
                    .to_string(),
            });
        }

        Ok(())
    }

    /// Cookie 是否应带 `Secure`。
    ///
    /// 恒定带 `Secure` 会让 `http://localhost` 的本地开发完全跑不通（浏览器
    /// 直接丢弃 cookie，OIDC 流程走不下去）。这里按部署协议决定：
    /// `app_url` 是 https 就带，否则不带。
    pub fn cookies_secure(&self) -> bool {
        self.app_url
            .trim()
            .to_ascii_lowercase()
            .starts_with("https://")
    }

    /// 未登录用户从 `/api/oidc/authorize` 被引导去的登录页。
    pub fn login_page_url(&self) -> String {
        self.login_page_url
            .clone()
            .unwrap_or_else(|| format!("{}/login", self.app_url.trim_end_matches('/')))
    }

    /// 验证邮件里链接指向的前端页面。
    pub fn verify_email_page_url(&self) -> String {
        self.verify_email_page_url
            .clone()
            .unwrap_or_else(|| format!("{}/verify-email", self.app_url.trim_end_matches('/')))
    }

    /// 重置邮件里链接指向的前端页面。
    ///
    /// 这一项以前不存在：重置链接被硬编码成 `{app_url}/reset-password/{token}`。
    /// 于是前端另有域名的部署方，验证信的链接能改、重置信的改不了，
    /// 用户点开重置链接落到一个不存在的页面上。
    pub fn reset_password_page_url(&self) -> String {
        self.reset_password_page_url
            .clone()
            .unwrap_or_else(|| format!("{}/reset-password", self.app_url.trim_end_matches('/')))
    }

    /// 本副本的审计链标识。
    ///
    /// 没有显式配置时用 `BIND_ADDR`。
    ///
    /// 曾经想过回落到 `{HOSTNAME}:{BIND_ADDR}` —— 容器里 HOSTNAME 天然各不相同，
    /// 看起来很合适。放弃了，两个理由：
    ///
    /// * 那是一次**猜测**。猜错的后果是两个副本共用一条链，后者的审计事件被
    ///   唯一索引静默拒绝 —— 恰好是这条链要消灭的那类故障。
    /// * `HOSTNAME` 不是 SoulAuth 的配置项，运维不设它，把它登记进配置注册表
    ///   是误导；不登记又会让「运行时读到的环境变量必须在注册表里」这条守卫
    ///   出现盲区。
    ///
    /// 所以生产环境**必须显式设**（见 `check_production_secrets`），
    /// 本地开发单进程时 `BIND_ADDR` 已经足够唯一。
    pub fn audit_chain_id(&self) -> String {
        self.instance_id
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or(&self.bind_addr)
            .to_string()
    }

    /// CORS 允许的来源列表：显式白名单优先，否则回落到自身 `app_url`。
    pub fn effective_cors_origins(&self) -> Vec<String> {
        if self.cors_allowed_origins.is_empty() {
            vec![self.app_url.trim_end_matches('/').to_string()]
        } else {
            self.cors_allowed_origins.clone()
        }
    }

    /// 测试用的默认配置。放在这里而不是各个测试模块里各写一份，
    /// 是为了新增字段时只有一处要改（漏改会直接编译不过）。
    #[cfg(test)]
    pub(crate) fn test_default() -> Self {
        Self {
            database_url: "http://localhost:8000".to_string(),
            database_user: "root".to_string(),
            database_pass: "root".to_string(),
            database_namespace: "auth".to_string(),
            database_name: "main".to_string(),
            database_connection_timeout: 30,
            jwt_secret: "0123456789abcdef0123456789abcdef".to_string(),
            jwt_expiration: 3600,
            google_client_id: Some("g".to_string()),
            google_client_secret: Some("g".to_string()),
            github_client_id: Some("h".to_string()),
            github_client_secret: Some("h".to_string()),
            oauth_redirect_url: Some("https://auth.example/api/auth/callback".to_string()),
            google_oauth_base_url: None,
            github_oauth_base_url: None,
            proxy_enabled: false,
            proxy_url: None,
            smtp_host: "localhost".to_string(),
            smtp_port: 1025,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_from: "noreply@example.com".to_string(),
            smtp_insecure: true,
            app_url: "https://auth.example".to_string(),
            email_verification_enabled: false,
            trust_proxy_headers: false,
            bootstrap_token: None,
            cors_allowed_origins: Vec::new(),
            oidc_rsa_private_key_pem: None,
            oidc_rsa_private_key_path: None,
            password_min_length: 12,
            mfa_encryption_key: None,
            login_page_url: None,
            verify_email_page_url: None,
            reset_password_page_url: None,
            instance_id: None,
            audit_integrity_key: None,
            bind_addr: "0.0.0.0:8080".to_string(),
            session_cache_ttl_seconds: 5,
            lockout_max_attempts: 5,
            lockout_duration_minutes: 15,
            lockout_reset_window_minutes: 60,
            lockout_user_enabled: true,
            lockout_ip_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::host_of;

    #[test]
    fn host_of_handles_ipv6_literals() {
        // 按 `:` 切会切进方括号里，得到 "["，于是 [::1] 被判成非环回。
        assert_eq!(host_of("http://[::1]:8080"), Some("[::1]"));
        assert_eq!(host_of("https://[2001:db8::1]/path"), Some("[2001:db8::1]"));
        assert_eq!(host_of("http://[::1]"), Some("[::1]"));
    }

    #[test]
    fn host_of_handles_ordinary_hosts() {
        assert_eq!(host_of("http://localhost:8080"), Some("localhost"));
        assert_eq!(
            host_of("https://auth.example.com"),
            Some("auth.example.com")
        );
        assert_eq!(
            host_of("https://auth.example.com/a/b"),
            Some("auth.example.com")
        );
        assert_eq!(host_of("not-a-url"), None);
        assert_eq!(host_of("https://"), None);
    }

    #[test]
    fn a_deployment_with_no_oauth_provider_is_valid() {
        // 这条是本次改动的目的：只用邮箱密码登录的部署，
        // 不该被迫在配置里填四个假的第三方凭证。
        let mut config = Config::test_default();
        config.google_client_id = None;
        config.google_client_secret = None;
        config.github_client_id = None;
        config.github_client_secret = None;
        config.oauth_redirect_url = None;
        assert!(!config.any_oauth_provider_configured());
    }

    #[test]
    fn half_configured_provider_counts_as_unconfigured() {
        // 只配 id 不配 secret 比两个都不配更危险：它看起来是开着的。
        let mut config = Config::test_default();
        config.google_client_secret = None;
        assert!(!config.google_configured());

        config.google_client_secret = Some("   ".to_string());
        assert!(!config.google_configured(), "空白值不算配置");
    }

    #[test]
    fn production_requires_persistent_signing_and_mfa_keys() {
        // 这两项的后果都不在启动时显现 —— 一个要等重启，一个要等轮换密钥，
        // 到那时候已经是线上事故。所以宁可起不来。
        let mut config = Config::test_default();
        config.app_url = "https://auth.example.com".to_string();
        config.oidc_rsa_private_key_pem = None;
        config.oidc_rsa_private_key_path = None;
        config.mfa_encryption_key = Some("k".to_string());
        assert!(
            config.check_production_secrets().is_err(),
            "缺 OIDC 私钥应拒绝启动"
        );

        config.oidc_rsa_private_key_pem = Some("pem".to_string());
        config.mfa_encryption_key = None;
        assert!(
            config.check_production_secrets().is_err(),
            "缺 MFA 密钥应拒绝启动"
        );

        config.mfa_encryption_key = Some("k".to_string());
        assert!(
            config.check_production_secrets().is_err(),
            "缺审计完整性密钥应拒绝启动"
        );

        config.audit_integrity_key = Some("k".to_string());
        assert!(
            config.check_production_secrets().is_err(),
            "缺副本标识应拒绝启动 —— 默认值在编排环境里每个 Pod 都一样"
        );

        config.instance_id = Some("pod-a".to_string());
        assert!(config.check_production_secrets().is_ok());
    }

    #[test]
    fn loopback_deployments_still_start_without_those_keys() {
        // 本地开发要能一条命令跑起来，否则这道闸门会被人用环境变量绕过去。
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            let mut config = Config::test_default();
            config.app_url = url.to_string();
            config.oidc_rsa_private_key_pem = None;
            config.oidc_rsa_private_key_path = None;
            config.mfa_encryption_key = None;
            assert!(config.check_production_secrets().is_ok(), "{url} 应放行");
        }
    }

    #[test]
    fn a_remote_app_url_must_be_https() {
        // 明文对外意味着三件事同时发生：cookie 掉 `Secure`、邮件链接明文、
        // OIDC issuer 违反 Discovery 规范。三条都不在启动时显现。
        for url in [
            "http://auth.example.com",
            "http://10.0.0.5:8080",
            "HTTP://AUTH.EXAMPLE.COM",
        ] {
            let mut config = Config::test_default();
            config.app_url = url.to_string();
            // 三把密钥都配齐，确保这条断言测的是 scheme 而不是缺密钥。
            config.oidc_rsa_private_key_pem = Some("pem".to_string());
            config.mfa_encryption_key = Some("k".to_string());
            config.audit_integrity_key = Some("k".to_string());
            config.instance_id = Some("pod-a".to_string());
            assert!(
                config.check_production_secrets().is_err(),
                "{url} 是明文的对外地址，应拒绝启动"
            );
        }
    }

    #[test]
    fn a_loopback_app_url_may_stay_plaintext() {
        // 本地开发跑 https 要自签证书，那会把「一条命令跑起来」变成一段仪式。
        let mut config = Config::test_default();
        config.app_url = "http://localhost:8080".to_string();
        assert!(config.check_production_secrets().is_ok());
    }

    #[test]
    fn reset_password_page_defaults_under_app_url() {
        assert_eq!(
            config_with_app_url("https://auth.example/").reset_password_page_url(),
            "https://auth.example/reset-password"
        );
    }

    use super::check_cors_origins;

    #[test]
    fn a_cors_wildcard_is_a_config_error_not_a_panic() {
        // 以前它会一路走到 `AllowOrigin::list` 才 panic。
        assert!(check_cors_origins(&["*".to_string()]).is_err());
        assert!(check_cors_origins(&["https://app.example".to_string(), "*".to_string()]).is_err());
        assert!(check_cors_origins(&["https://app.example".to_string()]).is_ok());
        assert!(check_cors_origins(&[]).is_ok());
    }

    use super::check_oauth_redirect_url;

    #[test]
    fn a_remote_oauth_callback_must_be_https() {
        // 判据与 endpoint override 同源：明文远端 = 授权码在链路上裸奔。
        for url in [
            "http://auth.example.com/api/auth/callback",
            "http://10.0.0.5:8080/cb",
            "/api/auth/callback",
            "auth.example.com/cb",
        ] {
            assert!(
                check_oauth_redirect_url(Some(url)).is_err(),
                "{url} 应被拒绝"
            );
        }
        for url in [
            "https://auth.example.com/api/auth/callback",
            "http://localhost:8080/api/auth/callback",
            "http://127.0.0.1:8080/cb",
            "http://[::1]:8080/cb",
        ] {
            assert!(check_oauth_redirect_url(Some(url)).is_ok(), "{url} 应放行");
        }
        // 没配就不检查 —— 「配了 provider 却没配它」由另一条判据管。
        assert!(check_oauth_redirect_url(None).is_ok());
        assert!(check_oauth_redirect_url(Some("  ")).is_ok());
    }

    use super::check_oauth_base_url;

    #[test]
    fn plaintext_oauth_endpoint_is_rejected_unless_it_is_loopback() {
        // 明文 http 指向远端 = client_secret 与访问令牌在链路上裸奔。
        // 这类配置必须在启动时炸掉，不能只打条警告然后照常上线。
        for host in ["http://oauth.evil.test", "http://10.0.0.5:8126", "ftp://x"] {
            assert!(
                check_oauth_base_url("GOOGLE_OAUTH_BASE_URL", Some(host)).is_err(),
                "should have rejected {host}"
            );
        }
    }

    #[test]
    fn loopback_and_https_overrides_are_accepted() {
        for ok in [
            "http://127.0.0.1:8126",
            "http://localhost:8126",
            "https://ghe.example.com",
        ] {
            assert!(
                check_oauth_base_url("GITHUB_OAUTH_BASE_URL", Some(ok)).is_ok(),
                "should have accepted {ok}"
            );
        }
        // 未设置就是未设置，不该被当成非法值
        assert!(check_oauth_base_url("GITHUB_OAUTH_BASE_URL", None).is_ok());
        assert!(check_oauth_base_url("GITHUB_OAUTH_BASE_URL", Some("  ")).is_ok());
    }

    #[test]
    fn a_trailing_slash_is_rejected_rather_than_silently_doubling_up() {
        // 端点由 `{base}/token` 拼出，base 带斜杠就成了 `//token`。
        // 有的服务端会 404，有的会重定向 —— 与其赌，不如不收。
        assert!(check_oauth_base_url("GOOGLE_OAUTH_BASE_URL", Some("https://x.test/")).is_err());
    }

    use super::Config;

    fn config_with_app_url(app_url: &str) -> Config {
        Config {
            app_url: app_url.to_string(),
            ..Config::test_default()
        }
    }

    #[test]
    fn cookies_are_secure_only_over_https() {
        assert!(config_with_app_url("https://auth.example").cookies_secure());
        assert!(!config_with_app_url("http://localhost:8080").cookies_secure());
    }

    #[test]
    fn login_page_defaults_to_app_url_login() {
        assert_eq!(
            config_with_app_url("https://auth.example/").login_page_url(),
            "https://auth.example/login"
        );
    }

    #[test]
    fn cors_falls_back_to_app_url() {
        assert_eq!(
            config_with_app_url("https://auth.example/").effective_cors_origins(),
            vec!["https://auth.example".to_string()]
        );
    }
}
