use crate::{
    config::Config,
    error::{AuthError, Result},
    models::identity_provider::OAuthUserInfo,
};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    HttpRequest, HttpResponse, RedirectUrl, Scope, TokenResponse, TokenUrl,
};

/// 配置完成的 OAuth 客户端类型。
///
/// oauth2 5.x 用 typestate 表达"哪些端点已设置"：设了 auth_uri 与 token_uri
/// 才有 `exchange_code`。代价是类型名要写全，收益是配漏端点在编译期就报错，
/// 而不是等到换令牌时才失败。
type ConfiguredClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;
use reqwest::{Client, Proxy};
use serde::Deserialize;
use tracing::{error, info};

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    id: String,
    email: String,
    verified_email: bool,
    name: Option<String>,
    picture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUserInfo {
    id: i64,
    // 注意：GitHub 的 /user 接口对隐藏邮箱的账号返回 email=null，
    // 所以邮箱一律从 /user/emails 取，这里不再声明该字段。
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

/// 用**我们自己配置的** `reqwest::Client` 执行 oauth2 的 HTTP 往返。
///
/// 为什么不直接把 client 交给 oauth2：它自带的 reqwest 集成绑的是它依赖的那个
/// reqwest 版本，与本项目直接依赖的不是同一个 crate 实例，`AsyncHttpClient`
/// 的 impl 对不上。走闭包这条通路（oauth2 对 `Fn(HttpRequest) -> Future` 有
/// blanket impl）则完全绕开版本耦合，并且保住了代理与超时配置 ——
/// 那正是这个函数最初存在的理由：`oauth2::reqwest::async_http_client` 内部
/// 自己 new 一个默认 client，**没有超时也不认代理**，PROXY_ENABLED 会静默失效。
async fn send_via_reqwest(
    client: Client,
    request: HttpRequest,
) -> std::result::Result<HttpResponse, AuthError> {
    let (parts, body) = request.into_parts();

    let mut builder = client.request(parts.method, parts.uri.to_string());
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }

    let response = builder.body(body).send().await?;

    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.bytes().await?.to_vec();

    let mut out = oauth2::http::Response::builder().status(status);
    if let Some(slot) = out.headers_mut() {
        *slot = headers;
    }
    out.body(bytes)
        .map_err(|e| AuthError::OAuthError(format!("Failed to assemble OAuth response: {e}")))
}

/// 出站 OAuth 请求的整体超时（含 TLS 握手、发送、读完响应体）。
const OUTBOUND_HTTP_TIMEOUT_SECS: u64 = 15;
/// 单独的建连超时，比整体超时短，让"连不上"比"响应慢"更快失败。
const OUTBOUND_CONNECT_TIMEOUT_SECS: u64 = 5;

pub struct OAuthService {
    config: Config,
    // 未配置凭证的 provider **没有 client**，而不是拿空串硬造一个。
    // 造出来的话，登录会一路走到「拿假 client_id 去 Google 换令牌」才失败，
    // 报错还指向 OAuth 库 —— 运维看不出这是「没配」而不是「配错」。
    google_client: Option<ConfiguredClient>,
    github_client: Option<ConfiguredClient>,
    // 授权 / 换令牌两个端点已经进了 BasicClient，不必重复保存；
    // 这三个是「换到令牌之后」才用的，得自己拿着。
    google_userinfo_url: String,
    github_user_url: String,
    github_emails_url: String,
}

/// 各 provider 的端点。`base` 为 `None` 时用官方地址；为 `Some` 时
/// **沿用该 provider 真实的路径形状**，只换根地址 —— 这样本地替身是忠实
/// 替身，测出来的东西对真实端点同样成立。
///
/// 只在这一处知道路径形状：换 provider 或改端点都只动这里。
fn google_endpoints(base: Option<&str>) -> (String, String, String) {
    match base {
        Some(b) => (
            format!("{b}/o/oauth2/v2/auth"),
            format!("{b}/token"),
            format!("{b}/oauth2/v2/userinfo"),
        ),
        None => (
            "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            "https://oauth2.googleapis.com/token".to_string(),
            "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
        ),
    }
}

/// 返回 (auth, token, user, emails)。覆盖时的路径正是 GitHub Enterprise 的约定。
fn github_endpoints(base: Option<&str>) -> (String, String, String, String) {
    match base {
        Some(b) => (
            format!("{b}/login/oauth/authorize"),
            format!("{b}/login/oauth/access_token"),
            format!("{b}/api/v3/user"),
            format!("{b}/api/v3/user/emails"),
        ),
        None => (
            "https://github.com/login/oauth/authorize".to_string(),
            "https://github.com/login/oauth/access_token".to_string(),
            "https://api.github.com/user".to_string(),
            "https://api.github.com/user/emails".to_string(),
        ),
    }
}

/// 把 URL 里的 `user:password@` 换成 `***@`，其余原样返回。
///
/// 代理地址常常带凭据，而这条日志是 info 级别 —— 会进日志收集、进工单附件。
/// 解析失败（不是 URL）时返回一个不含原文的占位串：宁可少一条线索，
/// 也不能把可能带口令的字符串原样打出去。
fn redact_credentials(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "<malformed proxy url>".to_string();
    };
    // authority 到第一个 '/'、'?' 或 '#' 为止。
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    match authority.rsplit_once('@') {
        Some((_creds, host)) => format!("{scheme}://***@{host}{tail}"),
        None => url.to_string(),
    }
}

impl OAuthService {
    pub fn new(config: Config) -> Result<Self> {
        let base = |v: &Option<String>| {
            v.as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let (google_auth, google_token, google_userinfo_url) =
            google_endpoints(base(&config.google_oauth_base_url).as_deref());
        let (github_auth, github_token, github_user_url, github_emails_url) =
            github_endpoints(base(&config.github_oauth_base_url).as_deref());

        // 回调地址在「配了 provider 就必须有」这条上由 Config 校验保证，
        // 这里取不到就等同于未配置。
        let redirect_base = config.oauth_redirect_url.clone();

        let google_client = if config.google_configured() {
            Some(
                BasicClient::new(ClientId::new(
                    config.google_client_id.clone().unwrap_or_default(),
                ))
                .set_client_secret(ClientSecret::new(
                    config.google_client_secret.clone().unwrap_or_default(),
                ))
                .set_auth_uri(
                    AuthUrl::new(google_auth).map_err(|e| AuthError::OAuthError(e.to_string()))?,
                )
                .set_token_uri(
                    TokenUrl::new(google_token)
                        .map_err(|e| AuthError::OAuthError(e.to_string()))?,
                )
                .set_redirect_uri(
                    RedirectUrl::new(format!(
                        "{}/google",
                        redirect_base.as_deref().unwrap_or_default()
                    ))
                    .map_err(|e| AuthError::OAuthError(e.to_string()))?,
                ),
            )
        } else {
            None
        };

        let github_client = if config.github_configured() {
            Some(
                BasicClient::new(ClientId::new(
                    config.github_client_id.clone().unwrap_or_default(),
                ))
                .set_client_secret(ClientSecret::new(
                    config.github_client_secret.clone().unwrap_or_default(),
                ))
                .set_auth_uri(
                    AuthUrl::new(github_auth).map_err(|e| AuthError::OAuthError(e.to_string()))?,
                )
                .set_token_uri(
                    TokenUrl::new(github_token)
                        .map_err(|e| AuthError::OAuthError(e.to_string()))?,
                )
                .set_redirect_uri(
                    RedirectUrl::new(format!(
                        "{}/github",
                        redirect_base.as_deref().unwrap_or_default()
                    ))
                    .map_err(|e| AuthError::OAuthError(e.to_string()))?,
                ),
            )
        } else {
            None
        };

        Ok(Self {
            config,
            google_client,
            github_client,
            google_userinfo_url,
            github_user_url,
            github_emails_url,
        })
    }

    // 创建一个配置了代理的 HTTP 客户端
    //
    // 注意：这里**不能**打开 `danger_accept_invalid_certs` —— 那等于对 Google /
    // GitHub 的 TLS 连接放弃证书校验，任何能插到链路中间的人都可以拿到授权码与
    // 访问令牌。自签名证书的场景请把 CA 加进系统信任库。
    fn create_http_client(&self) -> Result<Client> {
        // reqwest 默认**不设**任何超时。Google / GitHub（或一个配歪了的代理）一旦
        // 把连接吊住，回调 handler 就永远不返回，请求会一直堆着占住 tokio 任务和
        // 连接。这里给整个请求封顶。
        let mut client_builder = Client::builder()
            .timeout(std::time::Duration::from_secs(OUTBOUND_HTTP_TIMEOUT_SECS))
            .connect_timeout(std::time::Duration::from_secs(
                OUTBOUND_CONNECT_TIMEOUT_SECS,
            ));

        if self.config.proxy_enabled {
            if let Some(proxy_url) = &self.config.proxy_url {
                // 这里以前做两件错事：
                //
                //   let proxy_url = proxy_url.replace("https://", "http://");
                //   info!("Using proxy: {}", proxy_url);
                //
                // 一是把运维配的 https 代理**降级成明文**（而且是子串替换，
                // 不限于 scheme 位置）；二是把完整 PROXY_URL 打进日志，
                // 而代理地址里常常带 `user:password@`。
                //
                // 现在原样使用运维给的 scheme，日志只打脱敏后的地址。
                info!("Using proxy: {}", redact_credentials(proxy_url));
                client_builder = client_builder.proxy(Proxy::all(proxy_url).map_err(|e| {
                    AuthError::OAuthError(format!("Failed to create proxy: {}", e))
                })?);
            }
        }

        client_builder
            .build()
            .map_err(|e| AuthError::OAuthError(format!("Failed to create HTTP client: {}", e)))
    }

    /// 取某个 provider 的 client；未配置就是 501。
    ///
    /// 四个使用点共用这一处，错误文案只有一份 —— 分头写的话迟早出现
    /// 「入口说没配、回调说 OAuth 错误」这种自相矛盾的提示。
    fn client<'a>(
        client: &'a Option<ConfiguredClient>,
        provider: &str,
    ) -> Result<&'a ConfiguredClient> {
        client.as_ref().ok_or_else(|| {
            AuthError::NotConfigured(format!(
                "{provider} sign-in is not enabled on this deployment"
            ))
        })
    }

    /// 生成 Google 授权 URL。
    ///
    /// `state` 必须是调用方（`routes::oidc::create_oauth_state_token`）签发的令牌：
    /// 回调时会验签，以此实现真正的 CSRF 防护。以前这里自己生成一个随机
    /// `CsrfToken` 然后直接丢弃，回调侧根本没有可校验的东西。
    pub fn get_google_auth_url_with_state(&self, state: &str) -> Result<String> {
        let csrf_token = state.to_owned();
        let (auth_url, _) = Self::client(&self.google_client, "Google")?
            .authorize_url(|| CsrfToken::new(csrf_token))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_string(),
            ))
            .url();

        Ok(auth_url.to_string())
    }

    pub async fn handle_google_callback(&self, code: String) -> Result<OAuthUserInfo> {
        // 不要把 `code` 打进日志：授权码就是凭证，日志往往会外发到集中式平台，
        // 谁能读日志谁就能在它过期前抢先兑换成访问令牌。
        info!("Exchanging Google authorization code for access token");
        // 两条路径（走代理 / 不走代理）都用 `create_http_client`。以前不走代理时
        // 用的是 `async_http_client` 和 `Client::new()`，它们各自 new 一个默认
        // client —— 默认**没有超时**，等于把上面那份超时配置绕开了。
        let client = self.create_http_client()?;

        let exchange = {
            let client = client.clone();
            move |req| send_via_reqwest(client.clone(), req)
        };
        let token = Self::client(&self.google_client, "Google")?
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .request_async(&exchange)
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 使用访问令牌获取用户信息
        info!("Fetching user info from Google API");

        let user_info: GoogleUserInfo = match client
            .get(&self.google_userinfo_url)
            .bearer_auth(token.access_token().secret())
            .send()
            .await
        {
            Ok(response) => {
                info!("Received response from Google API");
                match response.json().await {
                    Ok(info) => {
                        info!("Successfully parsed user info");
                        info
                    }
                    Err(e) => {
                        error!("Failed to parse user info: {}", e);
                        return Err(AuthError::OAuthError(e.to_string()));
                    }
                }
            }
            Err(e) => {
                error!("Failed to fetch user info: {}", e);
                return Err(AuthError::OAuthError(e.to_string()));
            }
        };

        if !user_info.verified_email {
            error!("User email is not verified");
            return Err(AuthError::EmailNotVerified);
        }

        info!(
            "Successfully completed Google OAuth callback for user: {}",
            user_info.email
        );
        Ok(OAuthUserInfo {
            provider: "google".to_string(),
            provider_user_id: user_info.id,
            email: user_info.email,
            name: user_info.name,
            picture: user_info.picture,
        })
    }

    /// 生成 GitHub 授权 URL，`state` 语义同 Google。
    pub fn get_github_auth_url_with_state(&self, state: &str) -> Result<String> {
        let csrf_token = state.to_owned();
        let (auth_url, _) = Self::client(&self.github_client, "GitHub")?
            .authorize_url(|| CsrfToken::new(csrf_token))
            .add_scope(Scope::new("user:email".to_string()))
            .url();

        Ok(auth_url.to_string())
    }

    pub async fn handle_github_callback(&self, code: String) -> Result<OAuthUserInfo> {
        // 交换授权码获取访问令牌（同 Google：统一走带超时的 client）
        let client = self.create_http_client()?;

        let exchange = {
            let client = client.clone();
            move |req| send_via_reqwest(client.clone(), req)
        };
        let token = Self::client(&self.github_client, "GitHub")?
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .request_async(&exchange)
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 获取用户信息
        let user_info: GitHubUserInfo = client
            .get(&self.github_user_url)
            .bearer_auth(token.access_token().secret())
            .header("User-Agent", "soulauth")
            .send()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 获取用户邮箱（因为某些用户可能没有公开邮箱）
        let emails: Vec<GitHubEmail> = client
            .get(&self.github_emails_url)
            .bearer_auth(token.access_token().secret())
            .header("User-Agent", "soulauth")
            .send()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 获取主要且已验证的邮箱
        let primary_email = emails
            .into_iter()
            .find(|e| e.primary && e.verified)
            .ok_or(AuthError::EmailNotVerified)?;

        Ok(OAuthUserInfo {
            provider: "github".to_string(),
            provider_user_id: user_info.id.to_string(),
            email: primary_email.email,
            name: user_info.name,
            picture: user_info.avatar_url,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::OAuthService;
    use crate::config::Config;

    fn test_config() -> Config {
        Config::test_default()
    }

    #[test]
    fn google_auth_url_carries_the_supplied_signed_state() {
        let service = OAuthService::new(test_config()).expect("service");
        let signed_state = "eyJhbGciOiJIUzI1NiJ9.state.sig";

        let url = service
            .get_google_auth_url_with_state(signed_state)
            .expect("auth url");

        assert!(url.contains("state=eyJhbGciOiJIUzI1NiJ9.state.sig"));
    }

    #[test]
    fn endpoint_overrides_keep_each_providers_real_path_shape() {
        // 覆盖之所以只给一个根地址，前提就是路径形状照抄真实 provider；
        // 形状一旦被改歪，本地替身就不再是忠实替身，测过也说明不了什么。
        let (auth, token, userinfo) = super::google_endpoints(Some("http://127.0.0.1:8126"));
        assert_eq!(auth, "http://127.0.0.1:8126/o/oauth2/v2/auth");
        assert_eq!(token, "http://127.0.0.1:8126/token");
        assert_eq!(userinfo, "http://127.0.0.1:8126/oauth2/v2/userinfo");

        // GitHub 覆盖后的路径正是 GitHub Enterprise 的约定
        let (auth, token, user, emails) = super::github_endpoints(Some("https://ghe.example.com"));
        assert_eq!(auth, "https://ghe.example.com/login/oauth/authorize");
        assert_eq!(token, "https://ghe.example.com/login/oauth/access_token");
        assert_eq!(user, "https://ghe.example.com/api/v3/user");
        assert_eq!(emails, "https://ghe.example.com/api/v3/user/emails");
    }

    #[test]
    fn without_override_the_official_endpoints_are_used() {
        // 防的是「加了覆盖能力，结果默认路径也被顺手改掉」。
        let (auth, token, userinfo) = super::google_endpoints(None);
        assert_eq!(auth, "https://accounts.google.com/o/oauth2/v2/auth");
        assert_eq!(token, "https://oauth2.googleapis.com/token");
        assert_eq!(userinfo, "https://www.googleapis.com/oauth2/v2/userinfo");

        let (auth, token, user, emails) = super::github_endpoints(None);
        assert_eq!(auth, "https://github.com/login/oauth/authorize");
        assert_eq!(token, "https://github.com/login/oauth/access_token");
        assert_eq!(user, "https://api.github.com/user");
        assert_eq!(emails, "https://api.github.com/user/emails");
    }

    #[test]
    fn an_empty_override_is_treated_as_absent() {
        // `GOOGLE_OAUTH_BASE_URL=` 会读成 Some("")，若不当空处理，
        // 端点就变成 `/token` 这种没有主机名的地址，直接把换令牌打断。
        let mut config = test_config();
        config.google_oauth_base_url = Some("   ".to_string());
        let service = OAuthService::new(config).expect("service");
        assert_eq!(
            service.google_userinfo_url,
            "https://www.googleapis.com/oauth2/v2/userinfo"
        );
    }

    #[test]
    fn an_unconfigured_provider_reports_not_configured_rather_than_failing_later() {
        // 不配凭证时必须在入口就说清「本部署没开这个」，
        // 而不是拿空 client_id 一路走到换令牌才失败、还把错误指向 OAuth 库。
        let mut config = test_config();
        config.google_client_id = None;
        config.google_client_secret = None;
        let service = OAuthService::new(config).expect("service");

        let err = service
            .get_google_auth_url_with_state("state")
            .expect_err("must not hand out an auth url for an unconfigured provider");
        assert!(
            matches!(err, crate::error::AuthError::NotConfigured(_)),
            "expected NotConfigured, got {err:?}"
        );
    }

    #[test]
    fn one_provider_can_be_configured_without_the_other() {
        // 只用 GitHub 的部署不该被迫为 Google 填假凭证。
        let mut config = test_config();
        config.google_client_id = None;
        config.google_client_secret = None;
        let service = OAuthService::new(config).expect("service");

        assert!(service.get_github_auth_url_with_state("state").is_ok());
        assert!(service.get_google_auth_url_with_state("state").is_err());
    }

    #[test]
    fn github_auth_url_carries_the_supplied_signed_state() {
        let service = OAuthService::new(test_config()).expect("service");
        let signed_state = "eyJhbGciOiJIUzI1NiJ9.state.sig";

        let url = service
            .get_github_auth_url_with_state(signed_state)
            .expect("auth url");

        assert!(url.contains("state=eyJhbGciOiJIUzI1NiJ9.state.sig"));
    }

    use super::redact_credentials;

    #[test]
    fn proxy_credentials_never_reach_the_log() {
        assert_eq!(
            redact_credentials("http://user:pass@proxy.example:3128"),
            "http://***@proxy.example:3128"
        );
        assert_eq!(
            redact_credentials("https://user:pass@proxy.example:3128/path?q=1"),
            "https://***@proxy.example:3128/path?q=1"
        );
        // `@` 出现在路径里不算凭据，authority 段没有 `@` 就原样返回。
        assert_eq!(
            redact_credentials("http://proxy.example:3128/a@b"),
            "http://proxy.example:3128/a@b"
        );
        assert_eq!(
            redact_credentials("http://proxy.example:3128"),
            "http://proxy.example:3128"
        );
        // 解析不出来时宁可什么都不打，也不能把可能带口令的原文吐出去。
        assert_eq!(redact_credentials("not a url"), "<malformed proxy url>");
    }
}
