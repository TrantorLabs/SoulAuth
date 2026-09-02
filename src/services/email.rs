use crate::{
    config::Config,
    error::{AuthError, Result},
};
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use std::time::Duration;

pub struct EmailService {
    config: Config,
}

impl EmailService {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    fn create_transport(&self) -> Result<SmtpTransport> {
        tracing::info!(
            "SMTP transport config host={} port={} insecure={} username_set={}",
            self.config.smtp_host,
            self.config.smtp_port,
            self.config.smtp_insecure,
            !self.config.smtp_username.trim().is_empty()
        );
        let creds = if !self.config.smtp_username.trim().is_empty()
            || !self.config.smtp_password.trim().is_empty()
        {
            Some(Credentials::new(
                self.config.smtp_username.clone(),
                self.config.smtp_password.clone(),
            ))
        } else {
            None
        };

        // 这里曾经在每次发信时 `std::env::set_var` 改四个代理环境变量。两个问题：
        // 一是 `setenv` 在多线程进程里不安全 —— 另一个线程正好在 `getenv` 时就是
        // 数据竞争，而这个函数跑在 tokio 的工作线程上；二是根本没用，lettre 的 SMTP
        // 走的是裸 TCP，不认 HTTP_PROXY。需要经代理发信请在网络层做转发。

        let transport = if self.config.smtp_insecure {
            let mut builder = SmtpTransport::builder_dangerous(&self.config.smtp_host)
                .port(self.config.smtp_port)
                .timeout(Some(Duration::from_secs(60)));
            if let Some(creds) = creds {
                builder = builder.credentials(creds);
            }
            builder.build()
        } else {
            let mut builder = SmtpTransport::starttls_relay(&self.config.smtp_host)
                .map_err(|e| {
                    AuthError::ServerError(format!("Failed to create SMTP transport: {}", e))
                })?
                .port(self.config.smtp_port)
                .timeout(Some(Duration::from_secs(60)));
            if let Some(creds) = creds {
                builder = builder.credentials(creds);
            }
            builder.build()
        };

        Ok(transport)
    }

    /// 把阻塞式的 SMTP 发送挪到阻塞线程池。
    ///
    /// `lettre::SmtpTransport::send` 是同步的，超时还设到了 60 秒。直接在 async fn
    /// 里调用会把整个 tokio 工作线程占死那么久 —— 核数不多的机器上，几封发不出去的
    /// 邮件就能让全站停止响应。
    async fn send_blocking(&self, email: Message) -> Result<()> {
        let transport = self.create_transport()?;

        tokio::task::spawn_blocking(move || {
            transport
                .send(&email)
                .map_err(|e| AuthError::ServerError(format!("Failed to send email: {}", e)))
        })
        .await
        .map_err(|e| AuthError::ServerError(format!("Email task panicked: {e}")))??;

        Ok(())
    }

    pub async fn send_verification_email(&self, to_email: &str, token: &str) -> Result<()> {
        let from_address = self
            .config
            .smtp_from
            .parse::<Mailbox>()
            .map_err(|e| AuthError::ServerError(format!("Invalid from address: {}", e)))?;

        let to_address = to_email
            .parse::<Mailbox>()
            .map_err(|e| AuthError::ServerError(format!("Invalid to address: {}", e)))?;

        // 指向前端页面，由它去调 `GET /api/auth/verify-email/{token}`。
        // 以前这里直接给的是 API 地址，用户点开只会看到一段 JSON
        // ——而且响应体里还带着刚签发的访问令牌。
        let page = self.config.verify_email_page_url();
        let separator = if page.contains('?') { '&' } else { '?' };
        let verification_link = format!("{page}{separator}token={}", urlencoding::encode(token));

        let email = Message::builder()
            .from(from_address)
            .to(to_address)
            .subject("Verify your email address")
            .header(ContentType::TEXT_HTML)
            .body(format!(
                r#"
                <h1>Welcome!</h1>
                <p>Please click the link below to verify your email address:</p>
                <p><a href="{}">Verify Email</a></p>
                <p>If you didn't create an account, you can safely ignore this email.</p>
                "#,
                verification_link
            ))
            .map_err(|e| AuthError::ServerError(format!("Failed to build email: {}", e)))?;

        self.send_blocking(email).await
    }

    pub async fn send_password_reset_email(&self, to_email: &str, token: &str) -> Result<()> {
        let from_address = self
            .config
            .smtp_from
            .parse::<Mailbox>()
            .map_err(|e| AuthError::ServerError(format!("Invalid from address: {}", e)))?;

        let to_address = to_email
            .parse::<Mailbox>()
            .map_err(|e| AuthError::ServerError(format!("Invalid to address: {}", e)))?;

        // 页面地址可覆盖，令牌仍然走路径段。
        //
        // 没有跟验证信统一成 `?token=`：那会让所有已经按
        // `/reset-password/:token` 建好路由的前端在升级后全部 404。
        // 默认值 `{app_url}/reset-password` 拼出来与改动前逐字相同。
        let page = self.config.reset_password_page_url();
        let reset_link = format!(
            "{}/{}",
            page.trim_end_matches('/'),
            urlencoding::encode(token)
        );

        let email = Message::builder()
            .from(from_address)
            .to(to_address)
            .subject("Reset your password")
            .header(ContentType::TEXT_HTML)
            .body(format!(
                r#"
                <h1>Password Reset Request</h1>
                <p>You have requested to reset your password. Click the link below to set a new password:</p>
                <p><a href="{}">Reset Password</a></p>
                <p>If you didn't request this, you can safely ignore this email.</p>
                <p>This link will expire in 1 hour.</p>
                "#,
                reset_link
            ))
            .map_err(|e| AuthError::ServerError(format!("Failed to build email: {}", e)))?;

        self.send_blocking(email).await
    }
}
