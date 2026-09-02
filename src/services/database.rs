use serde_json::Value as JsonValue;
use std::time::Duration;
use std::{
    env,
    fmt::Debug,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use surrealdb::engine::remote::http::{Client, Http, Https};
use surrealdb::opt::auth::Root;
use surrealdb::types::SurrealValue;
use surrealdb::{types::RecordId, Surreal};
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::{
    config::Config,
    error::{AuthError, Result},
};

#[derive(Clone)]
pub struct Database {
    pub client: Surreal<Client>,
    // 保存建连时用的原始 URL：重连必须连回同一个地址、同一个 scheme。
    // 以前 `fresh_client` 直接读 env::var("DATABASE_URL")，与构造时的 Config
    // 可能不一致 —— 那样 https 分派在重连路径上会被绕开。
    database_url: String,
    // Keep auth context so we can re-authenticate when tokens expire.
    database_user: String,
    database_pass: String,
    database_namespace: String,
    database_name: String,
    prefer_fresh_until_epoch: Arc<AtomicU64>,
}

impl Database {
    fn unix_now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    fn should_prefer_fresh(&self) -> bool {
        Self::unix_now_secs() < self.prefer_fresh_until_epoch.load(Ordering::Relaxed)
    }

    fn mark_prefer_fresh_for(&self, seconds: u64) {
        self.prefer_fresh_until_epoch
            .store(Self::unix_now_secs() + seconds, Ordering::Relaxed);
    }

    /// surrealdb 的 `Http` 连接器只接受 `host:port`，带上 `http://` 会被当成
    /// 主机名解析（报 "DNS resolution failed for http:80"）。而 README 和本文件
    /// 里的默认值一直写的是 `http://localhost:8000` —— 也就是照文档配置反而起不来。
    /// 这里统一剥掉 scheme，两种写法都能用。
    fn endpoint_without_scheme(raw: &str) -> String {
        let ep = raw.trim().trim_end_matches('/');
        ep.strip_prefix("http://")
            .or_else(|| ep.strip_prefix("https://"))
            .unwrap_or(ep)
            .to_string()
    }

    /// 端点是否要求 TLS。
    fn is_tls_endpoint(raw: &str) -> bool {
        raw.trim().to_ascii_lowercase().starts_with("https://")
    }

    /// 按 scheme 选连接器建连。
    ///
    /// 以前**只用 `Http`**：`endpoint_without_scheme` 先把 `https://` 剥掉，
    /// 然后一律走明文连接器。于是配 `DATABASE_URL=https://db.internal:8000`
    /// 的部署实际是明文连库 —— root 口令、每一条查询、所有密码哈希与会话令牌
    /// 都在链路上裸奔，而且没有任何提示。同一个进程里 `rpc_signin_token`
    /// 走的却是 `endpoint_with_scheme`，它是认 https 的：两套行为并存，
    /// 说明这是疏漏而不是取舍。
    ///
    /// surrealdb 3.0 的 `Https` 连接器与 `Http` 共用同一个 `Client` 类型，
    /// 所以这里只在建连这一步分派，其余代码不受影响。
    async fn connect(raw: &str) -> Result<Surreal<Client>> {
        let endpoint = Self::endpoint_without_scheme(raw);
        let result = if Self::is_tls_endpoint(raw) {
            Surreal::<Client>::new::<Https>(&endpoint).await
        } else {
            Surreal::<Client>::new::<Http>(&endpoint).await
        };
        result.map_err(|e| AuthError::DatabaseError(format!("Failed to connect: {e}")))
    }

    /// 明文连接非环回数据库时告警一次。
    ///
    /// 这里**不拒绝启动**（与 `check_oauth_base_url` 不同）：把 SurrealDB 放在
    /// 私有网络里不加 TLS 是常见且可接受的部署形态，硬拦会把所有存量部署挡在门外。
    /// 真正的缺陷是"配了 https 却静默降级"—— 那一条已由 `connect` 修掉。
    /// 剩下的是知情权，所以给一条明确的 WARN，而不是沉默。
    fn warn_if_plaintext_remote(raw: &str) {
        if Self::is_tls_endpoint(raw) {
            return;
        }
        let host = Self::endpoint_without_scheme(raw);
        let host_only = host.split(&[':', '/'][..]).next().unwrap_or(&host);
        let loopback = matches!(host_only, "127.0.0.1" | "localhost" | "::1" | "[")
            || host.starts_with("[::1]");
        if !loopback {
            warn!(
                "DATABASE_URL points at a non-loopback host over plaintext HTTP ({host});                  database credentials, password hashes and session tokens travel unencrypted.                  Use https:// (or keep the database on a private link you trust)."
            );
        }
    }

    fn endpoint_with_scheme(raw: &str) -> String {
        let ep = raw.trim().trim_end_matches('/');
        if ep.starts_with("http://") || ep.starts_with("https://") {
            ep.to_string()
        } else {
            format!("http://{}", ep)
        }
    }

    async fn rpc_signin_token(
        endpoint: &str,
        user: &str,
        pass: &str,
        ns: &str,
        db: &str,
    ) -> Result<String> {
        let endpoint = endpoint.trim_end_matches('/');
        let rpc_url = format!("{endpoint}/rpc");
        let payloads = [
            serde_json::json!({
                "id": 1,
                "method": "signin",
                "params": [{ "user": user, "pass": pass }]
            }),
            serde_json::json!({
                "id": 1,
                "method": "signin",
                "params": [{ "user": user, "pass": pass, "ns": ns, "db": db }]
            }),
        ];

        let mut last_error = String::new();
        for payload in payloads {
            let resp = reqwest::Client::new()
                .post(&rpc_url)
                .header("Content-Type", "application/json")
                .body(payload.to_string())
                .send()
                .await
                .map_err(|e| AuthError::DatabaseError(format!("RPC signin request failed: {e}")))?;

            let body = resp.text().await.map_err(|e| {
                AuthError::DatabaseError(format!("RPC signin response read failed: {e}"))
            })?;

            let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
                AuthError::DatabaseError(format!("RPC signin invalid json: {e}; body={body}"))
            })?;

            if let Some(token) = v.get("result").and_then(|x| x.as_str()) {
                return Ok(token.to_string());
            }
            if let Some(token) = v
                .get("result")
                .and_then(|x| x.get("access"))
                .and_then(|x| x.as_str())
            {
                return Ok(token.to_string());
            }

            last_error = v
                .get("error")
                .cloned()
                .unwrap_or(serde_json::Value::String(body))
                .to_string();
        }

        Err(AuthError::DatabaseError(format!(
            "Failed to authenticate: {}",
            last_error
        )))
    }

    fn is_unauthorized_error<E: std::fmt::Display>(err: &E) -> bool {
        let msg = err.to_string();
        msg.contains("401")
            || msg.contains("Unauthorized")
            || msg.contains("Failed to authenticate")
            || msg.contains("native signin failed")
            || msg.contains("rpc authenticate(token) failed")
            || msg.contains("rpc signin failed")
    }

    fn should_retry_verify_with_fresh<E: std::fmt::Display>(err: &E) -> bool {
        Self::is_unauthorized_error(err)
    }

    pub async fn fresh_client(&self) -> Result<Surreal<Client>> {
        let endpoint_raw = self.database_url.clone();
        let with_scheme = Self::endpoint_with_scheme(&endpoint_raw);
        let ns = self.database_namespace.trim().to_string();
        let db = self.database_name.trim().to_string();
        let user = self.database_user.trim().to_string();
        let pass = self.database_pass.trim().to_string();

        let client = Self::connect(&endpoint_raw).await.map_err(|e| {
            AuthError::DatabaseError(format!("Failed to connect fresh client: {e}"))
        })?;

        match client
            .signin(Root {
                username: user.clone(),
                password: pass.clone(),
            })
            .await
        {
            Ok(_) => {}
            Err(native_err) => {
                warn!(
                    "fresh client native signin failed for user={} ns={} db={}, fallback to rpc token auth: {}",
                    user, ns, db, native_err
                );
                let token = Self::rpc_signin_token(&with_scheme, &user, &pass, &ns, &db).await?;
                client.authenticate(token).await.map_err(|e| {
                    AuthError::DatabaseError(format!("Failed to authenticate fresh client: {e}"))
                })?;
            }
        }

        client.use_ns(&ns).use_db(&db).await.map_err(|e| {
            AuthError::DatabaseError(format!(
                "Failed to select namespace/database for fresh client: {e}"
            ))
        })?;

        Ok(client)
    }

    pub async fn reauth(&self) -> Result<()> {
        debug!("Re-authenticating with database (refresh token)");
        let stored_user = self.database_user.trim().to_string();
        let stored_pass = self.database_pass.trim().to_string();
        let stored_ns = self.database_namespace.trim().to_string();
        let stored_db = self.database_name.trim().to_string();

        let env_db_user = env::var("DATABASE_USER").ok().map(|v| v.trim().to_string());
        let env_db_pass = env::var("DATABASE_PASS").ok().map(|v| v.trim().to_string());
        let env_db_ns = env::var("DATABASE_NAMESPACE")
            .ok()
            .map(|v| v.trim().to_string());
        let env_db_name = env::var("DATABASE_NAME").ok().map(|v| v.trim().to_string());

        // 候选只有两组：构造时记下的那份，和当前环境里的 `DATABASE_*`。
        //
        // 这里原本还有第三组 `SURREAL_USER/PASS/NAMESPACE/DATABASE`。它们
        // **只在重连时**被读，初次连接不认，于是同一个进程的配置来源会随时间
        // 变化；而且四个名字没出现在任何部署文件、文档或测试里。删掉，
        // 配置来源就只剩 `DATABASE_*` 一套。
        let mut candidates: Vec<(String, String, String, String)> = Vec::new();
        candidates.push((
            stored_user.clone(),
            stored_pass.clone(),
            stored_ns.clone(),
            stored_db.clone(),
        ));
        if let (Some(u), Some(p)) = (env_db_user.clone(), env_db_pass.clone()) {
            let ns = env_db_ns.clone().unwrap_or_else(|| stored_ns.clone());
            let db = env_db_name.clone().unwrap_or_else(|| stored_db.clone());
            candidates.push((u, p, ns, db));
        }

        let mut last_err: Option<AuthError> = None;
        for (user, pass, ns, db) in candidates.into_iter() {
            if user.is_empty() || pass.is_empty() || ns.is_empty() || db.is_empty() {
                continue;
            }
            // Prefer native signin first (more stable on SurrealDB 3.x)
            let signin_result = match self
                .client
                .signin(Root {
                    username: user.clone(),
                    password: pass.clone(),
                })
                .await
            {
                Ok(_) => Ok(()),
                Err(native_err) => {
                    warn!(
                        "native signin failed for user={} ns={} db={}, fallback to rpc token auth: {}",
                        user, ns, db, native_err
                    );
                    let endpoint = Self::endpoint_with_scheme(&self.database_url);
                    match Self::rpc_signin_token(&endpoint, &user, &pass, &ns, &db).await {
                        Ok(token) => self
                            .client
                            .authenticate(token)
                            .await
                            .map(|_| ())
                            .map_err(|auth_err| {
                                AuthError::DatabaseError(format!(
                                    "native signin failed: {native_err}; rpc authenticate(token) failed: {auth_err}"
                                ))
                            }),
                        Err(rpc_err) => Err(AuthError::DatabaseError(format!(
                            "native signin failed: {native_err}; rpc signin failed: {rpc_err}"
                        ))),
                    }
                }
            };
            match signin_result {
                Ok(_) => {
                    self.client.use_ns(&ns).use_db(&db).await.map_err(|e| {
                        AuthError::DatabaseError(format!(
                            "Failed to select namespace/database after reauth: {e}"
                        ))
                    })?;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "Reauth attempt failed for user={} ns={} db={} (will try next if any): {}",
                        user, ns, db, e
                    );
                    last_err = Some(AuthError::DatabaseError(format!(
                        "Failed to authenticate: {e}"
                    )));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            AuthError::DatabaseError("Failed to authenticate: no valid credential candidate".into())
        }))
    }

    pub async fn retry_on_unauthorized<T, F, Fut>(&self, op_name: &str, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        match f().await {
            Ok(v) => Ok(v),
            Err(e) => {
                // SurrealDB may return 401 when the auth token expires.
                let msg = format!("{e}");
                if msg.contains("401") || msg.contains("Unauthorized") {
                    self.mark_prefer_fresh_for(300);
                    warn!("{op_name} failed with 401; caller should retry on fresh client");
                    Err(e)
                } else {
                    Err(e)
                }
            }
        }
    }

    pub async fn new(config: &Config) -> Result<Self> {
        let mut retry_count = 0;
        let max_retries = 5;
        let retry_delay = Duration::from_secs(1);

        loop {
            match Self::try_connect(config).await {
                Ok(db) => return Ok(db),
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        return Err(e);
                    }
                    warn!(
                        "Failed to connect to database (attempt {}/{}): {}",
                        retry_count, max_retries, e
                    );
                    sleep(retry_delay).await;
                }
            }
        }
    }

    async fn try_connect(config: &Config) -> Result<Self> {
        debug!("Connecting to database url={}", config.database_url);

        // 设置连接超时
        Self::warn_if_plaintext_remote(&config.database_url);
        let client = tokio::time::timeout(
            Duration::from_secs(config.database_connection_timeout),
            Self::connect(&config.database_url),
        )
        .await
        .map_err(|_| AuthError::DatabaseError("Database connection timeout".to_string()))??;

        debug!("Authenticating with database");
        // Prefer native signin first, fallback to RPC token authenticate.
        match tokio::time::timeout(
            Duration::from_secs(config.database_connection_timeout),
            client.signin(Root {
                username: config.database_user.clone(),
                password: config.database_pass.clone(),
            }),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(native_err)) => {
                warn!(
                    "Database native signin failed at startup, fallback to rpc token auth: {}",
                    native_err
                );
                let endpoint = Self::endpoint_with_scheme(&config.database_url);
                let token = tokio::time::timeout(
                    Duration::from_secs(config.database_connection_timeout),
                    Self::rpc_signin_token(
                        &endpoint,
                        &config.database_user,
                        &config.database_pass,
                        &config.database_namespace,
                        &config.database_name,
                    ),
                )
                .await
                .map_err(|_| {
                    AuthError::DatabaseError("Database authentication timeout".to_string())
                })??;
                client.authenticate(token).await.map_err(|e| {
                    AuthError::DatabaseError(format!("Failed to authenticate: {e}"))
                })?;
            }
            Err(_) => {
                return Err(AuthError::DatabaseError(
                    "Database authentication timeout".to_string(),
                ));
            }
        }

        debug!("Selecting namespace and database");
        client
            .use_ns(&config.database_namespace)
            .use_db(&config.database_name)
            .await
            .map_err(|e| {
                AuthError::DatabaseError(format!("Failed to select namespace/database: {}", e))
            })?;

        debug!("Database connection established successfully");
        Ok(Database {
            client,
            database_url: config.database_url.clone(),
            database_user: config.database_user.clone(),
            database_pass: config.database_pass.clone(),
            database_namespace: config.database_namespace.clone(),
            database_name: config.database_name.clone(),
            prefer_fresh_until_epoch: Arc::new(AtomicU64::new(0)),
        })
    }

    /// 验证数据库连接
    /// 注意：数据库schema应该通过schema.sql文件手动创建
    pub async fn verify_connection(&self) -> Result<()> {
        if self.should_prefer_fresh() {
            let fresh = self.fresh_client().await?;
            fresh.query("INFO FOR DB").await.map_err(|e| {
                AuthError::DatabaseError(format!("Database connection failed: {e}"))
            })?;
            debug!("Database connection verified successfully via fresh client");
            return Ok(());
        }

        match self
            .retry_on_unauthorized("verify_connection", || async {
                // 使用 INFO 查询验证数据库连接
                let query = "INFO FOR DB";
                self.client
                    .query(query)
                    .await
                    .and_then(|response| response.check())
                    .map_err(|e| {
                        AuthError::DatabaseError(format!("Database connection failed: {e}"))
                    })?;
                Ok(())
            })
            .await
        {
            Ok(()) => {}
            Err(err) if Self::should_retry_verify_with_fresh(&err) => {
                let fresh = self.fresh_client().await?;
                fresh.query("INFO FOR DB").await.map_err(|e| {
                    AuthError::DatabaseError(format!("Database connection failed: {e}"))
                })?;
                debug!(
                    "Database connection verified successfully via fresh client after auth refresh"
                );
                return Ok(());
            }
            Err(err) => return Err(err),
        }

        debug!("Database connection verified successfully");
        Ok(())
    }

    pub async fn create_record<T>(&self, table: &str, record: &T) -> Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Debug + SurrealValue + 'static,
    {
        debug!("Creating record in table {}: {:?}", table, record);

        if self.should_prefer_fresh() {
            let fresh = self.fresh_client().await?;
            let created: Option<T> = fresh
                .create(table)
                .content(record.clone())
                .await
                .map_err(|e| AuthError::DatabaseError(format!("Failed to create record: {}", e)))?;
            return created
                .ok_or_else(|| AuthError::DatabaseError("Failed to create record".into()));
        }

        let created: Option<T> = match self.client.create(table).content(record.clone()).await {
            Ok(created) => created,
            Err(err) if Self::is_unauthorized_error(&err) => {
                warn!("create_record failed with 401, retrying on fresh client");
                let fresh = self.fresh_client().await?;
                fresh
                    .create(table)
                    .content(record.clone())
                    .await
                    .map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to create record: {}", e))
                    })?
            }
            Err(err) => {
                return Err(AuthError::DatabaseError(format!(
                    "Failed to create record: {}",
                    err
                )));
            }
        };

        created.ok_or_else(|| AuthError::DatabaseError("Failed to create record".into()))
    }

    pub async fn find_record_by_field<T>(
        &self,
        table: &str,
        field: &str,
        value: &str,
    ) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + Clone + Debug + SurrealValue,
    {
        debug!(
            "Finding record in table {} where {} = {}",
            table, field, value
        );

        if field == "id" {
            let (rid_table, rid_key) = if let Some((tb, key_raw)) = value.split_once(':') {
                (
                    tb.to_string(),
                    key_raw
                        .trim()
                        .trim_matches('⟨')
                        .trim_matches('⟩')
                        .to_string(),
                )
            } else {
                (table.to_string(), value.to_string())
            };
            let rid = RecordId::new(rid_table, rid_key);
            let query = format!("SELECT * FROM {} WHERE id = $value", table);
            debug!("执行查询: {}", query);
            debug!("查询参数: value = {:?}", rid);

            if self.should_prefer_fresh() {
                let fresh = self.fresh_client().await?;
                let mut result = fresh
                    .query(&query)
                    .bind(("value", rid))
                    .await
                    .map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to execute id query: {e}"))
                    })?;
                let records: Vec<T> = result.take(0).map_err(|e| {
                    AuthError::DatabaseError(format!("Failed to parse id records: {e}"))
                })?;
                return Ok(records.into_iter().next());
            }

            match self
                .retry_on_unauthorized("find_record_by_field(id)", || async {
                    let mut result = self
                        .client
                        .query(&query)
                        .bind(("value", rid.clone()))
                        .await
                        .and_then(|response| response.check())
                        .map_err(|e| {
                            AuthError::DatabaseError(format!("Failed to execute id query: {e}"))
                        })?;

                    debug!("原始查询结果: {:?}", result);

                    let records: Vec<T> = result.take(0).map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to parse id records: {e}"))
                    })?;

                    debug!("解析后的记录: {:?}", records);
                    Ok(records.into_iter().next())
                })
                .await
            {
                Ok(result) => Ok(result),
                Err(err) if Self::is_unauthorized_error(&err) => {
                    warn!("find_record_by_field(id) retrying on fresh client");
                    let fresh = self.fresh_client().await?;
                    let mut result =
                        fresh
                            .query(&query)
                            .bind(("value", rid))
                            .await
                            .map_err(|e| {
                                AuthError::DatabaseError(format!("Failed to execute id query: {e}"))
                            })?;
                    let records: Vec<T> = result.take(0).map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to parse id records: {e}"))
                    })?;
                    Ok(records.into_iter().next())
                }
                Err(err) => Err(err),
            }
        } else {
            let query = format!("SELECT * FROM {} WHERE {} = $value", table, field);
            debug!("执行查询: {}", query);
            debug!("查询参数: value = {}", value);

            if self.should_prefer_fresh() {
                let fresh = self.fresh_client().await?;
                let mut result = fresh
                    .query(&query)
                    .bind(("value", value.to_string()))
                    .await
                    .map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to execute query: {e}"))
                    })?;
                let records: Vec<T> = result.take(0).map_err(|e| {
                    AuthError::DatabaseError(format!("Failed to parse records: {e}"))
                })?;
                return Ok(records.into_iter().next());
            }

            match self
                .retry_on_unauthorized("find_record_by_field", || async {
                    let mut result = self
                        .client
                        .query(&query)
                        .bind(("value", value.to_string()))
                        .await
                        .and_then(|response| response.check())
                        .map_err(|e| {
                            AuthError::DatabaseError(format!("Failed to execute query: {e}"))
                        })?;

                    debug!("原始查询结果: {:?}", result);

                    let records: Vec<T> = result.take(0).map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to parse records: {e}"))
                    })?;

                    debug!("解析后的记录: {:?}", records);
                    Ok(records.into_iter().next())
                })
                .await
            {
                Ok(result) => Ok(result),
                Err(err) if Self::is_unauthorized_error(&err) => {
                    warn!("find_record_by_field retrying on fresh client");
                    let fresh = self.fresh_client().await?;
                    let mut result = fresh
                        .query(&query)
                        .bind(("value", value.to_string()))
                        .await
                        .map_err(|e| {
                            AuthError::DatabaseError(format!("Failed to execute query: {e}"))
                        })?;
                    let records: Vec<T> = result.take(0).map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to parse records: {e}"))
                    })?;
                    Ok(records.into_iter().next())
                }
                Err(err) => Err(err),
            }
        }
    }

    pub async fn update_record<T>(&self, table: &str, id: &str, record: &T) -> Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Debug + SurrealValue + 'static,
    {
        debug!(
            "Updating record in table {} with id {}: {:?}",
            table, id, record
        );

        if self.should_prefer_fresh() {
            let fresh = self.fresh_client().await?;
            let updated = if let Some((tb, key_raw)) = id.split_once(':') {
                let key = key_raw.trim().trim_matches('⟨').trim_matches('⟩');
                let rid = RecordId::new(tb, key);
                fresh.update(rid).content(record.clone()).await
            } else {
                let rid = RecordId::new(table, id);
                fresh.update(rid).content(record.clone()).await
            }
            .map_err(|e| AuthError::DatabaseError(format!("Failed to update record: {}", e)))?;

            return updated.ok_or_else(|| AuthError::DatabaseError("Record not found".into()));
        }

        let updated = match if let Some((tb, key_raw)) = id.split_once(':') {
            let key = key_raw.trim().trim_matches('⟨').trim_matches('⟩');
            let rid = RecordId::new(tb, key);
            self.client.update(rid).content(record.clone()).await
        } else {
            let rid = RecordId::new(table, id);
            self.client.update(rid).content(record.clone()).await
        } {
            Ok(updated) => updated,
            Err(err) if Self::is_unauthorized_error(&err) => {
                warn!("update_record failed with 401, retrying on fresh client");
                let fresh = self.fresh_client().await?;
                if let Some((tb, key_raw)) = id.split_once(':') {
                    let key = key_raw.trim().trim_matches('⟨').trim_matches('⟩');
                    let rid = RecordId::new(tb, key);
                    fresh.update(rid).content(record.clone()).await
                } else {
                    let rid = RecordId::new(table, id);
                    fresh.update(rid).content(record.clone()).await
                }
                .map_err(|e| AuthError::DatabaseError(format!("Failed to update record: {}", e)))?
            }
            Err(err) => {
                return Err(AuthError::DatabaseError(format!(
                    "Failed to update record: {}",
                    err
                )));
            }
        };

        updated.ok_or_else(|| AuthError::DatabaseError("Record not found".into()))
    }

    pub async fn delete_record<T>(&self, table: &str, id: &str) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + Clone + Debug + SurrealValue,
    {
        debug!("Deleting record from table {} with id {}", table, id);

        let rid = RecordId::new(table, id);
        let deleted = self
            .client
            .delete(rid)
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to delete record: {}", e)))?;

        Ok(deleted)
    }

    /// 删除单条会话（登出）。
    ///
    /// 走 `raw_query` 而不是直接用 `self.client`：前者会 `.check()` 语句级错误、
    /// 并在鉴权态过期时换新连接重试。以前这里是裸调用，写失败会被吞掉 ——
    /// 登出接口照样返回成功，`session` 行却还在，令牌一直有效到自然过期。
    /// 下面两个同族函数本来就是这么写的，唯独这个漏了。
    pub async fn delete_session_by_token(&self, token: &str) -> Result<()> {
        self.raw_query(
            "delete_session_by_token",
            "DELETE session WHERE token_hash = $session_token_hash",
            serde_json::json!({ "session_token_hash": crate::utils::crypto::hash_bearer(token) }),
        )
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to delete session: {}", e)))?;
        Ok(())
    }

    /// 把一个 user id 解析成它的**身份根** record id。
    ///
    /// Stage 3 把外键从 `user` 迁到 `actor_identity` 之后，凡是要写这些外键
    /// 的地方都需要 actor ref，而多数调用方手里只有 user id。这条解析收口在
    /// 这里，不散到各个服务里各写一遍。
    ///
    /// `user.subject_id` 自 Stage 2 起指向身份根，所以只需一次查表。取不到
    /// 说明这个 user 行还没挂上身份根 —— 那是数据完整性问题，不是「找不到」。
    pub async fn actor_ref_of_user(&self, user_id: &str) -> Result<RecordId> {
        let refs: Vec<RecordId> = self
            .query_take0_vec(
                "actor_ref_of_user",
                "SELECT VALUE subject_id FROM type::record('user', $user_key)",
                serde_json::json!({
                    "user_key": crate::utils::record_id::normalize_user_id(user_id),
                }),
            )
            .await?;
        refs.into_iter().next().ok_or_else(|| {
            AuthError::DatabaseError(format!("user {user_id} 没有关联的 actor_identity"))
        })
    }

    /// 删除某用户的全部会话（全端登出、改密后强制下线）。
    ///
    /// 会话自 Stage 3 起归属**身份根**而不是 user 行，但四个调用方手里拿到的
    /// 都还是 user id。与其让每处各查一次 actor，不如在这里做一次子查询 ——
    /// 改动收口在一处，调用方签名不动。
    ///
    /// 必须用 `type::record(table, id)` 两参形式：单参形式会把
    /// `"user:e81b4aa8-05f6-..."` 在第一个连字符处截断成 `user:e81b4aa8`，
    /// 于是条件永远匹配不到任何行 —— 全端登出和改密下线都会变成空操作。
    pub async fn delete_sessions_by_user_id(&self, user_id: &str) -> Result<()> {
        self.raw_query(
            "delete_sessions_by_user_id",
            "DELETE session WHERE user_id = \
             (SELECT VALUE subject_id FROM type::record('user', $user_key))[0]",
            serde_json::json!({
                "user_key": crate::utils::record_id::normalize_user_id(user_id),
            }),
        )
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to delete sessions: {}", e)))?;
        Ok(())
    }

    /// 列出某用户**仍然有效**的会话。两参形式的原因同 `delete_sessions_by_user_id`。
    ///
    /// `expires_at > $now` 这个条件不能省：这个接口的用途正是让用户核对
    /// "我还在哪些设备上登录着"，据此判断账号有没有被盗用。以前它不过滤过期行，
    /// 把早就失效的会话一并列出（实测：4 条里 3 条已过期，接口返回 4 条）——
    /// 展示的东西不对，这个功能就起了反作用。
    ///
    /// LIMIT 同样是必要的：`session` 行此前只增不减，重度用户能攒出很长一串。
    pub async fn get_sessions_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Vec<crate::models::session::Session>> {
        let mut result = self
            .raw_query(
                "get_sessions_by_user_id",
                "SELECT * FROM session \
                 WHERE user_id = (SELECT VALUE subject_id FROM type::record('user', $user_key))[0] \
                 AND expires_at > $now \
                 ORDER BY created_at DESC LIMIT 200",
                serde_json::json!({
                    "user_key": crate::utils::record_id::normalize_user_id(user_id),
                    "now": chrono::Utc::now().timestamp(),
                }),
            )
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to query sessions: {}", e)))?;

        result
            .take(0)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse sessions: {}", e)))
    }

    /// 启动自检：确认 schema 与种子数据确实落在**本进程连接的这个 ns/db** 上。
    ///
    /// `verify_connection` 只跑 `INFO FOR DB`，一个完全空的库照样通过。于是配错
    /// 命名空间的部署会「看起来一切正常」：进程起来、`/health` 返回 ok，
    /// 直到第一个用户请求才 500。实测过一次 —— 部署文档让你把 schema 导进
    /// `ns=production/db=auth`，而应用默认连 `ns=auth/db=main`，
    /// 注册接口直接 500 "Database error"，错误信息里没有任何线索指向 ns/db。
    ///
    /// 这里把那个运行期 500 提前成启动期的一句话，并且**把实际用的 ns/db 打出来**
    /// —— 那正是排查时唯一需要的信息。
    ///
    /// 判据用种子数据里的 `role:admin`：它同时覆盖两种失败（schema 没导 →
    /// 表不存在，查询报错；schema 导了但 initial_data 没导 → 查得到表、没有行）。
    /// 两种情况下运维要做的事是一样的，所以不必区分。
    pub async fn ensure_schema_initialised(&self) -> Result<()> {
        let rows: Vec<JsonValue> = self
            .query_take0_vec(
                "ensure_schema_initialised",
                "SELECT count() AS count FROM role WHERE name = 'admin' GROUP ALL",
                serde_json::json!({}),
            )
            .await
            .unwrap_or_default();

        let seeded = rows
            .first()
            .and_then(|row| row.get("count"))
            .and_then(|count| count.as_u64())
            .unwrap_or(0)
            > 0;

        if seeded {
            return Ok(());
        }

        Err(AuthError::ServerError(format!(
            "Database `{ns}` / `{db}` is not initialised: the seeded `admin` role is missing. \
             Apply schema.sql and initial_data.sql to **this** namespace and database, e.g.\n  \
             surreal import --endpoint {endpoint} --user <u> --pass <p> \
             --namespace {ns} --database {db} schema.sql\n  \
             surreal import --endpoint {endpoint} --user <u> --pass <p> \
             --namespace {ns} --database {db} initial_data.sql\n\
             (namespace/database come from DATABASE_NAMESPACE / DATABASE_NAME; \
             importing into a different one is the most common cause of this.)",
            ns = self.database_namespace,
            db = self.database_name,
            endpoint = Self::endpoint_with_scheme(&self.database_url),
        )))
    }

    /// 回收过期会话与失效的密码重置令牌。由每小时的后台任务调用。
    ///
    /// 这两张表此前**没有任何清理路径**：`session` 只在登出（按 token）与停用
    /// （按 user）时被删，`password_reset_token` 全代码库一条 DELETE 都没有，
    /// 用过的只是标记 `used = true`。两张都随时间单调增长，而
    /// `session.token_hash` 上还有一个 UNIQUE 索引，每个已认证请求都要查它。
    ///
    /// 两张表现在都只存 SHA-256 指纹（见 `utils::crypto::hash_bearer`），
    /// 但清理仍然必要：索引会随行数单调变大，而过期记录没有任何用处。
    pub async fn cleanup_expired_auth_artifacts(&self) -> Result<()> {
        let now = chrono::Utc::now();

        self.raw_query(
            "cleanup_expired_sessions",
            "DELETE session WHERE expires_at < $now",
            serde_json::json!({ "now": now.timestamp() }),
        )
        .await?;

        // `expires_at` 在这张表里是 datetime 列（与 session 的 number 不同），
        // 所以要走 type::datetime 而不是时间戳。
        self.raw_query(
            "cleanup_spent_password_reset_tokens",
            "DELETE password_reset_token \
             WHERE used = true OR expires_at < type::datetime($now_rfc3339)",
            serde_json::json!({ "now_rfc3339": now.to_rfc3339() }),
        )
        .await?;

        Ok(())
    }

    pub async fn raw_query(
        &self,
        op: &str,
        sql: &str,
        bindings: JsonValue,
    ) -> Result<surrealdb::IndexedResults> {
        if self.should_prefer_fresh() {
            let fresh = self.fresh_client().await?;
            return fresh
                .query(sql)
                .bind(bindings)
                .await
                .and_then(|response| response.check())
                .map_err(|e| AuthError::DatabaseError(format!("Failed to execute query: {e}")));
        }

        let bindings_for_retry = bindings.clone();
        match self
            .retry_on_unauthorized(op, || {
                let bindings = bindings_for_retry.clone();
                async move {
                    self.client
                        .query(sql)
                        .bind(bindings)
                        .await
                        .and_then(|response| response.check())
                        .map_err(|e| {
                            AuthError::DatabaseError(format!("Failed to execute query: {e}"))
                        })
                }
            })
            .await
        {
            Ok(response) => Ok(response),
            Err(err) if Self::is_unauthorized_error(&err) => {
                warn!("{op} retrying on fresh client");
                let fresh = self.fresh_client().await?;
                fresh
                    .query(sql)
                    .bind(bindings)
                    .await
                    .and_then(|response| response.check())
                    .map_err(|e| AuthError::DatabaseError(format!("Failed to execute query: {e}")))
            }
            Err(err) => Err(err),
        }
    }

    pub async fn raw_query_no_bind(
        &self,
        op: &str,
        sql: &str,
    ) -> Result<surrealdb::IndexedResults> {
        self.raw_query(op, sql, JsonValue::Object(Default::default()))
            .await
    }

    pub async fn query_take0_vec<T>(
        &self,
        op: &str,
        sql: &str,
        bindings: JsonValue,
    ) -> Result<Vec<T>>
    where
        T: serde::de::DeserializeOwned + surrealdb_types::SurrealValue,
    {
        let mut response = self.raw_query(op, sql, bindings).await?;
        response
            .take::<Vec<T>>(0usize)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse query result: {e}")))
    }

    pub async fn query_take0_option<T>(
        &self,
        op: &str,
        sql: &str,
        bindings: JsonValue,
    ) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + surrealdb_types::SurrealValue,
    {
        let mut response = self.raw_query(op, sql, bindings).await?;
        response
            .take::<Option<T>>(0usize)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse query result: {e}")))
    }

    pub async fn query_take0_vec_no_bind<T>(&self, op: &str, sql: &str) -> Result<Vec<T>>
    where
        T: serde::de::DeserializeOwned + surrealdb_types::SurrealValue,
    {
        self.query_take0_vec(op, sql, JsonValue::Object(Default::default()))
            .await
    }

    pub async fn query_take0_option_no_bind<T>(&self, op: &str, sql: &str) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + surrealdb_types::SurrealValue,
    {
        self.query_take0_option(op, sql, JsonValue::Object(Default::default()))
            .await
    }

    /// 公开的查询构造器，供其他服务使用。
    ///
    /// 注意：这里返回的是**未执行**的构造器，`.check()` 只能由调用方在 `.await`
    /// 之后自己加。需要自动 check + 401 重试的场合请优先用 `raw_query`。
    /// 当前无调用点，保留仅为对外扩展。
    #[allow(dead_code)]
    pub fn query<'a>(&'a self, sql: &'a str) -> surrealdb::method::Query<'a, Client> {
        self.client.query(sql)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_without_scheme_accepts_both_forms() {
        assert_eq!(
            Database::endpoint_without_scheme("http://localhost:8000"),
            "localhost:8000"
        );
        assert_eq!(
            Database::endpoint_without_scheme("https://db.example:8000/"),
            "db.example:8000"
        );
        assert_eq!(
            Database::endpoint_without_scheme(" 127.0.0.1:8000 "),
            "127.0.0.1:8000"
        );
    }

    #[test]
    fn endpoint_with_scheme_adds_http_when_missing() {
        assert_eq!(
            Database::endpoint_with_scheme("127.0.0.1:8000"),
            "http://127.0.0.1:8000"
        );
        assert_eq!(
            Database::endpoint_with_scheme("https://db.example:8000/"),
            "https://db.example:8000"
        );
    }

    #[test]
    fn verify_connection_retries_with_fresh_client_for_expired_auth() {
        let error = AuthError::DatabaseError(
            "Database connection failed: HTTP status client error (401 Unauthorized)".to_string(),
        );

        assert!(Database::should_retry_verify_with_fresh(&error));
    }
}
