use crate::{
    config::Config,
    error::{AuthError, Result},
    models::mfa::{
        EnableTotpRequest, MfaMethod, MfaStatus, MfaStatusResponse, MfaVerificationResponse,
        TotpSetupResponse, UseBackupCodeRequest, UserMfa, VerifyTotpRequest,
    },
    services::database::Database,
    utils::crypto::{constant_time_eq, hash_backup_code, verify_backup_code, SecretCipher},
};
use chrono::Utc;
use qrcode::{render::svg, QrCode};
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::{debug, error, info, warn};

/// TOTP 的时间步长（秒），与 `TOTP::new` 的 `step` 参数保持一致。
const TOTP_STEP_SECS: i64 = 30;

/// 在 `now` 前后各一步的窗口里找出 `code` 命中的时间步。
///
/// 窗口宽度对应 `TOTP::new(.., skew = 1, ..)`。抽成自由函数是为了能脱离
/// 数据库单测——重放拒绝依赖的正是这里返回的步长。
fn match_totp_step(totp: &TOTP, code: &str, now: i64) -> Option<i64> {
    let current_step = now.div_euclid(TOTP_STEP_SECS);

    for offset in [-1i64, 0, 1] {
        let step = current_step + offset;
        if step < 0 {
            continue;
        }
        let expected = totp.generate((step * TOTP_STEP_SECS) as u64);
        // 定长比较，避免按字符早退泄露前缀信息。
        if constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            return Some(step);
        }
    }

    None
}

/// MFA服务
pub struct MfaService {
    db: Database,
    /// TOTP 密钥的静态加密器。
    cipher: SecretCipher,
}

impl MfaService {
    /// 创建新的MFA服务实例
    pub fn new(db: Arc<Database>, config: Config) -> Result<Self> {
        Ok(Self {
            db: (*db).clone(),
            cipher: SecretCipher::from_config(&config)?,
        })
    }

    /// 为用户初始化TOTP设置
    pub async fn setup_totp(&self, user_id: &str) -> Result<TotpSetupResponse> {
        info!("Setting up TOTP for user: {}", user_id);

        // 检查用户是否已经启用MFA
        if let Ok(existing_mfa) = self.get_user_mfa(user_id).await {
            if existing_mfa.status == MfaStatus::Enabled {
                return Err(AuthError::ServerError("MFA already enabled".to_string()));
            }
        }

        // 生成TOTP密钥。
        // 注意 rng 必须在 await 之前析构：ThreadRng 不是 Send，
        // 跨 await 持有会让整个 handler future 变成 !Send，路由注册直接编译不过。
        let secret_bytes: Vec<u8> = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            (0..20).map(|_| rng.gen()).collect()
        };
        let secret_str =
            base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret_bytes);
        let secret = Secret::Encoded(secret_str.clone());

        // 创建TOTP实例
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().unwrap(),
            Some("RustAuth".to_string()),
            user_id.to_string(),
        )?;

        // 生成QR码
        let qr_code_url = totp.get_url();
        let qr_code = QrCode::new(&qr_code_url)
            .map_err(|e| AuthError::ServerError(format!("Failed to generate QR code: {}", e)))?;

        let qr_svg = qr_code
            .render::<svg::Color>()
            .min_dimensions(200, 200)
            .build();

        // 转换为数据URL
        use base64::{engine::general_purpose, Engine as _};
        let qr_data_url = format!(
            "data:image/svg+xml;base64,{}",
            general_purpose::STANDARD.encode(qr_svg)
        );

        // 生成备用恢复代码：明文只在这一次返回给用户，库里存 Argon2 哈希。
        let backup_codes = UserMfa::generate_backup_codes();
        let hashed_backup_codes = backup_codes
            .iter()
            .map(|code| hash_backup_code(code))
            .collect::<Result<Vec<_>>>()?;

        // 保存MFA配置到数据库（状态为Pending）
        let mfa_config = UserMfa {
            user_id: user_id.to_string(),
            status: MfaStatus::Pending,
            method: MfaMethod::Totp,
            totp_secret: Some(self.cipher.encrypt(&secret_str)?),
            backup_codes: hashed_backup_codes,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_at: None,
            // 换了新密钥，旧的重放水位随之作废。
            last_totp_step: None,
        };

        self.save_user_mfa(&mfa_config).await?;

        info!("TOTP setup completed for user: {}", user_id);

        Ok(TotpSetupResponse {
            secret: secret_str,
            qr_code: qr_data_url,
            backup_codes,
        })
    }

    /// 启用TOTP（验证初始化时的代码）
    pub async fn enable_totp(&self, user_id: &str, request: EnableTotpRequest) -> Result<bool> {
        info!("Enabling TOTP for user: {}", user_id);

        // 获取用户MFA配置
        let mfa_config = self.get_user_mfa(user_id).await?;

        if mfa_config.status != MfaStatus::Pending {
            return Err(AuthError::ServerError(
                "TOTP not in pending state".to_string(),
            ));
        }

        // 状态切换折进同一条语句：另起一次整体 UPSERT 会把刚推进的水位写回去。
        if self
            .accept_totp_code(&mfa_config, &request.totp_code, ", status = 'Enabled'")
            .await?
        {
            info!("TOTP enabled successfully for user: {}", user_id);
            Ok(true)
        } else {
            error!("Invalid TOTP code for user: {}", user_id);
            Ok(false)
        }
    }

    /// 验证TOTP代码
    pub async fn verify_totp(
        &self,
        user_id: &str,
        request: VerifyTotpRequest,
    ) -> Result<MfaVerificationResponse> {
        debug!("Verifying TOTP for user: {}", user_id);

        let mfa_config = self.get_user_mfa(user_id).await?;

        if mfa_config.status != MfaStatus::Enabled {
            return Ok(MfaVerificationResponse {
                verified: false,
                token: None,
                message: Some("MFA not enabled".to_string()),
            });
        }

        // 不再 `save_user_mfa`：水位、last_used_at、密钥重加密都已经在那条
        // 原子语句里写完了，再来一次整体 UPSERT 只会把并发对手推进的水位写回去。
        if self
            .accept_totp_code(&mfa_config, &request.totp_code, "")
            .await?
        {
            info!("TOTP verification successful for user: {}", user_id);

            Ok(MfaVerificationResponse {
                verified: true,
                token: None, // 将在上层生成JWT token
                message: None,
            })
        } else {
            error!("Invalid TOTP code for user: {}", user_id);

            Ok(MfaVerificationResponse {
                verified: false,
                token: None,
                message: Some("Invalid TOTP code".to_string()),
            })
        }
    }

    /// 使用备用恢复代码
    pub async fn use_backup_code(
        &self,
        user_id: &str,
        request: UseBackupCodeRequest,
    ) -> Result<MfaVerificationResponse> {
        info!("Using backup code for user: {}", user_id);

        let mfa_config = self.get_user_mfa(user_id).await?;

        if mfa_config.status != MfaStatus::Enabled {
            return Ok(MfaVerificationResponse {
                verified: false,
                token: None,
                message: Some("MFA not enabled".to_string()),
            });
        }

        // 逐条哈希比对；命中即消费掉该条。
        let hit = mfa_config
            .backup_codes
            .iter()
            .find(|stored| verify_backup_code(stored, &request.backup_code));

        if let Some(used) = hit {
            // 消费必须是原子的。这里以前是「按下标从内存数组里 remove →
            // 整体 UPSERT 写回」：两个并发请求会都命中同一条、都判定通过、
            // 都签发会话，而备用码按定义是一次性的。
            //
            // 改成一条带 `WHERE` 的 UPDATE，按**值**（哈希串本身，逐条加盐所以
            // 唯一）移除，而不是按下标 —— 按下标的话，另一条码被并发消费导致
            // 数组前移，就会把本来有效的码误判成失效。
            if !self.consume_backup_code(&mfa_config.user_id, used).await? {
                warn!("Backup code was already consumed concurrently for user: {user_id}");
                return Ok(MfaVerificationResponse {
                    verified: false,
                    token: None,
                    message: Some("Invalid backup code".to_string()),
                });
            }

            info!("Backup code used successfully for user: {}", user_id);

            Ok(MfaVerificationResponse {
                verified: true,
                token: None, // 将在上层生成JWT token
                message: None,
            })
        } else {
            error!("Invalid backup code for user: {}", user_id);

            Ok(MfaVerificationResponse {
                verified: false,
                token: None,
                message: Some("Invalid backup code".to_string()),
            })
        }
    }

    /// 禁用MFA
    pub async fn disable_mfa(&self, user_id: &str) -> Result<bool> {
        info!("Disabling MFA for user: {}", user_id);

        let mfa_config = self.get_user_mfa(user_id).await?;

        if mfa_config.status == MfaStatus::Disabled {
            return Ok(true);
        }

        // 删除MFA配置
        self.delete_user_mfa(user_id).await?;

        info!("MFA disabled successfully for user: {}", user_id);
        Ok(true)
    }

    /// 获取用户MFA状态
    pub async fn get_mfa_status(&self, user_id: &str) -> Result<MfaStatusResponse> {
        match self.get_user_mfa(user_id).await {
            Ok(mfa_config) => Ok(MfaStatusResponse {
                enabled: mfa_config.status == MfaStatus::Enabled,
                method: Some(mfa_config.method),
                backup_codes_count: mfa_config.backup_codes.len() as u32,
                last_used_at: mfa_config.last_used_at,
            }),
            Err(AuthError::UserNotFound) => Ok(MfaStatusResponse {
                enabled: false,
                method: None,
                backup_codes_count: 0,
                last_used_at: None,
            }),
            Err(e) => Err(e),
        }
    }

    /// 返回用户已启用的 MFA 方式；没有配置则返回 `Ok(None)`。
    ///
    /// 登录链路用它决定是否要走两步验证，因此**必须 fail-closed**：
    /// 查询出错时返回 Err 让登录直接失败，而不是当作"未启用 MFA"放行 ——
    /// 否则一次数据库抖动就等于对所有账号临时关闭了二次验证。
    pub async fn enabled_method(&self, user_id: &str) -> Result<Option<MfaMethod>> {
        match self.get_user_mfa(user_id).await {
            Ok(config) if config.status == MfaStatus::Enabled => Ok(Some(config.method)),
            Ok(_) => Ok(None),
            Err(AuthError::UserNotFound) => Ok(None),
            Err(e) => {
                error!("Failed to load MFA config for user {}: {:?}", user_id, e);
                Err(e)
            }
        }
    }

    /// 取出并解密 TOTP 密钥。
    ///
    /// 兼容升级前写入的明文记录：`SecretCipher::decrypt` 对无密文前缀的值原样返回，
    /// 这些记录会在下一次校验时被就地加密 —— 见 `accept_totp_code` 里那条
    /// 原子更新，它顺带把 `totp_secret` 写成密文。
    fn decrypted_secret(&self, mfa_config: &UserMfa) -> Result<String> {
        let stored = mfa_config
            .totp_secret
            .as_ref()
            .ok_or_else(|| AuthError::ServerError("TOTP secret not found".to_string()))?;

        self.cipher.decrypt(stored)
    }

    /// 验证 TOTP 代码，命中时返回它对应的时间步。
    ///
    /// 返回步长而不是 `bool`，是为了让调用方能拒绝重放：同一步只允许被接受一次。
    /// 这里手动遍历 `[now-1, now, now+1]`（与 `TOTP::skew = 1` 一致），因为
    /// `check_current` 只给 yes/no，拿不到命中的是哪一步。
    fn verify_totp_code(&self, secret: &str, code: &str) -> Result<Option<i64>> {
        let secret_bytes = Secret::Encoded(secret.to_string())
            .to_bytes()
            .map_err(|e| AuthError::ServerError(format!("Invalid secret: {}", e)))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("RustAuth".to_string()),
            "".to_string(),
        )
        .map_err(|e| AuthError::ServerError(format!("TOTP creation failed: {}", e)))?;

        Ok(match_totp_step(&totp, code, Utc::now().timestamp()))
    }

    /// 校验 TOTP 并**原子地**消费掉它对应的时间步。
    ///
    /// 这里以前是「读内存水位 → 比较 → 就地推进 → 由调用方整体 UPSERT 落库」。
    /// 那是一个 check-then-act：两个并发请求可以都读到旧水位、都判定通过、
    /// 都签发会话 —— 而重放保护存在的全部意义就是「同一个码只能用一次」。
    ///
    /// 现在把比较和推进合成一条带 `WHERE` 的 UPDATE 交给数据库：
    /// 谁先写谁赢，输的那个拿到空结果集，按重放处理。这与授权码单次使用
    /// （`oidc::update_authorization_code`）是同一个写法 —— 那条路径一直是对的，
    /// 只是 MFA 这边没跟上。
    ///
    /// `extra_set` 让调用方把自己那点状态（启用流程要把 status 置成 Enabled）
    /// 塞进同一条语句，而不是另起一次会覆盖水位的整体写。
    async fn accept_totp_code(
        &self,
        mfa_config: &UserMfa,
        code: &str,
        extra_set: &str,
    ) -> Result<bool> {
        let secret = self.decrypted_secret(mfa_config)?;

        let Some(step) = self.verify_totp_code(&secret, code)? else {
            return Ok(false);
        };

        // 顺带把存量明文密钥就地加密 —— 这件事以前挂在 `save_user_mfa` 上，
        // 而这条路径不再走那里了。
        let encrypted = if SecretCipher::is_encrypted(&secret) {
            mfa_config.totp_secret.clone()
        } else {
            Some(self.cipher.encrypt(&secret)?)
        };

        let query = format!(
            r#"
            UPDATE type::record('user_mfa', $user_id) SET
                last_totp_step = $step,
                last_used_at = time::now(),
                updated_at = time::now(),
                totp_secret = $totp_secret{extra_set}
            WHERE last_totp_step = NONE OR last_totp_step < $step
            RETURN VALUE type::string(id)
        "#
        );

        let mut result = self
            .db
            .raw_query(
                "mfa_consume_totp_step",
                &query,
                serde_json::json!({
                    "user_id": mfa_config.user_id,
                    "step": step,
                    "totp_secret": encrypted,
                }),
            )
            .await?;

        // 只取投影成字符串的 id，不用 `RETURN AFTER`：整条记录里
        // `created_at` / `updated_at` / `last_used_at` 都是 `datetime`，
        // SDK 把 `Value::Datetime` 转成 `serde_json::Value` 会失败
        // —— `get_user_mfa` 的注释里记着同一件事。
        let consumed: Vec<String> = result.take(0)?;
        if consumed.is_empty() {
            warn!(
                "Rejected replayed TOTP code for user '{}' (step {step} was already consumed)",
                mfa_config.user_id
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// 原子地消费一条备用码。命中并成功移除返回 `true`；已被并发消费返回 `false`。
    ///
    /// 与 `accept_totp_code` 同一个道理，也与 `oidc::update_authorization_code`
    /// 同一个写法：一次性凭据的「检查—消费」必须是数据库里的一条语句。
    async fn consume_backup_code(&self, user_id: &str, used_hash: &str) -> Result<bool> {
        let query = r#"
            UPDATE type::record('user_mfa', $user_id) SET
                backup_codes = array::complement(backup_codes, [$used]),
                last_used_at = time::now(),
                updated_at = time::now()
            WHERE $used IN backup_codes
            RETURN VALUE type::string(id)
        "#;

        let mut result = self
            .db
            .raw_query(
                "mfa_consume_backup_code",
                query,
                serde_json::json!({ "user_id": user_id, "used": used_hash }),
            )
            .await?;

        // 同样只回字符串 id，理由见 `accept_totp_code`。
        let consumed: Vec<String> = result.take(0)?;
        Ok(!consumed.is_empty())
    }

    /// 从数据库获取用户MFA配置
    async fn get_user_mfa(&self, user_id: &str) -> Result<UserMfa> {
        // 读写必须用同一种编码。写入走 serde（`MfaStatus` / `MfaMethod` 存成
        // "Pending" / "Totp" 这样的纯字符串），若这里用 `take::<UserMfa>` 走
        // SurrealValue 解码就会报 "no variants matched" —— `LockoutType` 上已
        // 实测到过同样的失败。所以读取也走 serde。
        //
        // 另外时间列必须投影成字符串：SDK 无法把原生 `Value::Datetime` 转成
        // `serde_json::Value`（"Expected any, got datetime"）。
        let query = r#"
            SELECT
                user_id,
                status,
                method,
                totp_secret,
                backup_codes,
                type::string(created_at) AS created_at,
                type::string(updated_at) AS updated_at,
                IF last_used_at = NONE { NONE } ELSE { type::string(last_used_at) } AS last_used_at,
                last_totp_step
            FROM user_mfa
            WHERE user_id = $user_id
            LIMIT 1
        "#;

        let mut result = self
            .db
            .raw_query(
                "mfa_get_user_config",
                query,
                serde_json::json!({ "user_id": user_id }),
            )
            .await?;

        let rows: Vec<serde_json::Value> = result
            .take(0)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        rows.into_iter()
            .next()
            .map(serde_json::from_value::<UserMfa>)
            .transpose()
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse MFA config: {e}")))?
            .ok_or(AuthError::UserNotFound)
    }

    /// 保存用户MFA配置到数据库。
    ///
    /// 写入前统一把 TOTP 密钥转成密文 —— 存量的明文记录只要经过任意一次
    /// 保存（启用、验证、用备用码）就会被就地加密。
    /// 注意：`raw_query` 用 JSON 绑定，`DateTime` 会序列化成 RFC3339 字符串，
    /// 而 `user_mfa` 的时间列是 `datetime` —— SCHEMAFULL 不会自动强转，
    /// 必须在语句里显式 `type::datetime()`，并兼容 `Option::None` 的 NULL。
    async fn save_user_mfa(&self, mfa_config: &UserMfa) -> Result<()> {
        let mfa_config = &self.with_encrypted_secret(mfa_config)?;
        let query = r#"
            UPSERT type::record('user_mfa', $user_id) CONTENT {
                user_id: $user_id,
                status: $status,
                method: $method,
                totp_secret: $totp_secret ?? NONE,
                backup_codes: $backup_codes,
                created_at: type::datetime($created_at),
                updated_at: type::datetime($updated_at),
                last_used_at: IF $last_used_at = NONE OR $last_used_at = NULL {
                    NONE
                } ELSE {
                    type::datetime($last_used_at)
                },
                last_totp_step: $last_totp_step ?? NONE
            }
        "#;

        self.db
            .raw_query(
                "mfa_save_user_config",
                query,
                serde_json::json!({
                    "user_id": mfa_config.user_id,
                    "status": mfa_config.status,
                    "method": mfa_config.method,
                    "totp_secret": mfa_config.totp_secret,
                    "backup_codes": mfa_config.backup_codes,
                    "created_at": mfa_config.created_at,
                    "updated_at": mfa_config.updated_at,
                    "last_used_at": mfa_config.last_used_at,
                    "last_totp_step": mfa_config.last_totp_step,
                }),
            )
            .await?;

        Ok(())
    }

    fn with_encrypted_secret(&self, mfa_config: &UserMfa) -> Result<UserMfa> {
        let mut config = mfa_config.clone();
        if let Some(secret) = &config.totp_secret {
            if !SecretCipher::is_encrypted(secret) {
                config.totp_secret = Some(self.cipher.encrypt(secret)?);
            }
        }
        Ok(config)
    }

    /// 删除用户MFA配置
    async fn delete_user_mfa(&self, user_id: &str) -> Result<()> {
        self.db
            .raw_query(
                "mfa_delete_user_config",
                "DELETE user_mfa WHERE user_id = $user_id",
                serde_json::json!({ "user_id": user_id }),
            )
            .await?;

        Ok(())
    }
}

// 为TOTP相关错误实现From trait
impl From<totp_rs::TotpUrlError> for AuthError {
    fn from(err: totp_rs::TotpUrlError) -> Self {
        AuthError::ServerError(format!("TOTP URL error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_totp_code_verification() {
        // 创建MFA服务实例用于测试
        // 注意：这需要有效的数据库配置，在实际测试中可能需要模拟

        // 测试TOTP代码验证逻辑
        let secret = Secret::Raw((0u8..20).collect());

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().unwrap(),
            Some("RustAuth".to_string()),
            "test@example.com".to_string(),
        )
        .unwrap();

        let code = totp.generate_current().unwrap();

        // 验证生成的代码应该是有效的
        assert!(totp.check_current(&code).unwrap());
    }

    fn test_totp() -> TOTP {
        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Raw((0u8..20).collect()).to_bytes().unwrap(),
            Some("RustAuth".to_string()),
            "".to_string(),
        )
        .unwrap()
    }

    #[test]
    fn match_totp_step_returns_the_matching_step() {
        let totp = test_totp();
        let now = 1_700_000_000i64;
        let current_step = now / 30;

        // 当前步、前一步、后一步都在窗口内，且各自报出自己的步号。
        for offset in [-1i64, 0, 1] {
            let step = current_step + offset;
            let code = totp.generate((step * 30) as u64);
            assert_eq!(
                match_totp_step(&totp, &code, now),
                Some(step),
                "offset={offset}"
            );
        }

        // 窗口外的码不认。
        let stale = totp.generate(((current_step - 5) * 30) as u64);
        assert_eq!(match_totp_step(&totp, &stale, now), None);
        assert_eq!(match_totp_step(&totp, "000000", now), None);
    }

    #[test]
    fn replay_watermark_rejects_a_reused_step() {
        // 这是 `accept_totp_code` 里的判据：步号不前进就是重放。
        let last_step = Some(56_666_666i64);
        let replay = |step: i64| matches!(last_step, Some(last) if step <= last);

        assert!(replay(56_666_666), "同一步应判定为重放");
        assert!(replay(56_666_665), "更早的步应判定为重放");
        assert!(!replay(56_666_667), "下一步应放行");
    }

    #[test]
    fn test_backup_codes_generation() {
        let codes = UserMfa::generate_backup_codes();

        assert_eq!(codes.len(), 8);

        for code in &codes {
            assert_eq!(code.len(), 8);
            assert!(code
                .chars()
                .all(|c| c.is_ascii_alphanumeric() && c.is_uppercase()));
        }

        // 确保代码是唯一的
        let mut unique_codes = codes.clone();
        unique_codes.sort();
        unique_codes.dedup();
        assert_eq!(unique_codes.len(), codes.len());
    }
}
