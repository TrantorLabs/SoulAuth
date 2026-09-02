use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::SurrealValue;
use validator::Validate;

/// MFA设置状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, SurrealValue)]
pub enum MfaStatus {
    /// 未启用MFA
    Disabled,
    /// MFA设置中（生成密钥但未验证）
    Pending,
    /// MFA已启用
    Enabled,
}

/// MFA方法类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, SurrealValue)]
pub enum MfaMethod {
    /// TOTP (Time-based One-Time Password)
    Totp,
    /// SMS验证码
    Sms,
    /// 邮箱验证码
    Email,
}

/// 用户MFA配置
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct UserMfa {
    /// 用户ID
    pub user_id: String,
    /// MFA状态
    pub status: MfaStatus,
    /// MFA方法
    pub method: MfaMethod,
    /// TOTP 密钥，以 `enc.v1.<base64>` 形式加密存储
    /// （见 `utils::crypto::SecretCipher`）。
    pub totp_secret: Option<String>,
    /// 备用恢复码的 **Argon2 哈希**，明文只在生成时返回给用户一次。
    pub backup_codes: Vec<String>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
    /// 最后使用时间
    pub last_used_at: Option<DateTime<Utc>>,
    /// 最近一次被接受的 TOTP 时间步（Unix 秒 / 30）。
    ///
    /// RFC 6238 §5.2 要求同一个码只能用一次：`check_current` 只判断码是否落在
    /// 当前窗口（含 ±1 步偏移），同一个 6 位码在 30~90 秒内可以反复提交。
    /// 记下已接受的步长后，验证时拒绝 `step <= last_totp_step`，钓鱼中转或
    /// 肩窥拿到的码就无法在窗口内复用。
    #[serde(default)]
    pub last_totp_step: Option<i64>,
}

impl UserMfa {
    /// 生成备用恢复代码
    pub fn generate_backup_codes() -> Vec<String> {
        use rand::{distributions::Uniform, Rng};

        // 仅使用大写字母，避免数字在 is_uppercase 判断中失败
        let alphabet = Uniform::new_inclusive(b'A', b'Z');
        let mut rng = rand::thread_rng();

        (0..8)
            .map(|_| {
                (0..8)
                    .map(|_| rng.sample(alphabet) as char)
                    .collect::<String>()
            })
            .collect()
    }
}

/// 启用TOTP的请求
#[derive(Debug, Deserialize, Validate)]
pub struct EnableTotpRequest {
    /// TOTP验证码
    #[validate(length(equal = 6))]
    pub totp_code: String,
}

/// 验证TOTP的请求
#[derive(Debug, Deserialize, Validate)]
pub struct VerifyTotpRequest {
    /// TOTP验证码
    #[validate(length(equal = 6))]
    pub totp_code: String,
}

/// 使用备用代码的请求
#[derive(Debug, Deserialize, Validate)]
pub struct UseBackupCodeRequest {
    /// 备用恢复代码
    #[validate(length(equal = 8))]
    pub backup_code: String,
}

/// TOTP设置响应
#[derive(Debug, Serialize)]
pub struct TotpSetupResponse {
    /// 密钥（用于手动输入）
    pub secret: String,
    /// QR码数据URL
    pub qr_code: String,
    /// 备用恢复代码
    pub backup_codes: Vec<String>,
}

/// MFA验证响应
#[derive(Debug, Serialize)]
pub struct MfaVerificationResponse {
    /// 是否验证成功
    pub verified: bool,
    /// 认证令牌（如果验证成功）
    pub token: Option<String>,
    /// 错误消息（如果验证失败）
    pub message: Option<String>,
}

/// MFA状态响应
#[derive(Debug, Serialize)]
pub struct MfaStatusResponse {
    /// MFA是否启用
    pub enabled: bool,
    /// MFA方法
    pub method: Option<MfaMethod>,
    /// 备用代码剩余数量
    pub backup_codes_count: u32,
    /// 最后使用时间
    pub last_used_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_codes_generation() {
        let codes = UserMfa::generate_backup_codes();

        assert_eq!(codes.len(), 8);

        // 检查每个代码都是8位大写字母数字
        for code in codes {
            assert_eq!(code.len(), 8);
            assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
            assert!(code.chars().all(|c| c.is_uppercase() || c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_enable_totp_request_validation() {
        use validator::Validate;

        let valid_request = EnableTotpRequest {
            totp_code: "123456".to_string(),
        };
        assert!(valid_request.validate().is_ok());

        let invalid_request = EnableTotpRequest {
            totp_code: "12345".to_string(), // 太短
        };
        assert!(invalid_request.validate().is_err());

        let invalid_request2 = EnableTotpRequest {
            totp_code: "1234567".to_string(), // 太长
        };
        assert!(invalid_request2.validate().is_err());
    }
}
