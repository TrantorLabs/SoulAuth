use crate::error::{AuthError, Result};

/// 邮箱格式校验。
///
/// 刻意保持保守：只拒绝明显不合法的输入（缺 `@`、缺域名点、含空白），
/// 真正的可达性由验证邮件确认。
pub fn validate_email(email: &str) -> Result<String> {
    let email = email.trim();

    if email.is_empty() {
        return Err(AuthError::ValidationError("Email is required".to_string()));
    }
    if email.len() > 254 {
        return Err(AuthError::ValidationError("Email is too long".to_string()));
    }
    if email.chars().any(|ch| ch.is_whitespace()) {
        return Err(AuthError::ValidationError(
            "Email must not contain whitespace".to_string(),
        ));
    }
    // 控制字符必须单独挡：它们**不是**空白字符，上面那条拦不住。
    //
    // 实测后果：`evil\x1b[31mred\x1b[0m@example.com` 能通过全部校验并注册成功
    // （返回 200），随后原始 ESC 字节原样进入日志 —— 发信失败那条 error! 会把
    // 邮箱打出来。攻击者据此可以在运维的终端里伪造日志行、清屏、隐藏自己的痕迹，
    // 而日志正是这个服务的审计凭证。
    //
    // 这一条也是 RUSTSEC-2025-0055（tracing-subscriber 的 ANSI 注入）在本项目里
    // 唯一可达的入口。堵在输入侧比依赖升级更根本：不论日志库是哪个版本，
    // 控制字符本来就不该出现在邮箱地址里（RFC 5321 也不允许）。
    if email.chars().any(|ch| ch.is_control()) {
        return Err(AuthError::ValidationError(
            "Email must not contain control characters".to_string(),
        ));
    }

    let (local, domain) = email
        .split_once('@')
        .ok_or_else(|| AuthError::ValidationError("Email must contain '@'".to_string()))?;

    if local.is_empty() || domain.is_empty() {
        return Err(AuthError::ValidationError(
            "Email is not a valid address".to_string(),
        ));
    }
    if domain.contains('@') {
        return Err(AuthError::ValidationError(
            "Email must contain exactly one '@'".to_string(),
        ));
    }
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return Err(AuthError::ValidationError(
            "Email domain is not valid".to_string(),
        ));
    }

    Ok(email.to_ascii_lowercase())
}

/// 密码强度校验：长度 + 至少三类字符（大写 / 小写 / 数字 / 符号）。
pub fn validate_password(password: &str, min_length: usize) -> Result<()> {
    // 下限必须按**字符数**算。`str::len()` 给的是字节数，一个汉字占 3 字节，
    // 于是 "密码密码Abc1"（8 个字符）就能满足 12 位的下限 —— 提示语说的是
    // "至少 12 个字符"，实际执行的却是"至少 12 字节"，两者对不上。
    if password.chars().count() < min_length {
        return Err(AuthError::ValidationError(format!(
            "Password must be at least {min_length} characters long"
        )));
    }
    // 上限反过来按字节算：这里挡的是"超长输入浪费 Argon2 的 CPU"，
    // 真正决定开销的是字节数（argon2 本身没有长度上限）。
    if password.len() > 1024 {
        return Err(AuthError::ValidationError(
            "Password must be at most 1024 bytes long".to_string(),
        ));
    }

    let has_lower = password.chars().any(|ch| ch.is_lowercase());
    let has_upper = password.chars().any(|ch| ch.is_uppercase());
    let has_digit = password.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = password
        .chars()
        .any(|ch| !ch.is_alphanumeric() && !ch.is_whitespace());

    let classes = [has_lower, has_upper, has_digit, has_symbol]
        .into_iter()
        .filter(|present| *present)
        .count();

    if classes < 3 {
        return Err(AuthError::ValidationError(
            "Password must contain at least three of: lowercase, uppercase, digit, symbol"
                .to_string(),
        ));
    }

    Ok(())
}

/// 用户名校验：长度 3~32，仅允许字母数字、下划线与连字符。
pub fn validate_username(username: &str) -> Result<String> {
    let username = username.trim();

    if username.len() < 3 || username.len() > 32 {
        return Err(AuthError::ValidationError(
            "Username must be between 3 and 32 characters".to_string(),
        ));
    }
    if !username
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(AuthError::ValidationError(
            "Username may only contain letters, digits, '_' and '-'".to_string(),
        ));
    }

    Ok(username.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_email_and_lowercases_it() {
        assert_eq!(
            validate_email(" User@Example.COM ").unwrap(),
            "user@example.com"
        );
    }

    #[test]
    fn rejects_control_characters_in_email() {
        // 控制字符不是空白字符，必须单独挡。放过去的后果是原始 ESC 字节
        // 随邮箱进入日志，攻击者可借此伪造 / 掩盖审计记录。
        for bad in [
            "evil\u{1b}[31mred\u{1b}[0m@example.com",
            "a\u{0}b@example.com",
            "a\u{7}b@example.com",
        ] {
            assert!(
                validate_email(bad).is_err(),
                "should reject control chars in {bad:?}"
            );
        }
        // 正常地址不受影响
        assert!(validate_email("normal.user+tag@example.com").is_ok());
    }

    #[test]
    fn rejects_malformed_emails() {
        for bad in [
            "",
            "no-at-sign",
            "a@b",
            "a@@b.com",
            "a b@example.com",
            "a@.com",
        ] {
            assert!(validate_email(bad).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn rejects_short_or_low_entropy_passwords() {
        assert!(validate_password("Short1!", 12).is_err());
        assert!(validate_password("alllowercaseletters", 12).is_err());
        assert!(validate_password("alllowercase12345678", 12).is_err());
    }

    #[test]
    fn accepts_password_with_three_character_classes() {
        assert!(validate_password("CorrectHorse42", 12).is_ok());
        assert!(validate_password("correct-horse-42", 12).is_ok());
    }

    #[test]
    fn password_length_counts_characters_not_bytes() {
        // 8 个字符、16 字节：按字节算会放行，按字符算必须拒绝。
        assert!(validate_password("密码密码Abc1", 12).is_err());
        // 12 个字符、24 字节：字符数够了，且含大小写+数字三类。
        assert!(validate_password("密码密码密码密码AAbb12", 12).is_ok());
    }

    #[test]
    fn rejects_password_over_the_byte_cap() {
        let huge = "A1b".repeat(400); // 1200 字节
        assert!(validate_password(&huge, 12).is_err());
    }

    #[test]
    fn validates_username_charset_and_length() {
        assert_eq!(validate_username(" alice_01 ").unwrap(), "alice_01");
        assert!(validate_username("ab").is_err());
        assert!(validate_username("bad name").is_err());
    }
}
