use surrealdb::types::{RecordId, RecordIdKey};

pub fn record_id_key_to_string(id: &RecordId) -> String {
    match &id.key {
        RecordIdKey::String(v) => v.clone(),
        RecordIdKey::Number(v) => v.to_string(),
        RecordIdKey::Uuid(v) => v.to_string(),
        // Fallback for composite keys; not used by current auth IDs.
        _ => serde_json::to_string(&id.key).unwrap_or_default(),
    }
}

pub fn normalize_record_id_key(value: &str) -> String {
    let mut normalized = value.trim().to_string();

    loop {
        let next = normalized
            .trim()
            .trim_matches('⟨')
            .trim_matches('⟩')
            .trim_matches('<')
            .trim_matches('>')
            .trim_matches('"')
            .trim_matches('`')
            .trim()
            .to_string();

        if next == normalized {
            return next;
        }

        normalized = next;
    }
}

/// 把各种写法的用户标识归一成裸 record key。
///
/// 接受 `abc`、`user:abc`、`user:⟨abc⟩` 等形式；带**其它表前缀**的值会原样
/// 返回，由 [`user_record_id`] 那一层拒绝 —— 见该函数的说明。
pub fn normalize_user_id(value: &str) -> String {
    let mut normalized = normalize_record_id_key(value);

    loop {
        let next = if let Some(key) = normalized.strip_prefix("user:") {
            normalize_record_id_key(key)
        } else {
            normalize_record_id_key(&normalized)
        };

        if next == normalized {
            return next;
        }

        normalized = next;
    }
}

/// 把身份根引用归一成裸 record key。
///
/// 接受 `abc`、`actor_identity:abc`、`actor_identity:⟨abc⟩`。
///
/// 需要它是因为存进 OIDC 授权码 / 令牌的 `user_id` 现在是 actor 记录引用，
/// 读回来经 `type::string()` 会带上 `actor_identity:` 前缀。用
/// [`normalize_user_id`] 剥不掉它 —— 那个只认 `user:` —— 于是后续查询
/// 拿一个带前缀的串去构造 record id，一行也匹配不到。
///
/// 症状很有迷惑性：授权码签发成功、兑换返回 400 "User not found"，
/// 看起来像 PKCE 或客户端认证出了问题。
pub fn normalize_actor_id(value: &str) -> String {
    let mut normalized = normalize_record_id_key(value);

    loop {
        let next = match normalized.strip_prefix("actor_identity:") {
            Some(key) => normalize_record_id_key(key),
            None => normalize_record_id_key(&normalized),
        };

        if next == normalized {
            return next;
        }

        normalized = next;
    }
}

/// 一个值是否带着**别的表**的前缀。
///
/// 判据是「冒号左边像一个表名」：全小写字母 / 数字 / 下划线，且非空。
/// 这样 `client:abc`、`role:admin` 会被识别，而恰好含冒号的合法 key
/// （例如 base64 片段、URL）不会被误伤。
fn foreign_table_prefix(value: &str) -> Option<&str> {
    let (table, rest) = value.split_once(':')?;
    if table.is_empty() || rest.is_empty() {
        return None;
    }
    let looks_like_table = table
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    (looks_like_table && table != "user").then_some(table)
}

/// 构造一个 `user` 表的 RecordId。
///
/// # 为什么这里要拒绝而不是照单全收
///
/// 此前传入 `client:abc` 会被原样包成 `user:⟨client:abc⟩`。结果只是查不到
/// （404），不会错配到别的记录，所以看起来无害。
///
/// 但 GA-04 §41 禁止的正是这个形状：调用方送来一个 `client_id`，而接口期待的是
/// ActorIdentity Reference —— 即使两者都是 string，跨命名空间的隐式转换也不
/// 允许。静默接受会把「命名空间用错了」这类调用方缺陷，伪装成「资源不存在」，
/// 而后者是完全不同的诊断。
///
/// 注意这不违反 §43 的另一半：拒绝之后**不做**任何回退尝试
/// （不会「查不到 user 就去查 client」），对外也不透露那个前缀属于哪个命名空间。
pub fn user_record_id(value: &str) -> Result<RecordId, ForeignNamespace> {
    let normalized = normalize_user_id(value);
    if let Some(table) = foreign_table_prefix(&normalized) {
        return Err(ForeignNamespace {
            table: table.to_string(),
        });
    }
    Ok(RecordId::new("user", normalized))
}

/// 调用方送来了属于另一个命名空间的标识符。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignNamespace {
    pub table: String,
}

impl std::fmt::Display for ForeignNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 内部诊断可以具体；对外错误由调用方决定要不要泛化 —— GA-04 §43
        // 允许为了防枚举而对外保持 generic。
        write!(
            f,
            "expected a user reference but received a `{}` reference",
            self.table
        )
    }
}

impl std::error::Error for ForeignNamespace {}

#[cfg(test)]
mod tests {
    use super::{normalize_user_id, user_record_id};

    #[test]
    fn foreign_namespace_reference_is_rejected() {
        // GA-04 §41：调用方送来 client_id 而接口期待 ActorIdentity Reference 时，
        // 即使两者都是 string 也不得隐式转换。
        for foreign in ["client:abc", "role:admin", "credential:xyz", "session:s1"] {
            let err = user_record_id(foreign).expect_err(foreign);
            assert_eq!(err.table, foreign.split(':').next().unwrap());
        }
    }

    #[test]
    fn user_references_are_accepted_in_every_written_form() {
        for ok in ["abc", "user:abc", "user:⟨abc⟩", "user:`abc`"] {
            let rid = user_record_id(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
            assert_eq!(rid.table.to_string(), "user");
        }
    }

    #[test]
    fn keys_that_merely_contain_a_colon_are_not_mistaken_for_namespaces() {
        // 冒号左边不像表名（含大写、连字符、点）就不算命名空间前缀，
        // 否则合法 key 会被误伤。
        for ok in ["Basic:abc", "a-b:c", "x.y:z", "AB:cd"] {
            assert!(user_record_id(ok).is_ok(), "{ok} 不该被当成外部命名空间");
        }
    }

    #[test]
    fn normalize_user_id_cases() {
        let cases = [
            ("abc", "abc"),
            ("user:abc", "abc"),
            ("user:user:abc", "abc"),
            ("user:\"abc\"", "abc"),
            ("user:`abc`", "abc"),
            ("user:⟨abc⟩", "abc"),
        ];

        for (input, expected) in cases {
            assert_eq!(normalize_user_id(input), expected, "input={input}");
        }
    }
}
