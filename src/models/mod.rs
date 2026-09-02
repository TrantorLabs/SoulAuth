// ── Actor Identity Domain（V2 身份根）────────────────────────────
pub mod actor_identity;
pub mod ai_actor;
pub mod human_account;
pub mod identity_binding;

// ── V1 遗留，Stage 2/3 逐步迁出 ─────────────────────────────────
pub mod account_lockout;
pub mod identity_provider;
pub mod mfa;
pub mod oidc_client;
pub mod oidc_token;
pub mod password_reset;
pub mod permission;
pub mod role;
pub mod session;
pub mod subject;
pub mod user;
pub mod user_activity;
pub mod user_preferences;
pub mod user_profile;
pub mod user_role;
