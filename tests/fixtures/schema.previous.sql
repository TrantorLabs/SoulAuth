OPTION IMPORT;
-- ↑ 放在第一行。这不是语法要求 —— 3.2.4 上实测，前面带注释同样导得进 ——
-- 而是因为 `surreal export` 自己就把它写在产物首行，跟着它走的文件不会有人
-- 怀疑该不该动。
--
-- SurrealDB 3.2 起 `surreal import` 强制要求这条语句，否则整条命令以 400 失败：
--   Invalid statement: Import requires `OPTION IMPORT;` as the first statement.
-- 3.0 上没有这个要求，两版都接受它（实测：加上之后 3.0.0 与 3.2.4 都是 24 张表）。
--
-- 它关掉事件、live query、字段处理与结果输出 —— 导入本来就不需要这些。
--
-- 不加的后果不是「慢一点」：Quickstart 第 2 步、DEPLOYMENT.md 第 3 步、
-- integration job、docker job 会同时断。这一条曾经在本机（3.0）全绿、在 CI
-- 拉到的最新版（3.2.4）全红，差别仅仅是安装那天 latest 指向哪里；现在 CI 与
-- docker-compose 都把版本钉死了，但文件本身对两代都成立才是根本的那道保险。

-- SoulAuth Database Schema
-- 运行此文件以创建所有必需的数据库表和索引

-- ═══════════════════════════════════════════════════════════════════
-- Actor Identity Domain
-- ═══════════════════════════════════════════════════════════════════
--
-- 身份根是 `actor_identity`，不是 `user`。
--
-- Human 与 AIActor 都是一等身份主体，通过同一套 Actor Identity Contract
-- 进入系统；它们可以拥有不同的 Credential、Authentication Method 与
-- Lifecycle，但没有哪一个需要伪装成另一个才能被认证。
--
-- 五个对象永远不能重新合并（GA-01 §4，GA-07 §13）：
--
--   ActorIdentity    谁？
--   HumanAccount     Human 怎样管理自己的登录账户？
--   IdentityBinding  外部某个身份如何证明与该 Actor 是同一主体？
--   Credential       Actor 用什么证明自己？        （Stage 2 收口）
--   Client           哪个软件正在请求身份能力？     （见 oidc_client）

-- 身份根。回答「谁是这个可以被认证的主体」，仅此而已。
DEFINE TABLE IF NOT EXISTS actor_identity SCHEMAFULL;

-- 对外稳定的 Authentication Subject。
--
-- OIDC `sub` 建立在它之上。Email、Username、Display Name 的修改，Credential
-- 的轮换，MFA 的增减，经由不同 Client 进入 —— 这些都不得改变它（GA-04 §7）。
--
-- 它与 record id 是**两个命名空间**。实现上可以取同一个值，但那是实现选择，
-- 不建立语义等同（GA-04 §5）：文档不得声称 `Resource ID = Stable Subject`。
DEFINE FIELD IF NOT EXISTS subject_key ON actor_identity TYPE string;

-- `human` | `ai_actor`
--
-- 第一阶段只承认这两类。Organization、Device、Application 要进入同一套
-- Actor Identity Contract，必须经过正式架构裁决，而不是因为加一个 enum
-- 变体很容易就加上（GA-01 §4）。
DEFINE FIELD IF NOT EXISTS actor_kind ON actor_identity TYPE string;

-- `local` | `soulseed` | `external`
--
-- 这个身份通过什么受控来源进入 SoulAuth。它不替代 IdentityBinding，
-- 也不意味着一个 Actor 只能有一条外部身份关系（GA-01 §4）。
DEFINE FIELD IF NOT EXISTS identity_source ON actor_identity TYPE string DEFAULT "local";

-- Soulseed 模式下绑定 SoulseedAGI 已经成立的 Canonical Actor。
--
-- 它只是一条受控引用：证明绑定关系，**不赋予** SoulAuth 定义或修改
-- Mind / SubjectIntent / Memory 的能力（GA-01 §11，GA-07 §9）。
-- 也不得默认暴露给第三方 OIDC Client —— 属受控 Integration Claim。
DEFINE FIELD IF NOT EXISTS canonical_actor_ref ON actor_identity TYPE option<string>;

-- `active` | `suspended` | `retired`
--
-- Retired 可以停止认证，但其 subject_key **不得**被重新分配给另一个 Actor：
-- 否则历史 Claims、Audit 与外部记录里的同一个 Subject，会在不同时间指向
-- 不同主体（GA-04 §12，06 §7）。
DEFINE FIELD IF NOT EXISTS status ON actor_identity TYPE string DEFAULT "active";

DEFINE FIELD IF NOT EXISTS created_at ON actor_identity TYPE number;
DEFINE FIELD IF NOT EXISTS updated_at ON actor_identity TYPE number;

DEFINE INDEX IF NOT EXISTS actor_subject_idx ON actor_identity COLUMNS subject_key UNIQUE;
DEFINE INDEX IF NOT EXISTS actor_kind_idx ON actor_identity COLUMNS actor_kind;
-- Canonical 绑定必须唯一：两个 ActorIdentity 绑到同一个 Canonical Actor，
-- 等于在 SoulAuth 里把一个主体分裂成两个。
DEFINE INDEX IF NOT EXISTS actor_canonical_ref_idx ON actor_identity COLUMNS canonical_actor_ref UNIQUE;

-- Human-specific account extension。**不是身份根。**
--
-- Human 修改 Email 不意味着 ActorIdentity 发生变化。AIActor 不需要为了
-- 拥有身份而伪造 Email / Username（GA-01 §4，GA-07 §13）。
--
-- Password 不在这里：它属于 Credential Domain。当前仍暂留在 `user` 表上，
-- Stage 2 收口。
DEFINE TABLE IF NOT EXISTS human_account SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS actor_identity_id ON human_account TYPE record<actor_identity>;
DEFINE FIELD IF NOT EXISTS email ON human_account TYPE string;
DEFINE FIELD IF NOT EXISTS username ON human_account TYPE string;
DEFINE FIELD IF NOT EXISTS username_normalized ON human_account TYPE string;
DEFINE FIELD IF NOT EXISTS email_verified ON human_account TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS created_at ON human_account TYPE number;
DEFINE FIELD IF NOT EXISTS updated_at ON human_account TYPE number;

DEFINE INDEX IF NOT EXISTS human_account_email_idx ON human_account COLUMNS email UNIQUE;
DEFINE INDEX IF NOT EXISTS human_account_username_idx ON human_account COLUMNS username_normalized UNIQUE;
-- 一个 Human ActorIdentity 至多一个账户。
DEFINE INDEX IF NOT EXISTS human_account_actor_idx ON human_account COLUMNS actor_identity_id UNIQUE;

-- 外部身份来源与本地 ActorIdentity 之间**经过验证的**对应关系。
--
-- 它是独立关系对象，不是 ActorIdentity 里的一个外部 ID 字段。
-- Google、GitHub、企业 IdP 与 Soulseed Canonical Actor 共享同一抽象 ——
-- 不需要为「机器人账号」另造一套（GA-01 §4，GA-07 §9）。
--
-- 关键边界：Binding 建立关系，但**不创造上游主体**。Google Identity 由
-- Google 定义，Canonical AIActor 由 SoulseedAGI 定义。
--
-- 也不等于 Credential：外部 IdP 里 Human 用的密码不会因此成为 SoulAuth 的
-- Actor Credential（GA-05 §4）。
DEFINE TABLE IF NOT EXISTS identity_binding SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS actor_identity_id ON identity_binding TYPE record<actor_identity>;
DEFINE FIELD IF NOT EXISTS provider ON identity_binding TYPE string;
DEFINE FIELD IF NOT EXISTS provider_subject ON identity_binding TYPE string;
-- `federated` | `canonical` —— 前者是外部 IdP，后者是 Soulseed Canonical Actor。
DEFINE FIELD IF NOT EXISTS binding_type ON identity_binding TYPE string DEFAULT "federated";
-- `verified` | `pending` | `revoked`
DEFINE FIELD IF NOT EXISTS verification_state ON identity_binding TYPE string DEFAULT "verified";
DEFINE FIELD IF NOT EXISTS bound_at ON identity_binding TYPE number;
DEFINE FIELD IF NOT EXISTS revoked_at ON identity_binding TYPE option<number>;

-- (provider, provider_subject) 必须联合唯一。
--
-- 只按 subject 唯一是一个真实的跨 provider 账号接管：数字 id 为 4001 的
-- GitHub 账号会匹配上 sub 为字符串 "4001" 的 Google 用户。
DEFINE INDEX IF NOT EXISTS identity_binding_provider_subject_idx
    ON identity_binding COLUMNS provider, provider_subject UNIQUE;
DEFINE INDEX IF NOT EXISTS identity_binding_actor_idx ON identity_binding COLUMNS actor_identity_id;

-- ═══════════════════════════════════════════════════════════════════
-- 以下为 V1 遗留，Stage 2/3 逐步迁出
-- ═══════════════════════════════════════════════════════════════════

-- 主体表（V1）。已被 actor_identity.actor_kind 取代，Stage 4 删除。
DEFINE TABLE IF NOT EXISTS subject SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS subject_type ON subject TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON subject TYPE number;
DEFINE FIELD IF NOT EXISTS updated_at ON subject TYPE number;

-- 用户表（V1）
DEFINE TABLE IF NOT EXISTS user SCHEMAFULL;
-- 指向身份根。
--
-- 字段名还叫 subject_id 是历史遗留（V1 指向 subject 表），Stage 4 拆掉
-- user 表时一并消失，现在改名只会制造一次纯噪声的 diff。
--
-- 这一处是步骤 3 批量迁移外键时**漏掉的第 12 处** —— 它写的是
-- `record<subject>` 而不是 `record<user>`，不匹配替换模式。集成测试
-- 以「Expected `none | record<subject>` but found `actor_identity:...`」
-- 抓到了它。
DEFINE FIELD IF NOT EXISTS subject_id ON user TYPE option<record<actor_identity>>;
DEFINE FIELD IF NOT EXISTS email ON user TYPE string;
DEFINE FIELD IF NOT EXISTS username ON user TYPE string;
DEFINE FIELD IF NOT EXISTS username_normalized ON user TYPE string;
DEFINE FIELD IF NOT EXISTS password ON user TYPE option<string>;
DEFINE FIELD IF NOT EXISTS verified ON user TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS verification_token_hash ON user TYPE option<string>;   -- 指纹，不是令牌
DEFINE FIELD IF NOT EXISTS verification_token_expires_at ON user TYPE option<number>;
DEFINE FIELD IF NOT EXISTS account_status ON user TYPE string DEFAULT "Active";
DEFINE FIELD IF NOT EXISTS membership_level ON user TYPE string DEFAULT "FREE";
-- 时间点而非自由字符串：形状由 SoulAuth 保证，语义（过期与否）由消费方解释。
DEFINE FIELD IF NOT EXISTS membership_expiry ON user TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS last_login_at ON user TYPE option<number>;
DEFINE FIELD IF NOT EXISTS last_login_ip ON user TYPE option<string>;
DEFINE FIELD IF NOT EXISTS created_at ON user TYPE number;
DEFINE FIELD IF NOT EXISTS updated_at ON user TYPE number;
DEFINE INDEX IF NOT EXISTS email_idx ON user COLUMNS email UNIQUE;
DEFINE INDEX IF NOT EXISTS username_idx ON user COLUMNS username_normalized UNIQUE;

-- 身份提供商表
DEFINE TABLE IF NOT EXISTS identity_provider SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS provider ON identity_provider TYPE string;
DEFINE FIELD IF NOT EXISTS provider_user_id ON identity_provider TYPE string;
DEFINE FIELD IF NOT EXISTS user_id ON identity_provider TYPE record<actor_identity>;
DEFINE FIELD IF NOT EXISTS created_at ON identity_provider TYPE number;
DEFINE FIELD IF NOT EXISTS updated_at ON identity_provider TYPE number;
DEFINE INDEX IF NOT EXISTS provider_idx ON identity_provider COLUMNS provider, provider_user_id UNIQUE;

-- 会话表
DEFINE TABLE IF NOT EXISTS session SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS user_id ON session TYPE record<actor_identity>;
DEFINE FIELD IF NOT EXISTS token_hash ON session TYPE string;          -- SHA-256 指纹，不是令牌本身
DEFINE FIELD IF NOT EXISTS expires_at ON session TYPE number;
DEFINE FIELD IF NOT EXISTS created_at ON session TYPE number;
DEFINE FIELD IF NOT EXISTS user_agent ON session TYPE string;
DEFINE FIELD IF NOT EXISTS ip_address ON session TYPE string;
DEFINE INDEX IF NOT EXISTS session_token_hash_idx ON session COLUMNS token_hash UNIQUE;

-- 密码重置令牌表
DEFINE TABLE IF NOT EXISTS password_reset_token SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS email ON password_reset_token TYPE string;
DEFINE FIELD IF NOT EXISTS token_hash ON password_reset_token TYPE string;        -- 指纹，不是令牌
DEFINE FIELD IF NOT EXISTS expires_at ON password_reset_token TYPE datetime;
DEFINE FIELD IF NOT EXISTS used ON password_reset_token TYPE bool;
DEFINE FIELD IF NOT EXISTS created_at ON password_reset_token TYPE datetime;
DEFINE INDEX IF NOT EXISTS reset_token_idx ON password_reset_token COLUMNS token_hash UNIQUE;
DEFINE INDEX IF NOT EXISTS reset_email_idx ON password_reset_token COLUMNS email;

-- 多因素认证表
DEFINE TABLE IF NOT EXISTS user_mfa SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS user_id ON user_mfa TYPE string;
DEFINE FIELD IF NOT EXISTS status ON user_mfa TYPE string;
DEFINE FIELD IF NOT EXISTS method ON user_mfa TYPE string;
-- 模型侧是 Option<String>（SMS / Email 方式下没有 TOTP 密钥），
-- schema 必须同为可空，否则写入 None 会被拒。
DEFINE FIELD IF NOT EXISTS totp_secret ON user_mfa TYPE option<string>;
DEFINE FIELD IF NOT EXISTS backup_codes ON user_mfa TYPE array;
DEFINE FIELD IF NOT EXISTS created_at ON user_mfa TYPE datetime;
DEFINE FIELD IF NOT EXISTS updated_at ON user_mfa TYPE datetime;
DEFINE FIELD IF NOT EXISTS last_used_at ON user_mfa TYPE option<datetime>;
-- 已接受过的 TOTP 时间步，用于拒绝同一个码在窗口内被重放（RFC 6238 §5.2）。
DEFINE FIELD IF NOT EXISTS last_totp_step ON user_mfa TYPE option<number>;
DEFINE INDEX IF NOT EXISTS user_mfa_user_idx ON user_mfa COLUMNS user_id UNIQUE;

-- 账户锁定表
DEFINE TABLE IF NOT EXISTS account_lockout SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS identifier ON account_lockout TYPE string;
DEFINE FIELD IF NOT EXISTS lockout_type ON account_lockout TYPE string;
DEFINE FIELD IF NOT EXISTS failed_attempts ON account_lockout TYPE number;
-- DEFAULT 是必须的：`increment_failed_attempts` 首次插入时只 SET 计数相关字段，
-- 不碰 status（碰了会把已锁定的记录改回 Normal）。
DEFINE FIELD IF NOT EXISTS status ON account_lockout TYPE string DEFAULT 'Normal';
DEFINE FIELD IF NOT EXISTS locked_at ON account_lockout TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS locked_until ON account_lockout TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS last_attempt_at ON account_lockout TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS created_at ON account_lockout TYPE datetime DEFAULT time::now();
DEFINE FIELD IF NOT EXISTS updated_at ON account_lockout TYPE datetime;
DEFINE INDEX IF NOT EXISTS lockout_identifier_idx ON account_lockout COLUMNS identifier, lockout_type UNIQUE;

-- 角色表
DEFINE TABLE IF NOT EXISTS role SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS name ON role TYPE string;
DEFINE FIELD IF NOT EXISTS display_name ON role TYPE string;
DEFINE FIELD IF NOT EXISTS description ON role TYPE option<string>;
DEFINE FIELD IF NOT EXISTS is_system ON role TYPE bool;
DEFINE FIELD IF NOT EXISTS created_at ON role TYPE number;
DEFINE FIELD IF NOT EXISTS updated_at ON role TYPE number;
DEFINE INDEX IF NOT EXISTS role_name_idx ON role COLUMNS name UNIQUE;

-- 权限表
DEFINE TABLE IF NOT EXISTS permission SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS name ON permission TYPE string;
DEFINE FIELD IF NOT EXISTS display_name ON permission TYPE string;
DEFINE FIELD IF NOT EXISTS description ON permission TYPE option<string>;
DEFINE FIELD IF NOT EXISTS resource ON permission TYPE string;
DEFINE FIELD IF NOT EXISTS action ON permission TYPE string;
DEFINE FIELD IF NOT EXISTS is_system ON permission TYPE bool;
DEFINE FIELD IF NOT EXISTS created_at ON permission TYPE number;
DEFINE FIELD IF NOT EXISTS updated_at ON permission TYPE number;
DEFINE INDEX IF NOT EXISTS permission_name_idx ON permission COLUMNS name UNIQUE;
DEFINE INDEX IF NOT EXISTS permission_resource_action_idx ON permission COLUMNS resource, action;

-- 用户角色关联表
DEFINE TABLE IF NOT EXISTS user_role SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS user_id ON user_role TYPE record<actor_identity>;
DEFINE FIELD IF NOT EXISTS role_id ON user_role TYPE record<role>;
DEFINE FIELD IF NOT EXISTS assigned_at ON user_role TYPE number;
DEFINE FIELD IF NOT EXISTS assigned_by ON user_role TYPE record<actor_identity>;
DEFINE INDEX IF NOT EXISTS user_role_unique_idx ON user_role COLUMNS user_id, role_id UNIQUE;
DEFINE INDEX IF NOT EXISTS user_role_user_idx ON user_role COLUMNS user_id;
DEFINE INDEX IF NOT EXISTS user_role_role_idx ON user_role COLUMNS role_id;

-- 角色权限关联表
DEFINE TABLE IF NOT EXISTS role_permission SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS role_id ON role_permission TYPE record<role>;
DEFINE FIELD IF NOT EXISTS permission_id ON role_permission TYPE record<permission>;
DEFINE FIELD IF NOT EXISTS granted_at ON role_permission TYPE number;
DEFINE FIELD IF NOT EXISTS granted_by ON role_permission TYPE record<actor_identity>;
DEFINE INDEX IF NOT EXISTS role_permission_unique_idx ON role_permission COLUMNS role_id, permission_id UNIQUE;
DEFINE INDEX IF NOT EXISTS role_permission_role_idx ON role_permission COLUMNS role_id;
DEFINE INDEX IF NOT EXISTS role_permission_permission_idx ON role_permission COLUMNS permission_id;

-- 用户档案表
DEFINE TABLE IF NOT EXISTS user_profile SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS user_id ON user_profile TYPE record<actor_identity>;
DEFINE FIELD IF NOT EXISTS first_name ON user_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS last_name ON user_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS display_name ON user_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS avatar_url ON user_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS phone ON user_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS date_of_birth ON user_profile TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS timezone ON user_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS locale ON user_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS bio ON user_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS website ON user_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS location ON user_profile TYPE option<string>;
DEFINE FIELD IF NOT EXISTS created_at ON user_profile TYPE number;
DEFINE FIELD IF NOT EXISTS updated_at ON user_profile TYPE number;
DEFINE INDEX IF NOT EXISTS user_profile_user_idx ON user_profile COLUMNS user_id UNIQUE;

-- 用户偏好表
DEFINE TABLE IF NOT EXISTS user_preferences SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS user_id ON user_preferences TYPE record<actor_identity>;
DEFINE FIELD IF NOT EXISTS theme ON user_preferences TYPE string DEFAULT "light";
DEFINE FIELD IF NOT EXISTS language ON user_preferences TYPE string DEFAULT "en";
DEFINE FIELD IF NOT EXISTS email_notifications ON user_preferences TYPE bool DEFAULT true;
DEFINE FIELD IF NOT EXISTS sms_notifications ON user_preferences TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS marketing_emails ON user_preferences TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS security_emails ON user_preferences TYPE bool DEFAULT true;
DEFINE FIELD IF NOT EXISTS newsletter ON user_preferences TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS timezone ON user_preferences TYPE string DEFAULT "UTC";
DEFINE FIELD IF NOT EXISTS date_format ON user_preferences TYPE string DEFAULT "YYYY-MM-DD";
DEFINE FIELD IF NOT EXISTS time_format ON user_preferences TYPE string DEFAULT "24h";
DEFINE FIELD IF NOT EXISTS created_at ON user_preferences TYPE number;
DEFINE FIELD IF NOT EXISTS updated_at ON user_preferences TYPE number;
DEFINE INDEX IF NOT EXISTS user_preferences_user_idx ON user_preferences COLUMNS user_id UNIQUE;

-- 用户活动日志表
DEFINE TABLE IF NOT EXISTS user_activity SCHEMAFULL;
-- 登录失败、限流触发这类事件未必对应一个已存在的用户，故为可选。
DEFINE FIELD IF NOT EXISTS user_id ON user_activity TYPE option<record<actor_identity>>;
DEFINE FIELD IF NOT EXISTS action ON user_activity TYPE string;
DEFINE FIELD IF NOT EXISTS category ON user_activity TYPE string;
DEFINE FIELD IF NOT EXISTS ip_address ON user_activity TYPE string;
DEFINE FIELD IF NOT EXISTS user_agent ON user_activity TYPE string;
-- details 是按事件类型变化的自由结构（reason / provider / permission / endpoint ...）。
-- SCHEMAFULL 表上必须显式放开嵌套键，否则写入会被拒：
--   "Found field 'details.endpoint', but no such field exists for table 'user_activity'"
DEFINE FIELD IF NOT EXISTS details ON user_activity TYPE object;
DEFINE FIELD IF NOT EXISTS details.* ON user_activity TYPE any;
DEFINE FIELD IF NOT EXISTS status ON user_activity TYPE string;
DEFINE FIELD IF NOT EXISTS timestamp ON user_activity TYPE number;
DEFINE INDEX IF NOT EXISTS user_activity_user_idx ON user_activity COLUMNS user_id;
DEFINE INDEX IF NOT EXISTS user_activity_timestamp_idx ON user_activity COLUMNS timestamp;
DEFINE INDEX IF NOT EXISTS user_activity_category_idx ON user_activity COLUMNS category;

-- 审计哈希链。
--
-- 单条修改、删除与乱序都会断链：改一行内容它的 event_hash 对不上，
-- 删一行则下一行的 previous_hash 指向一个不存在的前驱，seq 也会缺号。
--
-- 三个字段都是 option：本次改动之前写入的行没有链，校验端点会把它们单独
-- 计为 unchained，而不是当成断链 —— 升级不该把历史数据报成被篡改。
-- 链按**副本**分。seq 由写入进程在内存里递增，多副本各写各的链：
-- 唯一索引若只建在 seq 上，第二个副本的每一条事件都会撞号并被拒绝，
-- 表现是「从第二个副本起审计静默丢失」—— 恰好是哈希链要消灭的那类故障。
--
-- 全局单链的另一种做法是让数据库原子发号，代价是每条审计写入都要跨副本
-- 串行化，并且那条发号记录成为整个集群审计的单点。按副本分链没有跨副本
-- 协调，每条链各自完整，f4 的判据同样成立。
DEFINE FIELD IF NOT EXISTS chain_id ON user_activity TYPE option<string>;
DEFINE FIELD IF NOT EXISTS seq ON user_activity TYPE option<number>;
DEFINE FIELD IF NOT EXISTS previous_hash ON user_activity TYPE option<string>;
DEFINE FIELD IF NOT EXISTS event_hash ON user_activity TYPE option<string>;
DEFINE INDEX IF NOT EXISTS user_activity_chain_seq_idx ON user_activity COLUMNS chain_id, seq UNIQUE;

-- 审计 checkpoint。
--
-- 只有哈希链挡不住拥有全库写权限的人：他可以从被改的那一行起把整条链重算一遍。
-- checkpoint 记录某个时刻的链头，并用一把**不在数据库里**的 Ed25519 私钥签名，
-- 于是「整段历史被替换」也能被发现 —— 重算过的链头对不上已签发的签名。
DEFINE TABLE IF NOT EXISTS audit_checkpoint SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS chain_id ON audit_checkpoint TYPE string;
DEFINE FIELD IF NOT EXISTS seq_to ON audit_checkpoint TYPE number;
DEFINE FIELD IF NOT EXISTS head_hash ON audit_checkpoint TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON audit_checkpoint TYPE number;
DEFINE FIELD IF NOT EXISTS public_key ON audit_checkpoint TYPE string;
DEFINE FIELD IF NOT EXISTS signature ON audit_checkpoint TYPE string;
DEFINE INDEX IF NOT EXISTS audit_checkpoint_chain_seq_idx ON audit_checkpoint COLUMNS chain_id, seq_to UNIQUE;

-- ===============================
-- OIDC SSO 相关表结构
-- ===============================

-- OIDC 客户端应用表
DEFINE TABLE IF NOT EXISTS oidc_client SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS client_id ON oidc_client TYPE string;
DEFINE FIELD IF NOT EXISTS client_secret_hash ON oidc_client TYPE string;
DEFINE FIELD IF NOT EXISTS client_name ON oidc_client TYPE string;
DEFINE FIELD IF NOT EXISTS client_type ON oidc_client TYPE string; -- public, confidential
DEFINE FIELD IF NOT EXISTS redirect_uris ON oidc_client TYPE array;
DEFINE FIELD IF NOT EXISTS post_logout_redirect_uris ON oidc_client TYPE array;
DEFINE FIELD IF NOT EXISTS allowed_scopes ON oidc_client TYPE array;
DEFINE FIELD IF NOT EXISTS allowed_grant_types ON oidc_client TYPE array;
DEFINE FIELD IF NOT EXISTS allowed_response_types ON oidc_client TYPE array;
DEFINE FIELD IF NOT EXISTS require_pkce ON oidc_client TYPE bool DEFAULT true;
DEFINE FIELD IF NOT EXISTS access_token_lifetime ON oidc_client TYPE number DEFAULT 3600; -- 1小时
DEFINE FIELD IF NOT EXISTS refresh_token_lifetime ON oidc_client TYPE number DEFAULT 86400; -- 24小时
DEFINE FIELD IF NOT EXISTS id_token_lifetime ON oidc_client TYPE number DEFAULT 3600; -- 1小时
DEFINE FIELD IF NOT EXISTS is_active ON oidc_client TYPE bool DEFAULT true;
DEFINE FIELD IF NOT EXISTS created_by ON oidc_client TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON oidc_client TYPE number;
DEFINE FIELD IF NOT EXISTS updated_at ON oidc_client TYPE number;
DEFINE INDEX IF NOT EXISTS oidc_client_id_idx ON oidc_client COLUMNS client_id UNIQUE;

-- OIDC 授权码表
DEFINE TABLE IF NOT EXISTS oidc_authorization_code SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS code_hash ON oidc_authorization_code TYPE string;
DEFINE FIELD IF NOT EXISTS client_id ON oidc_authorization_code TYPE string;
DEFINE FIELD IF NOT EXISTS user_id ON oidc_authorization_code TYPE record<actor_identity>;
DEFINE FIELD IF NOT EXISTS redirect_uri ON oidc_authorization_code TYPE string;
DEFINE FIELD IF NOT EXISTS scope ON oidc_authorization_code TYPE string;
DEFINE FIELD IF NOT EXISTS state ON oidc_authorization_code TYPE option<string>;
DEFINE FIELD IF NOT EXISTS nonce ON oidc_authorization_code TYPE option<string>;
DEFINE FIELD IF NOT EXISTS code_challenge ON oidc_authorization_code TYPE option<string>;
DEFINE FIELD IF NOT EXISTS code_challenge_method ON oidc_authorization_code TYPE option<string>;
-- 签发时的 SoulAuth 认证会话主键，用于把 sid 带到 ID Token（P0-DECISION-10）。
DEFINE FIELD IF NOT EXISTS auth_session_ref ON oidc_authorization_code TYPE option<string>;
DEFINE FIELD IF NOT EXISTS used ON oidc_authorization_code TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS expires_at ON oidc_authorization_code TYPE number;
DEFINE FIELD IF NOT EXISTS created_at ON oidc_authorization_code TYPE number;
DEFINE INDEX IF NOT EXISTS oidc_auth_code_idx ON oidc_authorization_code COLUMNS code_hash UNIQUE;
DEFINE INDEX IF NOT EXISTS oidc_auth_code_expiry_idx ON oidc_authorization_code COLUMNS expires_at;

-- OIDC 访问令牌表
DEFINE TABLE IF NOT EXISTS oidc_access_token SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS token_hash ON oidc_access_token TYPE string;
DEFINE FIELD IF NOT EXISTS token_type ON oidc_access_token TYPE string DEFAULT "Bearer";
DEFINE FIELD IF NOT EXISTS client_id ON oidc_access_token TYPE string;
DEFINE FIELD IF NOT EXISTS user_id ON oidc_access_token TYPE record<actor_identity>;
DEFINE FIELD IF NOT EXISTS scope ON oidc_access_token TYPE string;
DEFINE FIELD IF NOT EXISTS expires_at ON oidc_access_token TYPE number;
DEFINE FIELD IF NOT EXISTS created_at ON oidc_access_token TYPE number;
DEFINE INDEX IF NOT EXISTS oidc_access_token_idx ON oidc_access_token COLUMNS token_hash UNIQUE;
DEFINE INDEX IF NOT EXISTS oidc_access_token_expiry_idx ON oidc_access_token COLUMNS expires_at;

-- OIDC 刷新令牌表
DEFINE TABLE IF NOT EXISTS oidc_refresh_token SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS token_hash ON oidc_refresh_token TYPE string;
DEFINE FIELD IF NOT EXISTS client_id ON oidc_refresh_token TYPE string;
DEFINE FIELD IF NOT EXISTS user_id ON oidc_refresh_token TYPE record<actor_identity>;
DEFINE FIELD IF NOT EXISTS access_token_hash ON oidc_refresh_token TYPE string; -- 关联访问令牌的指纹
DEFINE FIELD IF NOT EXISTS scope ON oidc_refresh_token TYPE string;
-- 同上：刷新也会签 ID Token，sid 必须能继续传递。
DEFINE FIELD IF NOT EXISTS auth_session_ref ON oidc_refresh_token TYPE option<string>;
DEFINE FIELD IF NOT EXISTS used ON oidc_refresh_token TYPE bool DEFAULT false;
DEFINE FIELD IF NOT EXISTS expires_at ON oidc_refresh_token TYPE number;
DEFINE FIELD IF NOT EXISTS created_at ON oidc_refresh_token TYPE number;
DEFINE INDEX IF NOT EXISTS oidc_refresh_token_idx ON oidc_refresh_token COLUMNS token_hash UNIQUE;
DEFINE INDEX IF NOT EXISTS oidc_refresh_token_expiry_idx ON oidc_refresh_token COLUMNS expires_at;

-- 跨副本共享的限流计数桶。
-- 记录 ID 是 (客户端标识, 端点) 的摘要；window_index 为固定窗口序号，
-- 换窗口即清零，因此不需要保留时间戳列表。
DEFINE TABLE IF NOT EXISTS rate_limit SCHEMALESS;
DEFINE FIELD IF NOT EXISTS hits ON rate_limit TYPE number DEFAULT 0;
DEFINE FIELD IF NOT EXISTS window_index ON rate_limit TYPE number DEFAULT 0;
DEFINE FIELD IF NOT EXISTS client_key ON rate_limit TYPE option<string>;
DEFINE FIELD IF NOT EXISTS endpoint ON rate_limit TYPE option<string>;
DEFINE FIELD IF NOT EXISTS blocked_until ON rate_limit TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS updated_at ON rate_limit TYPE option<datetime>;
DEFINE INDEX IF NOT EXISTS rate_limit_updated ON rate_limit FIELDS updated_at;

-- ═══════════════════ AIActor 凭证与挑战 ═══════════════════
--
-- 非人主体的认证路径。它**不经过** `user` 与 `human_account`：一个 Agent
-- 拥有独立的 `actor_identity`，凭证是一枚 Ed25519 公钥，认证是对服务端签发的
-- 一次性挑战做签名。没有邮箱，没有口令，没有 MFA。

DEFINE TABLE IF NOT EXISTS ai_actor_credential SCHEMAFULL;

DEFINE FIELD IF NOT EXISTS actor_identity_id ON ai_actor_credential TYPE record<actor_identity>;

-- base64url-no-pad 的 32 字节 Ed25519 公钥。
--
-- 这里存的是**公钥**，与库里其它密材性质不同：泄露它不产生任何冒充能力，
-- 因为私钥从未进入 SoulAuth。
DEFINE FIELD IF NOT EXISTS public_key ON ai_actor_credential TYPE string;

-- 取值受代码侧 ALLOWED_ALGORITHMS 约束（当前只有 `ed25519`）。
DEFINE FIELD IF NOT EXISTS algorithm ON ai_actor_credential TYPE string;

-- 运维标签，不参与认证判定。
DEFINE FIELD IF NOT EXISTS label ON ai_actor_credential TYPE string;

-- `active` | `revoked`。未知取值在代码侧 fail-closed 成 revoked。
DEFINE FIELD IF NOT EXISTS status ON ai_actor_credential TYPE string;
DEFINE FIELD IF NOT EXISTS created_at ON ai_actor_credential TYPE number;
DEFINE FIELD IF NOT EXISTS revoked_at ON ai_actor_credential TYPE option<number>;
DEFINE FIELD IF NOT EXISTS last_used_at ON ai_actor_credential TYPE option<number>;

-- 同一枚公钥不得注册两次：否则两个 Actor 共用一把钥匙，归因就失效了。
DEFINE INDEX IF NOT EXISTS ai_actor_credential_key_idx ON ai_actor_credential COLUMNS public_key UNIQUE;
DEFINE INDEX IF NOT EXISTS ai_actor_credential_actor_idx ON ai_actor_credential COLUMNS actor_identity_id;

DEFINE TABLE IF NOT EXISTS ai_actor_challenge SCHEMAFULL;

DEFINE FIELD IF NOT EXISTS actor_identity_id ON ai_actor_challenge TYPE record<actor_identity>;

-- base64url-no-pad 的 32 字节随机数。
--
-- 这里**不存指纹**，与 session / refresh token 的处理相反 —— 挑战不是凭证：
-- 它公开发给调用方，本身不授予任何权限，能证明身份的是对它的签名。
DEFINE FIELD IF NOT EXISTS nonce ON ai_actor_challenge TYPE string;

DEFINE FIELD IF NOT EXISTS issued_at ON ai_actor_challenge TYPE number;
DEFINE FIELD IF NOT EXISTS expires_at ON ai_actor_challenge TYPE number;

-- 一次性。消费走条件更新（`WHERE consumed = false RETURN VALUE`），
-- 与授权码、刷新令牌是同一套抗并发写法。
DEFINE FIELD IF NOT EXISTS consumed ON ai_actor_challenge TYPE bool DEFAULT false;

DEFINE INDEX IF NOT EXISTS ai_actor_challenge_nonce_idx ON ai_actor_challenge COLUMNS nonce UNIQUE;
DEFINE INDEX IF NOT EXISTS ai_actor_challenge_expiry_idx ON ai_actor_challenge COLUMNS expires_at;

-- 首个管理员的引导闸门。
--
-- 只有一行，record id 固定为 `bootstrap_claim:singleton`。存在即表示这道门
-- 已被某个请求抢到。抢占用 `CREATE`：SurrealDB 对已存在的 record id 直接报
-- `already exists`，所以「检查 + 占用」是一条语句、一次原子操作。
--
-- 引导流程后续任何一步失败都会把这一行删掉，让运维可以重来 —— 否则实例会卡在
-- 「没有管理员，而门已经关死」的状态。
DEFINE TABLE IF NOT EXISTS bootstrap_claim SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS claimed_at ON bootstrap_claim TYPE datetime;
DEFINE FIELD IF NOT EXISTS email ON bootstrap_claim TYPE string;
-- claiming    : 账号还在建
-- role_pending: 账号建好了，但授予 admin 失败 —— 带同一枚令牌、同一个邮箱
--               重试会认这一行，直接给 user_id 补授角色
-- done        : 引导完成
DEFINE FIELD IF NOT EXISTS stage ON bootstrap_claim TYPE string DEFAULT 'claiming';
-- 只在 role_pending 时有值。恢复时**只认这个 id**，绝不按邮箱去认领一个已存在的
-- 账号 —— 注册是开放的，按邮箱认领等于让人抢注 admin@… 白捡管理员。
DEFINE FIELD IF NOT EXISTS user_id ON bootstrap_claim TYPE option<string>;
