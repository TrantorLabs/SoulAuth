# Machine Contract Layer

这个目录是 SoulAuth 的 **Machine Contract Authority** —— 机器可读的、被测试守卫的
接口事实。它既不是文档，也不是代码，而是横在两者之间的第三层。

## 为什么需要单独一层

SoulAuth 的治理体系（GA-01～07）把「权威」拆成五种，各自能声称的东西不同：

| 权威层 | 它能回答的问题 | 载体 |
|---|---|---|
| Semantic Documentation | 这个概念**意味着**什么 | 公开文档正文 |
| **Machine Contract** | 当前 Release **实际暴露**什么表面 | **本目录** |
| External Normative | 外部标准**要求**什么 | RFC / OIDC 规范原文 |
| Runtime | 代码**真的在做**什么 | `src/` |
| Evidence | 上面几项**如何被证明** | `tests/` |

GA-07 的核心约束是：**Meaning flows down. Evidence flows up.**
语义可以向下指导契约与实现，但「我们支持 X」这句话只能自下而上地被证据顶上来。

缺了 Machine Contract 层，就只剩「文档说什么」和「代码做什么」两端，两者之间
没有可对账的中间物 —— 于是文档里的端点是手写的，代码里的权限常量是散落的，
谁也证明不了谁。这个目录把中间物补上。

## 四份注册表

| 文件 | 冻结什么 | 守卫 |
|---|---|---|
| `permissions.yaml` | 12 个权限常量 + 5 个内置角色 + 每个权限在**哪些 handler 上被真正检查** | `tests/conformance.rs::j1` |
| `configuration.yaml` | 42 个环境变量：类型、默认值、必填性、生产环境闸门 | `tests/conformance.rs::j2` |
| `openapi.yaml` | 64 条路径 / 75 个 operation + **Error Envelope**，与 axum 路由表逐条对齐 | `::j4` `::j7` |
| `standards.yaml` | 13 份外部规范各自的 implemented / supported / certified 状态 | `::j5` |

外加三条横向守卫：

- `::j3` —— 任何注册表里出现空白、`TBD`、`<EXACT>`、`Pending` 都直接让测试变红。
  依据是 V3 30 §29：未填充的占位符**阻断**发布，而不是「发布后再补」。
- `::j6` —— 全站只能有一种错误形状。它防的是一个真实存在过的缺口：
  `/api/rbac/*` 与 `/api/ops/*` 的 handler 曾返回 `Result<T, StatusCode>`，
  于是「权限不足」在那 14 个端点上是**空响应体**，在其余端点上是 JSON。
  四种形状并存时，API Reference 物理上写不出来。
- `::j7` —— 对外 URL 不得出现重复路径段。`/api/users/users/:user_id` 这类
  路径（nest 前缀与路由自身撞车的产物）会让读者第一眼认为文档写错了；
  发布前改零成本，发布后改是 breaking change。

### Error Envelope

全站错误统一为 `{"error": <稳定机器码>, "message": <人话>}`，个别错误另带
**已在契约里声明**的补充字段（`missing_permission` 带 `required_permission`，
`account_locked` 带 `locked_until_seconds`）。

按 `error` 分支，永远不要按 `message` 的文案分支 —— 码进契约，文案不进。

唯一例外是 OIDC 协议端点：形状由 RFC 6749 §5.2 规定为
`{"error", "error_description"}`，不能与上面统一。契约里单列为 `OAuthError`。

## 六个状态词

注册表里的状态词是有定义的，不能当形容词用：

- `implemented` —— 代码里存在这条路径。
- `supported` —— 当前 Release 正式承担它的行为契约与向后兼容责任。
- `tested` —— 有自动化证据覆盖。
- `conformant` —— 经过对照外部规范的符合性验证。
- `certified` —— 由标准组织的正式流程认证。**当前全部为 false**，
  自我声明不构成认证。

`implemented` 不蕴含 `supported`；`supported` 不蕴含 `conformant`。
`standards.yaml` 里 RFC 6750 就是一个 `implemented: partial, supported: false`
的真实例子：Bearer token 能用，但 `WWW-Authenticate` 质询语义没做全，
所以不承诺。

## 修改规则

**不要手工编辑本目录来"让文档好看"。** 正确顺序永远是：

1. 改 Runtime（`src/`）；
2. 改本目录的注册表使其与 Runtime 一致；
3. 跑 `cargo test --test conformance`，让守卫确认两边对上了；
4. 最后才改公开文档。

反过来做 —— 先在注册表里写上一个端点，指望之后补实现 —— 会被 `j4` 反向断言
抓住：契约声明而 Runtime 没有的端点，比 Runtime 有而契约漏掉的更危险，
因为消费方会照着它调。
