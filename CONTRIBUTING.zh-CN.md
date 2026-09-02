# 参与 SoulAuth

> English version: [CONTRIBUTING.md](CONTRIBUTING.md)（主版本）

这一页刻意写得短：通常要靠评审去问的那些事，这里由测试直接拦，所以需要记的东西不多。

## 动手之前

**任何改变行为的东西，先开一个 issue。** 不是走流程：这个代码库里的约束不太常规，
一个看起来合理的改动很可能违反其中一条，而在动手之前发现比写完再发现便宜得多。
错别字、文档、范围明确的 bug 修复不需要 issue。

## 本地要跑什么

```bash
cargo test                                # 188 项单测 + 61 条一致性不变式
cargo build && ./tests/integration.sh     # 27 组、355 项断言，跑在真实数据库上
./tests/deployment_walkthrough.sh         # 从空库执行一遍 DEPLOYMENT.md
```

工具链版本钉在 `rust-toolchain.toml`（1.91.1），`rustup` 会自己认。
CI 跑的是 `cargo clippy --all-targets -- -D warnings`，所以一条警告就会让构建变红。

`tests/integration.sh` 需要 `surreal` 在 `PATH` 上，它会自己在空闲端口起一个实例，
跑完自动清理。想看失败现场时用 `KEEP_WORK=1`，工作目录与日志会保留。

## 这个仓库里的数字是断言，不是装饰

这一条最容易让人第一次提 PR 就撞一片红，所以先说：

| 你如果 | 那么还要 |
|---|---|
| 增删了单测 | 改两份 README 里的数量 —— `J14` 会拿它和真实条数比对 |
| 增删了集成断言 | 调大 `tests/integration.sh` 里的 `MIN_PASS` —— 否则套件报「覆盖不足」 |
| 加了配置项 | `contracts/configuration.yaml` 与 `.env.example` **两边都要加** —— `J17` 双向比对 |
| 加了端点 | 写进 `contracts/openapi.yaml`，并在文档站用散文描述它 —— `j4` 与站点的 `coverage` 各查一头 |
| 改了错误响应 | 保持形状 —— `j6` 只认一种统一信封，外加 OIDC 的 RFC 6749 §5.2 那一种 |

这些都不是形式主义。每一条的存在，都是因为那件事真的漂过一次，而且直到读者撞上去
之前没有任何人发现。

## 文档在另一个仓库

站点是 [SoulAuth-docs](https://github.com/TrantorLabs/SoulAuth-docs)。它渲染的是
`contracts/*.yaml` 的**快照**，不是直接读这个仓库，所以：

> 改动碰到 `contracts/` 时，要在 SoulAuth-docs 同时提一个 PR，内容是
> `python3 scripts/sync-contracts.py` 的结果；并在代码 PR 合并之后再跑一次，
> 让快照记录到一个干净的 commit。

这是目前唯一没有守卫兜底的规则。`check:contracts` 只验证快照取自干净工作区，
不验证它是不是已经落后于代码。

## 架构不变式

`tests/conformance.rs` 对着源码与 schema 断言架构规则 —— 比如「ActorIdentity 不是
Credential」「审计日志是链式的」。其中 9 条标了 `#[ignore]`，因为它们还不成立，
每条都注明属于哪个 Stage。用 `cargo test --test conformance -- --ignored` 可以列出。

**放松那个文件里的断言，是比它看起来更大的改动。** 如果你的改动让某条挂了，
PR 里要回答的是「错的是代码还是这条不变式」。两个答案都可以接受，
悄悄把断言改松不行。完成一个 Stage 时，在同一个 PR 里删掉它的 `#[ignore]`。

## 提交信息

写清楚改了什么、**为什么**，包括你考虑过又否掉的方案和否掉的理由。
现有历史就是这么写的，而且它是这个仓库里比较有价值的东西之一 ——
后来的人能看出哪些替代方案已经被想过了。

没有前缀约定（`feat:` / `fix:` 之类）。请不要引入。

## Pull Request

- 从 `main` 开分支，一个 PR 只做一件事。
- 三个 CI job 必须全绿：`check · clippy · test`、`integration suite`、
  `docker compose （可执行文档）`。
- PR 走 squash 合并，所以描述会变成提交信息，请照此来写。
- 有几个路径需要维护者复核，见 [`.github/CODEOWNERS`](.github/CODEOWNERS)。
  它们的共同点是：出错之后在真正要紧的那一刻之前看不出来 ——
  开机门、审计链、生产闸门、schema 与契约。

## 安全问题

不要在公开 issue 里报漏洞。上报路径在 [`SECURITY.md`](SECURITY.md)。

## 许可

Apache-2.0。贡献按同一许可接受，见 [LICENSE](LICENSE) 第 5 节。没有单独的 CLA。
