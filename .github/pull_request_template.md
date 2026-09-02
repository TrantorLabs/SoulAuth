<!--
这个 PR 会被 squash 合并，下面写的内容就是最终的提交信息。
所以请写清楚改了什么、**为什么**，以及你考虑过又否掉的方案和否掉的理由 ——
现有历史都是这么写的。

This pull request will be squash-merged, so what you write below becomes the commit
message. Say what changed and **why**, including approaches you rejected and the reason.
-->

## 做了什么 · What this changes



## 为什么 · Why



## 跑过的 · Checks run

<!-- 三条都要跑。CI 会再跑一遍，但本地先跑能省一轮往返。 -->

- [ ] `cargo test`
- [ ] `cargo build && ./tests/integration.sh`
- [ ] `./tests/deployment_walkthrough.sh`

## 连带要改的 · Things that travel together

<!--
这个仓库里有几个数字是断言，不是装饰。只勾与本次改动相关的那些；
不相关的留空即可，不必逐条解释。详见 CONTRIBUTING.md。
-->

- [ ] 增删了单测 → 两份 README 里的数量已同步（`J14`）
- [ ] 增删了集成断言 → `MIN_PASS` 已同步（否则报「覆盖不足」）
- [ ] 加了配置项 → `contracts/configuration.yaml` 与 `.env.example` 两边都加了（`J17`）
- [ ] 加了端点 → 契约已更新，且文档站有散文描述它（`j4` + `coverage`）
- [ ] 改了 `contracts/` → 已在 SoulAuth-docs 提配套 PR（`sync-contracts.py`）
- [ ] 改动让某条 `conformance` 断言挂了 → 已在上面说明「错的是代码还是那条不变式」
