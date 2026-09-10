# Contributing to SoulAuth

> 中文版本见 [CONTRIBUTING.zh-CN.md](CONTRIBUTING.zh-CN.md)。

Thanks for looking. This page is short on purpose: most of what would normally be
review comments is enforced by the test suite instead, so there is less to remember.

## Before you write code

**Open an issue first for anything that changes behaviour.** Not as a formality — the
constraints in this codebase are unusual enough that a reasonable-looking change can
violate one, and it is cheaper to find that out before you write it than after. Typo
fixes, documentation and obviously-scoped bug fixes need no issue.

## Running the checks

```bash
cargo test                                # 188 unit tests + 65 conformance invariants
cargo build && ./tests/integration.sh     # 27 groups, 351 assertions, real database
./tests/deployment_walkthrough.sh         # executes DEPLOYMENT.md from an empty database
```

The toolchain is pinned in `rust-toolchain.toml` (1.91.1); `rustup` picks it up on its
own. CI runs `cargo clippy --all-targets -- -D warnings`, so a warning fails the build.

`tests/integration.sh` needs `surreal` on `PATH` and starts its own instance on a spare
port. It cleans up after itself; `KEEP_WORK=1` keeps the working directory and logs when
you need to see why something failed.

## Numbers in this repository are assertions, not decoration

This surprises people, so it is worth saying before your first pull request goes red:

| If you | Then also |
|---|---|
| add or remove a unit test | update the count in both READMEs — `J14` compares it against the real number |
| add or remove an integration assertion | raise `MIN_PASS` in `tests/integration.sh` — otherwise the suite reports "coverage short" |
| add a configuration key | add it to **both** `contracts/configuration.yaml` and `.env.example` — `J17` compares them in both directions |
| add an endpoint | add it to `contracts/openapi.yaml`, and describe it in prose on the documentation site — `j4` and the site's `coverage` guard both check |
| change an error response | keep the shape — `j6` allows exactly one envelope plus the OIDC RFC 6749 §5.2 form |

None of these is busywork. Every one of them exists because that specific thing drifted
once and nobody noticed until a reader hit it.

## The documentation lives in another repository

The site is [SoulAuth-docs](https://github.com/TrantorLabs/SoulAuth-docs). It renders
from a **snapshot** of `contracts/*.yaml`, not from this repository directly, so:

> If your change touches `contracts/`, open a matching pull request on SoulAuth-docs
> containing the output of `python3 scripts/sync-contracts.py`, and re-run it once your
> code change has merged so the snapshot records a clean commit.

This is currently the one rule with no guard behind it. `check:contracts` verifies the
snapshot was taken from a clean tree, but not that it is up to date.

## Architecture invariants

`tests/conformance.rs` asserts architectural rules against the source and the schema —
things like "an ActorIdentity is not a credential" and "the audit log is chained". Seven
of them are `#[ignore]`d because they do not hold yet; each carries the stage it belongs
to. `cargo test --test conformance -- --ignored` lists them.

**Relaxing an assertion in that file is a bigger change than it looks.** If your work
makes one fail, the question to answer in the pull request is which is wrong — the code
or the invariant. Both answers are acceptable; silently loosening the assertion is not.
When you complete a stage, delete its `#[ignore]` in the same pull request.

## Commit messages

Write what the change does and **why**, including approaches you rejected and the reason.
The existing history is written that way and it is one of the more useful things in the
repository — a future reader can see which alternatives were already considered.

There is no prefix convention (`feat:` / `fix:` and so on). Please do not introduce one.

## Pull requests

- Branch from `main`, one topic per pull request.
- All three CI jobs must be green: `check · clippy · test`, `integration suite`,
  `docker compose （可执行文档）`.
- Pull requests are squash-merged, so the description becomes the commit message. Write
  it accordingly.
- Some paths need a maintainer's review; see [`.github/CODEOWNERS`](.github/CODEOWNERS).
  They are the ones where a mistake is invisible until it matters: the bootstrap door,
  the audit chain, the production gate, the schema and the contracts.

## Security

Do not open a public issue for a vulnerability. [`SECURITY.md`](SECURITY.md) has the
reporting path.

## Licence

Apache-2.0. Contributions are accepted under the same licence — see section 5 of the
[LICENSE](LICENSE). There is no separate CLA.
