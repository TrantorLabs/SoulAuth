# Security

## Reporting a vulnerability

Please don't report security problems in a public issue. Mail the maintainers, or use
GitHub's private vulnerability reporting. Include steps to reproduce — a reproduction
that runs is worth far more than a description.

## Known advisories, and why they are unreachable here

`cargo audit` currently reports 7. All of them come from transitive dependencies or from
APIs this project doesn't call. The reasoning is written out below so you don't have to
redo the analysis:

| Dependency | Advisory | Why it doesn't affect SoulAuth |
|---|---|---|
| `rsa 0.9` | RUSTSEC-2023-0071 (Marvin timing side channel) | **No fixed version exists, and none is coming soon.** The attack targets PKCS#1 v1.5 **decryption**. This project uses `rsa` purely as a PEM/DER codec (reading the private key, exporting `n`/`e` for JWKS); the RS256 **signing is done by `jsonwebtoken` through `ring`**, and `rsa` never performs private-key math at all. |
| `ring 0.16` | RUSTSEC-2025-0009 | The affected surface is `ring::aead::quic::HeaderProtectionKey`. This project does not use QUIC. |
| `ring 0.16` | RUSTSEC-2025-0010 (unmaintained) | Same as above; pulled in transitively by `jsonwebtoken 8`. |
| `idna 0.4` | RUSTSEC-2024-0421 (punycode label confusion) | `redirect_uri` is compared as an **exact string**, with no URL normalisation and no IDNA processing, so there is no redirect bypass to build. Email domain checks are plain string checks too. |
| `rkyv 0.7` | RUSTSEC-2026-0235 | A transitive dependency of SurrealDB; this project does not use its serialisation path directly. |
| `atomic-polyfill` | RUSTSEC-2023-0089 (unmaintained) | Transitive. |
| `proc-macro-error` | RUSTSEC-2024-0370 (unmaintained) | Build-time only; never reaches the runtime. |

### Why `axum` / `jsonwebtoken` aren't upgraded to clear `ring 0.16`

`ring 0.16` comes from `jsonwebtoken 8`, and `hyper 0.14` from `axum 0.6`. Upgrading
means going axum 0.6→0.8 (`Server` removed, `TypedHeader` moved out, extractor changes)
and jsonwebtoken 8→10, while the table above shows both advisories are unreachable here.
The risk of the change outweighs what it buys, so this is a **deliberate choice**, not an
oversight. If your compliance process needs `cargo audit` to come back empty, use
`cargo audit --ignore` together with the table above.

## Known limitations

- **The database connection only authenticates as root.** The code goes through
  `surrealdb::opt::auth::Root`; there is no branch for namespace-level or
  database-level login. Until there is, keep SurrealDB on a private network, don't
  reuse the password anywhere else, and use `https://` across network segments.
- **Registration returns 409 for a duplicate address**, so it can be used to probe
  whether an address is already registered. Password reset and resending a verification
  mail deliberately don't do this — both always return 200. That is a trade between
  usability and enumeration resistance, not an oversight.
- **ID token lifetime is hard-capped at 300 seconds** for every client, and there is no
  RFC 7662 introspection endpoint — so a relying party cannot observe a revocation
  inside that window. The cap is what bounds it.
