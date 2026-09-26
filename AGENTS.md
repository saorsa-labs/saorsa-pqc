# saorsa-pqc

Post-quantum cryptography crate used across Saorsa (ant-quic, x0x, …). Wraps the
`fips203`/`fips204`/`fips205` crates (ML-KEM, ML-DSA, SLH-DSA) plus symmetric
primitives (ChaCha20-Poly1305, AES-256-GCM, BLAKE3, SHA3, HMAC, HKDF, HPKE).

## Decisions (docs/adr/)
- **ADR-001 — pure post-quantum only** since v0.5.0: Ed25519, X25519 and hybrid
  modes were removed. Don't reintroduce classical or hybrid primitives.
- **ADR-002 — two-tier API:** `src/api/` is the high-level surface (no RNG
  parameters, `OsRng` internally, concrete return types); `src/pqc/` is the
  trait-based core with explicit RNG and parameter sets.
- Before changing crypto, formats or public APIs, check `docs/adr/`. New decisions
  go in a Proposed ADR (`docs/adr/TEMPLATE.md`); Accepted ADRs are immutable and
  only a human marks an ADR Accepted.

## Build and test
- MSRV 1.88. Default feature `simd`; others: `cert_compression`, `test-utils`,
  `benchmarks`, `fuzzing`, `dangerous_configuration`.
- The lint workflow is stricter than the workspace default: it runs
  `cargo clippy --all-targets --all-features -- -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used -W clippy::pedantic`,
  so `unwrap`/`expect`/`panic!` fail CI even in tests.
- CI also runs NIST test vectors, constant-time verification, property tests,
  memory-safety, MSRV, wasm and cross-platform jobs (`.github/workflows/`).
- Docs: `docs/ARCHITECTURE.md`, `docs/fips/`, `docs/wasm.md`.
