# Browser WASM

The same ML-DSA, ML-KEM, symmetric crypto, and FIPS implementations compile for
`wasm32-unknown-unknown`. Browser entropy uses `getrandom`'s JavaScript backend
(Web Crypto). No native Tokio runtime, threads, or libc is required by the library.

```sh
rustup target add wasm32-unknown-unknown
cargo check --lib --target wasm32-unknown-unknown
cargo test --lib --test ml_dsa_tests --test ml_kem_tests
```

The `cargo check` command checks WASM compilation. The `cargo test` command runs
the crypto tests on the native host. The [WASM CI workflow](../.github/workflows/wasm.yml)
also checks compilation only; this repository does not currently run browser
runtime integration tests.

This does not provide a WASI entropy backend. JavaScript hosts must provide secure
Web Crypto randomness.
