# Browser WASM

The same ML-DSA, ML-KEM, symmetric crypto, and FIPS implementations compile for
`wasm32-unknown-unknown`. Browser entropy uses `getrandom`'s JavaScript backend
(Web Crypto). No native Tokio runtime, threads, or libc is required by the library.

```sh
rustup target add wasm32-unknown-unknown
cargo check --lib --target wasm32-unknown-unknown
cargo test --lib --test ml_dsa_tests --test ml_kem_tests
```

This does not provide a WASI entropy backend. JavaScript hosts must provide secure
Web Crypto randomness. Generated ant-core WASM integration tests exercise the
shared crypto through signed quotes and authenticated ML-KEM sessions.
