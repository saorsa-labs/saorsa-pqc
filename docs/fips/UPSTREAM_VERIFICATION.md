# Upstream FIPS Crate Verification Status

**Document Version:** 1.0
**Date:** 2025-01-08
**Tracking:** saorsa-pqc-acs.12

---

## Overview

This document tracks the constant-time verification status of upstream FIPS crates
used by saorsa-pqc. While saorsa-pqc implements a CT wrapper layer with DudeCT-verified
primitives, the underlying cryptographic operations depend on upstream implementations.

## Dependency Versions

| Crate | Version | FIPS Standard | Algorithm |
|-------|---------|---------------|-----------|
| `fips203` | 0.4.x | FIPS 203 | ML-KEM (Kyber) |
| `fips204` | 0.4.x | FIPS 204 | ML-DSA (Dilithium) |
| `fips205` | 0.4.x | FIPS 205 | SLH-DSA (SPHINCS+) |

**Source:** [integritychain](https://github.com/integritychain) (NIST PQC reference implementations in Rust)

---

## Verification Status by Crate

### fips203 (ML-KEM / Kyber)

| Operation | CT Status | Risk Level | Notes |
|-----------|-----------|------------|-------|
| `KG` (KeyGen) | ⚠️ Assumed | Medium | Random sampling, polynomial ops |
| `Encaps` | ⚠️ Assumed | Medium | Public key operations |
| `Decaps` | ⚠️ Assumed | **High** | Secret key operations, most critical |
| Shared secret comparison | ✅ Verified | Low | saorsa-pqc CT wrapper |

**Critical Path:** `Decaps` is the most timing-sensitive operation as it operates on
secret key material. Any timing variance could leak information about the secret key.

**Mitigation:**
- saorsa-pqc wraps all operations in `ct_ml_kem` module
- Shared secret handling uses `CtSharedSecret` with verified CT comparison
- API boundaries are timing-safe

### fips204 (ML-DSA / Dilithium)

| Operation | CT Status | Risk Level | Notes |
|-----------|-----------|------------|-------|
| `KG` (KeyGen) | ⚠️ Assumed | Medium | Random sampling |
| `Sign` | ⚠️ Assumed | **High** | Secret key operations |
| `Verify` | ✅ Public | Low | Public key operation |
| Signature comparison | ✅ Verified | Low | Public data, but CT for safety |

**Critical Path:** `Sign` operates on the secret signing key. Timing variance during
rejection sampling could leak information about the key.

**Mitigation:**
- saorsa-pqc wraps operations in `ct_ml_dsa` module
- Verification result handled in constant time
- API ensures timing-safe error handling

### fips205 (SLH-DSA / SPHINCS+)

| Operation | CT Status | Risk Level | Notes |
|-----------|-----------|------------|-------|
| `slh_keygen` | ⚠️ Assumed | Medium | Tree generation |
| `slh_sign` | ⚠️ Assumed | **High** | Secret key, WOTS+ chains |
| `slh_verify` | ✅ Public | Low | Public verification |

**Critical Path:** Signing involves traversing Merkle trees using secret key material.
The hash-based nature provides some inherent resistance, but timing should still be constant.

**Mitigation:**
- saorsa-pqc wraps operations in `ct_slh_dsa` module
- Verification result handled in constant time

---

## Upstream Crate Analysis

### Code Review Findings

Based on review of integritychain FIPS crate implementations:

**Positive Indicators:**
- Uses `subtle` crate for some constant-time operations
- No obvious early-exit patterns in critical paths
- Follows NIST reference implementation structure
- Active maintenance and security focus

**Areas of Concern:**
- No formal DudeCT or similar verification in upstream CI
- Polynomial operations may have data-dependent timing
- NTT (Number Theoretic Transform) timing not formally verified
- Rejection sampling loops have variable iteration counts

### Dependencies of Upstream Crates

| Upstream Dep | Used For | CT Relevance |
|--------------|----------|--------------|
| `sha3` | Hashing | Generally CT (fixed-size operations) |
| `sha2` | Hashing | Generally CT |
| `rand_core` | RNG trait | Interface only |
| `zeroize` | Memory clearing | CT when used correctly |

---

## Recommended Verification Actions

### Short Term (Before Next Release)

1. **Document upstream claims**
   - [ ] Review integritychain documentation for CT claims
   - [ ] Open issues requesting CT verification status
   - [ ] Document any responses

2. **Add integration-level DudeCT tests**
   - [ ] Test full `Encaps`/`Decaps` cycle timing
   - [ ] Test full `Sign`/`Verify` cycle timing
   - [ ] Compare timing with different key material

### Medium Term (Next Quarter)

3. **Engage with upstream maintainers**
   - [ ] Request DudeCT integration in upstream CI
   - [ ] Offer to contribute verification tests
   - [ ] Track upstream issues

4. **Implement additional protections**
   - [ ] Add timing jitter for defense-in-depth (if CT not verified)
   - [ ] Consider alternative implementations if issues found

### Long Term (For FIPS Certification)

5. **Formal verification pathway**
   - [ ] Evaluate CT-Wasm or similar formal tools
   - [ ] Consider CAVP testing for underlying primitives
   - [ ] Document verification evidence for CMVP

---

## Risk Assessment

### Current Risk Level: **Medium**

| Factor | Assessment |
|--------|------------|
| Upstream reputation | Good (integritychain, active development) |
| Code quality | Good (follows NIST specs) |
| Formal CT verification | Not present upstream |
| saorsa-pqc mitigations | Strong (CT wrapper layer, DudeCT verified) |

### Residual Risk

Even with saorsa-pqc's CT wrapper layer, the core cryptographic operations
(polynomial arithmetic, NTT, hash operations) execute in upstream code.
If those have timing leaks, our wrappers cannot fully prevent them.

**Recommendation:** Accept risk with monitoring, engage upstream for verification.

---

## Tracking

### GitHub Issues to Create

- [ ] `integritychain/fips203`: Request CT verification status
- [ ] `integritychain/fips204`: Request CT verification status
- [ ] `integritychain/fips205`: Request CT verification status

### Internal Tracking

- Epic: Side-Channel Protection Enhancement
- Task: saorsa-pqc-acs.12
- Status: Documentation complete, upstream engagement pending

---

## References

1. [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM Standard
2. [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA Standard
3. [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) - SLH-DSA Standard
4. [integritychain GitHub](https://github.com/integritychain) - Upstream crate source
5. [DudeCT Paper](https://eprint.iacr.org/2016/1123) - Timing analysis methodology

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-08 | Initial documentation |
