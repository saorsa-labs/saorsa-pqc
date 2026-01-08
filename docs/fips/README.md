# FIPS Compliance Documentation

This directory contains evidence documentation for FIPS 140-3 compliance assessment.

## Documents

| Document | Description |
|----------|-------------|
| [SIDE_CHANNEL_PROTECTION.md](./SIDE_CHANNEL_PROTECTION.md) | Side-channel attack resistance evidence |
| [CT_VERIFICATION_RESULTS.md](./CT_VERIFICATION_RESULTS.md) | DudeCT test results (auto-generated) |
| [UPSTREAM_VERIFICATION.md](./UPSTREAM_VERIFICATION.md) | Upstream crate CT verification status |

## FIPS Standards Implemented

| Standard | Algorithm | Module |
|----------|-----------|--------|
| FIPS 203 | ML-KEM (Kyber) | `src/pqc/ml_kem*.rs` |
| FIPS 204 | ML-DSA (Dilithium) | `src/pqc/ml_dsa*.rs` |
| FIPS 205 | SLH-DSA (SPHINCS+) | `src/api/slh.rs` |

## Security Features

### Constant-Time Operations

All cryptographic operations use constant-time primitives from:
- `src/pqc/constant_time.rs` - Core CT primitives
- `src/pqc/ct_fips.rs` - FIPS operation wrappers

### Verification

Timing behavior is verified using:
- **DudeCT** - Statistical timing analysis
- **CI Integration** - Automated verification on every PR
- **Threshold** - `|max_t| < 3.0` (99.7% confidence)

## Running Verification

```bash
# Quick verification (local)
cargo bench --bench ct_verification -- --continuous ct_eq_equal_vs_different

# Full CI verification
# See .github/workflows/ct-verification.yml
```

## Evidence Generation

For FIPS audit purposes, generate a complete evidence package:

```bash
# Quick verification (~5 minutes)
./scripts/generate_fips_evidence.sh --quick

# Extended verification (~90 minutes, recommended for audits)
./scripts/generate_fips_evidence.sh --extended

# Full verification (~3 hours, maximum confidence)
./scripts/generate_fips_evidence.sh --full
```

The script generates:
- `docs/fips/evidence/<timestamp>/` - Complete evidence package
- `docs/fips/CT_VERIFICATION_RESULTS.md` - Latest results summary

### Evidence Package Contents

| File | Description |
|------|-------------|
| `system_info.md` | Hardware/software environment |
| `build.log` | Compilation output |
| `summaries/ct_results_summary.md` | Test results with pass/fail |
| `raw_results/*.log` | Raw DudeCT output per benchmark |
| `MANIFEST.md` | Package contents and reproduction steps |

### For Auditors

Create a portable evidence archive:
```bash
cd docs/fips/evidence
tar -czf fips_ct_evidence_<timestamp>.tar.gz <timestamp>/
```

## Contact

For FIPS compliance questions, contact: david@saorsalabs.com
