#!/bin/bash
#
# FIPS Evidence Package Generator
# Generates comprehensive constant-time verification evidence for FIPS 140-3 audit
#
# Usage: ./scripts/generate_fips_evidence.sh [--quick|--extended|--full]
#   --quick:    30 seconds per test (default, ~5 minutes total)
#   --extended: 5 minutes per test (~90 minutes total)
#   --full:     10 minutes per test (~3 hours total)
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_ROOT/docs/fips/evidence"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
EVIDENCE_DIR="$OUTPUT_DIR/$TIMESTAMP"

# Timing configuration
MODE="${1:---quick}"
case "$MODE" in
    --quick)
        TIMEOUT_SECS=30
        MODE_NAME="quick"
        ;;
    --extended)
        TIMEOUT_SECS=300
        MODE_NAME="extended"
        ;;
    --full)
        TIMEOUT_SECS=600
        MODE_NAME="full"
        ;;
    *)
        echo "Usage: $0 [--quick|--extended|--full]"
        exit 1
        ;;
esac

# CT verification threshold (3-sigma = 99.7% confidence)
CT_THRESHOLD="${CT_THRESHOLD:-3.0}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       FIPS 140-3 Constant-Time Evidence Generator              ║${NC}"
echo -e "${BLUE}║       Mode: $MODE_NAME ($TIMEOUT_SECS seconds per test)                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Create output directories
mkdir -p "$EVIDENCE_DIR/raw_results"
mkdir -p "$EVIDENCE_DIR/summaries"

# Benchmarks to run
CORE_BENCHMARKS=(
    "ct_eq_equal_vs_different"
    "ct_eq_early_vs_late_diff"
    "ct_array_eq_verification"
    "ct_copy_bytes_choice_verification"
    "ct_copy_bytes_length_verification"
    "ct_select_verification"
    "ct_tag_verify_matching_vs_mismatching"
    "ct_buffer_eq_32byte_keys"
    "ct_conditional_zeroize_verification"
    "ct_validate_key_length_verification"
)

EXTENDED_BENCHMARKS=(
    "ct_eq_random_data"
    "ct_eq_empty_slices"
    "ct_eq_signature_sized"
    "ct_eq_large_key_sized"
    "ct_eq_single_bit_diff"
    "ct_select_u64_verification"
    "ct_array_eq_64byte"
    "ct_shared_secret_eq"
)

# Combine benchmarks based on mode
if [ "$MODE_NAME" = "quick" ]; then
    BENCHMARKS=("${CORE_BENCHMARKS[@]}")
else
    BENCHMARKS=("${CORE_BENCHMARKS[@]}" "${EXTENDED_BENCHMARKS[@]}")
fi

# System information
echo -e "${YELLOW}Collecting system information...${NC}"
{
    echo "# System Information"
    echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo ""
    echo "## Hardware"
    echo "- Architecture: $(uname -m)"
    echo "- OS: $(uname -s) $(uname -r)"
    if [ "$(uname -s)" = "Darwin" ]; then
        echo "- CPU: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")"
        echo "- CPU Cores: $(sysctl -n hw.ncpu)"
        echo "- Memory: $(( $(sysctl -n hw.memsize) / 1073741824 )) GB"
    else
        echo "- CPU: $(cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2 | xargs)"
        echo "- CPU Cores: $(nproc)"
        echo "- Memory: $(( $(cat /proc/meminfo | grep MemTotal | awk '{print $2}') / 1048576 )) GB"
    fi
    echo ""
    echo "## Software"
    echo "- Rust: $(rustc --version)"
    echo "- Cargo: $(cargo --version)"
    echo ""
    echo "## Library Version"
    cd "$PROJECT_ROOT"
    echo "- saorsa-pqc: $(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)"
    echo "- Git commit: $(git rev-parse HEAD)"
    echo "- Git branch: $(git branch --show-current)"
    echo ""
    echo "## Test Configuration"
    echo "- Mode: $MODE_NAME"
    echo "- Timeout per test: ${TIMEOUT_SECS}s"
    echo "- CT Threshold: $CT_THRESHOLD"
    echo "- Total benchmarks: ${#BENCHMARKS[@]}"
} > "$EVIDENCE_DIR/system_info.md"

echo -e "${GREEN}System info saved to $EVIDENCE_DIR/system_info.md${NC}"

# Build CT verification benchmarks
echo ""
echo -e "${YELLOW}Building CT verification benchmarks (release mode)...${NC}"
cd "$PROJECT_ROOT"
cargo build --release --bench ct_verification 2>&1 | tee "$EVIDENCE_DIR/build.log"

# Find the benchmark binary
CT_BINARY=$(ls ./target/release/deps/ct_verification-* 2>/dev/null | grep -v '\.d$' | head -1)
if [ -z "$CT_BINARY" ]; then
    echo -e "${RED}Error: CT verification binary not found${NC}"
    exit 1
fi
echo -e "${GREEN}Binary: $CT_BINARY${NC}"

# Run benchmarks
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║             Running DudeCT Timing Analysis                     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"

PASSED=0
FAILED=0
TOTAL=${#BENCHMARKS[@]}

# Initialize results summary
RESULTS_SUMMARY="$EVIDENCE_DIR/summaries/ct_results_summary.md"
{
    echo "# Constant-Time Verification Results"
    echo ""
    echo "**Generated:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "**Mode:** $MODE_NAME ($TIMEOUT_SECS seconds per test)"
    echo "**Threshold:** |max_t| < $CT_THRESHOLD (3-sigma, 99.7% confidence)"
    echo ""
    echo "## Results Summary"
    echo ""
    echo "| Benchmark | max_t | |max_t| | Status |"
    echo "|-----------|-------|--------|--------|"
} > "$RESULTS_SUMMARY"

for i in "${!BENCHMARKS[@]}"; do
    bench="${BENCHMARKS[$i]}"
    num=$((i + 1))

    echo ""
    echo -e "${YELLOW}[$num/$TOTAL] Testing: $bench${NC}"

    # Run benchmark
    RAW_OUTPUT="$EVIDENCE_DIR/raw_results/${bench}.log"
    timeout "${TIMEOUT_SECS}s" "$CT_BINARY" --continuous "$bench" > "$RAW_OUTPUT" 2>&1 || true

    # Extract max_t value
    if [ -f "$RAW_OUTPUT" ]; then
        LAST_LINE=$(grep "max t =" "$RAW_OUTPUT" | tail -1)

        if [ -n "$LAST_LINE" ]; then
            # Extract max_t (handles positive and negative)
            MAX_T=$(echo "$LAST_LINE" | grep -oE 'max t = [+-]?[0-9]+\.?[0-9]*' | grep -oE '[+-]?[0-9]+\.?[0-9]*$' || echo "0")
            ABS_MAX_T=$(echo "$MAX_T" | tr -d '-' | tr -d '+')

            # Count measurements
            MEASUREMENTS=$(grep -c "max t =" "$RAW_OUTPUT" || echo "0")

            echo "  Measurements: $MEASUREMENTS"
            echo "  Final: $LAST_LINE"

            # Check threshold
            EXCEEDS=$(echo "$ABS_MAX_T > $CT_THRESHOLD" | bc -l 2>/dev/null || echo "0")

            if [ "$EXCEEDS" = "1" ]; then
                echo -e "  ${RED}⚠️  POTENTIAL TIMING LEAK (|t| = $ABS_MAX_T > $CT_THRESHOLD)${NC}"
                STATUS="⚠️ WARN"
                ((FAILED++))
            else
                echo -e "  ${GREEN}✅ PASS (|t| = $ABS_MAX_T < $CT_THRESHOLD)${NC}"
                STATUS="✅ PASS"
                ((PASSED++))
            fi

            # Add to summary
            echo "| \`$bench\` | $MAX_T | $ABS_MAX_T | $STATUS |" >> "$RESULTS_SUMMARY"
        else
            echo -e "  ${RED}⚠️  No max_t value found in output${NC}"
            echo "| \`$bench\` | - | - | ⚠️ NO DATA |" >> "$RESULTS_SUMMARY"
            ((FAILED++))
        fi
    else
        echo -e "  ${RED}⚠️  No output file generated${NC}"
        echo "| \`$bench\` | - | - | ❌ ERROR |" >> "$RESULTS_SUMMARY"
        ((FAILED++))
    fi
done

# Finalize summary
{
    echo ""
    echo "## Overall Statistics"
    echo ""
    echo "- **Total Tests:** $TOTAL"
    echo "- **Passed:** $PASSED"
    echo "- **Warnings/Failures:** $FAILED"
    echo "- **Pass Rate:** $(echo "scale=1; $PASSED * 100 / $TOTAL" | bc)%"
    echo ""
    echo "## Interpretation"
    echo ""
    echo "- **|max_t| < 3.0**: Strong evidence of constant-time behavior (99.7% confidence)"
    echo "- **|max_t| 3.0-5.0**: Borderline, may warrant investigation"
    echo "- **|max_t| > 5.0**: Strong evidence of timing leak (95% confidence)"
    echo ""
    echo "## Methodology"
    echo ""
    echo "Tests use DudeCT (Welch's t-test) to statistically detect timing differences"
    echo "between two input classes. Each test compares operations that should take"
    echo "identical time if the implementation is constant-time."
    echo ""
    echo "Reference: [DudeCT Paper](https://eprint.iacr.org/2016/1123)"
} >> "$RESULTS_SUMMARY"

# Generate CT_VERIFICATION_RESULTS.md for the docs folder
cp "$RESULTS_SUMMARY" "$PROJECT_ROOT/docs/fips/CT_VERIFICATION_RESULTS.md"

# Create evidence package manifest
MANIFEST="$EVIDENCE_DIR/MANIFEST.md"
{
    echo "# FIPS Evidence Package Manifest"
    echo ""
    echo "**Package ID:** $TIMESTAMP"
    echo "**Generated:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo ""
    echo "## Contents"
    echo ""
    echo "| File | Description |"
    echo "|------|-------------|"
    echo "| \`system_info.md\` | Hardware/software environment |"
    echo "| \`build.log\` | Compilation output |"
    echo "| \`summaries/ct_results_summary.md\` | Test results summary |"
    echo "| \`raw_results/*.log\` | Raw DudeCT output per benchmark |"
    echo ""
    echo "## Files"
    echo ""
    echo "\`\`\`"
    find "$EVIDENCE_DIR" -type f | sed "s|$EVIDENCE_DIR/||" | sort
    echo "\`\`\`"
    echo ""
    echo "## Verification"
    echo ""
    echo "To reproduce these results:"
    echo ""
    echo "\`\`\`bash"
    echo "git checkout $(git rev-parse HEAD)"
    echo "./scripts/generate_fips_evidence.sh $MODE"
    echo "\`\`\`"
} > "$MANIFEST"

# Print summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Evidence Generation Complete                ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Package location: ${GREEN}$EVIDENCE_DIR${NC}"
echo ""
echo "Results:"
if [ "$FAILED" -eq 0 ]; then
    echo -e "  ${GREEN}✅ All $TOTAL tests passed (|max_t| < $CT_THRESHOLD)${NC}"
else
    echo -e "  ${YELLOW}⚠️  $PASSED/$TOTAL passed, $FAILED warnings${NC}"
fi
echo ""
echo "Files generated:"
echo "  - $EVIDENCE_DIR/system_info.md"
echo "  - $EVIDENCE_DIR/summaries/ct_results_summary.md"
echo "  - $EVIDENCE_DIR/raw_results/ (${#BENCHMARKS[@]} files)"
echo "  - $EVIDENCE_DIR/MANIFEST.md"
echo "  - docs/fips/CT_VERIFICATION_RESULTS.md (updated)"
echo ""
echo "For FIPS audit, provide the entire evidence directory:"
echo "  tar -czf fips_ct_evidence_$TIMESTAMP.tar.gz -C $OUTPUT_DIR $TIMESTAMP"
