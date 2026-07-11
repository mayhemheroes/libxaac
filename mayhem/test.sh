#!/usr/bin/env bash
# libxaac/mayhem/test.sh — RUN libxaac's decoder golden oracle (golden_decode, built by
# mayhem/build.sh with NORMAL flags) on a known AAC seed → CTRF. It never compiles, and it asserts
# decoder BEHAVIOR (bitstream-derived stream info + produced PCM), not just exit status.
#
# golden_decode REUSES the exact Codec driver the fuzzer exercises (it #includes the committed
# harness) to decode mayhem/testsuite/dec/mps_USAC_3_sin_44k.aac and assert the decoder reports the
# header-derived sampling frequency (44100 Hz), a sane channel count (2), and produces a non-trivial
# amount of PCM (cumulative outBytes > 0). Those values are read out of the AAC bitstream by the
# decoder, so a no-op / exit(0) "patch" (or a regression that stops decoding / mis-parses the
# stream) makes an asserted value wrong and golden_decode exits non-zero. "Ran without crashing"
# does NOT pass this oracle.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

GOLDEN_BIN=/mayhem/golden_decode
GOLDEN_AAC="$SRC/mayhem/xaac_dec_fuzzer/testsuite/mps_USAC_3_sin_44k.aac"

[ -x "$GOLDEN_BIN" ] || { echo "missing $GOLDEN_BIN — build.sh did not build the golden test" >&2; emit_ctrf "libxaac-golden" 0 1; exit 2; }
[ -f "$GOLDEN_AAC" ] || { echo "missing golden seed $GOLDEN_AAC" >&2; emit_ctrf "libxaac-golden" 0 1; exit 2; }

echo "test.sh: running libxaac golden decode oracle on $GOLDEN_AAC" >&2
GOLDEN_OUT=$("$GOLDEN_BIN" "$GOLDEN_AAC" 2>&1) || { echo "test.sh: golden decode FAILED (non-zero exit)" >&2; echo "$GOLDEN_OUT" >&2; emit_ctrf "libxaac-golden" 0 1; exit 1; }
echo "$GOLDEN_OUT"

# Assert BEHAVIOR: the decoder must report the expected bitstream-derived values.
# A no-op / exit(0) patch produces no output — the greps below FAIL it.
PASS_COUNT=0; FAIL_COUNT=0
check() {
  local label="$1" pattern="$2"
  if echo "$GOLDEN_OUT" | grep -qF "$pattern"; then
    echo "  PASS: $label ($pattern found)" >&2; PASS_COUNT=$(( PASS_COUNT + 1 ))
  else
    echo "  FAIL: $label — expected '$pattern' in output" >&2; FAIL_COUNT=$(( FAIL_COUNT + 1 ))
  fi
}

# Values are read from the AAC bitstream by the decoder — not present if the program is neutered.
check "sample rate 44100 Hz"    "samp_freq=44100"
check "2 channels"              "channels=2"
check "PCM output produced"     "total_out_bytes=8192"
check "decode frames reported"  "frames=10"
check "PASS marker"             "PASS: golden decode"

if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "test.sh: golden decode PASSED" >&2
  emit_ctrf "libxaac-golden" "$PASS_COUNT" 0
else
  echo "test.sh: golden decode FAILED ($FAIL_COUNT assertion(s) failed)" >&2
  emit_ctrf "libxaac-golden" "$PASS_COUNT" "$FAIL_COUNT"
  exit 1
fi
