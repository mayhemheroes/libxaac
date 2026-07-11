#!/usr/bin/env bash
#
# libxaac/mayhem/build.sh — build ittiam-systems/libxaac's two OSS-Fuzz harnesses as sanitized
# libFuzzer targets (+ standalone reproducers), AND the project's own xaacdec decoder test binary
# for mayhem/test.sh.
#
# libxaac is Ittiam's C/C++ AAC / xHE-AAC (USAC) audio codec. The two fuzzed surfaces are:
#   xaac_dec_fuzzer — DECODER. Input is a raw elementary AAC bitstream. The harness sniffs the first
#                     two bytes: 0xFF 0xFx => treated as ADTS, else as a raw/MP4 AudioSpecificConfig
#                     stream, then drives initDecoder -> configXAACDecoder -> decodeXAACStream over
#                     up to 500 frames (libxaacdec API). This is the headline target ("decodes AAC").
#   xaac_enc_fuzzer — ENCODER. Input is consumed by a FuzzedDataProvider to synthesize the encoder
#                     config (AOT/sample-rate/channels/DRC/…) + PCM, then drives ixheaace_create /
#                     ixheaace_process (libxaacenc API). Any byte string is a valid seed.
#
# The harnesses live upstream in fuzzer/*.cpp; they are COPIED verbatim into mayhem/harnesses/ and
# committed. We build via the project's OWN CMake (exactly like fuzzer/ossfuzz.sh) so the libraries
# AND the harnesses are compiled with $SANITIZER_FLAGS and the fuzzed codec code is instrumented.
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). Outputs: /mayhem/<fuzzer> (libFuzzer) + /mayhem/<fuzzer>-standalone
# (run-once reproducer) + /mayhem/xaacdec (decoder test app, NORMAL flags, for test.sh).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: explicit DWARF-3 so Mayhem triage can read symbols (clang-19 -g alone emits DWARF-5).
# Threaded AFTER $SANITIZER_FLAGS so it overrides any -g the sanitizer flags might add.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
export DEBUG_FLAGS
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

# The committed harnesses (mayhem/harnesses) are byte-identical to fuzzer/*.cpp; the project CMake
# compiles fuzzer/*.cpp, so refresh those from our committed copies to make the provenance explicit
# (and to let a PATCH that edits mayhem/harnesses/* take effect through the normal build).
cp "$SRC/mayhem/harnesses/xaac_dec_fuzzer.cpp" "$SRC/fuzzer/xaac_dec_fuzzer.cpp"
cp "$SRC/mayhem/harnesses/xaac_enc_fuzzer.cpp" "$SRC/fuzzer/xaac_enc_fuzzer.cpp"

# libxaac's cmake/utils.cmake reads -DSANITIZE=<list> and adds `-fsanitize=<list>
# -fno-omit-frame-pointer` to EVERY target (library + test + fuzzer), so the codec itself is
# instrumented. The fuzzer targets are linked with $LIB_FUZZING_ENGINE (the cmake honors the env
# var as the fuzzer link flag). We translate our $SANITIZER_FLAGS into that SANITIZE list.
#
# SANITIZE LIST — derive from SANITIZER_FLAGS:
#   ASan+UBSan halting (default)  -> address,undefined  + halting via -fno-sanitize-recover (CFLAGS)
#   empty SANITIZER_FLAGS         -> no -DSANITIZE (natural build, no sanitizer runtime)
# UBSan RELAX: upstream's own ossfuzz.sh opts OUT of the `shift` check under UBSan
# (`-fno-sanitize=shift`) — libxaac's bit-twiddling decode paths trip benign oversized/negative
# shifts on ~every input, which would abort the run before the fuzzer explores. We keep that single
# narrow relax (ASan + the rest of halting UBSan stay ON). A valid AAC seed must still run to exit 0.
# IMPORTANT — flag ORDER. libxaac's cmake calls add_compile_options(-fsanitize=${SANITIZE}) which
# CMake appends AFTER CMAKE_<LANG>_FLAGS. clang applies -f(no-)sanitize left-to-right, so anything in
# SANITIZE would RE-ENABLE a check we tried to relax via CMAKE_C_FLAGS. To make our narrow relaxes
# stick, we therefore put the FULL sanitizer compile spec (incl. the -fno-sanitize relaxes, in the
# right order) into CMAKE_<LANG>_FLAGS and pass -DSANITIZE=fuzzer-no-link ONLY (so add_compile_options
# appends just the fuzzer coverage, which does not re-enable the address/undefined checks).
#
# RELAXES — two ubiquitous, benign UBSan checks libxaac's decode paths trip on ~every input; left ON
# they abort the run before the fuzzer can explore. ASan + the rest of halting UBSan stay ON; a valid
# AAC seed still runs to exit 0 (verified by mayhem/test.sh + fuzz-smoke):
#   shift               — bit-twiddling oversized/negative shifts (upstream ossfuzz.sh opts out too).
#   float-cast-overflow — the PCM writer clamps then casts float->WORD16, but a NaN sample slips past
#                         the >32767 / <-32768 clamps (decoder/ixheaacd_decode_main.c:104), tripping
#                         the cast check on benign output. Relaxing only these keeps the target
#                         halting on REAL UB (signed overflow / OOB / etc.).
SAN_COMPILE=""        # full sanitizer compile spec for CMAKE_<LANG>_FLAGS (ordered: enable then relax)
SAN_LINK=""           # sanitizer link flags appended to the fuzzer engine (see below)
USE_SANITIZE_FUZZNOLINK=0
if [ -n "${SANITIZER_FLAGS}" ]; then
  ENABLE=""
  case "$SANITIZER_FLAGS" in *address*)   ENABLE="${ENABLE:+$ENABLE,}address" ;; esac
  case "$SANITIZER_FLAGS" in *undefined*) ENABLE="${ENABLE:+$ENABLE,}undefined" ;; esac
  if [ -n "$ENABLE" ]; then
    SAN_COMPILE="-fsanitize=$ENABLE"
    case "$ENABLE" in *undefined*) SAN_COMPILE="$SAN_COMPILE -fno-sanitize=shift -fno-sanitize=float-cast-overflow" ;; esac
    case "$SANITIZER_FLAGS" in *fno-sanitize-recover*) SAN_COMPILE="$SAN_COMPILE -fno-sanitize-recover=all" ;; esac
    SAN_COMPILE="$SAN_COMPILE -fno-omit-frame-pointer"
    SAN_LINK="-fsanitize=$ENABLE"
    USE_SANITIZE_FUZZNOLINK=1
  fi
fi

# ── helper: configure+build the libxaac CMake tree with a given fuzzer link engine ───────────────
# $1 = build dir, $2 = value to export as LIB_FUZZING_ENGINE for this configure
cmake_build() {
  local bdir="$1" engine="$2"
  rm -rf "$bdir"; mkdir -p "$bdir"
  local cmake_args=(
    "$SRC"
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
    -DCMAKE_BUILD_TYPE=Debug
  )
  # -DSANITIZE=fuzzer-no-link only (enables libFuzzer coverage instrumentation + passes the compiler
  # capability check); the address/undefined instrumentation + relaxes come from CMAKE_<LANG>_FLAGS.
  if [ "$USE_SANITIZE_FUZZNOLINK" = "1" ]; then
    cmake_args+=( -DSANITIZE="fuzzer-no-link" )
  fi
  cmake_args+=(
    -DCMAKE_C_FLAGS="$SAN_COMPILE $DEBUG_FLAGS"
    -DCMAKE_CXX_FLAGS="$SAN_COMPILE $DEBUG_FLAGS"
  )
  ( cd "$bdir" && LIB_FUZZING_ENGINE="$engine" cmake "${cmake_args[@]}" \
      && LIB_FUZZING_ENGINE="$engine" make -j"$MAYHEM_JOBS" xaac_dec_fuzzer xaac_enc_fuzzer )
}

# libxaac's cmake sets the fuzzer target's LINK_FLAGS to EXACTLY $LIB_FUZZING_ENGINE (overwriting,
# not appending) — so the link line would otherwise drop the -fsanitize=address/undefined the compile
# step added, and the asan runtime never gets linked (undefined __asan_* refs). The fuzzer engine
# string therefore carries the sanitizer link flags too ($SAN_LINK, set above).
FUZZ_ENGINE="$LIB_FUZZING_ENGINE $SAN_LINK"

# ── 1) libFuzzer targets (engine = $LIB_FUZZING_ENGINE + sanitizer link flags) ───────────────────
echo "build.sh: building libFuzzer targets (sanitizers='${SAN_COMPILE:-none}')"
cmake_build "$SRC/mayhem-build-fuzz" "$FUZZ_ENGINE"
cp "$SRC/mayhem-build-fuzz/xaac_dec_fuzzer" /mayhem/xaac_dec_fuzzer
cp "$SRC/mayhem-build-fuzz/xaac_enc_fuzzer" /mayhem/xaac_enc_fuzzer

# ── 2) standalone reproducers (engine = compiled StandaloneFuzzTargetMain) ───────────────────────
# The harnesses are C++ (export extern "C" LLVMFuzzerTestOneInput); the driver is C. Compile the C
# driver to an object and use it as the "fuzzing engine" link input so cmake links a run-once main.
echo "build.sh: building standalone reproducers"
STANDALONE_OBJ="$SRC/mayhem-build-standalone-main.o"
$CC ${SAN_COMPILE} ${DEBUG_FLAGS} -c "$STANDALONE_FUZZ_MAIN" -o "$STANDALONE_OBJ"
# Same as the libFuzzer link: the standalone main object plus the sanitizer runtime link flags.
cmake_build "$SRC/mayhem-build-standalone" "$STANDALONE_OBJ $SAN_LINK"
cp "$SRC/mayhem-build-standalone/xaac_dec_fuzzer" /mayhem/xaac_dec_fuzzer-standalone
cp "$SRC/mayhem-build-standalone/xaac_enc_fuzzer" /mayhem/xaac_enc_fuzzer-standalone

# ── 3) golden decode oracle with NORMAL flags (no sanitizers) for mayhem/test.sh ─────────────────
# golden_decode.cpp REUSES the harness's Codec driver (it #includes mayhem/harnesses/
# xaac_dec_fuzzer.cpp) to decode a known seed and assert the decoder's bitstream-derived sample
# rate / channel count + produced PCM — an honest PATCH oracle (those values come from the decoder
# parsing the AAC stream, so a no-op / exit(0) patch cannot satisfy them). Built sanitizer-free in a
# separate cmake tree so test.sh stays an honest gate.
echo "build.sh: building libxaacdec (normal flags) + golden_decode oracle"
TBUILD="$SRC/mayhem-build-test"
rm -rf "$TBUILD"; mkdir -p "$TBUILD"
( cd "$TBUILD" && env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
    cmake "$SRC" -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_BUILD_TYPE=Release \
  && env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS make -j"$MAYHEM_JOBS" libxaacdec )

# The golden program links the decoder library and uses the same includes the fuzzer cmake sets
# (decoder + test + drc_src + common), plus fuzzer/ for the #included harness. Normal flags.
GOLDEN_INC=(-Idecoder -Itest -Idecoder/drc_src -Icommon -Ifuzzer)
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  "$CXX" -std=c++17 -O2 -D_X86_64_ -DX86_64 -DLOUDNESS_LEVELING_SUPPORT "${GOLDEN_INC[@]}" \
    "$SRC/mayhem/golden_decode.cpp" "$TBUILD/libxaacdec.a" -lm -lpthread \
    -o /mayhem/golden_decode

echo "build.sh complete:"
ls -l /mayhem/xaac_dec_fuzzer /mayhem/xaac_enc_fuzzer \
      /mayhem/xaac_dec_fuzzer-standalone /mayhem/xaac_enc_fuzzer-standalone \
      /mayhem/golden_decode 2>&1 || true
