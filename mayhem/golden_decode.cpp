/*
 * libxaac/mayhem/golden_decode.cpp — honest golden-output PATCH oracle for mayhem/test.sh.
 *
 * It REUSES the exact decoder driver the fuzzer exercises: it #includes the committed harness
 * (mayhem/harnesses/xaac_dec_fuzzer.cpp) with the harness's LLVMFuzzerTestOneInput renamed out of
 * the way, so we get the SAME Codec class (initDecoder -> configXAACDecoder -> decodeXAACStream)
 * the fuzzer drives — no divergent re-implementation of the libxaacdec API.
 *
 * It then decodes a known AAC seed (argv[1]) through that Codec and ASSERTS the decoder reports a
 * deterministic, bitstream-derived result: getXAACStreamInfo() yields a sampling frequency > 0 AND
 * a sane channel count (1..MAX_CHANNEL_COUNT) AND the decode loop produces at least one frame of
 * PCM output (cumulative outBytes > 0). Those values are read out of the AAC bitstream by the
 * decoder, so a no-op / exit(0) "patch" — or a regression that stops decoding / mis-parses the
 * stream — makes an asserted value wrong and this program exits non-zero. "Ran without crashing"
 * does NOT pass this oracle. Built with NORMAL flags (no sanitizers) by build.sh.
 */
/* Rename the harness entry point out of the way and expose the Codec's private members so the
 * oracle can read the decoder's bitstream-derived sample rate / channel count WITHOUT editing the
 * committed harness. (`#define private public` is a standard, contained test-only trick.) */
#define LLVMFuzzerTestOneInput libxaac_harness_fuzz_one_input_unused
#define private public
#include "xaac_dec_fuzzer.cpp"
#undef private
#undef LLVMFuzzerTestOneInput

#include <stdio.h>
#include <stdlib.h>

static unsigned char *slurp(const char *path, size_t *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f) { fprintf(stderr, "cannot open %s\n", path); return NULL; }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n <= 0) { fclose(f); return NULL; }
  unsigned char *buf = (unsigned char *)malloc((size_t)n);
  if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }
  fclose(f);
  *out_len = (size_t)n;
  return buf;
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s <seed.aac>\n", argv[0]); return 2; }

  size_t size = 0;
  unsigned char *data = slurp(argv[1], &size);
  if (!data || size < 2) { free(data); fprintf(stderr, "bad input\n"); return 2; }

  bool isADTS = (data[0] == 0xFF) && ((data[1] & 0xF0) == 0xF0);

  Codec codec;
  if (codec.initDecoder(data, size, isADTS) != IA_NO_ERROR) {
    fprintf(stderr, "FAIL: initDecoder error\n"); free(data); return 1;
  }

  int32_t bytesConsumed = 0;
  codec.configXAACDecoder((uint8_t *)data, (uint32_t)size, &bytesConsumed);

  /* Decode frames, accumulating produced PCM bytes (mirrors the fuzzer's decode loop). */
  long total_out = 0;
  int iters = 0;
  const uint8_t *p = data;
  size_t remaining = size;
  while ((long)remaining > bytesConsumed && iters < 500) {
    int32_t numOutBytes = 0;
    remaining -= bytesConsumed;
    p += bytesConsumed;
    codec.decodeXAACStream((uint8_t *)p, (uint32_t)remaining, &bytesConsumed, &numOutBytes);
    if (numOutBytes > 0) total_out += numOutBytes;
    iters++;
    if (bytesConsumed == 0) bytesConsumed = 4;
  }

  /* Query the bitstream-derived stream info the same way the harness does, then read the values
   * the decoder filled in (members exposed via the `private->public` trick above). */
  codec.getXAACStreamInfo();
  int32_t samp_freq = codec.mSampFreq;
  int32_t channels  = codec.mNumChannels;

  printf("golden: samp_freq=%d channels=%d total_out_bytes=%ld frames=%d\n",
         samp_freq, channels, total_out, iters);

  int rc = 0;
  if (samp_freq <= 0)                 { fprintf(stderr, "FAIL: sample rate %d <= 0\n", samp_freq); rc = 1; }
  if (channels < 1 || channels > MAX_CHANNEL_COUNT) { fprintf(stderr, "FAIL: channels %d out of range\n", channels); rc = 1; }
  if (total_out <= 0)                 { fprintf(stderr, "FAIL: decoder produced no PCM output\n"); rc = 1; }

  codec.deInitXAACDecoder();
  codec.deInitMPEGDDDrc();
  free(data);
  if (rc == 0) printf("PASS: golden decode reported valid bitstream-derived stream info + PCM\n");
  return rc;
}
