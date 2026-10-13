#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <zstd.h>

static void fail(const char *operation, size_t code) {
  fprintf(stderr, "F005_ZSTD_ERROR operation=%s code=%zu name=%s\n", operation,
          code, ZSTD_getErrorName(code));
  abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const size_t input_capacity = ZSTD_CStreamInSize();
  const size_t output_capacity = ZSTD_CStreamOutSize();
  ZSTD_CCtx *context = ZSTD_createCCtx();
  uint8_t *output = malloc(output_capacity);
  size_t offset = 0;
  size_t result;

  if (context == NULL || output == NULL)
    abort();
  result = ZSTD_CCtx_setParameter(context, ZSTD_c_checksumFlag, 1);
  if (ZSTD_isError(result))
    fail("set-checksum", result);

  for (;;) {
    const size_t remaining_input = size - offset;
    const size_t chunk_size =
        remaining_input < input_capacity ? remaining_input : input_capacity;
    const int last_chunk = chunk_size == remaining_input;
    ZSTD_inBuffer input = {
        .src = data + offset,
        .size = chunk_size,
        .pos = 0,
    };

    for (int finished = 0; !finished;) {
      ZSTD_outBuffer encoded = {
          .dst = output,
          .size = output_capacity,
          .pos = 0,
      };

      result = ZSTD_compressStream2(
          context, &encoded, &input,
          last_chunk ? ZSTD_e_end : ZSTD_e_continue);
      if (ZSTD_isError(result))
        fail("compress-stream", result);
      finished = last_chunk ? result == 0 : input.pos == input.size;
    }
    if (input.pos != input.size)
      abort();
    offset += input.pos;
    if (last_chunk)
      break;
  }

  free(output);
  ZSTD_freeCCtx(context);
  return 0;
}
