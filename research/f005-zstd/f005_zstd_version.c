#include <stdio.h>
#include <zstd.h>

int main(void) {
  printf("F005_ZSTD_VERSION string=%s number=%u\n", ZSTD_versionString(),
         ZSTD_versionNumber());
  return 0;
}
