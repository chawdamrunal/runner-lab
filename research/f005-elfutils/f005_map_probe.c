#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

static void fail(const char *operation) {
  fprintf(stderr, "F005_MAP_PROBE_ERROR operation=%s errno=%d message=%s\n",
          operation, errno, strerror(errno));
  exit(2);
}

static void include_file_backed_mapping_in_core(void) {
  FILE *stream = fopen("/proc/self/coredump_filter", "w");

  if (stream == NULL)
    fail("open-coredump-filter");
  if (fputs("0x14\n", stream) == EOF)
    fail("write-coredump-filter");
  if (fclose(stream) != 0)
    fail("close-coredump-filter");
}

int main(int argc, char **argv) {
  struct stat status;
  volatile unsigned char checksum = 0;
  unsigned char *mapping;
  int fd;

  if (argc != 2) {
    fprintf(stderr, "usage: %s MAPPED_FILE\n", argv[0]);
    return 2;
  }

  if (prctl(PR_SET_NAME, "f005-map-probe", 0, 0, 0) != 0)
    fail("pr-set-name");
  include_file_backed_mapping_in_core();
  fd = open(argv[1], O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    fail("open");
  if (fstat(fd, &status) != 0)
    fail("fstat");
  if (status.st_size <= 0)
    fail("empty-input");

  mapping = mmap(NULL, (size_t)status.st_size, PROT_READ | PROT_EXEC,
                 MAP_PRIVATE, fd, 0);
  if (mapping == MAP_FAILED)
    fail("mmap");
  for (off_t offset = 0; offset < status.st_size; offset += 4096)
    checksum ^= mapping[offset];
  checksum ^= mapping[status.st_size - 1];

  fprintf(stderr,
          "F005_MAP_PROBE_READY path=%s bytes=%lld checksum=%u pid=%ld\n",
          argv[1], (long long)status.st_size, (unsigned int)checksum,
          (long)getpid());
  fflush(stderr);
  raise(SIGSEGV);
  return 3;
}
