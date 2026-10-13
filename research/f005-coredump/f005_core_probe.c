#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

static void fail(const char *what) {
  fprintf(stderr, "F005_SETUP_ERROR what=%s errno=%d message=%s\n", what,
          errno, strerror(errno));
  exit(2);
}

static void set_core_filter(void) {
  FILE *stream = fopen("/proc/self/coredump_filter", "w");
  if (stream == NULL)
    fail("open-coredump-filter");
  if (fputs("10\n", stream) == EOF)
    fail("write-coredump-filter");
  if (fclose(stream) != 0)
    fail("close-coredump-filter");
}

static void read_core_filter(char *buffer, size_t length) {
  FILE *stream = fopen("/proc/self/coredump_filter", "r");
  if (stream == NULL)
    fail("read-coredump-filter-open");
  if (fgets(buffer, (int)length, stream) == NULL)
    fail("read-coredump-filter-value");
  if (fclose(stream) != 0)
    fail("read-coredump-filter-close");
  buffer[strcspn(buffer, "\r\n")] = '\0';
}

int main(int argc, char **argv) {
  struct rlimit core_limit = {.rlim_cur = 0, .rlim_max = 0};
  char filter[32] = {0};
  int requested_dumpable;
  int observed_dumpable;

  if (argc != 2 || (strcmp(argv[1], "0") != 0 && strcmp(argv[1], "1") != 0)) {
    fprintf(stderr, "usage: %s 0|1\n", argv[0]);
    return 2;
  }
  requested_dumpable = argv[1][0] - '0';

  if (prctl(PR_SET_NAME, "f005-core-probe", 0, 0, 0) != 0)
    fail("pr-set-name");
  if (setrlimit(RLIMIT_CORE, &core_limit) != 0)
    fail("setrlimit-core");
  set_core_filter();
  if (prctl(PR_SET_DUMPABLE, requested_dumpable, 0, 0, 0) != 0)
    fail("pr-set-dumpable");

  observed_dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
  if (observed_dumpable < 0)
    fail("pr-get-dumpable");
  read_core_filter(filter, sizeof(filter));

  fprintf(stderr,
          "F005_SETUP requested_dumpable=%d observed_dumpable=%d pid=%ld uid=%ld "
          "gid=%ld rlimit_core_soft=0 rlimit_core_hard=0 coredump_filter=%s\n",
          requested_dumpable, observed_dumpable, (long)getpid(), (long)getuid(),
          (long)getgid(), filter);
  fflush(stderr);

  if (observed_dumpable != requested_dumpable) {
    fprintf(stderr, "F005_SETUP_ERROR dumpability-readback-mismatch\n");
    return 2;
  }

  sleep(3);
  raise(SIGSEGV);
  return 3;
}
