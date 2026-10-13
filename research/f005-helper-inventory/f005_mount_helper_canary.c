#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static const char *base_name(const char *path) {
  const char *slash = strrchr(path, '/');
  return slash == NULL ? path : slash + 1;
}

int main(int argc, char **argv) {
  const char *name = base_name(argv[0]);
  char output_path[256];
  int length = snprintf(output_path, sizeof(output_path), "/evidence/%s.json", name);
  if (length < 0 || (size_t)length >= sizeof(output_path)) {
    return 90;
  }

  int fd = open(output_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
  if (fd < 0) {
    dprintf(STDERR_FILENO, "canary_open_failed path=%s errno=%d\n", output_path, errno);
    return 91;
  }

  dprintf(fd,
          "{\"schema\":\"F005_MOUNT_HELPER_V1\",\"argv0\":\"%s\","
          "\"argc\":%d,\"uid\":%ld,\"euid\":%ld,\"gid\":%ld,"
          "\"egid\":%ld,\"ppid\":%ld}\n",
          argv[0], argc, (long)getuid(), (long)geteuid(), (long)getgid(),
          (long)getegid(), (long)getppid());
  close(fd);
  return 73;
}
