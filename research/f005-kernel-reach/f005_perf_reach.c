#define _GNU_SOURCE

#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static long perf_event_open(const struct perf_event_attr *attr,
                            pid_t pid,
                            int cpu,
                            int group_fd,
                            unsigned long flags)
{
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void emit_result(const char *name, long result, int saved_errno)
{
    printf("%s_result=%ld\n", name, result);
    printf("%s_errno=%d\n", name, saved_errno);
    printf("%s_error=%s\n", name,
           saved_errno == 0 ? "none" : strerror(saved_errno));
}

int main(void)
{
    const long page_size = sysconf(_SC_PAGESIZE);
    struct perf_event_attr attr;
    void *anonymous;
    void *perf_mapping = MAP_FAILED;
    long invalid_result;
    long valid_result;
    int invalid_errno;
    int valid_errno;
    int perf_mmap_errno = 0;
    int perf_mmap_readback = 0;
    uint32_t perf_mmap_version = 0;

    if (page_size <= 0) {
        perror("sysconf");
        return 2;
    }

    anonymous = mmap(NULL, (size_t)page_size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anonymous == MAP_FAILED) {
        perror("anonymous mmap");
        return 3;
    }
    ((volatile unsigned char *)anonymous)[0] = 0x5a;

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    errno = 0;
    invalid_result = perf_event_open(&attr, 0, -1, -1, 1UL << 63);
    invalid_errno = errno;
    if (invalid_result >= 0) {
        close((int)invalid_result);
    }

    errno = 0;
    valid_result = perf_event_open(&attr, 0, -1, -1, 0);
    valid_errno = errno;
    if (valid_result >= 0) {
        errno = 0;
        perf_mapping = mmap(NULL, (size_t)page_size * 2,
                            PROT_READ | PROT_WRITE, MAP_SHARED,
                            (int)valid_result, 0);
        perf_mmap_errno = errno;
        if (perf_mapping != MAP_FAILED) {
            const struct perf_event_mmap_page *metadata = perf_mapping;
            perf_mmap_version = metadata->version;
            perf_mmap_readback = 1;
            munmap(perf_mapping, (size_t)page_size * 2);
        }
        close((int)valid_result);
    }

    printf("schema=F005_PERF_REACH_V1\n");
    printf("uid=%lu\n", (unsigned long)getuid());
    printf("euid=%lu\n", (unsigned long)geteuid());
    printf("gid=%lu\n", (unsigned long)getgid());
    printf("egid=%lu\n", (unsigned long)getegid());
    printf("pid_positive=%ld\n", (long)getpid());
    printf("anonymous_mmap_positive=%d\n",
           ((volatile unsigned char *)anonymous)[0] == 0x5a);
    emit_result("invalid_flags", invalid_result, invalid_errno);
    emit_result("valid_self_software", valid_result, valid_errno);
    printf("perf_mmap_attempted=%d\n", valid_result >= 0);
    printf("perf_mmap_success=%d\n", perf_mapping != MAP_FAILED);
    printf("perf_mmap_errno=%d\n", perf_mmap_errno);
    printf("perf_mmap_readback=%d\n", perf_mmap_readback);
    printf("perf_mmap_version=%u\n", perf_mmap_version);

    munmap(anonymous, (size_t)page_size);
    return 0;
}

