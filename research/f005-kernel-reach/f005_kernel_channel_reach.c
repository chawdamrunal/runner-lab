#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/keyctl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN 0x20000000
#endif

static long add_key_call(const char *type,
                         const char *description,
                         const void *payload,
                         size_t payload_length,
                         int32_t keyring)
{
    return syscall(SYS_add_key, type, description, payload,
                   payload_length, keyring);
}

static long keyctl_unlink_call(int32_t key, int32_t keyring)
{
    return syscall(SYS_keyctl, KEYCTL_UNLINK, key, keyring, 0, 0);
}

static void print_call(const char *name, long result, int saved_errno)
{
    printf("%s_result=%ld\n", name, result);
    printf("%s_errno=%d\n", name, saved_errno);
    printf("%s_error=%s\n", name,
           saved_errno == 0 ? "none" : strerror(saved_errno));
}

static void probe_keyring(void)
{
    static const char payload[] = "F005";
    long invalid_result;
    long valid_result;
    long unlink_result = -1;
    int invalid_errno;
    int valid_errno;
    int unlink_errno = 0;

    errno = 0;
    invalid_result = add_key_call(NULL, "f005-invalid", payload,
                                  sizeof(payload) - 1,
                                  KEY_SPEC_PROCESS_KEYRING);
    invalid_errno = errno;

    errno = 0;
    valid_result = add_key_call("user", "f005-owned-reach", payload,
                                sizeof(payload) - 1,
                                KEY_SPEC_PROCESS_KEYRING);
    valid_errno = errno;

    if (valid_result >= 0 && valid_result <= INT32_MAX) {
        errno = 0;
        unlink_result = keyctl_unlink_call((int32_t)valid_result,
                                           KEY_SPEC_PROCESS_KEYRING);
        unlink_errno = errno;
    }

    print_call("key_invalid_type", invalid_result, invalid_errno);
    print_call("key_valid_owned", valid_result, valid_errno);
    print_call("key_unlink_owned", unlink_result, unlink_errno);
}

static void probe_fastopen(void)
{
    const char byte = 'F';
    char received = 0;
    struct sockaddr_in address;
    socklen_t address_length = sizeof(address);
    struct pollfd poll_descriptor;
    int listener = -1;
    int client = -1;
    int accepted = -1;
    int fastopen_errno = 0;
    int accept_errno = 0;
    ssize_t fastopen_result = -1;
    ssize_t read_result = -1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(listener, (struct sockaddr *)&address,
                    &address_length) != 0 ||
        listen(listener, 1) != 0) {
        printf("tfo_setup_errno=%d\n", errno);
        goto out;
    }

    client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client < 0) {
        printf("tfo_setup_errno=%d\n", errno);
        goto out;
    }

    errno = 0;
    fastopen_result = sendto(client, &byte, sizeof(byte), MSG_FASTOPEN,
                             (struct sockaddr *)&address, sizeof(address));
    fastopen_errno = errno;

    poll_descriptor.fd = listener;
    poll_descriptor.events = POLLIN;
    poll_descriptor.revents = 0;
    if (poll(&poll_descriptor, 1, 1000) > 0 &&
        (poll_descriptor.revents & POLLIN) != 0) {
        errno = 0;
        accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        accept_errno = errno;
        if (accepted >= 0) {
            read_result = read(accepted, &received, sizeof(received));
        }
    }

    printf("tfo_setup_errno=0\n");
    printf("tfo_send_result=%ld\n", (long)fastopen_result);
    printf("tfo_send_errno=%d\n", fastopen_errno);
    printf("tfo_send_error=%s\n",
           fastopen_errno == 0 ? "none" : strerror(fastopen_errno));
    printf("tfo_accept_result=%d\n", accepted);
    printf("tfo_accept_errno=%d\n", accept_errno);
    printf("tfo_read_result=%ld\n", (long)read_result);
    printf("tfo_payload_readback=%d\n",
           read_result == 1 && received == byte);

out:
    if (accepted >= 0) {
        close(accepted);
    }
    if (client >= 0) {
        close(client);
    }
    if (listener >= 0) {
        close(listener);
    }
}

static void probe_process_primitives(void)
{
    int pipe_fds[2];
    int child_result[2] = {-1, 0};
    pid_t child;
    pid_t waited;
    long child_setsid = -1;
    int child_errno = 0;
    int wait_errno = 0;
    int status = 0;
    ssize_t read_length;

    if (pipe(pipe_fds) != 0) {
        printf("process_control_errno=%d\n", errno);
        return;
    }

    child = fork();
    if (child == 0) {
        int result[2];
        close(pipe_fds[0]);
        errno = 0;
        result[0] = (int)setsid();
        result[1] = errno;
        (void)write(pipe_fds[1], result, sizeof(result));
        close(pipe_fds[1]);
        _exit(0);
    }

    if (child < 0) {
        printf("process_control_errno=%d\n", errno);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return;
    }

    close(pipe_fds[1]);
    read_length = read(pipe_fds[0], child_result, sizeof(child_result));
    if (read_length == (ssize_t)sizeof(child_result)) {
        child_setsid = child_result[0];
        child_errno = child_result[1];
    }
    close(pipe_fds[0]);

    errno = 0;
    waited = waitpid(child, &status, 0);
    wait_errno = errno;
    printf("process_control_errno=0\n");
    printf("fork_child=%ld\n", (long)child);
    printf("child_setsid_result=%ld\n", child_setsid);
    printf("child_setsid_errno=%d\n", child_errno);
    printf("waitpid_result=%ld\n", (long)waited);
    printf("waitpid_errno=%d\n", wait_errno);
    printf("child_exit_zero=%d\n", waited == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
}

int main(void)
{
    printf("schema=F005_KERNEL_CHANNEL_REACH_V1\n");
    printf("uid=%lu\n", (unsigned long)getuid());
    printf("euid=%lu\n", (unsigned long)geteuid());
    printf("gid=%lu\n", (unsigned long)getgid());
    printf("egid=%lu\n", (unsigned long)getegid());
    probe_keyring();
    probe_fastopen();
    probe_process_primitives();
    return 0;
}

