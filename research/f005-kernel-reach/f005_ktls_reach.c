#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

static void print_result(const char *name, int result, int saved_errno)
{
    printf("%s_result=%d\n", name, result);
    printf("%s_errno=%d\n", name, saved_errno);
    printf("%s_error=%s\n", name,
           saved_errno == 0 ? "none" : strerror(saved_errno));
}

int main(void)
{
    static const char invalid_ulp[] = "f005none";
    static const char tls_ulp[] = "tls";
    const char byte = 'K';
    char received = 0;
    char selected_ulp[32] = {0};
    struct sockaddr_in address;
    socklen_t address_length = sizeof(address);
    socklen_t selected_length = sizeof(selected_ulp);
    int listener = -1;
    int client = -1;
    int accepted = -1;
    int invalid_result;
    int invalid_errno;
    int tls_result;
    int tls_errno;
    int get_result;
    int get_errno;
    ssize_t write_result = -1;
    ssize_t read_result = -1;

    printf("schema=F005_KTLS_REACH_V1\n");
    printf("uid=%lu\n", (unsigned long)getuid());
    printf("euid=%lu\n", (unsigned long)geteuid());
    printf("gid=%lu\n", (unsigned long)getgid());
    printf("egid=%lu\n", (unsigned long)getegid());

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(listener, (struct sockaddr *)&address,
                    &address_length) != 0 ||
        listen(listener, 1) != 0) {
        printf("socket_control_errno=%d\n", errno);
        goto out;
    }

    client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client < 0 ||
        connect(client, (struct sockaddr *)&address, sizeof(address)) != 0) {
        printf("socket_control_errno=%d\n", errno);
        goto out;
    }

    accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (accepted < 0) {
        printf("socket_control_errno=%d\n", errno);
        goto out;
    }

    write_result = write(client, &byte, sizeof(byte));
    if (write_result == 1) {
        read_result = read(accepted, &received, sizeof(received));
    }
    printf("socket_control_errno=0\n");
    printf("socket_write_result=%ld\n", (long)write_result);
    printf("socket_read_result=%ld\n", (long)read_result);
    printf("socket_payload_readback=%d\n",
           read_result == 1 && received == byte);

    errno = 0;
    invalid_result = setsockopt(client, IPPROTO_TCP, TCP_ULP,
                                invalid_ulp, sizeof(invalid_ulp));
    invalid_errno = errno;
    print_result("invalid_ulp", invalid_result, invalid_errno);

    errno = 0;
    tls_result = setsockopt(client, IPPROTO_TCP, TCP_ULP,
                            tls_ulp, sizeof(tls_ulp));
    tls_errno = errno;
    print_result("tls_ulp", tls_result, tls_errno);

    errno = 0;
    get_result = getsockopt(client, IPPROTO_TCP, TCP_ULP,
                            selected_ulp, &selected_length);
    get_errno = errno;
    print_result("selected_ulp", get_result, get_errno);
    printf("selected_ulp_length=%lu\n", (unsigned long)selected_length);
    printf("selected_ulp_name=%s\n",
           get_result == 0 && selected_length > 0 ? selected_ulp : "none");

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
    return 0;
}
