/*
 * tcpServer — Assignment 2
 *
 * Usage: ./tcpserver host:port
 *
 * One child per connection (fork). Supports TEXT TCP 1.1 and BINARY TCP 1.1.
 * Every client operation must finish within 5 seconds; otherwise the child
 * sends "ERROR TO\n", closes the socket, and exits.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "calcLib.h"
#include "protocol.h"

#define OP_TIMEOUT 5

static int client_fd = -1;

static void on_alarm(int sig)
{
    (void)sig;
    if (client_fd >= 0) {
        const char *msg = "ERROR TO\n";
        write(client_fd, msg, strlen(msg));
        close(client_fd);
        client_fd = -1;
    }
    _exit(1);
}

static void on_sigchld(int sig)
{
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

/* host:port, [ipv6]:port, or last-colon split. */
static int parse_host_port(const char *input, char *host, size_t host_sz,
                           char *port, size_t port_sz)
{
    const char *sep;
    size_t hlen;

    if (input[0] == '[') {
        const char *rb = strchr(input, ']');
        if (rb == NULL || rb[1] != ':') {
            return -1;
        }
        hlen = (size_t)(rb - (input + 1));
        if (hlen == 0 || hlen >= host_sz) {
            return -1;
        }
        memcpy(host, input + 1, hlen);
        host[hlen] = '\0';
        strncpy(port, rb + 2, port_sz - 1);
        port[port_sz - 1] = '\0';
        return port[0] ? 0 : -1;
    }

    sep = strrchr(input, ':');
    if (sep == NULL || sep == input || sep[1] == '\0') {
        return -1;
    }
    hlen = (size_t)(sep - input);
    if (hlen >= host_sz) {
        return -1;
    }
    memcpy(host, input, hlen);
    host[hlen] = '\0';
    strncpy(port, sep + 1, port_sz - 1);
    port[port_sz - 1] = '\0';
    return 0;
}

static const char *map_special_host(const char *host, int *family)
{
    if (strcmp(host, "ip4-localhost") == 0) {
        *family = AF_INET;
        return "127.0.0.1";
    }
    if (strcmp(host, "ip6-localhost") == 0) {
        *family = AF_INET6;
        return "::1";
    }
    *family = AF_UNSPEC;
    return host;
}

static ssize_t timed_read(int fd, void *buf, size_t n)
{
    size_t got = 0;
    alarm(OP_TIMEOUT);
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r == 0) {
            alarm(0);
            return (ssize_t)got;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            alarm(0);
            return -1;
        }
        got += (size_t)r;
    }
    alarm(0);
    return (ssize_t)got;
}

static ssize_t timed_read_line(int fd, char *buf, size_t cap)
{
    size_t n = 0;
    alarm(OP_TIMEOUT);
    while (n + 1 < cap) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r == 0) {
            alarm(0);
            buf[n] = '\0';
            return (ssize_t)n;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            alarm(0);
            return -1;
        }
        buf[n++] = c;
        if (c == '\n') {
            break;
        }
    }
    alarm(0);
    buf[n] = '\0';
    return (ssize_t)n;
}

static int timed_write(int fd, const void *buf, size_t n)
{
    size_t sent = 0;
    alarm(OP_TIMEOUT);
    while (sent < n) {
        ssize_t w = write(fd, (const char *)buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            alarm(0);
            return -1;
        }
        sent += (size_t)w;
    }
    alarm(0);
    return 0;
}

static void strip_crlf(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

static int arith_code(const char *op)
{
    if (strcmp(op, "add") == 0) {
        return 1;
    }
    if (strcmp(op, "sub") == 0) {
        return 2;
    }
    if (strcmp(op, "mul") == 0) {
        return 3;
    }
    if (strcmp(op, "div") == 0) {
        return 4;
    }
    return 0;
}

static void make_task(char *op, size_t opsz, int *a, int *b, int *expected)
{
    const char *t = randomType();
    strncpy(op, t, opsz - 1);
    op[opsz - 1] = '\0';
    *a = randomInt();
    *b = randomInt();
    if (strcmp(op, "div") == 0 && *b == 0) {
        *b = 1;
    }
    if (strcmp(op, "add") == 0) {
        *expected = *a + *b;
    } else if (strcmp(op, "sub") == 0) {
        *expected = *a - *b;
    } else if (strcmp(op, "mul") == 0) {
        *expected = *a * *b;
    } else {
        *expected = *a / *b;
    }
}

static void handle_text(int fd)
{
    char op[16];
    char line[256];
    char task[128];
    int a, b, expected, got;
    int n;

    make_task(op, sizeof op, &a, &b, &expected);
    n = snprintf(task, sizeof task, "%s %d %d\n", op, a, b);
    if (timed_write(fd, task, (size_t)n) < 0) {
        return;
    }

    if (timed_read_line(fd, line, sizeof line) <= 0) {
        timed_write(fd, "ERROR TO\n", 9);
        return;
    }
    strip_crlf(line);
    if (sscanf(line, "%d", &got) != 1) {
        timed_write(fd, "ERROR\n", 6);
        return;
    }
    if (got == expected) {
        timed_write(fd, "OK\n", 3);
    } else {
        timed_write(fd, "ERROR\n", 6);
    }
}

static void handle_binary(int fd)
{
    char op[16];
    int a, b, expected;
    uint32_t id;
    struct calcProtocol job, ans;
    struct calcMessage verdict;

    make_task(op, sizeof op, &a, &b, &expected);
    id = (uint32_t)(randomInt() + 1) * 1000u + (uint32_t)randomInt();

    memset(&job, 0, sizeof job);
    job.type = htons(1);
    job.major_version = htons(1);
    job.minor_version = htons(1);
    job.id = htonl(id);
    job.arith = htonl((uint32_t)arith_code(op));
    job.inValue1 = htonl(a);
    job.inValue2 = htonl(b);
    job.inResult = htonl(0);

    if (timed_write(fd, &job, sizeof job) < 0) {
        return;
    }

    if (timed_read(fd, &ans, sizeof ans) != (ssize_t)sizeof ans) {
        timed_write(fd, "ERROR TO\n", 9);
        return;
    }

    memset(&verdict, 0, sizeof verdict);
    verdict.type = htons(2);
    verdict.protocol = htons(6);
    verdict.major_version = htons(1);
    verdict.minor_version = htons(1);

    if (ntohs(ans.type) == 2 && ntohs(ans.major_version) == 1 &&
        ntohs(ans.minor_version) == 1 && ntohl(ans.id) == id &&
        (int32_t)ntohl((uint32_t)ans.inResult) == expected) {
        verdict.message = htonl(1);
    } else {
        verdict.message = htonl(2);
    }
    timed_write(fd, &verdict, sizeof verdict);
}

static void handle_client(int fd)
{
    const char *hello = "TEXT TCP 1.1\nBINARY TCP 1.1\n\n";
    char line[256];

    client_fd = fd;
    signal(SIGALRM, on_alarm);

    if (timed_write(fd, hello, strlen(hello)) < 0) {
        return;
    }
    if (timed_read_line(fd, line, sizeof line) <= 0) {
        timed_write(fd, "ERROR TO\n", 9);
        return;
    }
    strip_crlf(line);

    if (strcmp(line, "TEXT TCP 1.1 OK") == 0) {
        handle_text(fd);
    } else if (strcmp(line, "BINARY TCP 1.1 OK") == 0) {
        handle_binary(fd);
    } else {
        const char *err = "ERROR: MISSMATCH PROTOCOL\n";
        timed_write(fd, err, strlen(err));
    }
}

int main(int argc, char **argv)
{
    char host[256];
    char port[64];
    const char *bind_host;
    int family;
    struct addrinfo hints;
    struct addrinfo *res = NULL, *rp;
    int listen_fds[8];
    int nlisten = 0;
    int maxfd = -1;
    int i;
    int err;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s host:port\n", argv[0]);
        return 1;
    }
    if (parse_host_port(argv[1], host, sizeof host, port, sizeof port) != 0) {
        fprintf(stderr, "Error: input must be in host:port format\n");
        return 1;
    }

    initCalcLib();
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, on_sigchld);

    bind_host = map_special_host(host, &family);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_TCP;

    err = getaddrinfo(bind_host[0] ? bind_host : NULL, port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return 1;
    }

    for (rp = res; rp != NULL && nlisten < 8; rp = rp->ai_next) {
        int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        int yes = 1;
        if (fd < 0) {
            continue;
        }
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
        if (rp->ai_family == AF_INET6) {
            int off = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
        }
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) != 0 || listen(fd, 16) != 0) {
            close(fd);
            continue;
        }
        listen_fds[nlisten++] = fd;
        if (fd > maxfd) {
            maxfd = fd;
        }
    }
    freeaddrinfo(res);

    if (nlisten == 0) {
        fprintf(stderr, "failed to bind %s:%s\n", host, port);
        return 1;
    }
    fprintf(stderr, "TCP server on %s:%s\n", host, port);

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        for (i = 0; i < nlisten; i++) {
            FD_SET(listen_fds[i], &rfds);
        }
        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            break;
        }
        for (i = 0; i < nlisten; i++) {
            int conn;
            pid_t pid;
            if (!FD_ISSET(listen_fds[i], &rfds)) {
                continue;
            }
            conn = accept(listen_fds[i], NULL, NULL);
            if (conn < 0) {
                if (errno == EINTR) {
                    continue;
                }
                perror("accept");
                continue;
            }
            pid = fork();
            if (pid < 0) {
                perror("fork");
                close(conn);
                continue;
            }
            if (pid == 0) {
                int j;
                for (j = 0; j < nlisten; j++) {
                    close(listen_fds[j]);
                }
                initCalcLib();
                handle_client(conn);
                close(conn);
                _exit(0);
            }
            close(conn);
        }
    }
    return 1;
}
