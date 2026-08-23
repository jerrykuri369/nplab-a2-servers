/*
 * udpServer — Assignment 2
 *
 * Usage: ./udpserver host:port
 *
 * One datagram socket (or one per bound address), multiplexed with select().
 * UDP is stateless: each datagram is classified by size and first byte, then
 * matched to a stored client if this is the second message.
 *
 * Handshake datagram  -> store client + send a job.
 * Answer datagram     -> compare with the stored result.
 * No reply within 10s -> drop the client; a late (11s) answer is rejected.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "calcLib.h"
#include "protocol.h"

#define CLIENT_TTL_SEC 10
#define MAX_CLIENTS 256
#define MAX_DGRAM 2048

struct pending_client {
    int in_use;
    int binary; /* 0 = text, 1 = binary */
    int expected;
    uint32_t id;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    struct timespec deadline;
};

static struct pending_client clients[MAX_CLIENTS];

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

static int same_client(const struct pending_client *c,
                       const struct sockaddr_storage *addr, socklen_t len)
{
    return c->in_use && c->addrlen == len && memcmp(&c->addr, addr, len) == 0;
}

static int find_client(const struct sockaddr_storage *addr, socklen_t len)
{
    int i;
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (same_client(&clients[i], addr, len)) {
            return i;
        }
    }
    return -1;
}

static int timespec_after(const struct timespec *a, const struct timespec *b)
{
    if (a->tv_sec != b->tv_sec) {
        return a->tv_sec > b->tv_sec;
    }
    return a->tv_nsec > b->tv_nsec;
}

static void expire_clients(void)
{
    struct timespec now;
    int i;
    clock_gettime(CLOCK_MONOTONIC, &now);
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].in_use && timespec_after(&now, &clients[i].deadline)) {
            clients[i].in_use = 0;
        }
    }
}

static int store_client(const struct sockaddr_storage *addr, socklen_t len,
                        int binary, int expected, uint32_t id)
{
    int i;
    int slot = -1;
    struct timespec now;

    expire_clients();
    i = find_client(addr, len);
    if (i >= 0) {
        slot = i;
    } else {
        for (i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].in_use) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0) {
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    clients[slot].in_use = 1;
    clients[slot].binary = binary;
    clients[slot].expected = expected;
    clients[slot].id = id;
    clients[slot].addr = *addr;
    clients[slot].addrlen = len;
    clients[slot].deadline = now;
    clients[slot].deadline.tv_sec += CLIENT_TTL_SEC;
    return slot;
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

static int is_printable_text(const unsigned char *buf, ssize_t n)
{
    return n > 0 && buf[0] >= 0x20;
}

static int is_text_hello(const char *buf, ssize_t n)
{
    char tmp[64];
    size_t len;
    if (n <= 0 || (size_t)n >= sizeof tmp) {
        return 0;
    }
    memcpy(tmp, buf, (size_t)n);
    tmp[n] = '\0';
    len = strlen(tmp);
    while (len > 0 && (tmp[len - 1] == '\n' || tmp[len - 1] == '\r')) {
        tmp[--len] = '\0';
    }
    return strcmp(tmp, "TEXT UDP 1.1") == 0;
}

static int parse_calc_message(const unsigned char *buf, ssize_t n,
                              struct calcMessage *out)
{
    if (n != (ssize_t)sizeof(struct calcMessage)) {
        return 0;
    }
    memcpy(out, buf, sizeof(*out));
    return 1;
}

static int parse_calc_protocol(const unsigned char *buf, ssize_t n,
                               struct calcProtocol *out)
{
    if (n != (ssize_t)sizeof(struct calcProtocol)) {
        return 0;
    }
    memcpy(out, buf, sizeof(*out));
    return 1;
}

static void send_text_job(int fd, const struct sockaddr *to, socklen_t tolen)
{
    char op[16];
    char job[128];
    int a, b, expected;
    int n;

    make_task(op, sizeof op, &a, &b, &expected);
    n = snprintf(job, sizeof job, "%s %d %d\n", op, a, b);
    sendto(fd, job, (size_t)n, 0, to, tolen);
    store_client((const struct sockaddr_storage *)to, tolen, 0, expected, 0);
}

static void send_binary_job(int fd, const struct sockaddr *to, socklen_t tolen)
{
    char op[16];
    int a, b, expected;
    uint32_t id;
    struct calcProtocol job;

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

    sendto(fd, &job, sizeof job, 0, to, tolen);
    store_client((const struct sockaddr_storage *)to, tolen, 1, expected, id);
}

static void reject_binary(int fd, const struct sockaddr *to, socklen_t tolen)
{
    struct calcMessage msg;
    memset(&msg, 0, sizeof msg);
    msg.type = htons(2);
    msg.message = htonl(2);
    msg.protocol = htons(17);
    msg.major_version = htons(1);
    msg.minor_version = htons(1);
    sendto(fd, &msg, sizeof msg, 0, to, tolen);
}

static void handle_dgram(int fd, unsigned char *buf, ssize_t n,
                         struct sockaddr_storage *from, socklen_t fromlen)
{
    struct calcMessage cm;
    struct calcProtocol cp;
    int idx;
    struct timespec now;

    expire_clients();
    clock_gettime(CLOCK_MONOTONIC, &now);
    idx = find_client(from, fromlen);

    /* Binary handshake: calcMessage type 22, v1.1, UDP (17). */
    if (parse_calc_message(buf, n, &cm)) {
        uint16_t type = ntohs(cm.type);
        uint16_t major = ntohs(cm.major_version);
        uint16_t minor = ntohs(cm.minor_version);
        uint16_t proto = ntohs(cm.protocol);
        uint32_t message = ntohl(cm.message);

        if (type == 22 && major == 1 && minor == 1 && proto == 17 && message == 0) {
            send_binary_job(fd, (struct sockaddr *)from, fromlen);
            return;
        }
        /* Anything else at CM size is invalid. */
        reject_binary(fd, (struct sockaddr *)from, fromlen);
        return;
    }

    /* Binary answer: calcProtocol, client->server type 2. */
    if (parse_calc_protocol(buf, n, &cp)) {
        uint16_t type = ntohs(cp.type);
        uint16_t major = ntohs(cp.major_version);
        uint16_t minor = ntohs(cp.minor_version);
        uint32_t id = ntohl(cp.id);
        int32_t result = (int32_t)ntohl((uint32_t)cp.inResult);
        struct calcMessage verdict;

        memset(&verdict, 0, sizeof verdict);
        verdict.type = htons(2);
        verdict.protocol = htons(17);
        verdict.major_version = htons(1);
        verdict.minor_version = htons(1);

        if (idx < 0 || !clients[idx].binary ||
            timespec_after(&now, &clients[idx].deadline) ||
            type != 2 || major != 1 || minor != 1 || id != clients[idx].id ||
            result != clients[idx].expected) {
            verdict.message = htonl(2);
        } else {
            verdict.message = htonl(1);
        }
        sendto(fd, &verdict, sizeof verdict, 0, (struct sockaddr *)from, fromlen);
        if (idx >= 0) {
            clients[idx].in_use = 0;
        }
        return;
    }

    /* Text. First byte must be printable. */
    if (!is_printable_text(buf, n)) {
        return;
    }

    if (is_text_hello((const char *)buf, n)) {
        send_text_job(fd, (struct sockaddr *)from, fromlen);
        return;
    }

    /* Second text message: the integer result. */
    {
        char tmp[64];
        int got;
        const char *reply;

        if ((size_t)n >= sizeof tmp) {
            return;
        }
        memcpy(tmp, buf, (size_t)n);
        tmp[n] = '\0';
        if (sscanf(tmp, "%d", &got) != 1) {
            return;
        }

        if (idx < 0 || clients[idx].binary ||
            timespec_after(&now, &clients[idx].deadline)) {
            reply = "ERROR\n";
        } else if (got == clients[idx].expected) {
            reply = "OK\n";
        } else {
            reply = "ERROR\n";
        }
        sendto(fd, reply, strlen(reply), 0, (struct sockaddr *)from, fromlen);
        if (idx >= 0) {
            clients[idx].in_use = 0;
        }
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
    int socks[8];
    int nsock = 0;
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
    bind_host = map_special_host(host, &family);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_UDP;

    err = getaddrinfo(bind_host[0] ? bind_host : NULL, port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return 1;
    }

    for (rp = res; rp != NULL && nsock < 8; rp = rp->ai_next) {
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
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) != 0) {
            close(fd);
            continue;
        }
        socks[nsock++] = fd;
        if (fd > maxfd) {
            maxfd = fd;
        }
    }
    freeaddrinfo(res);

    if (nsock == 0) {
        fprintf(stderr, "failed to bind %s:%s\n", host, port);
        return 1;
    }
    fprintf(stderr, "UDP server on %s:%s\n", host, port);

    for (;;) {
        fd_set rfds;
        struct timeval tv;
        int rc;

        expire_clients();
        FD_ZERO(&rfds);
        for (i = 0; i < nsock; i++) {
            FD_SET(socks[i], &rfds);
        }
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        rc = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            break;
        }
        if (rc == 0) {
            continue;
        }
        for (i = 0; i < nsock; i++) {
            unsigned char buf[MAX_DGRAM];
            struct sockaddr_storage from;
            socklen_t fromlen;
            ssize_t n;
            if (!FD_ISSET(socks[i], &rfds)) {
                continue;
            }
            fromlen = sizeof from;
            n = recvfrom(socks[i], buf, sizeof buf, 0, (struct sockaddr *)&from, &fromlen);
            if (n <= 0) {
                continue;
            }
            handle_dgram(socks[i], buf, n, &from, fromlen);
        }
    }
    return 1;
}
