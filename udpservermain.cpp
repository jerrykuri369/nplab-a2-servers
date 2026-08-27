#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* You will to add includes here */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// Included to get the support library
#include <calcLib.h>
#include <protocol.h>

// Enable if you want debugging to be printed, see examble below.
// Alternative, pass CFLAGS=-DDEBUG to make, make CFLAGS=-DDEBUG
#define DEBUG


using namespace std;

#define CLIENT_TTL_SEC 10
#define MAX_CLIENTS 256
#define MAX_DGRAM 2048

struct pending_client {
  int in_use;
  int binary;
  int expected;
  uint32_t id;
  struct sockaddr_storage addr;
  socklen_t addrlen;
  struct timespec deadline;
};

static struct pending_client clients[MAX_CLIENTS];

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

static void send_text_job(int fd, const struct sockaddr *to, socklen_t tolen)
{
  char op[16];
  char job[128];
  int a, b, expected, n;

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
  calcProtocol job;

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
  calcMessage msg;
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
  calcMessage cm;
  calcProtocol cp;
  int idx;
  struct timespec now;

  expire_clients();
  clock_gettime(CLOCK_MONOTONIC, &now);
  idx = find_client(from, fromlen);

  if (n == (ssize_t)sizeof(calcMessage)) {
    uint16_t type, major, minor, proto;
    uint32_t message;

    memcpy(&cm, buf, sizeof cm);
    type = ntohs(cm.type);
    major = ntohs(cm.major_version);
    minor = ntohs(cm.minor_version);
    proto = ntohs(cm.protocol);
    message = ntohl(cm.message);

    if (type == 22 && major == 1 && minor == 1 && proto == 17 && message == 0) {
      send_binary_job(fd, (struct sockaddr *)from, fromlen);
      return;
    }
    reject_binary(fd, (struct sockaddr *)from, fromlen);
    return;
  }

  if (n == (ssize_t)sizeof(calcProtocol)) {
    uint16_t type, major, minor;
    uint32_t id;
    int32_t result;
    calcMessage verdict;

    memcpy(&cp, buf, sizeof cp);
    type = ntohs(cp.type);
    major = ntohs(cp.major_version);
    minor = ntohs(cp.minor_version);
    id = ntohl(cp.id);
    result = (int32_t)ntohl((uint32_t)cp.inResult);

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

  if (n <= 0 || buf[0] < 0x20) {
    return;
  }

  if (is_text_hello((const char *)buf, n)) {
    send_text_job(fd, (struct sockaddr *)from, fromlen);
    return;
  }

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

int main(int argc, char *argv[]){
  if (argc < 2) {
    fprintf(stderr, "Usage: %s protocol://server:port/path.\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  
  char *input = argv[1];
  char *sep = strchr(input, ':');
  
  if (!sep) {
    fprintf(stderr, "Error: input must be in host:port format\n");
    return 1;
  }
  
  // Allocate buffers big enough
  char hoststring[256];
  char portstring[64];
  
  // Copy host part
  size_t hostlen = sep - input;
  if (hostlen >= sizeof(hoststring)) {
    fprintf(stderr, "Error: hostname too long\n");
    return 1;
  }
  strncpy(hoststring, input, hostlen);
  hoststring[hostlen] = '\0';
  strncpy(portstring, sep + 1, sizeof(portstring) - 1);
  portstring[sizeof(portstring) - 1] = '\0';
  
  printf("UDP Server on: %s:%s\n", hoststring,portstring);

  initCalcLib();

  struct addrinfo hints, *results = NULL, *p;
  int sockfd = -1;
  int yes = 1;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = IPPROTO_UDP;

  if (getaddrinfo(hoststring, portstring, &hints, &results) != 0) {
    fprintf(stderr, "ERROR: RESOLVE ISSUE\n");
    return EXIT_FAILURE;
  }

  for (p = results; p != NULL; p = p->ai_next) {
    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd < 0) {
      continue;
    }
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (p->ai_family == AF_INET6) {
      int on = 1;
      setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
    }
    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
      break;
    }
    close(sockfd);
    sockfd = -1;
  }
  freeaddrinfo(results);

  if (sockfd < 0) {
    fprintf(stderr, "ERROR: CANT BIND\n");
    return EXIT_FAILURE;
  }

  for (;;) {
    fd_set reading;
    struct timeval timeout;
    int rc;
    unsigned char buf[MAX_DGRAM];
    struct sockaddr_storage clientAddr;
    socklen_t addrLen;
    ssize_t n;

    expire_clients();
    FD_ZERO(&reading);
    FD_SET(sockfd, &reading);
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    rc = select(sockfd + 1, &reading, NULL, NULL, &timeout);
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

    addrLen = sizeof clientAddr;
    n = recvfrom(sockfd, buf, sizeof buf, 0, (struct sockaddr *)&clientAddr, &addrLen);
    if (n <= 0) {
      continue;
    }
    handle_dgram(sockfd, buf, n, &clientAddr, addrLen);
  }

  close(sockfd);
  return 0;
}
