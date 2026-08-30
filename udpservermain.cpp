#include <stdio.h>                 // printf, fprintf, perror
#include <string.h>                // strchr, strncpy, strcmp, strlen, memset, memcpy, memcmp
#include <stdlib.h>                // exit, EXIT_FAILURE
/* You will to add includes here */
#include <arpa/inet.h>             // htons, htonl, ntohs, ntohl
#include <ctype.h>                 // character tests if needed
#include <errno.h>                 // errno, EINTR
#include <netdb.h>                 // getaddrinfo, freeaddrinfo, addrinfo
#include <netinet/in.h>            // IPPROTO_UDP, IPV6_V6ONLY
#include <sys/select.h>            // select, fd_set, FD_ZERO, FD_SET
#include <sys/socket.h>            // socket, bind, recvfrom, sendto, setsockopt
#include <sys/time.h>              // struct timeval
#include <sys/types.h>             // POSIX types
#include <time.h>                  // clock_gettime, CLOCK_MONOTONIC, timespec
#include <unistd.h>                // close

// Included to get the support library
#include <calcLib.h>               // initCalcLib, randomType, randomInt
#include <protocol.h>              // packed calcProtocol (26 B) and calcMessage (12 B)

// Enable if you want debugging to be printed, see examble below.
// Alternative, pass CFLAGS=-DDEBUG to make, make CFLAGS=-DDEBUG
#define DEBUG                      // kept from the course template


using namespace std;               // required by the course template

#define CLIENT_TTL_SEC 10          // a job is valid for 10 s; a reply at 11 s is rejected
#define MAX_CLIENTS 256            // how many waiting UDP clients we remember
#define MAX_DGRAM 2048             // recvfrom buffer (TEXT jobs are tiny; this is generous)

// UDP is stateless: the socket does not remember who last spoke.
// We store each waiting client ourselves, keyed by source address.
struct pending_client {
  int in_use;                      // 1 = this slot holds a client waiting for an answer
  int binary;                      // 0 = TEXT UDP, 1 = BINARY UDP
  int expected;                    // correct result for the job we sent
  uint32_t id;                     // calcProtocol id the client must echo (binary only)
  struct sockaddr_storage addr;    // who to send the verdict back to
  socklen_t addrlen;               // length of that address (IPv4 or IPv6)
  struct timespec deadline;        // now + 10 s; after this the slot is expired
};

static struct pending_client clients[MAX_CLIENTS];  // the in-memory client table

// True if this slot is the same sender (same address bytes and length).
static int same_client(const struct pending_client *c,
                       const struct sockaddr_storage *addr, socklen_t len)
{
  return c->in_use && c->addrlen == len && memcmp(&c->addr, addr, len) == 0;
}

// Linear search: return the table index for this sender, or -1 if unknown.
static int find_client(const struct sockaddr_storage *addr, socklen_t len)
{
  int i;                           // loop index
  for (i = 0; i < MAX_CLIENTS; i++) {
    if (same_client(&clients[i], addr, len)) {
      return i;                    // found
    }
  }
  return -1;                       // first message from this address (or already expired)
}

// True if timespec a is strictly after timespec b.
static int timespec_after(const struct timespec *a, const struct timespec *b)
{
  if (a->tv_sec != b->tv_sec) {
    return a->tv_sec > b->tv_sec;
  }
  return a->tv_nsec > b->tv_nsec;
}

// Drop clients that did not answer within 10 seconds.
static void expire_clients(void)
{
  struct timespec now;             // current monotonic time
  int i;
  clock_gettime(CLOCK_MONOTONIC, &now);  // not wall-clock, so NTP cannot stretch the window
  for (i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].in_use && timespec_after(&now, &clients[i].deadline)) {
      clients[i].in_use = 0;       // forget this client; a late 11 s reply will not match
    }
  }
}

// Remember this sender until they answer, or until the 10 s window closes.
static int store_client(const struct sockaddr_storage *addr, socklen_t len,
                        int binary, int expected, uint32_t id)
{
  int i;
  int slot = -1;                   // table index we will use
  struct timespec now;

  expire_clients();                // free stale slots first
  i = find_client(addr, len);
  if (i >= 0) {
    slot = i;                      // same sender sent another hello: overwrite the old job
  } else {
    for (i = 0; i < MAX_CLIENTS; i++) {
      if (!clients[i].in_use) {
        slot = i;                  // first free slot
        break;
      }
    }
  }
  if (slot < 0) {
    return -1;                     // table full; cannot store this client
  }

  clock_gettime(CLOCK_MONOTONIC, &now);
  clients[slot].in_use = 1;
  clients[slot].binary = binary;
  clients[slot].expected = expected;
  clients[slot].id = id;
  clients[slot].addr = *addr;
  clients[slot].addrlen = len;
  clients[slot].deadline = now;
  clients[slot].deadline.tv_sec += CLIENT_TTL_SEC;  // valid until now + 10 s
  return slot;
}

// Map operator name to calcProtocol.arith: 1 add, 2 sub, 3 mul, 4 div.
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

// Random job from calcLib. Second operand is never 0 on division.
static void make_task(char *op, size_t opsz, int *a, int *b, int *expected)
{
  const char *t = randomType();    // "add", "div", or "mul"
  strncpy(op, t, opsz - 1);
  op[opsz - 1] = '\0';
  *a = randomInt();                // 0..99
  *b = randomInt();
  if (strcmp(op, "div") == 0 && *b == 0) {  // assignment: no division by zero
    *b = 1;
  }
  if (strcmp(op, "add") == 0) {
    *expected = *a + *b;
  } else if (strcmp(op, "sub") == 0) {
    *expected = *a - *b;
  } else if (strcmp(op, "mul") == 0) {
    *expected = *a * *b;
  } else {
    *expected = *a / *b;           // integer division
  }
}

// True if the datagram is the TEXT hello "TEXT UDP 1.1" (optional newline).
static int is_text_hello(const char *buf, ssize_t n)
{
  char tmp[64];                    // NUL-terminated copy for string ops
  size_t len;
  if (n <= 0 || (size_t)n >= sizeof tmp) {
    return 0;                      // too small or too large to be the hello
  }
  memcpy(tmp, buf, (size_t)n);
  tmp[n] = '\0';
  len = strlen(tmp);
  while (len > 0 && (tmp[len - 1] == '\n' || tmp[len - 1] == '\r')) {
    tmp[--len] = '\0';             // strip line ending
  }
  return strcmp(tmp, "TEXT UDP 1.1") == 0;
}

// First TEXT datagram: store the client and send "op a b\n".
static void send_text_job(int fd, const struct sockaddr *to, socklen_t tolen)
{
  char op[16];
  char job[128];
  int a, b, expected, n;

  make_task(op, sizeof op, &a, &b, &expected);
  n = snprintf(job, sizeof job, "%s %d %d\n", op, a, b);
  sendto(fd, job, (size_t)n, 0, to, tolen);  // reply to this datagram's sender
  store_client((const struct sockaddr_storage *)to, tolen, 0, expected, 0);
}

// First BINARY datagram: store the client and send a calcProtocol job (type 1).
static void send_binary_job(int fd, const struct sockaddr *to, socklen_t tolen)
{
  char op[16];
  int a, b, expected;
  uint32_t id;
  calcProtocol job;

  make_task(op, sizeof op, &a, &b, &expected);
  id = (uint32_t)(randomInt() + 1) * 1000u + (uint32_t)randomInt();

  memset(&job, 0, sizeof job);
  job.type = htons(1);             // 1 = server -> client
  job.major_version = htons(1);    // version 1.1
  job.minor_version = htons(1);
  job.id = htonl(id);
  job.arith = htonl((uint32_t)arith_code(op));
  job.inValue1 = htonl(a);
  job.inValue2 = htonl(b);
  job.inResult = htonl(0);

  sendto(fd, &job, sizeof job, 0, to, tolen);  // 26-byte packed job
  store_client((const struct sockaddr_storage *)to, tolen, 1, expected, id);
}

// Reject a bad binary hello with calcMessage message=2, protocol=17 (UDP).
static void reject_binary(int fd, const struct sockaddr *to, socklen_t tolen)
{
  calcMessage msg;
  memset(&msg, 0, sizeof msg);
  msg.type = htons(2);             // server -> client, binary
  msg.message = htonl(2);          // 2 = NOT OK
  msg.protocol = htons(17);        // 17 = UDP
  msg.major_version = htons(1);
  msg.minor_version = htons(1);
  sendto(fd, &msg, sizeof msg, 0, to, tolen);
}

// Classify one datagram by size, then by content. Never assume who sent it.
static void handle_dgram(int fd, unsigned char *buf, ssize_t n,
                         struct sockaddr_storage *from, socklen_t fromlen)
{
  calcMessage cm;                  // 12-byte binary hello / verdict
  calcProtocol cp;                 // 26-byte binary job / answer
  int idx;                         // pending-client slot, or -1
  struct timespec now;

  expire_clients();                // drop anyone past 10 s before we look them up
  clock_gettime(CLOCK_MONOTONIC, &now);
  idx = find_client(from, fromlen);  // who sent this datagram?

  // 12 bytes -> calcMessage. Server should only see client types 21-23; we accept 22.
  if (n == (ssize_t)sizeof(calcMessage)) {
    uint16_t type, major, minor, proto;
    uint32_t message;

    memcpy(&cm, buf, sizeof cm);   // copy so packed fields are aligned enough to convert
    type = ntohs(cm.type);
    major = ntohs(cm.major_version);
    minor = ntohs(cm.minor_version);
    proto = ntohs(cm.protocol);
    message = ntohl(cm.message);

    if (type == 22 && major == 1 && minor == 1 && proto == 17 && message == 0) {
      send_binary_job(fd, (struct sockaddr *)from, fromlen);  // valid BINARY UDP 1.1 hello
      return;
    }
    reject_binary(fd, (struct sockaddr *)from, fromlen);  // wrong type / version / protocol
    return;
  }

  // 26 bytes -> calcProtocol answer. Must be a known binary client, on time, matching id.
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
        result != clients[idx].expected) {  // unknown, late, wrong id, or wrong result
      verdict.message = htonl(2);  // NOT OK
    } else {
      verdict.message = htonl(1);  // OK
    }
    sendto(fd, &verdict, sizeof verdict, 0, (struct sockaddr *)from, fromlen);
    if (idx >= 0) {
      clients[idx].in_use = 0;     // one job per client; forget them after the verdict
    }
    return;
  }

  // TEXT starts with a printable byte (>= 0x20 / '!'). Binary types start with 0x00.
  if (n <= 0 || buf[0] < 0x20) {
    return;                        // not a valid TEXT datagram
  }

  if (is_text_hello((const char *)buf, n)) {
    send_text_job(fd, (struct sockaddr *)from, fromlen);  // first TEXT message
    return;
  }

  // Second TEXT datagram: the integer result. Late or unknown clients are rejected.
  {
    char tmp[64];
    int got;                       // parsed integer
    const char *reply;

    if ((size_t)n >= sizeof tmp) {
      return;                      // not a short integer string
    }
    memcpy(tmp, buf, (size_t)n);
    tmp[n] = '\0';
    if (sscanf(tmp, "%d", &got) != 1) {
      return;                      // not an integer — ignore
    }

    if (idx < 0 || clients[idx].binary ||
        timespec_after(&now, &clients[idx].deadline)) {
      reply = "ERROR\n";           // unknown, was binary, or past 10 s
    } else if (got == clients[idx].expected) {
      reply = "OK\n";
    } else {
      reply = "ERROR\n";           // wrong value
    }
    sendto(fd, reply, strlen(reply), 0, (struct sockaddr *)from, fromlen);
    if (idx >= 0) {
      clients[idx].in_use = 0;
    }
  }
}

int main(int argc, char *argv[]){
  if (argc < 2) {                  // one required argument: host:port
    fprintf(stderr, "Usage: %s protocol://server:port/path.\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  
  char *input = argv[1];           // the host:port string
  char *sep = strchr(input, ':');  // first colon splits host from port (template parser)
  
  if (!sep) {
    fprintf(stderr, "Error: input must be in host:port format\n");
    return 1;
  }
  
  // Allocate buffers big enough
  char hoststring[256];            // hostname or IPv4 dotted-decimal
  char portstring[64];             // port as text for getaddrinfo
  
  // Copy host part
  size_t hostlen = sep - input;
  if (hostlen >= sizeof(hoststring)) {
    fprintf(stderr, "Error: hostname too long\n");
    return 1;
  }
  strncpy(hoststring, input, hostlen);
  hoststring[hostlen] = '\0';
  
  // Copy port part
  strncpy(portstring, sep + 1, sizeof(portstring) - 1);
  portstring[sizeof(portstring) - 1] = '\0';
  
  printf("UDP Server on: %s:%s\n", hoststring,portstring);

  initCalcLib();                   // seed calcLib's random generator

  struct addrinfo hints, *results = NULL, *p;  // DNS / address list
  int sockfd = -1;                 // the one UDP socket
  int yes = 1;                     // value for SO_REUSEADDR

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;     // IPv4 and IPv6
  hints.ai_socktype = SOCK_DGRAM;  // UDP
  hints.ai_flags = AI_PASSIVE;     // suitable for bind
  hints.ai_protocol = IPPROTO_UDP;

  if (getaddrinfo(hoststring, portstring, &hints, &results) != 0) {
    fprintf(stderr, "ERROR: RESOLVE ISSUE\n");
    return EXIT_FAILURE;
  }

  for (p = results; p != NULL; p = p->ai_next) {  // try each resolved address
    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd < 0) {
      continue;
    }
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (p->ai_family == AF_INET6) {
      int on = 1;                  // do not steal IPv4 when we bind IPv6
      setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
    }
    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
      break;                       // bound
    }
    close(sockfd);
    sockfd = -1;
  }
  freeaddrinfo(results);

  if (sockfd < 0) {
    fprintf(stderr, "ERROR: CANT BIND\n");
    return EXIT_FAILURE;
  }

  // select() watches the single UDP socket. A 1 s tick also expires 10 s clients.
  for (;;) {
    fd_set reading;                // sockets to watch for incoming datagrams
    struct timeval timeout;        // 1 s tick
    int rc;                        // select result
    unsigned char buf[MAX_DGRAM];  // one datagram
    struct sockaddr_storage clientAddr;  // who sent it
    socklen_t addrLen;
    ssize_t n;                     // bytes in this datagram

    expire_clients();
    FD_ZERO(&reading);
    FD_SET(sockfd, &reading);
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    rc = select(sockfd + 1, &reading, NULL, NULL, &timeout);
    if (rc < 0) {
      if (errno == EINTR) {        // interrupted: just loop
        continue;
      }
      perror("select");
      break;
    }
    if (rc == 0) {
      continue;                    // tick: no datagram, deadlines already checked
    }

    addrLen = sizeof clientAddr;
    n = recvfrom(sockfd, buf, sizeof buf, 0, (struct sockaddr *)&clientAddr, &addrLen);
    if (n <= 0) {
      continue;                    // empty or error; do not assume anything about the sender
    }
    handle_dgram(sockfd, buf, n, &clientAddr, addrLen);  // validate, identify, reply
  }

  close(sockfd);
  return 0;
}
