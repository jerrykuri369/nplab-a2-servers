#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* You will to add includes here */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Included to get the support library
#include <calcLib.h>
#include <protocol.h>

// Enable if you want debugging to be printed, see examble below.
// Alternative, pass CFLAGS=-DDEBUG to make, make CFLAGS=-DDEBUG
#define DEBUG


using namespace std;

#define OP_TIMEOUT 5
#define MAX_LISTEN 8

static void reap_children(int sig)
{
  (void)sig;
  while (waitpid(-1, NULL, WNOHANG) > 0) {
  }
}

static int wait_ready(int fd, int seconds)
{
  fd_set rfds;
  struct timeval tv;
  int rc;

  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);
  tv.tv_sec = seconds;
  tv.tv_usec = 0;
  rc = select(fd + 1, &rfds, NULL, NULL, &tv);
  if (rc < 0 && errno == EINTR) {
    return wait_ready(fd, seconds);
  }
  return rc;
}

static int send_all(int fd, const void *buf, size_t n)
{
  size_t sent = 0;
  while (sent < n) {
    ssize_t w = write(fd, (const char *)buf + sent, n - sent);
    if (w < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    sent += (size_t)w;
  }
  return 0;
}

static int send_error_to(int fd)
{
  return send_all(fd, "ERROR TO\n", 9);
}

static ssize_t read_n(int fd, void *buf, size_t n)
{
  size_t got = 0;
  while (got < n) {
    int w = wait_ready(fd, OP_TIMEOUT);
    if (w == 0) {
      send_error_to(fd);
      errno = ETIMEDOUT;
      return -1;
    }
    if (w < 0) {
      return -1;
    }
    ssize_t r = read(fd, (char *)buf + got, n - got);
    if (r == 0) {
      return (ssize_t)got;
    }
    if (r < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    got += (size_t)r;
  }
  return (ssize_t)got;
}

static ssize_t read_line(int fd, char *buf, size_t cap)
{
  size_t n = 0;
  while (n + 1 < cap) {
    int w = wait_ready(fd, OP_TIMEOUT);
    if (w == 0) {
      send_error_to(fd);
      buf[n] = '\0';
      errno = ETIMEDOUT;
      return -1;
    }
    if (w < 0) {
      buf[n] = '\0';
      return -1;
    }
    char c;
    ssize_t r = read(fd, &c, 1);
    if (r == 0) {
      buf[n] = '\0';
      return (ssize_t)n;
    }
    if (r < 0) {
      if (errno == EINTR) {
        continue;
      }
      buf[n] = '\0';
      return -1;
    }
    buf[n++] = c;
    if (c == '\n') {
      break;
    }
  }
  buf[n] = '\0';
  return (ssize_t)n;
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
  int a, b, expected, got, n;

  make_task(op, sizeof op, &a, &b, &expected);
  n = snprintf(task, sizeof task, "%s %d %d\n", op, a, b);
  if (send_all(fd, task, (size_t)n) < 0) {
    return;
  }
  if (read_line(fd, line, sizeof line) <= 0) {
    return;
  }
  strip_crlf(line);
  if (sscanf(line, "%d", &got) != 1) {
    send_all(fd, "ERROR\n", 6);
    return;
  }
  if (got == expected) {
    send_all(fd, "OK\n", 3);
  } else {
    send_all(fd, "ERROR\n", 6);
  }
}

static void handle_binary(int fd)
{
  char op[16];
  int a, b, expected;
  uint32_t id;
  calcProtocol job, ans;
  calcMessage verdict;

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

  if (send_all(fd, &job, sizeof job) < 0) {
    return;
  }
  if (read_n(fd, &ans, sizeof ans) != (ssize_t)sizeof ans) {
    if (errno != ETIMEDOUT) {
      send_error_to(fd);
    }
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
  send_all(fd, &verdict, sizeof verdict);
}

static void handle_client(int fd)
{
  const char *hello = "TEXT TCP 1.1\nBINARY TCP 1.1\n\n";
  char line[256];

  if (send_all(fd, hello, strlen(hello)) < 0) {
    return;
  }
  if (read_line(fd, line, sizeof line) <= 0) {
    return;
  }
  strip_crlf(line);

  if (strcmp(line, "TEXT TCP 1.1 OK") == 0) {
    handle_text(fd);
  } else if (strcmp(line, "BINARY TCP 1.1 OK") == 0) {
    handle_binary(fd);
  } else {
    send_all(fd, "ERROR: MISSMATCH PROTOCOL\n", 26);
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
  
  // Copy port part
  strncpy(portstring, sep + 1, sizeof(portstring) - 1);
  portstring[sizeof(portstring) - 1] = '\0';
  
  printf("TCP server on: %s:%s\n", hoststring,portstring);
  fflush(stdout);

  /* ---- server implementation starts here ---- */
  const char *bind_host = hoststring;
  int family = AF_UNSPEC;
  struct addrinfo hints, *results = NULL, *p;
  int listen_fds[MAX_LISTEN];
  int nlisten = 0;
  int maxfd = -1;
  int i;

  if (strcmp(hoststring, "ip4-localhost") == 0) {
    bind_host = "127.0.0.1";
    family = AF_INET;
  } else if (strcmp(hoststring, "ip6-localhost") == 0) {
    bind_host = "::1";
    family = AF_INET6;
  }

  initCalcLib();
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, reap_children);
  signal(SIGALRM, SIG_IGN);

  memset(&hints, 0, sizeof hints);
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = IPPROTO_TCP;

  if (getaddrinfo(bind_host, portstring, &hints, &results) != 0) {
    fprintf(stderr, "ERROR: RESOLVE ISSUE\n");
    return EXIT_FAILURE;
  }

  for (p = results; p != NULL && nlisten < MAX_LISTEN; p = p->ai_next) {
    int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    int yes = 1;
    if (fd < 0) {
      continue;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (p->ai_family == AF_INET6) {
      int on = 1;
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
    }
    if (bind(fd, p->ai_addr, p->ai_addrlen) != 0 || listen(fd, 16) != 0) {
      close(fd);
      continue;
    }
    listen_fds[nlisten++] = fd;
    if (fd > maxfd) {
      maxfd = fd;
    }
  }
  freeaddrinfo(results);

  if (nlisten == 0) {
    fprintf(stderr, "ERROR: CANT BIND\n");
    return EXIT_FAILURE;
  }

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
      int clientfd;
      pid_t pid;
      if (!FD_ISSET(listen_fds[i], &rfds)) {
        continue;
      }
      clientfd = accept(listen_fds[i], NULL, NULL);
      if (clientfd < 0) {
        if (errno == EINTR) {
          continue;
        }
        perror("accept");
        continue;
      }
      pid = fork();
      if (pid < 0) {
        perror("fork");
        close(clientfd);
        continue;
      }
      if (pid == 0) {
        int j;
        for (j = 0; j < nlisten; j++) {
          close(listen_fds[j]);
        }
        initCalcLib();
        handle_client(clientfd);
        close(clientfd);
        _exit(0);
      }
      close(clientfd);
    }
  }

  return 0;
}
