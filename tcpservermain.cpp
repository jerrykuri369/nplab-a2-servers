#include <stdio.h>                 // printf / fprintf for banners and errors
#include <string.h>                // strchr, strncpy, strcmp, strlen, memset, memcpy
#include <stdlib.h>                // exit() and EXIT_FAILURE
/* You will to add includes here */
#include <arpa/inet.h>             // htons / htonl / ntohs / ntohl (network byte order)
#include <ctype.h>                 // character helpers if a line needs trimming
#include <errno.h>                 // errno, EINTR, ETIMEDOUT
#include <netdb.h>                 // getaddrinfo() so DNS, IPv4 and IPv6 all work
#include <netinet/in.h>            // IPPROTO_TCP, IPV6_V6ONLY
#include <signal.h>                // signal() for SIGPIPE, SIGCHLD, SIGALRM
#include <sys/select.h>            // select() used as the 5 s timeout
#include <sys/socket.h>            // socket, bind, listen, accept, setsockopt
#include <sys/time.h>              // struct timeval for select()
#include <sys/types.h>             // pid_t and other POSIX types
#include <sys/wait.h>              // waitpid() to reap finished children
#include <unistd.h>                // read, write, close, fork, _exit

// Included to get the support library
#include <calcLib.h>               // initCalcLib, randomType, randomInt
#include <protocol.h>              // packed calcProtocol and calcMessage (version 1.1)

// Enable if you want debugging to be printed, see examble below.
// Alternative, pass CFLAGS=-DDEBUG to make, make CFLAGS=-DDEBUG
#define DEBUG                      // kept from the course template


using namespace std;               // required by the course template

#define OP_TIMEOUT 5               // every client step must finish within 5 seconds
#define MAX_LISTEN 8               // how many listen sockets (IPv4 + IPv6) we keep

static void reap_children(int sig) // SIGCHLD handler: collect exited children
{
  (void)sig;                       // signal number is unused
  while (waitpid(-1, NULL, WNOHANG) > 0) {  // reap any zombie without blocking
  }
}

static int wait_ready(int fd, int seconds)  // wait until fd is readable or timeout
{
  fd_set rfds;                     // set of sockets to watch
  struct timeval tv;               // how long select() may block
  int rc;                          // select() result: >0 ready, 0 timeout, -1 error

  FD_ZERO(&rfds);                  // start with an empty set
  FD_SET(fd, &rfds);               // watch this client socket
  tv.tv_sec = seconds;             // whole seconds to wait
  tv.tv_usec = 0;                  // no extra microseconds
  rc = select(fd + 1, &rfds, NULL, NULL, &tv);  // block until readable or timeout
  if (rc < 0 && errno == EINTR) {  // interrupted by a signal: try again
    return wait_ready(fd, seconds);
  }
  return rc;                       // tell the caller ready / timeout / error
}

static int send_all(int fd, const void *buf, size_t n)  // write every byte of buf
{
  size_t sent = 0;                 // bytes already written
  while (sent < n) {               // TCP write() may send only part of the buffer
    ssize_t w = write(fd, (const char *)buf + sent, n - sent);  // write the rest
    if (w < 0) {                   // write failed
      if (errno == EINTR) {        // interrupted: retry the same remainder
        continue;
      }
      return -1;                   // real error
    }
    sent += (size_t)w;             // count the bytes that actually left
  }
  return 0;                        // whole buffer is on the wire
}

static int send_error_to(int fd)   // assignment: notify a slow client
{
  return send_all(fd, "ERROR TO\n", 9);  // then the child will close and _exit
}

static ssize_t read_n(int fd, void *buf, size_t n)  // read exactly n bytes (binary structs)
{
  size_t got = 0;                  // bytes received so far
  while (got < n) {                // a struct may arrive in several TCP segments
    int w = wait_ready(fd, OP_TIMEOUT);  // 5 s for the next piece
    if (w == 0) {                  // client was too slow
      send_error_to(fd);           // required timeout reply
      errno = ETIMEDOUT;           // remember why we failed
      return -1;
    }
    if (w < 0) {                   // select error
      return -1;
    }
    ssize_t r = read(fd, (char *)buf + got, n - got);  // fill the remaining hole
    if (r == 0) {                  // peer closed the connection
      return (ssize_t)got;
    }
    if (r < 0) {                   // read error
      if (errno == EINTR) {        // interrupted: retry
        continue;
      }
      return -1;
    }
    got += (size_t)r;              // account for this chunk
  }
  return (ssize_t)got;             // full n bytes
}

static ssize_t read_line(int fd, char *buf, size_t cap)  // read one TEXT line (until '\n')
{
  size_t n = 0;                    // characters stored so far
  while (n + 1 < cap) {            // leave room for the terminating NUL
    int w = wait_ready(fd, OP_TIMEOUT);  // 5 s for the next character
    if (w == 0) {                  // timeout
      send_error_to(fd);           // required timeout reply
      buf[n] = '\0';               // keep a valid C string
      errno = ETIMEDOUT;
      return -1;
    }
    if (w < 0) {                   // select error
      buf[n] = '\0';
      return -1;
    }
    char c;                        // one byte from the stream
    ssize_t r = read(fd, &c, 1);   // TEXT protocol is line-oriented
    if (r == 0) {                  // peer closed
      buf[n] = '\0';
      return (ssize_t)n;
    }
    if (r < 0) {                   // read error
      if (errno == EINTR) {
        continue;
      }
      buf[n] = '\0';
      return -1;
    }
    buf[n++] = c;                  // keep this character
    if (c == '\n') {               // end of the text line
      break;
    }
  }
  buf[n] = '\0';                   // NUL-terminate
  return (ssize_t)n;
}

static void strip_crlf(char *s)    // drop trailing CR/LF so strcmp can match keywords
{
  size_t n = strlen(s);            // current length
  while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {  // peel off line endings
    s[--n] = '\0';
  }
}

static int arith_code(const char *op)  // map name -> calcProtocol.arith (1 add, 2 sub, 3 mul, 4 div)
{
  if (strcmp(op, "add") == 0) {    // addition
    return 1;
  }
  if (strcmp(op, "sub") == 0) {    // subtraction
    return 2;
  }
  if (strcmp(op, "mul") == 0) {    // multiplication
    return 3;
  }
  if (strcmp(op, "div") == 0) {    // integer division
    return 4;
  }
  return 0;                        // unknown (should not happen with calcLib)
}

static void make_task(char *op, size_t opsz, int *a, int *b, int *expected)  // random job from calcLib
{
  const char *t = randomType();    // "add", "div" or "mul"
  strncpy(op, t, opsz - 1);        // copy the operator name
  op[opsz - 1] = '\0';             // guarantee a terminator
  *a = randomInt();                // first operand 0..99
  *b = randomInt();                // second operand 0..99
  if (strcmp(op, "div") == 0 && *b == 0) {  // assignment: never divide by zero
    *b = 1;
  }
  if (strcmp(op, "add") == 0) {    // compute the reference result we will check against
    *expected = *a + *b;
  } else if (strcmp(op, "sub") == 0) {
    *expected = *a - *b;
  } else if (strcmp(op, "mul") == 0) {
    *expected = *a * *b;
  } else {
    *expected = *a / *b;           // integer division, matching the C client
  }
}

static void handle_text(int fd)    // TEXT TCP 1.1: send "op a b\n", wait for an integer
{
  char op[16];                     // operator name
  char line[256];                  // client's answer line
  char task[128];                  // formatted "add 10 20\n"
  int a, b, expected, got, n;      // operands, reference result, parsed answer, length

  make_task(op, sizeof op, &a, &b, &expected);  // create the job
  n = snprintf(task, sizeof task, "%s %d %d\n", op, a, b);  // format the TEXT task
  if (send_all(fd, task, (size_t)n) < 0) {  // send it
    return;
  }
  if (read_line(fd, line, sizeof line) <= 0) {  // wait for the answer (5 s)
    return;                        // timeout already sent ERROR TO
  }
  strip_crlf(line);                // drop the newline
  if (sscanf(line, "%d", &got) != 1) {  // must be an integer
    send_all(fd, "ERROR\n", 6);
    return;
  }
  if (got == expected) {           // correct
    send_all(fd, "OK\n", 3);
  } else {                         // wrong value
    send_all(fd, "ERROR\n", 6);
  }
}

static void handle_binary(int fd)  // BINARY TCP 1.1: calcProtocol job, then calcMessage verdict
{
  char op[16];                     // operator name
  int a, b, expected;              // operands and reference result
  uint32_t id;                     // server-chosen job id the client must echo
  calcProtocol job, ans;           // outgoing task and incoming answer
  calcMessage verdict;             // OK / NOT OK

  make_task(op, sizeof op, &a, &b, &expected);
  id = (uint32_t)(randomInt() + 1) * 1000u + (uint32_t)randomInt();  // non-zero id

  memset(&job, 0, sizeof job);     // start from a clean packed struct
  job.type = htons(1);             // 1 = server -> client
  job.major_version = htons(1);    // protocol 1.1
  job.minor_version = htons(1);
  job.id = htonl(id);              // client must return this id
  job.arith = htonl((uint32_t)arith_code(op));  // 1/2/3/4
  job.inValue1 = htonl(a);
  job.inValue2 = htonl(b);
  job.inResult = htonl(0);         // unused on the way out

  if (send_all(fd, &job, sizeof job) < 0) {  // 26-byte packed job
    return;
  }
  if (read_n(fd, &ans, sizeof ans) != (ssize_t)sizeof ans) {  // wait for 26-byte answer
    if (errno != ETIMEDOUT) {      // incomplete read that was not a timeout
      send_error_to(fd);
    }
    return;
  }

  memset(&verdict, 0, sizeof verdict);
  verdict.type = htons(2);         // server -> client, binary
  verdict.protocol = htons(6);     // 6 = TCP
  verdict.major_version = htons(1);
  verdict.minor_version = htons(1);

  if (ntohs(ans.type) == 2 && ntohs(ans.major_version) == 1 &&
      ntohs(ans.minor_version) == 1 && ntohl(ans.id) == id &&
      (int32_t)ntohl((uint32_t)ans.inResult) == expected) {  // type, version, id, result
    verdict.message = htonl(1);    // 1 = OK
  } else {
    verdict.message = htonl(2);    // 2 = NOT OK
  }
  send_all(fd, &verdict, sizeof verdict);  // 12-byte packed verdict
}

static void handle_client(int fd)  // one connected client, runs in the child after fork
{
  const char *hello = "TEXT TCP 1.1\nBINARY TCP 1.1\n\n";  // advertise both versions
  char line[256];                  // client's choice

  if (send_all(fd, hello, strlen(hello)) < 0) {  // first write after accept
    return;
  }
  if (read_line(fd, line, sizeof line) <= 0) {  // wait for TEXT ... OK or BINARY ... OK
    return;
  }
  strip_crlf(line);

  if (strcmp(line, "TEXT TCP 1.1 OK") == 0) {  // text client
    handle_text(fd);
  } else if (strcmp(line, "BINARY TCP 1.1 OK") == 0) {  // binary client
    handle_binary(fd);
  } else {                         // official spelling includes the extra S
    send_all(fd, "ERROR: MISSMATCH PROTOCOL\n", 26);
  }
}

int main(int argc, char *argv[]){
  if (argc < 2) {                  // one required argument: host:port
    fprintf(stderr, "Usage: %s protocol://server:port/path.\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  
  char *input = argv[1];           // the host:port string from the command line
  char *sep = strchr(input, ':');  // first colon splits host from port (template parser)
  
  if (!sep) {                      // missing colon
    fprintf(stderr, "Error: input must be in host:port format\n");
    return 1;
  }
  
  // Allocate buffers big enough
  char hoststring[256];            // hostname or IPv4 dotted-decimal
  char portstring[64];             // port as text for getaddrinfo
  
  // Copy host part
  size_t hostlen = sep - input;    // bytes before the colon
  if (hostlen >= sizeof(hoststring)) {
    fprintf(stderr, "Error: hostname too long\n");
    return 1;
  }
  strncpy(hoststring, input, hostlen);  // copy the host
  hoststring[hostlen] = '\0';      // terminate (strncpy does not if src is longer)
  
  // Copy port part
  strncpy(portstring, sep + 1, sizeof(portstring) - 1);
  portstring[sizeof(portstring) - 1] = '\0';
  
  printf("TCP server on: %s:%s\n", hoststring,portstring);
  fflush(stdout);                  // testers may read the banner immediately

  /* ---- server implementation starts here ---- */
  const char *bind_host = hoststring;  // may be rewritten for CodeGrade special names
  int family = AF_UNSPEC;          // allow both IPv4 and IPv6 unless a test forces one
  struct addrinfo hints, *results = NULL, *p;  // DNS / address list
  int listen_fds[MAX_LISTEN];      // listening sockets (one per family that bound)
  int nlisten = 0;                 // how many listen sockets we have
  int maxfd = -1;                  // largest fd, needed by select()
  int i;                           // loop index

  if (strcmp(hoststring, "ip4-localhost") == 0) {  // CodeGrade IPv4-only host
    bind_host = "127.0.0.1";
    family = AF_INET;
  } else if (strcmp(hoststring, "ip6-localhost") == 0) {  // CodeGrade IPv6-only host
    bind_host = "::1";
    family = AF_INET6;
  }

  initCalcLib();                   // seed calcLib's random generator
  signal(SIGPIPE, SIG_IGN);        // writing to a closed client must not kill us
  signal(SIGCHLD, reap_children);  // auto-reap children
  signal(SIGALRM, SIG_IGN);        // do not let a grader alarm take down the parent

  memset(&hints, 0, sizeof hints); // getaddrinfo needs a zeroed hints struct
  hints.ai_family = family;        // AF_UNSPEC, or forced IPv4 / IPv6
  hints.ai_socktype = SOCK_STREAM; // TCP
  hints.ai_flags = AI_PASSIVE;     // suitable for bind()
  hints.ai_protocol = IPPROTO_TCP;

  if (getaddrinfo(bind_host, portstring, &hints, &results) != 0) {  // resolve host
    fprintf(stderr, "ERROR: RESOLVE ISSUE\n");
    return EXIT_FAILURE;
  }

  for (p = results; p != NULL && nlisten < MAX_LISTEN; p = p->ai_next) {  // try each address
    int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    int yes = 1;                   // value for SO_REUSEADDR
    if (fd < 0) {                  // this family failed; try the next
      continue;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);  // restart on same port
    if (p->ai_family == AF_INET6) {
      int on = 1;                  // keep IPv6 off IPv4 so both families can bind
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
    }
    if (bind(fd, p->ai_addr, p->ai_addrlen) != 0 || listen(fd, 16) != 0) {
      close(fd);                   // this address failed
      continue;
    }
    listen_fds[nlisten++] = fd;    // keep this listening socket
    if (fd > maxfd) {
      maxfd = fd;                  // select() needs the largest fd + 1
    }
  }
  freeaddrinfo(results);           // done with the DNS list

  if (nlisten == 0) {              // nothing bound
    fprintf(stderr, "ERROR: CANT BIND\n");
    return EXIT_FAILURE;
  }

  for (;;) {                       // parent accept loop
    fd_set rfds;                   // listen sockets that have a new connection
    FD_ZERO(&rfds);
    for (i = 0; i < nlisten; i++) {
      FD_SET(listen_fds[i], &rfds);  // watch every listening socket
    }
    if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {  // wait for a client
      if (errno == EINTR) {        // interrupted by SIGCHLD
        continue;
      }
      perror("select");
      break;
    }
    for (i = 0; i < nlisten; i++) {
      int clientfd;                // connected socket for this client
      pid_t pid;                   // child's process id
      if (!FD_ISSET(listen_fds[i], &rfds)) {
        continue;                  // this listen socket has no new connection
      }
      clientfd = accept(listen_fds[i], NULL, NULL);  // take the connection
      if (clientfd < 0) {
        if (errno == EINTR) {
          continue;
        }
        perror("accept");
        continue;
      }
      pid = fork();                // one child per client
      if (pid < 0) {               // fork failed
        perror("fork");
        close(clientfd);
        continue;
      }
      if (pid == 0) {              // child
        int j;
        for (j = 0; j < nlisten; j++) {
          close(listen_fds[j]);    // child does not accept further connections
        }
        initCalcLib();             // fresh random seed in the child
        handle_client(clientfd);   // full TEXT/BINARY conversation, 5 s per step
        close(clientfd);
        _exit(0);                  // do not run atexit handlers in the child
      }
      close(clientfd);             // parent is done with this connected socket
    }
  }

  return 0;
}
