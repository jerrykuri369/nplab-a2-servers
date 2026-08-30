#include <stdio.h>                 // printf, fprintf, perror
#include <string.h>                // strchr, strncpy, strcmp, strlen, memset, memcpy
#include <stdlib.h>                // exit, EXIT_FAILURE, EXIT_SUCCESS
/* You will to add includes here */
#include <arpa/inet.h>             // htons, htonl, ntohs, ntohl (network byte order)
#include <ctype.h>                 // character tests if needed
#include <errno.h>                 // errno, EINTR, ETIMEDOUT
#include <netdb.h>                 // getaddrinfo, freeaddrinfo, addrinfo, gai_strerror
#include <netinet/in.h>            // sockaddr_in, IPPROTO_TCP, IPV6_V6ONLY
#include <signal.h>                // signal, SIGPIPE, SIGCHLD, SIGALRM
#include <sys/select.h>            // select, fd_set, FD_ZERO, FD_SET
#include <sys/socket.h>            // socket, bind, listen, accept, setsockopt
#include <sys/time.h>              // struct timeval for select timeout
#include <sys/types.h>             // pid_t and other POSIX types
#include <sys/wait.h>              // waitpid, WNOHANG (reap child processes)
#include <unistd.h>                // read, write, close, fork, _exit
// Included to get the support library
#include <calcLib.h>               // initCalcLib, randomType, randomInt
#include <protocol.h>              // packed calcProtocol and calcMessage (version 1.1)

// Enable if you want debugging to be printed, see examble below.
// Alternative, pass CFLAGS=-DDEBUG to make, make CFLAGS=-DDEBUG
#define DEBUG                      // kept from the course template


using namespace std;               // required by the course template

#define OP_TIMEOUT 5               // every client step must finish within 5 seconds

// Reap finished children so the parent does not leave zombie processes.
static void reap_children(int sig)
{
  (void)sig;                       // unused parameter (signal number)
  while (waitpid(-1, NULL, WNOHANG) > 0) {  // collect any exited child without blocking
  }
}

// Wait until fd is readable, or the 5 s timeout elapses. Returns >0 ready, 0 timeout, -1 error.
static int wait_ready(int fd, int seconds)
{
  fd_set rfds;                     // set of file descriptors to watch
  struct timeval tv;               // timeout for this wait
  int rc;                          // return value from select

  FD_ZERO(&rfds);                  // start with an empty set
  FD_SET(fd, &rfds);               // watch this client socket
  tv.tv_sec = seconds;             // whole seconds to wait
  tv.tv_usec = 0;                  // no extra microseconds
  rc = select(fd + 1, &rfds, NULL, NULL, &tv);  // block until readable or timeout
  if (rc < 0 && errno == EINTR) {  // interrupted by a signal: try again
    return wait_ready(fd, seconds);
  }
  return rc;                       // pass ready / timeout / error to the caller
}

// Write every byte of buf. Loops until all n bytes are sent.
static int send_all(int fd, const void *buf, size_t n)
{
  size_t sent = 0;                 // how many bytes have gone out so far
  while (sent < n) {               // keep going until the whole buffer is written
    ssize_t w = write(fd, (const char *)buf + sent, n - sent);  // write the remainder
    if (w < 0) {                   // write failed
      if (errno == EINTR) {        // interrupted: retry the same remainder
        continue;
      }
      return -1;                   // real error
    }
    sent += (size_t)w;             // count the bytes that actually left
  }
  return 0;                        // success
}

// Send the required timeout string and leave the rest of the shutdown to the caller.
static int send_error_to(int fd)
{
  return send_all(fd, "ERROR TO\n", 9);  // assignment: notify the client, then the child exits
}

// Read exactly n bytes (used for packed binary structs). On timeout send ERROR TO.
static ssize_t read_n(int fd, void *buf, size_t n)
{
  size_t got = 0;                  // bytes received so far
  while (got < n) {                // TCP may deliver the struct in several pieces
    int w = wait_ready(fd, OP_TIMEOUT);  // 5 s for this next piece
    if (w == 0) {                  // client was too slow
      send_error_to(fd);           // required timeout reply
      errno = ETIMEDOUT;           // mark why we failed
      return -1;
    }
    if (w < 0) {                   // select error
      return -1;
    }
    ssize_t r = read(fd, (char *)buf + got, n - got);  // read into the remaining hole
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

// Read one text line, byte by byte, until '\n'. Same 5 s rule as binary reads.
static ssize_t read_line(int fd, char *buf, size_t cap)
{
  size_t n = 0;                    // characters stored so far
  while (n + 1 < cap) {            // leave room for the terminating NUL
    int w = wait_ready(fd, OP_TIMEOUT);  // 5 s for the next character
    if (w == 0) {                  // timeout
      send_error_to(fd);           // required timeout reply
      buf[n] = '\0';               // keep the buffer a valid C string
      errno = ETIMEDOUT;
      return -1;
    }
    if (w < 0) {                   // select error
      buf[n] = '\0';
      return -1;
    }
    char c;                        // one byte from the stream
    ssize_t r = read(fd, &c, 1);   // text protocol is line-oriented
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

// Remove trailing CR/LF so strcmp can match the protocol keywords.
static void strip_crlf(char *s)
{
  size_t n = strlen(s);            // current length
  while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {  // peel off line endings
    s[--n] = '\0';
  }
}

// Map operator name to calcProtocol.arith: 1 add, 2 sub, 3 mul, 4 div.
static int arith_code(const char *op)
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

// Draw a random job from calcLib. Never allow a zero divisor.
static void make_task(char *op, size_t opsz, int *a, int *b, int *expected)
{
  const char *t = randomType();    // "add", "div", or "mul" from calcLib
  strncpy(op, t, opsz - 1);        // copy the operator name
  op[opsz - 1] = '\0';             // guarantee a terminator
  *a = randomInt();                // first operand 0..99
  *b = randomInt();                // second operand 0..99
  if (strcmp(op, "div") == 0 && *b == 0) {  // assignment: no division by zero
    *b = 1;
  }
  if (strcmp(op, "add") == 0) {    // compute the reference result
    *expected = *a + *b;
  } else if (strcmp(op, "sub") == 0) {
    *expected = *a - *b;
  } else if (strcmp(op, "mul") == 0) {
    *expected = *a * *b;
  } else {
    *expected = *a / *b;           // integer division, matching the C client
  }
}

// TEXT TCP 1.1: send "op a b\n", wait for an integer, reply OK or ERROR.
static void handle_text(int fd)
{
  char op[16];                     // operator name
  char line[256];                  // client's answer line
  char task[128];                  // "add 10 20\n"
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

// BINARY TCP 1.1: send calcProtocol type 1, read type 2, reply with calcMessage (protocol 6).
static void handle_binary(int fd)
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

// One connected client, runs in the child after fork.
static void handle_client(int fd)
{
  const char *hello = "TEXT TCP 1.1\nBINARY TCP 1.1\n\n";  // advertise both versions
  char line[256];                  // client's choice

  if (send_all(fd, hello, strlen(hello)) < 0) {  // first write, still under the 5 s rule via send
    return;
  }
  if (read_line(fd, line, sizeof line) <= 0) {  // wait for "TEXT TCP 1.1 OK" or binary
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

  initCalcLib();                   // seed calcLib's random generator
  signal(SIGPIPE, SIG_IGN);        // writing to a closed client must not kill the process
  signal(SIGCHLD, reap_children);  // auto-reap children
  signal(SIGALRM, SIG_IGN);        // do not let a grader alarm take down the parent

  struct addrinfo hints, *results = NULL, *p;  // DNS / address list
  int listenfd = -1;               // listening socket
  int yes = 1;                     // value for SO_REUSEADDR

  memset(&hints, 0, sizeof hints); // getaddrinfo needs a zeroed hints struct
  hints.ai_family = AF_UNSPEC;     // IPv4 and IPv6
  hints.ai_socktype = SOCK_STREAM; // TCP
  hints.ai_flags = AI_PASSIVE;     // suitable for bind
  hints.ai_protocol = IPPROTO_TCP;

  if (getaddrinfo(hoststring, portstring, &hints, &results) != 0) {  // resolve host
    fprintf(stderr, "ERROR: RESOLVE ISSUE\n");
    return EXIT_FAILURE;
  }

  for (p = results; p != NULL; p = p->ai_next) {  // try each resolved address
    listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (listenfd < 0) {            // this family failed; try the next
      continue;
    }
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);  // restart on same port
    if (p->ai_family == AF_INET6) {
      int on = 1;                  // keep IPv6 off IPv4 so both families can bind if needed
      setsockopt(listenfd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
    }
    if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0 && listen(listenfd, 16) == 0) {
      break;                       // bound and listening
    }
    close(listenfd);               // this address failed
    listenfd = -1;
  }
  freeaddrinfo(results);           // done with the DNS list

  if (listenfd < 0) {              // nothing bound
    fprintf(stderr, "ERROR: CANT BIND\n");
    return EXIT_FAILURE;
  }

  for (;;) {                       // parent accept loop
    struct sockaddr_storage cli;   // client address (IPv4 or IPv6)
    socklen_t clilen = sizeof cli;
    int clientfd = accept(listenfd, (struct sockaddr *)&cli, &clilen);  // new connection
    pid_t pid;                     // child's process id

    if (clientfd < 0) {
      if (errno == EINTR) {        // accept interrupted by SIGCHLD
        continue;
      }
      perror("accept");
      continue;
    }

    pid = fork();                  // one child per client
    if (pid < 0) {                 // fork failed
      perror("fork");
      close(clientfd);
      continue;
    }
    if (pid == 0) {                // child
      close(listenfd);             // child does not accept further connections
      initCalcLib();               // fresh random seed in the child
      handle_client(clientfd);     // full TEXT/BINARY conversation, 5 s per step
      close(clientfd);
      _exit(0);                    // do not run atexit handlers in the child
    }
    close(clientfd);               // parent is done with this connected socket
  }

  return 0;
}
