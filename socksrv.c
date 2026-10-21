/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <sys/types.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/sched.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include "elfldr.h"
#include "log.h"
#include "notify.h"
#include "selfldr.h"
#include "uri.h"

/**
 * Magic number that socket input starts with (little endian).
 **/
#define PAYLOAD_MAGIC_ELF 0x464C457F  // ELF payload
#define PAYLOAD_MAGIC_SELF 0x1D3D154F // SELF payload
#define PAYLOAD_MAGIC_FILE 0x656C6966 // file:// URI
#define PAYLOAD_MAGIC_HTTP 0x70747468 // http:// or https:// URI
#define PAYLOAD_MAGIC_POST 0x54534F50 // HTTP POST request

/**
 * Seconds a client may stay silent while a payload is being received.
 **/
#define RECV_TIMEOUT 10

/**
 * Decode an escaped argument.
 **/
static char *
args_decode(const char *s) {
  size_t length = strlen(s);
  char *arg = malloc(length + 1);
  size_t off = 0;
  int escape = 0;

  for(size_t i = 0; i < length; i++) {
    if(s[i] == '\\' && !escape) {
      escape = 1;
    } else {
      arg[off++] = s[i];
      escape = 0;
    }
  }

  arg[off] = 0;
  return arg;
}

/**
 *
 **/
static int
args_split(const char *args, char **argv, size_t size) {
  char *buf = strdup(args);
  size_t len = strlen(buf);
  int escape = 0;
  int argc = 0;

  memset(argv, 0, size * sizeof(char *));
  for(int i = 0; i < len && argc < size; i++) {
    if(escape) {
      escape = 0;
      continue;
    }

    if(buf[i] == '\\') {
      escape = 1;
      continue;
    }

    if(buf[i] == ' ') {
      buf[i] = 0;
      continue;
    }

    if(buf[i] && !i) {
      argv[argc++] = buf + i;
      continue;
    }

    if(buf[i] && !buf[i - 1]) {
      argv[argc++] = buf + i;
    }
  }

  for(int i = 0; i < argc; i++) {
    argv[i] = args_decode(argv[i]);
  }

  free(buf);

  return argc;
}

/**
 * Spawn an ELF or a SELF payload.
 **/
static pid_t
payload_spawn(char *filename, char *args, int fd, uint8_t *payload,
              size_t payload_size) {
  int magic = *((int *)payload);
  char *argv[255 + 2] = { 0 };
  pid_t pid = -1;

  argv[0] = filename;
  args_split(args, argv + 1, 255);

  if(magic == PAYLOAD_MAGIC_ELF) {
    pid = elfldr_spawn(fd, argv, payload, payload_size);

  } else if(magic == PAYLOAD_MAGIC_SELF) {
    pid = selfldr_spawn(fd, argv, payload, payload_size);
  }

  for(int i = 1; argv[i]; i++) {
    free(argv[i]);
  }

  return pid;
}

/**
 *
 **/
static int
payload_readuri(int fd, char *uri, size_t size) {
  char c;
  int n;

  for(int i = 0; i < size; i++) {
    if((n = read(fd, &c, 1)) < 0) {
      return -1;
    }
    if(n == 0) {
      uri[i] = 0;
      return 0;
    }
    if(c == '\r') {
      continue;
    }
    if(c == '\n') {
      uri[i] = 0;
      return 0;
    }

    uri[i] = c;
  }

  return -1;
}

/**
 * Send a HTTP error response, and set errno to the given error.
 **/
static int
http_error(int fd, const char *status, int err) {
  char buf[255];
  int n;

  n = snprintf(buf, sizeof(buf),
               "HTTP/1.1 %s\r\n"
               "Access-Control-Allow-Origin: *\r\n"
               "Content-Length: 0\r\n"
               "Connection: close\r\n"
               "\r\n",
               status);
  write(fd, buf, n);
  errno = err;

  return -1;
}

/**
 * Receive exactly len bytes from a socket. The data is received in chunks, so
 * that the receive timeout of the socket applies to the time a client is idle,
 * not to the time it takes to upload the whole body.
 **/
static int
http_recv(int fd, void *buf, size_t len) {
  uint8_t *p = buf;

  while(len) {
    size_t chunk = len < 0x10000 ? len : 0x10000;
    ssize_t n = recv(fd, p, chunk, MSG_WAITALL);

    if(n != chunk) {
      if(n >= 0) {
        errno = ECONNRESET;
      }

      return -1;
    }

    p += n;
    len -= n;
  }

  return 0;
}

/**
 * Get the value of a header in a HTTP request, or NULL if it is missing.
 **/
static const char *
http_header(const char *request, const char *name) {
  size_t len = strlen(name);
  const char *p = request;

  while((p = strstr(p, "\r\n"))) {
    p += 2;
    if(!strncasecmp(p, name, len) && p[len] == ':') {
      p += len + 1;
      while(*p == ' ' || *p == '\t') {
        p++;
      }
      return p;
    }
  }

  return 0;
}

/**
 * Read a HTTP (POST) request, where the body is the payload to spawn. Like
 * the other large buffers of this loader, the body is obtained from mmap().
 **/
static int
payload_readpost(int fd, char *uri, size_t size, uint8_t **payload,
                 size_t *payload_size) {
  const char *headers = ("HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/x-log; charset=utf-8\r\n"
                         "Cache-Control: no-cache\r\n"
                         "Access-Control-Allow-Origin: *\r\n"
                         "Connection: close\r\n"
                         "\r\n");
  const char *cont = "HTTP/1.1 100 Continue\r\n\r\n";
  char buf[4096] = { 0 };
  const char *target;
  const char *value;
  uint8_t *body;
  size_t length;
  size_t n = 0;
  char *end;
  char *p;
  int magic;

  while(n < sizeof(buf) - 1) {
    if(http_recv(fd, buf + n, 1)) {
      return -1;
    }

    n++;
    if(n >= 4 && !memcmp(buf + n - 4, "\r\n\r\n", 4)) {
      break;
    }
  }

  if(memcmp(buf + n - 4, "\r\n\r\n", 4)) {
    return http_error(fd, "431 Request Header Fields Too Large", EMSGSIZE);
  }

  if(memcmp(buf, "POST /", 6)) {
    return http_error(fd, "400 Bad Request", EINVAL);
  }

  target = buf + 5;
  if(!(p = memchr(target, ' ', strstr(buf, "\r\n") - target))) {
    return http_error(fd, "400 Bad Request", EINVAL);
  }

  if(p - target >= size) {
    return http_error(fd, "414 URI Too Long", ENAMETOOLONG);
  }

  memcpy(uri, target, p - target);
  uri[p - target] = 0;

  if(http_header(buf, "Transfer-Encoding")) {
    return http_error(fd, "501 Not Implemented", ENOTSUP);
  }

  if(!(value = http_header(buf, "Content-Length"))) {
    return http_error(fd, "411 Length Required", EINVAL);
  }

  if(*value < '0' || *value > '9') {
    return http_error(fd, "400 Bad Request", EINVAL);
  }

  errno = 0;
  length = strtoull(value, &end, 10);
  if(errno == ERANGE) {
    return http_error(fd, "413 Payload Too Large", EFBIG);
  }

  if(*end != '\r' && *end != ' ' && *end != '\t') {
    return http_error(fd, "400 Bad Request", EINVAL);
  }

  if(length < sizeof(magic)) {
    return http_error(fd, "400 Bad Request", EINVAL);
  }

  body = mmap(NULL, length, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(body == MAP_FAILED) {
    return http_error(fd, "413 Payload Too Large", ENOMEM);
  }

  if((value = http_header(buf, "Expect"))
     && !strncasecmp(value, "100-continue", 12)) {
    write(fd, cont, strlen(cont));
  }

  if(http_recv(fd, body, length)) {
    munmap(body, length);
    return -1;
  }

  memcpy(&magic, body, sizeof(magic));
  if(magic != PAYLOAD_MAGIC_ELF && magic != PAYLOAD_MAGIC_SELF) {
    munmap(body, length);
    return http_error(fd, "415 Unsupported Media Type", ENOEXEC);
  }

  write(fd, headers, strlen(headers));

  *payload = body;
  *payload_size = length;

  return 0;
}

/**
 * Set how long a receive on a socket may wait for data, in seconds, or 0 to
 * wait forever.
 **/
static void
recv_timeout(int fd, time_t seconds) {
  struct timeval tv = { .tv_sec = seconds };

  if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    LOG_PERROR("setsockopt");
  }
}

/**
 * Process connection input.
 **/
static void
on_connection(int fd) {
  char *filename = "payload.elf";
  char uri[PATH_MAX + 1] = { 0 };
  uint8_t *buf = 0;
  size_t len = 0;
  int optval = 1;
  char *args = "";
  char *pipe = "";
  int mapped = 0;
  int magic = 0;

  if(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval)) < 0) {
    LOG_PERROR("setsockopt");
    return;
  }

  recv_timeout(fd, RECV_TIMEOUT);

  if(recv(fd, &magic, sizeof(magic), MSG_PEEK | MSG_WAITALL)
     != sizeof(magic)) {
    LOG_PERROR("recv");
    write(fd, "[elfldr.elf] Unknown payload format\n\r\0", 38);
    return;
  }

  if(magic == PAYLOAD_MAGIC_FILE || magic == PAYLOAD_MAGIC_HTTP) {
    if(payload_readuri(fd, uri, PATH_MAX)
       || uri_get_content(uri, &buf, &len)) {
      LOG_PERROR("read_uri");
      write(fd, "[elfldr.elf] Error reading URI payload\n\r\0", 41);
    }

  } else if(magic == PAYLOAD_MAGIC_POST) {
    if(payload_readpost(fd, uri, PATH_MAX, &buf, &len)) {
      LOG_PERROR("payload_readpost");
    } else {
      mapped = 1;
    }

  } else if(magic == PAYLOAD_MAGIC_ELF) {
    if(elfldr_read(fd, &buf, &len)) {
      LOG_PERROR("elfldr_read");
      write(fd, "[elfldr.elf] Error reading ELF payload\n\r\0", 41);
    }

  } else if(magic == PAYLOAD_MAGIC_SELF) {
    if(selfldr_read(fd, &buf, &len)) {
      LOG_PERROR("selfldr_read");
      write(fd, "[elfldr.elf] Error reading SELF payload\n\r\0", 42);
    }
  } else {
    write(fd, "[elfldr.elf] Unknown payload format\n\r\0", 38);
  }

  if(buf) {
    recv_timeout(fd, 0);

    filename = uri_get_filename(uri);
    if(!filename || !*filename) {
      free(filename);
      filename = strdup("payload.elf");
    }
    if(!(args = uri_get_param(uri, "args"))) {
      args = strdup("");
    }
    if(!(pipe = uri_get_param(uri, "pipe"))) {
      pipe = strdup("1");
    }

    if(!strcmp(pipe, "0") || !strcasecmp(pipe, "false")
       || !strcasecmp(pipe, "no")) {
      fd = -1;
    }

    if(payload_spawn(filename, args, fd, buf, len) < 0) {
      write(fd, "[elfldr.elf] Error spawning payload\n\r\0", 38);
    }
    free(filename);
    free(pipe);
    free(args);
    if(mapped) {
      munmap(buf, len);
    } else {
      free(buf);
    }
  }
}

/**
 * Serve an ELF loader via a TCP socket on the given port.
 **/
static int
serve_elfldr(uint16_t port) {
  struct sockaddr_in srvaddr;
  struct sockaddr_in cliaddr;
  socklen_t socklen;
  int connfd;
  int srvfd;

  if((srvfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    LOG_PERROR("socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int))
     < 0) {
    LOG_PERROR("setsockopt");
    return -1;
  }

  memset(&srvaddr, 0, sizeof(srvaddr));
  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  srvaddr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) != 0) {
    LOG_PERROR("bind");
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    LOG_PERROR("listen");
    return -1;
  }

  while(1) {
    socklen = sizeof(cliaddr);
    if((connfd = accept(srvfd, (struct sockaddr *)&cliaddr, &socklen)) < 0) {
      LOG_PERROR("accept");
      break;
    }

    on_connection(connfd);
    close(connfd);
  }

  return close(srvfd);
}

/**
 * Fint the pid of a process with the given name.
 **/
static pid_t
find_pid(const char *name) {
  int mib[4] = { 1, 14, 8, 0 };
  pid_t mypid = getpid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    LOG_PERROR("sysctl");
    return -1;
  }

  if(!(buf = malloc(buf_size))) {
    LOG_PERROR("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    LOG_PERROR("sysctl");
    free(buf);
    return -1;
  }

  for(uint8_t *ptr = buf; ptr < (buf + buf_size);) {
    int ki_structsize = *(int *)ptr;
    pid_t ki_pid = *(pid_t *)&ptr[72];
    char *ki_tdname = (char *)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && ki_pid != mypid) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}

static int
notify_address(const char *prefix, int port) {
  char ip[INET_ADDRSTRLEN] = "127.0.0.1";
  struct ifaddrs *ifaddr;

  if(getifaddrs(&ifaddr) == -1) {
    LOG_PERROR("getifaddrs");
    return -1;
  }

  // Enumerate all AF_INET IPs
  for(struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if(ifa->ifa_addr == NULL) {
      continue;
    }

    if(ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    // skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in *)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // skip interfaces without an ip
    if(!strncmp("0.", ip, 2)) {
      continue;
    }
  }

  freeifaddrs(ifaddr);

  notify("%s %s:%d", prefix, ip, port);
  LOG_PRINTF("%s %s:%d\n", prefix, ip, port);

  return 0;
}

/**
 *
 **/
int
main(int argc, char* argv[]) {
  struct sched_param sp;
  int port = 9021;
  int notify_user = 1;
  pid_t pid;
  char c;

  syscall(SYS_thr_set_name, -1, "elfldr.elf");
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  while((c=getopt(argc, argv, "p:qh")) != -1) {
    switch(c) {
    case 'p':
      port = atoi(optarg);
      break;

    case 'q':
      notify_user = 0;
      break;

    case 'h':
    default:
      LOG_PRINTF("usage: %s [-p PORT] [-q]\n", argv[0]);
      LOG_PUTS("");
      LOG_PUTS("options:");
      LOG_PUTS("    -p PORT    Bind the socket server to the given PORT (default: 9021)");
      LOG_PUTS("    -q         Do not send an on-screen notification when the server starts");
      return EXIT_FAILURE;
    }
  }

  LOG_PRINTF("Socket server was compiled at %s %s\n", __DATE__, __TIME__);

  if(chdir("/")) {
    LOG_PERROR("chdir");
    return -1;
  }

  sp.sched_priority = sched_get_priority_max(SCHED_RR);
  if(sched_setscheduler(0, SCHED_RR, &sp)) {
    LOG_PERROR("sched_setscheduler");
  }

  syscall(SYS_setsid);
  while((pid = find_pid("elfldr.elf")) > 0) {
    if(kill(pid, SIGKILL)) {
      LOG_PERROR("kill");
      _exit(-1);
    }
    sleep(1);
  }

  if(notify_user) {
    notify_address("Serving ELF loader on", port);
  }
  while(1) {
    serve_elfldr(port);
    sleep(3);
  }

  return 0;
}
