#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int sceKernelLoadStartModule(const char *path, size_t args, const void *argp,
                             unsigned int flags, const void *opt, int *res);
int sceKernelDlsym(int handle, const char *symbol, void **addr);

#define MAX_REQUESTS 8

static int mode;

static int (*ssl_init)(size_t);
static int (*ssl_term)(int);

static int (*h2_init)(int, int, size_t, int);
static int (*h2_term)(int);
static int (*h2_create_template)(int, const char *, int, int);
static int (*h2_set_ssl_callback)(int, void *, void *);
static int (*h2_delete_template)(int);
static int (*h2_create_request)(int, const char *, const char *, uint64_t);
static int (*h2_delete_request)(int);
static int (*h2_content_length)(int, int *, uint64_t *);
static int (*h2_send_request)(int, const void *, size_t);
static int (*h2_status_code)(int, int *);
static int (*h2_read_data)(int, void *, size_t);

static int (*h1_init)(int, int, size_t);
static int (*h1_term)(int);
static int (*h1_create_template)(int, const char *, int, int);
static int (*h1_set_ssl_callback)(int, void *, void *);
static int (*h1_delete_template)(int);
static int (*h1_create_connection)(int, const char *, int);
static int (*h1_delete_connection)(int);
static int (*h1_create_request)(int, const char *, const char *, uint64_t);
static int (*h1_delete_request)(int);
static int (*h1_content_length)(int, int *, uint64_t *);
static int (*h1_send_request)(int, const void *, size_t);
static int (*h1_status_code)(int, int *);
static int (*h1_read_data)(int, void *, size_t);

static int request_ids[MAX_REQUESTS];
static int connection_ids[MAX_REQUESTS];

static int
load_module(const char *name) {
  static const char dir1[] = "/system/common/lib/";
  static const char dir2[] = "/system_ex/common_ex/lib/";
  char path[128];
  int handle;

  snprintf(path, sizeof(path), "%s%s", dir1, name);
  if((handle = sceKernelLoadStartModule(path, 0, 0, 0, 0, 0)) >= 0) {
    return handle;
  }

  snprintf(path, sizeof(path), "%s%s", dir2, name);
  if((handle = sceKernelLoadStartModule(path, 0, 0, 0, 0, 0)) >= 0) {
    return handle;
  }

  return -1;
}

static int
bind_symbol(int handle, const char *name, void *slot) {
  return sceKernelDlsym(handle, name, (void **)slot);
}

static int
resolve_new(void) {
  int ssl = load_module("libSceSsl2.sprx");
  int http = load_module("libSceHttp2.sprx");

  if(ssl < 0 || http < 0) {
    return -1;
  }

  if(bind_symbol(ssl, "sceSslInit", &ssl_init) ||
     bind_symbol(ssl, "sceSslTerm", &ssl_term) ||
     bind_symbol(http, "sceHttp2Init", &h2_init) ||
     bind_symbol(http, "sceHttp2Term", &h2_term) ||
     bind_symbol(http, "sceHttp2CreateTemplate", &h2_create_template) ||
     bind_symbol(http, "sceHttp2SetSslCallback", &h2_set_ssl_callback) ||
     bind_symbol(http, "sceHttp2DeleteTemplate", &h2_delete_template) ||
     bind_symbol(http, "sceHttp2CreateRequestWithURL", &h2_create_request) ||
     bind_symbol(http, "sceHttp2DeleteRequest", &h2_delete_request) ||
     bind_symbol(http, "sceHttp2GetResponseContentLength", &h2_content_length) ||
     bind_symbol(http, "sceHttp2SendRequest", &h2_send_request) ||
     bind_symbol(http, "sceHttp2GetStatusCode", &h2_status_code) ||
     bind_symbol(http, "sceHttp2ReadData", &h2_read_data)) {
    return -1;
  }

  return 0;
}

static int
resolve_old(void) {
  int ssl = load_module("libSceSsl.sprx");
  int http = load_module("libSceHttp.sprx");

  if(ssl < 0 || http < 0) {
    return -1;
  }

  if(bind_symbol(ssl, "sceSslInit", &ssl_init) ||
     bind_symbol(ssl, "sceSslTerm", &ssl_term) ||
     bind_symbol(http, "sceHttpInit", &h1_init) ||
     bind_symbol(http, "sceHttpTerm", &h1_term) ||
     bind_symbol(http, "sceHttpCreateTemplate", &h1_create_template) ||
     bind_symbol(http, "sceHttpsSetSslCallback", &h1_set_ssl_callback) ||
     bind_symbol(http, "sceHttpDeleteTemplate", &h1_delete_template) ||
     bind_symbol(http, "sceHttpCreateConnectionWithURL",
                 &h1_create_connection) ||
     bind_symbol(http, "sceHttpDeleteConnection", &h1_delete_connection) ||
     bind_symbol(http, "sceHttpCreateRequestWithURL2", &h1_create_request) ||
     bind_symbol(http, "sceHttpDeleteRequest", &h1_delete_request) ||
     bind_symbol(http, "sceHttpGetResponseContentLength", &h1_content_length) ||
     bind_symbol(http, "sceHttpSendRequest", &h1_send_request) ||
     bind_symbol(http, "sceHttpGetStatusCode", &h1_status_code) ||
     bind_symbol(http, "sceHttpReadData", &h1_read_data)) {
    return -1;
  }

  return 0;
}

static int
http_ready(void) {
  if(!mode) {
    if(!resolve_new()) {
      mode = 2;
    } else if(!resolve_old()) {
      mode = 1;
    } else {
      mode = -1;
    }
  }

  return mode > 0 ? 0 : -1;
}

int
sceSslInit(size_t pool_size) {
  if(http_ready()) {
    return -1;
  }

  return ssl_init(pool_size);
}

int
sceSslTerm(int ctx) {
  return mode > 0 ? ssl_term(ctx) : -1;
}

int
sceHttp2Init(int net_mem_id, int ssl_ctx_id, size_t pool_size, int parallel) {
  if(http_ready()) {
    return -1;
  }

  if(mode == 2) {
    return h2_init(net_mem_id, ssl_ctx_id, pool_size, parallel);
  }

  return h1_init(net_mem_id, ssl_ctx_id, pool_size);
}

int
sceHttp2Term(int ctx) {
  if(mode == 2) {
    return h2_term(ctx);
  }

  return mode == 1 ? h1_term(ctx) : -1;
}

int
sceHttp2CreateTemplate(int ctx, const char *agent, int version, int proxy) {
  if(mode == 2) {
    return h2_create_template(ctx, agent, version, proxy);
  }

  return mode == 1 ? h1_create_template(ctx, agent, version > 2 ? 2 : version,
                                        proxy)
                   : -1;
}

int
sceHttp2SetSslCallback(int tmpl, void *callback, void *arg) {
  if(mode == 2) {
    return h2_set_ssl_callback(tmpl, callback, arg);
  }

  return mode == 1 ? h1_set_ssl_callback(tmpl, callback, arg) : -1;
}

int
sceHttp2DeleteTemplate(int tmpl) {
  if(mode == 2) {
    return h2_delete_template(tmpl);
  }

  return mode == 1 ? h1_delete_template(tmpl) : -1;
}

int
sceHttp2CreateRequestWithURL(int tmpl, const char *method, const char *url,
                             uint64_t content_length) {
  int connection;
  int request;

  if(mode == 2) {
    return h2_create_request(tmpl, method, url, content_length);
  }

  if(mode != 1) {
    return -1;
  }

  if((connection = h1_create_connection(tmpl, url, 1)) < 0) {
    return connection;
  }

  if((request = h1_create_request(connection, method, url, content_length))
     < 0) {
    h1_delete_connection(connection);
    return request;
  }

  for(int i = 0; i < MAX_REQUESTS; i++) {
    if(!request_ids[i]) {
      request_ids[i] = request;
      connection_ids[i] = connection;
      break;
    }
  }

  return request;
}

int
sceHttp2DeleteRequest(int request) {
  int err;

  if(mode == 2) {
    return h2_delete_request(request);
  }

  if(mode != 1) {
    return -1;
  }

  err = h1_delete_request(request);

  for(int i = 0; i < MAX_REQUESTS; i++) {
    if(request_ids[i] == request) {
      h1_delete_connection(connection_ids[i]);
      request_ids[i] = 0;
      connection_ids[i] = 0;
      break;
    }
  }

  return err;
}

int
sceHttp2GetResponseContentLength(int request, int *result,
                                 uint64_t *content_length) {
  if(mode == 2) {
    return h2_content_length(request, result, content_length);
  }

  return mode == 1 ? h1_content_length(request, result, content_length) : -1;
}

int
sceHttp2SendRequest(int request, const void *data, size_t size) {
  if(mode == 2) {
    return h2_send_request(request, data, size);
  }

  return mode == 1 ? h1_send_request(request, data, size) : -1;
}

int
sceHttp2GetStatusCode(int request, int *status) {
  if(mode == 2) {
    return h2_status_code(request, status);
  }

  return mode == 1 ? h1_status_code(request, status) : -1;
}

int
sceHttp2ReadData(int request, void *data, size_t size) {
  if(mode == 2) {
    return h2_read_data(request, data, size);
  }

  return mode == 1 ? h1_read_data(request, data, size) : -1;
}
