> 本说明旨在描述twemproxy数据处理流程，并依据此进行二次开发，制定自己的转发策略

## 数据结构

### instance

> 代表twemproxy实例

```c
struct instance {
    struct context  *ctx;                        /* active context */
    int             log_level;                   /* log level */
    const char      *log_filename;               /* log filename */
    const char      *conf_filename;              /* configuration filename */
    uint16_t        stats_port;                  /* stats monitoring port */
    int             stats_interval;              /* stats aggregation interval */
    const char      *stats_addr;                 /* stats monitoring addr */
    char            hostname[NC_MAXHOSTNAMELEN]; /* hostname */
    size_t          mbuf_chunk_size;             /* mbuf chunk size */
    pid_t           pid;                         /* process id */
    const char      *pid_filename;               /* pid filename */
    unsigned        pidfile:1;                   /* pid file created? */
};
```

### context

```c
struct context {
    uint32_t           id;          /* unique context id */
    struct conf        *cf;         /* configuration */
    struct stats       *stats;      /* stats */

    struct array       pool;        /* server_pool[] */
    struct event_base  *evb;        /* event base */
    int                max_timeout; /* max timeout in msec */
    int                timeout;     /* timeout in msec */

    uint32_t           max_nfd;     /* max # files */
    uint32_t           max_ncconn;  /* max # client connections */
    uint32_t           max_nsconn;  /* max # server connections */
};
```

### conf

```c
struct conf_listen {
    struct string   pname;   /* listen: as "hostname:port" */
    struct string   name;    /* hostname:port */
    int             port;    /* port */
    mode_t          perm;    /* socket permissions */
    struct sockinfo info;    /* listen socket info */
    unsigned        valid:1; /* valid? */
};

struct conf_server {
    struct string   pname;      /* server: as "hostname:port:weight" */
    struct string   name;       /* hostname:port or [name] */
    struct string   addrstr;    /* hostname */
    int             port;       /* port */
    int             weight;     /* weight */
    struct sockinfo info;       /* connect socket info */
    unsigned        valid:1;    /* valid? */
};

struct conf_pool {
    struct string      name;                  /* pool name (root node) */
    struct conf_listen listen;                /* listen: */
    hash_type_t        hash;                  /* hash: */
    struct string      hash_tag;              /* hash_tag: */
    dist_type_t        distribution;          /* distribution: */
    int                timeout;               /* timeout: */
    int                backlog;               /* backlog: */
    int                client_connections;    /* client_connections: */
    int                tcpkeepalive;          /* tcpkeepalive: */
    int                redis;                 /* redis: */
    struct string      redis_auth;            /* redis_auth: redis auth password (matches requirepass on redis) */
    int                redis_db;              /* redis_db: redis db */
    int                preconnect;            /* preconnect: */
    int                auto_eject_hosts;      /* auto_eject_hosts: */
    int                server_connections;    /* server_connections: */
    int                server_retry_timeout;  /* server_retry_timeout: in msec */
    int                server_failure_limit;  /* server_failure_limit: */
    struct array       server;                /* servers: conf_server[] */
    unsigned           valid:1;               /* valid? */
    int                reuseport;             /* set SO_REUSEPORT to socket */
};

struct conf {
    const char    *fname;           /* file name (ref in argv[]) */
    FILE          *fh;              /* file handle */
    struct array  arg;              /* string[] (parsed {key, value} pairs) */
    struct array  pool;             /* conf_pool[] (parsed pools) */
    uint32_t      depth;            /* parsed tree depth */
    yaml_parser_t parser;           /* yaml parser */
    yaml_event_t  event;            /* yaml event */
    yaml_token_t  token;            /* yaml token */
    unsigned      seq:1;            /* sequence? */
    unsigned      valid_parser:1;   /* valid parser? */
    unsigned      valid_event:1;    /* valid event? */
    unsigned      valid_token:1;    /* valid token? */
    unsigned      sound:1;          /* sound? */
    unsigned      parsed:1;         /* parsed? */
    unsigned      valid:1;          /* valid? */
};

struct command {
    struct string name;
    const char    *(*set)(struct conf *cf, const struct command *cmd, void *data);
    int           offset;
};
```

### event_base

```c
#define EVENT_SIZE  1024

#define EVENT_READ  0x0000ff
#define EVENT_WRITE 0x00ff00
#define EVENT_ERR   0xff0000

typedef int (*event_cb_t)(void *, uint32_t);
typedef void (*event_stats_cb_t)(void *, void *);

#ifdef NC_HAVE_KQUEUE

struct event_base {
    int           kq;          /* kernel event queue descriptor */

    struct kevent *change;     /* change[] - events we want to monitor */
    int           nchange;     /* # change */

    struct kevent *event;      /* event[] - events that were triggered */
    int           nevent;      /* # event */
    int           nreturned;   /* # event placed in event[] */
    int           nprocessed;  /* # event processed from event[] */

    event_cb_t    cb;          /* event callback */
};

#elif NC_HAVE_EPOLL

struct event_base {
    int                ep;      /* epoll descriptor */

    struct epoll_event *event;  /* event[] - events that were triggered */
    int                nevent;  /* # event */

    event_cb_t         cb;      /* event callback */
};

#elif NC_HAVE_EVENT_PORTS

#include <port.h>

struct event_base {
    int          evp;     /* event port descriptor */

    port_event_t *event;  /* event[] - events that were triggered */
    int          nevent;  /* # event */

    event_cb_t   cb;      /* event callback */
};
```



### server

```c
typedef uint32_t (*hash_t)(const char *, size_t);

struct continuum {
    uint32_t index;  /* server index */
    uint32_t value;  /* hash value */
};

struct server {
    uint32_t           idx;           /* server index */
    struct server_pool *owner;        /* owner pool */

    struct string      pname;         /* hostname:port:weight (ref in conf_server) */
    struct string      name;          /* hostname:port or [name] (ref in conf_server) */
    struct string      addrstr;       /* hostname (ref in conf_server) */
    uint16_t           port;          /* port */
    uint32_t           weight;        /* weight */
    struct sockinfo    info;          /* server socket info */

    uint32_t           ns_conn_q;     /* # server connection */
    struct conn_tqh    s_conn_q;      /* server connection q */

    int64_t            next_retry;    /* next retry time in usec */
    uint32_t           failure_count; /* # consecutive failures */
};

struct server_pool {
    uint32_t           idx;                  /* pool index */
    struct context     *ctx;                 /* owner context */

    struct conn        *p_conn;              /* proxy connection (listener) */
    uint32_t           nc_conn_q;            /* # client connection */
    struct conn_tqh    c_conn_q;             /* client connection q */

    struct array       server;               /* server[] */
    uint32_t           ncontinuum;           /* # continuum points */
    uint32_t           nserver_continuum;    /* # servers - live and dead on continuum (const) */
    struct continuum   *continuum;           /* continuum */
    uint32_t           nlive_server;         /* # live server */
    int64_t            next_rebuild;         /* next distribution rebuild time in usec */

    struct string      name;                 /* pool name (ref in conf_pool) */
    struct string      addrstr;              /* pool address - hostname:port (ref in conf_pool) */
    uint16_t           port;                 /* port */
    struct sockinfo    info;                 /* listen socket info */
    mode_t             perm;                 /* socket permission */
    int                dist_type;            /* distribution type (dist_type_t) */
    int                key_hash_type;        /* key hash type (hash_type_t) */
    hash_t             key_hash;             /* key hasher */
    struct string      hash_tag;             /* key hash tag (ref in conf_pool) */
    int                timeout;              /* timeout in msec */
    int                backlog;              /* listen backlog */
    int                redis_db;             /* redis database to connect to */
    uint32_t           client_connections;   /* maximum # client connection */
    uint32_t           server_connections;   /* maximum # server connection */
    int64_t            server_retry_timeout; /* server retry timeout in usec */
    uint32_t           server_failure_limit; /* server failure limit */
    struct string      redis_auth;           /* redis_auth password (matches requirepass on redis) */
    unsigned           require_auth;         /* require_auth? */
    unsigned           auto_eject_hosts:1;   /* auto_eject_hosts? */
    unsigned           preconnect:1;         /* preconnect? */
    unsigned           redis:1;              /* redis? */
    unsigned           tcpkeepalive:1;       /* tcpkeepalive? */
    unsigned           reuseport:1;          /* set SO_REUSEPORT to socket */
};
```

### connection/conn

```c
struct conn {
    TAILQ_ENTRY(conn)   conn_tqe;        /* link in server_pool / server / free q */
    void                *owner;          /* connection owner - server_pool / server */

    int                 sd;              /* socket descriptor */
    int                 family;          /* socket address family */
    socklen_t           addrlen;         /* socket length */
    struct sockaddr     *addr;           /* socket address (ref in server or server_pool) */

    struct msg_tqh      imsg_q;          /* incoming request Q */
    struct msg_tqh      omsg_q;          /* outstanding request Q */
    struct msg          *rmsg;           /* current message being rcvd */
    struct msg          *smsg;           /* current message being sent */

    conn_recv_t         recv;            /* recv (read) handler */
    conn_recv_next_t    recv_next;       /* recv next message handler */
    conn_recv_done_t    recv_done;       /* read done handler */
    conn_send_t         send;            /* send (write) handler */
    conn_send_next_t    send_next;       /* write next message handler */
    conn_send_done_t    send_done;       /* write done handler */
    conn_close_t        close;           /* close handler */
    conn_active_t       active;          /* active? handler */
    conn_post_connect_t post_connect;    /* post connect handler */
    conn_swallow_msg_t  swallow_msg;     /* react on messages to be swallowed */

    conn_ref_t          ref;             /* connection reference handler */
    conn_unref_t        unref;           /* connection unreference handler */

    conn_msgq_t         enqueue_inq;     /* connection inq msg enqueue handler */
    conn_msgq_t         dequeue_inq;     /* connection inq msg dequeue handler */
    conn_msgq_t         enqueue_outq;    /* connection outq msg enqueue handler */
    conn_msgq_t         dequeue_outq;    /* connection outq msg dequeue handler */

    size_t              recv_bytes;      /* received (read) bytes */
    size_t              send_bytes;      /* sent (written) bytes */

    uint32_t            events;          /* connection io events */
    err_t               err;             /* connection errno */
    unsigned            recv_active:1;   /* recv active? */
    unsigned            recv_ready:1;    /* recv ready? */
    unsigned            send_active:1;   /* send active? */
    unsigned            send_ready:1;    /* send ready? */

    unsigned            client:1;        /* client? or server? */
    unsigned            proxy:1;         /* proxy? */
    unsigned            connecting:1;    /* connecting? */
    unsigned            connected:1;     /* connected? */
    unsigned            eof:1;           /* eof? aka passive close? */
    unsigned            done:1;          /* done? aka close? */
    unsigned            redis:1;         /* redis? */
    unsigned            authenticated:1; /* authenticated? */
};
```

## C语言解析Yaml配置文件示例

当然！以下是一个使用C语言解析YAML文件的示例代码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <yaml.h>

void parse_yaml(yaml_document_t *doc, yaml_node_t *node);

void parse_mapping_node(yaml_document_t *doc, yaml_node_t *node) {
    yaml_node_pair_t *pair;
    yaml_node_t *key, *value;

    for (pair = node->data.mapping.pairs.start;
         pair < node->data.mapping.pairs.top; pair++) {
        key = yaml_document_get_node(doc, pair->key);
        value = yaml_document_get_node(doc, pair->value);

        // 解析键
        if (key->type == YAML_SCALAR_NODE) {
            printf("Key: %s\n", key->data.scalar.value);
        }

        // 解析值
        parse_yaml(doc, value);
    }
}

void parse_sequence_node(yaml_document_t *doc, yaml_node_t *node) {
    yaml_node_item_t *item;
    yaml_node_t *child_node;

    for (item = node->data.sequence.items.start;
         item < node->data.sequence.items.top; item++) {
        child_node = yaml_document_get_node(doc, *item);
        parse_yaml(doc, child_node);
    }
}

void parse_yaml(yaml_document_t *doc, yaml_node_t *node) {
    switch (node->type) {
        case YAML_MAPPING_NODE:
            parse_mapping_node(doc, node);
            break;
        case YAML_SEQUENCE_NODE:
            parse_sequence_node(doc, node);
            break;
        case YAML_SCALAR_NODE:
            printf("Value: %s\n", node->data.scalar.value);
            break;
        default:
            break;
    }
}

int main() {
    yaml_parser_t parser;
    yaml_document_t document;

    // 初始化解析器
    if (!yaml_parser_initialize(&parser)) {
        printf("Failed to initialize parser!\n");
        return 1;
    }

    // 打开并读取YAML文件
    FILE *file = fopen("example.yaml", "rb");
    if (!file) {
        printf("Failed to open file!\n");
        return 1;
    }

    // 配置解析器
    yaml_parser_set_input_file(&parser, file);

    // 解析YAML文档
    if (!yaml_parser_load(&parser, &document)) {
        printf("Failed to load YAML document!\n");
        return 1;
    }

    // 解析YAML节点
    parse_yaml(&document, yaml_document_get_root_node(&document));

    // 释放资源
    yaml_parser_delete(&parser);
    yaml_document_delete(&document);
    fclose(file);

    return 0;
}
```

请将上述示例代码保存为一个名为 "yaml_parser.c" 的文件，并确保在同一目录下存在一个名为 "example.yaml" 的YAML文件。然后，使用C编译器（如gcc）编译代码：

```
gcc yaml_parser.c -o yaml_parser -lyaml
```

运行生成的可执行文件：

```
./yaml_parser
```

代码将解析 "example.yaml" 文件并打印出其中的键和值。

请注意，此示例使用了 `libyaml` 库来处理YAML解析。在编译代码之前，请确保已安装该库，并且在编译命令中使用了 `-lyaml` 参数以链接该库。

## 启动

```c
static void
nc_run(struct instance *nci)
{
    rstatus_t status;
    struct context *ctx;

    ctx = core_start(nci);
    if (ctx == NULL) {
        return;
    }

    /* run rabbit run */
    for (;;) {
        status = core_loop(ctx);
        if (status != NC_OK) {
            break;
        }
    }

    core_stop(ctx);
}
```

```c
struct context *
core_start(struct instance *nci)
{
    struct context *ctx;

    mbuf_init(nci);
    msg_init();
    conn_init();

  	// 初始化全局context
    ctx = core_ctx_create(nci);
    if (ctx != NULL) {
        nci->ctx = ctx;
        return ctx;
    }

    conn_deinit();
    msg_deinit();
    mbuf_deinit();

    return NULL;
}
```

```c
static struct context *
core_ctx_create(struct instance *nci)
{
    rstatus_t status;
    struct context *ctx;

    ctx = nc_alloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->id = ++ctx_id;
    ctx->cf = NULL;
    ctx->stats = NULL;
    ctx->evb = NULL;
    array_null(&ctx->pool);
    ctx->max_timeout = nci->stats_interval;
    ctx->timeout = ctx->max_timeout;
    ctx->max_nfd = 0;
    ctx->max_ncconn = 0;
    ctx->max_nsconn = 0;

    /* parse and create configuration */
    // TODO, yaml配置文件解析
    ctx->cf = conf_create(nci->conf_filename);
    if (ctx->cf == NULL) {
        nc_free(ctx);
        return NULL;
    }

    /* initialize server pool from configuration */
    status = server_pool_init(&ctx->pool, &ctx->cf->pool, ctx);
    if (status != NC_OK) {
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /*
     * Get rlimit and calculate max client connections after we have
     * calculated max server connections
     */
    status = core_calc_connections(ctx);
    if (status != NC_OK) {
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /* create stats per server pool */
    ctx->stats = stats_create(nci->stats_port, nci->stats_addr, nci->stats_interval,
                              nci->hostname, &ctx->pool);
    if (ctx->stats == NULL) {
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /* initialize event handling for client, proxy and server */
    ctx->evb = event_base_create(EVENT_SIZE, &core_core);
    if (ctx->evb == NULL) {
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /* preconnect? servers in server pool */
    status = server_pool_preconnect(ctx);
    if (status != NC_OK) {
        server_pool_disconnect(ctx);
        event_base_destroy(ctx->evb);
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /* initialize proxy per server pool */
  	// 启动代理实例proxy给每一个端口或者server_pool
  	// server_pool其实就是指代的Yaml配置文件的每一个server块及其对应的配置
    status = proxy_init(ctx);
    if (status != NC_OK) {
        server_pool_disconnect(ctx);
        event_base_destroy(ctx->evb);
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    log_debug(LOG_VVERB, "created ctx %p id %"PRIu32"", ctx, ctx->id);

    return ctx;
}
```

### server_pool初始化

```c
rstatus_t
server_pool_init(struct array *server_pool, struct array *conf_pool,
                 struct context *ctx)
{
    rstatus_t status;
    uint32_t npool;

    npool = array_n(conf_pool);
    ASSERT(npool != 0);
    ASSERT(array_n(server_pool) == 0);

    // 根据配置块数量初始化server_pool数量
  	status = array_init(server_pool, npool, sizeof(struct server_pool));
    if (status != NC_OK) {
        return status;
    }

    /* transform conf pool to server pool */
    status = array_each(conf_pool, conf_pool_each_transform, server_pool);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }
    ASSERT(array_n(server_pool) == npool);

    /* set ctx as the server pool owner */
    // when get ctx from conn
    status = array_each(server_pool, server_pool_each_set_owner, ctx);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    /* compute max server connections */
    ctx->max_nsconn = 0;
    status = array_each(server_pool, server_pool_each_calc_connections, ctx);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    /* update server pool continuum */
    status = array_each(server_pool, server_pool_each_run, NULL);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    log_debug(LOG_DEBUG, "init %"PRIu32" pools", npool);

    return NC_OK;
}
```

### 通过conf_pool构建server_pool

```c
rstatus_t
conf_pool_each_transform(void *elem, void *data)
{
    rstatus_t status;
    struct conf_pool *cp = elem;
    struct array *server_pool = data;
    struct server_pool *sp;

    ASSERT(cp->valid);

    sp = array_push(server_pool);
    ASSERT(sp != NULL);

    sp->idx = array_idx(server_pool, sp);
    sp->ctx = NULL;

    sp->p_conn = NULL;
    sp->nc_conn_q = 0;
    TAILQ_INIT(&sp->c_conn_q);

    array_null(&sp->server);
    sp->ncontinuum = 0;
    sp->nserver_continuum = 0;
    sp->continuum = NULL;
    sp->nlive_server = 0;
    sp->next_rebuild = 0LL;

    sp->name = cp->name;
    sp->addrstr = cp->listen.pname;
    sp->port = (uint16_t)cp->listen.port;

    nc_memcpy(&sp->info, &cp->listen.info, sizeof(cp->listen.info));
    sp->perm = cp->listen.perm;

    sp->key_hash_type = cp->hash;
    sp->key_hash = hash_algos[cp->hash];
    sp->dist_type = cp->distribution;
    sp->hash_tag = cp->hash_tag;

    sp->tcpkeepalive = cp->tcpkeepalive ? 1 : 0;
    sp->reuseport = cp->reuseport ? 1 : 0;

    sp->redis = cp->redis ? 1 : 0;
    sp->timeout = cp->timeout;
    sp->backlog = cp->backlog;
    sp->redis_db = cp->redis_db;

    sp->redis_auth = cp->redis_auth;
    sp->require_auth = cp->redis_auth.len > 0 ? 1 : 0;

    sp->client_connections = (uint32_t)cp->client_connections;
    sp->server_connections = (uint32_t)cp->server_connections;
    sp->server_retry_timeout = (int64_t)cp->server_retry_timeout * 1000LL;
    sp->server_failure_limit = (uint32_t)cp->server_failure_limit;
    sp->auto_eject_hosts = cp->auto_eject_hosts ? 1 : 0;
    sp->preconnect = cp->preconnect ? 1 : 0;

    status = server_init(&sp->server, &cp->server, sp);
    if (status != NC_OK) {
        return status;
    }

    log_debug(LOG_VERB, "transform to pool %"PRIu32" '%.*s'", sp->idx,
              sp->name.len, sp->name.data);

    return NC_OK;
}

static rstatus_t
server_pool_each_set_owner(void *elem, void *data)
{
    struct server_pool *sp = elem;
    struct context *ctx = data;

    sp->ctx = ctx;

    return NC_OK;
}

static rstatus_t
server_pool_each_calc_connections(void *elem, void *data)
{
    struct server_pool *sp = elem;
    struct context *ctx = data;

    ctx->max_nsconn += sp->server_connections * array_n(&sp->server);
    ctx->max_nsconn += 1; /* pool listening socket */

    return NC_OK;
}
```

### server_pool_each_run

```c
rstatus_t
server_pool_run(struct server_pool *pool)
{
    ASSERT(array_n(&pool->server) != 0);

    switch (pool->dist_type) {
    case DIST_KETAMA:
        return ketama_update(pool);

    case DIST_MODULA:
        return modula_update(pool);

    case DIST_RANDOM:
        return random_update(pool);

    default:
        NOT_REACHED();
        return NC_ERROR;
    }

    return NC_OK;
}

static rstatus_t
server_pool_each_run(void *elem, void *data)
{
    return server_pool_run(elem);
}
```

### 如何获取服务器连接

```c
static uint32_t
server_pool_hash(const struct server_pool *pool, const uint8_t *key, uint32_t keylen)
{
    ASSERT(array_n(&pool->server) != 0);
    ASSERT(key != NULL);

    if (array_n(&pool->server) == 1) {
        return 0;
    }

    if (keylen == 0) {
        return 0;
    }

    return pool->key_hash((const char *)key, keylen);
}

uint32_t
server_pool_idx(const struct server_pool *pool, const uint8_t *key, uint32_t keylen)
{
    uint32_t hash, idx;
    uint32_t nserver = array_n(&pool->server);

    ASSERT(nserver != 0);
    ASSERT(key != NULL);

    if (nserver == 1) {
        /* Optimization: Skip hashing and dispatching for pools with only one server */
        return 0;
    }

    /*
     * If hash_tag: is configured for this server pool, we use the part of
     * the key within the hash tag as an input to the distributor. Otherwise
     * we use the full key
     */
    if (!string_empty(&pool->hash_tag)) {
        const struct string *tag = &pool->hash_tag;
        const uint8_t *tag_start, *tag_end;

        tag_start = nc_strchr(key, key + keylen, tag->data[0]);
        if (tag_start != NULL) {
            tag_end = nc_strchr(tag_start + 1, key + keylen, tag->data[1]);
            if ((tag_end != NULL) && (tag_end - tag_start > 1)) {
                key = tag_start + 1;
                keylen = (uint32_t)(tag_end - key);
            }
        }
    }

    switch (pool->dist_type) {
    case DIST_KETAMA:
        hash = server_pool_hash(pool, key, keylen);
        idx = ketama_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;

    case DIST_MODULA:
        hash = server_pool_hash(pool, key, keylen);
        idx = modula_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;

    case DIST_RANDOM:
        idx = random_dispatch(pool->continuum, pool->ncontinuum, 0);
        break;

    default:
        NOT_REACHED();
        return 0;
    }
    ASSERT(idx < array_n(&pool->server));
    return idx;
}

static struct server *
server_pool_server(struct server_pool *pool, const uint8_t *key, uint32_t keylen)
{
    struct server *server;
    uint32_t idx;

    idx = server_pool_idx(pool, key, keylen);
    server = array_get(&pool->server, idx);

    log_debug(LOG_VERB, "key '%.*s' on dist %d maps to server '%.*s'", keylen,
              key, pool->dist_type, server->pname.len, server->pname.data);

    return server;
}

struct conn *
server_pool_conn(struct context *ctx, struct server_pool *pool, const uint8_t *key,
                 uint32_t keylen)
{
    rstatus_t status;
    struct server *server;
    struct conn *conn;

    // TODO，这里可能就是为什么可以提前在配置文件中预埋服务器地址和端口，而后再后续维护中启动对应机器即可的原因
  	status = server_pool_update(pool);
    if (status != NC_OK) {
        return NULL;
    }

    /* from a given {key, keylen} pick a server from pool */
    server = server_pool_server(pool, key, keylen);
    if (server == NULL) {
        return NULL;
    }

    /* pick a connection to a given server */
    conn = server_conn(server);
    if (conn == NULL) {
        return NULL;
    }

    status = server_connect(ctx, server, conn);
    if (status != NC_OK) {
        server_close(ctx, conn);
        return NULL;
    }

    return conn;
}
```

### server初始化

```c
rstatus_t
server_init(struct array *server, struct array *conf_server,
            struct server_pool *sp)
{
    rstatus_t status;
    uint32_t nserver;

    nserver = array_n(conf_server);
    ASSERT(nserver != 0);
    ASSERT(array_n(server) == 0);

    status = array_init(server, nserver, sizeof(struct server));
    if (status != NC_OK) {
        return status;
    }

    /* transform conf server to server */
    status = array_each(conf_server, conf_server_each_transform, server);
    if (status != NC_OK) {
        server_deinit(server);
        return status;
    }
    ASSERT(array_n(server) == nserver);

    /* set server owner */
    status = array_each(server, server_each_set_owner, sp);
    if (status != NC_OK) {
        server_deinit(server);
        return status;
    }

    log_debug(LOG_DEBUG, "init %"PRIu32" servers in pool %"PRIu32" '%.*s'",
              nserver, sp->idx, sp->name.len, sp->name.data);

    return NC_OK;
}

rstatus_t
conf_server_each_transform(void *elem, void *data)
{
    struct conf_server *cs = elem;
    struct array *server = data;
    struct server *s;

    ASSERT(cs->valid);

    s = array_push(server);
    ASSERT(s != NULL);

    s->idx = array_idx(server, s);
    s->owner = NULL;

    s->pname = cs->pname;
    s->name = cs->name;
    s->addrstr = cs->addrstr;
    s->port = (uint16_t)cs->port;
    s->weight = (uint32_t)cs->weight;

    nc_memcpy(&s->info, &cs->info, sizeof(cs->info));

    s->ns_conn_q = 0;
    TAILQ_INIT(&s->s_conn_q);

    s->next_retry = 0LL;
    s->failure_count = 0;

    log_debug(LOG_VERB, "transform to server %"PRIu32" '%.*s'",
              s->idx, s->pname.len, s->pname.data);

    return NC_OK;
}

static rstatus_t
server_each_set_owner(void *elem, void *data)
{
    struct server *s = elem;
    struct server_pool *sp = data;

    s->owner = sp;

    return NC_OK;
}
```

### proxy初始化

```c
rstatus_t
proxy_init(struct context *ctx)
{
    rstatus_t status;

    ASSERT(array_n(&ctx->pool) != 0);

    status = array_each(&ctx->pool, proxy_each_init, NULL);
    if (status != NC_OK) {
        proxy_deinit(ctx);
        return status;
    }

    log_debug(LOG_VVERB, "init proxy with %"PRIu32" pools",
              array_n(&ctx->pool));

    return NC_OK;
}

rstatus_t
proxy_each_init(void *elem, void *data)
{
    rstatus_t status;
    struct server_pool *pool = elem;
    struct conn *p;

    p = conn_get_proxy(pool);
    if (p == NULL) {
        return NC_ENOMEM;
    }

    status = proxy_listen(pool->ctx, p);
    if (status != NC_OK) {
        p->close(pool->ctx, p);
        return status;
    }

    log_debug(LOG_NOTICE, "p %d listening on '%.*s' in %s pool %"PRIu32" '%.*s'"
              " with %"PRIu32" servers", p->sd, pool->addrstr.len,
              pool->addrstr.data, pool->redis ? "redis" : "memcache",
              pool->idx, pool->name.len, pool->name.data,
              array_n(&pool->server));

    return NC_OK;
}

struct conn *
conn_get_proxy(struct server_pool *pool)
{
    struct conn *conn;

  	// just get initialized conn
    conn = _conn_get();
    if (conn == NULL) {
        return NULL;
    }

    conn->redis = pool->redis;

    conn->proxy = 1;

    conn->recv = proxy_recv;
    /*
    rstatus_t
    proxy_recv(struct context *ctx, struct conn *conn)
    {
        rstatus_t status;

        ASSERT(conn->proxy && !conn->client);
        ASSERT(conn->recv_active);

        conn->recv_ready = 1;
        do {
            status = proxy_accept(ctx, conn);
            if (status != NC_OK) {
                return status;
            }
        } while (conn->recv_ready);

        return NC_OK;
    }
    */
    conn->recv_next = NULL;
    conn->recv_done = NULL;

    conn->send = NULL;
    conn->send_next = NULL;
    conn->send_done = NULL;

    conn->close = proxy_close;
    conn->active = NULL;

    conn->ref = proxy_ref;
    conn->unref = proxy_unref;

    conn->enqueue_inq = NULL;
    conn->dequeue_inq = NULL;
    conn->enqueue_outq = NULL;
    conn->dequeue_outq = NULL;

    conn->ref(conn, pool);

    log_debug(LOG_VVERB, "get conn %p proxy %d", conn, conn->proxy);

    return conn;
}

static rstatus_t
proxy_listen(struct context *ctx, struct conn *p)
{
    rstatus_t status;
    struct server_pool *pool = p->owner;

    ASSERT(p->proxy);

    p->sd = socket(p->family, SOCK_STREAM, 0);
    if (p->sd < 0) {
        log_error("socket failed: %s", strerror(errno));
        return NC_ERROR;
    }

    status = proxy_reuse(p);
    if (status < 0) {
        log_error("reuse of addr '%.*s' for listening on p %d failed: %s",
                  pool->addrstr.len, pool->addrstr.data, p->sd,
                  strerror(errno));
        return NC_ERROR;
    }

    if (pool->reuseport) {
        status = nc_set_reuseport(p->sd);
        if (status < 0) {
            log_error("reuse of port '%.*s' for listening on p %d failed: %s",
                      pool->addrstr.len, pool->addrstr.data, p->sd,
                      strerror(errno));
            return NC_ERROR;
        }
    }

    status = bind(p->sd, p->addr, p->addrlen);
    if (status < 0) {
        log_error("bind on p %d to addr '%.*s' failed: %s", p->sd,
                  pool->addrstr.len, pool->addrstr.data, strerror(errno));
        return NC_ERROR;
    }

    if (p->family == AF_UNIX && pool->perm) {
        struct sockaddr_un *un = (struct sockaddr_un *)p->addr;
        status = chmod(un->sun_path, pool->perm);
        if (status < 0) {
            log_error("chmod on p %d on addr '%.*s' failed: %s", p->sd,
                      pool->addrstr.len, pool->addrstr.data, strerror(errno));
            return NC_ERROR;
        }
    }

    status = listen(p->sd, pool->backlog);
    if (status < 0) {
        log_error("listen on p %d on addr '%.*s' failed: %s", p->sd,
                  pool->addrstr.len, pool->addrstr.data, strerror(errno));
        return NC_ERROR;
    }

    status = nc_set_nonblocking(p->sd);
    if (status < 0) {
        log_error("set nonblock on p %d on addr '%.*s' failed: %s", p->sd,
                  pool->addrstr.len, pool->addrstr.data, strerror(errno));
        return NC_ERROR;
    }

    status = event_add_conn(ctx->evb, p);
    if (status < 0) {
        log_error("event add conn p %d on addr '%.*s' failed: %s",
                  p->sd, pool->addrstr.len, pool->addrstr.data,
                  strerror(errno));
        return NC_ERROR;
    }

    status = event_del_out(ctx->evb, p);
    if (status < 0) {
        log_error("event del out p %d on addr '%.*s' failed: %s",
                  p->sd, pool->addrstr.len, pool->addrstr.data,
                  strerror(errno));
        return NC_ERROR;
    }

    return NC_OK;
}
```

### proxy_accept

```c
static rstatus_t
proxy_accept(struct context *ctx, struct conn *p)
{
    rstatus_t status;
    struct conn *c;
    int sd;
    struct server_pool *pool = p->owner;

    ASSERT(p->proxy && !p->client);
    ASSERT(p->sd > 0);
    ASSERT(p->recv_active && p->recv_ready);

    for (;;) {
        sd = accept(p->sd, NULL, NULL);
        if (sd < 0) {
            if (errno == EINTR) {
                log_debug(LOG_VERB, "accept on p %d not ready - eintr", p->sd);
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNABORTED) {
                log_debug(LOG_VERB, "accept on p %d not ready - eagain", p->sd);
                p->recv_ready = 0;
                return NC_OK;
            }

            /*
             * Workaround of https://github.com/twitter/twemproxy/issues/97
             *
             * We should never reach here because the check for conn_ncurr_cconn()
             * against ctx->max_ncconn should catch this earlier in the cycle.
             * If we reach here ignore EMFILE/ENFILE, return NC_OK will enable
             * the server continue to run instead of close the server socket
             *
             * The right solution however, is on EMFILE/ENFILE to mask out IN
             * event on the proxy and mask it back in when some existing
             * connections gets closed
             */
            if (errno == EMFILE || errno == ENFILE) {
                log_debug(LOG_CRIT, "accept on p %d with max fds %"PRIu32" "
                          "used connections %"PRIu32" max client connections %"PRIu32" "
                          "curr client connections %"PRIu32" failed: %s",
                          p->sd, ctx->max_nfd, conn_ncurr_conn(),
                          ctx->max_ncconn, conn_ncurr_cconn(), strerror(errno));

                p->recv_ready = 0;

                return NC_OK;
            }

            log_error("accept on p %d failed: %s", p->sd, strerror(errno));

            return NC_ERROR;
        }

        break;
    }

    if (conn_ncurr_cconn() >= ctx->max_ncconn) {
        log_debug(LOG_CRIT, "client connections %"PRIu32" exceed limit %"PRIu32,
                  conn_ncurr_cconn(), ctx->max_ncconn);
        status = close(sd);
        if (status < 0) {
            log_error("close c %d failed, ignored: %s", sd, strerror(errno));
        }
        return NC_OK;
    }

  	// !!!!!Important
    c = conn_get(p->owner, true, p->redis);
    if (c == NULL) {
        log_error("get conn for c %d from p %d failed: %s", sd, p->sd,
                  strerror(errno));
        status = close(sd);
        if (status < 0) {
            log_error("close c %d failed, ignored: %s", sd, strerror(errno));
        }
        return NC_ENOMEM;
    }
    c->sd = sd;

    stats_pool_incr(ctx, c->owner, client_connections);

    status = nc_set_nonblocking(c->sd);
    if (status < 0) {
        log_error("set nonblock on c %d from p %d failed: %s", c->sd, p->sd,
                  strerror(errno));
        c->close(ctx, c);
        return status;
    }

    if (pool->tcpkeepalive) {
        status = nc_set_tcpkeepalive(c->sd);
        if (status < 0) {
            log_warn("set tcpkeepalive on c %d from p %d failed, ignored: %s",
                     c->sd, p->sd, strerror(errno));
        }
    }

    if (p->family == AF_INET || p->family == AF_INET6) {
        status = nc_set_tcpnodelay(c->sd);
        if (status < 0) {
            log_warn("set tcpnodelay on c %d from p %d failed, ignored: %s",
                     c->sd, p->sd, strerror(errno));
        }
    }

    status = event_add_conn(ctx->evb, c);
    if (status < 0) {
        log_error("event add conn from p %d failed: %s", p->sd,
                  strerror(errno));
        c->close(ctx, c);
        return status;
    }

    log_debug(LOG_NOTICE, "accepted c %d on p %d from '%s'", c->sd, p->sd,
              nc_unresolve_peer_desc(c->sd));

    return NC_OK;
}
```

### conn_get

> 每个代理有对应的读事件之后处理连接请求时，对连接做处理时用到的，添加读写处理函数

```shell
struct conn *
conn_get(void *owner, bool client, bool redis)
{
    struct conn *conn;

    conn = _conn_get();
    if (conn == NULL) {
        return NULL;
    }

    /* connection either handles redis or memcache messages */
    conn->redis = redis ? 1 : 0;

    conn->client = client ? 1 : 0;

    if (conn->client) {
        /*
         * client receives a request, possibly parsing it, and sends a
         * response downstream.
         */
        conn->recv = msg_recv;
        conn->recv_next = req_recv_next;
        conn->recv_done = req_recv_done;  //调用recv_forward，然后获取server连接，转发消息

        conn->send = msg_send;
        conn->send_next = rsp_send_next;
        conn->send_done = rsp_send_done;

        conn->close = client_close;
        conn->active = client_active;

        conn->ref = client_ref;
        conn->unref = client_unref;

        conn->enqueue_inq = NULL;
        conn->dequeue_inq = NULL;
        conn->enqueue_outq = req_client_enqueue_omsgq;
        conn->dequeue_outq = req_client_dequeue_omsgq;
        conn->post_connect = NULL;
        conn->swallow_msg = NULL;

        ncurr_cconn++;
    } else {
        /*
         * server receives a response, possibly parsing it, and sends a
         * request upstream.
         */
        conn->recv = msg_recv;
        conn->recv_next = rsp_recv_next;
        conn->recv_done = rsp_recv_done;

        conn->send = msg_send;
        conn->send_next = req_send_next;
        conn->send_done = req_send_done;

        conn->close = server_close;
        conn->active = server_active;

        conn->ref = server_ref;
        conn->unref = server_unref;

        conn->enqueue_inq = req_server_enqueue_imsgq;
        conn->dequeue_inq = req_server_dequeue_imsgq;
        conn->enqueue_outq = req_server_enqueue_omsgq;
        conn->dequeue_outq = req_server_dequeue_omsgq;
        if (redis) {
          conn->post_connect = redis_post_connect;
          conn->swallow_msg = redis_swallow_msg;
        } else {
          conn->post_connect = memcache_post_connect;
          conn->swallow_msg = memcache_swallow_msg;
        }
    }

    conn->ref(conn, owner);
    log_debug(LOG_VVERB, "get conn %p client %d", conn, conn->client);

    return conn;
}
```

### 事件循环处理器

```c
rstatus_t
core_core(void *arg, uint32_t events)
{
    rstatus_t status;
    struct conn *conn = arg;
    struct context *ctx;

    if (conn->owner == NULL) {
        log_warn("conn is already unrefed!");
        return NC_OK;
    }

    // get ctx from server pool by connection
    ctx = conn_to_ctx(conn);

    log_debug(LOG_VVERB, "event %04"PRIX32" on %c %d", events,
              conn->client ? 'c' : (conn->proxy ? 'p' : 's'), conn->sd);

    conn->events = events;

    /* error takes precedence over read | write */
    if (events & EVENT_ERR) {
        core_error(ctx, conn);
        return NC_ERROR;
    }

    /* read takes precedence over write */
    if (events & EVENT_READ) {
        status = core_recv(ctx, conn);
        if (status != NC_OK || conn->done || conn->err) {
            core_close(ctx, conn);
            return NC_ERROR;
        }
    }

    if (events & EVENT_WRITE) {
        status = core_send(ctx, conn);
        if (status != NC_OK || conn->done || conn->err) {
            core_close(ctx, conn);
            return NC_ERROR;
        }
    }

    return NC_OK;
}
```

## 读写请求处理

### 读取消息

```c
static rstatus_t
msg_recv_chain(struct context *ctx, struct conn *conn, struct msg *msg)
{
    rstatus_t status;
    struct msg *nmsg;
    struct mbuf *mbuf;
    size_t msize;
    ssize_t n;

    mbuf = STAILQ_LAST(&msg->mhdr, mbuf, next);
    if (mbuf == NULL || mbuf_full(mbuf)) {
        mbuf = mbuf_get();
        if (mbuf == NULL) {
            return NC_ENOMEM;
        }
        mbuf_insert(&msg->mhdr, mbuf);
        msg->pos = mbuf->pos;
    }
    ASSERT(mbuf->end - mbuf->last > 0);

    msize = mbuf_size(mbuf);

    n = conn_recv(conn, mbuf->last, msize);
    if (n < 0) {
        if (n == NC_EAGAIN) {
            return NC_OK;
        }
        return NC_ERROR;
    }

    ASSERT((mbuf->last + n) <= mbuf->end);
    mbuf->last += n;
    msg->mlen += (uint32_t)n;

    for (;;) {
        status = msg_parse(ctx, conn, msg);
        if (status != NC_OK) {
            return status;
        }

        /* get next message to parse */
        nmsg = conn->recv_next(ctx, conn, false);
        if (nmsg == NULL || nmsg == msg) {
            /* no more data to parse */
            break;
        }

        msg = nmsg;
    }

    return NC_OK;
}

rstatus_t
msg_recv(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    struct msg *msg;

    ASSERT(conn->recv_active);

    conn->recv_ready = 1;
    do {
        msg = conn->recv_next(ctx, conn, true);
        if (msg == NULL) {
            return NC_OK;
        }

        status = msg_recv_chain(ctx, conn, msg);
        if (status != NC_OK) {
            return status;
        }
    } while (conn->recv_ready);

    return NC_OK;
}

static rstatus_t
msg_parsed(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct msg *nmsg;
    struct mbuf *mbuf, *nbuf;

    mbuf = STAILQ_LAST(&msg->mhdr, mbuf, next);
    if (msg->pos == mbuf->last) {
        /* no more data to parse */
        conn->recv_done(ctx, conn, msg, NULL);
        return NC_OK;
    }

    /*
     * Input mbuf has un-parsed data. Split mbuf of the current message msg
     * into (mbuf, nbuf), where mbuf is the portion of the message that has
     * been parsed and nbuf is the portion of the message that is un-parsed.
     * Parse nbuf as a new message nmsg in the next iteration.
     */
    nbuf = mbuf_split(&msg->mhdr, msg->pos, NULL, NULL);
    if (nbuf == NULL) {
        return NC_ENOMEM;
    }

    nmsg = msg_get(msg->owner, msg->request, conn->redis);
    if (nmsg == NULL) {
        mbuf_put(nbuf);
        return NC_ENOMEM;
    }
    mbuf_insert(&nmsg->mhdr, nbuf);
    nmsg->pos = nbuf->pos;

    /* update length of current (msg) and new message (nmsg) */
    nmsg->mlen = mbuf_length(nbuf);
    msg->mlen -= nmsg->mlen;

    conn->recv_done(ctx, conn, msg, nmsg);

    return NC_OK;
}

static rstatus_t
msg_repair(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct mbuf *nbuf;

    nbuf = mbuf_split(&msg->mhdr, msg->pos, NULL, NULL);
    if (nbuf == NULL) {
        return NC_ENOMEM;
    }
    mbuf_insert(&msg->mhdr, nbuf);
    msg->pos = nbuf->pos;

    return NC_OK;
}

static rstatus_t
msg_parse(struct context *ctx, struct conn *conn, struct msg *msg)
{
    rstatus_t status;

    if (msg_empty(msg)) {
        /* no data to parse */
        conn->recv_done(ctx, conn, msg, NULL);
        return NC_OK;
    }

    msg->parser(msg);

    switch (msg->result) {
    case MSG_PARSE_OK:
        status = msg_parsed(ctx, conn, msg);
        break;

    case MSG_PARSE_REPAIR:
        status = msg_repair(ctx, conn, msg);
        break;

    case MSG_PARSE_AGAIN:
        status = NC_OK;
        break;

    default:
        status = NC_ERROR;
        conn->err = errno;
        break;
    }

    return conn->err != 0 ? NC_ERROR : status;
}
```

### 发送消息

```c
static rstatus_t
msg_send_chain(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct msg_tqh send_msgq;            /* send msg q */
    struct msg *nmsg;                    /* next msg */
    struct mbuf *mbuf, *nbuf;            /* current and next mbuf */
    size_t mlen;                         /* current mbuf data length */
    struct iovec *ciov, iov[NC_IOV_MAX]; /* current iovec */
    struct array sendv;                  /* send iovec */
    size_t nsend, nsent;                 /* bytes to send; bytes sent */
    size_t limit;                        /* bytes to send limit */
    ssize_t n;                           /* bytes sent by sendv */

    TAILQ_INIT(&send_msgq);

    array_set(&sendv, iov, sizeof(iov[0]), NC_IOV_MAX);

    /* preprocess - build iovec */

    nsend = 0;
    /*
     * readv() and writev() returns EINVAL if the sum of the iov_len values
     * overflows an ssize_t value Or, the vector count iovcnt is less than
     * zero or greater than the permitted maximum.
     */
    limit = SSIZE_MAX;

    for (;;) {
        ASSERT(conn->smsg == msg);

        TAILQ_INSERT_TAIL(&send_msgq, msg, m_tqe);

        for (mbuf = STAILQ_FIRST(&msg->mhdr);
             mbuf != NULL && array_n(&sendv) < NC_IOV_MAX && nsend < limit;
             mbuf = nbuf) {
            nbuf = STAILQ_NEXT(mbuf, next);

            if (mbuf_empty(mbuf)) {
                continue;
            }

            mlen = mbuf_length(mbuf);
            if ((nsend + mlen) > limit) {
                mlen = limit - nsend;
            }

            ciov = array_push(&sendv);
            ciov->iov_base = mbuf->pos;
            ciov->iov_len = mlen;

            nsend += mlen;
        }

        if (array_n(&sendv) >= NC_IOV_MAX || nsend >= limit) {
            break;
        }

        msg = conn->send_next(ctx, conn);
        if (msg == NULL) {
            break;
        }
    }

    /*
     * (nsend == 0) is possible in redis multi-del
     * see PR: https://github.com/twitter/twemproxy/pull/225
     */
    conn->smsg = NULL;
    if (!TAILQ_EMPTY(&send_msgq) && nsend != 0) {
        n = conn_sendv(conn, &sendv, nsend);
    } else {
        n = 0;
    }

    nsent = n > 0 ? (size_t)n : 0;

    /* postprocess - process sent messages in send_msgq */

    for (msg = TAILQ_FIRST(&send_msgq); msg != NULL; msg = nmsg) {
        nmsg = TAILQ_NEXT(msg, m_tqe);

        TAILQ_REMOVE(&send_msgq, msg, m_tqe);

        if (nsent == 0) {
            if (msg->mlen == 0) {
                conn->send_done(ctx, conn, msg);
            }
            continue;
        }

        /* adjust mbufs of the sent message */
        for (mbuf = STAILQ_FIRST(&msg->mhdr); mbuf != NULL; mbuf = nbuf) {
            nbuf = STAILQ_NEXT(mbuf, next);

            if (mbuf_empty(mbuf)) {
                continue;
            }

            mlen = mbuf_length(mbuf);
            if (nsent < mlen) {
                /* mbuf was sent partially; process remaining bytes later */
                mbuf->pos += nsent;
                ASSERT(mbuf->pos < mbuf->last);
                nsent = 0;
                break;
            }

            /* mbuf was sent completely; mark it empty */
            mbuf->pos = mbuf->last;
            nsent -= mlen;
        }

        /* message has been sent completely, finalize it */
        if (mbuf == NULL) {
            conn->send_done(ctx, conn, msg);
        }
    }

    ASSERT(TAILQ_EMPTY(&send_msgq));

    if (n >= 0) {
        return NC_OK;
    }

    return (n == NC_EAGAIN) ? NC_OK : NC_ERROR;
}

rstatus_t
msg_send(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    struct msg *msg;

    ASSERT(conn->send_active);

    conn->send_ready = 1;
    do {
        msg = conn->send_next(ctx, conn);
        if (msg == NULL) {
            /* nothing to send */
            return NC_OK;
        }

        status = msg_send_chain(ctx, conn, msg);
        if (status != NC_OK) {
            return status;
        }

    } while (conn->send_ready);

    return NC_OK;
}
```

### 请求转发

```c
void
req_recv_done(struct context *ctx, struct conn *conn, struct msg *msg,
              struct msg *nmsg)
{
    rstatus_t status;
    struct server_pool *pool;
    struct msg_tqh frag_msgq;
    struct msg *sub_msg;
    struct msg *tmsg; 			/* tmp next message */

    ASSERT(conn->client && !conn->proxy);
    ASSERT(msg->request);
    ASSERT(msg->owner == conn);
    ASSERT(conn->rmsg == msg);
    ASSERT(nmsg == NULL || nmsg->request);

    /* enqueue next message (request), if any */
    conn->rmsg = nmsg;

    if (req_filter(conn, msg)) {
        return;
    }

    if (msg->noforward) {
        status = req_make_reply(ctx, conn, msg);
        if (status != NC_OK) {
            conn->err = errno;
            return;
        }

        status = msg->reply(msg);
        if (status != NC_OK) {
            conn->err = errno;
            return;
        }

        status = event_add_out(ctx->evb, conn);
        if (status != NC_OK) {
            conn->err = errno;
        }

        return;
    }

    /* do fragment */
    pool = conn->owner;
    TAILQ_INIT(&frag_msgq);
    status = msg->fragment(msg, array_n(&pool->server), &frag_msgq);
    if (status != NC_OK) {
        if (!msg->noreply) {
            conn->enqueue_outq(ctx, conn, msg);
        }
        req_forward_error(ctx, conn, msg);
    }

    /* if no fragment happened */
    if (TAILQ_EMPTY(&frag_msgq)) {
        req_forward(ctx, conn, msg);
        return;
    }

    status = req_make_reply(ctx, conn, msg);
    if (status != NC_OK) {
        if (!msg->noreply) {
            conn->enqueue_outq(ctx, conn, msg);
        }
        req_forward_error(ctx, conn, msg);
    }

    for (sub_msg = TAILQ_FIRST(&frag_msgq); sub_msg != NULL; sub_msg = tmsg) {
        tmsg = TAILQ_NEXT(sub_msg, m_tqe);

        TAILQ_REMOVE(&frag_msgq, sub_msg, m_tqe);
        req_forward(ctx, conn, sub_msg);
    }

    ASSERT(TAILQ_EMPTY(&frag_msgq));
    return;
}
```

> 接收完消息之后，再进行转发

```c
static void
req_forward(struct context *ctx, struct conn *c_conn, struct msg *msg)
{
    rstatus_t status;
    struct conn *s_conn;
    uint8_t *key;
    uint32_t keylen;
    struct keypos *kpos;

    ASSERT(c_conn->client && !c_conn->proxy);

    /* enqueue message (request) into client outq, if response is expected */
    if (!msg->noreply) {
        c_conn->enqueue_outq(ctx, c_conn, msg);
    }

    ASSERT(array_n(msg->keys) > 0);
    kpos = array_get(msg->keys, 0);
    key = kpos->start;
    keylen = (uint32_t)(kpos->end - kpos->start);

    // !!!!Important
  	// 从server_pool中获取一个conn
  	s_conn = server_pool_conn(ctx, c_conn->owner, key, keylen);
    if (s_conn == NULL) {
        /*
         * Handle a failure to establish a new connection to a server,
         * e.g. due to dns resolution errors.
         *
         * If this is a fragmented request sent to multiple servers such as
         * a memcache get(multiget),
         * mark the fragment for this request to the server as done.
         *
         * Normally, this would be done when the request was forwarded to the
         * server, but due to failing to connect to the server this check is
         * repeated here.
         */
        if (msg->frag_owner != NULL) {
            msg->frag_owner->nfrag_done++;
        }
        req_forward_error(ctx, c_conn, msg);
        return;
    }
    ASSERT(!s_conn->client && !s_conn->proxy);

    /* enqueue the message (request) into server inq */
    if (TAILQ_EMPTY(&s_conn->imsg_q)) {
        status = event_add_out(ctx->evb, s_conn);
        if (status != NC_OK) {
            req_forward_error(ctx, c_conn, msg);
            s_conn->err = errno;
            return;
        }
    }

    if (!conn_authenticated(s_conn)) {
        status = msg->add_auth(ctx, c_conn, s_conn);
        if (status != NC_OK) {
            req_forward_error(ctx, c_conn, msg);
            s_conn->err = errno;
            return;
        }
    }

    s_conn->enqueue_inq(ctx, s_conn, msg);

    req_forward_stats(ctx, s_conn->owner, msg);

    log_debug(LOG_VERB, "forward from c %d to s %d req %"PRIu64" len %"PRIu32
              " type %d with key '%.*s'", c_conn->sd, s_conn->sd, msg->id,
              msg->mlen, msg->type, keylen, key);
}
```

## 自定义转发策略

> 修改server_pool字段

```c
map_t              hm_server;            /* 根据 server 的 name 为key, index 为 val 的hashmap*/
```

> 修改根据sp类型获取server的方式

```c
    case DIST_SERVER_NAME:
        hash = hash_server_name(pool, (char *)key, keylen);
        idx = server_name_dispatch(pool->continuum, pool->ncontinuum, hash);
        return idx;

```



### 配置示例

```yaml
servers:
  listen: /tmp/twemproxy.sock
  hash: server_name
  distribution: server_name
  timeout: 8000
  redis: true
  auto_eject_hosts: false
  preconnect: true
  servers:
   - 127.0.0.1:6379:1 r1
   - 127.0.0.1:6379:1 r2
   - 127.0.0.1:6379:1 r3
   - 127.0.0.1:6379:1 r4
   - 127.0.0.1:6379:1 r5
   - 127.0.0.1:6379:1 r6

```

