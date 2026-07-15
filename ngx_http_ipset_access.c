/********************************************************************
 * A nginx module that help you control access of users using IPSET
 *
 * Original author: Mohammad Mahdi Roozitalab <mehdiboss_qi@hotmail.com>
 *
 * Fork changes:
 *   - IPv4 + IPv6 client address support (dual stack).
 *   - Client address is now obtained from c->addr_text instead of
 *     inet_ntoa(), which only ever worked for AF_INET.
 *   - Blocked requests now get HTTP 444 (connection closed, no
 *     response sent) instead of HTTP 403.
 *   - The "blacklist"/"whitelist" directives are now also valid
 *     inside "location" blocks (NGX_HTTP_LOC_CONF), in addition to
 *     "http" and "server".
 *   - Verified against the nginx 1.31.x module API (phases, module
 *     context, ngx_http_get_module_loc_conf, connection->addr_text)
 *     -- no changes were required in the core API used by this
 *     module between the version this was originally written
 *     against and 1.31.
 ********************************************************************/

/* ngx_config.h must be included first: it sets the feature-test macros
 * (e.g. _GNU_SOURCE) that glibc's own headers rely on (in6_pktinfo and
 * friends). Pulling in a system header such as <sys/socket.h> before
 * it, as the upstream module used to do, leaves those macros unset for
 * whichever glibc header gets included first and breaks the build as
 * soon as something transitively drags in <netinet/in.h> (nginx's own
 * ngx_event_udp.h does, from 1.9.13 onward). */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <pthread.h>
#include <sys/socket.h>

#include <libipset/session.h>
#include <libipset/types.h>

#if __GNUC__
#   define NGX_LIKELY(x)       __builtin_expect(!!(x), 1)
#   define NGX_UNLIKELY(x)     __builtin_expect(!!(x), 0)
#else
#   define NGX_LIKELY(x)        (x)
#   define NGX_UNLIKELY(x)      (x)
#endif

/** IPSET integration ***********************************************/
typedef struct ipset_session        ngx_ipset_session_t;
typedef enum ngx_ipset_test_result_t {
    IPS_TEST_IS_IN_SET,
    IPS_TEST_IS_NOT_IN_SET,
    IPS_TEST_INVALID_SETNAME,
    IPS_TEST_INVALID_IP,
    IPS_TEST_FAIL,
} ngx_ipset_test_result_t;

/** Initialize IPSET.
 * \return 0 to indicate success and other value to indicate error */
static int ngx_initialize_ipset() {
    ipset_load_types();
    return 0;
}

/** Create a new IPSET session. */
static ngx_ipset_session_t* ngx_create_ipset_session() {
#ifdef WITH_LIBIPSET_V6_COMPAT
#   define ngx_ipset_session_new() ipset_session_init(printf)
#else
#   define ngx_ipset_session_new() ipset_session_init(NULL, NULL)
#endif
    return ngx_ipset_session_new();
#undef ngx_ipset_session_new
}

/** Destroy an IPSET session that created using \ref ngx_create_ipset_session */
static void ngx_destroy_ipset_session(void* session) {
    if (NGX_UNLIKELY(!session)) {
        return;
    }
    ipset_session_fini(session);
}

static ngx_ipset_test_result_t ngx_test_ip_is_in_set(
    ngx_ipset_session_t* session,
    char const* set,
    char const* ip) {
    int ret;
    const struct ipset_type* type;

    ret = ipset_parse_setname(session, IPSET_SETNAME, set);
    if (NGX_UNLIKELY(ret < 0)) {
        return IPS_TEST_INVALID_SETNAME;
    }

    type = ipset_type_get(session, IPSET_CMD_TEST);
    if (!type) {
        return IPS_TEST_FAIL;
    }

    /* ipset_parse_elem auto-detects the address family (IPv4 vs IPv6)
     * from the textual representation of "ip", so the very same code
     * path works transparently for both hash:ip/hash:net sets created
     * with "family inet" and with "family inet6". */
    ret = ipset_parse_elem(session, type->last_elem_optional, ip);
    if (NGX_UNLIKELY(ret < 0)) {
        return IPS_TEST_INVALID_IP;
    }

    ret = ipset_cmd(session, IPSET_CMD_TEST, 0);
    if (ret < 0) {
        return IPS_TEST_IS_NOT_IN_SET;
    }

    return IPS_TEST_IS_IN_SET;
}

/********************************************************************/

/** IPSET session caching *******************************************
 * In order to minimize overhead of the application we will cache IPSET
 * sessions in per thread storage.
 ********************************************************************/
static pthread_key_t ngx_ipset_cache_key;
static int ngx_ipset_cache_initialize_result = 0;
static pthread_once_t ngx_ipset_cache_initialize_once = PTHREAD_ONCE_INIT;

static void ngx_ipset_cache_initializer() {
    ngx_ipset_cache_initialize_result = ngx_initialize_ipset();
    if (ngx_ipset_cache_initialize_result) {
        return;
    }

    if (pthread_key_create(&ngx_ipset_cache_key, ngx_destroy_ipset_session)) {
        ngx_ipset_cache_initialize_result = ngx_errno;
    }
}

static int ngx_initialize_ipset_cache() {
    pthread_once(&ngx_ipset_cache_initialize_once, &ngx_ipset_cache_initializer);
    return ngx_ipset_cache_initialize_result;
}

static ngx_ipset_session_t* ngx_get_session() {
    ngx_ipset_session_t* session;
    int ret = ngx_initialize_ipset_cache();
    if (NGX_UNLIKELY(ret)) {
        ngx_set_errno(ret);
        return NULL;
    }

    session = pthread_getspecific(ngx_ipset_cache_key);
    if (NGX_LIKELY(session)) {
        return session;
    }

    session = ngx_create_ipset_session();
    if (NGX_UNLIKELY(!session)) {
        return NULL;
    }

    pthread_setspecific(ngx_ipset_cache_key, session);
    return session;
}

/********************************************************************/

/** Configuration ***************************************************
 * This struct is used both as the module's server-level and
 * location-level configuration (create_loc_conf/merge_loc_conf), the
 * same way ngx_http_access_module does it, so that "blacklist"/
 * "whitelist" can appear in http{}, server{} and location{} and be
 * correctly inherited down the configuration tree.
 ********************************************************************/
typedef struct ngx_ipset_command_conf_s {
    enum {
        e_mode_not_configured = 0,
        e_mode_off,
        e_mode_blacklist,
        e_mode_whitelist
    } mode;
    ngx_array_t sets;
} ngx_ipset_access_loc_conf_t;

static int ngx_str_copy(ngx_pool_t* pool, ngx_str_t* dst, ngx_str_t const* src) {
    if (NGX_UNLIKELY(dst->len >= src->len)) {
        memcpy(dst->data, src->data, src->len);
        dst->len = src->len;
        return 0;
    } else {
        if (NGX_UNLIKELY(dst->data)) {
            ngx_pfree(pool, dst->data);
        }

        dst->data = ngx_pcalloc(pool, src->len + 1);
        if (!dst->data) {
            dst->len = 0;
            return ENOMEM;
        }

        memcpy(dst->data, src->data, src->len);
        dst->data[src->len] = 0;
        dst->len = src->len;
        return 0;
    }
}

static int ngx_str_array_copy(ngx_pool_t* pool, ngx_array_t* dst, ngx_array_t const* src, ngx_uint_t si) {
    ngx_uint_t i;
    ngx_str_t* dst_values;
    ngx_str_t const* src_values;

    dst_values = ngx_array_push_n(dst, src->nelts - si);
    if (!dst_values) {
        return ENOMEM;
    }

    src_values = ((ngx_str_t*)src->elts) + si;
    for (i = si; i < src->nelts; i++) {
        int ret = ngx_str_copy(pool, dst_values++, src_values++);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

#ifdef NGX_DEBUG
static char* ngx_str_array_to_str(char* buffer, size_t len, ngx_array_t const* array) {
    char* b = buffer;
    char* e = buffer + len - 2;

    if (!array->pool) {
        strcpy(buffer, "INVALID_ARRAY");
        return buffer;
    }

    *b++ = '[';
    if (!array->nelts) {
        *b++ = ']';
        *b++ = 0;
    } else {
        ngx_uint_t i;
        bool more = false;
        ngx_str_t* value = array->elts;

        for (i = 0; i < array->nelts; i++) {
            size_t cp = value->len;
            if (i) {
                *b++ = ',';
            }

            if (cp > (size_t)(e - b)) {
                cp = e - b;
                more = true;
            }

            memcpy(b, value->data, cp);
            b += value->len;

            if (more) {
                break;
            }
            ++value;
        }

        if (more) {
            memcpy(e - 3, "...]", 5);
        } else {
            *b++ = ']';
            *b++ = 0;
        }
    }

    return buffer;
}
#endif

static void* ngx_ipset_access_loc_conf_create(ngx_conf_t *cf) {
    ngx_ipset_access_loc_conf_t* conf = ngx_pcalloc(cf->pool, sizeof(ngx_ipset_access_loc_conf_t));
    if (conf) {
        if (ngx_array_init(&conf->sets, cf->pool, 0, sizeof(ngx_str_t))) {
            // error in allocating buffer
            ngx_log_error(NGX_LOG_ERR, cf->log, ENOMEM, "Failed to allocate array");
            ngx_pfree(cf->pool, conf);
            return NULL;
        }
    }
    return conf;
}

static char* ngx_ipset_access_loc_conf_merge(ngx_conf_t* cf, void* parent, void* child) {
    ngx_ipset_access_loc_conf_t* prev = parent;
    ngx_ipset_access_loc_conf_t* conf = child;

#ifdef NGX_DEBUG
    char temp[512];
    ngx_log_debug4(NGX_LOG_INFO, cf->log, 0,
        "Merging configuration(parent: { mode: %d, sets: %s }, child: { mode: %d, sets: %s })",
        prev->mode, ngx_str_array_to_str(temp, sizeof(temp) / 2, &prev->sets),
        conf->mode, ngx_str_array_to_str(temp + sizeof(temp) / 2, sizeof(temp) / 2, &conf->sets));
#endif

    if (conf->mode == e_mode_not_configured) {
        // configuration is not configured here, so lets copy it from the parent
        conf->mode = prev->mode;
        if (prev->sets.nelts) {
            if (ngx_str_array_copy(cf->pool, &conf->sets, &prev->sets, 0)) {
                return (char*)NGX_ERROR;
            }
        }
    }

#ifdef NGX_DEBUG
    ngx_log_debug2(NGX_LOG_INFO, cf->log, 0,
        "Merging configuration(return: { mode: %d, sets: %s })",
        conf->mode, ngx_str_array_to_str(temp, sizeof(temp), &conf->sets));
#endif

    return NGX_OK;
}

static char* ngx_ipset_access_loc_conf_parse(ngx_conf_t* cf, ngx_command_t* command, void* pv_conf) {
    ngx_uint_t i;
    ngx_str_t* value;
    ngx_ipset_session_t* session;
    ngx_str_t* args = cf->args->elts;
    ngx_ipset_access_loc_conf_t* conf = pv_conf;

#ifdef NGX_DEBUG
    char buffer[129];
    ngx_log_debug1(NGX_LOG_INFO, cf->log, 0, "Parsing config(args: %s)",
        ngx_str_array_to_str(buffer, 129, cf->args));
#endif

    // first arg is name of the command, and rest of them are values for that command
    if (args[1].len == 3 && memcmp(args[1].data, "off", 3) == 0) {
#ifdef NGX_DEBUG
        ngx_log_debug2(NGX_LOG_INFO, cf->log, 0, "Parse result(mode: %d, sets: %s)",
            conf->mode, ngx_str_array_to_str(buffer, 129, &conf->sets));
#endif
        conf->mode = e_mode_off;
        return NGX_OK;
    }

    if (ngx_str_array_copy(cf->pool, &conf->sets, cf->args, 1)) {
#ifdef NGX_DEBUG
        ngx_log_debug0(NGX_LOG_INFO, cf->log, ENOMEM, "Failed to copy arg values");
#endif
        return (char*)NGX_ERROR;
    }

    conf->mode = args[0].data[0] == 'b' ? e_mode_blacklist : e_mode_whitelist;

#ifdef NGX_DEBUG
    ngx_log_debug2(NGX_LOG_INFO, cf->log, 0, "Parse result(mode: %d, sets: %s)",
        conf->mode, ngx_str_array_to_str(buffer, 129, &conf->sets));
#endif

    // test input sets, both for IPv4 and IPv6, so that mistakes (e.g. a
    // typo in the set name, or an inet6 set with an inet-only pattern)
    // are caught at configuration time instead of at request time.
    value = conf->sets.elts;
    session = ngx_get_session();
    if (!session) {
        // failed to create session
#ifdef NGX_DEBUG
        ngx_log_debug0(NGX_LOG_INFO, cf->log, EINVAL, "Failed to load IPSET session");
#endif
        return (char*)NGX_ERROR;
    }

    for (i = 0; i < conf->sets.nelts; i++, value++) {
        ngx_ipset_test_result_t result = ngx_test_ip_is_in_set(session, (const char*)value->data, "127.0.0.1");
        if (result == IPS_TEST_FAIL || result == IPS_TEST_INVALID_SETNAME) {
            // error in testing IP in set
#ifdef NGX_DEBUG
            ngx_log_debug1(NGX_LOG_INFO, cf->log, EINVAL, "error in testing IP in set(%s)", value->data);
#endif
            return (char*)NGX_ERROR;
        } else {
#ifdef NGX_DEBUG
            ngx_log_debug4(NGX_LOG_INFO, cf->log, 0, "ngx_test_ip_is_in_set(%p, %s, %s) -> %d",
                session, (const char*)value->data, "127.0.0.1", result);
#endif
        }
    }

    return NGX_OK;
}

/********************************************************************/

/** Forward declarations ********************************************/
static ngx_int_t ngx_ipset_access_http_access_handler(ngx_http_request_t* request);

/********************************************************************/

/** NGINX HTTP module ***********************************************/
#define IPSET_ACCESS_COMMAND(name) { \
    /* name */   ngx_string(name), \
    /*** configurable in main config, virtual server and location ***/ \
    /*** we require at least one set, but we support more than one ***/ \
    /* type */   NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE, \
    /* set */    ngx_ipset_access_loc_conf_parse, \
    /* conf */   NGX_HTTP_LOC_CONF_OFFSET, \
    /* offset */ 0, \
    /* post */   NULL \
}

static ngx_command_t ngx_http_ipset_access_commands[] = {
    IPSET_ACCESS_COMMAND("blacklist"),
    IPSET_ACCESS_COMMAND("whitelist"),
    ngx_null_command
};

#define checked_array_push(arr, elem) { h = ngx_array_push(&arr); if (h == NULL){ return NGX_ERROR;} *h = elem; }

static ngx_int_t ngx_ipset_access_install_handlers(ngx_conf_t *cf) {
    ngx_http_handler_pt* h;
    ngx_http_core_main_conf_t* cmcf;

#ifdef NGX_DEBUG
    ngx_log_debug0(NGX_LOG_NOTICE, cf->log, 0, "Installing filter handler");
#endif

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    checked_array_push(cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers, ngx_ipset_access_http_access_handler);

    return NGX_OK;
}

static ngx_int_t ngx_ipset_access_on_init_process(ngx_cycle_t *cycle) {
#ifdef NGX_DEBUG
    ngx_log_debug0(NGX_LOG_NOTICE, cycle->log, 0, "module init_process called");
#endif
    return NGX_OK;
}

static ngx_http_module_t ngx_http_ipset_access_module_context = {
    NULL,                                  /* preconfiguration */

    ngx_ipset_access_install_handlers,     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* merge main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_ipset_access_loc_conf_create,      /* create location configuration */
    ngx_ipset_access_loc_conf_merge        /* merge location configuration */
};

ngx_module_t ngx_http_ipset_access = {
    NGX_MODULE_V1,
    &ngx_http_ipset_access_module_context, /* module context */
    ngx_http_ipset_access_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_ipset_access_on_init_process,      /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/********************************************************************/

/** implementations *************************************************/

/** Copy the textual client address out of c->addr_text into a local,
 * NUL-terminated buffer that can be handed to libipset.
 *
 * c->addr_text is filled in by nginx for every accepted connection
 * (via ngx_sock_ntop()) regardless of address family, which makes it
 * the right source of truth for both IPv4 and IPv6 -- unlike
 * inet_ntoa(), which only understands struct sockaddr_in and would
 * simply be wrong (or crash) for AF_INET6 connections.
 *
 * IPv4-mapped IPv6 addresses (::ffff:a.b.c.d), which show up when a
 * dual-stack "listen [::]:80;" socket accepts an IPv4 client, are
 * normalized to plain IPv4 dotted notation so that they still match
 * against IPv4-only ipsets.
 *
 * \return NGX_OK and fills *out on success, NGX_ERROR otherwise. */
static ngx_int_t ngx_ipset_access_get_client_ip(
    ngx_http_request_t* r, u_char* buf, size_t buf_size, ngx_str_t* out) {
    ngx_connection_t* c = r->connection;
    ngx_str_t* addr_text = &c->addr_text;
    u_char* data = addr_text->data;
    size_t len = addr_text->len;

    if (NGX_UNLIKELY(len == 0 || len >= buf_size)) {
        return NGX_ERROR;
    }

    if (len > 7 && ngx_strncmp(data, "::ffff:", 7) == 0) {
        data += 7;
        len -= 7;
    }

    ngx_memcpy(buf, data, len);
    buf[len] = '\0';

    out->data = buf;
    out->len = len;

    return NGX_OK;
}

static ngx_int_t ngx_ipset_access_http_access_handler(ngx_http_request_t* request) {
    ngx_ipset_access_loc_conf_t *conf = ngx_http_get_module_loc_conf(request, ngx_http_ipset_access);

#ifdef NGX_DEBUG
    char temp[129];
    ngx_log_debug5(NGX_LOG_NOTICE, request->connection->log, 0,
        "Access handler(mode: %d, sets: %s): {connection: %p, sockaddr: %p, family: %d}",
        conf->mode, ngx_str_array_to_str(temp, sizeof(temp), &conf->sets),
        request->connection, request->connection ? request->connection->sockaddr : NULL,
        (request->connection && request->connection->sockaddr) ? request->connection->sockaddr->sa_family : -1);
#endif

    if ((conf->mode == e_mode_whitelist || conf->mode == e_mode_blacklist) &&
        (request->connection->sockaddr->sa_family == AF_INET ||
         request->connection->sockaddr->sa_family == AF_INET6)) {
        u_char ip_buf[NGX_INET6_ADDRSTRLEN + 1];
        ngx_str_t ip;
        ngx_ipset_session_t* session;
        ngx_ipset_test_result_t result = 0;

        if (NGX_UNLIKELY(ngx_ipset_access_get_client_ip(request, ip_buf, sizeof(ip_buf), &ip) != NGX_OK)) {
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                "ipset_access: failed to obtain a textual client address");
            return NGX_DECLINED;
        }

#ifdef NGX_DEBUG
        ngx_log_debug1(NGX_LOG_INFO, request->connection->log, 0, "testing '%V' in IPSET for permission", &ip);
#endif

        session = ngx_get_session();
        if (!session) {
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0, "failed to load an IPSET session");
            result = IPS_TEST_FAIL;
        } else {
            ngx_uint_t i;
            ngx_str_t* set = conf->sets.elts;
            for (i = 0; i < conf->sets.nelts; i++, set++) {
                result = ngx_test_ip_is_in_set(session, (char*)set->data, (char*)ip.data);
                if (result != IPS_TEST_IS_NOT_IN_SET) {
#ifdef NGX_DEBUG
                    ngx_log_debug3(NGX_LOG_DEBUG, request->connection->log, 0, "test %s %V -> %d", set->data, &ip, result);
#endif
                    if (result == IPS_TEST_FAIL) {
                        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0, "Failed to test presence of IP in IPSET.");
                    }
                    break;
                }
            }
        }

        if ((conf->mode == e_mode_whitelist && (result != IPS_TEST_IS_NOT_IN_SET)) ||
            (conf->mode == e_mode_blacklist && (result == IPS_TEST_IS_IN_SET))) {
            request->keepalive = 0;
            ngx_log_error(NGX_LOG_EMERG, request->connection->log, 0, "Blocking %V due to IPSET", &ip);

            /* Close the connection without sending a response, instead of
             * the previous HTTP 403, so that scanners/attackers get no
             * information at all about why (or that) they were blocked. */
            return NGX_HTTP_CLOSE;
        }

        return NGX_OK;
    }

    return NGX_DECLINED;
}

/********************************************************************/
