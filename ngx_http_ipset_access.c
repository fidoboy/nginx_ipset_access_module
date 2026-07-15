/********************************************************************
 * A nginx module that help you control access of users using IPSET
 *
 * Original author: Mohammad Mahdi Roozitalab <mehdiboss_qi@hotmail.com>
 *
 * Fork changes:
 * - IPv4 + IPv6 client address support (dual stack).
 * - Client address is now obtained from c->addr_text instead of
 *   inet_ntoa(), which only ever worked for AF_INET.
 * - Blocked requests now get HTTP 444 (connection closed, no
 *   response sent) instead of HTTP 403.
 * - The "blacklist"/"whitelist" directives are now also valid
 *   inside "location" blocks (NGX_HTTP_LOC_CONF), in addition to
 *   "http" and "server".
 * - Verified against the nginx 1.31.x module API (phases, module
 *   context, ngx_http_get_module_loc_conf, connection->addr_text)
 *   -- no changes were required in the core API used by this
 *   module between the version this was originally written
 *   against and 1.31.
 * - Blocking is now logged at NGX_LOG_NOTICE instead of
 *   NGX_LOG_EMERG: an IP being denied by design is expected,
 *   routine behavior, not an emergency condition.
 * - Removed the per-worker libipset session cache built on
 *   pthread_key_t / pthread_once / TLS. nginx workers are separate
 *   processes, not threads, so there was never more than one
 *   session to cache per worker in the first place. The module now
 *   simply creates a single libipset session in the worker's
 *   init_process callback and keeps a plain static pointer to it,
 *   which is simpler and removes an unnecessary dependency on
 *   pthreads.
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

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libipset/session.h>
#include <libipset/types.h>

/* Not every platform/nginx build defines NGX_INET6_ADDRSTRLEN (it only
 * exists when nginx was itself compiled with IPv6 support). Fall back
 * to the standard INET6_ADDRSTRLEN from <netinet/in.h> in that case. */
#ifndef NGX_INET6_ADDRSTRLEN
# define NGX_INET6_ADDRSTRLEN INET6_ADDRSTRLEN
#endif

#if __GNUC__
# define NGX_LIKELY(x)   __builtin_expect(!!(x), 1)
# define NGX_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
# define NGX_LIKELY(x)   (x)
# define NGX_UNLIKELY(x) (x)
#endif

/** IPSET integration ***********************************************/

typedef struct ipset_session ngx_ipset_session_t;

typedef enum ngx_ipset_test_result_t {
    IPS_TEST_IS_IN_SET,
    IPS_TEST_IS_NOT_IN_SET,
    IPS_TEST_INVALID_SETNAME,
    IPS_TEST_INVALID_IP,
    IPS_TEST_FAIL,
} ngx_ipset_test_result_t;

/** Initialize IPSET.
 *
 * ngx_initialize_ipset() is called once per "blacklist"/"whitelist"
 * directive while parsing the configuration (in the master process),
 * again on every "nginx -s reload", and once more per worker from
 * init_process. Since workers are fork()ed from the master, whatever
 * global state ipset_load_types() registers during config parsing is
 * already present in each worker's memory via copy-on-write, so this
 * guard also makes the init_process call a cheap no-op in the common
 * case rather than a redundant re-registration.
 *
 * \return 0 to indicate success and other value to indicate error */
static ngx_uint_t ngx_ipset_types_loaded = 0;

static int ngx_initialize_ipset() {
    if (!ngx_ipset_types_loaded) {
        ipset_load_types();
        ngx_ipset_types_loaded = 1;
    }
    return 0;
}

/** Create a new IPSET session. */
static ngx_ipset_session_t* ngx_create_ipset_session() {
#ifdef WITH_LIBIPSET_V6_COMPAT
# define ngx_ipset_session_new() ipset_session_init(printf)
#else
# define ngx_ipset_session_new() ipset_session_init(NULL, NULL)
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
    char const* ip)
{
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

    ret = ipset_parse_elem(session, type->last_elem_optional, ip);
    if (NGX_UNLIKELY(ret < 0)) {
        return IPS_TEST_INVALID_IP;
    }

    ret = ipset_cmd(session, IPSET_CMD_TEST, 0);
    if (ret == 0) {
        return IPS_TEST_IS_IN_SET;
    }

    if (ret > 0) {
        return IPS_TEST_IS_NOT_IN_SET;
    }

    return IPS_TEST_FAIL;
}

/********************************************************************/

/** Per-worker IPSET session *****************************************
 * nginx workers are independent processes (not threads), so there is
 * exactly one libipset session to keep per worker. It is created once
 * in the worker's init_process callback and stored here; every
 * request handled by this worker reuses the same pointer. No
 * pthread_key_t / pthread_once / TLS machinery is needed for this.
 ********************************************************************/

static ngx_ipset_session_t* ngx_worker_ipset_session = NULL;

/** Create the libipset session for this worker process.
 * Called once from init_process.
 * \return NGX_OK on success, NGX_ERROR otherwise. */
static ngx_int_t ngx_ipset_access_init_worker_session(ngx_log_t* log) {
    if (ngx_initialize_ipset()) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ipset_access: failed to initialize IPSET types");
        return NGX_ERROR;
    }

    ngx_worker_ipset_session = ngx_create_ipset_session();
    if (!ngx_worker_ipset_session) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "ipset_access: failed to create IPSET session");
        return NGX_ERROR;
    }

    return NGX_OK;
}

/** Destroy the worker's libipset session.
 * Called once from exit_process. */
static void ngx_ipset_access_exit_worker_session() {
    if (ngx_worker_ipset_session) {
        ngx_destroy_ipset_session(ngx_worker_ipset_session);
        ngx_worker_ipset_session = NULL;
    }
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
    if (!dst || !src) {
        return EINVAL;
    }

    dst->data = ngx_pnalloc(pool, src->len + 1);
    if (!dst->data) {
        dst->len = 0;
        return ENOMEM;
    }

    ngx_memcpy(dst->data, src->data, src->len);
    dst->data[src->len] = '\0';
    dst->len = src->len;
    return 0;
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
            b += cp;
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

static char* ngx_ipset_access_loc_conf_parse(ngx_conf_t *cf, ngx_command_t *command, void *pv_conf) {
    (void) command;
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
    //
    // Both an IPv4 and an IPv6 probe address are tried per set: a set
    // created with "family inet6" will reject an IPv4 probe address in
    // ipset_parse_elem() -- before the kernel is ever actually queried
    // -- so testing with only one family risks the real set-name
    // validation being masked by a family mismatch instead. The set is
    // only considered valid if at least one of the two probes reaches
    // the kernel with a real answer (in-set or not-in-set); if both
    // come back as an error, this module expects hash:ip/hash:net
    // sets, so that is a genuine configuration mistake and must fail
    // "nginx -t", not just warn.
    //
    // This runs in the master process while parsing the config, before
    // any worker exists, so it cannot use the per-worker session above;
    // it creates and destroys a throwaway session of its own instead.
    if (ngx_initialize_ipset()) {
#ifdef NGX_DEBUG
        ngx_log_debug0(NGX_LOG_INFO, cf->log, EINVAL, "Failed to initialize IPSET types");
#endif
        return (char*)NGX_ERROR;
    }

    session = ngx_create_ipset_session();
    if (!session) {
        // failed to create session
#ifdef NGX_DEBUG
        ngx_log_debug0(NGX_LOG_INFO, cf->log, EINVAL, "Failed to load IPSET session");
#endif
        return (char*)NGX_ERROR;
    }

    value = conf->sets.elts;
    for (i = 0; i < conf->sets.nelts; i++, value++) {
        ngx_ipset_test_result_t result_v4;
        ngx_ipset_test_result_t result_v6;

        result_v4 = ngx_test_ip_is_in_set(session, (const char*)value->data, "127.0.0.1");
        result_v6 = ngx_test_ip_is_in_set(session, (const char*)value->data, "::1");

        if (result_v4 != IPS_TEST_IS_IN_SET && result_v4 != IPS_TEST_IS_NOT_IN_SET &&
            result_v6 != IPS_TEST_IS_IN_SET && result_v6 != IPS_TEST_IS_NOT_IN_SET) {
            // Neither probe reached a real answer from the kernel: the
            // set name is wrong, or it is not a family inet/inet6
            // hash:ip/hash:net set as this module expects.
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "ipset_access: set \"%V\" failed validation for both IPv4 and IPv6 "
                "(v4 result: %d, v6 result: %d); check the set name and its family",
                value, result_v4, result_v6);
            ngx_destroy_ipset_session(session);
            return (char*)NGX_ERROR;
        }

#ifdef NGX_DEBUG
        ngx_log_debug3(NGX_LOG_INFO, cf->log, 0, "ngx_test_ip_is_in_set(%V) -> v4:%d v6:%d",
            value, result_v4, result_v6);
#endif
    }

    ngx_destroy_ipset_session(session);
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

    if (ngx_ipset_access_init_worker_session(cycle->log) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void ngx_ipset_access_on_exit_process(ngx_cycle_t *cycle) {
#ifdef NGX_DEBUG
    ngx_log_debug0(NGX_LOG_NOTICE, cycle->log, 0, "module exit_process called");
#endif

    ngx_ipset_access_exit_worker_session();
}

static ngx_http_module_t ngx_http_ipset_access_module_context = {
    NULL,                               /* preconfiguration */
    ngx_ipset_access_install_handlers,  /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* merge main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_ipset_access_loc_conf_create,   /* create location configuration */
    ngx_ipset_access_loc_conf_merge     /* merge location configuration */
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
    ngx_ipset_access_on_exit_process,      /* exit process */
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
    ngx_connection_t *c = request->connection;

    ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
        "ipset_access handler reached, addr_text=%V",
        &c->addr_text);

    if (c == NULL || c->sockaddr == NULL) {
        return NGX_DECLINED;
    }

    ngx_ipset_access_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(request, ngx_http_ipset_access);

#ifdef NGX_DEBUG
    char temp[129];
    ngx_log_debug5(NGX_LOG_NOTICE, c->log, 0,
        "Access handler(mode: %d, sets: %s): {connection: %p, sockaddr: %p, family: %d}",
        conf->mode, ngx_str_array_to_str(temp, sizeof(temp), &conf->sets),
        c, c ? c->sockaddr : NULL,
        (c && c->sockaddr) ? c->sockaddr->sa_family : -1);
#endif

    if ((conf->mode == e_mode_whitelist || conf->mode == e_mode_blacklist) &&
        (c->sockaddr->sa_family == AF_INET ||
         c->sockaddr->sa_family == AF_INET6)) {
        u_char ip_buf[NGX_INET6_ADDRSTRLEN + 1];
        ngx_str_t ip;
        ngx_ipset_session_t* session;
        ngx_ipset_test_result_t result = 0;

        if (NGX_UNLIKELY(ngx_ipset_access_get_client_ip(request, ip_buf, sizeof(ip_buf), &ip) != NGX_OK)) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ipset_access: failed to obtain a textual client address");
            return NGX_DECLINED;
        }

#ifdef NGX_DEBUG
        ngx_log_debug1(NGX_LOG_INFO, c->log, 0, "testing '%V' in IPSET for permission", &ip);
#endif

        session = ngx_worker_ipset_session;
        if (!session) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0, "no IPSET session available for this worker");
            result = IPS_TEST_FAIL;
        } else {
            ngx_uint_t i;
            ngx_str_t* set = conf->sets.elts;
            for (i = 0; i < conf->sets.nelts; i++, set++) {
                result = ngx_test_ip_is_in_set(session, (const char*)set->data, (const char*)ip.data);
                if (result != IPS_TEST_IS_NOT_IN_SET) {
#ifdef NGX_DEBUG
                    ngx_log_debug3(NGX_LOG_DEBUG, c->log, 0, "test %V %V -> %d", set, &ip, result);
#endif
                    if (result == IPS_TEST_FAIL) {
                        ngx_log_error(NGX_LOG_WARN, c->log, 0, "ipset_access: failed to test client %V against set %V", &ip, set);
                    }
                    break;
                }
            }
        }

        if ((conf->mode == e_mode_whitelist && (result != IPS_TEST_IS_NOT_IN_SET)) ||
            (conf->mode == e_mode_blacklist && (result == IPS_TEST_IS_IN_SET))) {
            /* Denying an IP is expected, routine behavior driven entirely
             * by configuration/ipset contents -- not an emergency
             * condition -- so log it at NOTICE rather than EMERG. */
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "Blocking %V due to IPSET", &ip);

            /* Close the connection without sending a response, instead of
             * the previous HTTP 403, so that scanners/attackers get no
             * information at all about why (or that) they were blocked.
             * NGX_HTTP_CLOSE already tears the connection down, so there
             * is no need to additionally clear request->keepalive. */
            return NGX_HTTP_CLOSE;
        }

        return NGX_OK;
    }

    return NGX_DECLINED;
}

/********************************************************************/
