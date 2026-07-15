# ngx_http_ipset_access (fork)

Fork of [mehdi-roozitalab/nginx_ipset_access_module](https://github.com/mehdi-roozitalab/nginx_ipset_access_module),
an nginx module that controls access using Netfilter `ipset` sets
(dynamic blacklists/whitelists without reloading nginx).

## Changes from the original

- **IPv6 support.** The request handler no longer ignores connections
  whose `sa_family` is `AF_INET6`; they are now processed exactly like
  `AF_INET` connections. Simply create the corresponding `ipset` with
  `family inet6` and reference it from `blacklist`/`whitelist` just like
  an IPv4 set (IPv4 and IPv6 sets can be mixed within the same
  directive).
- **HTTP 444 instead of 403.** Previously, blocked requests returned
  `403 Forbidden` (despite the source code containing an unused
  `//return 444;` comment). The module now always returns
  `NGX_HTTP_CLOSE` (444), causing nginx to close the connection without
  sending any response instead of explicitly informing the client that
  access was denied.
- **Verified compatibility with the nginx 1.31.x API.** The module
  continues to use the same HTTP phase mechanism
  (`NGX_HTTP_PREACCESS_PHASE`), the same HTTP module context, and the
  same configuration helpers
  (`ngx_http_get_module_loc_conf`,
  `ngx_http_conf_get_module_main_conf`, etc.), whose ABI/API has
  remained compatible between the nginx version the module was
  originally written for and nginx 1.31.x.

## Migration notes

- If you were already using this module with IPv4 `ipset`s, no changes
  are required. Behavior remains identical for `family inet` sets,
  except that blocked requests now return HTTP 444 instead of 403.
- If you relied on HTTP 403 for any purpose (for example, a custom
  `error_page 403 ...`), it will no longer be triggered for requests
  blocked by this module, since HTTP 444 closes the connection without
  generating a response.
- `ipset`s must be created using the appropriate address family:

  ```
  sudo ipset create blacklist4 hash:ip family inet
  sudo ipset create blacklist6 hash:ip family inet6
  ```

  Both can then be referenced in the same directive:

  ```
  blacklist blacklist4 blacklist6;
  ```

## Installation

Same as the original project:

```
./configure --add-module=/path/to/nginx_ipset_access_module
```

or as a dynamic module:

```
./configure --add-dynamic-module=/path/to/nginx_ipset_access_module --with-compat
```

Requires `libipset` (`-lipset`) and the
`libipset/linux_ip_set.h` header at build time, as well as
`CAP_NET_ADMIN` (or root privileges) at runtime so nginx workers can
query kernel `ipset`s.

See `nginx.conf.example` for a complete IPv4/IPv6 example, including
usage inside `location` blocks.

## Known limitations

- This fork does not introduce a directive to configure the HTTP status
  code; it is fixed at 444. If configurable status codes are required
  (403, 429, etc.), a new directive such as `ipset_status` would need to
  be added.
- Support for `realip`/`X-Forwarded-For` has not been modified. The
  module still uses the TCP connection address
  (`connection->addr_text`), not the original client IP behind a proxy.
  If you need that behavior, combine this module with
  `ngx_http_realip_module`, which rewrites `connection->sockaddr` and
  `connection->addr_text` before the `PREACCESS` phase is executed.
