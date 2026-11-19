#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include <tlsuv/http.h>

#include "util.h"

// `s` is an IPv6 address, without the brackets and without a zone id.
static bool is_ipv6_literal(const char *s, size_t len) {
    char buf[46]; // INET6_ADDRSTRLEN: the longest address, with an embedded IPv4 part, and '\0'
    unsigned char addr[16];
    if (len >= sizeof(buf))
        return false;
    memcpy(buf, s, len);
    buf[len] = '\0';
    return uv_inet_pton(AF_INET6, buf, addr) == 0;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t tlsuv__url_decode(char *s, size_t len) {
    size_t out = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '%' && i + 2 < len) {
            int hi = hex_value(s[i + 1]);
            int lo = hex_value(s[i + 2]);
            bool is_nul = hi == 0 && lo == 0; // "%00" would cut the text short, it is left as is
            if (hi >= 0 && lo >= 0 && !is_nul) {
                c = (char) (hi << 4 | lo);
                i += 2;
            }
        }
        s[out++] = c;
    }
    s[out] = '\0';
    return out;
}

int tlsuv_parse_url(struct tlsuv_url_s *url, const char *urlstr) {
    memset(url, 0, sizeof(struct tlsuv_url_s));

    const char *p = urlstr;

    int file_prefix_len = strlen("file:/");
    // special handling for file:/, file://, file://host/, file:///
    if (strncmp(urlstr, "file:/", file_prefix_len) == 0) {
        url->scheme = p;
        url->scheme_len = 4; // strlen("file")
        p += file_prefix_len;

        if (p[0] == '/') {
            p++;
            if (p[0] == '/') {
                // file:/// means empty hostname
                p++;
            } else {
                // file://path means there must be a hostname. find the next slash
                const char *pos = strchr(p, '/');
                if (pos != NULL) {
                    const size_t index = pos - p;
                    url->hostname = p;
                    url->hostname_len = index;
                    p += index + 1;
                } else {
                    // poorly formatted entry. this would be just `file://` or `file://hostnameonly`
                    url->hostname = p;
                    url->hostname_len = strlen(p);
                    return -1;
                }
            }
        } else {
            // one slash - else empty on purpose to indicate this is expected to be no-op
        }

#ifdef _WIN32
        if (strlen(p) > 0 && p[1] == ':') {
            // expect a windows path to have a drive letter c:, d:, etc.
        } else {
            // if no ':' in position 2, back up to pickup the leading slash
            p--;
        }
#else
        p--; // on non-windows, always backup to pick up the leading slash
#endif
        url->path = p;
        url->path_len = strlen(p);
        return 0;
    }

    int count = 0;
    int rc = sscanf(p, "%*[^:]%n://", &count);
    if (rc == 0 &&
        (p + count)[0] == ':' && (p + count)[1] == '/' && (p + count)[2] == '/'
            ) {
        url->scheme = p;
        url->scheme_len = count;
        p += (count + 3);
    }

    // userinfo is only in the authority, which ends at the first '/', '?' or '#':
    // an '@' after it is part of the path or the query
    if (memchr(p, '@', strcspn(p, "/?#")) != NULL) {
        url->username = p;
        count = (int) strcspn(p, ":@");
        url->username_len = count;
        p += count;
        if (*p == ':') {
            p++;
            url->password = p;
            count = (int) strcspn(p, "@");
            url->password_len = count;
            p += count;
        }
        p++;
    }

    count = 0;
    if (*p == '[') {
        // bracketed IPv6 literal: the hostname is what is inside the brackets
        size_t len = strcspn(p + 1, "]/");
        if (p[1 + len] != ']')
            return -1;
        // A zone id (`[fe80::1%25eth0]`) is ignored: it is cut off the hostname, which stays the
        // address alone. The resolver cannot use it percent-encoded, and a Host header cannot carry it.
        size_t addr_len = len;
        const char *zone = memchr(p + 1, '%', len);
        if (zone != NULL) {
            addr_len = zone - (p + 1);
            if (addr_len + 1 == len) // nothing after the '%'
                return -1;
        }
        if (!is_ipv6_literal(p + 1, addr_len))
            return -1;
        url->hostname = p + 1;
        url->hostname_len = addr_len;
        p += len + 2;
        if (*p != '\0' && *p != ':' && *p != '/')
            return -1;
    } else if (sscanf(p, "%*[^:/]%n", &count) == 0 && count > 0) {
        url->hostname = p;
        url->hostname_len = count;
        p += count;
    }

    if (*p == ':') {
        if (url->hostname == NULL)
            return -1;
        p += 1;
        char *pend;
        long lport = strtol(p, &pend, 10);

        if (pend == p)
            return -1;

        if (lport > 0 && lport <= UINT16_MAX) {
            url->port = (uint16_t) lport;
            p = pend;
        } else {
            return -1;
        }
    }

    if (*p == '\0')
        return 0;

    if (*p != '/') {
        return -1;
    }

    if (sscanf(p, "%*[^?]%n", &count) == 0) {
        url->path = p;
        url->path_len = count;
        p += count;
    }

    if (*p == '?') {
        url->query = p + 1;
        url->query_len = strlen(url->query);
    }

    return 0;
}
