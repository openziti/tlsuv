#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tlsuv/http.h>

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
                char *pos = strchr(p, '/');
                if (pos != NULL) {
                    size_t index = pos - p;
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

    if (strchr(p, '@') != NULL) {
        url->username = p;
        sscanf(p, "%*[^:@]%n", &count);
        url->username_len = count;
        p += count;
        if (*p == ':') {
            p++;
            url->password = p;
            sscanf(p, "%*[^@]%n", &count);
            url->password_len = count;
            p += count;
        }
        p++;
    }

    count = 0;
    if (sscanf(p, "%*[^:/]%n", &count) == 0 && count > 0) {
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
