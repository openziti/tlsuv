// Copyright (c) NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string.h>
#include <tlsuv/tls_engine.h>
#include "um_debug.h"


typedef int (*tls_configure)(void);

#define TLS_FACTORY_NAME(impl) new_## impl ## _ctx
#define TLS_FACTORY(impl) TLS_FACTORY_NAME(impl)

#define TLS_CONFIGURE_NAME(impl) configure_## impl
#define TLS_CONFIGURE(impl) TLS_CONFIGURE_NAME(impl)

extern tls_context* TLS_FACTORY(TLS_IMPL)(const char* ca, size_t ca_len);
extern int TLS_CONFIGURE(TLS_IMPL)();

static tls_configure configure_tls = TLS_CONFIGURE(TLS_IMPL);
static tls_context_factory factory = TLS_FACTORY(TLS_IMPL);

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

void set_default_tls_impl(tls_context_factory f) {
    factory = f;
}

tls_context *default_tls_context(const char *ca, size_t ca_len) {
    if (factory == NULL) {
        UM_LOG(ERR, "FATAL error no default TLS engine is set");
        return NULL;
    }
    return factory(ca, ca_len);
}

static char tls_config_path[PATH_MAX] = {0};
int tlsuv_set_config_path(const char *path) {
    if (path == NULL) {
        tls_config_path[0] = 0;
        return configure_tls ? configure_tls() : 0;
    }

    if (strlen(path) >= sizeof(tls_config_path)) {
        UM_LOG(ERR, "path too long: %s", path);
        return UV_EINVAL;
    }

    uv_fs_t stat;
    int rc = uv_fs_stat(NULL, &stat, path, NULL);
    if (rc != 0) {
        UM_LOG(ERR, "failed to stat %s: %s", path, uv_strerror(rc));
        return rc;
    }
    if ((stat.statbuf.st_mode & (S_IFREG|S_IFLNK)) == 0) {
        UM_LOG(ERR, "path is not a regular file: %s", path);
        uv_fs_req_cleanup(&stat);
        return UV_EINVAL;
    }

    strcpy(tls_config_path, path);
    return configure_tls ? configure_tls() : 0;
}

const char* tlsuv_get_config_path(void) {
    return tls_config_path[0] ? tls_config_path : NULL;
}

