/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_log.h"
#include "http_request.h"
#include "http_config.h"
#include "http_protocol.h"

#include "apr_strings.h"
#include "apr_time.h"

#include "ap_socache.h"

#include "distcache/dc_client.h"

#if !defined(DISTCACHE_CLIENT_API) || (DISTCACHE_CLIENT_API < 0x0001)
#error "You must compile with a more recent version of the distcache-base package"
#endif

struct context {
    /* Configured target server: */
    const char *target;
    /* distcache client context: */
    DC_CTX *dc;
};

static const char *socache_dc_create(void **context, const char *arg, 
                                     apr_pool_t *tmp, apr_pool_t *p)
{
    struct context *ctx;

    ctx = *context = apr_palloc(p, sizeof *ctx);
    
    ctx->target = apr_pstrdup(p, arg);

    return NULL;
}

static apr_status_t socache_dc_init(void *context, server_rec *s, apr_pool_t *p)
{
    struct context *ctx = ctx;

#if 0
    /* If a "persistent connection" mode of operation is preferred, you *must*
     * also use the PIDCHECK flag to ensure fork()'d processes don't interlace
     * comms on the same connection as each other. */
#define SESSION_CTX_FLAGS        SESSION_CTX_FLAG_PERSISTENT | \
                                 SESSION_CTX_FLAG_PERSISTENT_PIDCHECK | \
                                 SESSION_CTX_FLAG_PERSISTENT_RETRY | \
                                 SESSION_CTX_FLAG_PERSISTENT_LATE
#else
    /* This mode of operation will open a temporary connection to the 'target'
     * for each cache operation - this makes it safe against fork()
     * automatically. This mode is preferred when running a local proxy (over
     * unix domain sockets) because overhead is negligable and it reduces the
     * performance/stability danger of file-descriptor bloatage. */
#define SESSION_CTX_FLAGS        0
#endif
    ctx->dc = DC_CTX_new(ctx->target, SESSION_CTX_FLAGS);
    if (!ctx->dc) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache failed to obtain context");
        return APR_EGENERAL;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "distributed scache context initialised");

    return APR_SUCCESS;
}

static void socache_dc_kill(void *context, server_rec *s)
{
    struct context *ctx = context;

    if (ctx && ctx->dc) {
        DC_CTX_free(ctx->dc);
        ctx->dc = NULL;
    }
}

static apr_status_t socache_dc_store(void *context, server_rec *s, 
                                     const unsigned char *id, unsigned int idlen,
                                     time_t timeout,
                                     unsigned char *der, unsigned int der_len)
{
    struct context *ctx = context;

    /* !@#$%^ - why do we deal with *absolute* time anyway??? */
    timeout -= time(NULL);
    /* Send the serialised session to the distributed cache context */
    if (!DC_CTX_add_session(ctx->dc, id, idlen, der, der_len,
                            (unsigned long)timeout * 1000)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'add_session' failed");
        return APR_EGENERAL;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "distributed scache 'add_session' successful");
    return APR_SUCCESS;
}

static apr_status_t socache_dc_retrieve(void *context, server_rec *s, 
                                        const unsigned char *id, unsigned int idlen,
                                        unsigned char *dest, unsigned int *destlen,
                                        apr_pool_t *p)
{
    unsigned int data_len;
    struct context *ctx = context;

    /* Retrieve any corresponding session from the distributed cache context */
    if (!DC_CTX_get_session(ctx->dc, id, idlen, dest, *destlen, &data_len)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "distributed scache 'get_session' MISS");
        return APR_EGENERAL;
    }
    if (data_len > *destlen) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'get_session' OVERFLOW");
        return APR_ENOSPC;
    }
    *destlen = data_len;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "distributed scache 'get_session' HIT");
    return APR_SUCCESS;
}

static void socache_dc_remove(void *context, server_rec *s, 
                              const unsigned char *id, unsigned int idlen, 
                              apr_pool_t *p)
{
    struct context *ctx = context;

    /* Remove any corresponding session from the distributed cache context */
    if (!DC_CTX_remove_session(ctx->dc, id, idlen)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'remove_session' MISS");
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "distributed scache 'remove_session' HIT");
    }
}

static void socache_dc_status(void *context, request_rec *r, int flags)
{
    struct context *ctx = context;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "distributed scache 'socache_dc_status'");
    ap_rprintf(r, "cache type: <b>DC (Distributed Cache)</b>, "
               " target: <b>%s</b><br>", ctx->target);
}

static const ap_socache_provider_t socache_dc = {
    "distcache",
    0,
    socache_dc_create,
    socache_dc_init,
    socache_dc_kill,
    socache_dc_store,
    socache_dc_retrieve,
    socache_dc_remove,
    socache_dc_status
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AP_SOCACHE_PROVIDER_GROUP, "dc", 
                         AP_SOCACHE_PROVIDER_VERSION,
                         &socache_dc);
}

const module AP_MODULE_DECLARE_DATA socache_dc_module = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL, NULL, NULL, NULL,
    register_hooks
};

