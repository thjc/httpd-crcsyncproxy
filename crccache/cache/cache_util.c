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

#include "cache.h"
#include <ap_config.h>
#include "mod_crccache_client.h"
#include <http_log.h>
#include <http_protocol.h>
#include <apr_date.h>
#include <apr_time.h>
#include <apr_md5.h>
#include <apr_lib.h>
#include <apr_strings.h>

/* Determine if "url" matches the hostname, scheme and port and path
 * in "filter". All but the path comparisons are case-insensitive.
 */
int uri_meets_conditions(apr_uri_t filter, int pathlen, apr_uri_t url)
{
    /* Compare the hostnames */
    if(filter.hostname) {
        if (!url.hostname) {
            return 0;
        }
        else if (strcasecmp(filter.hostname, url.hostname)) {
            return 0;
        }
    }

    /* Compare the schemes */
    if(filter.scheme) {
        if (!url.scheme) {
            return 0;
        }
        else if (strcasecmp(filter.scheme, url.scheme)) {
            return 0;
        }
    }

    /* Compare the ports */
    if(filter.port_str) {
        if (url.port_str && filter.port != url.port) {
            return 0;
        }
        /* NOTE:  ap_port_of_scheme will return 0 if given NULL input */
        else if (filter.port != apr_uri_port_of_scheme(url.scheme)) {
            return 0;
        }
    }
    else if(url.port_str && filter.scheme) {
        if (apr_uri_port_of_scheme(filter.scheme) == url.port) {
            return 0;
        }
    }

    /* For HTTP caching purposes, an empty (NULL) path is equivalent to
     * a single "/" path. RFCs 3986/2396
     */
    if (!url.path) {
        if (*filter.path == '/' && pathlen == 1) {
            return 1;
        }
        else {
            return 0;
        }
    }

    /* Url has met all of the filter conditions so far, determine
     * if the paths match.
     */
    return !strncmp(filter.path, url.path, pathlen);
}
#if 0
CACHE_DECLARE(cache_provider_list *)ap_cache_get_providers(request_rec *r,
                                                  cache_server_conf *conf,
                                                  apr_uri_t uri)
{
    cache_provider_list *providers = NULL;
    int i;

    /* loop through all the cacheenable entries */
    for (i = 0; i < conf->cacheenable->nelts; i++) {
        struct cache_enable *ent =
                                (struct cache_enable *)conf->cacheenable->elts;
        if (uri_meets_conditions(ent[i].url, ent[i].pathlen, uri)) {
            /* Fetch from global config and add to the list. */
            cache_provider *provider;
            provider = ap_lookup_provider(CACHE_PROVIDER_GROUP, ent[i].type,
                                          "0");
            if (!provider) {
                /* Log an error! */
            }
            else {
                cache_provider_list *newp;
                newp = apr_pcalloc(r->pool, sizeof(cache_provider_list));
                newp->provider_name = ent[i].type;
                newp->provider = provider;

                if (!providers) {
                    providers = newp;
                }
                else {
                    cache_provider_list *last = providers;

                    while (last->next) {
                        last = last->next;
                    }
                    last->next = newp;
                }
            }
        }
    }

    /* then loop through all the cachedisable entries
     * Looking for urls that contain the full cachedisable url and possibly
     * more.
     * This means we are disabling cachedisable url and below...
     */
    for (i = 0; i < conf->cachedisable->nelts; i++) {
        struct cache_disable *ent =
                               (struct cache_disable *)conf->cachedisable->elts;
        if (uri_meets_conditions(ent[i].url, ent[i].pathlen, uri)) {
            /* Stop searching now. */
            return NULL;
        }
    }

    return providers;
}
#endif

/* do a HTTP/1.1 age calculation */
CACHE_DECLARE(apr_int64_t) ap_cache_current_age(cache_info_t *info,
                                                const apr_time_t age_value,
                                                apr_time_t now)
{
    apr_time_t apparent_age, corrected_received_age, response_delay,
               corrected_initial_age, resident_time, current_age,
               age_value_usec;

    age_value_usec = apr_time_from_sec(age_value);

    /* Perform an HTTP/1.1 age calculation. (RFC2616 13.2.3) */

    apparent_age = MAX(0, info->response_time - info->date);
    corrected_received_age = MAX(apparent_age, age_value_usec);
    response_delay = info->response_time - info->request_time;
    corrected_initial_age = corrected_received_age + response_delay;
    resident_time = now - info->response_time;
    current_age = corrected_initial_age + resident_time;

    return apr_time_sec(current_age);
}

/*
 * list is a comma-separated list of case-insensitive tokens, with
 * optional whitespace around the tokens.
 * The return returns 1 if the token val is found in the list, or 0
 * otherwise.
 */
CACHE_DECLARE(int) ap_cache_liststr(apr_pool_t *p, const char *list,
                                    const char *key, char **val)
{
    apr_size_t key_len;
    const char *next;

    if (!list) {
        return 0;
    }

    key_len = strlen(key);
    next = list;

    for (;;) {

        /* skip whitespace and commas to find the start of the next key */
        while (*next && (apr_isspace(*next) || (*next == ','))) {
            next++;
        }

        if (!*next) {
            return 0;
        }

        if (!strncasecmp(next, key, key_len)) {
            /* this field matches the key (though it might just be
             * a prefix match, so make sure the match is followed
             * by either a space or an equals sign)
             */
            next += key_len;
            if (!*next || (*next == '=') || apr_isspace(*next) ||
                (*next == ',')) {
                /* valid match */
                if (val) {
                    while (*next && (*next != '=') && (*next != ',')) {
                        next++;
                    }
                    if (*next == '=') {
                        next++;
                        while (*next && apr_isspace(*next )) {
                            next++;
                        }
                        if (!*next) {
                            *val = NULL;
                        }
                        else {
                            const char *val_start = next;
                            while (*next && !apr_isspace(*next) &&
                                   (*next != ',')) {
                                next++;
                            }
                            *val = apr_pstrmemdup(p, val_start,
                                                  next - val_start);
                        }
                    }
                    else {
                        *val = NULL;
                    }
                }
                return 1;
            }
        }

        /* skip to the next field */
        do {
            next++;
            if (!*next) {
                return 0;
            }
        } while (*next != ',');
    }
}

/* return each comma separated token, one at a time */
CACHE_DECLARE(const char *)ap_cache_tokstr(apr_pool_t *p, const char *list,
                                           const char **str)
{
    apr_size_t i;
    const char *s;

    s = ap_strchr_c(list, ',');
    if (s != NULL) {
        i = s - list;
        do
            s++;
        while (apr_isspace(*s))
            ; /* noop */
    }
    else
        i = strlen(list);

    while (i > 0 && apr_isspace(list[i - 1]))
        i--;

    *str = s;
    if (i)
        return apr_pstrndup(p, list, i);
    else
        return NULL;
}

/*
 * Converts apr_time_t expressed as hex digits to
 * a true apr_time_t.
 */
CACHE_DECLARE(apr_time_t) ap_cache_hex2usec(const char *x)
{
    int i, ch;
    apr_time_t j;
    for (i = 0, j = 0; i < sizeof(j) * 2; i++) {
        ch = x[i];
        j <<= 4;
        if (apr_isdigit(ch))
            j |= ch - '0';
        else if (apr_isupper(ch))
            j |= ch - ('A' - 10);
        else
            j |= ch - ('a' - 10);
    }
    return j;
}

/*
 * Converts apr_time_t to apr_time_t expressed as hex digits.
 */
CACHE_DECLARE(void) ap_cache_usec2hex(apr_time_t j, char *y)
{
    int i, ch;

    for (i = (sizeof(j) * 2)-1; i >= 0; i--) {
        ch = (int)(j & 0xF);
        j >>= 4;
        if (ch >= 10)
            y[i] = ch + ('A' - 10);
        else
            y[i] = ch + '0';
    }
    y[sizeof(j) * 2] = '\0';
}

static void cache_hash(const char *it, char *val, int ndepth, int nlength)
{
    apr_md5_ctx_t context;
    unsigned char digest[16];
    char tmp[22];
    int i, k, d;
    unsigned int x;
    static const char enc_table[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@";

    apr_md5_init(&context);
    apr_md5_update(&context, (const unsigned char *) it, strlen(it));
    apr_md5_final(digest, &context);

    /* encode 128 bits as 22 characters, using a modified uuencoding
     * the encoding is 3 bytes -> 4 characters* i.e. 128 bits is
     * 5 x 3 bytes + 1 byte -> 5 * 4 characters + 2 characters
     */
    for (i = 0, k = 0; i < 15; i += 3) {
        x = (digest[i] << 16) | (digest[i + 1] << 8) | digest[i + 2];
        tmp[k++] = enc_table[x >> 18];
        tmp[k++] = enc_table[(x >> 12) & 0x3f];
        tmp[k++] = enc_table[(x >> 6) & 0x3f];
        tmp[k++] = enc_table[x & 0x3f];
    }

    /* one byte left */
    x = digest[15];
    tmp[k++] = enc_table[x >> 2];    /* use up 6 bits */
    tmp[k++] = enc_table[(x << 4) & 0x3f];

    /* now split into directory levels */
    for (i = k = d = 0; d < ndepth; ++d) {
        memcpy(&val[i], &tmp[k], nlength);
        k += nlength;
        val[i + nlength] = '/';
        i += nlength + 1;
    }
    memcpy(&val[i], &tmp[k], 22 - k);
    val[i + 22 - k] = '\0';
}

CACHE_DECLARE(char *)ap_cache_generate_name(apr_pool_t *p, int dirlevels,
                                            int dirlength, const char *name)
{
    char hashfile[66];
    cache_hash(name, hashfile, dirlevels, dirlength);
    return apr_pstrdup(p, hashfile);
}

/*
 * Create a new table consisting of those elements from an 
 * headers table that are allowed to be stored in a cache.
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_headers(apr_pool_t *pool,
                                                        apr_table_t *t,
                                                        server_rec *s)
{
    apr_table_t *headers_out;

    /* Short circuit the common case that there are not
     * (yet) any headers populated.
     */
    if (t == NULL) {
        return apr_table_make(pool, 10);
    };

    /* Make a copy of the headers, and remove from
     * the copy any hop-by-hop headers, as defined in Section
     * 13.5.1 of RFC 2616
     */
    headers_out = apr_table_copy(pool, t);

    apr_table_unset(headers_out, "Connection");
    apr_table_unset(headers_out, "Keep-Alive");
    apr_table_unset(headers_out, "Proxy-Authenticate");
    apr_table_unset(headers_out, "Proxy-Authorization");
    apr_table_unset(headers_out, "TE");
    apr_table_unset(headers_out, "Trailers");
    apr_table_unset(headers_out, "Transfer-Encoding");
    apr_table_unset(headers_out, "Upgrade");

    return headers_out;
}

/*
 * Legacy call - functionally equivalent to ap_cache_cacheable_headers.
 * @deprecated @see ap_cache_cacheable_headers
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_hdrs_out(apr_pool_t *p,
                                                        apr_table_t *t,
                                                        server_rec *s)
{
    return ap_cache_cacheable_headers(p,t,s);
}

/*
 * Create a new table consisting of those elements from an input
 * headers table that are allowed to be stored in a cache.
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_headers_in(request_rec *r)
{
    return ap_cache_cacheable_headers(r->pool, r->headers_in, r->server);
}

/*
 * Create a new table consisting of those elements from an output
 * headers table that are allowed to be stored in a cache;
 * ensure there is a content type and capture any errors.
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_headers_out(request_rec *r)
{
    apr_table_t *headers_out;

    headers_out = apr_table_overlay(r->pool, r->headers_out,
                                        r->err_headers_out);

    apr_table_clear(r->err_headers_out);

    headers_out = ap_cache_cacheable_headers(r->pool, headers_out,
                                                  r->server);

    if (!apr_table_get(headers_out, "Content-Type")
        && r->content_type) {
        apr_table_setn(headers_out, "Content-Type",
                       ap_make_content_type(r, r->content_type));
    }

    if (!apr_table_get(headers_out, "Content-Encoding")
        && r->content_encoding) {
        apr_table_setn(headers_out, "Content-Encoding",
                       r->content_encoding);
    }

    return headers_out;
}
