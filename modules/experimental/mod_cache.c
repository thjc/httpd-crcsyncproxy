/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#define CORE_PRIVATE

#include "mod_cache.h"

module AP_MODULE_DECLARE_DATA cache_module;



/* -------------------------------------------------------------- */



/*
 * CACHE handler
 * -------------
 *
 * Can we deliver this request from the cache?
 * If yes:
 *   deliver the content by installing the CACHE_OUT filter.
 * If no:
 *   check whether we're allowed to try cache it
 *   If yes:
 *     add CACHE_IN filter
 *   If No:
 *     oh well.
 */

int ap_url_cache_handler(request_rec *r);

int ap_url_cache_handler(request_rec *r)
{
    apr_status_t rv;
    const char *cc_in;
    apr_uri_t uri = r->parsed_uri;
    char *url = r->unparsed_uri;
    char *path = uri.path;
    const char *types;
    cache_info *info = NULL;
    cache_request_rec *cache;
    cache_server_conf *conf = (cache_server_conf *) ap_get_module_config(r->server->module_config, 
                                                                         &cache_module);

    /* we don't handle anything but GET */
    if (r->method_number != M_GET) return DECLINED;

    /*
     * Which cache module (if any) should handle this request?
     */
    if (!(types = ap_cache_get_cachetype(r, conf, path))) {
        return DECLINED;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "cache: URL %s is being handled by %s", path, types);

    /* make space for the per request config */
    cache = (cache_request_rec *) ap_get_module_config(r->request_config, &cache_module);
    if (!cache) {
        cache = ap_pcalloc(r->pool, sizeof(cache_request_rec));
        ap_set_module_config(r->request_config, &cache_module, cache);
    }

    /* save away the type */
    cache->types = types;

    /*
     * Are we allowed to serve cached info at all?
     */

    /* find certain cache controlling headers */
    cc_in = ap_table_get(r->headers_in, "Cache-Control");

    /* first things first - does the request allow us to return
     * cached information at all? If not, just decline the request.
     *
     * Note that there is a big difference between not being allowed
     * to cache a request (no-store) and not being allowed to return
     * a cached request without revalidation (max-age=0).
     *
     * Caching is forbidden under the following circumstances:
     *
     * - RFC2616 14.9.2 Cache-Control: no-store
     * we are not supposed to store this request at all. Behave as a
     * tunnel.
     */
    if (ap_cache_liststr(cc_in, "no-store", NULL)) {
        /* delete the previously cached file */
        cache_remove_url(r, cache->types, url);

        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "cache: no-store forbids caching of %s", url);
        return DECLINED;
    }

    /*
     * Try serve this request from the cache.
     *
     * If no existing cache file
     *   add cache_in filter
     * If stale cache file
     *   If conditional request
     *     add cache_in filter
     *   If non-conditional request
     *     fudge response into a conditional
     *     add cache_conditional filter
     * If fresh cache file
     *   clear filter stack
     *   add cache_out filter
     */

    rv = cache_select_url(r, cache->types, url);
    if (DECLINED == rv) {
        /* no existing cache file */
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "cache: no cache - add cache_in filter and DECLINE");
        /* add cache_in filter to cache this request */
        ap_add_output_filter("CACHE_IN", NULL, r, r->connection);
        /* return DECLINED */
        return DECLINED;
    }
    else if (OK == rv) {
        /* cache file exists */
        if (cache->fresh) {
            apr_bucket_brigade *out;

            /* fresh data available */
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                         "cache: fresh cache - add cache_out filter and handle request");

            /* We are in the quick handler hook, which means that no output
             * filters have been set. So lets run the insert_filter hook.
             * Humm... Probably should not go through most of these hooks
             * for a proxy request, so take out all but the basics.
             */
            ap_run_insert_filter(r);
            if (r->proxyreq) {
                ap_cache_reset_output_filters(r);
            }
            /* Now add the cache_out filter. cache_out is a FTYPE_CONTENT
             * which means it will be inserted first in the stream, which
             * is exactly what we need.
             */
            ap_add_output_filter("CACHE_OUT", NULL, r, r->connection);

            /* kick off the filter stack */
            out = apr_brigade_create(r->pool);
            if (APR_SUCCESS != (rv = ap_pass_brigade(r->output_filters, out))) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                             "cache: error returned while trying to return %s cached data", cache->type);
                return rv;
            }
            return OK;
        }
        else {
            /* stale data available */
            ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                         "cache: stale cache - test conditional");
            /* if conditional request */
            if (ap_cache_request_is_conditional(r)) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                             "cache: conditional - add cache_in filter and DECLINE");
                /* add cache_in filter */
                ap_add_output_filter("CACHE_IN", NULL, r, r->connection);
                /* return DECLINED */
                return DECLINED;
            }
            /* else if non-conditional request */
            else {
                /* fudge response into a conditional */
                if (info && info->etag) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                                 "cache: nonconditional - fudge conditional by etag");
                    /* if we have a cached etag */
                    apr_table_set(r->headers_in, "If-None-Match", info->etag);
                }
                else if (info && info->lastmods) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                                 "cache: nonconditional - fudge conditional by lastmod");
                    /* if we have a cached IMS */
                    apr_table_set(r->headers_in, "If-Modified-Since", info->lastmods);
                }
                else {
                    /* something else - pretend there was no cache */
                    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                                 "cache: nonconditional - no cached etag/lastmods - add cache_in and DECLINE");
                    /* add cache_in filter to cache this request */
                    ap_add_output_filter("CACHE_IN", NULL, r, r->connection);
                    /* return DECLINED */
                    return DECLINED;
                }
                /* add cache_conditional filter */
                ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                             "cache: nonconditional - add cache_conditional and DECLINE");
                ap_add_output_filter("CACHE_CONDITIONAL", NULL, r, r->connection);
                /* return DECLINED */
                return DECLINED;
            }
        }
    }
    else {
        /* error */
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                     "cache: error returned while checking for cached file by %s cache", cache->type);
        return DECLINED;
    }
}

/*
 * CACHE_OUT filter
 * ----------------
 *
 * Deliver cached content (headers and body) up the stack.
 */
int ap_cache_out_filter(ap_filter_t *f, apr_bucket_brigade *bb);

int ap_cache_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    request_rec *r = f->r;
    apr_table_t *headers;
    cache_request_rec *cache = (cache_request_rec *) ap_get_module_config(r->request_config, 
                                                                          &cache_module);

    if (!cache) {
        /* user likely configured CACHE_OUT manually; they should use mod_cache
         * configuration to do that */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "CACHE_OUT enabled unexpectedly");
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
		 "cache: running CACHE_OUT filter");

    cache_read_entity_headers(cache->handle, r, &headers);
    r->headers_out = headers;
    cache_read_entity_body(cache->handle, bb);

    /* This filter is done once it has served up its content */
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}


/*
 * CACHE_CONDITIONAL filter
 * ------------------------
 *
 * Decide whether or not cached content should be delivered
 * based on our fudged conditional request.
 * If response HTTP_NOT_MODIFIED
 *   replace ourselves with cache_out filter
 * Otherwise
 *   replace ourselves with cache_in filter
 */
int ap_cache_conditional_filter(ap_filter_t *f, apr_bucket_brigade *in);

int ap_cache_conditional_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, f->r->server,
                 "cache: running CACHE_CONDITIONAL filter");

    if (f->r->status == HTTP_NOT_MODIFIED) {
        /* replace ourselves with CACHE_OUT filter */
        ap_add_output_filter("CACHE_OUT", NULL, f->r, f->r->connection);
    }
    else {
        /* replace ourselves with CACHE_IN filter */
        ap_add_output_filter("CACHE_IN", NULL, f->r, f->r->connection);
    }
    ap_remove_output_filter(f);

    return ap_pass_brigade(f->next, in);
}


/*
 * CACHE_IN filter
 * ---------------
 *
 * Decide whether or not this content should be cached.
 * If we decide no it should:
 *   remove the filter from the chain
 * If we decide yes it should:
 *   pass the data to the storage manager
 *   pass the data to the next filter (the network)
 *
 */
int ap_cache_in_filter(ap_filter_t *f, apr_bucket_brigade *in);

int ap_cache_in_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    int rv;
    request_rec *r = f->r;
    char *url = r->unparsed_uri;
    const char *cc_out = ap_table_get(r->headers_out, "Cache-Control");
    const char *exps, *lastmods, *dates, *etag;
    apr_time_t exp, date, lastmod, now;
    apr_size_t size;
    cache_info *info;
    void *sconf = r->server->module_config;
    cache_server_conf *conf =
    (cache_server_conf *) ap_get_module_config(sconf, &cache_module);
    void *scache = r->request_config;
    cache_request_rec *cache =
    (cache_request_rec *) ap_get_module_config(scache, &cache_module);


    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, f->r->server,
                 "cache: running CACHE_IN filter");

    /* check first whether running this filter has any point or not */
    if(r->no_cache) {
        return ap_pass_brigade(f->next, in);
    }

    /*
     * Pass Data to Cache
     * ------------------
     * This section passes the brigades into the cache modules, but only
     * if the setup section (see below) is complete.
     */

    /* have we already run the cachability check and set up the cached file handle? */
    if(cache->in_checked) {
        /* pass the brigades into the cache, then pass them
         * up the filter stack
         */
        cache_write_entity_body(cache->handle, in);
        return ap_pass_brigade(f->next, in);
    }

    /*
     * Setup Data in Cache
     * -------------------
     * This section opens the cache entity and sets various caching parameters,
     * and decides whether this URL should be cached at all. This section is
     * run before the above section.
     */
    info = ap_pcalloc(r->pool, sizeof(cache_info));

    /* read expiry date; if a bad date, then leave it so the client can
     * read it 
     */
    exps = ap_table_get(r->headers_out, "Expires");
    if (exps != NULL) {
        if (APR_DATE_BAD == (exp = apr_date_parse_http(exps))) {
            exps = NULL;
        }
    }
    else {
        exp = APR_DATE_BAD;
    }

    /* read the last-modified date; if the date is bad, then delete it */
    lastmods = ap_table_get(r->headers_out, "Last-Modified");
    if (lastmods != NULL) {
        if (APR_DATE_BAD == (lastmod = apr_date_parse_http(lastmods))) {
            lastmods = NULL;
        }
    }
    else {
        lastmod = APR_DATE_BAD;
    }

    /* read the etag from the entity */
    etag = ap_table_get(r->headers_out, "Etag");

    /*
     * what responses should we not cache?
     *
     * At this point we decide based on the response headers whether it
     * is appropriate _NOT_ to cache the data from the server. There are
     * a whole lot of conditions that prevent us from caching this data.
     * They are tested here one by one to be clear and unambiguous. 
     */

    /* RFC2616 13.4 we are allowed to cache 200, 203, 206, 300, 301 or 410
     * We don't cache 206, because we don't (yet) cache partial responses.
     * We include 304 Not Modified here too as this is the origin server
     * telling us to serve the cached copy. */
    if ((r->status != HTTP_OK && r->status != HTTP_NON_AUTHORITATIVE && 
         r->status != HTTP_MULTIPLE_CHOICES && 
         r->status != HTTP_MOVED_PERMANENTLY && r->status != HTTP_NOT_MODIFIED) ||

    /* if a broken Expires header is present, don't cache it */
        (exps != NULL && exp == APR_DATE_BAD) ||

    /* if the server said 304 Not Modified but we have no cache file - pass
     * this untouched to the user agent, it's not for us. */
        (r->status == HTTP_NOT_MODIFIED && (NULL == cache->handle)) ||

    /* 200 OK response from HTTP/1.0 and up without a Last-Modified header/Etag */
        (r->status == HTTP_OK && lastmods == NULL && etag == NULL) ||

    /* HEAD requests */
        r->header_only ||

    /* RFC2616 14.9.2 Cache-Control: no-store response indicating do not
     * cache, or stop now if you are trying to cache it */
        ap_cache_liststr(cc_out, "no-store", NULL) ||

    /* RFC2616 14.9.1 Cache-Control: private
     * this object is marked for this user's eyes only. Behave as a tunnel. */
        ap_cache_liststr(cc_out, "private", NULL) ||

    /* RFC2616 14.8 Authorisation:
     * if authorisation is included in the request, we don't cache, but we
     * can cache if the following exceptions are true:
     * 1) If Cache-Control: s-maxage is included
     * 2) If Cache-Control: must-revalidate is included
     * 3) If Cache-Control: public is included
     */
        (ap_table_get(r->headers_in, "Authorization") != NULL &&
         !(ap_cache_liststr(cc_out, "s-maxage", NULL) || 
           ap_cache_liststr(cc_out, "must-revalidate", NULL) || 
           ap_cache_liststr(cc_out, "public", NULL))
        ) ||

    /* or we've been asked not to cache it above */
        r->no_cache) {

        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "cache: response is not cachable");

        /* remove this object from the cache 
         * BillS Asks.. Why do we need to make this call to remove_url?
         * leave it in for now..
         */
        cache_remove_url(r, cache->types, url);

        /* remove this filter from the chain */
        ap_remove_output_filter(f);

        /* ship the data up the stack */
        return ap_pass_brigade(f->next, in);
    }
    cache->in_checked = 1;

    /* Set the content length if known.  We almost certainly do NOT want to
     * cache streams with unknown content lengths in the in-memory cache.
     * Streams with unknown content length should be first cached in the
     * file system. If they are withing acceptable limits, then they can be 
     * moved to the in-memory cache.
     */
    {
        const char* cl;
        cl = apr_table_get(r->headers_out, "Content-Length");
        if (cl) {
            size = atol(cl);
        }
        else
            size = -1;
    }

    /* It's safe to cache the response.
     *
     * There are two possiblities at this point:
     * - cache->handle == NULL. In this case there is no previously
     * cached entity anywhere on the system. We must create a brand
     * new entity and store the response in it.
     * - cache->handle != NULL. In this case there is a stale
     * entity in the system which needs to be replaced by new
     * content (unless the result was 304 Not Modified, which means
     * the cached entity is actually fresh, and we should update
     * the headers).
     */
    /* no cache handle, create a new entity */
    if (!cache->handle) {
        rv = cache_create_entity(r, cache->types, url, size);
    }
    /* pre-existing cache handle and 304, make entity fresh */
    else if (r->status == HTTP_NOT_MODIFIED) {
        /* update headers */

        /* remove this filter ??? */
    }
    /* pre-existing cache handle and new entity, replace entity with this one */
    else {
        cache_remove_entity(r, cache->types, cache->handle);
        rv = cache_create_entity(r, cache->types, url, size);
    }
    
    if (rv != OK) {
        /* Caching layer declined the opportunity to cache the response */
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, in);
    }
    
    /*
     * We now want to update the cache file header information with
     * the new date, last modified, expire and content length and write
     * it away to our cache file. First, we determine these values from
     * the response, using heuristics if appropriate.
     *
     * In addition, we make HTTP/1.1 age calculations and write them away
     * too.
     */

    /* Read the date. Generate one if one is not supplied */
    dates = ap_table_get(r->headers_out, "Date");
    if (dates != NULL)
        info->date = apr_date_parse_http(dates);
    else
        info->date = APR_DATE_BAD;

    now = apr_time_now();
    if (info->date == APR_DATE_BAD) {	/* No, or bad date */
        char *dates;
        /* no date header! */
        /* add one; N.B. use the time _now_ rather than when we were checking the cache */
        date = now;
        dates = apr_pcalloc(r->pool, MAX_STRING_LEN);
        apr_rfc822_date(dates, now);
        ap_table_set(r->headers_out, "Date", dates);
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "cache: Added date header");
    }
    info->date = date;

    /* set response_time for HTTP/1.1 age calculations */
    info->response_time = now;

    /* get the request time */
    info->request_time = r->request_time;

    /* check last-modified date */
    if (lastmod != APR_DATE_BAD && lastmod > date)
    {
	/* if its in the future, then replace by date */
        lastmod = date;
        lastmods = dates;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "cache: Last modified is in the future, replacing with now");
    }
    info->lastmod = lastmod;

    /* so we now have the expiry date */
    /* if no expiry date then
     *   if lastmod
     *      expiry date = now + min((date - lastmod) * factor, maxexpire)
     *   else
     *      expire date = now + defaultexpire
     */
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                 "cache: Expiry date is %ld", (long)exp);
    if (exp == APR_DATE_BAD) {
        if (lastmod != APR_DATE_BAD) {
            double x = (double) (date - lastmod) * conf->factor;
            double maxex = conf->maxex;
            if (x > maxex)
                x = maxex;
            exp = now + (int) x;
        }
        else
            exp = now + conf->defex;
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r->server,
                     "cache: Expiry date calculated %ld", (long)exp);
    }
    info->expire = exp;

    /*
     * Write away header information to cache.
     */
    cache_write_entity_headers(cache->handle, r, info, r->headers_in, r->headers_out);
    
    return ap_pass_brigade(f->next, in);
}

/* -------------------------------------------------------------- */
/* Setup configurable data */

static void * create_cache_config(apr_pool_t *p, server_rec *s)
{
    cache_server_conf *ps = ap_pcalloc(p, sizeof(cache_server_conf));

    /* 1 if the cache is enabled, 0 otherwise */
    ps->cacheon = 0;
    ps->cacheon_set = 0;
    /* array of URL prefixes for which caching is enabled */
    ps->cacheenable = ap_make_array(p, 10, sizeof(struct cache_enable));
    /* array of URL prefixes for which caching is disabled */
    ps->cachedisable = ap_make_array(p, 10, sizeof(struct cache_disable));
    /* maximum time to cache a document */
    ps->maxex = DEFAULT_CACHE_MAXEXPIRE;
    ps->maxex_set = 0;
    /* default time to cache a document */
    ps->defex = DEFAULT_CACHE_EXPIRE;
    ps->defex_set = 0;
    /* factor used to estimate Expires date from LastModified date */
    ps->factor = DEFAULT_CACHE_LMFACTOR;
    ps->factor_set = 0;
    /* default percentage to force cache completion */
    ps->complete = DEFAULT_CACHE_COMPLETION;
    ps->complete_set = 0;
    return ps;
}

static void * merge_cache_config(apr_pool_t *p, void *basev, void *overridesv)
{
    cache_server_conf *ps = ap_pcalloc(p, sizeof(cache_server_conf));
    cache_server_conf *base = (cache_server_conf *) basev;
    cache_server_conf *overrides = (cache_server_conf *) overridesv;

    /* 1 if the cache is enabled, 0 otherwise */
    ps->cacheon = (overrides->cacheon_set == 0) ? base->cacheon : overrides->cacheon;
    /* array of URL prefixes for which caching is disabled */
    ps->cachedisable = ap_append_arrays(p, base->cachedisable, overrides->cachedisable);
    /* array of URL prefixes for which caching is enabled */
    ps->cacheenable = ap_append_arrays(p, base->cacheenable, overrides->cacheenable);
    /* maximum time to cache a document */
    ps->maxex = (overrides->maxex_set == 0) ? base->maxex : overrides->maxex;
    /* default time to cache a document */
    ps->defex = (overrides->defex_set == 0) ? base->defex : overrides->defex;
    /* factor used to estimate Expires date from LastModified date */
    ps->factor = (overrides->factor_set == 0) ? base->factor : overrides->factor;
    /* default percentage to force cache completion */
    ps->complete = (overrides->complete_set == 0) ? base->complete : overrides->complete;

    return ps;
}

static const char
*set_cache_on(cmd_parms *parms, void *dummy, int flag)
{
    cache_server_conf *conf = ap_get_module_config(parms->server->module_config, &cache_module);

    conf->cacheon = 1;
    conf->cacheon_set = 1;
    return NULL;
}

static const char
*add_cache_enable(cmd_parms *parms, void *dummy, const char *type, const char *url)
{
    cache_server_conf *conf = ap_get_module_config(parms->server->module_config, &cache_module);
    struct cache_enable *new;

    new = apr_array_push(conf->cacheenable);
    new->type = type;
    new->url = url;
    return NULL;
}

static const char
*add_cache_disable(cmd_parms *parms, void *dummy, const char *url)
{
    cache_server_conf *conf = ap_get_module_config(parms->server->module_config, &cache_module);
    struct cache_enable *new;

    new = apr_array_push(conf->cachedisable);
    new->url = url;
    return NULL;
}

static const char
*set_cache_maxex(cmd_parms *parms, void *dummy, const char *arg)
{
    cache_server_conf *conf = ap_get_module_config(parms->server->module_config, &cache_module);
    double val;

    if (sscanf(arg, "%lg", &val) != 1)
        return "CacheMaxExpire value must be a float";
    conf->maxex = (apr_time_t) (val * MSEC_ONE_HR);
    conf->maxex_set = 1;
    return NULL;
}

static const char
*set_cache_defex(cmd_parms *parms, void *dummy, const char *arg)
{
    cache_server_conf *conf = ap_get_module_config(parms->server->module_config, &cache_module);
    double val;

    if (sscanf(arg, "%lg", &val) != 1)
        return "CacheDefaultExpire value must be a float";
    conf->defex = (apr_time_t) (val * MSEC_ONE_HR);
    conf->defex_set = 1;
    return NULL;
}

static const char
*set_cache_factor(cmd_parms *parms, void *dummy, const char *arg)
{
    cache_server_conf *conf = ap_get_module_config(parms->server->module_config, &cache_module);
    double val;

    if (sscanf(arg, "%lg", &val) != 1)
        return "CacheLastModifiedFactor value must be a float";
    conf->factor = val;
    conf->factor_set = 1;
    return NULL;
}

static const char
*set_cache_complete(cmd_parms *parms, void *dummy, const char *arg)
{
    cache_server_conf *conf = ap_get_module_config(parms->server->module_config, &cache_module);
    int val;

    if (sscanf(arg, "%u", &val) != 1)
        return "CacheForceCompletion value must be a percentage";
    conf->complete = val;
    conf->complete_set = 1;
    return NULL;
}

static const command_rec cache_cmds[] =
{
    /* XXX
     * Consider a new config directive that enables loading specific cache
     * implememtations (like mod_cache_mem, mod_cache_file, etc.).
     * Rather than using a LoadModule directive, admin would use something
     * like CacheModule  mem_cache_module | file_cache_module, etc,
     * which would cause the approprpriate cache module to be loaded.
     * This is more intuitive that requiring a LoadModule directive.
     */

    AP_INIT_FLAG("CacheOn", set_cache_on, NULL, RSRC_CONF,
     "On if the transparent cache should be enabled"),
    AP_INIT_TAKE2("CacheEnable", add_cache_enable, NULL, RSRC_CONF,
     "A cache type and partial URL prefix below which caching is enabled"),
    AP_INIT_TAKE1("CacheDisable", add_cache_disable, NULL, RSRC_CONF,
     "A partial URL prefix below which caching is disabled"),
    AP_INIT_TAKE1("CacheMaxExpire", set_cache_maxex, NULL, RSRC_CONF,
     "The maximum time in hours to cache a document"),
    AP_INIT_TAKE1("CacheDefaultExpire", set_cache_defex, NULL, RSRC_CONF,
     "The default time in hours to cache a document"),
    AP_INIT_TAKE1("CacheLastModifiedFactor", set_cache_factor, NULL, RSRC_CONF,
     "The factor used to estimate Expires date from LastModified date"),
    AP_INIT_TAKE1("CacheForceCompletion", set_cache_complete, NULL, RSRC_CONF,
     "Percentage of download to arrive for the cache to force complete transfer"),
    {NULL}
};

static void
register_hooks(apr_pool_t *p)
{
    /* cache initializer */
    /* cache handler */
    ap_hook_quick_handler(ap_url_cache_handler, NULL, NULL, APR_HOOK_FIRST);
    /* cache filters */
    ap_register_output_filter("CACHE_IN", ap_cache_in_filter, AP_FTYPE_NETWORK);
    ap_register_output_filter("CACHE_OUT", ap_cache_out_filter, AP_FTYPE_CONTENT);
    ap_register_output_filter("CACHE_CONDITIONAL", ap_cache_conditional_filter, AP_FTYPE_NETWORK);
}

module AP_MODULE_DECLARE_DATA cache_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    create_cache_config,	/* create per-server config structure */
    merge_cache_config,		/* merge per-server config structures */
    cache_cmds,			/* command apr_table_t */
    register_hooks
};
