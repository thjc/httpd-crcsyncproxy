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
 */

/*
 * Author: mod_file_cache by Bill Stoddard <stoddard@apache.org> 
 *         Based on mod_mmap_static by Dean Gaudet <dgaudet@arctic.org>
 *
 * v0.01: initial implementation
 */

/*
    Documentation:

    Some sites have a set of static files that are really busy, and 
    change infrequently (or even on a regular schedule). Save time 
    by caching open handles to these files. This module, unlike 
    mod_mmap_static, caches open file handles, not file content. 
    On systems (like Windows) with heavy system call overhead and
    that have an efficient sendfile implementation, caching file handles
    offers several advantages over caching content. First, the file system
    can manage the memory, allowing infrequently hit cached files to
    be paged out. Second, since caching open handles does not consume
    significant resources, it will be possible to enable an AutoLoadCache
    feature where static files are dynamically loaded in the cache 
    as the server runs. On systems that have file change notification,
    this module can be enhanced to automatically garbage collect 
    cached files that change on disk.

    This module should work on Unix systems that have sendfile. Place 
    cachefile directives into your configuration to direct files to
    be cached.

	cachefile /path/to/file1
	cachefile /path/to/file2
	...

    These files are only cached when the server is restarted, so if you 
    change the list, or if the files are changed, then you'll need to 
    restart the server.

    To reiterate that point:  if the files are modified *in place*
    without restarting the server you may end up serving requests that
    are completely bogus.  You should update files by unlinking the old
    copy and putting a new copy in place. 

    There's no such thing as inheriting these files across vhosts or
    whatever... place the directives in the main server only.

    Known problems:

    Don't use Alias or RewriteRule to move these files around...  unless
    you feel like paying for an extra stat() on each request.  This is
    a deficiency in the Apache API that will hopefully be solved some day.
    The file will be served out of the file handle cache, but there will be
    an extra stat() that's a waste.
*/

#include "apr.h"

#if !(APR_HAS_SENDFILE || APR_HAS_MMAP)
#error mod_file_cache only works on systems with APR_HAS_SENDFILE or APR_HAS_MMAP
#endif

#include "apr_mmap.h"
#include "apr_strings.h"
#include "apr_hash.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#define CORE_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_core.h"

module AP_MODULE_DECLARE_DATA file_cache_module;

typedef struct {
#if APR_HAS_SENDFILE
    apr_file_t *file;
#endif
    const char *filename;
    apr_finfo_t finfo;
    int is_mmapped;
#if APR_HAS_MMAP
    apr_mmap_t *mm;
#endif
    char mtimestr[APR_RFC822_DATE_LEN];
    char sizestr[21];	/* big enough to hold any 64-bit file size + null */ 
} a_file;

typedef struct {
    apr_hash_t *fileht;
} a_server_config;


static void *create_server_config(apr_pool_t *p, server_rec *s)
{
    a_server_config *sconf = apr_palloc(p, sizeof(*sconf));

    sconf->fileht = apr_hash_make(p);
    return sconf;
}

static apr_status_t cleanup_file_cache(void *sconfv)
{
    a_server_config *sconf = sconfv;
    a_file *file;
    apr_hash_index_t *hi;

    /* Iterate over the file hash table and clean up each entry */
    for (hi = apr_hash_first(sconf->fileht); hi; hi=apr_hash_next(hi)) {
        apr_hash_this(hi, NULL, NULL, (void **)&file);
#if APR_HAS_MMAP
        if (file->is_mmapped) { 
	    apr_mmap_delete(file->mm);
        } 
#endif 
#if APR_HAS_SENDFILE
        if (!file->is_mmapped) {
            apr_file_close(file->file); 
        }
#endif
    }
    return APR_SUCCESS;
}

static void cache_the_file(cmd_parms *cmd, const char *filename, int mmap)
{
    a_server_config *sconf;
    a_file *new_file;
    a_file tmp;
    apr_file_t *fd = NULL;
    apr_status_t rc;
    const char *fspec;

    fspec = ap_os_case_canonical_filename(cmd->pool, filename);
    if ((rc = apr_stat(&tmp.finfo, fspec, APR_FINFO_MIN, 
                       cmd->temp_pool)) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, rc, cmd->server,
	    "mod_file_cache: unable to stat(%s), skipping", fspec);
	return;
    }
    if (tmp.finfo.filetype != APR_REG) {
	ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, cmd->server,
	    "mod_file_cache: %s isn't a regular file, skipping", fspec);
	return;
    }

    rc = apr_file_open(&fd, fspec, APR_READ | APR_XTHREAD, APR_OS_DEFAULT, cmd->pool);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rc, cmd->server,
                     "mod_file_cache: unable to open(%s, O_RDONLY), skipping", fspec);
	return;
    }

    /* WooHoo, we have a file to put in the cache */
    new_file = apr_pcalloc(cmd->pool, sizeof(a_file));
    new_file->finfo = tmp.finfo;

#if APR_HAS_MMAP
    if (mmap) {
         /* MMAPFile directive. MMAP'ing the file */
        if ((rc = apr_mmap_create(&new_file->mm, fd, 0, new_file->finfo.size,
                                  APR_MMAP_READ, cmd->pool)) != APR_SUCCESS) { 
            apr_file_close(fd);
            ap_log_error(APLOG_MARK, APLOG_WARNING, rc, cmd->server,
                         "mod_file_cache: unable to mmap %s, skipping", filename);
            return;
        }
        apr_file_close(fd);
        new_file->is_mmapped = TRUE;
    }
#endif
#if APR_HAS_SENDFILE
    if (!mmap) {
        /* CacheFile directive. Caching the file handle */
        new_file->is_mmapped = FALSE;
        new_file->file = fd;
    }
#endif

    new_file->filename = fspec;
    apr_rfc822_date(new_file->mtimestr, new_file->finfo.mtime);
    apr_snprintf(new_file->sizestr, sizeof new_file->sizestr, "%" APR_OFF_T_FMT, new_file->finfo.size);

    sconf = ap_get_module_config(cmd->server->module_config, &file_cache_module);
    apr_hash_set(sconf->fileht, new_file->filename, strlen(new_file->filename), new_file);

    if (apr_hash_count(sconf->fileht) == 1) {
	/* first one, register the cleanup */
	apr_pool_cleanup_register(cmd->pool, sconf, cleanup_file_cache, apr_pool_cleanup_null);
    }
}

static const char *cachefilehandle(cmd_parms *cmd, void *dummy, const char *filename)
{
#if APR_HAS_SENDFILE
    cache_the_file(cmd, filename, 0);
#else
    /* Sendfile not supported by this OS */
    ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, cmd->server,
                 "mod_file_cache: unable to cache file: %s. Sendfile is not supported on this OS", filename);
#endif
    return NULL;
}
static const char *cachefilemmap(cmd_parms *cmd, void *dummy, const char *filename) 
{
#if APR_HAS_MMAP
    cache_the_file(cmd, filename, 1);
#else
    /* MMAP not supported by this OS */
    ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, cmd->server,
                 "mod_file_cache: unable to cache file: %s. MMAP is not supported by this OS", filename);
#endif
    return NULL;
}

static void file_cache_post_config(apr_pool_t *p, apr_pool_t *plog,
                                   apr_pool_t *ptemp, server_rec *s)
{
    /* Hummm, anything to do here? */
}

/* If it's one of ours, fill in r->finfo now to avoid extra stat()... this is a
 * bit of a kludge, because we really want to run after core_translate runs.
 */
static int file_cache_xlat(request_rec *r)
{
    a_server_config *sconf;
    a_file *match;
    int res;

    sconf = ap_get_module_config(r->server->module_config, &file_cache_module);

    /* we only operate when at least one cachefile directive was used */
    if (!apr_hash_count(sconf->fileht)) {
	return DECLINED;
    }

    res = ap_core_translate(r);
    if (res != OK || !r->filename) {
	return res;
    }

    /* search the cache */
    match = (a_file *) apr_hash_get(sconf->fileht, r->filename, APR_HASH_KEY_STRING);
    if (match == NULL)
        return DECLINED;

    /* pass search results to handler */
    ap_set_module_config(r->request_config, &file_cache_module, match);

    /* shortcircuit the get_path_info() stat() calls and stuff */
    r->finfo = match->finfo;
    return OK;
}

static int mmap_handler(request_rec *r, a_file *file)
{
#if APR_HAS_MMAP
    ap_send_mmap (file->mm, r, 0, file->finfo.size);
#endif
    return OK;
}

static int sendfile_handler(request_rec *r, a_file *file)
{
#if APR_HAS_SENDFILE
    apr_size_t nbytes;
    apr_status_t rv = APR_EINIT;
    apr_file_t *rfile;
    apr_os_file_t fd;

    /* A cached file handle (more importantly, its file pointer) is 
     * shared by all threads in the process. The file pointer will 
     * be corrupted if multiple threads attempt to read from the 
     * cached file handle. The sendfile API does not rely on the position 
     * of the file pointer instead taking explicit file offset and 
     * length arguments. 
     *
     * We should call ap_send_fd with a cached file handle IFF 
     * we are CERTAIN the file will be served with apr_sendfile(). 
     * The presense of an AP_FTYPE_FILTER in the filter chain nearly
     * guarantees that apr_sendfile will NOT be used to send the file.
     * Furthermore, AP_FTYPE_CONTENT filters will be at the beginning
     * of the chain, so it should suffice to just check the first 
     * filter in the chain. If the first filter is not a content filter, 
     * assume apr_sendfile() will be used to send the content.
     */
    if (r->output_filters && r->output_filters->frec) {
        if (r->output_filters->frec->ftype == AP_FTYPE_CONTENT)
            return DECLINED;
    }

    /* Create an apr_file_t anchored out of the request pool to use 
     * on the call to ap_send_fd(). The cached apr_file_t is allocated 
     * out of pconf (a life of the server pool) and sending it down
     * the filter chain could cause memory leaks.
     */
    apr_os_file_get(&fd, file->file);
    apr_os_file_put(&rfile, &fd, r->pool);
    rv = ap_send_fd(rfile, r, 0, file->finfo.size, &nbytes);
    if (rv != APR_SUCCESS) {
        /* ap_send_fd will log the error */
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif
    return OK;
}

static int file_cache_handler(request_rec *r) 
{
    a_file *match;
    int errstatus;
    int rc = OK;

    /* XXX: not sure if this is right yet
     * see comment in http_core.c:default_handler
     */
    if (ap_strcmp_match(r->handler, "*/*")) {
        return DECLINED;
    }

    /* we don't handle anything but GET */
    if (r->method_number != M_GET) return DECLINED;

    /* did xlat phase find the file? */
    match = ap_get_module_config(r->request_config, &file_cache_module);

    if (match == NULL) {
	return DECLINED;
    }

    /* note that we would handle GET on this resource */
    r->allowed |= (1 << M_GET);

    /* This handler has no use for a request body (yet), but we still
     * need to read and discard it if the client sent one.
     */
    if ((errstatus = ap_discard_request_body(r)) != OK)
        return errstatus;

    ap_update_mtime(r, match->finfo.mtime);

    /* ap_set_last_modified() always converts the file mtime to a string
     * which is slow.  Accelerate the common case.
     * ap_set_last_modified(r);
     */
    {
        apr_time_t mod_time;
        char *datestr;

        mod_time = ap_rationalize_mtime(r, r->mtime);
        if (mod_time == match->finfo.mtime)
            datestr = match->mtimestr;
        else {
            datestr = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
            apr_rfc822_date(datestr, mod_time);
        }
        apr_table_setn(r->headers_out, "Last-Modified", datestr);
    }

    ap_set_etag(r);
    if ((errstatus = ap_meets_conditions(r)) != OK) {
       return errstatus;
    }

    /* ap_set_content_length() always converts the same number and never
     * returns an error.  Accelerate it.
     */
    r->clength = match->finfo.size;
    apr_table_setn(r->headers_out, "Content-Length", match->sizestr);

    /* Call appropriate handler */
    if (!r->header_only) {    
        if (match->is_mmapped == TRUE)
            rc = mmap_handler(r, match);
        else
            rc = sendfile_handler(r, match);
    }

    return rc;
}

static command_rec file_cache_cmds[] =
{
AP_INIT_ITERATE("cachefile", cachefilehandle, NULL, RSRC_CONF,
     "A space separated list of files to add to the file handle cache at config time"),
AP_INIT_ITERATE("mmapfile", cachefilemmap, NULL, RSRC_CONF,
     "A space separated list of files to mmap at config time"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(file_cache_handler, NULL, NULL, APR_HOOK_LAST);
    ap_hook_post_config(file_cache_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(file_cache_xlat, NULL, NULL, APR_HOOK_MIDDLE);
    /* This trick doesn't work apparently because the translate hooks
       are single shot. If the core_hook returns OK, then our hook is 
       not called.
    ap_hook_translate_name(file_cache_xlat, aszPre, NULL, APR_HOOK_MIDDLE); 
    */

}

module AP_MODULE_DECLARE_DATA file_cache_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                     /* create per-directory config structure */
    NULL,                     /* merge per-directory config structures */
    create_server_config,     /* create per-server config structure */
    NULL,                     /* merge per-server config structures */
    file_cache_cmds,          /* command handlers */
    register_hooks            /* register hooks */
};
