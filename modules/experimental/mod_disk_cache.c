/* Copyright 2000-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mod_cache.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "util_filter.h"
#include "util_script.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* needed for unlink/link */
#endif

/*
 * disk_cache_object_t
 * Pointed to by cache_object_t::vobj
 */
typedef struct disk_cache_object {
    const char *root;        /* the location of the cache directory */
    char *tempfile;          /* temp file tohold the content */
#if 0
    int dirlevels;              /* Number of levels of subdirectories */
    int dirlength;            /* Length of subdirectory names */
#endif
    char *datafile;          /* name of file where the data will go */
    char *hdrsfile;          /* name of file where the hdrs will go */
    char *hashfile;          /* Computed hash key for this URI */
    char *name;
    apr_time_t version;      /* update count of the file */
    apr_file_t *fd;          /* data file */
    apr_file_t *hfd;         /* headers file */
    apr_off_t file_size;     /*  File size of the cached data file  */
} disk_cache_object_t;

/*
 * mod_disk_cache configuration
 */
/* TODO: Make defaults OS specific */
#define CACHEFILE_LEN 20        /* must be less than HASH_LEN/2 */
#define DEFAULT_DIRLEVELS 3
#define DEFAULT_DIRLENGTH 2
#define DEFAULT_MIN_FILE_SIZE 1
#define DEFAULT_MAX_FILE_SIZE 1000000
#define DEFAULT_CACHE_SIZE 1000000

typedef struct {
    const char* cache_root;
    apr_size_t cache_root_len;
    off_t space;                 /* Maximum cache size (in 1024 bytes) */
    apr_time_t maxexpire;        /* Maximum time to keep cached files in msecs */
    apr_time_t defaultexpire;    /* default time to keep cached file in msecs */
    double lmfactor;             /* factor for estimating expires date */
    apr_time_t gcinterval;       /* garbage collection interval, in msec */
    int dirlevels;               /* Number of levels of subdirectories */
    int dirlength;               /* Length of subdirectory names */
    int        expirychk;               /* true if expiry time is observed for cached files */
    apr_size_t minfs;            /* minumum file size for cached files */
    apr_size_t maxfs;            /* maximum file size for cached files */
    apr_time_t mintm;            /* minimum time margin for caching files */
    /* dgc_time_t gcdt;            time of day for daily garbage collection */
    apr_array_header_t *gcclnun; /* gc_retain_t entries for unused files */
    apr_array_header_t *gcclean; /* gc_retain_t entries for all files */
    int maxgcmem;                /* maximum memory used by garbage collection */
} disk_cache_conf;

module AP_MODULE_DECLARE_DATA disk_cache_module;

/* Forward declarations */
static int remove_entity(cache_handle_t *h);
static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *i);
static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b);
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r);
static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);

/*
 * Local static functions
 */
#define CACHE_HEADER_SUFFIX ".header"
#define CACHE_DATA_SUFFIX   ".data"
static char *header_file(apr_pool_t *p, disk_cache_conf *conf,
                         disk_cache_object_t *dobj, const char *name)
{
    if (!dobj->hashfile) {
        dobj->hashfile = generate_name(p, conf->dirlevels, conf->dirlength,
                                       name);
    }
    return apr_pstrcat(p, conf->cache_root, "/", dobj->hashfile,
                       CACHE_HEADER_SUFFIX, NULL);
}

static char *data_file(apr_pool_t *p, disk_cache_conf *conf,
                       disk_cache_object_t *dobj, const char *name)
{
    if (!dobj->hashfile) {
        dobj->hashfile = generate_name(p, conf->dirlevels, conf->dirlength,
                                       name);
    }
    return apr_pstrcat(p, conf->cache_root, "/", dobj->hashfile,
                       CACHE_DATA_SUFFIX, NULL);
}

static void mkdir_structure(disk_cache_conf *conf, char *file, apr_pool_t *pool)
{
    apr_status_t rv;
    char *p;

    for (p = file + conf->cache_root_len + 1;;) {
        p = strchr(p, '/');
        if (!p)
            break;
        *p = '\0';

        rv = apr_dir_make(file,
                          APR_UREAD|APR_UWRITE|APR_UEXECUTE, pool);
        if (rv != APR_SUCCESS && !APR_STATUS_IS_EEXIST(rv)) {
            /* XXX */
        }
        *p = '/';
        ++p;
    }
}

static apr_status_t file_cache_el_final(cache_handle_t *h, request_rec *r)
{
    apr_status_t rv;
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &disk_cache_module);
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;

    /* move the data over */
    if (dobj->fd) {
        apr_file_flush(dobj->fd);
        if (!dobj->datafile) {
            dobj->datafile = data_file(r->pool, conf, dobj, h->cache_obj->key);
        }
        /* Remove old file with the same name. If remove fails, then
         * perhaps we need to create the directory tree where we are
         * about to write the new file.
         */
        rv = apr_file_remove(dobj->datafile, r->pool);
        if (rv != APR_SUCCESS) {
            mkdir_structure(conf, dobj->datafile, r->pool);
        }

        /*
         * This assumes that the tempfile is on the same file system
         * as the cache_root. If not, then we need a file copy/move
         * rather than a rename.
         */
        rv = apr_file_rename(dobj->tempfile, dobj->datafile, r->pool);
        if (rv != APR_SUCCESS) {
            /* XXX log */
        }

        apr_file_close(dobj->fd);
        dobj->fd = NULL;
        /* XXX log */
    }

    return APR_SUCCESS;
}

static apr_status_t file_cache_errorcleanup(disk_cache_object_t *dobj, request_rec *r)
{
    if (dobj->fd) {
        apr_file_close(dobj->fd);
        dobj->fd = NULL;
    }
    /* Remove the header file, the temporary body file, and a potential old body file */
    apr_file_remove(dobj->hdrsfile, r->pool);
    apr_file_remove(dobj->tempfile, r->pool);
    apr_file_remove(dobj->datafile, r->pool);

    /* Return non-APR_SUCCESS in order to have mod_cache remove the disk_cache filter */
    return DECLINED;
}


/* These two functions get and put state information into the data
 * file for an ap_cache_el, this state information will be read
 * and written transparent to clients of this module
 */
static int file_cache_recall_mydata(apr_file_t *fd, cache_info *info,
                                  disk_cache_object_t *dobj)
{
    apr_status_t rv;
    char urlbuff[1034]; /* XXX FIXME... THIS IS A POTENTIAL SECURITY HOLE */
    int urllen = sizeof(urlbuff);
    int offset=0;
    char * temp;

    /* read the data from the cache file */
    /* format
     * date SP expire SP count CRLF
     * dates are stored as a hex representation of apr_time_t (number of
     * microseconds since 00:00:00 january 1, 1970 UTC)
     */
    rv = apr_file_gets(&urlbuff[0], urllen, fd);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if ((temp = strchr(&urlbuff[0], '\n')) != NULL) /* trim off new line character */
        *temp = '\0';      /* overlay it with the null terminator */

    if (!apr_date_checkmask(urlbuff, "&&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&& &&&&&&&&&&&&&&&&")) {
        return APR_EGENERAL;
    }

    info->date = ap_cache_hex2usec(urlbuff + offset);
    offset += (sizeof(info->date)*2) + 1;
    info->expire = ap_cache_hex2usec(urlbuff + offset);
    offset += (sizeof(info->expire)*2) + 1;
    dobj->version = ap_cache_hex2usec(urlbuff + offset);
    offset += (sizeof(info->expire)*2) + 1;
    info->request_time = ap_cache_hex2usec(urlbuff + offset);
    offset += (sizeof(info->expire)*2) + 1;
    info->response_time = ap_cache_hex2usec(urlbuff + offset);

    /* check that we have the same URL */
    rv = apr_file_gets(&urlbuff[0], urllen, fd);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if ((temp = strchr(&urlbuff[0], '\n')) != NULL) { /* trim off new line character */
        *temp = '\0';      /* overlay it with the null terminator */
    }

    if (strncmp(urlbuff, "X-NAME: ", 7) != 0) {
        return APR_EGENERAL;
    }
    if (strcmp(urlbuff + 8, dobj->name) != 0) {
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

static int file_cache_store_mydata(apr_file_t *fd , cache_handle_t *h, request_rec *r)
{
    apr_status_t rc;
    char *buf;
    apr_size_t amt;

    char	dateHexS[sizeof(apr_time_t) * 2 + 1];
    char	expireHexS[sizeof(apr_time_t) * 2 + 1];
    char	verHexS[sizeof(apr_time_t) * 2 + 1];
    char	requestHexS[sizeof(apr_time_t) * 2 + 1];
    char	responseHexS[sizeof(apr_time_t) * 2 + 1];
    cache_info *info = &(h->cache_obj->info);
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;

    if (!r->headers_out) {
        /* XXX log message */
        return 0;
    }

    ap_cache_usec2hex(info->date, dateHexS);
    ap_cache_usec2hex(info->expire, expireHexS);
    ap_cache_usec2hex(dobj->version++, verHexS);
    ap_cache_usec2hex(info->request_time, requestHexS);
    ap_cache_usec2hex(info->response_time, responseHexS);
    buf = apr_pstrcat(r->pool, dateHexS, " ", expireHexS, " ", verHexS, " ", requestHexS, " ", responseHexS, "\n", NULL);
    amt = strlen(buf);
    rc = apr_file_write(fd, buf, &amt);
    if (rc != APR_SUCCESS) {
        /* XXX log message */
        return 0;
    }

    buf = apr_pstrcat(r->pool, "X-NAME: ", dobj->name, "\n", NULL);
    amt = strlen(buf);
    rc = apr_file_write(fd, buf, &amt);
    if (rc != APR_SUCCESS) {
        /* XXX log message */
        return 0;
    }
    return 1;
}

/*
 * Hook and mod_cache callback functions
 */
#define AP_TEMPFILE "/aptmpXXXXXX"
static int create_entity(cache_handle_t *h, request_rec *r,
                         const char *key,
                         apr_off_t len)
{
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &disk_cache_module);
    apr_status_t rv;
    cache_object_t *obj;
    disk_cache_object_t *dobj;
    apr_file_t *tmpfile;

    if (conf->cache_root == NULL) {
        return DECLINED;
    }

    /* If the Content-Length is still unknown, cache anyway */
    if (len != -1 && (len < conf->minfs || len > conf->maxfs)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "cache_disk: URL %s failed the size check, "
                     "or is incomplete",
                     key);
        return DECLINED;
    }

    /* Allocate and initialize cache_object_t and disk_cache_object_t */
    obj = apr_pcalloc(r->pool, sizeof(*obj));
    obj->vobj = dobj = apr_pcalloc(r->pool, sizeof(*dobj));

    obj->key = apr_pstrdup(r->pool, key);
    /* XXX Bad Temporary Cast - see cache_object_t notes */
    obj->info.len = (apr_size_t) len;
    obj->complete = 0;   /* Cache object is not complete */

    dobj->name = obj->key;

    /* open temporary file */
    dobj->tempfile = apr_pstrcat(r->pool, conf->cache_root, AP_TEMPFILE, NULL);
    rv = apr_file_mktemp(&tmpfile, dobj->tempfile,
                         APR_CREATE | APR_READ | APR_WRITE | APR_EXCL, r->pool);

    if (rv == APR_SUCCESS) {
        /* Populate the cache handle */
        h->cache_obj = obj;

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                     "disk_cache: Storing URL %s",  key);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                     "disk_cache: Could not store URL %s [%d]", key, rv);

        return DECLINED;
    }

    return OK;
}

static int open_entity(cache_handle_t *h, request_rec *r, const char *key)
{
    apr_status_t rc;
    static int error_logged = 0;
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &disk_cache_module);
    apr_finfo_t finfo;
    cache_object_t *obj;
    cache_info *info;
    disk_cache_object_t *dobj;
    int flags;

    h->cache_obj = NULL;

    /* Look up entity keyed to 'url' */
    if (conf->cache_root == NULL) {
        if (!error_logged) {
            error_logged = 1;
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "disk_cache: Cannot cache files to disk without a CacheRoot specified.");
        }
        return DECLINED;
    }


    /* Create and init the cache object */
    h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(cache_object_t));
    obj->vobj = dobj = apr_pcalloc(r->pool, sizeof(disk_cache_object_t));

    info = &(obj->info);
    obj->key = (char *) key;
    dobj->name = (char *) key;
    dobj->datafile = data_file(r->pool, conf, dobj, key);
    dobj->hdrsfile = header_file(r->pool, conf, dobj, key);

    /* Open the data file */
    flags = APR_READ|APR_BINARY;
#ifdef APR_SENDFILE_ENABLED
    flags |= APR_SENDFILE_ENABLED;
#endif
    rc = apr_file_open(&dobj->fd, dobj->datafile, flags, 0, r->pool);
    if (rc != APR_SUCCESS) {
        /* XXX: Log message */
        return DECLINED;
    }

    /* Open the headers file */
    flags = APR_READ|APR_BINARY|APR_BUFFERED;
    rc = apr_file_open(&dobj->hfd, dobj->hdrsfile, flags, 0, r->pool);
    if (rc != APR_SUCCESS) {
        /* XXX: Log message */
        return DECLINED;
    }

    rc = apr_file_info_get(&finfo, APR_FINFO_SIZE, dobj->fd);
    if (rc == APR_SUCCESS) {
        dobj->file_size = finfo.size;
    }

    /* Read the bytes to setup the cache_info fields */
    rc = file_cache_recall_mydata(dobj->hfd, info, dobj);
    if (rc != APR_SUCCESS) {
        /* XXX log message */
        return DECLINED;
    }

    /* Initialize the cache_handle callback functions */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "disk_cache: Recalled cached URL info header %s",  dobj->name);
    return OK;
}

static int remove_entity(cache_handle_t *h)
{
    /* Null out the cache object pointer so next time we start from scratch  */
    h->cache_obj = NULL;
    return OK;
}

static int remove_url(const char *key)
{
    /* XXX: Delete file from cache! */
    return OK;
}

/*
 * Reads headers from a buffer and returns an array of headers.
 * Returns NULL on file error
 * This routine tries to deal with too long lines and continuation lines.
 * @@@: XXX: FIXME: currently the headers are passed thru un-merged.
 * Is that okay, or should they be collapsed where possible?
 */
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r)
{
    apr_status_t rv;
    char urlbuff[1034];
    int urllen = sizeof(urlbuff);
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    apr_table_t * tmp;

    /* This case should not happen... */
    if (!dobj->hfd) {
        /* XXX log message */
        return APR_NOTFOUND;
    }

    if(!r->headers_out) {
        r->headers_out = apr_table_make(r->pool, 20);
    }

    /*
     * Call routine to read the header lines/status line
     */
    ap_scan_script_header_err(r, dobj->hfd, NULL);

    apr_table_setn(r->headers_out, "Content-Type",
                   ap_make_content_type(r, r->content_type));

    rv = apr_file_gets(&urlbuff[0], urllen, dobj->hfd);           /* Read status  */
    if (rv != APR_SUCCESS) {
        /* XXX log message */
	return rv;
    }

    r->status = atoi(urlbuff);                           /* Save status line into request rec  */

    /* Read and ignore the status line (This request might result in a
     * 304, so we don't necessarily want to retransmit a 200 from the cache.)
     */
    rv = apr_file_gets(&urlbuff[0], urllen, dobj->hfd);
    if (rv != APR_SUCCESS) {
        /* XXX log message */
	return rv;
    }

    h->req_hdrs = apr_table_make(r->pool, 20);

    /*
     * Call routine to read the header lines/status line
     */
    tmp = r->err_headers_out;
    r->err_headers_out = h->req_hdrs;
    rv = apr_file_gets(&urlbuff[0], urllen, dobj->hfd);           /* Read status  */
    ap_scan_script_header_err(r, dobj->hfd, NULL);
    r->err_headers_out = tmp;

    apr_file_close(dobj->hfd);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "disk_cache: Recalled headers for URL %s",  dobj->name);
    return APR_SUCCESS;
}

static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb)
{
    apr_bucket *e;
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;

    e = apr_bucket_file_create(dobj->fd, 0, (apr_size_t) dobj->file_size, p,
                               bb->bucket_alloc);
    APR_BRIGADE_INSERT_HEAD(bb, e);
    e = apr_bucket_eos_create(bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);

    return APR_SUCCESS;
}

static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *info)
{
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &disk_cache_module);
    apr_status_t rv;
    char *buf;
    char statusbuf[8];
    apr_size_t amt;
    disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;
    apr_file_t *hfd = dobj->hfd;

    if (!hfd)  {
        if (!dobj->hdrsfile) {
            dobj->hdrsfile = header_file(r->pool, conf, dobj,
                                         h->cache_obj->key);
        }

        /* This is flaky... we need to manage the cache_info differently */
        h->cache_obj->info = *info;

        /* Remove old file with the same name. If remove fails, then
         * perhaps we need to create the directory tree where we are
         * about to write the new headers file.
         */
        rv = apr_file_remove(dobj->hdrsfile, r->pool);
        if (rv != APR_SUCCESS) {
            mkdir_structure(conf, dobj->hdrsfile, r->pool);
        }

        rv = apr_file_open(&dobj->hfd, dobj->hdrsfile,
                           APR_WRITE | APR_CREATE | APR_EXCL,
                           APR_OS_DEFAULT, r->pool);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        hfd = dobj->hfd;
        dobj->name = h->cache_obj->key;

        file_cache_store_mydata(dobj->hfd, h, r);

        if (r->headers_out) {
            int i;
            apr_table_t* headers_out = ap_cache_cacheable_hdrs_out(r->pool, r->headers_out);
            apr_table_entry_t *elts = (apr_table_entry_t *) apr_table_elts(headers_out)->elts;
            for (i = 0; i < apr_table_elts(headers_out)->nelts; ++i) {
                if (elts[i].key != NULL) {
                    buf = apr_pstrcat(r->pool, elts[i].key, ": ",  elts[i].val, CRLF, NULL);
                    amt = strlen(buf);
                    apr_file_write(hfd, buf, &amt);
                }
            }
            buf = apr_pstrcat(r->pool, CRLF, NULL);
            amt = strlen(buf);
            apr_file_write(hfd, buf, &amt);

            /* This case only occurs when the content is generated locally */
            if (!apr_table_get(r->headers_out, "Content-Type") && r->content_type) {
                apr_table_setn(r->headers_out, "Content-Type",
                               ap_make_content_type(r, r->content_type));
            }
        }
        sprintf(statusbuf,"%d", r->status);
        buf = apr_pstrcat(r->pool, statusbuf, CRLF, NULL);
        amt = strlen(buf);
        apr_file_write(hfd, buf, &amt);

        /* This case only occurs when the content is generated locally */
        if (!r->status_line) {
            r->status_line = ap_get_status_line(r->status);
        }
        buf = apr_pstrcat(r->pool, r->status_line, "\n", NULL);
        amt = strlen(buf);
        apr_file_write(hfd, buf, &amt);
        buf = apr_pstrcat(r->pool, CRLF, NULL);
        amt = strlen(buf);
        apr_file_write(hfd, buf, &amt);

	/* Parse the vary header and dump those fields from the headers_in. */
	/* Make call to the same thing cache_select_url calls to crack Vary. */
	/* @@@ Some day, not today. */
        if (r->headers_in) {
            int i;
            apr_table_entry_t *elts = (apr_table_entry_t *) apr_table_elts(r->headers_in)->elts;
            for (i = 0; i < apr_table_elts(r->headers_in)->nelts; ++i) {
                if (elts[i].key != NULL) {
                    buf = apr_pstrcat(r->pool, elts[i].key, ": ",  elts[i].val, CRLF, NULL);
                    amt = strlen(buf);
                    apr_file_write(hfd, buf, &amt);
                }
            }
            buf = apr_pstrcat(r->pool, CRLF, NULL);
            amt = strlen(buf);
            apr_file_write(hfd, buf, &amt);
        }
        apr_file_close(hfd); /* flush and close */
    }
    else {
        /* XXX log message */
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "disk_cache: Stored headers for URL %s",  dobj->name);
    return APR_SUCCESS;
}

static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b)
{
    apr_bucket *e;
    apr_status_t rv;
    disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
    disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
                                                 &disk_cache_module);

    if (!dobj->fd) {
        rv = apr_file_open(&dobj->fd, dobj->tempfile,
                           APR_WRITE | APR_CREATE | APR_BINARY| APR_TRUNCATE | APR_BUFFERED,
                           APR_UREAD | APR_UWRITE, r->pool);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        dobj->file_size = 0;
    }
    for (e = APR_BRIGADE_FIRST(b);
         e != APR_BRIGADE_SENTINEL(b);
         e = APR_BUCKET_NEXT(e))
    {
        const char *str;
        apr_size_t length;
        apr_bucket_read(e, &str, &length, APR_BLOCK_READ);
        if (apr_file_write(dobj->fd, str, &length) != APR_SUCCESS) {
          ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "cache_disk: Error when writing cache file for URL %s",
                     h->cache_obj->key);
          /* Remove the intermediate cache file and return non-APR_SUCCESS */
          return file_cache_errorcleanup(dobj, r);
        }
        dobj->file_size += length;
        if (dobj->file_size > conf->maxfs) {
          ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "cache_disk: URL %s failed the size check (%lu>%lu)",
                     h->cache_obj->key, (unsigned long)dobj->file_size, (unsigned long)conf->maxfs);
          /* Remove the intermediate cache file and return non-APR_SUCCESS */
          return file_cache_errorcleanup(dobj, r);
        }
    }

    /* Was this the final bucket? If yes, close the body file and make sanity checks */
    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(b))) {
        if (h->cache_obj->info.len <= 0) {
          h->cache_obj->info.len = dobj->file_size;
        }
        else if (h->cache_obj->info.len != dobj->file_size) {
          /* "Content-Length" and actual content disagree in size. Log that. */
          ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                       "disk_cache: URL %s failed the size check (%lu != %lu)",
                       h->cache_obj->key,
                       (unsigned long)h->cache_obj->info.len,
                       (unsigned long)dobj->file_size);
          /* Remove the intermediate cache file and return non-APR_SUCCESS */
          return file_cache_errorcleanup(dobj, r);
        }
        if (dobj->file_size < conf->minfs) {
          ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "cache_disk: URL %s failed the size check (%lu<%lu)",
                     h->cache_obj->key, (unsigned long)dobj->file_size, (unsigned long)conf->minfs);
          /* Remove the intermediate cache file and return non-APR_SUCCESS */
          return file_cache_errorcleanup(dobj, r);
        }
        /* All checks were fine. Move tempfile to final destination */
        file_cache_el_final(h, r);    /* Link to the perm file, and close the descriptor */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "disk_cache: Body for URL %s cached.",  dobj->name);
    }

    return APR_SUCCESS;
}

static void *create_config(apr_pool_t *p, server_rec *s)
{
    disk_cache_conf *conf = apr_pcalloc(p, sizeof(disk_cache_conf));

    /* XXX: Set default values */
    conf->dirlevels = DEFAULT_DIRLEVELS;
    conf->dirlength = DEFAULT_DIRLENGTH;
    conf->space = DEFAULT_CACHE_SIZE;
    conf->maxfs = DEFAULT_MAX_FILE_SIZE;
    conf->minfs = DEFAULT_MIN_FILE_SIZE;
    conf->expirychk = 1;

    conf->cache_root = NULL;
    conf->cache_root_len = 0;

    return conf;
}

/*
 * mod_disk_cache configuration directives handlers.
 */
static const char
*set_cache_root(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    conf->cache_root = arg;
    conf->cache_root_len = strlen(arg);
    /* TODO: canonicalize cache_root and strip off any trailing slashes */

    return NULL;
}
static const char
*set_cache_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    conf->space = atoi(arg);
    return NULL;
}
static const char
*set_cache_gcint(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
/*
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
*/
    /* XXX */
    return NULL;
}
/*
 * Consider eliminating the next two directives in favor of
 * Ian's prime number hash...
 * key = hash_fn( r->uri)
 * filename = "/key % prime1 /key %prime2/key %prime3"
 */
static const char
*set_cache_dirlevels(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    int val = atoi(arg);
    if (val < 1)
        return "CacheDirLevels value must be an integer greater than 0";
    if (val * conf->dirlength > CACHEFILE_LEN)
        return "CacheDirLevels*CacheDirLength value must not be higher than 20";
    conf->dirlevels = val;
    return NULL;
}
static const char
*set_cache_dirlength(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    int val = atoi(arg);
    if (val < 1)
        return "CacheDirLength value must be an integer greater than 0";
    if (val * conf->dirlevels > CACHEFILE_LEN)
        return "CacheDirLevels*CacheDirLength value must not be higher than 20";

    conf->dirlength = val;
    return NULL;
}
static const char
*set_cache_exchk(cmd_parms *parms, void *in_struct_ptr, int flag)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    conf->expirychk = flag;

    return NULL;
}
static const char
*set_cache_minfs(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    conf->minfs = atoi(arg);
    return NULL;
}
static const char
*set_cache_maxfs(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    conf->maxfs = atoi(arg);
    return NULL;
}
static const char
*set_cache_minetm(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    /* XXX
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    */
    return NULL;
}
static const char
*set_cache_gctime(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    /* XXX
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    */
    return NULL;
}
static const char
*add_cache_gcclean(cmd_parms *parms, void *in_struct_ptr, const char *arg, const char *arg1)
{
    /* XXX
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    */
    return NULL;
}
static const char
*add_cache_gcclnun(cmd_parms *parms, void *in_struct_ptr, const char *arg, const char *arg1)
{
    /* XXX
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    */
    return NULL;
}
static const char
*set_cache_maxgcmem(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    /* XXX
    disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
                                                 &disk_cache_module);
    */
    return NULL;
}

static const command_rec disk_cache_cmds[] =
{
    AP_INIT_TAKE1("CacheRoot", set_cache_root, NULL, RSRC_CONF,
                 "The directory to store cache files"),
    AP_INIT_TAKE1("CacheSize", set_cache_size, NULL, RSRC_CONF,
                  "The maximum disk space used by the cache in KB"),
    AP_INIT_TAKE1("CacheGcInterval", set_cache_gcint, NULL, RSRC_CONF,
                  "The interval between garbage collections, in hours"),
    AP_INIT_TAKE1("CacheDirLevels", set_cache_dirlevels, NULL, RSRC_CONF,
                  "The number of levels of subdirectories in the cache"),
    AP_INIT_TAKE1("CacheDirLength", set_cache_dirlength, NULL, RSRC_CONF,
                  "The number of characters in subdirectory names"),
    AP_INIT_FLAG("CacheExpiryCheck", set_cache_exchk, NULL, RSRC_CONF,
                 "on if cache observes Expires date when seeking files"),
    AP_INIT_TAKE1("CacheMinFileSize", set_cache_minfs, NULL, RSRC_CONF,
                  "The minimum file size to cache a document"),
    AP_INIT_TAKE1("CacheMaxFileSize", set_cache_maxfs, NULL, RSRC_CONF,
                  "The maximum file size to cache a document"),
    AP_INIT_TAKE1("CacheTimeMargin", set_cache_minetm, NULL, RSRC_CONF,
                  "The minimum time margin to cache a document"),
    AP_INIT_TAKE1("CacheGcDaily", set_cache_gctime, NULL, RSRC_CONF,
                  "The time of day for garbage collection (24 hour clock)"),
    AP_INIT_TAKE2("CacheGcUnused", add_cache_gcclnun, NULL, RSRC_CONF,
                  "The time in hours to retain unused file that match a url"),
    AP_INIT_TAKE2("CacheGcClean", add_cache_gcclean, NULL, RSRC_CONF,
                  "The time in hours to retain unchanged files that match a url"),
    AP_INIT_TAKE1("CacheGcMemUsage", set_cache_maxgcmem, NULL, RSRC_CONF,
                  "The maximum kilobytes of memory used for garbage collection"),
    {NULL}
};

static const cache_provider cache_disk_provider =
{
    &remove_entity,
    &store_headers,
    &store_body,
    &recall_headers,
    &recall_body,
    &create_entity,
    &open_entity,
    &remove_url,
};

static void disk_cache_register_hook(apr_pool_t *p)
{
    /* cache initializer */
    ap_register_provider(p, CACHE_PROVIDER_GROUP, "disk", "0",
                         &cache_disk_provider);
}

module AP_MODULE_DECLARE_DATA disk_cache_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    create_config,              /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    disk_cache_cmds,	        /* command apr_table_t */
    disk_cache_register_hook	/* register hooks */
};
