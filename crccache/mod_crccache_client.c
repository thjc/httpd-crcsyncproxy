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

/* crcsync/crccache apache client module
 *
 * This module is designed to run as a cache server on the local end of a slow
 * internet link. This module uses a crc running hash algorithm to reduce
 * data transfer in cached but modified upstream files.
 *
 * CRC algorithm uses the crcsync library created by Rusty Russel
 *
 * Author: Toby Collett (2009)
 * Contributor: Alex Wulms (2009)
 *
 */



#include <assert.h>

#include <apr-1.0/apr_file_io.h>
#include <apr-1.0/apr_strings.h>
#include <apr-1.0/apr_base64.h>
#include <apr-1.0/apr_lib.h>
#include <apr-1.0/apr_date.h>
#include "ap_provider.h"
#include "util_filter.h"
#include "util_script.h"
#include "util_charset.h"
#include <http_log.h>
#include <http_protocol.h>

#include "crccache.h"
#include "ap_wrapper.h"
#include <crcsync/crcsync.h>
#include <zlib.h>

#include "mod_crccache_client.h"

static ap_filter_rec_t *crccache_decode_filter_handle;

/* Handles for cache filters, resolved at startup to eliminate
 * a name-to-function mapping on each request
 */
static ap_filter_rec_t *cache_save_filter_handle;
static ap_filter_rec_t *cache_save_subreq_filter_handle;
static ap_filter_rec_t *cache_out_filter_handle;
static ap_filter_rec_t *cache_out_subreq_filter_handle;
static ap_filter_rec_t *cache_remove_url_filter_handle;

/*
 * mod_disk_cache: Disk Based HTTP 1.1 Cache.
 *
 * Flow to Find the .data file:
 *   Incoming client requests URI /foo/bar/baz
 *   Generate <hash> off of /foo/bar/baz
 *   Open <hash>.header
 *   Read in <hash>.header file (may contain Format #1 or Format #2)
 *   If format #1 (Contains a list of Vary Headers):
 *      Use each header name (from .header) with our request values (headers_in) to
 *      regenerate <hash> using HeaderName+HeaderValue+.../foo/bar/baz
 *      re-read in <hash>.header (must be format #2)
 *   read in <hash>.data
 *
 * Format #1:
 *   apr_uint32_t format;
 *   apr_time_t expire;
 *   apr_array_t vary_headers (delimited by CRLF)
 *
 * Format #2:
 *   disk_cache_info_t (first sizeof(apr_uint32_t) bytes is the format)
 *   entity name (dobj->name) [length is in disk_cache_info_t->name_len]
 *   r->headers_out (delimited by CRLF)
 *   CRLF
 *   r->headers_in (delimited by CRLF)
 *   CRLF
 */

module AP_MODULE_DECLARE_DATA crccache_client_module;
APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;


static int cache_post_config(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    /* This is the means by which unusual (non-unix) os's may find alternate
     * means to run a given command (e.g. shebang/registry parsing on Win32)
     */
    cache_generate_key = APR_RETRIEVE_OPTIONAL_FN(ap_cache_generate_key);
    if (!cache_generate_key) {
        cache_generate_key = cache_generate_key_default;
    }
    return OK;
}


/*
 * Local static functions
 */

static char *header_file(apr_pool_t *p, crccache_client_conf *conf,
		disk_cache_object_t *dobj, const char *name) {
	if (!dobj->hashfile) {
		dobj->hashfile = ap_cache_generate_name(p, conf->dirlevels,
				conf->dirlength, name);
	}

	if (dobj->prefix) {
		return apr_pstrcat(p, dobj->prefix, CACHE_VDIR_SUFFIX, "/",
				dobj->hashfile, CACHE_HEADER_SUFFIX, NULL);
	} else {
		return apr_pstrcat(p, conf->cache_root, "/", dobj->hashfile,
				CACHE_HEADER_SUFFIX, NULL);
	}
}

static char *data_file(apr_pool_t *p, crccache_client_conf *conf,
		disk_cache_object_t *dobj, const char *name) {
	if (!dobj->hashfile) {
		dobj->hashfile = ap_cache_generate_name(p, conf->dirlevels,
				conf->dirlength, name);
	}

	if (dobj->prefix) {
		return apr_pstrcat(p, dobj->prefix, CACHE_VDIR_SUFFIX, "/",
				dobj->hashfile, CACHE_DATA_SUFFIX, NULL);
	} else {
		return apr_pstrcat(p, conf->cache_root, "/", dobj->hashfile,
				CACHE_DATA_SUFFIX, NULL);
	}
}

static void mkdir_structure(crccache_client_conf *conf, const char *file,
		apr_pool_t *pool) {
	apr_status_t rv;
	char *p;

	for (p = (char*) file + conf->cache_root_len + 1;;) {
		p = strchr(p, '/');
		if (!p)
			break;
		*p = '\0';

		rv = apr_dir_make(file, APR_UREAD | APR_UWRITE | APR_UEXECUTE, pool);
		if (rv != APR_SUCCESS && !APR_STATUS_IS_EEXIST(rv)) {
			/* XXX */
		}
		*p = '/';
		++p;
	}
}

/* htcacheclean may remove directories underneath us.
 * So, we'll try renaming three times at a cost of 0.002 seconds.
 */
static apr_status_t safe_file_rename(crccache_client_conf *conf, const char *src,
		const char *dest, apr_pool_t *pool) {
	apr_status_t rv;

	rv = apr_file_rename(src, dest, pool);

	if (rv != APR_SUCCESS) {
		int i;

		for (i = 0; i < 2 && rv != APR_SUCCESS; i++) {
			/* 1000 micro-seconds aka 0.001 seconds. */
			apr_sleep(1000);

			mkdir_structure(conf, dest, pool);

			rv = apr_file_rename(src, dest, pool);
		}
	}

	return rv;
}

static apr_status_t file_cache_el_final(disk_cache_object_t *dobj,
		request_rec *r) {
	/* move the data over */
	if (dobj->tfd) {
		apr_status_t rv;

		apr_file_close(dobj->tfd);

		/* This assumes that the tempfile is on the same file system
		 * as the cache_root. If not, then we need a file copy/move
		 * rather than a rename.
		 */
		rv = apr_file_rename(dobj->tempfile, dobj->datafile, r->pool);
		if (rv != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_WARNING, rv,r->server, "disk_cache: rename tempfile to datafile failed:"
			" %s -> %s", dobj->tempfile, dobj->datafile);
			apr_file_remove(dobj->tempfile, r->pool);
		}

		dobj->tfd = NULL;
	}

	return APR_SUCCESS;
}

static apr_status_t file_cache_errorcleanup(disk_cache_object_t *dobj,
		request_rec *r) {
	/* Remove the header file and the body file. */
	apr_file_remove(dobj->hdrsfile, r->pool);
	apr_file_remove(dobj->datafile, r->pool);

	/* If we opened the temporary data file, close and remove it. */
	if (dobj->tfd) {
		apr_file_close(dobj->tfd);
		apr_file_remove(dobj->tempfile, r->pool);
		dobj->tfd = NULL;
	}

	return APR_SUCCESS;
}

/* These two functions get and put state information into the data
 * file for an ap_cache_el, this state information will be read
 * and written transparent to clients of this module
 */
static int file_cache_recall_mydata(apr_file_t *fd, cache_info *info,
		disk_cache_object_t *dobj, request_rec *r) {
	apr_status_t rv;
	char *urlbuff;
	disk_cache_info_t disk_info;
	apr_size_t len;

	/* read the data from the cache file */
	len = sizeof(disk_cache_info_t);
	rv = apr_file_read_full(fd, &disk_info, len, &len);
	if (rv != APR_SUCCESS) {
		return rv;
	}

	/* Store it away so we can get it later. */
	dobj->disk_info = disk_info;

	info->status = disk_info.status;
	info->date = disk_info.date;
	info->expire = disk_info.expire;
	info->request_time = disk_info.request_time;
	info->response_time = disk_info.response_time;

	/* Note that we could optimize this by conditionally doing the palloc
	 * depending upon the size. */
	urlbuff = apr_palloc(r->pool, disk_info.name_len + 1);
	len = disk_info.name_len;
	rv = apr_file_read_full(fd, urlbuff, len, &len);
	if (rv != APR_SUCCESS) {
		return rv;
	}
	urlbuff[disk_info.name_len] = '\0';

	/* check that we have the same URL */
	/* Would strncmp be correct? */
	if (strcmp(urlbuff, dobj->name) != 0) {
		return APR_EGENERAL;
	}

	return APR_SUCCESS;
}

static const char* regen_key(apr_pool_t *p, apr_table_t *headers,
		apr_array_header_t *varray, const char *oldkey) {
	struct iovec *iov;
	int i, k;
	int nvec;
	const char *header;
	const char **elts;

	nvec = (varray->nelts * 2) + 1;
	iov = apr_palloc(p, sizeof(struct iovec) * nvec);
	elts = (const char **) varray->elts;

	/* TODO:
	 *    - Handle multiple-value headers better. (sort them?)
	 *    - Handle Case in-sensitive Values better.
	 *        This isn't the end of the world, since it just lowers the cache
	 *        hit rate, but it would be nice to fix.
	 *
	 * The majority are case insenstive if they are values (encoding etc).
	 * Most of rfc2616 is case insensitive on header contents.
	 *
	 * So the better solution may be to identify headers which should be
	 * treated case-sensitive?
	 *  HTTP URI's (3.2.3) [host and scheme are insensitive]
	 *  HTTP method (5.1.1)
	 *  HTTP-date values (3.3.1)
	 *  3.7 Media Types [exerpt]
	 *     The type, subtype, and parameter attribute names are case-
	 *     insensitive. Parameter values might or might not be case-sensitive,
	 *     depending on the semantics of the parameter name.
	 *  4.20 Except [exerpt]
	 *     Comparison of expectation values is case-insensitive for unquoted
	 *     tokens (including the 100-continue token), and is case-sensitive for
	 *     quoted-string expectation-extensions.
	 */

	for (i = 0, k = 0; i < varray->nelts; i++) {
		header = apr_table_get(headers, elts[i]);
		if (!header) {
			header = "";
		}
		iov[k].iov_base = (char*) elts[i];
		iov[k].iov_len = strlen(elts[i]);
		k++;
		iov[k].iov_base = (char*) header;
		iov[k].iov_len = strlen(header);
		k++;
	}
	iov[k].iov_base = (char*) oldkey;
	iov[k].iov_len = strlen(oldkey);
	k++;

	return apr_pstrcatv(p, iov, k, NULL);
}

static int array_alphasort(const void *fn1, const void *fn2) {
	return strcmp(*(char**) fn1, *(char**) fn2);
}

static void tokens_to_array(apr_pool_t *p, const char *data,
		apr_array_header_t *arr) {
	char *token;

	while ((token = ap_get_list_item(p, &data)) != NULL) {
		*((const char **) apr_array_push(arr)) = token;
	}

	/* Sort it so that "Vary: A, B" and "Vary: B, A" are stored the same. */
	qsort((void *) arr->elts, arr->nelts, sizeof(char *), array_alphasort);
}

/*
 * Hook and mod_cache callback functions
 */
int create_entity(cache_handle_t *h, request_rec *r, const char *key,
		apr_off_t len) {
	crccache_client_conf *conf = ap_get_module_config(r->server->module_config,
			&crccache_client_module);
	cache_object_t *obj;
	disk_cache_object_t *dobj;

	if (conf->cache_root == NULL) {
		return DECLINED;
	}

	/* Allocate and initialize cache_object_t and disk_cache_object_t */
	h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(*obj));
	obj->vobj = dobj = apr_pcalloc(r->pool, sizeof(*dobj));

	obj->key = apr_pstrdup(r->pool, key);

	dobj->name = obj->key;
	dobj->prefix = NULL;
	/* Save the cache root */
	dobj->root = apr_pstrndup(r->pool, conf->cache_root, conf->cache_root_len);
	dobj->root_len = conf->cache_root_len;
	dobj->datafile = data_file(r->pool, conf, dobj, key);
	dobj->hdrsfile = header_file(r->pool, conf, dobj, key);
	dobj->tempfile = apr_pstrcat(r->pool, conf->cache_root, AP_TEMPFILE, NULL);

	return OK;
}

int open_entity(cache_handle_t *h, request_rec *r, const char *key) {
	apr_uint32_t format;
	apr_size_t len;
	const char *nkey;
	apr_status_t rc;
	static int error_logged = 0;
	crccache_client_conf *conf = ap_get_module_config(r->server->module_config,
			&crccache_client_module);
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
					"disk_cache: Cannot cache files to disk without a CacheRootClient specified.");
        }
        return DECLINED;
    }

    /* Create and init the cache object */
    h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(cache_object_t));
    obj->vobj = dobj = apr_pcalloc(r->pool, sizeof(disk_cache_object_t));

    info = &(obj->info);

    /* Open the headers file */
    dobj->prefix = NULL;

    /* Save the cache root */
    dobj->root = apr_pstrndup(r->pool, conf->cache_root, conf->cache_root_len);
    dobj->root_len = conf->cache_root_len;

    dobj->hdrsfile = header_file(r->pool, conf, dobj, key);
    flags = APR_READ|APR_BINARY|APR_BUFFERED;
    rc = apr_file_open(&dobj->hfd, dobj->hdrsfile, flags, 0, r->pool);
    if (rc != APR_SUCCESS) {
        return DECLINED;
    }

    /* read the format from the cache file */
    len = sizeof(format);
    apr_file_read_full(dobj->hfd, &format, len, &len);

    if (format == VARY_FORMAT_VERSION) {
        apr_array_header_t* varray;
        apr_time_t expire;

        len = sizeof(expire);
        apr_file_read_full(dobj->hfd, &expire, len, &len);

        varray = apr_array_make(r->pool, 5, sizeof(char*));
        rc = read_array(r, varray, dobj->hfd);
        if (rc != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rc, r->server,
                         "disk_cache: Cannot parse vary header file: %s",
                         dobj->hdrsfile);
            return DECLINED;
        }
        apr_file_close(dobj->hfd);

        nkey = regen_key(r->pool, r->headers_in, varray, key);

        dobj->hashfile = NULL;
        dobj->prefix = dobj->hdrsfile;
        dobj->hdrsfile = header_file(r->pool, conf, dobj, nkey);

        flags = APR_READ|APR_BINARY|APR_BUFFERED;
        rc = apr_file_open(&dobj->hfd, dobj->hdrsfile, flags, 0, r->pool);
        if (rc != APR_SUCCESS) {
            return DECLINED;
        }
    }
    else if (format != DISK_FORMAT_VERSION) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "cache_disk: File '%s' has a version mismatch. File had version: %d.",
                     dobj->hdrsfile, format);
        return DECLINED;
    }
    else {
        apr_off_t offset = 0;
        /* This wasn't a Vary Format file, so we must seek to the
         * start of the file again, so that later reads work.
         */
        apr_file_seek(dobj->hfd, APR_SET, &offset);
        nkey = key;
    }

    obj->key = nkey;
    dobj->key = nkey;
    dobj->name = key;
    dobj->datafile = data_file(r->pool, conf, dobj, nkey);
    dobj->tempfile = apr_pstrcat(r->pool, conf->cache_root, AP_TEMPFILE, NULL);

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

    rc = apr_file_info_get(&finfo, APR_FINFO_SIZE, dobj->fd);
    if (rc == APR_SUCCESS) {
        dobj->file_size = finfo.size;
    }

    /* Read the bytes to setup the cache_info fields */
    rc = file_cache_recall_mydata(dobj->hfd, info, dobj, r);
    if (rc != APR_SUCCESS) {
        /* XXX log message */
        return DECLINED;
    }

    /* Initialize the cache_handle callback functions */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "disk_cache: Recalled cached URL info header %s",  dobj->name);
    return OK;
}

int remove_entity(cache_handle_t *h) {
	/* Null out the cache object pointer so next time we start from scratch  */
	h->cache_obj = NULL;

	return OK;
}

int remove_url(cache_handle_t *h, apr_pool_t *p) {
	apr_status_t rc;
	disk_cache_object_t *dobj;

	/* Get disk cache object from cache handle */
	dobj = (disk_cache_object_t *) h->cache_obj->vobj;
	if (!dobj) {
		return DECLINED;
	}

	/* Delete headers file */
	if (dobj->hdrsfile) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
		"disk_cache: Deleting %s from cache.", dobj->hdrsfile);

		rc = apr_file_remove(dobj->hdrsfile, p);
		if ((rc != APR_SUCCESS) && !APR_STATUS_IS_ENOENT(rc)) {
			/* Will only result in an output if httpd is started with -e debug.
			 * For reason see log_error_core for the case s == NULL.
			 */
			ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, NULL,
			"disk_cache: Failed to delete headers file %s from cache.",
			dobj->hdrsfile);
			return DECLINED;
		}
	}

	/* Delete data file */
	if (dobj->datafile) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
		"disk_cache: Deleting %s from cache.", dobj->datafile);

		rc = apr_file_remove(dobj->datafile, p);
		if ((rc != APR_SUCCESS) && !APR_STATUS_IS_ENOENT(rc)) {
			/* Will only result in an output if httpd is started with -e debug.
			 * For reason see log_error_core for the case s == NULL.
			 */
			ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, NULL,
			"disk_cache: Failed to delete data file %s from cache.",
			dobj->datafile);
			return DECLINED;
		}
	}

	/* now delete directories as far as possible up to our cache root */
	if (dobj->root) {
		const char *str_to_copy;

		str_to_copy = dobj->hdrsfile ? dobj->hdrsfile : dobj->datafile;
		if (str_to_copy) {
			char *dir, *slash, *q;

			dir = apr_pstrdup(p, str_to_copy);

			/* remove filename */
			slash = strrchr(dir, '/');
			*slash = '\0';

			/*
			 * now walk our way back to the cache root, delete everything
			 * in the way as far as possible
			 *
			 * Note: due to the way we constructed the file names in
			 * header_file and data_file, we are guaranteed that the
			 * cache_root is suffixed by at least one '/' which will be
			 * turned into a terminating null by this loop.  Therefore,
			 * we won't either delete or go above our cache root.
			 */
			for (q = dir + dobj->root_len; *q; ) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
				"disk_cache: Deleting directory %s from cache",
				dir);

				rc = apr_dir_remove(dir, p);
				if (rc != APR_SUCCESS && !APR_STATUS_IS_ENOENT(rc)) {
					break;
				}
				slash = strrchr(q, '/');
				*slash = '\0';
			}
		}
	}

	return OK;
}

apr_status_t read_array(request_rec *r, apr_array_header_t* arr,
		apr_file_t *file) {
	char w[MAX_STRING_LEN];
	int p;
	apr_status_t rv;

	while (1) {
		rv = apr_file_gets(w, MAX_STRING_LEN - 1, file);
		if (rv != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"Premature end of vary array.");
			return rv;
		}

		p = strlen(w);
		if (p> 0 && w[p - 1] == '\n') {
			if (p> 1 && w[p - 2] == CR) {
				w[p - 2] = '\0';
			}
			else {
				w[p - 1] = '\0';
			}
		}

		/* If we've finished reading the array, break out of the loop. */
		if (w[0] == '\0') {
			break;
		}

		*((const char **) apr_array_push(arr)) = apr_pstrdup(r->pool, w);
	}

	return APR_SUCCESS;
}

static apr_status_t store_array(apr_file_t *fd, apr_array_header_t* arr) {
	int i;
	apr_status_t rv;
	struct iovec iov[2];
	apr_size_t amt;
	const char **elts;

	elts = (const char **) arr->elts;

	for (i = 0; i < arr->nelts; i++) {
		iov[0].iov_base = (char*) elts[i];
		iov[0].iov_len = strlen(elts[i]);
		iov[1].iov_base = CRLF;
		iov[1].iov_len = sizeof(CRLF) - 1;

		rv = apr_file_writev(fd, (const struct iovec *) &iov, 2,
				&amt);
		if (rv != APR_SUCCESS) {
			return rv;
		}
	}

	iov[0].iov_base = CRLF;
	iov[0].iov_len = sizeof(CRLF) - 1;

	return apr_file_writev(fd, (const struct iovec *) &iov, 1,
			&amt);
}

apr_status_t read_table(cache_handle_t *handle, request_rec *r,
		apr_table_t *table, apr_file_t *file) {
	char w[MAX_STRING_LEN];
	char *l;
	int p;
	apr_status_t rv;

	while (1) {

		/* ### What about APR_EOF? */
		rv = apr_file_gets(w, MAX_STRING_LEN - 1, file);
		if (rv != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"Premature end of cache headers.");
			return rv;
		}

		/* Delete terminal (CR?)LF */

		p = strlen(w);
		/* Indeed, the host's '\n':
		 '\012' for UNIX; '\015' for MacOS; '\025' for OS/390
		 -- whatever the script generates.
		 */
		if (p> 0 && w[p - 1] == '\n') {
			if (p> 1 && w[p - 2] == CR) {
				w[p - 2] = '\0';
			}
			else {
				w[p - 1] = '\0';
			}
		}

		/* If we've finished reading the headers, break out of the loop. */
		if (w[0] == '\0') {
			break;
		}

#if APR_CHARSET_EBCDIC
			/* Chances are that we received an ASCII header text instead of
			 * the expected EBCDIC header lines. Try to auto-detect:
			 */
			if (!(l = strchr(w, ':'))) {
				int maybeASCII = 0, maybeEBCDIC = 0;
				unsigned char *cp, native;
				apr_size_t inbytes_left, outbytes_left;

				for (cp = w; *cp != '\0'; ++cp) {
					native = apr_xlate_conv_byte(ap_hdrs_from_ascii, *cp);
					if (apr_isprint(*cp) && !apr_isprint(native))
					++maybeEBCDIC;
					if (!apr_isprint(*cp) && apr_isprint(native))
					++maybeASCII;
				}
				if (maybeASCII> maybeEBCDIC) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
							"CGI Interface Error: Script headers apparently ASCII: (CGI = %s)",
                             r->filename);
                inbytes_left = outbytes_left = cp - w;
                apr_xlate_conv_buffer(ap_hdrs_from_ascii,
                                      w, &inbytes_left, w, &outbytes_left);
            }
        }
#endif /*APR_CHARSET_EBCDIC*/

        /* if we see a bogus header don't ignore it. Shout and scream */
        if (!(l = strchr(w, ':'))) {
            return APR_EGENERAL;
        }

        *l++ = '\0';
        while (*l && apr_isspace(*l)) {
            ++l;
        }

        apr_table_add(table, w, l);
    }

    return APR_SUCCESS;
}

/**
 * Clean-up memory used by helper libraries, that don't know about apr_palloc
 * and that (probably) use classical malloc/free
 */
apr_status_t deflate_ctx_cleanup(void *data)
{
	crccache_client_ctx *ctx = (crccache_client_ctx *)data;

	if (ctx != NULL)
	{
		if (ctx->decompression_state != DECOMPRESSION_ENDED)
		{
			inflateEnd(ctx->decompression_stream);
			ctx->decompression_state = DECOMPRESSION_ENDED;
		}
	}
	return APR_SUCCESS;
}


/*
 * Reads headers from a buffer and returns an array of headers.
 * Returns NULL on file error
 * This routine tries to deal with too long lines and continuation lines.
 * @@@: XXX: FIXME: currently the headers are passed thru un-merged.
 * Is that okay, or should they be collapsed where possible?
 */
apr_status_t recall_headers(cache_handle_t *h, request_rec *r) {
	const char *data;
	apr_size_t len;
	apr_bucket *e;
	unsigned i;
	int z_RC;

	disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;

	/* This case should not happen... */
	if (!dobj->hfd) {
		/* XXX log message */
		return APR_NOTFOUND;
	}

	h->req_hdrs = apr_table_make(r->pool, 20);
	h->resp_hdrs = apr_table_make(r->pool, 20);

	/* Call routine to read the header lines/status line */
	read_table(h, r, h->resp_hdrs, dobj->hfd);
	read_table(h, r, h->req_hdrs, dobj->hfd);

	// TODO: We only really want to add our block hashes if the cache is not fresh
	// TODO: We could achieve that by adding a filter here on sending the request
	// and then doing all of this in the filter 'JIT'
	e = apr_bucket_file_create(dobj->fd, 0, (apr_size_t) dobj->file_size, r->pool,
	r->connection->bucket_alloc);

	/* read */
	apr_bucket_read(e, &data, &len, APR_BLOCK_READ);

	// this will be rounded down, but thats okay
	// TODO: I think that we should just add %  to the trailing block, otherwise our extra block
	// is always limited to max of BLOCK_COUNT size.
	size_t blocksize = len/FULL_BLOCK_COUNT;
	size_t tail_block_size = len % FULL_BLOCK_COUNT;
	size_t block_count_including_final_block = FULL_BLOCK_COUNT + (tail_block_size != 0);
	// sanity check for very small files
	if (blocksize> 4)
	{
		//ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"crccache: %d blocks of %ld bytes",FULL_BLOCK_COUNT,blocksize);

		crccache_client_ctx * ctx;
		ctx = apr_pcalloc(r->pool, sizeof(*ctx));
		ctx->bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
		ctx->block_size = blocksize;
		ctx->tail_block_size = tail_block_size;
		ctx->state = DECODING_NEW_SECTION;
		ctx->cached_bucket = e;

		// Setup inflate for decompressing non-matched literal data
		ctx->decompression_stream = apr_palloc(r->pool, sizeof(*(ctx->decompression_stream)));
		ctx->decompression_stream->zalloc = Z_NULL;
		ctx->decompression_stream->zfree = Z_NULL;
		ctx->decompression_stream->opaque = Z_NULL;
		ctx->decompression_stream->avail_in = 0;
		ctx->decompression_stream->next_in = Z_NULL;
		z_RC = inflateInit(ctx->decompression_stream);
		if (z_RC != Z_OK)
		{
			ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server,
			"Can not initialize decompression engine, return code: %d", z_RC);
			return APR_SUCCESS;
		}
		ctx->decompression_state = DECOMPRESSION_INITIALIZED;

		// Register a cleanup function to cleanup internal libz resources
		apr_pool_cleanup_register(r->pool, ctx, deflate_ctx_cleanup,
                                  apr_pool_cleanup_null);

		// All OK to go for the crcsync decoding: add the headers
		// and set-up the decoding filter

		// add one for base 64 overflow and null terminator
		char hash_set[HASH_HEADER_SIZE+1];

		uint64_t crcs[block_count_including_final_block];
		crc_of_blocks(data, len, blocksize, HASH_SIZE, crcs);

		// swap to network byte order
		for (i = 0; i < block_count_including_final_block;++i)
		{
			htobe64(crcs[i]);
		}

		apr_base64_encode (hash_set, (char *)crcs, block_count_including_final_block*sizeof(crcs[0]));
		hash_set[HASH_HEADER_SIZE] = '\0';
		//apr_bucket_delete(e);

		// TODO; bit of a safety margin here, could calculate exact size
		const int block_header_max_size = HASH_HEADER_SIZE+32;
		char block_header_txt[block_header_max_size];
		snprintf(block_header_txt, block_header_max_size,"fs=%zu, h=%s",len,hash_set);
		apr_table_set(r->headers_in, BLOCK_HEADER, block_header_txt);
		// TODO: do we want to cache the hashes here?

		// initialise the context for our sha1 digest of the unencoded response
		EVP_MD_CTX_init(&ctx->mdctx);
		const EVP_MD *md = EVP_sha1();
		EVP_DigestInit_ex(&ctx->mdctx, md, NULL);

		// we want to add a filter here so that we can decode the response.
		// we need access to the original cached data when we get the response as
		// we need that to fill in the matched blocks.
		ap_add_output_filter_handle(crccache_decode_filter_handle,
		ctx, r, r->connection);

		// TODO: why is hfd file only closed in this case?
		apr_file_close(dobj->hfd);
	}
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
	"crccache_client: Recalled headers for URL %s", dobj->name);
	return APR_SUCCESS;
}

apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p,
		apr_bucket_brigade *bb) {
	apr_bucket *e;
	disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;

	e = apr_bucket_file_create(dobj->fd, 0, (apr_size_t) dobj->file_size, p,
			bb->bucket_alloc);

	APR_BRIGADE_INSERT_HEAD(bb, e);
	e = apr_bucket_eos_create(bb->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, e);

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,	"crccache_client: Recalled body for URL %s", dobj->name);
	return APR_SUCCESS;
}

apr_status_t store_table(apr_file_t *fd, apr_table_t *table) {
	int i;
	apr_status_t rv;
	struct iovec iov[4];
	apr_size_t amt;
	apr_table_entry_t *elts;

	elts = (apr_table_entry_t *) apr_table_elts(table)->elts;
	for (i = 0; i < apr_table_elts(table)->nelts; ++i) {
		if (elts[i].key != NULL) {
			iov[0].iov_base = elts[i].key;
			iov[0].iov_len = strlen(elts[i].key);
			iov[1].iov_base = ": ";
			iov[1].iov_len = sizeof(": ") - 1;
			iov[2].iov_base = elts[i].val;
			iov[2].iov_len = strlen(elts[i].val);
			iov[3].iov_base = CRLF;
			iov[3].iov_len = sizeof(CRLF) - 1;

			rv = apr_file_writev(fd, (const struct iovec *) &iov, 4,
					&amt);
			if (rv != APR_SUCCESS) {
				return rv;
			}
		}
	}
	iov[0].iov_base = CRLF;
	iov[0].iov_len = sizeof(CRLF) - 1;
	rv = apr_file_writev(fd, (const struct iovec *) &iov, 1,
			&amt);
	return rv;
}

apr_status_t store_headers(cache_handle_t *h, request_rec *r,
		cache_info *info) {
	crccache_client_conf *conf = ap_get_module_config(r->server->module_config,
			&crccache_client_module);

	apr_status_t rv;
	apr_size_t amt;
	disk_cache_object_t *dobj = (disk_cache_object_t*) h->cache_obj->vobj;

	disk_cache_info_t disk_info;
	struct iovec iov[2];

	/* This is flaky... we need to manage the cache_info differently */
	h->cache_obj->info = *info;

	if (r->headers_out) {
		const char *tmp;

		tmp = apr_table_get(r->headers_out, "Vary");

		if (tmp) {
			apr_array_header_t* varray;
			apr_uint32_t format = VARY_FORMAT_VERSION;

			/* If we were initially opened as a vary format, rollback
			 * that internal state for the moment so we can recreate the
			 * vary format hints in the appropriate directory.
			 */
			if (dobj->prefix) {
				dobj->hdrsfile = dobj->prefix;
				dobj->prefix = NULL;
			}

			mkdir_structure(conf, dobj->hdrsfile, r->pool);

			rv = apr_file_mktemp(&dobj->tfd, dobj->tempfile,
					APR_CREATE | APR_WRITE | APR_BINARY | APR_EXCL,
					r->pool);

			if (rv != APR_SUCCESS) {
				return rv;
			}

			amt = sizeof(format);
			apr_file_write(dobj->tfd, &format, &amt);

			amt = sizeof(info->expire);
			apr_file_write(dobj->tfd, &info->expire, &amt);

			varray = apr_array_make(r->pool, 6, sizeof(char*));
			tokens_to_array(r->pool, tmp, varray);

			store_array(dobj->tfd, varray);

			apr_file_close(dobj->tfd);

			dobj->tfd = NULL;

			rv = safe_file_rename(conf, dobj->tempfile, dobj->hdrsfile,
					r->pool);
			if (rv != APR_SUCCESS) {
				ap_log_error(APLOG_MARK, APLOG_WARNING, rv, r->server,
						"disk_cache: rename tempfile to varyfile failed: %s -> %s",
                    dobj->tempfile, dobj->hdrsfile);
                apr_file_remove(dobj->tempfile, r->pool);
                return rv;
            }

            dobj->tempfile = apr_pstrcat(r->pool, conf->cache_root, AP_TEMPFILE, NULL);
            tmp = regen_key(r->pool, r->headers_in, varray, dobj->name);
            dobj->prefix = dobj->hdrsfile;
            dobj->hashfile = NULL;
            dobj->datafile = data_file(r->pool, conf, dobj, tmp);
            dobj->hdrsfile = header_file(r->pool, conf, dobj, tmp);
        }
    }


    rv = apr_file_mktemp(&dobj->hfd, dobj->tempfile,
                         APR_CREATE | APR_WRITE | APR_BINARY |
                         APR_BUFFERED | APR_EXCL, r->pool);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    disk_info.format = DISK_FORMAT_VERSION;
    disk_info.date = info->date;
    disk_info.expire = info->expire;
    disk_info.entity_version = dobj->disk_info.entity_version++;
    disk_info.request_time = info->request_time;
    disk_info.response_time = info->response_time;
    disk_info.status = info->status;

    disk_info.name_len = strlen(dobj->name);

    iov[0].iov_base = (void*)&disk_info;
    iov[0].iov_len = sizeof(disk_cache_info_t);
    iov[1].iov_base = (void*)dobj->name;
    iov[1].iov_len = disk_info.name_len;

    rv = apr_file_writev(dobj->hfd, (const struct iovec *) &iov, 2, &amt);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if (r->headers_out) {
        apr_table_t *headers_out;

        headers_out = ap_cache_cacheable_hdrs_out(r->pool, r->headers_out,
                                                  r->server);

        if (!apr_table_get(headers_out, "Content-Type")
            && r->content_type) {
            apr_table_setn(headers_out, "Content-Type",
                           ap_make_content_type(r, r->content_type));
        }

        headers_out = apr_table_overlay(r->pool, headers_out,
                                        r->err_headers_out);
        rv = store_table(dobj->hfd, headers_out);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    /* Parse the vary header and dump those fields from the headers_in. */
    /* FIXME: Make call to the same thing cache_select calls to crack Vary. */
    if (r->headers_in) {
        apr_table_t *headers_in;

        headers_in = ap_cache_cacheable_hdrs_out(r->pool, r->headers_in,
                                                 r->server);
        rv = store_table(dobj->hfd, headers_in);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    apr_file_close(dobj->hfd); /* flush and close */

    /* Remove old file with the same name. If remove fails, then
     * perhaps we need to create the directory tree where we are
     * about to write the new headers file.
     */
    rv = apr_file_remove(dobj->hdrsfile, r->pool);
    if (rv != APR_SUCCESS) {
        mkdir_structure(conf, dobj->hdrsfile, r->pool);
    }

    rv = safe_file_rename(conf, dobj->tempfile, dobj->hdrsfile, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, r->server,
                     "disk_cache: rename tempfile to hdrsfile failed: %s -> %s",
                     dobj->tempfile, dobj->hdrsfile);
        apr_file_remove(dobj->tempfile, r->pool);
        return rv;
    }

    dobj->tempfile = apr_pstrcat(r->pool, conf->cache_root, AP_TEMPFILE, NULL);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "disk_cache: Stored headers for URL %s",  dobj->name);
    return APR_SUCCESS;
}

apr_status_t store_body(cache_handle_t *h, request_rec *r,
		apr_bucket_brigade *bb) {
	apr_bucket *e;
	apr_status_t rv;

	disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
	crccache_client_conf *conf = ap_get_module_config(r->server->module_config,
			&crccache_client_module);

	/* We write to a temp file and then atomically rename the file over
	 * in file_cache_el_final().
	 */
	if (!dobj->tfd) {
		rv = apr_file_mktemp(&dobj->tfd, dobj->tempfile, APR_CREATE | APR_WRITE
				| APR_BINARY | APR_BUFFERED | APR_EXCL, r->pool);
		if (rv != APR_SUCCESS) {
			return rv;
		}
		dobj->file_size = 0;
	}

	for (e = APR_BRIGADE_FIRST(bb); e != APR_BRIGADE_SENTINEL(bb); e = APR_BUCKET_NEXT(e)) {
		const char *str;
		apr_size_t length, written;
		rv = apr_bucket_read(e, &str, &length, APR_BLOCK_READ);
		if (rv != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			"cache_disk: Error when reading bucket for URL %s",
			h->cache_obj->key);
			/* Remove the intermediate cache file and return non-APR_SUCCESS */
			file_cache_errorcleanup(dobj, r);
			return rv;
		}
		rv = apr_file_write_full(dobj->tfd, str, length, &written);
		if (rv != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
					"cache_disk: Error when writing cache file for URL %s",
					h->cache_obj->key);
			/* Remove the intermediate cache file and return non-APR_SUCCESS */
			file_cache_errorcleanup(dobj, r);
			return rv;
		}
		dobj->file_size += written;
		if (dobj->file_size> conf->maxfs) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
					"cache_disk: URL %s failed the size check "
					"(%" APR_OFF_T_FMT " > %" APR_OFF_T_FMT ")",
					h->cache_obj->key, dobj->file_size, conf->maxfs);
			/* Remove the intermediate cache file and return non-APR_SUCCESS */
			file_cache_errorcleanup(dobj, r);
			return APR_EGENERAL;
		}
	}

	/* Was this the final bucket? If yes, close the temp file and perform
	 * sanity checks.
	 */
	if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
		if (r->connection->aborted || r->no_cache) {
			ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
					"disk_cache: Discarding body for URL %s "
					"because connection has been aborted.",
					h->cache_obj->key);
			/* Remove the intermediate cache file and return non-APR_SUCCESS */
			file_cache_errorcleanup(dobj, r);
			return APR_EGENERAL;
		}
		if (dobj->file_size < conf->minfs) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
					"cache_disk: URL %s failed the size check "
					"(%" APR_OFF_T_FMT " < %" APR_OFF_T_FMT ")",
					h->cache_obj->key, dobj->file_size, conf->minfs);
			/* Remove the intermediate cache file and return non-APR_SUCCESS */
			file_cache_errorcleanup(dobj, r);
			return APR_EGENERAL;
		}

		/* All checks were fine. Move tempfile to final destination */
		/* Link to the perm file, and close the descriptor */
		file_cache_el_final(dobj, r);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
				"disk_cache: Body for URL %s cached.", dobj->name);
	}

	return APR_SUCCESS;
}

/*
 * CACHE_DECODE filter
 * ----------------
 *
 * Deliver cached content (headers and body) up the stack.
 */
static int crccache_decode_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
	apr_bucket *e;
	request_rec *r = f->r;
	// TODO: set up context type struct
	crccache_client_ctx *ctx = f->ctx;

	// if this is the first pass in decoding we should check the headers etc
	// and fix up those headers that we modified as part of the encoding
	if (ctx->headers_checked == 0)
	{
		ctx->headers_checked = 1;

		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
				"CRCSYNC retuned status code (%d)", r->status);

		// TODO: make this work if we have multiple encodings
		const char * content_encoding;
		content_encoding = apr_table_get(r->headers_out, ENCODING_HEADER);
		if (content_encoding == NULL || strcmp(CRCCACHE_ENCODING, content_encoding)
				!= 0) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
			"CRCSYNC not decoding, content encoding bad (%s)", content_encoding?content_encoding:"NULL");
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}
		// TODO: Remove crcsync from the content encoding header

		// TODO: we should only set the status back to 200 if there are no
		// other instance codings used
		//r->status = 200;
		//r->status_line = "200 OK";


		// TODO: Fix up the etag as well
	}



	/* Do nothing if asked to filter nothing. */
	if (APR_BRIGADE_EMPTY(bb)) {
		return ap_pass_brigade(f->next, bb);
	}

	/* We require that we have a context already, otherwise we dont have our cached file
	 * to fill in the gaps with.
	 */
	if (!ctx) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
				"No context available %s", r->uri);
		ap_remove_output_filter(f);
		return ap_pass_brigade(f->next, bb);
	}

	while (!APR_BRIGADE_EMPTY(bb))
	{
		const char *data;
		apr_size_t len;

		e = APR_BRIGADE_FIRST(bb);

		if (APR_BUCKET_IS_EOS(e)) {

			/* Remove EOS from the old list, and insert into the new. */
			APR_BUCKET_REMOVE(e);
			APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

			/* This filter is done once it has served up its content */
			ap_remove_output_filter(f);

			// TODO: check strong hash here
			unsigned md_len;
			unsigned char md_value[EVP_MAX_MD_SIZE];
			EVP_DigestFinal_ex(&ctx->mdctx, md_value, &md_len);
			EVP_MD_CTX_cleanup(&ctx->mdctx);

			if (memcmp(md_value, ctx->md_value_rx, 20) != 0)
			{
				// TODO: Actually signal this to the user
				ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCSYNC-DECODE HASH CHECK FAILED");
			}
			else
			{
				ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCSYNC-DECODE HASH CHECK PASSED");
			}

			/* Okay, we've seen the EOS.
			 * Time to pass it along down the chain.
			 */
			return ap_pass_brigade(f->next, ctx->bb);
		}

		if (APR_BUCKET_IS_FLUSH(e)) {
			apr_status_t rv;

			/* Remove flush bucket from old brigade anf insert into the new. */
			APR_BUCKET_REMOVE(e);
			APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
			rv = ap_pass_brigade(f->next, ctx->bb);
			if (rv != APR_SUCCESS) {
				return rv;
			}
			continue;
		}

		if (APR_BUCKET_IS_METADATA(e)) {
			/*
			 * Remove meta data bucket from old brigade and insert into the
			 * new.
			 */
			APR_BUCKET_REMOVE(e);
			APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
			continue;
		}

		/* read */
		apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
		//ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCSYNC-DECODE read %zd bytes",len);

		apr_size_t consumed_bytes = 0;
		while (consumed_bytes < len)
		{
			//ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCSYNC-DECODE remaining %zd bytes",len - consumed_bytes);
			// no guaruntee that our buckets line up with our encoding sections
			// so we need a processing state machine stored in our context
			switch (ctx->state)
			{
				case DECODING_NEW_SECTION:
				{
					// check if we have a compressed section or a block section
					if (data[consumed_bytes] == ENCODING_COMPRESSED)
						ctx->state = DECODING_COMPRESSED;
					else if (data[consumed_bytes] == ENCODING_BLOCK)
						ctx->state = DECODING_BLOCK_HEADER;
					else if (data[consumed_bytes] == ENCODING_LITERAL)
						ctx->state = DECODING_LITERAL;
					else if (data[consumed_bytes] == ENCODING_HASH)
					{
						ctx->state = DECODING_HASH;
						ctx->md_value_rx_count = 0;
					}
					else
					{
						ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server,
								"CRCSYNC-DECODE, unknown section %d(%c)",data[consumed_bytes],data[consumed_bytes]);
						apr_brigade_cleanup(bb);
						return APR_EGENERAL;
					}
					//ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCSYNC-DECODE found a new section %d",ctx->state);
					consumed_bytes++;
					break;
				}
				case DECODING_BLOCK_HEADER:
				{
					unsigned char block_number = data[consumed_bytes];
					consumed_bytes++;
					ctx->state = DECODING_NEW_SECTION;

					// TODO: Output the indicated block here
					size_t current_block_size = block_number < FULL_BLOCK_COUNT ? ctx->block_size : ctx->tail_block_size;
					ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
							"CRCSYNC-DECODE block section, block %d, size %zu" ,block_number, current_block_size);

					char * buf = apr_palloc(r->pool, current_block_size);
					const char * source_data;
					size_t source_len;
					apr_bucket_read(ctx->cached_bucket, &source_data, &source_len, APR_BLOCK_READ);
					assert(block_number < (FULL_BLOCK_COUNT + (ctx->tail_block_size != 0)));
					memcpy(buf,&source_data[block_number*ctx->block_size],current_block_size);
					// update our sha1 hash
					EVP_DigestUpdate(&ctx->mdctx, buf, current_block_size);
					apr_bucket * b = apr_bucket_pool_create(buf, current_block_size, r->pool, f->c->bucket_alloc);
					APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
					break;
				}
				case DECODING_HASH:
				{
					unsigned avail_in = len - consumed_bytes;
					// 20 bytes for an SHA1 hash
					unsigned needed = MIN(20-ctx->md_value_rx_count, avail_in);
					memcpy(&ctx->md_value_rx[ctx->md_value_rx_count], &data[consumed_bytes],needed);
					ctx->md_value_rx_count+=needed;
					consumed_bytes += needed;
					if (ctx->md_value_rx_count == 20)
					{
						ctx->state = DECODING_NEW_SECTION;
					}
					break;
				}
				case DECODING_COMPRESSED:
				{
					unsigned char decompressed_data_buf[30000];
					int z_RC;
					z_stream *strm = ctx->decompression_stream;
					strm->avail_in = len - consumed_bytes;
					strm->next_in = (Bytef *)(data + consumed_bytes);
					// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "CRCSYNC-DECODE inflating %d bytes", strm.avail_in);
					// ap_log_hex(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, strm.next_in, strm.avail_in);
					do {
						strm->avail_out = sizeof(decompressed_data_buf);
						strm->next_out = decompressed_data_buf;
						uInt avail_in_pre_inflate = strm->avail_in;
						z_RC = inflate(strm, Z_NO_FLUSH);
						if (z_RC == Z_NEED_DICT || z_RC == Z_DATA_ERROR || z_RC == Z_MEM_ERROR)
						{
							ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r->server, "CRCSYNC-DECODE inflate error: %d", z_RC);
							apr_brigade_cleanup(bb);
							return APR_EGENERAL;
						}
						int have = sizeof(decompressed_data_buf) - strm->avail_out;
						ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
								"CRCSYNC-DECODE inflate rslt %d, consumed %d, produced %d",
								z_RC, avail_in_pre_inflate - strm->avail_in, have);
						if (have)
						{
							// write output data
							char * buf = apr_palloc(r->pool, have);
							memcpy(buf,decompressed_data_buf,have);
							EVP_DigestUpdate(&ctx->mdctx, buf, have);
							apr_bucket * b = apr_bucket_pool_create(buf, have, r->pool, f->c->bucket_alloc);
							APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
						}
					} while (strm->avail_out == 0);
					consumed_bytes = len - strm->avail_in;
					if (z_RC == Z_STREAM_END)
					{
						ctx->state = DECODING_NEW_SECTION;
						inflateReset(strm);
					}
					break;
				}
				default:
				{
					ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server,
							"CRCSYNC-DECODE, unknown state %d, terminating transaction",ctx->state);
					apr_brigade_cleanup(bb);
					return APR_EGENERAL; // TODO: figure out how to pass the error on to the client
				}
			}
			APR_BUCKET_REMOVE(e);
		}
	}

	apr_brigade_cleanup(bb);
	return APR_SUCCESS;
}

static void *create_config(apr_pool_t *p, server_rec *s) {
	crccache_client_conf *conf = apr_pcalloc(p, sizeof(crccache_client_conf));
    /* array of URL prefixes for which caching is enabled */
    conf->cacheenable = apr_array_make(p, 10, sizeof(struct cache_enable));
    /* array of URL prefixes for which caching is enabled */
    conf->cacheenable = apr_array_make(p, 10, sizeof(struct cache_enable));
    /* array of URL prefixes for which caching is disabled */
    conf->cachedisable = apr_array_make(p, 10, sizeof(struct cache_disable));
    /* maximum time to cache a document */
    conf->maxex = DEFAULT_CACHE_MAXEXPIRE;
    conf->maxex_set = 0;
    conf->minex = DEFAULT_CACHE_MINEXPIRE;
    conf->minex_set = 0;
    /* default time to cache a document */
    conf->defex = DEFAULT_CACHE_EXPIRE;
    conf->defex_set = 0;
    /* factor used to estimate Expires date from LastModified date */
    conf->factor = DEFAULT_CACHE_LMFACTOR;
    conf->factor_set = 0;
    conf->no_last_mod_ignore_set = 0;
    conf->no_last_mod_ignore = 0;
    conf->ignorecachecontrol = 0;
    conf->ignorecachecontrol_set = 0;
    conf->store_private = 0;
    conf->store_private_set = 0;
    conf->store_nostore = 0;
    conf->store_nostore_set = 0;
    /* array of headers that should not be stored in cache */
    conf->ignore_headers = apr_array_make(p, 10, sizeof(char *));
    conf->ignore_headers_set = CACHE_IGNORE_HEADERS_UNSET;
    /* flag indicating that query-string should be ignored when caching */
    conf->ignorequerystring = 0;
    conf->ignorequerystring_set = 0;

	/* XXX: Set default values */
	conf->dirlevels = DEFAULT_DIRLEVELS;
	conf->dirlength = DEFAULT_DIRLENGTH;
	conf->maxfs = DEFAULT_MAX_FILE_SIZE;
	conf->minfs = DEFAULT_MIN_FILE_SIZE;

	conf->cache_root = NULL;
	conf->cache_root_len = 0;

	return conf;
}

/*
 * mod_disk_cache configuration directives handlers.
 */
static const char *set_cache_root(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	crccache_client_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_client_module);
	conf->cache_root = arg;
	conf->cache_root_len = strlen(arg);
	/* TODO: canonicalize cache_root and strip off any trailing slashes */

	return NULL;
}

/*
 * Consider eliminating the next two directives in favor of
 * Ian's prime number hash...
 * key = hash_fn( r->uri)
 * filename = "/key % prime1 /key %prime2/key %prime3"
 */
static const char *set_cache_dirlevels(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	crccache_client_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_client_module);
	int val = atoi(arg);
	if (val < 1)
		return "CacheDirLevelsClient value must be an integer greater than 0";
	if (val * conf->dirlength > CACHEFILE_LEN)
		return "CacheDirLevelsClient*CacheDirLengthClient value must not be higher than 20";
	conf->dirlevels = val;
	return NULL;
}
static const char *set_cache_dirlength(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	crccache_client_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_client_module);
	int val = atoi(arg);
	if (val < 1)
		return "CacheDirLengthClient value must be an integer greater than 0";
	if (val * conf->dirlevels > CACHEFILE_LEN)
		return "CacheDirLevelsClient*CacheDirLengthClient value must not be higher than 20";

	conf->dirlength = val;
	return NULL;
}

static const char *set_cache_minfs(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	crccache_client_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_client_module);

	if (apr_strtoff(&conf->minfs, arg, NULL, 0) != APR_SUCCESS || conf->minfs
			< 0) {
		return "CacheMinFileSizeClient argument must be a non-negative integer representing the min size of a file to cache in bytes.";
	}
	return NULL;
}

static const char *set_cache_maxfs(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	crccache_client_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_client_module);
	if (apr_strtoff(&conf->maxfs, arg, NULL, 0) != APR_SUCCESS || conf->maxfs
			< 0) {
		return "CacheMaxFileSizeClient argument must be a non-negative integer representing the max size of a file to cache in bytes.";
	}
	return NULL;
}

static const char *add_crc_client_enable(cmd_parms *parms, void *dummy,
                                    const char *type,
                                    const char *url)
{
	crccache_client_conf *conf;
    struct cache_enable *new;

    if (*type == '/') {
        return apr_psprintf(parms->pool,
          "provider (%s) starts with a '/'.  Are url and provider switched?",
          type);
    }

    conf =
        (crccache_client_conf *)ap_get_module_config(parms->server->module_config,
                                                  &crccache_client_module);
    new = apr_array_push(conf->cacheenable);
    new->type = type;
    if (apr_uri_parse(parms->pool, url, &(new->url))) {
        return NULL;
    }
    if (new->url.path) {
        new->pathlen = strlen(new->url.path);
    } else {
        new->pathlen = 1;
        new->url.path = "/";
    }
    return NULL;
}

static const command_rec disk_cache_cmds[] =
{
    AP_INIT_TAKE2("CRCClientEnable", add_crc_client_enable, NULL, RSRC_CONF, "A cache type and partial URL prefix below which caching is enabled"),
	AP_INIT_TAKE1("CacheRootClient", set_cache_root, NULL, RSRC_CONF,"The directory to store cache files"),
	AP_INIT_TAKE1("CacheDirLevelsClient", set_cache_dirlevels, NULL, RSRC_CONF, "The number of levels of subdirectories in the cache"),
	AP_INIT_TAKE1("CacheDirLengthClient", set_cache_dirlength, NULL, RSRC_CONF, "The number of characters in subdirectory names"),
	AP_INIT_TAKE1("CacheMinFileSizeClient", set_cache_minfs, NULL, RSRC_CONF, "The minimum file size to cache a document"),
	AP_INIT_TAKE1("CacheMaxFileSizeClient", set_cache_maxfs, NULL, RSRC_CONF, "The maximum file size to cache a document"),
	{ NULL }
};

int ap_run_insert_filter(request_rec *r);

int cache_url_handler(request_rec *r, int lookup)
{
    apr_status_t rv;
    const char *auth;
    cache_request_rec *cache;
    crccache_client_conf *conf;
    apr_bucket_brigade *out;
    ap_filter_t *next;
    ap_filter_rec_t *cache_out_handle;

    /* Delay initialization until we know we are handling a GET */
    if (r->method_number != M_GET) {
        return DECLINED;
    }

    conf = (crccache_client_conf *) ap_get_module_config(r->server->module_config,
                                                      &crccache_client_module);

    /* make space for the per request config */
    cache = (cache_request_rec *) ap_get_module_config(r->request_config,
                                                       &crccache_client_module);
    if (!cache) {
        cache = apr_pcalloc(r->pool, sizeof(cache_request_rec));
        ap_set_module_config(r->request_config, &crccache_client_module, cache);
    }

    /*
     * Are we allowed to serve cached info at all?
     */

    /* find certain cache controlling headers */
    auth = apr_table_get(r->headers_in, "Authorization");

    /* First things first - does the request allow us to return
     * cached information at all? If not, just decline the request.
     */
    if (auth) {
        return DECLINED;
    }

    /*
     * Try to serve this request from the cache.
     *
     * If no existing cache file (DECLINED)
     *   add cache_save filter
     * If cached file (OK)
     *   clear filter stack
     *   add cache_out filter
     *   return OK
     */
    rv = cache_select(r);
    if (rv != OK) {
        if (rv == DECLINED) {
            if (!lookup) {

                /*
                 * Add cache_save filter to cache this request. Choose
                 * the correct filter by checking if we are a subrequest
                 * or not.
                 */
                if (r->main) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                                 r->server,
                                 "Adding CACHE_SAVE_SUBREQ filter for %s",
                                 r->uri);
                    ap_add_output_filter_handle(cache_save_subreq_filter_handle,
                                                NULL, r, r->connection);
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                                 r->server, "Adding CACHE_SAVE filter for %s",
                                 r->uri);
                    ap_add_output_filter_handle(cache_save_filter_handle,
                                                NULL, r, r->connection);
                }

                ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
                             "Adding CACHE_REMOVE_URL filter for %s",
                             r->uri);

                /* Add cache_remove_url filter to this request to remove a
                 * stale cache entry if needed. Also put the current cache
                 * request rec in the filter context, as the request that
                 * is available later during running the filter maybe
                 * different due to an internal redirect.
                 */
                cache->remove_url_filter =
                    ap_add_output_filter_handle(cache_remove_url_filter_handle,
                                                cache, r, r->connection);
            }
            else {
                if (cache->stale_headers) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                                 r->server, "Restoring request headers for %s",
                                 r->uri);

                    r->headers_in = cache->stale_headers;
                }

                /* Delete our per-request configuration. */
                ap_set_module_config(r->request_config, &crccache_client_module, NULL);
            }
        }
        else {
            /* error */
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                         "cache: error returned while checking for cached "
                         "file by cache");
        }
        return DECLINED;
    }

    /* if we are a lookup, we are exiting soon one way or another; Restore
     * the headers. */
    if (lookup) {
        if (cache->stale_headers) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
                         "Restoring request headers.");
            r->headers_in = cache->stale_headers;
        }

        /* Delete our per-request configuration. */
        ap_set_module_config(r->request_config, &crccache_client_module, NULL);
    }

    rv = ap_meets_conditions(r);
    if (rv != OK) {
        /* If we are a lookup, we have to return DECLINED as we have no
         * way of knowing if we will be able to serve the content.
         */
        if (lookup) {
            return DECLINED;
        }

        /* Return cached status. */
        return rv;
    }

    /* If we're a lookup, we can exit now instead of serving the content. */
    if (lookup) {
        return OK;
    }

    /* Serve up the content */

    /* We are in the quick handler hook, which means that no output
     * filters have been set. So lets run the insert_filter hook.
     */
    ap_run_insert_filter(r);

    /*
     * Add cache_out filter to serve this request. Choose
     * the correct filter by checking if we are a subrequest
     * or not.
     */
    if (r->main) {
        cache_out_handle = cache_out_subreq_filter_handle;
    }
    else {
        cache_out_handle = cache_out_filter_handle;
    }
    ap_add_output_filter_handle(cache_out_handle, NULL, r, r->connection);

    /*
     * Remove all filters that are before the cache_out filter. This ensures
     * that we kick off the filter stack with our cache_out filter being the
     * first in the chain. This make sense because we want to restore things
     * in the same manner as we saved them.
     * There may be filters before our cache_out filter, because
     *
     * 1. We call ap_set_content_type during cache_select. This causes
     *    Content-Type specific filters to be added.
     * 2. We call the insert_filter hook. This causes filters e.g. like
     *    the ones set with SetOutputFilter to be added.
     */
    next = r->output_filters;
    while (next && (next->frec != cache_out_handle)) {
        ap_remove_output_filter(next);
        next = next->next;
    }

    /* kick off the filter stack */
    out = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    rv = ap_pass_brigade(r->output_filters, out);
    if (rv != APR_SUCCESS) {
        if (rv != AP_FILTER_ERROR) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, r->server,
                         "cache: error returned while trying to return "
                         "cached data");
        }
        return rv;
    }

    return OK;
}



/*
 * CACHE_OUT filter
 * ----------------
 *
 * Deliver cached content (headers and body) up the stack.
 */
int cache_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    request_rec *r = f->r;
    cache_request_rec *cache;

    cache = (cache_request_rec *) ap_get_module_config(r->request_config,
                                                       &crccache_client_module);

    if (!cache) {
        /* user likely configured CACHE_OUT manually; they should use mod_cache
         * configuration to do that */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                     "CACHE_OUT enabled unexpectedly");
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
                 "cache: running CACHE_OUT filter");

    /* restore status of cached response */
    /* XXX: This exposes a bug in mem_cache, since it does not
     * restore the status into it's handle. */
    r->status = cache->handle->cache_obj->info.status;

    /* recall_headers() was called in cache_select() */
    recall_body(cache->handle, r->pool, bb);

    /* This filter is done once it has served up its content */
    ap_remove_output_filter(f);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
                 "cache: serving %s", r->uri);
    return ap_pass_brigade(f->next, bb);
}


/*
 * CACHE_SAVE filter
 * ---------------
 *
 * Decide whether or not this content should be cached.
 * If we decide no it should not:
 *   remove the filter from the chain
 * If we decide yes it should:
 *   Have we already started saving the response?
 *      If we have started, pass the data to the storage manager via store_body
 *      Otherwise:
 *        Check to see if we *can* save this particular response.
 *        If we can, call cache_create_entity() and save the headers and body
 *   Finally, pass the data to the next filter (the network or whatever)
 */

int cache_save_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    int rv = !OK;
    request_rec *r = f->r;
    cache_request_rec *cache;
    crccache_client_conf *conf;
    const char *cc_out, *cl;
    const char *exps, *lastmods, *dates, *etag;
    apr_time_t exp, date, lastmod, now;
    apr_off_t size;
    cache_info *info = NULL;
    char *reason;
    apr_pool_t *p;

    conf = (crccache_client_conf *) ap_get_module_config(r->server->module_config,
                                                      &crccache_client_module);

    /* Setup cache_request_rec */
    cache = (cache_request_rec *) ap_get_module_config(r->request_config,
                                                       &crccache_client_module);
    if (!cache) {
        /* user likely configured CACHE_SAVE manually; they should really use
         * mod_cache configuration to do that
         */
        cache = apr_pcalloc(r->pool, sizeof(cache_request_rec));
        ap_set_module_config(r->request_config, &crccache_client_module, cache);
    }

    reason = NULL;
    p = r->pool;
    /*
     * Pass Data to Cache
     * ------------------
     * This section passes the brigades into the cache modules, but only
     * if the setup section (see below) is complete.
     */
    if (cache->block_response) {
        /* We've already sent down the response and EOS.  So, ignore
         * whatever comes now.
         */
        return APR_SUCCESS;
    }

    /* have we already run the cachability check and set up the
     * cached file handle?
     */
    if (cache->in_checked) {
        /* pass the brigades into the cache, then pass them
         * up the filter stack
         */
        rv = store_body(cache->handle, r, in);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                         "cache: Cache provider's store_body failed!");
            ap_remove_output_filter(f);
        }
        return ap_pass_brigade(f->next, in);
    }

    /*
     * Setup Data in Cache
     * -------------------
     * This section opens the cache entity and sets various caching
     * parameters, and decides whether this URL should be cached at
     * all. This section is* run before the above section.
     */

    /* read expiry date; if a bad date, then leave it so the client can
     * read it
     */
    exps = apr_table_get(r->err_headers_out, "Expires");
    if (exps == NULL) {
        exps = apr_table_get(r->headers_out, "Expires");
    }
    if (exps != NULL) {
        if (APR_DATE_BAD == (exp = apr_date_parse_http(exps))) {
            exps = NULL;
        }
    }
    else {
        exp = APR_DATE_BAD;
    }

    /* read the last-modified date; if the date is bad, then delete it */
    lastmods = apr_table_get(r->err_headers_out, "Last-Modified");
    if (lastmods == NULL) {
        lastmods = apr_table_get(r->headers_out, "Last-Modified");
    }
    if (lastmods != NULL) {
        lastmod = apr_date_parse_http(lastmods);
        if (lastmod == APR_DATE_BAD) {
            lastmods = NULL;
        }
    }
    else {
        lastmod = APR_DATE_BAD;
    }

    /* read the etag and cache-control from the entity */
    etag = apr_table_get(r->err_headers_out, "Etag");
    if (etag == NULL) {
        etag = apr_table_get(r->headers_out, "Etag");
    }
    cc_out = apr_table_get(r->err_headers_out, "Cache-Control");
    if (cc_out == NULL) {
        cc_out = apr_table_get(r->headers_out, "Cache-Control");
    }

    /*
     * what responses should we not cache?
     *
     * At this point we decide based on the response headers whether it
     * is appropriate _NOT_ to cache the data from the server. There are
     * a whole lot of conditions that prevent us from caching this data.
     * They are tested here one by one to be clear and unambiguous.
     */
    if (r->status != HTTP_OK && r->status != HTTP_NON_AUTHORITATIVE
        && r->status != HTTP_MULTIPLE_CHOICES
        && r->status != HTTP_MOVED_PERMANENTLY
        && r->status != HTTP_NOT_MODIFIED) {
        /* RFC2616 13.4 we are allowed to cache 200, 203, 206, 300, 301 or 410
         * We don't cache 206, because we don't (yet) cache partial responses.
         * We include 304 Not Modified here too as this is the origin server
         * telling us to serve the cached copy.
         */
        if (exps != NULL || cc_out != NULL) {
            /* We are also allowed to cache any response given that it has a
             * valid Expires or Cache Control header. If we find a either of
             * those here,  we pass request through the rest of the tests. From
             * the RFC:
             *
             * A response received with any other status code (e.g. status
             * codes 302 and 307) MUST NOT be returned in a reply to a
             * subsequent request unless there are cache-control directives or
             * another header(s) that explicitly allow it. For example, these
             * include the following: an Expires header (section 14.21); a
             * "max-age", "s-maxage",  "must-revalidate", "proxy-revalidate",
             * "public" or "private" cache-control directive (section 14.9).
             */
        }
        else {
            reason = apr_psprintf(p, "Response status %d", r->status);
        }
    }

    if (reason) {
        /* noop */
    }
    else if (exps != NULL && exp == APR_DATE_BAD) {
        /* if a broken Expires header is present, don't cache it */
        reason = apr_pstrcat(p, "Broken expires header: ", exps, NULL);
    }
    else if (exp != APR_DATE_BAD && exp < r->request_time)
    {
        /* if a Expires header is in the past, don't cache it */
        reason = "Expires header already expired, not cacheable";
    }
    else if (!conf->ignorequerystring && r->parsed_uri.query && exps == NULL &&
             !ap_cache_liststr(NULL, cc_out, "max-age", NULL)) {
        /* if a query string is present but no explicit expiration time,
         * don't cache it (RFC 2616/13.9 & 13.2.1)
         */
        reason = "Query string present but no explicit expiration time";
    }
    else if (r->status == HTTP_NOT_MODIFIED &&
             !cache->handle && !cache->stale_handle) {
        /* if the server said 304 Not Modified but we have no cache
         * file - pass this untouched to the user agent, it's not for us.
         */
        reason = "HTTP Status 304 Not Modified";
    }
    else if (r->status == HTTP_OK && lastmods == NULL && etag == NULL
             && (exps == NULL) && (conf->no_last_mod_ignore ==0)) {
        /* 200 OK response from HTTP/1.0 and up without Last-Modified,
         * Etag, or Expires headers.
         */
        /* Note: mod-include clears last_modified/expires/etags - this
         * is why we have an optional function for a key-gen ;-)
         */
        reason = "No Last-Modified, Etag, or Expires headers";
    }
    else if (r->header_only && !cache->stale_handle) {
        /* Forbid HEAD requests unless we have it cached already */
        reason = "HTTP HEAD request";
    }
    else if (!conf->store_nostore &&
             ap_cache_liststr(NULL, cc_out, "no-store", NULL)) {
        /* RFC2616 14.9.2 Cache-Control: no-store response
         * indicating do not cache, or stop now if you are
         * trying to cache it.
         */
        /* FIXME: The Cache-Control: no-store could have come in on a 304,
         * FIXME: while the original request wasn't conditional.  IOW, we
         * FIXME:  made the the request conditional earlier to revalidate
         * FIXME: our cached response.
         */
        reason = "Cache-Control: no-store present";
    }
    else if (!conf->store_private &&
             ap_cache_liststr(NULL, cc_out, "private", NULL)) {
        /* RFC2616 14.9.1 Cache-Control: private response
         * this object is marked for this user's eyes only. Behave
         * as a tunnel.
         */
        /* FIXME: See above (no-store) */
        reason = "Cache-Control: private present";
    }
    else if (apr_table_get(r->headers_in, "Authorization") != NULL
             && !(ap_cache_liststr(NULL, cc_out, "s-maxage", NULL)
                  || ap_cache_liststr(NULL, cc_out, "must-revalidate", NULL)
                  || ap_cache_liststr(NULL, cc_out, "public", NULL))) {
        /* RFC2616 14.8 Authorisation:
         * if authorisation is included in the request, we don't cache,
         * but we can cache if the following exceptions are true:
         * 1) If Cache-Control: s-maxage is included
         * 2) If Cache-Control: must-revalidate is included
         * 3) If Cache-Control: public is included
         */
        reason = "Authorization required";
    }
    else if (ap_cache_liststr(NULL,
                              apr_table_get(r->headers_out, "Vary"),
                              "*", NULL)) {
        reason = "Vary header contains '*'";
    }
    else if (apr_table_get(r->subprocess_env, "no-cache") != NULL) {
        reason = "environment variable 'no-cache' is set";
    }
    else if (r->no_cache) {
        /* or we've been asked not to cache it above */
        reason = "r->no_cache present";
    }

    if (reason) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "cache: %s not cached. Reason: %s", r->unparsed_uri,
                     reason);

        /* remove this filter from the chain */
        ap_remove_output_filter(f);

        /* ship the data up the stack */
        return ap_pass_brigade(f->next, in);
    }

    /* Make it so that we don't execute this path again. */
    cache->in_checked = 1;

    /* Set the content length if known.
     */
    cl = apr_table_get(r->err_headers_out, "Content-Length");
    if (cl == NULL) {
        cl = apr_table_get(r->headers_out, "Content-Length");
    }
    if (cl) {
        char *errp;
        if (apr_strtoff(&size, cl, &errp, 10) || *errp || size < 0) {
            cl = NULL; /* parse error, see next 'if' block */
        }
    }

    if (!cl) {
        /* if we don't get the content-length, see if we have all the
         * buckets and use their length to calculate the size
         */
        apr_bucket *e;
        int all_buckets_here=0;
        int unresolved_length = 0;
        size=0;
        for (e = APR_BRIGADE_FIRST(in);
             e != APR_BRIGADE_SENTINEL(in);
             e = APR_BUCKET_NEXT(e))
        {
            if (APR_BUCKET_IS_EOS(e)) {
                all_buckets_here=1;
                break;
            }
            if (APR_BUCKET_IS_FLUSH(e)) {
                unresolved_length = 1;
                continue;
            }
            if (e->length == (apr_size_t)-1) {
                break;
            }
            size += e->length;
        }
        if (!all_buckets_here) {
            size = -1;
        }
    }

    /* It's safe to cache the response.
     *
     * There are two possiblities at this point:
     * - cache->handle == NULL. In this case there is no previously
     * cached entity anywhere on the system. We must create a brand
     * new entity and store the response in it.
     * - cache->stale_handle != NULL. In this case there is a stale
     * entity in the system which needs to be replaced by new
     * content (unless the result was 304 Not Modified, which means
     * the cached entity is actually fresh, and we should update
     * the headers).
     */

    /* Did we have a stale cache entry that really is stale?
     *
     * Note that for HEAD requests, we won't get the body, so for a stale
     * HEAD request, we don't remove the entity - instead we let the
     * CACHE_REMOVE_URL filter remove the stale item from the cache.
     */
    if (cache->stale_handle) {
        if (r->status == HTTP_NOT_MODIFIED) {
            /* Oh, hey.  It isn't that stale!  Yay! */
            cache->handle = cache->stale_handle;
            info = &cache->handle->cache_obj->info;
            rv = OK;
        }
        else if (!r->header_only) {
            /* Oh, well.  Toss it. */
            remove_entity(cache->stale_handle);
            /* Treat the request as if it wasn't conditional. */
            cache->stale_handle = NULL;
            /*
             * Restore the original request headers as they may be needed
             * by further output filters like the byterange filter to make
             * the correct decisions.
             */
            r->headers_in = cache->stale_headers;
        }
    }

    /* no cache handle, create a new entity only for non-HEAD requests */
    if (!cache->handle && !r->header_only) {
        rv = cache_create_entity(r, size);
        info = apr_pcalloc(r->pool, sizeof(cache_info));
        /* We only set info->status upon the initial creation. */
        info->status = r->status;
    }

    if (rv != OK) {
        /* Caching layer declined the opportunity to cache the response */
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, in);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "cache: Caching url: %s", r->unparsed_uri);

    /* We are actually caching this response. So it does not
     * make sense to remove this entity any more.
     */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "cache: Removing CACHE_REMOVE_URL filter.");
    ap_remove_output_filter(cache->remove_url_filter);

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
    dates = apr_table_get(r->err_headers_out, "Date");
    if (dates == NULL) {
        dates = apr_table_get(r->headers_out, "Date");
    }
    if (dates != NULL) {
        info->date = apr_date_parse_http(dates);
    }
    else {
        info->date = APR_DATE_BAD;
    }

    now = apr_time_now();
    if (info->date == APR_DATE_BAD) {  /* No, or bad date */
        /* no date header (or bad header)! */
        info->date = now;
    }
    date = info->date;

    /* set response_time for HTTP/1.1 age calculations */
    info->response_time = now;

    /* get the request time */
    info->request_time = r->request_time;

    /* check last-modified date */
    if (lastmod != APR_DATE_BAD && lastmod > date) {
        /* if it's in the future, then replace by date */
        lastmod = date;
        lastmods = dates;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
                     r->server,
                     "cache: Last modified is in the future, "
                     "replacing with now");
    }

    /* if no expiry date then
     *   if Cache-Control: max-age
     *      expiry date = date + max-age
     *   else if lastmod
     *      expiry date = date + min((date - lastmod) * factor, maxexpire)
     *   else
     *      expire date = date + defaultexpire
     */
    if (exp == APR_DATE_BAD) {
        char *max_age_val;

        if (ap_cache_liststr(r->pool, cc_out, "max-age", &max_age_val) &&
            max_age_val != NULL) {
            apr_int64_t x;

            errno = 0;
            x = apr_atoi64(max_age_val);
            if (errno) {
                x = conf->defex;
            }
            else {
                x = x * MSEC_ONE_SEC;
            }
            if (x < conf->minex) {
                x = conf->minex;
            }
            if (x > conf->maxex) {
                x = conf->maxex;
            }
            exp = date + x;
        }
        else if ((lastmod != APR_DATE_BAD) && (lastmod < date)) {
            /* if lastmod == date then you get 0*conf->factor which results in
             * an expiration time of now. This causes some problems with
             * freshness calculations, so we choose the else path...
             */
            apr_time_t x = (apr_time_t) ((date - lastmod) * conf->factor);

            if (x < conf->minex) {
                x = conf->minex;
            }
            if (x > conf->maxex) {
                x = conf->maxex;
            }
            exp = date + x;
        }
        else {
            exp = date + conf->defex;
        }
    }
    info->expire = exp;

    /* We found a stale entry which wasn't really stale. */
    if (cache->stale_handle) {
        /* Load in the saved status and clear the status line. */
        r->status = info->status;
        r->status_line = NULL;

        /* RFC 2616 10.3.5 states that entity headers are not supposed
         * to be in the 304 response.  Therefore, we need to combine the
         * response headers with the cached headers *before* we update
         * the cached headers.
         *
         * However, before doing that, we need to first merge in
         * err_headers_out and we also need to strip any hop-by-hop
         * headers that might have snuck in.
         */
        r->headers_out = ap_cache_cacheable_headers_out(r);

        /* Merge in our cached headers.  However, keep any updated values. */
        ap_cache_accept_headers(cache->handle, r, 1);
    }

    /* Write away header information to cache. It is possible that we are
     * trying to update headers for an entity which has already been cached.
     *
     * This may fail, due to an unwritable cache area. E.g. filesystem full,
     * permissions problems or a read-only (re)mount. This must be handled
     * later.
     */
    rv = store_headers(cache->handle, r, info);

    /* Did we just update the cached headers on a revalidated response?
     *
     * If so, we can now decide what to serve to the client.  This is done in
     * the same way as with a regular response, but conditions are now checked
     * against the cached or merged response headers.
     */
    if (cache->stale_handle) {
        apr_bucket_brigade *bb;
        apr_bucket *bkt;
        int status;

        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

        /* Restore the original request headers and see if we need to
         * return anything else than the cached response (ie. the original
         * request was conditional).
         */
        r->headers_in = cache->stale_headers;
        status = ap_meets_conditions(r);
        if (status != OK) {
            r->status = status;

            bkt = apr_bucket_flush_create(bb->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, bkt);
        }
        else {
            recall_body(cache->handle, r->pool, bb);
        }

        cache->block_response = 1;

        /* Before returning we need to handle the possible case of an
         * unwritable cache. Rather than leaving the entity in the cache
         * and having it constantly re-validated, now that we have recalled
         * the body it is safe to try and remove the url from the cache.
         */
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                         "cache: updating headers with store_headers failed. "
                         "Removing cached url.");

            rv = remove_url(cache->stale_handle, r->pool);
            if (rv != OK) {
                /* Probably a mod_disk_cache cache area has been (re)mounted
                 * read-only, or that there is a permissions problem.
                 */
                ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                     "cache: attempt to remove url from cache unsuccessful.");
            }
        }

        return ap_pass_brigade(f->next, bb);
    }

    if(rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                     "cache: store_headers failed");
        ap_remove_output_filter(f);

        return ap_pass_brigade(f->next, in);
    }

    rv = store_body(cache->handle, r, in);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                     "cache: store_body failed");
        ap_remove_output_filter(f);
    }

    return ap_pass_brigade(f->next, in);
}


/*
 * CACHE_REMOVE_URL filter
 * ---------------
 *
 * This filter gets added in the quick handler every time the CACHE_SAVE filter
 * gets inserted. Its purpose is to remove a confirmed stale cache entry from
 * the cache.
 *
 * CACHE_REMOVE_URL has to be a protocol filter to ensure that is run even if
 * the response is a canned error message, which removes the content filters
 * and thus the CACHE_SAVE filter from the chain.
 *
 * CACHE_REMOVE_URL expects cache request rec within its context because the
 * request this filter runs on can be different from the one whose cache entry
 * should be removed, due to internal redirects.
 *
 * Note that CACHE_SAVE_URL (as a content-set filter, hence run before the
 * protocol filters) will remove this filter if it decides to cache the file.
 * Therefore, if this filter is left in, it must mean we need to toss any
 * existing files.
 */
int cache_remove_url_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    cache_request_rec *cache;

    /* Setup cache_request_rec */
    cache = (cache_request_rec *) f->ctx;

    if (!cache) {
        /* user likely configured CACHE_REMOVE_URL manually; they should really
         * use mod_cache configuration to do that. So:
         * 1. Remove ourselves
         * 2. Do nothing and bail out
         */
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                     "cache: CACHE_REMOVE_URL enabled unexpectedly");
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, in);
    }
    /* Now remove this cache entry from the cache */
    cache_remove_url(cache, r->pool);

    /* remove ourselves */
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, in);
}


/*static const cache_provider crccache_client_provider = { &remove_entity,
		&store_headers, &store_body, &recall_headers, &recall_body,
		&create_entity, &open_entity, &remove_url, };
*/
static void disk_cache_register_hook(apr_pool_t *p) {
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, NULL,
			"Registering crccache client module, (C) 2009, Toby Collett");

    /* cache initializer */
    /* cache handler */
    ap_hook_quick_handler(cache_url_handler, NULL, NULL, APR_HOOK_FIRST);
    /* cache filters
     * XXX The cache filters need to run right after the handlers and before
     * any other filters. Consider creating AP_FTYPE_CACHE for this purpose.
     *
     * Depending on the type of request (subrequest / main request) they
     * need to be run before AP_FTYPE_CONTENT_SET / after AP_FTYPE_CONTENT_SET
     * filters. Thus create two filter handles for each type:
     * cache_save_filter_handle / cache_out_filter_handle to be used by
     * main requests and
     * cache_save_subreq_filter_handle / cache_out_subreq_filter_handle
     * to be run by subrequest
     */
    /*
     * CACHE_SAVE must go into the filter chain after a possible DEFLATE
     * filter to ensure that the compressed content is stored.
     * Incrementing filter type by 1 ensures his happens.
     */
    cache_save_filter_handle =
        ap_register_output_filter("CACHE_SAVE",
                                  cache_save_filter,
                                  NULL,
                                  AP_FTYPE_CONTENT_SET+1);
    /*
     * CACHE_SAVE_SUBREQ must go into the filter chain before SUBREQ_CORE to
     * handle subrequsts. Decrementing filter type by 1 ensures this
     * happens.
     */
    cache_save_subreq_filter_handle =
        ap_register_output_filter("CACHE_SAVE_SUBREQ",
                                  cache_save_filter,
                                  NULL,
                                  AP_FTYPE_CONTENT_SET-1);
    /*
     * CACHE_OUT must go into the filter chain after a possible DEFLATE
     * filter to ensure that already compressed cache objects do not
     * get compressed again. Incrementing filter type by 1 ensures
     * his happens.
     */
    cache_out_filter_handle =
        ap_register_output_filter("CACHE_OUT",
                                  cache_out_filter,
                                  NULL,
                                  AP_FTYPE_CONTENT_SET+1);
    /*
     * CACHE_OUT_SUBREQ must go into the filter chain before SUBREQ_CORE to
     * handle subrequsts. Decrementing filter type by 1 ensures this
     * happens.
     */
    cache_out_subreq_filter_handle =
        ap_register_output_filter("CACHE_OUT_SUBREQ",
                                  cache_out_filter,
                                  NULL,
                                  AP_FTYPE_CONTENT_SET-1);
    /* CACHE_REMOVE_URL has to be a protocol filter to ensure that is
     * run even if the response is a canned error message, which
     * removes the content filters.
     */
    cache_remove_url_filter_handle =
        ap_register_output_filter("CACHE_REMOVE_URL",
                                  cache_remove_url_filter,
                                  NULL,
                                  AP_FTYPE_PROTOCOL);

	/* cache initializer */
//	ap_register_provider(p, CACHE_PROVIDER_GROUP, "crccache_client", "0",
//			&crccache_client_provider);
	/*
	 * CACHE_OUT must go into the filter chain after a possible DEFLATE
	 * filter to ensure that already compressed cache objects do not
	 * get compressed again. Incrementing filter type by 1 ensures
	 * his happens.
	 */
	crccache_decode_filter_handle = ap_register_output_filter(
			"CRCCACHE_DECODE", crccache_decode_filter, NULL,
			AP_FTYPE_CONTENT_SET + 1);

	ap_hook_post_config(cache_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);

}

module AP_MODULE_DECLARE_DATA crccache_client_module = {
		STANDARD20_MODULE_STUFF, NULL, /* create per-directory config structure */
		NULL ,                       /* merge per-directory config structures */
    create_config, /* create per-server config structure */
NULL		, /* merge per-server config structures */
		disk_cache_cmds, /* command apr_table_t */
		disk_cache_register_hook /* register hooks */
	};
