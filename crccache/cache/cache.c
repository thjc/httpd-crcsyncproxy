/*
 * cache.c
 *
 *  Created on: 30/10/2009
 *      Author: tcollett
 */

#include <cache/cache.h>
#include <mod_crccache_client.h>

#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_base64.h>
#include <apr_lib.h>
#include <apr_date.h>

#include <http_log.h>
#include <http_protocol.h>

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
int file_cache_recall_mydata(apr_pool_t *ptemp, apr_file_t *fd, cache_info_t *info,
		disk_cache_object_t *dobj, /*request_rec *r, */int validate_url) {
	apr_status_t rv;
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
	char *uribuf = apr_palloc(ptemp, disk_info.name_len + 1); 
	if (uribuf == NULL)
	{
		return APR_EGENERAL;
	}
	len = disk_info.name_len;
	rv = apr_file_read_full(fd, uribuf, len, &len);
	if (rv != APR_SUCCESS) {
		return rv;
	}
	uribuf[disk_info.name_len] = '\0';
	info->uri = uribuf;

	/* check that we have the same URL */
	/* Would strncmp be correct? */
	if (validate_url && strcmp(info->uri, dobj->name) != 0) {
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
	cache_info_t *info;
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
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
					 r->server, "Failed to open file");

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
    rc = file_cache_recall_mydata(r->pool, dobj->hfd, info, dobj, 1);
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

apr_status_t read_table(/*cache_handle_t *handle, request_rec *r,*/server_rec *s,
		apr_table_t *table, apr_file_t *file) {
	char w[MAX_STRING_LEN];
	char *l;
	int p;
	apr_status_t rv;

	while (1) {

		/* ### What about APR_EOF? */
		rv = apr_file_gets(w, MAX_STRING_LEN - 1, file);
		if (rv != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
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
		cache_info_t *info) {
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
		apr_bucket_brigade *bb, void (*post_store_body_callback)(disk_cache_object_t *dobj, request_rec *r)) {
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
		if (post_store_body_callback != NULL) {
			(*post_store_body_callback)(dobj, r);
		}
	}

	return APR_SUCCESS;
}
