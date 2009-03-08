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

#include "apr_file_io.h"
#include "apr_strings.h"
#include "mod_cache.h"
#include "mod_disk_cache.h"
#include "ap_provider.h"
#include "util_filter.h"
#include "util_script.h"
#include "util_charset.h"

#include "crccache.h"

#include <crcsync/crcsync.h>

const int bufferSize = 1024;

module AP_MODULE_DECLARE_DATA crccache_server_module;

//#define MIN(X,Y) (X<Y?X:Y)

static void *create_config(apr_pool_t *p, server_rec *s) {
	disk_cache_conf *conf = apr_pcalloc(p, sizeof(disk_cache_conf));

	/* XXX: Set default values */
	conf->dirlevels = DEFAULT_DIRLEVELS;
	conf->dirlength = DEFAULT_DIRLENGTH;
	conf->maxfs = DEFAULT_MAX_FILE_SIZE;
	conf->minfs = DEFAULT_MIN_FILE_SIZE;

	conf->cache_root = NULL;
	conf->cache_root_len = 0;

	return conf;
}

typedef struct crccache_ctx_t {
	unsigned char *buffer;
	size_t buffer_count;
	apr_bucket_brigade *bb;
	size_t block_size;
	unsigned hashes[BLOCK_COUNT];
	struct crc_context *crcctx;
} crccache_ctx;

/*
 * mod_disk_cache configuration directives handlers.
 */
static const char *set_cache_root(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_server_module);
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
	disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_server_module);
	int val = atoi(arg);
	if (val < 1)
		return "CacheDirLevels value must be an integer greater than 0";
	if (val * conf->dirlength > CACHEFILE_LEN)
		return "CacheDirLevels*CacheDirLength value must not be higher than 20";
	conf->dirlevels = val;
	return NULL;
}
static const char *set_cache_dirlength(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_server_module);
	int val = atoi(arg);
	if (val < 1)
		return "CacheDirLength value must be an integer greater than 0";
	if (val * conf->dirlevels > CACHEFILE_LEN)
		return "CacheDirLevels*CacheDirLength value must not be higher than 20";

	conf->dirlength = val;
	return NULL;
}

static const char *set_cache_minfs(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_server_module);

	if (apr_strtoff(&conf->minfs, arg, NULL, 0) != APR_SUCCESS || conf->minfs
			< 0) {
		return "CacheMinFileSize argument must be a non-negative integer representing the min size of a file to cache in bytes.";
	}
	return NULL;
}

static const char *set_cache_maxfs(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	disk_cache_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_server_module);
	if (apr_strtoff(&conf->maxfs, arg, NULL, 0) != APR_SUCCESS || conf->maxfs
			< 0) {
		return "CacheMaxFileSize argument must be a non-negative integer representing the max size of a file to cache in bytes.";
	}
	return NULL;
}

static const command_rec disk_cache_cmds[] = { AP_INIT_TAKE1("CacheRoot", set_cache_root, NULL, RSRC_CONF,
		"The directory to store cache files"), AP_INIT_TAKE1("CacheDirLevels", set_cache_dirlevels, NULL, RSRC_CONF,
		"The number of levels of subdirectories in the cache"), AP_INIT_TAKE1("CacheDirLength", set_cache_dirlength, NULL, RSRC_CONF,
		"The number of characters in subdirectory names"), AP_INIT_TAKE1("CacheMinFileSize", set_cache_minfs, NULL, RSRC_CONF,
		"The minimum file size to cache a document"), AP_INIT_TAKE1("CacheMaxFileSize", set_cache_maxfs, NULL, RSRC_CONF,
		"The maximum file size to cache a document"), { NULL } };

static ap_filter_rec_t *crccache_out_filter_handle;

static int crccache_server_header_parser_handler(request_rec *r) {
	//disk_cache_conf *conf = ap_get_module_config(r->server->module_config,
	//		&crccache_server_module);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,"check if we have a Block-Hashes header here");
	const char * hashes, *block_size_header;
	hashes = apr_table_get(r->headers_in, "Block-Hashes");
	block_size_header = apr_table_get(r->headers_in, "Block-Size");
	if (hashes && block_size_header)
	{
		size_t block_size;
		int ret = sscanf(block_size_header,"%ld",&block_size);
		if (ret < 0)
		{
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "crccache: failed to convert block size header to int, %s",block_size_header);
			return OK;
		}

		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "we have a Block-Hashes header here, we should response in kind: %s",hashes);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Need to attache a filter here so we can set the content encoding for the return");
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
				r->server, "Adding CRCCACHE_ENCODE filter for %s",
				r->uri);
		ap_add_output_filter_handle(crccache_out_filter_handle,
				NULL, r, r->connection);

	}

	return OK;
}

/* PR 39727: we're screwing up our clients if we leave a strong ETag
 * header while transforming content.  Henrik Nordstrom suggests
 * appending ";gzip".
 *
 * Pending a more thorough review of our Etag handling, let's just
 * implement his suggestion.  It fixes the bug, or at least turns it
 * from a showstopper to an inefficiency.  And it breaks nothing that
 * wasn't already broken.
 */
static void crccache_check_etag(request_rec *r, const char *transform) {
	const char *etag = apr_table_get(r->headers_out, "ETag");
	if (etag && (((etag[0] != 'W') && (etag[0] != 'w')) || (etag[1] != '/'))) {
		apr_table_set(r->headers_out, "ETag", apr_pstrcat(r->pool, etag, "-",
				transform, NULL));
	}
}

/*
 * CACHE_OUT filter
 * ----------------
 *
 * Deliver cached content (headers and body) up the stack.
 */
static int crccache_out_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
	apr_bucket *e;
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
	"cache: running CRCCACHE_OUT filter");

	/* Do nothing if asked to filter nothing. */
	if (APR_BRIGADE_EMPTY(bb)) {
		return ap_pass_brigade(f->next, bb);
	}

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
			"crccache encoding %s", r->uri);

	/* If we don't have a context, we need to ensure that it is okay to send
	 * the deflated content.  If we have a context, that means we've done
	 * this before and we liked it.
	 * This could be not so nice if we always fail.  But, if we succeed,
	 * we're in better shape.
	 */
	if (!ctx) {
//		char *token;
		const char *encoding;

		/* only work on main request/no subrequests */
		if (r->main != NULL) {
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}

		/* We can't operate on Content-Ranges */
		if (apr_table_get(r->headers_out, "Content-Range") != NULL) {
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}

		/* Let's see what our current Content-Encoding is.
		 * If it's already encoded, don't compress again.
		 * (We could, but let's not.)
		 */
		encoding = apr_table_get(r->headers_out, "Content-Encoding");
		if (encoding && strcasecmp(CRCCACHE_ENCODING,encoding) == 0) {
			/* Even if we don't accept this request based on it not having
			 * the Accept-Encoding, we need to note that we were looking
			 * for this header and downstream proxies should be aware of that.
			 */
			apr_table_mergen(r->headers_out, "Vary", "Accept-Encoding");
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}

		/* For a 304 or 204 response there is no entity included in
		 * the response and hence nothing to deflate. */
		if (r->status == HTTP_NOT_MODIFIED || r->status == HTTP_NO_CONTENT){
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        /* We're cool with filtering this. */
        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);

        /* If the entire Content-Encoding is "identity", we can replace it. */
        if (!encoding || !strcasecmp(encoding, "identity")) {
            apr_table_setn(r->headers_out, "Content-Encoding", CRCCACHE_ENCODING);
        }
        else {
            apr_table_mergen(r->headers_out, "Content-Encoding", CRCCACHE_ENCODING);
        }
        apr_table_unset(r->headers_out, "Content-Length");
        apr_table_unset(r->headers_out, "Content-MD5");
        crccache_check_etag(r, CRCCACHE_ENCODING);

    	const char * hashes, *block_size_header;
    	hashes = apr_table_get(r->headers_in, "Block-Hashes");
    	block_size_header = apr_table_get(r->headers_in, "Block-Size");

        ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
                     "crccache encoding block size %s", block_size_header);


    	errno=0;
    	ctx->block_size = strtoull(block_size_header,NULL,0);
    	if (errno || ctx->block_size <= 0)
    	{
    		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "crccache: failed to convert block size header to int, %s",block_size_header);
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
    	}

		// allocate a buffer of twice our block size so we can store non matching parts of data as it comes in
    	ctx->buffer_count = 0;
    	ctx->buffer = apr_palloc(r->pool, ctx->block_size*2);

		int ii;
    	for (ii = 0; ii < BLOCK_COUNT; ++ii)
    	{
    		ctx->hashes[ii] = decode_30bithash(&hashes[ii*HASH_BASE64_SIZE_TX]);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
                         "cache: decoded hash[%d] %08X",ii,ctx->hashes[ii]);
    	}

    	// now initialise the crcsync context that will do the real work
    	ctx->crcctx = crc_context_new(ctx->block_size, HASH_SIZE,ctx->hashes, BLOCK_COUNT);



    }


    while (!APR_BRIGADE_EMPTY(bb))
    {
        const char *data;
//        apr_bucket *b;
        apr_size_t len;

        e = APR_BRIGADE_FIRST(bb);

        if (APR_BUCKET_IS_EOS(e)) {
//            char *buf;

            // this just added the zlib validation header
/*            buf = apr_palloc(r->pool, VALIDATION_SIZE);
            putLong((unsigned char *)&buf[0], ctx->crc);
            putLong((unsigned char *)&buf[4], ctx->stream.total_in);

            b = apr_bucket_pool_create(buf, VALIDATION_SIZE, r->pool,
                                       f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "Zlib: Compressed %ld to %ld : URL %s",
                          ctx->stream.total_in, ctx->stream.total_out, r->uri);
			*/

            /* Remove EOS from the old list, and insert into the new. */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* This filter is done once it has served up its content */
            ap_remove_output_filter(f);

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

        ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
                     "cache: running CRCCACHE_OUT filter, read %ld bytes",len);

        // TODO: make this a little more efficient so we need to copy less data around
        size_t bucket_used_count = 0;
        size_t data_left;
        while(bucket_used_count < len)
        {
        	data_left = len - bucket_used_count;
			if (ctx->buffer_count > 0 || data_left < ctx->block_size)
			{
				size_t copy_size = MIN(ctx->block_size*2-ctx->buffer_count,data_left);
				memcpy(&ctx->buffer[ctx->buffer_count],data,copy_size);
				ctx->buffer_count += copy_size;
				bucket_used_count += copy_size;
	        	data_left = len - bucket_used_count;
				// not enough to match a block so stop here
				if (ctx->buffer_count < ctx->block_size)
					break;
			}

			long result;
			size_t count;
			if (ctx->buffer_count > 0)
				count = crc_read_block(ctx->crcctx, &result,
						ctx->buffer, ctx->buffer_count);
			else
				count = crc_read_block(ctx->crcctx, &result,
						&data[bucket_used_count], data_left);

			// if we match stuff would create new bucket here...
			ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
						 "crccache: CRCSYNC, processed %ld bytes, result was %ld",count,result);

			if (ctx->buffer_count > 0)
			{
				// if we have enough data left stop using the buffer
				if (ctx->buffer_count - count < len && data_left > 0)
				{
					size_t extra_data = ctx->buffer_count - bucket_used_count;
					bucket_used_count = count - extra_data;
					ctx->buffer_count = 0;
				}

				// otherwise memmove the unused data to the start of the buffer
				memmove(ctx->buffer,&ctx->buffer[count],ctx->buffer_count - count);
				ctx->buffer_count -= count;

			}
			else
			{
				bucket_used_count += count;
			}

        }

        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

    }

    apr_brigade_cleanup(bb);
    return APR_SUCCESS;
}

static void disk_cache_register_hook(apr_pool_t *p) {
	ap_hook_header_parser(crccache_server_header_parser_handler, NULL, NULL,
			APR_HOOK_MIDDLE);

	/*
	 * CACHE_OUT must go into the filter chain after a possible DEFLATE
	 * filter to ensure that already compressed cache objects do not
	 * get compressed again. Incrementing filter type by 1 ensures
	 * his happens.
	 */
	crccache_out_filter_handle = ap_register_output_filter("CRCCACHE_OUT",
			crccache_out_filter, NULL, AP_FTYPE_CONTENT_SET + 1);
}

module AP_MODULE_DECLARE_DATA crccache_server_module = {
		STANDARD20_MODULE_STUFF, NULL, /* create per-directory config structure */
		NULL ,                       /* merge per-directory config structures */
    create_config, /* create per-server config structure */
NULL		, /* merge per-server config structures */
		disk_cache_cmds, /* command apr_table_t */
		disk_cache_register_hook /* register hooks */
	};
