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

/* crcsync/crccache apache server module
 *
 * This module is designed to run as a proxy server on the remote end of a slow
 * internet link. This module uses a crc32 running hash algorithm to reduce
 * data transfer in cached but modified downstream files.
 *
 * CRC algorithm uses the crcsync library created by Rusty Russel
 *
 * Authors: Toby Collett (2009), Alex Wulms (2009)
 *
 */

#include <stdbool.h>
#include "apr_file_io.h"
#include "apr_strings.h"
#include "mod_cache.h"
#include "mod_disk_cache.h"
#include "ap_provider.h"
#include "util_filter.h"
#include "util_script.h"
#include "util_charset.h"

#include "crccache.h"
#include "mod_crccache_server.h"

#include <crcsync/crcsync.h>

module AP_MODULE_DECLARE_DATA crccache_server_module;

//#define MIN(X,Y) (X<Y?X:Y)

static void *create_config(apr_pool_t *p, server_rec *s) {
	crccache_server_conf *conf = apr_pcalloc(p, sizeof(crccache_server_conf));
	conf->disk_cache_conf = apr_pcalloc(p, sizeof(disk_cache_conf));

	/* XXX: Set default values */
	conf->enabled = 0;
	conf->disk_cache_conf->dirlevels = DEFAULT_DIRLEVELS;
	conf->disk_cache_conf->dirlength = DEFAULT_DIRLENGTH;
	conf->disk_cache_conf->maxfs = DEFAULT_MAX_FILE_SIZE;
	conf->disk_cache_conf->minfs = DEFAULT_MIN_FILE_SIZE;

	conf->disk_cache_conf->cache_root = NULL;
	conf->disk_cache_conf->cache_root_len = 0;

	return conf;
}

typedef struct crccache_ctx_t {
	unsigned char *buffer;
	size_t buffer_digest_getpos;
	size_t buffer_read_getpos;
	size_t buffer_putpos;
	size_t buffer_size;
	long crc_read_block_result;
	size_t crc_read_block_ndigested;
	apr_bucket_brigade *bb;
	size_t block_size;
	size_t tail_block_size;
	unsigned hashes[FULL_BLOCK_COUNT+1];
	struct crc_context *crcctx;
	size_t orig_length;
	size_t tx_length;
} crccache_ctx;

/*
 * mod_disk_cache configuration directives handlers.
 */
static const char *set_cache_root(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	crccache_server_conf *conf = ap_get_module_config(parms->server->module_config,
				&crccache_server_module);
	conf->disk_cache_conf->cache_root = arg;
	conf->disk_cache_conf->cache_root_len = strlen(arg);
	/* TODO: canonicalize cache_root and strip off any trailing slashes */

	return NULL;
}

/*
 * Only enable CRCCache Server when requested through the config file
 * so that the user can switch CRCCache server on in a specific virtual server
 */
static const char *set_crccache_server(cmd_parms *parms, void *dummy, int flag)
{
	crccache_server_conf *conf = ap_get_module_config(parms->server->module_config,
				&crccache_server_module);
	conf->enabled = flag;
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
	crccache_server_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_server_module);
	int val = atoi(arg);
	if (val < 1)
		return "CacheDirLevelsServer value must be an integer greater than 0";
	if (val * conf->disk_cache_conf->dirlength > CACHEFILE_LEN)
		return "CacheDirLevelsServer*CacheDirLengthServer value must not be higher than 20";
	conf->disk_cache_conf->dirlevels = val;
	return NULL;
}
static const char *set_cache_dirlength(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	crccache_server_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_server_module);
	int val = atoi(arg);
	if (val < 1)
		return "CacheDirLengthServer value must be an integer greater than 0";
	if (val * conf->disk_cache_conf->dirlevels > CACHEFILE_LEN)
		return "CacheDirLevelsServer*CacheDirLengthServer value must not be higher than 20";

	conf->disk_cache_conf->dirlength = val;
	return NULL;
}

static const char *set_cache_minfs(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	crccache_server_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_server_module);

	if (apr_strtoff(&conf->disk_cache_conf->minfs, arg, NULL, 0) != APR_SUCCESS || conf->disk_cache_conf->minfs
			< 0) {
		return "CacheMinFileSizeServer argument must be a non-negative integer representing the min size of a file to cache in bytes.";
	}
	return NULL;
}

static const char *set_cache_maxfs(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	crccache_server_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_server_module);
	if (apr_strtoff(&conf->disk_cache_conf->maxfs, arg, NULL, 0) != APR_SUCCESS || conf->disk_cache_conf->maxfs
			< 0) {
		return "CacheMaxFileSizeServer argument must be a non-negative integer representing the max size of a file to cache in bytes.";
	}
	return NULL;
}

static const command_rec disk_cache_cmds[] = { AP_INIT_TAKE1("CacheRootServer", set_cache_root, NULL, RSRC_CONF,
		"The directory to store cache files"), AP_INIT_TAKE1("CacheDirLevelsServer", set_cache_dirlevels, NULL, RSRC_CONF,
		"The number of levels of subdirectories in the cache"), AP_INIT_TAKE1("CacheDirLengthServer", set_cache_dirlength, NULL, RSRC_CONF,
		"The number of characters in subdirectory names"), AP_INIT_TAKE1("CacheMinFileSizeServer", set_cache_minfs, NULL, RSRC_CONF,
		"The minimum file size to cache a document"), AP_INIT_TAKE1("CacheMaxFileSizeServer", set_cache_maxfs, NULL, RSRC_CONF,
		"The maximum file size to cache a document"), AP_INIT_FLAG("CRCcacheServer", set_crccache_server, NULL, RSRC_CONF,
		"Enable the CRCCache server in this virtual server"),{ NULL } };

static ap_filter_rec_t *crccache_out_filter_handle;

static int crccache_server_header_parser_handler(request_rec *r) {
	crccache_server_conf *conf = ap_get_module_config(r->server->module_config,
			&crccache_server_module);
	if (conf->enabled)
	{
		const char * hashes, *file_size_header;
		hashes = apr_table_get(r->headers_in, "Block-Hashes");
		file_size_header = apr_table_get(r->headers_in, "File-Size");
		if (hashes && file_size_header)
		{
			size_t file_size;
			int ret = sscanf(file_size_header,"%ld",&file_size);
			if (ret < 0)
			{
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "crccache: failed to convert file size header to size_t, %s",file_size_header);
				return OK;
			}

			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CRCSYNC: Block-Hashes header found so enabling protocol: %s",hashes);
			ap_add_output_filter_handle(crccache_out_filter_handle,
					NULL, r, r->connection);

		}
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


/**
 * Write literal data
 */
static void write_literal(ap_filter_t *f, unsigned char *buffer, long count)
{
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE literal %ld bytes",count);
	unsigned bucket_size = count + ENCODING_LITERAL_HEADER_SIZE;
	ctx->tx_length += bucket_size;
	char * buf = apr_palloc(r->pool, bucket_size);

	buf[0] = ENCODING_LITERAL;
	*(unsigned *)&buf[1] = htonl(count);
	memcpy(buf + ENCODING_LITERAL_HEADER_SIZE, buffer, count);

	apr_bucket * b = apr_bucket_pool_create(buf, bucket_size, r->pool, f->c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
}

/**
 * Write a block reference
 */
static void write_block_reference(ap_filter_t *f, long result)
{
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;

	unsigned bucket_size = ENCODING_BLOCK_HEADER_SIZE;
	ctx->tx_length += bucket_size;
	char * buf = apr_palloc(r->pool, bucket_size);

	buf[0] = ENCODING_BLOCK;
	buf[1] = (unsigned char) ((-result)-1); // invert and get back to zero based
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE block %d",buf[1]);
	apr_bucket * b = apr_bucket_pool_create(buf, bucket_size, r->pool, f->c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
}

/*
 * Process one block of data: try to match it against the CRC, append
 * the result to the ouput ring and remember the result (e.g. was
 * it a block-match or was a literal processed)
 */
static void process_block(ap_filter_t *f)
{
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;

	// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE invoking crc_read_block");
	if (ctx->crcctx == NULL)
	{
		// This should never happen
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server,"CRCCACHE-ENCODE crcctx = null");
		exit(1);
	}
	
	long result;
	size_t ndigested = crc_read_block(
		ctx->crcctx,
		&result,
		ctx->buffer+ctx->buffer_digest_getpos,
		ctx->buffer_putpos-ctx->buffer_digest_getpos
	);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE crc_read_block ndigested: %ld, result %ld", ndigested, result);

	
	// result = 0: do nothing (it is a 'literal' block of exactly 'blocksize' bytes at the end of the buffer, it will have to be moved
	//  to the beginning of the moving window so that it can be written upon the next call to crc_read_block or crc_read_flush)
	// result > 0: send literal
	// result < 0: send block
	if (result > 0)
	{
		write_literal(f, ctx->buffer+ctx->buffer_read_getpos, result);
		ctx->buffer_read_getpos += result;
	}
	else if (result < 0)
	{
		write_block_reference(f, result);
		unsigned char blocknum = (unsigned char) ((-result)-1);
		ctx->buffer_read_getpos += (blocknum == FULL_BLOCK_COUNT) ? ctx->tail_block_size : ctx->block_size;
	}
	
	// Update the context with the results
	ctx->crc_read_block_result = result;
	ctx->crc_read_block_ndigested = ndigested;
	ctx->buffer_digest_getpos += ndigested;
}

/*
 * Flush one block of data: get it from the crccontext, append
 * the result to the ouput ring and remember the result (e.g. was
 * it a block-match or was a literal processed)
 */
static void flush_block(ap_filter_t *f)
{
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;

	// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE invoking crc_read_flush");
	if (ctx->crcctx == NULL)
	{
		// This should never happen
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server,"CRCCACHE-ENCODE crcctx = null");
		exit(1);
	}
	long result = crc_read_flush(ctx->crcctx);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE crc_read_flush result %ld", result);

	// result = 0: do nothing
	// result > 0: send literal that was already digested but not yet returned by read-block
	// result < 0: send block that was already digested but not yet returned by read-block
	if (result > 0)
	{
		write_literal(f, ctx->buffer+ctx->buffer_read_getpos, result);
		ctx->buffer_read_getpos += result;
	}
	else if (result < 0)
	{
		write_block_reference(f, result);
		unsigned char blocknum = (unsigned char) ((-result)-1);
		ctx->buffer_read_getpos += (blocknum == FULL_BLOCK_COUNT) ? ctx->tail_block_size : ctx->block_size;
	}
	
	// Update the context with the results
	ctx->crc_read_block_result = result;
	ctx->crc_read_block_ndigested = 0;
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

	/* Do nothing if asked to filter nothing. */
	if (APR_BRIGADE_EMPTY(bb)) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE bucket brigade is empty -> nothing todo");
		return ap_pass_brigade(f->next, bb);
	}

	/* If we don't have a context, we need to ensure that it is okay to send
	 * the deflated content.  If we have a context, that means we've done
	 * this before and we liked it.
	 * This could be not so nice if we always fail.  But, if we succeed,
	 * we're in better shape.
	 */
	if (ctx == NULL)
	{
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
		 * If it's already encoded by crccache: don't compress again.
		 * (We could, but let's not.)
		 */
		encoding = apr_table_get(r->headers_out, "Content-Encoding");
		if (encoding && strcasecmp(CRCCACHE_ENCODING,encoding) == 0)
		{
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
		if (r->status == HTTP_NOT_MODIFIED || r->status ==HTTP_NO_CONTENT)
		{
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}

		/* We're cool with filtering this. */
		ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));
		ctx->orig_length = 0;
		ctx->tx_length = 0;
		ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);

		/* If the entire Content-Encoding is "identity", we can replace it. */
		if (!encoding || !strcasecmp(encoding, "identity")) {
			apr_table_setn(r->headers_out, "Content-Encoding", CRCCACHE_ENCODING);
		}
		else {
			// Unknown encoding. Don't confuse the client with multiple encoding combinations,
			// like gzip and crccache.
			ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r->server,
					"Not encoding with crccache. It is already encoded with: %s", encoding);
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}
		apr_table_unset(r->headers_out, "Content-Length");
		apr_table_unset(r->headers_out, "Content-MD5");
		crccache_check_etag(r, CRCCACHE_ENCODING);

		const char * hashes, *file_size_header;
		hashes = apr_table_get(r->headers_in, "Block-Hashes");
		file_size_header = apr_table_get(r->headers_in, "File-Size");

		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
				"CRCCACHE-ENCODE encoding file size header %s", file_size_header);

		errno=0;
		size_t file_size = strtoull(file_size_header,NULL,0);
		if (errno || file_size <= 0)
		{
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,"crccache: failed to convert file size header to size_t, %s",file_size_header);
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}
		ctx->block_size = file_size/FULL_BLOCK_COUNT;
		ctx->tail_block_size = file_size % FULL_BLOCK_COUNT;
		size_t block_count_including_final_block = FULL_BLOCK_COUNT + (ctx->tail_block_size != 0);

		// Data come in at chunks that are potentially smaller then block_size
		// Accumulate those chunks into a buffer.
		// The buffer must be at least 2*block_size so that crc_read_block(...) can find a matching block, regardless
		// of the data alignment compared to the original page.
		// The buffer is basically a moving window in the new page. So sometimes the last part of the buffer must be
		// copied to the beginning again. The larger the buffer, the less often such a copy operation is required
		// Though, the larger the buffer, the bigger the memory demand.
		// A size of 4*block_size (20% of original file size) seems to be a good balance

		// TODO: tune the buffer-size depending on the mime-type. Already compressed data (zip, gif, jpg, mpg, etc) will
		// probably only have matching blocks if the file is totally unmodified. As soon as one byte differs in the original
		// uncompressed data, the entire compressed data stream will be different anyway, so in such case it does not make
		// much sense to even keep invoking the crc_read_block(...) function as soon as a difference has been found.
		// Hence, no need to make a (potentially huge) buffer for these type of compressed (potentially huge, think about movies)
		// data types.
		ctx->buffer_size = ctx->block_size*4 + 1; 
		ctx->buffer_digest_getpos = 0;
		ctx->buffer_read_getpos = 0;
		ctx->buffer_putpos = 0;
		ctx->crc_read_block_result = 0;
		ctx->buffer = apr_palloc(r->pool, ctx->buffer_size);

		// Decode the hashes
		int ii;
		for (ii = 0; ii < block_count_including_final_block; ++ii)
		{
			ctx->hashes[ii] = decode_30bithash(&hashes[ii*HASH_BASE64_SIZE_TX]);
			//ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "CRCCACHE-ENCODE decoded hash[%d] %08X",ii,ctx->hashes[ii]);
		}

		// now initialise the crcsync context that will do the real work
		ctx->crcctx = crc_context_new(ctx->block_size, HASH_SIZE,ctx->hashes, block_count_including_final_block, ctx->tail_block_size);
	}


	while (!APR_BRIGADE_EMPTY(bb))
	{
		const char *data;
		apr_size_t len;

		e = APR_BRIGADE_FIRST(bb);

		if (APR_BUCKET_IS_EOS(e))
		{
			ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE EOS reached for APR bucket");
			while (ctx->buffer_digest_getpos < ctx->buffer_putpos)
			{
				// There is still data in the buffer. Process it.
				process_block(f);
			}
			
			do
			{
				// Flush remaining block in the crcctx
				flush_block(f);
			}
			while (ctx->crc_read_block_result != 0);
			
			// Free data structures in crcctx
			// TODO: is this really smart? Based on the tests, it seems like we get
			// a fresh new f per request, in which case this clean-up is safe and
			// required to prevent a memory leak. However, I should study the API better
			// to understand if getting a new f per request is indeed always the case or
			// if it is configuration dependant (e.g. subprocesses versus light-weight-thread
			// implementation).
			crc_context_free(ctx->crcctx);
			ctx->crcctx = NULL;
			// free f->ctx
			// f->ctx = NULL;

			// TODO: add strong hash here


			ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
				"CRCCACHE-ENCODE complete size %f%% (encoded=%ld original=%ld",100.0*((float)ctx->tx_length/(float)ctx->orig_length),ctx->tx_length, ctx->orig_length);


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

		if (APR_BUCKET_IS_FLUSH(e))
		{
			// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE flush APR bucket");
			apr_status_t rv;

			/* Remove flush bucket from old brigade and insert into the new. */
			APR_BUCKET_REMOVE(e);
			// TODO: optimize; do not insert two consecutive flushes when no intermediate
			//        output block was written
			APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
			rv = ap_pass_brigade(f->next, ctx->bb);
			if (rv != APR_SUCCESS) {
				return rv;
			}
			continue;
		}

		if (APR_BUCKET_IS_METADATA(e)) {
			// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE metadata APR bucket");
			/*
			 * Remove meta data bucket from old brigade and insert into the
			 * new.
			 */
			// TODO: do we need to encode metadata
			apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
			if (len > 2)
				ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
				"CRCCACHE-ENCODE Metadata, read %ld, %d %d %d",len,data[0],data[1],data[2]);
			else
				ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
								"CRCCACHE-ENCODE Metadata, read %ld",len);
			APR_BUCKET_REMOVE(e);
			APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
			continue;
		}

		/* read */
		apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
		ctx->orig_length += len;
		// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE normal data in APR bucket, read %ld", len);

		// append data to the buffer and encode buffer content using the crc_read_block magic
		size_t bucket_used_count = 0;
		// size_t data_left;
		size_t bucket_data_left;
		while(bucket_used_count < len)
		{
			/* Append as much data as possible into the buffer */
			bucket_data_left = len - bucket_used_count;
			size_t copy_size = MIN(ctx->buffer_size-ctx->buffer_putpos, bucket_data_left);
			memcpy(ctx->buffer+ctx->buffer_putpos, data+bucket_used_count, copy_size);
			bucket_used_count += copy_size;
			bucket_data_left -= copy_size;
			ctx->buffer_putpos += copy_size;
			/* flush the buffer if it is appropriate */
			if (ctx->buffer_putpos == ctx->buffer_size)
			{
				// Buffer is filled to the end. Flush as much as possible
				ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
						"CRCCACHE-ENCODE Buffer is filled to end, read_getpos: %ld, digest_getpos: %ld, putpos: %ld, putpos-digest_getpos: %ld (blocksize: %ld)", 
						ctx->buffer_read_getpos, ctx->buffer_digest_getpos, ctx->buffer_putpos, ctx->buffer_putpos-ctx->buffer_digest_getpos, ctx->block_size);
				while (ctx->buffer_putpos - ctx->buffer_digest_getpos > ctx->block_size)
				{
					// We can still scan at least 1 block + 1 byte forward: try to flush next part
					process_block(f);
					ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
							"CRCCACHE-ENCODE Processed a block, read_getpos: %ld, digest_getpos: %ld, putpos: %ld, putpos-digest_getpos: %ld (blocksize: %ld)", 
						ctx->buffer_read_getpos, ctx->buffer_digest_getpos, ctx->buffer_putpos, ctx->buffer_putpos-ctx->buffer_digest_getpos, ctx->block_size);
				}

				if (ctx->buffer_putpos != ctx->buffer_read_getpos)
				{
					// Copy the remaining part of the buffer to the start of the buffer,
					// so that it can be filled again as new data arrive
					
					ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
							"CRCCACHE-ENCODE Moving %ld bytes to begin of buffer", 
							ctx->buffer_putpos - ctx->buffer_read_getpos);
					memcpy(ctx->buffer, ctx->buffer + ctx->buffer_read_getpos, ctx->buffer_putpos - ctx->buffer_read_getpos);
				}
				// Reset getpos to the beginning of the buffer and putpos accordingly
				ctx->buffer_putpos -= ctx->buffer_read_getpos;
				ctx->buffer_digest_getpos -= ctx->buffer_read_getpos;
				ctx->buffer_read_getpos = 0;
			}
			while (ctx->crc_read_block_result < 0 && ctx->buffer_putpos - ctx->buffer_digest_getpos > ctx->block_size)
			{
				// Previous block matched exactly. Let's hope the next block as well
				ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
						"CRCCACHE-ENCODE Previous block matched, read_getpos: %ld, digest_getpos: %ld, putpos: %ld, putpos-digest_getpos: %ld (blocksize: %ld)", 
						ctx->buffer_read_getpos, ctx->buffer_digest_getpos, ctx->buffer_putpos, ctx->buffer_putpos-ctx->buffer_digest_getpos, ctx->block_size);
				process_block(f);
			}
        }
        APR_BUCKET_REMOVE(e);
    }

    apr_brigade_cleanup(bb);
    return APR_SUCCESS;
}

static void disk_cache_register_hook(apr_pool_t *p) {
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, NULL,
			"Registering crccache server module, (C) 2009, Toby Collett and Alex Wulms");

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
