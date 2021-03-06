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

#include <apr_file_io.h>
#include <apr_file_info.h>
#include <apr_strings.h>
#include <apr_base64.h>
#include <apr_lib.h>
#include <apr_date.h>
#include <apr_tables.h>
#include "ap_provider.h"
#include <ap_regex.h>
#include "util_filter.h"
#include "util_script.h"
#include "util_charset.h"
#include <http_log.h>
#include <http_protocol.h>

#include "crccache.h"
#include "ap_log_helper.h"
#include <crcsync/crcsync.h>
#include <crc/crc.h>
#include <zlib.h>

#include "mod_crccache_client.h"
#include "mod_crccache_client_find_similar.h"

static ap_filter_rec_t *crccache_decode_filter_handle;
static ap_filter_rec_t *cache_save_filter_handle;
static ap_filter_rec_t *cache_save_subreq_filter_handle;

module AP_MODULE_DECLARE_DATA crccache_client_module;


APR_DECLARE_OPTIONAL_FN(apr_status_t,
                        ap_cache_generate_key,
                        (request_rec *r, apr_pool_t*p, char**key ));
APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;

// const char* cache_create_key( request_rec*r );


// extern APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;

/*
 * Private strucures and constants only used in mod_crccache_client
 */

// hashes per file
#define FULL_BLOCK_COUNT 40

typedef enum decoding_state {
	DECODING_NEW_SECTION,
	DECODING_COMPRESSED,
	DECODING_LITERAL_BODY,
	DECODING_LITERAL_SIZE,
	DECODING_HASH,
	DECODING_BLOCK_HEADER,
	DECODING_BLOCK
} decoding_state;

typedef enum {
	DECOMPRESSION_INITIALIZED,
	DECOMPRESSION_ENDED
} decompression_state_t;

typedef struct crccache_client_ctx_t {
	apr_bucket_brigade *bb;
	size_t block_size;
	size_t tail_block_size;
	apr_bucket * cached_bucket;// original data so we can fill in the matched blocks

	decoding_state state;
	decompression_state_t decompression_state;
	z_stream *decompression_stream;
	int headers_checked;
	struct apr_sha1_ctx_t sha1_ctx;
	unsigned char sha1_value_rx[APR_SHA1_DIGESTSIZE];
	unsigned rx_count;
	unsigned literal_size;
	unsigned char * partial_literal;// original data so we can fill in the matched blocks
} crccache_client_ctx;

static int crccache_client_post_config_per_virtual_host(apr_pool_t *p, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s)
{
	/**
     * The cache can be configured (differently) per virtual host, hence make the correct settings
     * at the virtual host level 
     */
    crccache_client_conf *conf = ap_get_module_config(s->module_config,
                                                 &crccache_client_module);
    ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, s,
                 "mod_crccache_client.post_config_per_vhost (%s): Number of cacheable URLs: %d", 
                 format_hostinfo(ptemp, s), conf->cacheenable->nelts);

    if (conf->cacheenable->nelts != 0) {
    	// Cache client is enabled in this (virtual) server. Initialize it
        if (!conf->cache_root) {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s,
                         "mod_crccache_client.post_config_per_vhost (%s): Please set parameter CacheRootClient in (virtual) server config %s",
                         format_hostinfo(ptemp, s), s->defn_name);
            return APR_EGENERAL;
        }
    	return crccache_client_fsp_post_config_per_virtual_host(p, plog, ptemp, s, conf->similar_page_cache, conf->cache_root);
    }
    
    return OK;
}

static int crccache_client_post_config(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
	int result;
	
    /*
     * TODO: AW: Why is the cache_generate_key function looked-up as an optional function?
     * As far as I can see, this function is:
     * 1) Very platform agnostic (so the need to ever write a platform specific module
     *    in order to export a platform specific implementation hardly exists...)
     * 2) Very closely coupled to the way it is used in the cache client (an externally
     *    exported function could break the client by implementing other semantics!)
     * 3) There are no existing modules registering/exporting an ap_cache_generate_key function
     *    (which confirmes the two above points, that there is no need for it)
     * Nevertheless, I assume the original author of mod_cache knows what he is doing so I
     * leave this indirect look-up here for the time being
     */
    cache_generate_key = APR_RETRIEVE_OPTIONAL_FN(ap_cache_generate_key);
    if (!cache_generate_key) {
        cache_generate_key = cache_generate_key_default;
    }

    // Perform the post_config logic for the 'find similar page' feature
    server_rec *current_server = s;
    while (current_server != NULL)
    {
    	result = crccache_client_post_config_per_virtual_host(p, plog, ptemp, current_server);
    	if (result != OK)
    		return result;

	    current_server = current_server->next;
    }
    return OK;

}

static void crccache_client_child_init_per_virtual_host(apr_pool_t *p, server_rec *s)
{
    crccache_client_conf *conf = ap_get_module_config(s->module_config,
                                                 &crccache_client_module);
    crccache_client_fsp_child_init_per_virtual_host(p, s, conf->similar_page_cache);
}

static void crccache_client_child_init(apr_pool_t *p, server_rec *s)
{
	server_rec *current_server = s;
	while (current_server != NULL)
	{
		crccache_client_child_init_per_virtual_host(p, current_server);
	    current_server = current_server->next;
	}
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

// ______ continue with refactoring

/**
 * Request CRCSYNC/delta-http encoding for a page: open the previous data file from the cache, preferably
 * for the exact URL but if not present then for a similar URL. Then calculate the CRC blocks for the
 * opened page and generate the header
 * Returns APR_SUCCESS if the delta-http could be prepared and APR_EGENERAL or APR_NOTFOUND in case of
 * error conditions (APR_NOTFOUND if no body could be found, APR_EGENERAL for all other errors)
 */
static apr_status_t request_crcsync_encoding(cache_handle_t *h, request_rec *r, crccache_client_conf *client_conf)	
{
	const char *data;
	apr_size_t len;
	apr_bucket *e;
	unsigned i;
	int z_RC;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "Preparing CRCSYNC/delta-http for %s", r->unparsed_uri);
	disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;
	if (!dobj->fd)
	{
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, 
				"No page found in cache for requested URL. Trying to find page for similar URLs");
		dobj = apr_palloc(r->pool, sizeof(disk_cache_object_t));
		if (find_similar_page(dobj, r, client_conf->similar_page_cache) != APR_SUCCESS) 
		{
			ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, 
					"Failed to prepare CRCSYNC/delta-http. No (similar) page found in cache");
			return APR_NOTFOUND;
		}
	}
	
	e = apr_bucket_file_create(dobj->fd, 0, (apr_size_t) dobj->file_size, r->pool,
			r->connection->bucket_alloc);

	/* Read file into bucket. Hopefully the entire file fits in the bucket */
	apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
	if (len != dobj->file_size)
	{
		ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r->server,
				"crccache_client: Only read %" APR_SIZE_T_FMT " bytes out of %" APR_SIZE_T_FMT " bytes from the "
				"original response data into the bucket cache", 
				len, dobj->file_size);
		return APR_EGENERAL;
	}
	// this will be rounded down, but thats okay
	size_t blocksize = len/FULL_BLOCK_COUNT;
	size_t tail_block_size = blocksize + len % FULL_BLOCK_COUNT;
	size_t block_count_including_final_block = FULL_BLOCK_COUNT;
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, 
			"Read file into bucket, len: %" APR_SIZE_T_FMT ", blocksize: %" APR_SIZE_T_FMT ", tail_block_size: %" APR_SIZE_T_FMT,
			len, blocksize, tail_block_size);
	
	// sanity check for very small files
	if (blocksize <= 4)
	{
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,	"Skipped CRCSYNC/delta-http, due to too small blocksize");
		return APR_SUCCESS;
	}
	
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
		return APR_EGENERAL;
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
	crc_of_blocks(data, len, blocksize, tail_block_size, HASH_SIZE, crcs);

	// swap to network byte order
	for (i = 0; i < block_count_including_final_block;++i)
	{
		htobe64(crcs[i]);
	}

	apr_base64_encode (hash_set, (char *)crcs, block_count_including_final_block*sizeof(crcs[0]));
	hash_set[HASH_HEADER_SIZE] = '\0';
	//apr_bucket_delete(e);

	// TODO; bit of a safety margin here, could calculate exact size
	const int block_header_max_size = HASH_HEADER_SIZE+40;
	char block_header_txt[block_header_max_size];
	apr_snprintf(block_header_txt, block_header_max_size,"v=1; fs=%" APR_SIZE_T_FMT "; h=%s",len,hash_set);
	apr_table_set(r->headers_in, BLOCK_HEADER, block_header_txt);
	// TODO: do we want to cache the hashes here?

	// initialise the context for our sha1 digest of the unencoded response
	apr_sha1_init(&ctx->sha1_ctx);
	
	// we want to add a filter here so that we can decode the response.
	// we need access to the original cached data when we get the response as
	// we need that to fill in the matched blocks.
	// TODO: does the original cached data file remain open between this request
	//        and the subsequent response or do we run the risk that a concurrent
	//        request modifies it?
	ap_add_output_filter_handle(crccache_decode_filter_handle, ctx, r, r->connection);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,	"Successfully prepared CRCSYNC/delta-http");

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
	disk_cache_object_t *dobj = (disk_cache_object_t *) h->cache_obj->vobj;

	/* This case should not happen... */
	if (!dobj->hfd) {
		/* XXX log message */
		return APR_NOTFOUND;
	}

	h->req_hdrs = apr_table_make(r->pool, 20);
	h->resp_hdrs = apr_table_make(r->pool, 20);

	/* Call routine to read the header lines/status line */
	read_table(/*h, r, */r->server, h->resp_hdrs, dobj->hfd);
	read_table(/*h, r, */r->server, h->req_hdrs, dobj->hfd);
	apr_file_close(dobj->hfd);

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
			"crccache_client: Recalled headers for URL %s", dobj->name);
	return APR_SUCCESS;
}

/*
 * CACHE_DECODE filter
 * ----------------
 * Deliver crc decoded content (headers and body) up the stack.
 */
static int crccache_decode_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
	apr_bucket *e;
	request_rec *r = f->r;
	crccache_client_ctx *ctx = f->ctx;

	// if this is the first pass in decoding we should check the headers etc
	// and fix up those headers that we modified as part of the encoding
	if (ctx->headers_checked == 0)
	{
		ctx->headers_checked = 1;

		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
				"CRCSYNC returned status code (%d)", r->status);

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

		// remove the encoding header
		apr_table_unset(r->headers_out, ENCODING_HEADER);

		// remove If-Block from the Vary header
		char * vary = apr_pstrdup(r->pool, apr_table_get(r->headers_out, "Vary"));
		if (vary)
		{
			ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "Incoming Vary header: %s", vary);
			apr_table_unset(r->headers_out, "Vary");
			char * tok;
			char * last = NULL;
			for (tok = apr_strtok(vary,", ",&last);tok != NULL;tok = apr_strtok(NULL,", ",&last))
			{
				if (strcmp(BLOCK_HEADER,tok)!=0)
				{
					apr_table_mergen(r->headers_out,"Vary",tok);
				}
			}
		}

		// fix up etag
		char * etag = apr_pstrdup(r->pool, apr_table_get(r->headers_out, ETAG_HEADER));
		if (etag)
		{
			// TODO: get original encoding from etag header so that it can be re-applied
			ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "Incoming ETag header: %s", etag);
			int etaglen = strlen(etag);
			if (etaglen>strlen(CRCCACHE_ENCODING) + 1)
			{
				int etag_start_pos = etaglen-(strlen(CRCCACHE_ENCODING) + 1);
				if (strcmp("-"CRCCACHE_ENCODING,&etag[etag_start_pos])==0)
				{
					etag[etag_start_pos] = '\0';
					apr_table_setn(r->headers_out,"etag",etag);
				}
			}
		}
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

			// check strong hash here
			unsigned char sha1_value[APR_SHA1_DIGESTSIZE];
			apr_sha1_final(sha1_value, &ctx->sha1_ctx);
			if (memcmp(sha1_value, ctx->sha1_value_rx, APR_SHA1_DIGESTSIZE) != 0)
			{
				ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCSYNC-DECODE HASH CHECK FAILED for uri %s", r->unparsed_uri);
				apr_brigade_cleanup(bb);
				return APR_EGENERAL;
			}
			else
			{
				ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCSYNC-DECODE HASH CHECK PASSED for uri %s", r->unparsed_uri);
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
		//ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCSYNC-DECODE read %" APR_SIZE_T_FMT " bytes",len);

		apr_size_t consumed_bytes = 0;
		while (consumed_bytes < len)
		{
			//ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCSYNC-DECODE remaining %" APR_SIZE_T_FMT " bytes",len - consumed_bytes);
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
					{
						ctx->state = DECODING_LITERAL_SIZE;
						ctx->partial_literal = NULL;
						ctx->rx_count = 0;
					}
					else if (data[consumed_bytes] == ENCODING_HASH)
					{
						ctx->state = DECODING_HASH;
						ctx->rx_count = 0;
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
					size_t current_block_size = block_number < FULL_BLOCK_COUNT-1 ? ctx->block_size : ctx->tail_block_size;
					ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
							"CRCSYNC-DECODE block section, block %d, size %" APR_SIZE_T_FMT, block_number, current_block_size);

					char * buf = apr_palloc(r->pool, current_block_size);
					const char * source_data;
					size_t source_len;
					apr_bucket_read(ctx->cached_bucket, &source_data, &source_len, APR_BLOCK_READ);
					assert(block_number < (FULL_BLOCK_COUNT /*+ (ctx->tail_block_size != 0)*/));
					memcpy(buf,&source_data[block_number*ctx->block_size],current_block_size);
					// update our sha1 hash
					apr_sha1_update_binary(&ctx->sha1_ctx, (const unsigned char *)buf, current_block_size);
					apr_bucket * b = apr_bucket_pool_create(buf, current_block_size, r->pool, f->c->bucket_alloc);
					APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
					break;
				}
				case DECODING_LITERAL_SIZE:
				{
					unsigned avail_in = len - consumed_bytes;
					// if we havent got the full int then store the data for later
					if (avail_in < 4 || ctx->rx_count != 0)
					{
						if (ctx->partial_literal == NULL)
						{
							ctx->partial_literal = apr_palloc(r->pool, 4);
						}
						unsigned len_to_copy = MIN(4-ctx->rx_count, avail_in);
						memcpy(&ctx->partial_literal[ctx->rx_count], &data[consumed_bytes],len_to_copy);
						ctx->rx_count += len_to_copy;
						consumed_bytes += len_to_copy;

						if (ctx->rx_count == 4)
						{
							ctx->literal_size = ntohl(*(unsigned*)ctx->partial_literal);
							ctx->rx_count = 0;
						}
						else
						{
							break;
						}
					}
					else
					{
						ctx->literal_size = ntohl(*(unsigned*)&data[consumed_bytes]);
						consumed_bytes += 4;
					}
					ctx->partial_literal = apr_palloc(r->pool, ctx->literal_size);
					ctx->state = DECODING_LITERAL_BODY;
					break;
				}
				case DECODING_LITERAL_BODY:
				{
					unsigned avail_in = len - consumed_bytes;
					unsigned len_to_copy = MIN(ctx->literal_size-ctx->rx_count, avail_in);
					memcpy(&ctx->partial_literal[ctx->rx_count], &data[consumed_bytes],len_to_copy);
					ctx->rx_count += len_to_copy;
					consumed_bytes += len_to_copy;

					if (ctx->rx_count == ctx->literal_size)
					{
						apr_sha1_update_binary(&ctx->sha1_ctx, ctx->partial_literal, ctx->literal_size);
						apr_bucket * b = apr_bucket_pool_create((char*)ctx->partial_literal, ctx->literal_size, r->pool, f->c->bucket_alloc);
						APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
						ctx->state = DECODING_NEW_SECTION;
					}

					break;
				}
				case DECODING_HASH:
				{
					unsigned avail_in = len - consumed_bytes;
					// APR_SHA1_DIGESTSIZE bytes for a SHA1 hash
					unsigned needed = MIN(APR_SHA1_DIGESTSIZE-ctx->rx_count, avail_in);
					memcpy(&ctx->sha1_value_rx[ctx->rx_count], &data[consumed_bytes], needed);
					ctx->rx_count+=needed;
					consumed_bytes += needed;
					if (ctx->rx_count == 20)
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
							apr_sha1_update_binary(&ctx->sha1_ctx, (const unsigned char *)buf, have);
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

static void *crccache_client_create_config(apr_pool_t *p, server_rec *s) {
    ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, s,
                 "mod_crccache_client: entering crccache_client_create_config (%s)", 
                 format_hostinfo(p, s));

	
	crccache_client_conf *conf = apr_pcalloc(p, sizeof(crccache_client_conf));
    /* array of URL prefixes for which caching is enabled */
    conf->cacheenable = apr_array_make(p, 10, sizeof(struct cache_enable));
    /* array of URL prefixes for which caching is disabled */
    conf->cachedisable = apr_array_make(p, 10, sizeof(struct cache_disable));

	/* XXX: Set default values */
	conf->dirlevels = DEFAULT_DIRLEVELS;
	conf->dirlength = DEFAULT_DIRLENGTH;
	conf->maxfs = DEFAULT_MAX_FILE_SIZE;
	conf->minfs = DEFAULT_MIN_FILE_SIZE;

	conf->cache_root = NULL;
	// apr_pcalloc has already initialized everyting to 0
	// conf->cache_root_len = 0;

	// TODO: ____ rename once it works
	conf->similar_page_cache = create_similar_page_cache(p);

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
                                    const char *url)
{
	crccache_client_conf *conf;
    struct cache_enable *new;

    conf =
        (crccache_client_conf *)ap_get_module_config(parms->server->module_config,
                                                  &crccache_client_module);
    new = apr_array_push(conf->cacheenable);
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

static const char *set_cache_bytes(cmd_parms *parms, void *in_struct_ptr,
		const char *arg) {
	crccache_client_conf *conf = ap_get_module_config(parms->server->module_config,
			&crccache_client_module);
	return crccache_client_fsp_set_cache_bytes(parms, in_struct_ptr, arg, conf->similar_page_cache);
}

static const command_rec crccache_client_cmds[] =
{
    AP_INIT_TAKE1("CRCClientEnable", add_crc_client_enable, NULL, RSRC_CONF, "A partial URL prefix below which caching is enabled"),
	AP_INIT_TAKE1("CacheRootClient", set_cache_root, NULL, RSRC_CONF,"The directory to store cache files"),
	AP_INIT_TAKE1("CacheDirLevelsClient", set_cache_dirlevels, NULL, RSRC_CONF, "The number of levels of subdirectories in the cache"),
	AP_INIT_TAKE1("CacheDirLengthClient", set_cache_dirlength, NULL, RSRC_CONF, "The number of characters in subdirectory names"),
	AP_INIT_TAKE1("CacheMinFileSizeClient", set_cache_minfs, NULL, RSRC_CONF, "The minimum file size to cache a document"),
	AP_INIT_TAKE1("CacheMaxFileSizeClient", set_cache_maxfs, NULL, RSRC_CONF, "The maximum file size to cache a document"),
	AP_INIT_TAKE1("CRCClientSharedCacheSize", set_cache_bytes, NULL, RSRC_CONF, "Set the size of the shared memory cache (in bytes). Use 0 "
			"to disable the shared memory cache. (default: 10MB). "
			"Disabling the shared memory cache prevents the cache client from using a similar page as base for the delta-request "
			"when an exact match (on the URL) can not be found in the cache"),
	{ NULL }
};

int ap_run_insert_filter(request_rec *r);

int crccache_client_url_handler(request_rec *r, int lookup)
{
    const char *auth;
    cache_request_rec *cache;
    crccache_client_conf *conf;

    /* Delay initialization until we know we are handling a GET */
    if (r->method_number != M_GET) {
        return DECLINED;
    }

    conf = (crccache_client_conf *) ap_get_module_config(r->server->module_config,
                                                      &crccache_client_module);

    if (conf->cacheenable->nelts == 0)
    	return DECLINED;

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

    cache_handle_t *h;
    char *key;

    if (cache_generate_key(r, r->pool, &key) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
					 r->server, "Failed to generate key");
        return DECLINED;
    }
    h = apr_palloc(r->pool, sizeof(cache_handle_t));
    if (open_entity(h, r, key) == OK)
    {
    	if (recall_headers(h, r) == APR_SUCCESS) {
    		cache->handle = h;
    	}
    	else {
    		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
    					 r->server, "Failed to recall headers");
    	}
    	
    }
    else
    {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
					 r->server, "Failed to open entity");
    }
    if (request_crcsync_encoding(h, r, conf) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
					 r->server, "Failed to request CRCSYNC/delta-http encoding");
    }
    return DECLINED;
}

void post_store_body_callback(disk_cache_object_t *dobj, request_rec *r)
{
	// ____ 
	crccache_client_conf *conf = (crccache_client_conf *) ap_get_module_config(r->server->module_config,
                                                      &crccache_client_module);
	update_or_add_similar_page(dobj, r, conf->similar_page_cache);
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
    const char *cl;
    const char *exps, *dates;
    apr_time_t exp, now;
    apr_off_t size;
    cache_info_t *info = NULL;
    char *reason;

    /* Setup cache_request_rec */
    cache = (cache_request_rec *) ap_get_module_config(r->request_config,
                                                       &crccache_client_module);
    if (!cache) {
        /* user likely configured CACHE_SAVE manually; they should really use
         * mod_cache configuration to do that
         * TODO: Don't support this situation. In stead, write a WARNING to the log and abort the filter processing
         */
        cache = apr_pcalloc(r->pool, sizeof(cache_request_rec));
        ap_set_module_config(r->request_config, &crccache_client_module, cache);
    }

    reason = NULL;
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
        rv = store_body(cache->handle, r, in, &post_store_body_callback);
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
    }

    if (reason) {
        /* noop */
    }

    else if (r->status == HTTP_NOT_MODIFIED &&
             !cache->handle && !cache->stale_handle) {
        /* if the server said 304 Not Modified but we have no cache
         * file - pass this untouched to the user agent, it's not for us.
         */
        reason = "HTTP Status 304 Not Modified";
    }

    else if (r->header_only && !cache->stale_handle) {
        /* Forbid HEAD requests unless we have it cached already */
        reason = "HTTP HEAD request";
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
        char *key;
        cache_handle_t *h = apr_pcalloc(r->pool, sizeof(cache_handle_t));
        rv = cache_generate_key(r, r->pool, &key);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        rv = create_entity(h, r, key, size);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        cache->handle = h;
        info = apr_pcalloc(r->pool, sizeof(cache_info_t));
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
    // ap_remove_output_filter(cache->remove_url_filter);

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

    /* set response_time for HTTP/1.1 age calculations */
    info->response_time = now;

    /* get the request time */
    info->request_time = r->request_time;

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

    if(rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                     "cache: store_headers failed");
        ap_remove_output_filter(f);

        return ap_pass_brigade(f->next, in);
    }

    rv = store_body(cache->handle, r, in, &post_store_body_callback);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, r->server,
                     "cache: store_body failed");
        ap_remove_output_filter(f);
    }

    return ap_pass_brigade(f->next, in);
}

static void crccache_client_register_hook(apr_pool_t *p) {
	ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, NULL,
			"Registering crccache client module, (C) 2009, Toby Collett");

    /* cache initializer */
	ap_hook_post_config(crccache_client_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    /* cache handler */
    ap_hook_quick_handler(crccache_client_url_handler, NULL, NULL, APR_HOOK_FIRST);
    /* child initializer */
    ap_hook_child_init(crccache_client_child_init, NULL, NULL, APR_HOOK_REALLY_FIRST);
    
	/*
	 * CRCCACHE_DECODE must go into the filter chain before the cache save filter,
	 * so that the cache saves the decoded response
	 */
	crccache_decode_filter_handle = ap_register_output_filter(
			"CRCCACHE_DECODE", crccache_decode_filter, NULL,
			AP_FTYPE_CONTENT_SET);

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
     * TODO: Revise this logic. In order for the crccache to work properly, 
     *        the plain text content must be cached and not the deflated content
     *        Even more so, when receiving compressed content from the upstream
     *        server, the cache_save_filter handler should uncompress it before
     *        storing in the cache (but provide the compressed data to the client)
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
}

module AP_MODULE_DECLARE_DATA crccache_client_module = {
		STANDARD20_MODULE_STUFF, 
		NULL, /* create per-directory config structure */
		NULL,                       /* merge per-directory config structures */
		crccache_client_create_config, /* create per-server config structure */
		NULL, /* merge per-server config structures */
		crccache_client_cmds, /* command apr_table_t */
		crccache_client_register_hook /* register hooks */
	};
