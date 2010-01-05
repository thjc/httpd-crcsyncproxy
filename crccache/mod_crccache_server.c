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

#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_base64.h>

#include "ap_provider.h"

#include "util_filter.h"
#include "util_script.h"
#include "util_charset.h"

#include <http_log.h>
#include "ap_wrapper.h"

#include "crccache.h"
#include "mod_crccache_server.h"

#include <crcsync/crcsync.h>
#include <zlib.h>
#include <openssl/evp.h>

module AP_MODULE_DECLARE_DATA crccache_server_module;

// Possible states for the output compression
typedef enum  {
	COMPRESSION_BUFFER_EMPTY,
	COMPRESSION_FIRST_DATA_RECEIVED,
	COMPRESSION_FIRST_BLOCK_WRITTEN,
	COMPRESSION_ENDED
} compression_state_t;

static void *crccache_server_create_config(apr_pool_t *p, server_rec *s) {
	crccache_server_conf *conf = apr_pcalloc(p, sizeof(crccache_server_conf));
	conf->enabled = 0;
	conf->decoder_modules = NULL;
	conf->decoder_modules_cnt = 0;
	return conf;
}

typedef enum { GS_INIT, GS_HEADERS_SAVED, GS_ENCODING } global_state_t;

typedef struct crccache_ctx_t {
	global_state_t global_state;
	char *old_content_encoding;
	char *old_etag;
	unsigned char *buffer;
	size_t buffer_digest_getpos;
	size_t buffer_read_getpos;
	size_t buffer_putpos;
	size_t buffer_size;
	long crc_read_block_result;
	size_t crc_read_block_ndigested;
	apr_bucket_brigade *bb;
	unsigned block_count;
	size_t block_size;
	size_t tail_block_size;
	uint64_t *hashes;
	struct crc_context *crcctx;
	size_t orig_length;
	size_t tx_length;
	size_t tx_uncompressed_length;
	compression_state_t compression_state;
	z_stream *compression_stream;
	EVP_MD_CTX mdctx;
	int debug_skip_writing; // ____
} crccache_ctx;


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

static const char *set_crccache_decoder_module(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
	crccache_server_conf *conf = ap_get_module_config(parms->server->module_config,
				&crccache_server_module);
	struct decoder_modules_t *decoder_module = malloc(sizeof(*decoder_module));
	if (decoder_module == NULL)
	{
		return "Out of memory exception while allocating decoder_module structure";
	}
	char *tok;
	char *last = NULL;

	char *data = strdup(arg);
	if (data == NULL)
	{
		return "Out of memory exception while parsing DecoderModule parameter";
	}
	
	tok = apr_strtok(data, ": ", &last);
	if (tok == NULL)
	{
		return "DecoderModule value must be of format:  filtername:encoding[,encoding]*";
	}

	decoder_module->name = strdup(tok);
	if (decoder_module->name == NULL)
	{
		return "Out of memory exception while storing name in decoder_module structure";
	}
	
	tok = apr_strtok(NULL, ": ", &last);
	if (tok == NULL)
	{
		return "DecoderModule value must be of format:  filtername:encoding[,encoding]*";
	}
	
	for (tok = apr_strtok(tok, ", ", &last); tok != NULL; tok = apr_strtok(NULL, ", ", &last))
	{
		struct encodings_t *encoding = malloc(sizeof(*encoding));
		if (encoding == NULL)
		{
			return "Out of memory exception while allocating encoding structure";
		}

		encoding->encoding = strdup(tok);
		if (encoding->encoding == NULL)
		{
			return "Out of memory exception while storing encoding value in encoding structure";
		}
		
		// Insert new encoding to the head of the encodings list
		encoding->next = decoder_module->encodings;
		decoder_module->encodings = encoding;
	}

	// Insert (new) decoder module to the head of the decoder_modules list
	decoder_module->next = conf->decoder_modules;
	conf->decoder_modules = decoder_module;
	conf->decoder_modules_cnt++;
	
	return NULL;
}

static const command_rec crccache_server_cmds[] =
{
	AP_INIT_FLAG("CRCcacheServer", set_crccache_server, NULL, RSRC_CONF, "Enable the CRCCache server in this virtual server"),
	AP_INIT_TAKE1("DecoderModule", set_crccache_decoder_module, NULL, RSRC_CONF, "DecoderModules to decode content-types (e.g. INFLATE:gzip,x-gzip)"),
	{ NULL }
};

static ap_filter_rec_t *crccache_out_filter_handle;
static ap_filter_rec_t *crccache_out_save_headers_filter_handle;


int decode_if_block_header(const char * header, int * version, size_t * file_size, char ** hashes)
{
	*version = 1;
	*file_size = 0;
	*hashes = NULL; // this will be allocated below, make sure we free it
	int start = 0;
	int ii;
	size_t headerlen = strlen(header);
	for (ii = 0; ii < headerlen;++ii)
	{
		if (header[ii] == ';' || ii == headerlen-1)
		{
			sscanf(&header[start]," v=%d",version);
			sscanf(&header[start]," h=%as",hashes);
			sscanf(&header[start]," fs=%zu",file_size);
			start = ii + 1;
		}
	}

	if (*hashes == NULL)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "CRCCACHE-ENCODE no hashes reported in header");
		return -1;
	}
	if (*version != 1)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "CRCCACHE-ENCODE Unsupported header version, %d",*version);
		free(*hashes);
		*hashes = NULL;
		return -1;
	}
	if (*file_size == 0)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "CRCCACHE-ENCODE no file size reported in header");
		free(*hashes);
		*hashes = NULL;
		return -1;
	}
	return 0;
}

static int crccache_server_header_parser_handler(request_rec *r) {
	crccache_server_conf *conf = ap_get_module_config(r->server->module_config,
			&crccache_server_module);
	if (conf->enabled)
	{
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CRCCACHE-ENCODE Checking for headers");
		const char * header;
		header = apr_table_get(r->headers_in, BLOCK_HEADER);
		if (header)
		{
			crccache_ctx *ctx = apr_pcalloc(r->pool, sizeof(*ctx));
			ctx->global_state = GS_INIT;
			ctx->old_content_encoding = NULL;
			ctx->old_etag = NULL;

			int version;
			size_t file_size;
			char * hashes;
			if (decode_if_block_header(header,&version,&file_size,&hashes) < 0)
			{
				// failed to decode if block header so only put the Capability header in the response
				ap_add_output_filter_handle(crccache_out_filter_handle,
						ctx, r, r->connection);
				return OK;
			}
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CRCCACHE-ENCODE Block Hashes header found (hashes: %s)",hashes);
			free (hashes);
			hashes = NULL;
			
			// Add the filter to save the headers, so that they can be restored after an optional INFLATE or other decoder module
			ap_add_output_filter_handle(crccache_out_save_headers_filter_handle,
					ctx, r, r->connection);

			char *accept_encoding = apr_pstrdup(r->pool, apr_table_get(r->headers_in, ACCEPT_ENCODING_HEADER));
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CRCCACHE-ENCODE Incoming Accept-Encoding header: %s", accept_encoding == NULL ? "NULL" : accept_encoding);
			if (accept_encoding != NULL)
			{
				struct decoder_modules_t *required_dms[conf->decoder_modules_cnt];
				unsigned required_dms_size = 0;
				char *tok;
				char *last = NULL;
				struct decoder_modules_t *dm;
				struct encodings_t *enc;
				unsigned cnt;
				// Build the list of filter modules to handle the requested encodings and 
				// remove all non-supported encodings from the header
				apr_table_unset(r->headers_in, ACCEPT_ENCODING_HEADER);
				for (tok = apr_strtok(accept_encoding, ", ", &last); tok != NULL; tok = apr_strtok(NULL, ", ", &last)) {
					for (dm = conf->decoder_modules; dm != NULL; dm = dm->next) {
						for (enc = dm->encodings; enc != NULL; enc = enc->next) {
							if (strcmp(tok, enc->encoding) == 0)
							{
								// This module supports the requested encoding
								// Add it to the list if it is not already present
								for (cnt = 0; cnt != required_dms_size; cnt++)
								{
									if (required_dms[cnt] == dm)
										break; // module is already inserted in list
								}
								if (cnt == required_dms_size)
								{
									required_dms[required_dms_size++] = dm;
								}
								apr_table_mergen(r->headers_in, ACCEPT_ENCODING_HEADER, tok);
							}
						}
					}
				}
				// Enable the requested filter modules 
				for (cnt = 0; cnt != required_dms_size; cnt++)	{
					dm = required_dms[cnt];
					ap_filter_t *filter = ap_add_output_filter(dm->name, NULL, r, r->connection);
					if (filter == NULL) {
						ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r->server,	"CRCCACHE-ENCODE Could not enable %s filter", dm->name);
						// Remove the encodings handled by this filter from the list of accepted encodings
						accept_encoding = apr_pstrdup(r->pool, apr_table_get(r->headers_in, ACCEPT_ENCODING_HEADER));
						apr_table_unset(r->headers_in, ACCEPT_ENCODING_HEADER);
						for (tok = apr_strtok(accept_encoding, ", ", &last); tok != NULL; tok = apr_strtok(NULL, ", ", &last)) {
							for (enc = dm->encodings; enc != NULL; enc = enc->next) {
								if (strcmp(tok, enc->encoding)==0) {
									ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r->server,	"CRCCACHE-ENCODE Removing encoding %s", tok);
									break;
								}
							}
							if (enc == NULL) {
								// Did not find the tok encoding in the list. It can be merged back into the header
								apr_table_mergen(r->headers_in, ACCEPT_ENCODING_HEADER, tok);
							}
						}
					}
					else
					{
						ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "CRCCACHE-ENCODE Successfully enabled %s filter", dm->name);
					}
				}
				const char *updated_accept_encoding = apr_table_get(r->headers_in, ACCEPT_ENCODING_HEADER);
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CRCCACHE-ENCODE Modified Accept-Encoding header: %s", updated_accept_encoding == NULL ? "NULL" : updated_accept_encoding);
			}
			// Add the crccache filter itself, after the decoder modules
			ap_add_output_filter_handle(crccache_out_filter_handle,
					ctx, r, r->connection);
		}
		else
		{
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CRCCACHE-ENCODE Did not detect blockheader (%s)", BLOCK_HEADER);
		}
			
/*		// All is okay, so set response header to IM Used
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "CRCCACHE-ENCODE Setting 226 header");
		r->status=226;
		r->status_line="226 IM Used";
		return 226;*/
	}
	return OK;
}

/*static int crccache_server_header_filter_handler(ap_filter_t *f, apr_bucket_brigade *b) {
	//request_rec *r)
	request_rec *r = f->r;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE Setting return status code");

// All is okay, so set response header to IM Used
	r->status=226;
	r->status_line="HTTP/1.1 226 IM Used";
	return 226;
}*/

static void crccache_check_etag(request_rec *r, crccache_ctx *ctx, const char *transform) {
	const char *etag = ctx->old_etag;
	if (etag) {
		apr_table_set(r->headers_out, ETAG_HEADER, 
				apr_pstrcat(
						r->pool, 
						etag, "-",
						transform, "-",
						ctx->old_content_encoding == NULL ? "identity" : ctx->old_content_encoding,
						NULL
				)
		);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "CRCCACHE-ENCODE Changed ETag header to %s", apr_table_get(r->headers_out, ETAG_HEADER));
	}
}

static apr_status_t write_compress_buffer(ap_filter_t *f, int flush)
{
	unsigned char compress_buf[30000];
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;
	z_stream *strm = ctx->compression_stream;

	if (ctx->debug_skip_writing)
		return APR_SUCCESS;

	do
	{
		strm->avail_out = sizeof(compress_buf);
		strm->next_out = compress_buf;
		uInt avail_in_pre_deflate = strm->avail_in;
		int zRC = deflate(strm, flush);
		if (zRC == Z_STREAM_ERROR)
		{
			ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r->server,"CRCCACHE-ENCODE deflate error: %d", zRC);
			return APR_EGENERAL;
		}
		int have = sizeof(compress_buf) - strm->avail_out;
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
				"CRCCACHE-ENCODE deflate rslt %d, flush %d, consumed %d, produced %d",
				zRC, flush, avail_in_pre_deflate - strm->avail_in, have);
		if (have != 0)
		{
			// output buffer contains some data to be written
			// ap_log_hex(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, compress_buf, have);
			unsigned bucket_size = have;
			if (ctx->compression_state != COMPRESSION_FIRST_BLOCK_WRITTEN)
			{
				bucket_size += ENCODING_COMPRESSED_HEADER_SIZE;
			}
			ctx->tx_length += bucket_size;
			char * buf = apr_palloc(r->pool, bucket_size);

			if (ctx->compression_state != COMPRESSION_FIRST_BLOCK_WRITTEN)
			{
				buf[0] = ENCODING_COMPRESSED;
				memcpy(buf + ENCODING_COMPRESSED_HEADER_SIZE, compress_buf, have);
				ctx->compression_state = COMPRESSION_FIRST_BLOCK_WRITTEN;
			}
			else
			{
				memcpy(buf, compress_buf, have);
			}
			apr_bucket * b = apr_bucket_pool_create(buf, bucket_size, r->pool, f->c->bucket_alloc);
			APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
		}
	}
	while (strm->avail_out == 0);
	if (strm->avail_in != 0)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, r->server,"CRCCACHE-ENCODE deflate still has %d input bytes available", strm->avail_in);
		return APR_EGENERAL;
	}

	return APR_SUCCESS;
}


static apr_status_t flush_compress_buffer(ap_filter_t *f)
{
	crccache_ctx *ctx = f->ctx;
	apr_status_t rslt = APR_SUCCESS; // assume all will be fine

	if (ctx->debug_skip_writing)
		return APR_SUCCESS;

	if (ctx->compression_state != COMPRESSION_BUFFER_EMPTY)
	{
		rslt = write_compress_buffer(f, Z_FINISH); // take the real status
		deflateReset(ctx->compression_stream);
		ctx->compression_state = COMPRESSION_BUFFER_EMPTY;
		// ____ ctx->debug_skip_writing = 1; // skip writing after handling first compressed block
	}
	return rslt;
}

/**
 * Write literal data
 */
static apr_status_t write_literal(ap_filter_t *f, unsigned char *buffer, long count)
{
	crccache_ctx *ctx = f->ctx;

	if (ctx->debug_skip_writing)
		return APR_SUCCESS;

	apr_status_t rslt;
	if (ctx->compression_state == COMPRESSION_BUFFER_EMPTY)
	{
		ctx->compression_state = COMPRESSION_FIRST_DATA_RECEIVED;
	}
	ctx->compression_stream->avail_in = count;
	ctx->compression_stream->next_in = buffer;
	// ap_log_hex(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, f->r->server, buffer, count);
	rslt = write_compress_buffer(f, Z_NO_FLUSH);
	ctx->tx_uncompressed_length += count;
	return rslt;
}

/**
 * Write hash
 */
static apr_status_t write_hash(ap_filter_t *f, unsigned char *buffer, long count)
{
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;
	apr_status_t rslt;

	rslt = flush_compress_buffer(f);
	if (rslt != APR_SUCCESS)
	{
		return rslt;
	}

	if (ctx->debug_skip_writing)
		return APR_SUCCESS;

	unsigned bucket_size = count + 1;
	ctx->tx_length += bucket_size;
	ctx->tx_uncompressed_length += bucket_size;
	char * buf = apr_palloc(r->pool, bucket_size);

	buf[0] = ENCODING_HASH;
	memcpy(&buf[1],buffer,count);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE HASH");
	apr_bucket * b = apr_bucket_pool_create(buf, bucket_size, r->pool, f->c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
	return APR_SUCCESS;
}


/**
 * Write a block reference
 */
static apr_status_t write_block_reference(ap_filter_t *f, long result)
{
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;
	apr_status_t rslt;

	rslt = flush_compress_buffer(f);
	if (rslt != APR_SUCCESS)
	{
		return rslt;
	}

	if (ctx->debug_skip_writing)
		return APR_SUCCESS;

	unsigned bucket_size = ENCODING_BLOCK_HEADER_SIZE;
	ctx->tx_length += bucket_size;
	ctx->tx_uncompressed_length += bucket_size;
	char * buf = apr_palloc(r->pool, bucket_size);

	buf[0] = ENCODING_BLOCK;
	buf[1] = (unsigned char) ((-result)-1); // invert and get back to zero based
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE block %d",buf[1]);
	apr_bucket * b = apr_bucket_pool_create(buf, bucket_size, r->pool, f->c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
	return APR_SUCCESS;
}

/*
 * Process one block of data: try to match it against the CRC, append
 * the result to the ouput ring and remember the result (e.g. was
 * it a block-match or was a literal processed)
 */
static apr_status_t process_block(ap_filter_t *f)
{
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;
	apr_status_t rslt = APR_SUCCESS;

	// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE invoking crc_read_block");
	if (ctx->crcctx == NULL)
	{
		// This should never happen
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server,"CRCCACHE-ENCODE crcctx = null");
		return APR_EGENERAL;
	}

	long rd_block_rslt;
	size_t ndigested = crc_read_block(
		ctx->crcctx,
		&rd_block_rslt,
		ctx->buffer+ctx->buffer_digest_getpos,
		ctx->buffer_putpos-ctx->buffer_digest_getpos
	);
	ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
			"CRCCACHE-ENCODE crc_read_block ndigested: %zu, result %ld", ndigested, rd_block_rslt);


	// rd_block_rslt = 0: do nothing (it is a 'literal' block of exactly 'tail_blocksize' bytes at the end of the buffer,
	//  it will have to be moved to the beginning of the moving window so that it can be written upon the next call to
	//  crc_read_block or crc_read_flush)
	// rd_block_rslt > 0: send literal
	// rd_block_rslt < 0: send block
	if (rd_block_rslt > 0)
	{
		rslt = write_literal(f, ctx->buffer+ctx->buffer_read_getpos, rd_block_rslt);
		ctx->buffer_read_getpos += rd_block_rslt;
	}
	else if (rd_block_rslt < 0)
	{
		rslt = write_block_reference(f, rd_block_rslt);
		unsigned char blocknum = (unsigned char) ((-rd_block_rslt)-1);
		ctx->buffer_read_getpos += (blocknum == ctx->block_count-1) ? ctx->tail_block_size : ctx->block_size;
	}

	// Update the context with the results
	ctx->crc_read_block_result = rd_block_rslt;
	ctx->crc_read_block_ndigested = ndigested;
	ctx->buffer_digest_getpos += ndigested;
	return rslt;
}

/*
 * Flush one block of data: get it from the crccontext, append
 * the result to the ouput ring and remember the result (e.g. was
 * it a block-match or was a literal processed)
 */
static apr_status_t flush_block(ap_filter_t *f)
{
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;
	apr_status_t rslt = APR_SUCCESS;

	// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE invoking crc_read_flush");
	if (ctx->crcctx == NULL)
	{
		// This should never happen
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server,"CRCCACHE-ENCODE crcctx = null");
		return APR_EGENERAL;
	}
	long rd_flush_rslt = crc_read_flush(ctx->crcctx);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE crc_read_flush result %ld", rd_flush_rslt);

	// rd_flush_rslt = 0: do nothing
	// rd_flush_rslt > 0: send literal that was already digested but not yet returned by read-block
	// rd_flush_rslt < 0: send block that was already digested but not yet returned by read-block
	if (rd_flush_rslt > 0)
	{
		rslt = write_literal(f, ctx->buffer+ctx->buffer_read_getpos, rd_flush_rslt);
		ctx->buffer_read_getpos += rd_flush_rslt;
	}
	else if (rd_flush_rslt < 0)
	{
		rslt = write_block_reference(f, rd_flush_rslt);
		unsigned char blocknum = (unsigned char) ((-rd_flush_rslt)-1);
		ctx->buffer_read_getpos += (blocknum == ctx->block_count-1) ? ctx->tail_block_size : ctx->block_size;
	}

	// Update the context with the results
	ctx->crc_read_block_result = rd_flush_rslt;
	ctx->crc_read_block_ndigested = 0;
	return rslt;
}

/**
 * Clean-up memory used by helper libraries, that don't know about apr_palloc
 * and that (probably) use classical malloc/free
 */
static apr_status_t deflate_ctx_cleanup(void *data)
{
	crccache_ctx *ctx = (crccache_ctx *)data;

    if (ctx != NULL)
    {
    	if (ctx->compression_state != COMPRESSION_ENDED)
    	{
    		deflateEnd(ctx->compression_stream);
    		ctx->compression_state = COMPRESSION_ENDED;
    	}
    	if (ctx->crcctx != NULL)
    	{
    		crc_context_free(ctx->crcctx);
    		ctx->crcctx = NULL;
    	}
    }
    return APR_SUCCESS;
}
/*
 * End of stream has been reached:
 * Process any data still in the buffer and flush all internal
 * structures of crcsync and of zlib
 * Furthermore, add a strong hash
 */
static apr_status_t process_eos(ap_filter_t *f)
{
	crccache_ctx *ctx = f->ctx;
	apr_status_t rslt;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, f->r->server,"CRCCACHE-ENCODE EOS reached for APR bucket");


	while (ctx->buffer_digest_getpos < ctx->buffer_putpos)
	{
		// There is still data in the buffer. Process it.
		rslt = process_block(f);
		if (rslt != APR_SUCCESS)
		{
			return rslt;
		}
	}

	do
	{
		// Flush remaining block in the crcctx
		rslt = flush_block(f);
		if (rslt != APR_SUCCESS)
		{
			return rslt;
		}
	}
	while (ctx->crc_read_block_result != 0);

	// Flush anything that is remaining in the compress buffer
	rslt = flush_compress_buffer(f);
	if (rslt != APR_SUCCESS)
	{
		return rslt;
	}

	unsigned md_len;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	EVP_DigestFinal_ex(&ctx->mdctx, md_value, &md_len);
	EVP_MD_CTX_cleanup(&ctx->mdctx);
	write_hash(f, md_value, md_len);

	ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, f->r->server,
		"CRCCACHE-ENCODE complete size %f%% (encoded-uncompressed=%zu encoded=%zu original=%zu",100.0*((float)ctx->tx_length/(float)ctx->orig_length),ctx->tx_uncompressed_length, ctx->tx_length, ctx->orig_length);

	return APR_SUCCESS;
}

/*
 * Process a data bucket; append data into a moving window buffer
 * and encode it with crcsync algorithm when window contains enough
 * data for crcsync to find potential matches
 */
static apr_status_t process_data_bucket(ap_filter_t *f, apr_bucket *e)
{
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;

	const char *data;
	apr_size_t len;
	apr_status_t rslt;

	/* read */
	apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
	ctx->orig_length += len;
	// update our sha1 hash
	EVP_DigestUpdate(&ctx->mdctx, data, len);
	// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE normal data in APR bucket, read %ld", len);

	// append data to the buffer and encode buffer content using the crc_read_block magic
	size_t bucket_used_count = 0;
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
			ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
					"CRCCACHE-ENCODE Buffer is filled to end, read_getpos: %zu, digest_getpos: %zu, putpos: %zu, putpos-digest_getpos: %zu (tail_block_size: %zu)",
					ctx->buffer_read_getpos, ctx->buffer_digest_getpos, ctx->buffer_putpos, ctx->buffer_putpos-ctx->buffer_digest_getpos, ctx->tail_block_size);
			while (ctx->buffer_putpos - ctx->buffer_digest_getpos > ctx->tail_block_size)
			{
				// We can still scan at least 1 tail block + 1 byte forward: try to flush next part
				rslt = process_block(f);
				if (rslt != APR_SUCCESS)
				{
					return rslt;
				}
				ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
						"CRCCACHE-ENCODE Processed a block, read_getpos: %zu, digest_getpos: %zu, putpos: %zu, putpos-digest_getpos: %zu (tail_block_size: %zu)",
					ctx->buffer_read_getpos, ctx->buffer_digest_getpos, ctx->buffer_putpos, ctx->buffer_putpos-ctx->buffer_digest_getpos, ctx->tail_block_size);
			}

			if (ctx->buffer_putpos != ctx->buffer_read_getpos)
			{
				// Copy the remaining part of the buffer to the start of the buffer,
				// so that it can be filled again as new data arrive
				ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
						"CRCCACHE-ENCODE Moving %zu bytes to begin of buffer",
						ctx->buffer_putpos - ctx->buffer_read_getpos);
				memcpy(ctx->buffer, ctx->buffer + ctx->buffer_read_getpos, ctx->buffer_putpos - ctx->buffer_read_getpos);
			}
			// Reset getpos to the beginning of the buffer and putpos accordingly
			ctx->buffer_putpos -= ctx->buffer_read_getpos;
			ctx->buffer_digest_getpos -= ctx->buffer_read_getpos;
			ctx->buffer_read_getpos = 0;
		}
		while (ctx->crc_read_block_result < 0 && ctx->buffer_putpos - ctx->buffer_digest_getpos > ctx->tail_block_size)
		{
			// Previous block matched exactly. Let's hope the next block as well
			ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
					"CRCCACHE-ENCODE Previous block matched, read_getpos: %zu, digest_getpos: %zu, putpos: %zu, putpos-digest_getpos: %zu (tail_block_size: %zu)",
					ctx->buffer_read_getpos, ctx->buffer_digest_getpos, ctx->buffer_putpos, ctx->buffer_putpos-ctx->buffer_digest_getpos, ctx->tail_block_size);
			rslt = process_block(f);
			if (rslt != APR_SUCCESS)
			{
				return rslt;
			}
		}
	}
	return APR_SUCCESS; // Yahoo, all went well
}

/*
 * CACHE_OUT filter
 * ----------------
 *
 * Deliver cached content (headers and body) up the stack.
 */
static apr_status_t crccache_out_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
	apr_bucket *e;
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;
	int zRC;
	int return_code = APR_SUCCESS;

	/* Do nothing if asked to filter nothing. */
	if (APR_BRIGADE_EMPTY(bb)) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE bucket brigade is empty -> nothing todo");
		return ap_pass_brigade(f->next, bb);
	}

	/* If state is not yet GS_ENCODING content, we need to ensure that it is okay to send
	 * the encoded content.  If the state is GS_ENCODING, that means we've done
	 * this before and we liked it.
	 * This could be not so nice if we always fail.  But, if we succeed,
	 * we're in better shape.
	 */
	if (ctx->global_state != GS_ENCODING)
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
		
		// Advertise crcsync capability and preferred blocksize multiple
		apr_table_mergen(r->headers_out, CAPABILITY_HEADER, "crcsync; m=1");

		if (ctx->global_state == GS_INIT)
		{
			// Still in GS_INIT state implies there is no need to encode.
			// It is sufficient that the capability header has been set
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}
		
		if (ctx->global_state != GS_HEADERS_SAVED)
		{
			ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "CRCCACHE-ENCODE unexpected ctx-state: %d, expected: %d", ctx->global_state, GS_HEADERS_SAVED);
			return APR_EGENERAL;
		}

		/* Indicate to caches that they may only re-use this response for a request
		 * with the same BLOCK_HEADER value as the current request
		 * Indicate to clients that the server supports crcsync, even if checks
		 * further down prevent this specific response from being crc-encoded
		 */
		apr_table_mergen(r->headers_out, VARY_HEADER, BLOCK_HEADER);

		/* If Content-Encoding is present and differs from "identity", we can't handle it */
		encoding = apr_table_get(r->headers_out, ENCODING_HEADER);
		if (encoding && strcasecmp(encoding, "identity")) {
			ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r->server,
					"Not encoding with crccache. It is already encoded with: %s", encoding);
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}

		/* For a 304 or 204 response there is no entity included in
		 * the response and hence nothing to crc-encode. */
		if (r->status == HTTP_NOT_MODIFIED || r->status ==HTTP_NO_CONTENT)
		{
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}

		/* All Ok. We're cool with filtering this. */
		ctx->global_state = GS_ENCODING;
		ctx->debug_skip_writing = 0;
		ctx->orig_length = 0;
		ctx->tx_length = 0;
		ctx->tx_uncompressed_length = 0;
		ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);

		/* Parse the input headers */
		const char * header;
		header = apr_table_get(r->headers_in, BLOCK_HEADER);
		int version;
		size_t file_size;
		char * hashes;
		if (decode_if_block_header(header,&version,&file_size,&hashes) < 0)
		{
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,"crccache: failed to decode if-block header");
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}
		// Decode the hashes
		ctx->block_count = apr_base64_decode_len(hashes)/(HASH_SIZE/8);
		// this may over allocate by a couple of bytes but no big deal
		ctx->hashes = apr_palloc(r->pool, apr_base64_decode_len(hashes));
		apr_base64_decode((char *)ctx->hashes, hashes);
		free(hashes);
		hashes = NULL;

		ctx->block_size = file_size/ctx->block_count;
		ctx->tail_block_size = ctx->block_size + file_size % ctx->block_count;
		size_t block_count_including_final_block = ctx->block_count;// + (ctx->tail_block_size != 0);
		ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r->server,
				"If-block header decoded, version %d: %d hashes of %d and one of %d", version, ctx->block_count-1,(int)ctx->block_size,(int)ctx->tail_block_size);

		// swap to network byte order
		int i;
		for (i = 0; i < block_count_including_final_block;++i)
		{
			htobe64(ctx->hashes[i]);
		}

		// Data come in at chunks that are potentially smaller then block_size or tail_block_size
		// Accumulate those chunks into a buffer.
		// The buffer must be at least block_size+tail_block_size so that crc_read_block(...) can find a matching block, regardless
		// of the data alignment compared to the original page.
		// The buffer is basically a moving window in the new page. So sometimes the last part of the buffer must be
		// copied to the beginning again. The larger the buffer, the less often such a copy operation is required
		// Though, the larger the buffer, the bigger the memory demand.
		// A size of 3*block_size+tail_block_size+1 (20% of original file size) seems to be a good balance

		// TODO: tune the buffer-size depending on the mime-type. Already compressed data (zip, gif, jpg, mpg, etc) will
		// probably only have matching blocks if the file is totally unmodified. As soon as one byte differs in the original
		// uncompressed data, the entire compressed data stream will be different anyway, so in such case it does not make
		// much sense to even keep invoking the crc_read_block(...) function as soon as a difference has been found.
		// Hence, no need to make a (potentially huge) buffer for these type of compressed (potentially huge, think about movies)
		// data types.
		ctx->buffer_size = ctx->block_size*3 + ctx->tail_block_size + 1;
		ctx->buffer_digest_getpos = 0;
		ctx->buffer_read_getpos = 0;
		ctx->buffer_putpos = 0;
		ctx->crc_read_block_result = 0;
		ctx->buffer = apr_palloc(r->pool, ctx->buffer_size);

		/* Setup deflate for compressing non-matched literal data */
		ctx->compression_state = COMPRESSION_BUFFER_EMPTY;
		// TODO: should I pass some apr_palloc based function to prevent memory leaks
		//in case of unexpected errors?

		ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE size of compression stream: %zd",sizeof(*(ctx->compression_stream)));
		ctx->compression_stream = apr_palloc(r->pool, sizeof(*(ctx->compression_stream)));
		ctx->compression_stream->zalloc = Z_NULL;
		ctx->compression_stream->zfree = Z_NULL;
		ctx->compression_stream->opaque = Z_NULL;
		zRC = deflateInit(ctx->compression_stream, Z_DEFAULT_COMPRESSION); // TODO: make compression level configurable
		if (zRC != Z_OK)
		{
			// Can't initialize the compression engine for compressing literal data
			deflateEnd(ctx->compression_stream); // free memory used by deflate
			free(ctx->compression_stream);
			ctx->compression_stream = NULL;
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
							"unable to init Zlib: "
							"deflateInit returned %d: URL %s",
							zRC, r->uri);
			ap_remove_output_filter(f);
			return ap_pass_brigade(f->next, bb);
		}

		// initialise the context for our sha1 digest of the unencoded response
		EVP_MD_CTX_init(&ctx->mdctx);
		const EVP_MD *md = EVP_sha1();
		EVP_DigestInit_ex(&ctx->mdctx, md, NULL);

		// now initialise the crcsync context that will do the real work
		ctx->crcctx = crc_context_new(ctx->block_size, HASH_SIZE,ctx->hashes, block_count_including_final_block, ctx->tail_block_size);

		// Register a cleanup function to cleanup internal libz and crcsync resources
		apr_pool_cleanup_register(r->pool, ctx, deflate_ctx_cleanup,
                                  apr_pool_cleanup_null);

		// All checks and initializations are OK
		// Modify headers that are impacted by this transformation
		apr_table_setn(r->headers_out, ENCODING_HEADER, CRCCACHE_ENCODING);
		apr_table_unset(r->headers_out, "Content-Length");
		apr_table_unset(r->headers_out, "Content-MD5");
		crccache_check_etag(r, ctx, CRCCACHE_ENCODING);

		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "CRCCACHE Server end of context setup");
	}

	if (ctx->global_state != GS_ENCODING)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "CRCCACHE-ENCODE unexpected ctx-state: %d, expected: %d", ctx->global_state, GS_ENCODING);
		return APR_EGENERAL;
	}

	while (!APR_BRIGADE_EMPTY(bb))
	{
		const char *data;
		apr_size_t len;
		apr_status_t rslt;

		e = APR_BRIGADE_FIRST(bb);

		if (APR_BUCKET_IS_EOS(e))
		{
			// Process end of stream: flush data buffers, compression buffers, etc.
			// and calculate a strong hash.
			rslt = process_eos(f);

			/* Remove EOS from the old list, and insert into the new. */
			APR_BUCKET_REMOVE(e);
			APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

			/* This filter is done once it has served up its content */
			ap_remove_output_filter(f);

			if (rslt != APR_SUCCESS)
			{
				return rslt; // A problem occurred. Abort the processing
			}

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
			/*
			 * Remove meta data bucket from old brigade and insert into the
			 * new.
			 */
			apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
			if (len > 2)
				ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
				"CRCCACHE-ENCODE Metadata, read %zu, %d %d %d",len,data[0],data[1],data[2]);
			else
				ap_log_error_wrapper(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
								"CRCCACHE-ENCODE Metadata, read %zu",len);
			APR_BUCKET_REMOVE(e);
			APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
			continue;
		}

		// Bucket is non of the above types. Assume it is a data bucket
		// which means it can be encoded with the crcsync algorithm
		rslt = process_data_bucket(f, e);

		APR_BUCKET_REMOVE(e);
        if (rslt != APR_SUCCESS)
        {
        	break; // A problem occurred. Abort the processing
        }
    }

    apr_brigade_cleanup(bb);
    return return_code;
}


/*
 * CACHE_OUT_SAVE_HEADERS filter
 * ----------------
 *
 * Save headers into the context
 */
static apr_status_t crccache_out_save_headers_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
	request_rec *r = f->r;
	crccache_ctx *ctx = f->ctx;

	/* Do nothing if asked to filter nothing. */
	if (APR_BRIGADE_EMPTY(bb)) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,"CRCCACHE-ENCODE (save headers) bucket brigade is empty -> nothing todo");
		return ap_pass_brigade(f->next, bb);
	}

	if (ctx->global_state != GS_INIT)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r->server, "CRCCACHE-ENCODE (save headers) unexpected ctx-state: %d, expected: %d", ctx->global_state, GS_INIT);
		return APR_EGENERAL;
	}
	
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

	 /* Save content-encoding and etag header for later usage by the crcsync
	  * encoder
	 */
	const char *encoding = apr_table_get(r->headers_out, ENCODING_HEADER);
	if (encoding != NULL)
	{
		ctx->old_content_encoding = apr_pstrdup(r->pool, encoding);
		ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r->server,
				"Saved old content-encoding: %s", encoding);
	}
	const char *etag = apr_table_get(r->headers_out, ETAG_HEADER);
	if (etag != NULL)
	{
		ctx->old_etag = apr_pstrdup(r->pool, etag);
		ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r->server,
				"Saved old etag: %s", etag);
	}
	ctx->global_state = GS_HEADERS_SAVED;
	
	/* Done saving headers. Nothing left to do */
	ap_remove_output_filter(f);
	return ap_pass_brigade(f->next, bb);
}


static void crccache_server_register_hook(apr_pool_t *p) {
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, NULL,
			"Registering crccache server module, (C) 2009, Toby Collett and Alex Wulms");

	ap_hook_header_parser(crccache_server_header_parser_handler, NULL, NULL,
			APR_HOOK_MIDDLE);
/*
        ap_register_output_filter("CRCCACHE_HEADER", crccache_server_header_filter_handler,
                                  NULL, AP_FTYPE_PROTOCOL);
*/
	crccache_out_save_headers_filter_handle = ap_register_output_filter("CRCCACHE_OUT_SAVE_HEADERS",
			crccache_out_save_headers_filter, NULL, AP_FTYPE_RESOURCE-1); // make sure to handle it *before* INFLATE filter (or other decode modules)
	
	crccache_out_filter_handle = ap_register_output_filter("CRCCACHE_OUT",
			crccache_out_filter, NULL, AP_FTYPE_CONTENT_SET);
}

module AP_MODULE_DECLARE_DATA crccache_server_module = {
		STANDARD20_MODULE_STUFF, NULL, /* create per-directory config structure */
		NULL ,                       /* merge per-directory config structures */
		crccache_server_create_config, /* create per-server config structure */
		NULL		, /* merge per-server config structures */
		crccache_server_cmds, /* command apr_table_t */
		crccache_server_register_hook /* register hooks */
	};
