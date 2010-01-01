/*
 * mod_crccache_client.h
 *
 *  Created on: 15/03/2009
 *      Author: awulms
 */

#ifndef MOD_CRCCACHE_CLIENT_H
#define MOD_CRCCACHE_CLIENT_H

#include "cache/cache.h"
#include <zlib.h>
#include <openssl/evp.h>
#include <ap_config.h>
#include <http_config.h>
#include <apr_optional.h>

extern module AP_MODULE_DECLARE_DATA crccache_client_module;

const char* cache_create_key( request_rec*r );

APR_DECLARE_OPTIONAL_FN(apr_status_t,
                        ap_cache_generate_key,
                        (request_rec *r, apr_pool_t*p, char**key ));

extern APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;


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
	EVP_MD_CTX mdctx;
	unsigned char md_value_calc[EVP_MAX_MD_SIZE];
	unsigned char md_value_rx[EVP_MAX_MD_SIZE];
	unsigned rx_count;
	unsigned literal_size;
	unsigned char * partial_literal;// original data so we can fill in the matched blocks
} crccache_client_ctx;

struct cache_enable {
    apr_uri_t url;
    const char *type;
    apr_size_t pathlen;
};

struct cache_disable {
    apr_uri_t url;
    apr_size_t pathlen;
};

/* static information about the local cache */
typedef struct {
	// from mod cache
    apr_array_header_t *cacheenable;    /* URLs to cache */
    apr_array_header_t *cachedisable;   /* URLs not to cache */

    // from mod diskcache
    const char* cache_root;
    apr_size_t cache_root_len;
    int dirlevels;               /* Number of levels of subdirectories */
    int dirlength;               /* Length of subdirectory names */
    apr_off_t minfs;             /* minimum file size for cached files */
    apr_off_t maxfs;             /* maximum file size for cached files */
} crccache_client_conf;

#endif /*MOD_CRCCACHE_CLIENT_H*/

