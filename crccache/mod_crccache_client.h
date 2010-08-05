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
#include <ap_config.h>
#include <http_config.h>
#include <apr_optional.h>
#include <apr_sha1.h>
#include "mod_crccache_client_find_similar.h"

extern module AP_MODULE_DECLARE_DATA crccache_client_module;

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

    similar_page_cache_t *similar_page_cache;
} crccache_client_conf;

#endif /*MOD_CRCCACHE_CLIENT_H*/

