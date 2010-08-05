/*
 * mod_crccache_client.h
 *
 *  Created on: 15/03/2009
 *      Author: awulms
 */
#ifndef MOD_CRCCACHE_CLIENT_FIND_SIMILAR_H
#define MOD_CRCCACHE_CLIENT_FIND_SIMILAR_H

#include "cache/cache.h"
#include <apr_pools.h>
#include <apr_shm.h>
#include <apr_rmm.h>
#include <apr_global_mutex.h>
#include <apr_hash.h>
#include <http_config.h>

typedef struct similar_page_cache_s similar_page_cache_t;

similar_page_cache_t *create_similar_page_cache(apr_pool_t *p);

const char *crccache_client_fsp_set_cache_bytes(cmd_parms *parms, void *in_struct_ptr,
		const char *arg, similar_page_cache_t *conf);

int crccache_client_fsp_post_config_per_virtual_host(apr_pool_t *p, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s, similar_page_cache_t *conf, const char *cache_root);

void crccache_client_fsp_child_init_per_virtual_host(apr_pool_t *p, server_rec *s, similar_page_cache_t *conf);

apr_status_t find_similar_page(disk_cache_object_t *dobj, request_rec *r, similar_page_cache_t *sp_cache);

void update_or_add_similar_page(disk_cache_object_t *dobj, request_rec *r, similar_page_cache_t *sp_cache);

#endif /* MOD_CRCCACHE_CLIENT_FIND_SIMILAR_H */