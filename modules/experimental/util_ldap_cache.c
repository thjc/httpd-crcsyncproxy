/* Copyright 2001-2004 The Apache Software Foundation
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

/*
 * util_ldap_cache.c: LDAP cache things
 * 
 * Original code from auth_ldap module for Apache v1.3:
 * Copyright 1998, 1999 Enbridge Pipelines Inc. 
 * Copyright 1999-2001 Dave Carrigan
 */

#include <apr_ldap.h>
#include "util_ldap.h"
#include "util_ldap_cache.h"

#if APR_HAS_LDAP

#if APR_HAS_SHARED_MEMORY
#define MODLDAP_SHMEM_CACHE "/tmp/mod_ldap_cache"
#endif

/* ------------------------------------------------------------------ */

unsigned long util_ldap_url_node_hash(void *n)
{
    util_url_node_t *node = (util_url_node_t *)n;
    return util_ald_hash_string(1, node->url);
}

int util_ldap_url_node_compare(void *a, void *b)
{
    util_url_node_t *na = (util_url_node_t *)a;
    util_url_node_t *nb = (util_url_node_t *)b;

    return(strcmp(na->url, nb->url) == 0);
}

void *util_ldap_url_node_copy(util_ald_cache_t *cache, void *c)
{
    util_url_node_t *n = (util_url_node_t *)c;
    util_url_node_t *node = (util_url_node_t *)util_ald_alloc(cache, sizeof(util_url_node_t));

    if (node) {
        if (!(node->url = util_ald_strdup(cache, n->url))) {
            util_ald_free(cache, node->url);
            return NULL;
        }
        node->search_cache = n->search_cache;
        node->compare_cache = n->compare_cache;
        node->dn_compare_cache = n->dn_compare_cache;
        return node;
    }
    else {
        return NULL;
    }
}

void util_ldap_url_node_free(util_ald_cache_t *cache, void *n)
{
    util_url_node_t *node = (util_url_node_t *)n;

    util_ald_free(cache, node->url);
    util_ald_destroy_cache(node->search_cache);
    util_ald_destroy_cache(node->compare_cache);
    util_ald_destroy_cache(node->dn_compare_cache);
    util_ald_free(cache, node);
}

/* ------------------------------------------------------------------ */

/* Cache functions for search nodes */
unsigned long util_ldap_search_node_hash(void *n)
{
    util_search_node_t *node = (util_search_node_t *)n;
    return util_ald_hash_string(1, ((util_search_node_t *)(node))->username);
}

int util_ldap_search_node_compare(void *a, void *b)
{
    return(strcmp(((util_search_node_t *)a)->username,
		  ((util_search_node_t *)b)->username) == 0);
}

void *util_ldap_search_node_copy(util_ald_cache_t *cache, void *c)
{
    util_search_node_t *node = (util_search_node_t *)c;
    util_search_node_t *newnode = util_ald_alloc(cache, sizeof(util_search_node_t));

    /* safety check */
    if (newnode) {

        /* copy vals */
        if (node->vals) {
            int k = 0;
            int i = 0;
            while (node->vals[k++]);
            if (!(newnode->vals = util_ald_alloc(cache, sizeof(char *) * (k+1)))) {
                util_ldap_search_node_free(cache, newnode);
                return NULL;
            }
            while (node->vals[i]) {
                if (!(newnode->vals[i] = util_ald_strdup(cache, node->vals[i]))) {
                    util_ldap_search_node_free(cache, newnode);
                    return NULL;
                }
                i++;
            }
        }
        else {
            newnode->vals = NULL;
        }
        if (!(newnode->username = util_ald_strdup(cache, node->username)) ||
            !(newnode->dn = util_ald_strdup(cache, node->dn)) ) {
            util_ldap_search_node_free(cache, newnode);
            return NULL;
        }
        if(node->bindpw) {
            if(!(newnode->bindpw = util_ald_strdup(cache, node->bindpw))) {
                util_ldap_search_node_free(cache, newnode);
                return NULL;
            }
        } else {
            newnode->bindpw = NULL;
        }
        newnode->lastbind = node->lastbind;

    }
    return (void *)newnode;
}

void util_ldap_search_node_free(util_ald_cache_t *cache, void *n)
{
    int i = 0;
    util_search_node_t *node = (util_search_node_t *)n;
    if (node->vals) {
        while (node->vals[i]) {
            util_ald_free(cache, node->vals[i++]);
        }
        util_ald_free(cache, node->vals);
    }
    util_ald_free(cache, node->username);
    util_ald_free(cache, node->dn);
    util_ald_free(cache, node->bindpw);
    util_ald_free(cache, node);
}

/* ------------------------------------------------------------------ */

unsigned long util_ldap_compare_node_hash(void *n)
{
    util_compare_node_t *node = (util_compare_node_t *)n;
    return util_ald_hash_string(3, node->dn, node->attrib, node->value);
}

int util_ldap_compare_node_compare(void *a, void *b)
{
    util_compare_node_t *na = (util_compare_node_t *)a;
    util_compare_node_t *nb = (util_compare_node_t *)b;
    return (strcmp(na->dn, nb->dn) == 0 &&
	    strcmp(na->attrib, nb->attrib) == 0 &&
	    strcmp(na->value, nb->value) == 0);
}

void *util_ldap_compare_node_copy(util_ald_cache_t *cache, void *c)
{
    util_compare_node_t *n = (util_compare_node_t *)c;
    util_compare_node_t *node = (util_compare_node_t *)util_ald_alloc(cache, sizeof(util_compare_node_t));

    if (node) {
        if (!(node->dn = util_ald_strdup(cache, n->dn)) ||
            !(node->attrib = util_ald_strdup(cache, n->attrib)) ||
            !(node->value = util_ald_strdup(cache, n->value))) {
            util_ldap_compare_node_free(cache, node);
            return NULL;
        }
        node->lastcompare = n->lastcompare;
        node->result = n->result;
        return node;
    }
    else {
        return NULL;
    }
}

void util_ldap_compare_node_free(util_ald_cache_t *cache, void *n)
{
    util_compare_node_t *node = (util_compare_node_t *)n;
    util_ald_free(cache, node->dn);
    util_ald_free(cache, node->attrib);
    util_ald_free(cache, node->value);
    util_ald_free(cache, node);
}

/* ------------------------------------------------------------------ */

unsigned long util_ldap_dn_compare_node_hash(void *n)
{
    return util_ald_hash_string(1, ((util_dn_compare_node_t *)n)->reqdn);
}

int util_ldap_dn_compare_node_compare(void *a, void *b)
{
    return (strcmp(((util_dn_compare_node_t *)a)->reqdn,
		   ((util_dn_compare_node_t *)b)->reqdn) == 0);
}

void *util_ldap_dn_compare_node_copy(util_ald_cache_t *cache, void *c)
{
    util_dn_compare_node_t *n = (util_dn_compare_node_t *)c;
    util_dn_compare_node_t *node = (util_dn_compare_node_t *)util_ald_alloc(cache, sizeof(util_dn_compare_node_t));
    if (node) {
        if (!(node->reqdn = util_ald_strdup(cache, n->reqdn)) ||
            !(node->dn = util_ald_strdup(cache, n->dn))) {
            util_ldap_dn_compare_node_free(cache, node);
            return NULL;
        }
        return node;
    }
    else {
        return NULL;
    }
}

void util_ldap_dn_compare_node_free(util_ald_cache_t *cache, void *n)
{
    util_dn_compare_node_t *node = (util_dn_compare_node_t *)n;
    util_ald_free(cache, node->reqdn);
    util_ald_free(cache, node->dn);
    util_ald_free(cache, node);
}


/* ------------------------------------------------------------------ */
apr_status_t util_ldap_cache_child_kill(void *data);
apr_status_t util_ldap_cache_module_kill(void *data);

apr_status_t util_ldap_cache_module_kill(void *data)
{
    util_ldap_state_t *st = (util_ldap_state_t *)data;

#if APR_HAS_SHARED_MEMORY
    if (st->cache_shm != NULL) {
        apr_status_t result = apr_shm_destroy(st->cache_shm);
        st->cache_shm = NULL;
        apr_file_remove(st->cache_file, st->pool);
        return result;
    }
#endif
    util_ald_destroy_cache(st->util_ldap_cache);
    return APR_SUCCESS;
}

apr_status_t util_ldap_cache_init(apr_pool_t *pool, util_ldap_state_t *st)
{
#if APR_HAS_SHARED_MEMORY
    apr_status_t result;

    if (!st->cache_file) {
    	return -1;
    }

    result = apr_shm_create(&st->cache_shm, st->cache_bytes, st->cache_file, st->pool);
    if (result == EEXIST) {
        /*
         * The cache could have already been created (i.e. we may be a child process).  See
         * if we can attach to the existing shared memory
         */
        result = apr_shm_attach(&st->cache_shm, st->cache_file, st->pool);
    } 
    if (result != APR_SUCCESS) {
        return result;
    }

    /* This will create a rmm "handler" to get into the shared memory area */
    apr_rmm_init(&st->cache_rmm, NULL, (void *)apr_shm_baseaddr_get(st->cache_shm), st->cache_bytes, st->pool);
#endif

    apr_pool_cleanup_register(st->pool, st , util_ldap_cache_module_kill, apr_pool_cleanup_null);

    st->util_ldap_cache =
        util_ald_create_cache(st,
                              util_ldap_url_node_hash,
                              util_ldap_url_node_compare,
                              util_ldap_url_node_copy,
                              util_ldap_url_node_free);
    return APR_SUCCESS;
}


#endif /* APR_HAS_LDAP */
