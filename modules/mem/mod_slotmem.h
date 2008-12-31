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

#ifndef SLOTMEM_H
#define SLOTMEM_H

/* Memory handler for a shared memory divided in slot.
 */
/**
 * @file  slotmem.h
 * @brief Memory Slot Extension Storage Module for Apache
 *
 * @defgroup MEM mem
 * @ingroup  APACHE_MODS
 * @{
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "ap_provider.h"

#include "apr.h"
#include "apr_strings.h"
#include "apr_pools.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"
#include "apr_file_io.h"

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#if APR_HAVE_UNISTD_H
#include <unistd.h>         /* for getpid() */
#endif

#define SLOTMEM_STORAGE "slotmem"

typedef struct ap_slotmem_t ap_slotmem_t;

struct ap_slotmem_t {
    char                 *name;       /* per segment name */
    void                 *shm;        /* ptr to memory segment (apr_shm_t *) */
    void                 *base;       /* data set start */
    apr_size_t           size;        /* size of each memory slot */
    int                  num;         /* number of mem slots */
    apr_pool_t           *gpool;      /* per segment global pool */
    apr_global_mutex_t   *smutex;     /* mutex */
    void                 *context;    /* general purpose storage */
    struct ap_slotmem_t  *next;       /* location of next allocated segment */
};


/**
 * callback function used for slotmem.
 * @param mem is the memory associated with a worker.
 * @param data is what is passed to slotmem.
 * @param pool is pool used to create scoreboard
 * @return APR_SUCCESS if all went well
 */
typedef apr_status_t ap_slotmem_callback_fn_t(void* mem, void *data, apr_pool_t *pool);

struct ap_slotmem_storage_method {
/**
 * call the callback on all worker slots
 * @param s ap_slotmem_t to use.
 * @param funct callback function to call for each element.
 * @param data parameter for the callback function.
 * @param pool is pool used to create scoreboard
 * @return APR_SUCCESS if all went well
 */
apr_status_t (* slotmem_do)(ap_slotmem_t *s, ap_slotmem_callback_fn_t *func, void *data, apr_pool_t *pool);

/**
 * create a new slotmem with each item size is item_size.
 * This would create shared memory, basically.
 * @param pointer to store the address of the scoreboard.
 * @param name is a key used for debugging and in mod_status output or allow another process to share this space.
 * @param item_size size of each item
 * @param item_num number of item to create.
 * @param pool is pool used to create scoreboard
 * @return APR_SUCCESS if all went well
 */
apr_status_t (* slotmem_create)(ap_slotmem_t **new, const char *name, apr_size_t item_size, int item_num, apr_pool_t *pool);

/**
 * attach to an existing slotmem.
 * This would attach to  shared memory, basically.
 * @param pointer to store the address of the scoreboard.
 * @param name is a key used for debugging and in mod_status output or allow another process to share this space.
 * @param item_size size of each item
 * @param item_num max number of item.
 * @param pool is pool to memory allocate.
 * @return APR_SUCCESS if all went well
 */
apr_status_t (* slotmem_attach)(ap_slotmem_t **new, const char *name, apr_size_t *item_size, int *item_num, apr_pool_t *pool);
/**
 * get the memory associated with this worker slot.
 * @param s ap_slotmem_t to use.
 * @param item_id item to return for 0 to item_num
 * @param mem address to store the pointer to the slot
 * @return APR_SUCCESS if all went well
 */
apr_status_t (* slotmem_mem)(ap_slotmem_t *s, int item_id, void**mem);
/**
 * lock the memory segment
 * NOTE: All slots share the same mutex
 * @param s ap_slotmem_t to use
 * @return APR_SUCCESS if all went well
 */
apr_status_t (* slotmem_lock)(ap_slotmem_t *s);
/**
 * unlock the memory segment
 * NOTE: All slots share the same mutex
 * @param s ap_slotmem_t to use.
 * @return APR_SUCCESS if all went well
 */
apr_status_t (* slotmem_unlock)(ap_slotmem_t *s);
};

typedef struct ap_slotmem_storage_method ap_slotmem_storage_method;

/*
 * mod_slotmem externals exposed to the outside world.
 *  Thus the provider nature of mod_slotmem is somewhat insulated
 *  from the end user but can still be used directed if need
 *  be. The rationale is to make it easier for additional
 *  memory providers to be provided and having a single
 *  simple interface for all
 */
/**
 * obtain the array of provider methods desired
 * @param pool is the pool to use
 * @return pointer to array of provider names available
 */
AP_DECLARE(apr_array_header_t *) ap_slotmem_methods(apr_pool_t *pool);
/**
 * obtain the provider method desired
 * @param provider is name of the provider to use
 * @return pointer to provider or NULL
 */
AP_DECLARE(ap_slotmem_storage_method *) ap_slotmem_method(const char *provider);
/**
 * call the callback on all worker slots
 * @param sm ap_slotmem_storage_method provider obtained
 * @param s ap_slotmem_t to use.
 * @param funct callback function to call for each element.
 * @param data parameter for the callback function.
 * @param pool is pool used to create scoreboard
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_slotmem_do(ap_slotmem_storage_method *sm, ap_slotmem_t *s, ap_slotmem_callback_fn_t *func, void *data, apr_pool_t *pool);

/**
 * create a new slotmem with each item size is item_size.
 * This would create shared memory, basically.
 * @param pointer to store the address of the scoreboard.
 * @param name is a key used for debugging and in mod_status output or allow another process to share this space.
 * @param item_size size of each item
 * @param item_num number of item to create.
 * @param pool is pool used to create scoreboard
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_slotmem_create(ap_slotmem_storage_method *sm, ap_slotmem_t **new, const char *name, apr_size_t item_size, int item_num, apr_pool_t *pool);

/**
 * attach to an existing slotmem.
 * This would attach to  shared memory, basically.
 * @param pointer to store the address of the scoreboard.
 * @param name is a key used for debugging and in mod_status output or allow another process to share this space.
 * @param item_size size of each item
 * @param item_num max number of item.
 * @param pool is pool to memory allocate.
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_slotmem_attach(ap_slotmem_storage_method *sm, ap_slotmem_t **new, const char *name, apr_size_t *item_size, int *item_num, apr_pool_t *pool);
/**
 * get the memory associated with this worker slot.
 * @param s ap_slotmem_t to use.
 * @param item_id item to return for 0 to item_num
 * @param mem address to store the pointer to the slot
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_slotmem_mem(ap_slotmem_storage_method *sm, ap_slotmem_t *s, int item_id, void**mem);
/**
 * lock the memory segment
 * NOTE: All slots share the same mutex
 * @param s ap_slotmem_t to use
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_slotmem_lock(ap_slotmem_storage_method *sm, ap_slotmem_t *s);
/**
 * unlock the memory segment
 * NOTE: All slots share the same mutex
 * @param s ap_slotmem_t to use.
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_slotmem_unlock(ap_slotmem_storage_method *sm, ap_slotmem_t *s);

#endif /*SLOTMEM_H*/
