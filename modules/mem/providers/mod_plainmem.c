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

/* Memory handler for a plain memory divided in slot.
 * This one uses plain memory.
 */

#include  "mod_slotmem.h"

/* global pool and list of slotmem we are handling */
static struct ap_slotmem *globallistmem = NULL;
static apr_pool_t *gpool = NULL;

static apr_status_t slotmem_do(ap_slotmem_t *mem, ap_slotmem_callback_fn_t *func, void *data, apr_pool_t *pool)
{
    int i;
    void *ptr;

    if (!mem)
        return APR_ENOSHMAVAIL;

    ptr = mem->base;
    for (i = 0; i < mem->num; i++) {
        ptr = ptr + mem->size;
        func((void *) ptr, data, pool);
    }
    return APR_SUCCESS;
}

static apr_status_t slotmem_create(ap_slotmem_t **new, const char *name, apr_size_t item_size, int item_num, apr_pool_t *pool)
{
    ap_slotmem_t *res;
    ap_slotmem_t *next = globallistmem;
    const char *fname;

    if (name) {
        if (name[0] == ':')
            fname = name;
        else
            fname = ap_server_root_relative(pool, name);

        /* first try to attach to existing slotmem */
        if (next) {
            for (;;) {
                if (strcmp(next->name, fname) == 0) {
                    /* we already have it */
                    *new = next;
                    return APR_SUCCESS;
                }
                if (!next->next)
                    break;
                next = next->next;
            }
        }
    }
    else
        fname = "anonymous";

    /* create the memory using the gpool */
    res = (ap_slotmem_t *) apr_pcalloc(gpool, sizeof(ap_slotmem_t));
    res->base = apr_pcalloc(gpool, item_size * item_num);
    if (!res->base)
        return APR_ENOSHMAVAIL;

    /* For the chained slotmem stuff */
    res->name = apr_pstrdup(gpool, fname);
    res->size = item_size;
    res->num = item_num;
    res->next = NULL;
    if (globallistmem == NULL)
        globallistmem = res;
    else
        next->next = res;

    *new = res;
    return APR_SUCCESS;
}

static apr_status_t slotmem_attach(ap_slotmem_t **new, const char *name, apr_size_t *item_size, int *item_num, apr_pool_t *pool)
{
    ap_slotmem_t *next = globallistmem;
    const char *fname;

    if (name) {
        if (name[0] == ':')
            fname = name;
        else
            fname = ap_server_root_relative(pool, name);
    }
    else
        return APR_ENOSHMAVAIL;

    /* first try to attach to existing slotmem */
    if (next) {
        for (;;) {
            if (strcmp(next->name, fname) == 0) {
                /* we already have it */
                *new = next;
                *item_size = next->size;
                *item_num = next->num;
                return APR_SUCCESS;
            }
            if (!next->next)
                break;
            next = next->next;
        }
    }

    return APR_ENOSHMAVAIL;
}

static apr_status_t slotmem_mem(ap_slotmem_t *score, int id, void **mem)
{

    void *ptr;

    if (!score)
        return APR_ENOSHMAVAIL;
    if (id < 0 || id > score->num)
        return APR_ENOSHMAVAIL;

    ptr = score->base + score->size * id;
    if (!ptr)
        return APR_ENOSHMAVAIL;
    *mem = ptr;
    return APR_SUCCESS;
}

static const ap_slotmem_storage_method storage = {
    &slotmem_do,
    &slotmem_create,
    &slotmem_attach,
    &slotmem_mem
};

static int pre_config(apr_pool_t *p, apr_pool_t *plog,
                      apr_pool_t *ptemp)
{
    gpool = p;
    return OK;
}

static void ap_plainmem_register_hook(apr_pool_t *p)
{
    /* XXX: static const char * const prePos[] = { "mod_slotmem.c", NULL }; */
    ap_register_provider(p, SLOTMEM_STORAGE, "plain", "0", &storage);
    ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA plainmem_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                        /* create per-directory config structure */
    NULL,                        /* merge per-directory config structures */
    NULL,                        /* create per-server config structure */
    NULL,                        /* merge per-server config structures */
    NULL,                        /* command apr_table_t */
    ap_plainmem_register_hook    /* register hooks */
};

