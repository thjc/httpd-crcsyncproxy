/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */

#include "httpd.h"
#include "util_filter.h"

/* ### make this visible for direct manipulation?
 * ### use a hash table
 */
static ap_filter_rec_t *registered_output_filters = NULL;
static ap_filter_rec_t *registered_input_filters = NULL;

/* NOTE: Apache's current design doesn't allow a pool to be passed thu,
   so we depend on a global to hold the correct pool
*/
#define FILTER_POOL     ap_global_hook_pool
#include "ap_hooks.h"   /* for ap_global_hook_pool */

/*
** This macro returns true/false if a given filter should be inserted BEFORE
** another filter. This will happen when one of: 1) there isn't another
** filter; 2) that filter has a higher filter type (class); 3) that filter
** corresponds to a different request.
*/
#define INSERT_BEFORE(f, before_this) ((before_this) == NULL \
                           || (before_this)->frec->ftype > (f)->frec->ftype \
                           || (before_this)->r != (f)->r)


static apr_status_t filter_cleanup(void *ctx)
{
    registered_output_filters = NULL;
    registered_input_filters = NULL;
    return APR_SUCCESS;
}

static void register_filter(const char *name,
                            ap_filter_func filter_func,
                            ap_filter_type ftype,
                            ap_filter_rec_t **reg_filter_list)
{
    ap_filter_rec_t *frec = apr_palloc(FILTER_POOL, sizeof(*frec));

    frec->name = name;
    frec->filter_func = filter_func;
    frec->ftype = ftype;

    frec->next = *reg_filter_list;
    *reg_filter_list = frec;

    apr_register_cleanup(FILTER_POOL, NULL, filter_cleanup, apr_null_cleanup);
}

API_EXPORT(void) ap_register_input_filter(const char *name,
                                          ap_filter_func filter_func,
                                          ap_filter_type ftype)
{
    register_filter(name, filter_func, ftype, 
                    &registered_input_filters);
}                                                                    

API_EXPORT(void) ap_register_output_filter(const char *name,
                                           ap_filter_func filter_func,
                                           ap_filter_type ftype)
{
    register_filter(name, filter_func, ftype, 
                    &registered_output_filters);
}

API_EXPORT(void) ap_add_input_filter(const char *name, void *ctx, conn_rec *c)
{
    ap_filter_rec_t *frec = registered_input_filters;

    for (; frec != NULL; frec = frec->next) {
        if (!strcasecmp(name, frec->name)) {
            ap_filter_t *f = apr_pcalloc(c->pool, sizeof(*f));

            f->frec = frec;
            f->ctx = ctx;
            f->r = NULL;
            f->c = c;

            if (INSERT_BEFORE(f, c->input_filters)) {
                f->next = c->input_filters;
                c->input_filters = f;
            }
            else {
                ap_filter_t *fscan = c->input_filters;
                while (!INSERT_BEFORE(f, fscan->next))
                    fscan = fscan->next;
                f->next = fscan->next;
                fscan->next = f;
            }

            break;
        }
    }
}

API_EXPORT(void) ap_add_output_filter(const char *name, void *ctx, 
                                      request_rec *r, conn_rec *c)
{
    ap_filter_rec_t *frec = registered_output_filters;

    for (; frec != NULL; frec = frec->next) {
        if (!strcasecmp(name, frec->name)) {
            apr_pool_t *p = r ? r->pool : c->pool;
            ap_filter_t *f = apr_pcalloc(p, sizeof(*f));
            ap_filter_t **outf = r ? &r->output_filters : &c->output_filters;

            f->frec = frec;
            f->ctx = ctx;
            f->r = r;
            f->c = c;

            if (INSERT_BEFORE(f, *outf)) {
                f->next = *outf;
                *outf = f;
            }
            else {
                ap_filter_t *fscan = *outf;
                while (!INSERT_BEFORE(f, fscan->next))
                    fscan = fscan->next;
                f->next = fscan->next;
                fscan->next = f;
            }

            break;
        }
    }
}

/* 
 * Read data from the next filter in the filter stack.  Data should be 
 * modified in the bucket brigade that is passed in.  The core allocates the
 * bucket brigade, modules that wish to replace large chunks of data or to
 * save data off to the side should probably create their own temporary
 * brigade especially for that use.
 */
API_EXPORT(apr_status_t) ap_get_brigade(ap_filter_t *next, ap_bucket_brigade *bb)
{
    if (next) {
        return next->frec->filter_func(next, bb);
    }
    return AP_NOBODY_READ;
}

/* Pass the buckets to the next filter in the filter stack.  If the
 * current filter is a handler, we should get NULL passed in instead of
 * the current filter.  At that point, we can just call the first filter in
 * the stack, or r->output_filters.
 */
API_EXPORT(apr_status_t) ap_pass_brigade(ap_filter_t *next, ap_bucket_brigade *bb)
{
    if (next) {
        if (AP_BRIGADE_LAST(bb)->type == AP_BUCKET_EOS && next->r) {
            next->r->eos_sent = 1;
        }
        return next->frec->filter_func(next, bb);
    }
    return AP_NOBODY_WROTE;
}

API_EXPORT(void) ap_save_brigade(ap_filter_t *f, ap_bucket_brigade **saveto,
                                        ap_bucket_brigade **b)
{
    ap_bucket *e;
    apr_pool_t *p = f->r ? f->r->pool : f->c->pool;

    /* If have never stored any data in the filter, then we had better
     * create an empty bucket brigade so that we can concat.
     */
    if (!(*saveto)) {
        *saveto = ap_brigade_create(p);
    }
    
    AP_RING_FOREACH(e, &(*b)->list, ap_bucket, link) {
        if (e->setaside)
            e->setaside(e);
    }
    AP_BRIGADE_CONCAT(*saveto, *b);
}
