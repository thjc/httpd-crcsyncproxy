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
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/*
 * mod_ext_filter allows Unix-style filters to filter http content.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#define CORE_PRIVATE
#include "http_core.h"
#include "ap_buckets.h"
#include "util_filter.h"
#include "apr_strings.h"
#include "apr_hash.h"

typedef struct ef_server_t {
    apr_pool_t *p;
    apr_hash_t *h;
} ef_server_t;

typedef struct ef_filter_t {
    const char *name;
    enum {INPUT_FILTER=1, OUTPUT_FILTER} mode;
    const char *command;
    int numArgs;
    char *args[30];
    const char *intype;             /* list of IMTs we process (well, just one for now) */
#define INTYPE_ALL (char *)1
    const char *outtype;            /* IMT of filtered output */
#define OUTTYPE_UNCHANGED (char *)1
    int preserves_content_length;
} ef_filter_t;

typedef struct ef_dir_t {
    int debug;
    int log_stderr;
} ef_dir_t;

typedef struct ef_ctx_t {
    apr_pool_t *p;
    apr_proc_t *proc;
    apr_procattr_t *procattr;
    ef_dir_t *dc;
    ef_filter_t *filter;
    int noop;
#if APR_FILES_AS_SOCKETS
    apr_pollfd_t *pollset;
#endif
} ef_ctx_t;

module ext_filter_module;

static apr_status_t ef_output_filter(ap_filter_t *, ap_bucket_brigade *);

#define DBGLVL_SHOWOPTIONS         1
#define DBGLVL_GORY                9

static void *create_ef_dir_conf(apr_pool_t *p, char *dummy)
{
    ef_dir_t *dc = (ef_dir_t *)apr_pcalloc(p, sizeof(ef_dir_t));

    dc->debug = -1;
    dc->log_stderr = -1;

    return dc;
}

static void *create_ef_server_conf(apr_pool_t *p, server_rec *s)
{
    ef_server_t *conf;

    conf = (ef_server_t *)apr_pcalloc(p, sizeof(ef_server_t));
    conf->p = p;
    conf->h = apr_make_hash(conf->p);
    return conf;
}

static void *merge_ef_dir_conf(apr_pool_t *p, void *basev, void *overridesv)
{
    ef_dir_t *a = (ef_dir_t *)apr_pcalloc (p, sizeof(ef_dir_t));
    ef_dir_t *base = (ef_dir_t *)basev, *over = (ef_dir_t *)overridesv;

    if (over->debug != -1) {        /* if admin coded something... */
        a->debug = over->debug;
    }
    else {
        a->debug = base->debug;
    }

    if (over->log_stderr != -1) {   /* if admin coded something... */
        a->log_stderr = over->log_stderr;
    }
    else {
        a->log_stderr = base->log_stderr;
    }

    return a;
}

static const char *add_options(cmd_parms *cmd, void *in_dc,
                               const char *arg)
{
    ef_dir_t *dc = in_dc;

    if (!strncasecmp(arg, "DebugLevel=", 11)) {
        dc->debug = atoi(arg + 11);
    }
    else if (!strcasecmp(arg, "LogStderr")) {
        dc->log_stderr = 1;
    }
    else if (!strcasecmp(arg, "NoLogStderr")) {
        dc->log_stderr = 0;
    }
    else {
        return apr_pstrcat(cmd->temp_pool, 
                           "Invalid ExtFilterOptions option: ",
                           arg,
                           NULL);
    }

    return NULL;
}

static const char *parse_cmd(apr_pool_t *p, const char **args, ef_filter_t *filter)
{
    if (**args == '"') {
        const char *start = *args + 1;
        char *parms;

        ++*args; /* move past leading " */
        while (**args && **args != '"') {
            ++*args;
        }
        if (**args != '"') {
            return "Expected cmd= delimiter";
        }
        parms = apr_pstrndup(p, start, *args - start);
        ++*args; /* move past trailing " */

        /* parms now has the command-line to parse */
        while (filter->numArgs < 30 &&
               strlen(filter->args[filter->numArgs] = ap_getword_white_nc(p, &parms))) {
            ++filter->numArgs;
        }
        if (filter->numArgs < 1) {
            return "cmd= parse error";
        }
        filter->args[filter->numArgs] = NULL; /* we stored "" in the while() loop */
        filter->command = filter->args[0];
    }
    else
    {
        /* simple path */
        filter->args[0] = ap_getword_white(p, args);
        if (!filter->args[0]) {
            return "Invalid cmd= parameter";
        }
        filter->numArgs = 1;
        filter->command = filter->args[0];
    }
    return NULL;
}

static const char *define_filter(cmd_parms *cmd, void *dummy, const char *args)
{
    ef_server_t *conf = ap_get_module_config(cmd->server->module_config,
                                             &ext_filter_module);
    const char *token;
    const char *name;
    ef_filter_t *filter;

    name = ap_getword_white(cmd->pool, &args);
    if (!name) {
        return "Filter name not found";
    }

    if (apr_hash_get(conf->h, name, APR_HASH_KEY_STRING)) {
        return apr_psprintf(cmd->pool, "ExtFilter %s is already defined",
                            name);
    }

    filter = (ef_filter_t *)apr_pcalloc(conf->p, sizeof(ef_filter_t));
    filter->name = name;
    filter->mode = OUTPUT_FILTER;
    apr_hash_set(conf->h, name, APR_HASH_KEY_STRING, filter);

    while (*args) {
        while (apr_isspace(*args)) {
            ++args;
        }

        /* Nasty parsing...  I wish I could simply use ap_getword_white()
         * here and then look at the token, but ap_getword_white() doesn't
         * do the right thing when we have cmd="word word word"
         */
        if (!strncasecmp(args, "preservescontentlength", 22)) {
            token = ap_getword_white(cmd->pool, &args);
            if (!strcasecmp(token, "preservescontentlength")) {
                filter->preserves_content_length = 1;
            }
            else {
                return apr_psprintf(cmd->pool, 
                                    "mangled argument `%s'",
                                    token);
            }
            continue;
        }

        if (!strncasecmp(args, "mode=", 5)) {
            args += 5;
            token = ap_getword_white(cmd->pool, &args);
            if (!strcasecmp(token, "output")) {
                filter->mode = OUTPUT_FILTER;
            }
            else if (!strcasecmp(token, "input")) {
                filter->mode = INPUT_FILTER;
            }
            else {
                return apr_psprintf(cmd->pool, "Invalid mode: `%s'",
                                    token);
            }
            continue;
        }

        if (!strncasecmp(args, "intype=", 7)) {
            args += 7;
            filter->intype = ap_getword_white(cmd->pool, &args);
            continue;
        }

        if (!strncasecmp(args, "outtype=", 8)) {
            args += 8;
            filter->outtype = ap_getword_white(cmd->pool, &args);
            continue;
        }

        if (!strncasecmp(args, "cmd=", 4)) {
            args += 4;
            if ((token = parse_cmd(cmd->pool, &args, filter))) {
                return token;
            }
            continue;
        }

        return apr_psprintf(cmd->pool, "Unexpected parameter: `%s'",
                            args);
    }

    /* parsing is done...  register the filter 
     */
    if (filter->mode == OUTPUT_FILTER) {
        /* XXX need a way to ensure uniqueness among all filters */
        ap_register_output_filter(filter->name, ef_output_filter, AP_FTYPE_CONTENT);
    }
#if 0              /* no input filters yet */
    else if (filter->mode == INPUT_FILTER) {
        /* XXX need a way to ensure uniqueness among all filters */
        ap_register_input_filter(filter->name, ef_input_filter, AP_FTYPE_CONTENT);
    }
#endif
    else {
        ap_assert(1 != 1); /* we set the field wrong somehow */
    }

    return NULL;
}

static const command_rec cmds[] =
{
    AP_INIT_ITERATE("ExtFilterOptions",
                    add_options,
                    NULL,
                    ACCESS_CONF, /* same as AddInputFilter/AddOutputFilter */
                    "valid options: DebugLevel=n, LogStderr, NoLogStderr"),
    AP_INIT_RAW_ARGS("ExtFilterDefine",
                     define_filter,
                     NULL,
                     RSRC_CONF,
                     "Define an external filter"),
    {NULL}
};

static apr_status_t set_resource_limits(request_rec *r, 
                                        apr_procattr_t *procattr)
{
#if defined(RLIMIT_CPU)  || defined(RLIMIT_NPROC) || \
    defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined (RLIMIT_AS)
    core_dir_config *conf = 
        (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                &core_module);
    apr_status_t rv;

#ifdef RLIMIT_CPU
    rv = apr_setprocattr_limit(procattr, APR_LIMIT_CPU, conf->limit_cpu);
    ap_assert(rv == APR_SUCCESS); /* otherwise, we're out of sync with APR */
#endif
#if defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS)
    rv = apr_setprocattr_limit(procattr, APR_LIMIT_MEM, conf->limit_mem);
    ap_assert(rv == APR_SUCCESS); /* otherwise, we're out of sync with APR */
#endif
#ifdef RLIMIT_NPROC
    rv = apr_setprocattr_limit(procattr, APR_LIMIT_NPROC, conf->limit_nproc);
    ap_assert(rv == APR_SUCCESS); /* otherwise, we're out of sync with APR */
#endif

#endif /* if at least one limit defined */

    return APR_SUCCESS;
}

static apr_status_t ef_close_file(void *vfile)
{
    apr_file_t *f = vfile;

    return apr_close(vfile);
}

/* init_ext_filter_process: get the external filter process going
 * This is per-filter-instance (i.e., per-request) initialization.
 */
static apr_status_t init_ext_filter_process(ap_filter_t *f)
{
    ef_ctx_t *ctx = f->ctx;
    apr_status_t rc;
    ef_dir_t *dc = ctx->dc;

    ctx->proc = apr_pcalloc(ctx->p, sizeof(*ctx->proc));

    rc = apr_createprocattr_init(&ctx->procattr, ctx->p);
    ap_assert(rc == APR_SUCCESS);

    rc = apr_setprocattr_io(ctx->procattr,
                            APR_CHILD_BLOCK,
                            APR_CHILD_BLOCK,
                            APR_CHILD_BLOCK);
    ap_assert(rc == APR_SUCCESS);

    rc = set_resource_limits(f->r, ctx->procattr);
    ap_assert(rc == APR_SUCCESS);

    if (dc->log_stderr > 0) {
        rc = apr_setprocattr_childerr(ctx->procattr,
                                      f->r->server->error_log, /* stderr in child */
                                      NULL);
        ap_assert(rc == APR_SUCCESS);
    }
                                  
    rc = apr_create_process(ctx->proc, 
                            ctx->filter->command, 
                            ctx->filter->args, 
                            NULL, /* environment */
                            ctx->procattr, 
                            ctx->p);
    if (rc != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, f->r,
                      "couldn't create child process to run `%s'",
                      ctx->filter->command);
        return rc;
    }

    apr_note_subprocess(ctx->p, ctx->proc, kill_after_timeout);

    /* We don't want the handle to the child's stdin inherited by any
     * other processes created by httpd.  Otherwise, when we close our
     * handle, the child won't see EOF because another handle will still
     * be open.
     */

    apr_register_cleanup(ctx->p, ctx->proc->in, NULL, ef_close_file);

#if APR_FILES_AS_SOCKETS
    {
        apr_socket_t *newsock;

        rc = apr_setup_poll(&ctx->pollset, 2, ctx->p);
        ap_assert(rc == APR_SUCCESS);
        rc = apr_socket_from_file(&newsock, ctx->proc->in);
        ap_assert(rc == APR_SUCCESS);
        rc = apr_add_poll_socket(ctx->pollset, newsock, APR_POLLOUT);
        ap_assert(rc == APR_SUCCESS);
        rc = apr_socket_from_file(&newsock, ctx->proc->out);
        ap_assert(rc == APR_SUCCESS);
        rc = apr_add_poll_socket(ctx->pollset, newsock, APR_POLLIN);
        ap_assert(rc == APR_SUCCESS);
    }
#endif

    return APR_SUCCESS;
}

static const char *get_cfg_string(ef_dir_t *dc, ef_filter_t *filter, apr_pool_t *p)
{
    const char *debug_str = dc->debug == -1 ? 
        "DebugLevel=0" : apr_psprintf(p, "DebugLevel=%d", dc->debug);
    const char *log_stderr_str = dc->log_stderr < 1 ?
        "NoLogStderr" : "LogStderr";
    const char *preserve_content_length_str = filter->preserves_content_length ?
        "PreservesContentLength" : "!PreserveContentLength";
    const char *intype_str = !filter->intype ?
        "*/*" : filter->intype;
    const char *outtype_str = !filter->outtype ?
        "(unchanged)" : filter->outtype;
    
    return apr_psprintf(p,
                        "ExtFilterOptions %s %s %s ExtFilterInType %s "
                        "ExtFilterOuttype %s",
                        debug_str, log_stderr_str, preserve_content_length_str,
                        intype_str, outtype_str);
}

static apr_status_t init_filter_instance(ap_filter_t *f)
{
    ef_ctx_t *ctx;
    ef_dir_t *dc;
    ef_server_t *sc;
    apr_status_t rv;

    f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(ef_ctx_t));
    dc = ap_get_module_config(f->r->per_dir_config,
                              &ext_filter_module);
    sc = ap_get_module_config(f->r->server->module_config,
                              &ext_filter_module);
    ctx->dc = dc;
    /* look for the user-defined filter */
    ctx->filter = apr_hash_get(sc->h, f->frec->name, APR_HASH_KEY_STRING);
    if (!ctx->filter) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, f->r,
                      "couldn't find definition of filter '%s'",
                      f->frec->name);
        return APR_EINVAL;
    }
    ctx->p = f->r->pool;
    if (ctx->filter->intype &&
        ctx->filter->intype != INTYPE_ALL &&
        strcasecmp(ctx->filter->intype, f->r->content_type)) {
        /* wrong IMT for us; don't mess with the output */
        ctx->noop = 1;
    }
    else {
        rv = init_ext_filter_process(f);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        if (ctx->filter->outtype &&
            ctx->filter->outtype != OUTTYPE_UNCHANGED) {
            f->r->content_type = ctx->filter->outtype;
        }
        if (ctx->filter->preserves_content_length != 1) {
            /* nasty, but needed to avoid confusing the browser 
             */
            apr_table_unset(f->r->headers_out, "Content-Length");
        }
    }

    if (dc->debug >= DBGLVL_SHOWOPTIONS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, f->r,
                      "%sfiltering `%s' through `%s', cfg %s",
                      ctx->noop ? "skipping: " : "",
                      f->r->uri ? f->r->uri : f->r->filename,
                      ctx->filter->command,
                      get_cfg_string(dc, ctx->filter, f->r->pool));
    }

    return APR_SUCCESS;
}

/* drain_available_output(): 
 *
 * if any data is available from the filter, read it and pass it
 * to the next filter
 */
static apr_status_t drain_available_output(ap_filter_t *f)
{
    ef_ctx_t *ctx = f->ctx;
    ef_dir_t *dc = ctx->dc;
    apr_size_t len;
    char buf[4096];
    apr_status_t rv;
    ap_bucket_brigade *bb;
    ap_bucket *b;

    while (1) {
        len = sizeof(buf);
        rv = apr_read(ctx->proc->out,
                      buf,
                      &len);
        if ((rv && !APR_STATUS_IS_EAGAIN(rv)) ||
            dc->debug >= DBGLVL_GORY) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, f->r,
                          "apr_read(child output), len %d",
                          !rv ? len : -1);
        }
        if (rv != APR_SUCCESS) {
            return rv;
        }
        bb = ap_brigade_create(f->r->pool);
        b = ap_bucket_create_transient(buf, len);
        AP_BRIGADE_INSERT_TAIL(bb, b);
        if ((rv = ap_pass_brigade(f->next, bb)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                          "ap_pass_brigade()");
            return rv;
        }
    }
    /* we should never get here; if we do, a bogus error message would be
     * the least of our problems 
     */
    return APR_ANONYMOUS;
}

static apr_status_t pass_data_to_filter(ap_filter_t *f, const char *data, 
                                        apr_ssize_t len)
{
    ef_ctx_t *ctx = f->ctx;
    ef_dir_t *dc = ctx->dc;
    apr_status_t rv;
    apr_size_t bytes_written = 0;
    apr_size_t tmplen;
    
    do {
        tmplen = len - bytes_written;
        rv = apr_write(ctx->proc->in,
                       (const char *)data + bytes_written,
                       &tmplen);
        bytes_written += tmplen;
        if (rv != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(rv)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                          "apr_write(child input), len %d",
                          tmplen);
            return rv;
        }
        if (APR_STATUS_IS_EAGAIN(rv)) {
            /* XXX handle blocking conditions here...  if we block, we need 
             * to read data from the child process and pass it down to the
             * next filter!
             */
            rv = drain_available_output(f);
            if (APR_STATUS_IS_EAGAIN(rv)) {
#if APR_FILES_AS_SOCKETS
                int num_events;
                
                rv = apr_poll(ctx->pollset,
                              &num_events,
                              f->r->server->timeout * APR_USEC_PER_SEC);
                if (rv || dc->debug >= DBGLVL_GORY) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG,
                                  rv, f->r, "apr_poll()");
                }
                if (rv != APR_SUCCESS && rv != APR_EINTR) { 
                    /* some error such as APR_TIMEUP */
                    return rv;
                }
#else /* APR_FILES_AS_SOCKETS */
                /* Yuck... I'd really like to wait until I can read
                 * or write, but instead I have to sleep and try again 
                 */
                apr_sleep(100000); /* 100 milliseconds */
                if (dc->debug >= DBGLVL_GORY) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 
                                  0, f->r, "apr_sleep()");
                }
#endif /* APR_FILES_AS_SOCKETS */
            }
            else if (rv != APR_SUCCESS) {
                return rv;
            }
        }
    } while (bytes_written < len);
    return rv;
}

static apr_status_t ef_output_filter(ap_filter_t *f, ap_bucket_brigade *bb)
{
    ef_ctx_t *ctx = f->ctx;
    ap_bucket *b;
    ef_dir_t *dc;
    apr_size_t len;
    const char *data;
    apr_status_t rv;
    char buf[4096];
    ap_bucket *eos = NULL;

    if (!ctx) {
        if ((rv = init_filter_instance(f)) != APR_SUCCESS) {
            return rv;
        }
        ctx = f->ctx;
    }
    if (ctx->noop) {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }
    dc = ctx->dc;

    AP_BRIGADE_FOREACH(b, bb) {

        if (AP_BUCKET_IS_EOS(b)) {
            eos = b;
            break;
        }

        rv = ap_bucket_read(b, &data, &len, 1);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, "ap_bucket_read()");
            return rv;
        }

        if (len > 0 &&
            (rv = pass_data_to_filter(f, data, len)) != APR_SUCCESS) {
            return rv;
        }
    }

    ap_brigade_destroy(bb);

    /* XXX What we *really* need to do once we've hit eos is create a pipe bucket
     * from the child output pipe and pass down the pipe bucket + eos.
     */
    if (eos) {
        /* close the child's stdin to signal that no more data is coming;
         * that will cause the child to finish generating output
         */
        if ((rv = apr_close(ctx->proc->in)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                          "apr_close(child input)");
            return rv;
        }
        /* since we've seen eos and closed the child's stdin, set the proper pipe 
         * timeout; we don't care if we don't return from apr_read() for a while... 
         */
        rv = apr_set_pipe_timeout(ctx->proc->out, 
                                  f->r->server->timeout * APR_USEC_PER_SEC);
        if (rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                          "apr_set_pipe_timeout(child output)");
            return rv;
        }
    }

    do {
        len = sizeof(buf);
        rv = apr_read(ctx->proc->out,
                      buf,
                      &len);
        if ((rv && !APR_STATUS_IS_EOF(rv) && !APR_STATUS_IS_EAGAIN(rv)) ||
            dc->debug >= DBGLVL_GORY) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, f->r,
                          "apr_read(child output), len %d",
                          !rv ? len : -1);
        }
        if (APR_STATUS_IS_EAGAIN(rv)) {
            if (eos) {
                /* should not occur, because we have an APR timeout in place */
                AP_DEBUG_ASSERT(1 != 1);
            }
            return APR_SUCCESS;
        }
        
        if (rv == APR_SUCCESS) {
            bb = ap_brigade_create(f->r->pool);
            b = ap_bucket_create_transient(buf, len);
            AP_BRIGADE_INSERT_TAIL(bb, b);
            if ((rv = ap_pass_brigade(f->next, bb)) != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                              "ap_pass_brigade(filtered buffer) failed");
                return rv;
            }
        }
    } while (rv == APR_SUCCESS);

    if (!APR_STATUS_IS_EOF(rv)) {
        return rv;
    }

    if (eos) {
        /* pass down eos */
        bb = ap_brigade_create(f->r->pool);
        b = ap_bucket_create_eos();
        AP_BRIGADE_INSERT_TAIL(bb, b);
        if ((rv = ap_pass_brigade(f->next, bb)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                          "ap_pass_brigade(eos) failed");
            return rv;
        }
    }

    return APR_SUCCESS;
}

#if 0
static int ef_input_filter(ap_filter_t *f, ap_bucket_brigade *bb, 
                           ap_input_mode_t mode)
{
    apr_status_t rv;
    ap_bucket *b;
    char *buf;
    apr_ssize_t len;
    char *zero;

    rv = ap_get_brigade(f->next, bb, mode);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    AP_BRIGADE_FOREACH(b, bb) {
        if (!AP_BUCKET_IS_EOS(b)) {
            if ((rv = ap_bucket_read(b, (const char **)&buf, &len, 0)) != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r, "ap_bucket_read() failed");
                return rv;
            }
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "ap_bucket_read -> %d bytes",
                         len);
            while ((zero = memchr(buf, '0', len))) {
                *zero = 'a';
            }
        }
        else
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "got eos bucket");
    }

    return rv;
}
#endif

module ext_filter_module =
{
    STANDARD20_MODULE_STUFF,
    create_ef_dir_conf,
    merge_ef_dir_conf,
    create_ef_server_conf,
    NULL,
    cmds,
};
