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
 * http_config.c: once was auxillary functions for reading httpd's config
 * file and converting filenames into a namespace
 *
 * Rob McCool 
 * 
 * Wall-to-wall rewrite for Apache... commands which are part of the
 * server core can now be found next door in "http_core.c".  Now contains
 * general command loop, and functions which do bookkeeping for the new
 * Apache config stuff (modules and configuration vectors).
 *
 * rst
 *
 */

#define CORE_PRIVATE

#include "ap_config.h"
#include "apr_portable.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_log.h"		/* for errors in parse_htaccess */
#include "http_request.h"	/* for default_handler (see invoke_handler) */
#include "http_main.h"
#include "http_vhost.h"
#include "util_cfgtree.h"
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

AP_DECLARE_DATA const char *ap_server_argv0;

AP_DECLARE_DATA const char *ap_server_root;

AP_DECLARE_DATA apr_array_header_t *ap_server_pre_read_config;
AP_DECLARE_DATA apr_array_header_t *ap_server_post_read_config;
AP_DECLARE_DATA apr_array_header_t *ap_server_config_defines;

AP_HOOK_STRUCT(
	    AP_HOOK_LINK(header_parser)
	    AP_HOOK_LINK(pre_config)
	    AP_HOOK_LINK(post_config)
	    AP_HOOK_LINK(open_logs)
	    AP_HOOK_LINK(child_init)
)

AP_IMPLEMENT_HOOK_RUN_ALL(int,header_parser,
                          (request_rec *r),(r),OK,DECLINED)
AP_IMPLEMENT_HOOK_VOID(pre_config,
		       (apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp),
                       (pconf,plog,ptemp))
AP_IMPLEMENT_HOOK_VOID(post_config,
		       (apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp,
                        server_rec *s),(pconf,plog,ptemp,s))
AP_IMPLEMENT_HOOK_VOID(open_logs,
		       (apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, 
                        server_rec *s),(pconf,plog,ptemp,s))
AP_IMPLEMENT_HOOK_VOID(child_init,
                       (apr_pool_t *pchild, server_rec *s),(pchild,s))

/****************************************************************
 *
 * We begin with the functions which deal with the linked list
 * of modules which control just about all of the server operation.
 */

/* total_modules is the number of modules that have been linked
 * into the server.
 */
static int total_modules = 0;
/* dynamic_modules is the number of modules that have been added
 * after the pre-loaded ones have been set up. It shouldn't be larger
 * than DYNAMIC_MODULE_LIMIT.
 */
static int dynamic_modules = 0;
AP_DECLARE_DATA module *top_module = NULL;
AP_DECLARE_DATA module **ap_loaded_modules=NULL;

typedef int (*handler_func) (request_rec *);
typedef void *(*dir_maker_func) (apr_pool_t *, char *);
typedef void *(*merger_func) (apr_pool_t *, void *, void *);

/* Dealing with config vectors.  These are associated with per-directory,
 * per-server, and per-request configuration, and have a void* pointer for
 * each modules.  The nature of the structure pointed to is private to the
 * module in question... the core doesn't (and can't) know.  However, there
 * are defined interfaces which allow it to create instances of its private
 * per-directory and per-server structures, and to merge the per-directory
 * structures of a directory and its subdirectory (producing a new one in
 * which the defaults applying to the base directory have been properly
 * overridden).
 */

#ifndef ap_get_module_config
AP_DECLARE(void *) ap_get_module_config(void *conf_vector, module *m)
{
    void **confv = (void **) conf_vector;
    return confv[m->module_index];
}
#endif

#ifndef ap_set_module_config
AP_DECLARE(void) ap_set_module_config(void *conf_vector, module *m, void *val)
{
    void **confv = (void **) conf_vector;
    confv[m->module_index] = val;
}
#endif

static void *create_empty_config(apr_pool_t *p)
{
    void **conf_vector = (void **) apr_pcalloc(p, sizeof(void *) *
				    (total_modules + DYNAMIC_MODULE_LIMIT));
    return (void *) conf_vector;
}

static void *create_default_per_dir_config(apr_pool_t *p)
{
    void **conf_vector = (void **) apr_pcalloc(p, sizeof(void *) * (total_modules + DYNAMIC_MODULE_LIMIT));
    module *modp;

    for (modp = top_module; modp; modp = modp->next) {
	dir_maker_func df = modp->create_dir_config;

	if (df)
	    conf_vector[modp->module_index] = (*df) (p, NULL);
    }

    return (void *) conf_vector;
}

void *
     ap_merge_per_dir_configs(apr_pool_t *p, void *base, void *new)
{
    void **conf_vector = (void **) apr_palloc(p, sizeof(void *) * total_modules);
    void **base_vector = (void **) base;
    void **new_vector = (void **) new;
    module *modp;

    for (modp = top_module; modp; modp = modp->next) {
	merger_func df = modp->merge_dir_config;
	int i = modp->module_index;

	if (df && new_vector[i])
	    conf_vector[i] = (*df) (p, base_vector[i], new_vector[i]);
	else
	    conf_vector[i] = new_vector[i] ? new_vector[i] : base_vector[i];
    }

    return (void *) conf_vector;
}

static void *create_server_config(apr_pool_t *p, server_rec *s)
{
    void **conf_vector = (void **) apr_pcalloc(p, sizeof(void *) * (total_modules + DYNAMIC_MODULE_LIMIT));
    module *modp;

    for (modp = top_module; modp; modp = modp->next) {
	if (modp->create_server_config)
	    conf_vector[modp->module_index] = (*modp->create_server_config) (p, s);
    }

    return (void *) conf_vector;
}

static void merge_server_configs(apr_pool_t *p, void *base, void *virt)
{
    /* Can reuse the 'virt' vector for the spine of it, since we don't
     * have to deal with the moral equivalent of .htaccess files here...
     */

    void **base_vector = (void **) base;
    void **virt_vector = (void **) virt;
    module *modp;

    for (modp = top_module; modp; modp = modp->next) {
	merger_func df = modp->merge_server_config;
	int i = modp->module_index;

	if (!virt_vector[i])
	    virt_vector[i] = base_vector[i];
	else if (df)
	    virt_vector[i] = (*df) (p, base_vector[i], virt_vector[i]);
    }
}

void *ap_create_request_config(apr_pool_t *p)
{
    return create_empty_config(p);
}

void *ap_create_conn_config(apr_pool_t *p)
{
    return create_empty_config(p);
}

AP_CORE_DECLARE(void *) ap_create_per_dir_config(apr_pool_t *p)
{
    return create_empty_config(p);
}

/*
 * For speed/efficiency we generate a compact list of all the handlers
 * and wildcard handlers.  This means we won't have to scan the entire
 * module list looking for handlers... where we'll find a whole whack
 * of NULLs.
 */
typedef struct {
    handler_rec hr;
    size_t len;
} fast_handler_rec;

static fast_handler_rec *handlers;
static fast_handler_rec *wildhandlers;

static void init_handlers(apr_pool_t *p)
{
    module *modp;
    int nhandlers = 0;
    int nwildhandlers = 0;
    const handler_rec *handp;
    fast_handler_rec *ph, *pw;
    const char *starp;

    for (modp = top_module; modp; modp = modp->next) {
	if (!modp->handlers)
	    continue;
	for (handp = modp->handlers; handp->content_type; ++handp) {
	    if (ap_strchr_c(handp->content_type, '*')) {
                nwildhandlers ++;
            } else {
                nhandlers ++;
            }
        }
    }
    ph = handlers = apr_palloc(p, sizeof(*ph)*(nhandlers + 1));
    pw = wildhandlers = apr_palloc(p, sizeof(*pw)*(nwildhandlers + 1));
    for (modp = top_module; modp; modp = modp->next) {
	if (!modp->handlers)
	    continue;
	for (handp = modp->handlers; handp->content_type; ++handp) {
	    if ((starp = ap_strchr_c(handp->content_type, '*'))) {
                pw->hr.content_type = handp->content_type;
                pw->hr.handler = handp->handler;
		pw->len = starp - handp->content_type;
                pw ++;
            } else {
                ph->hr.content_type = handp->content_type;
                ph->hr.handler = handp->handler;
		ph->len = strlen(handp->content_type);
                ph ++;
            }
        }
    }
    pw->hr.content_type = NULL;
    pw->hr.handler = NULL;
    ph->hr.content_type = NULL;
    ph->hr.handler = NULL;
}

int ap_invoke_handler(request_rec *r)
{
    fast_handler_rec *handp;
    const char *handler;
    const char *p;
    size_t handler_len;
    int result = HTTP_INTERNAL_SERVER_ERROR;

    if (r->handler) {
        handler = r->handler;
        handler_len = strlen(handler);
    }
    else {
        handler = r->content_type ? r->content_type : ap_default_type(r);
        if ((p = ap_strchr_c(handler, ';')) != NULL) {
	    /* MIME type arguments */
            while (p > handler && p[-1] == ' ')
	        --p;		/* strip trailing spaces */
	    handler_len = p - handler;
	}
	else {
	    handler_len = strlen(handler);
	}
    }

    /* Pass one --- direct matches */

    for (handp = handlers; handp->hr.content_type; ++handp) {
        if (handler_len == handp->len
            && !strncmp(handler, handp->hr.content_type, handler_len)) {
            result = (*handp->hr.handler) (r);

            if (result != DECLINED)
                return result;
        }
    }

    /* Pass two --- wildcard matches */

    for (handp = wildhandlers; handp->hr.content_type; ++handp) {
        if (handler_len >= handp->len
            && !strncmp(handler, handp->hr.content_type, handp->len)) {
            result = (*handp->hr.handler) (r);

            if (result != DECLINED)
                return result;
         }
    }

    if (result == HTTP_INTERNAL_SERVER_ERROR && r->handler && r->filename) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
            "handler \"%s\" not found for: %s", r->handler, r->filename);
    }
    return HTTP_INTERNAL_SERVER_ERROR;
}

AP_DECLARE(int) ap_method_is_limited(cmd_parms *cmd, const char *method) {
    int methnum;
    int i;
    char **xmethod;

    methnum = ap_method_number_of(method);
    /*
     * The simple case: a method hard-coded into Apache.
     */
    if (methnum != M_INVALID) {
	return (methnum & cmd->limited);
    }
    /*
     * Some extension method we don't know implicitly.
     */
    if ((cmd->limited_xmethods == NULL)
	|| (cmd->limited_xmethods->nelts == 0)) {
	return 0;
    }
    xmethod = (char **) cmd->limited_xmethods->elts;
    for (i = 0; i < cmd->limited_xmethods->nelts; ++i) {
	if (strcmp(method, xmethod[i]) == 0) {
	    return 1;
	}
    }
    return 0;
}

AP_DECLARE(void) ap_register_hooks(module *m)
    {
    if(m->register_hooks)
	{
	if(getenv("SHOW_HOOKS"))
	    {
	    printf("Registering hooks for %s\n",m->name);
	    ap_debug_module_hooks=1;
	    }
	ap_debug_module_name=m->name;
	m->register_hooks();
	}
    }

/* One-time setup for precompiled modules --- NOT to be done on restart */

AP_DECLARE(void) ap_add_module(module *m)
{
    /* This could be called from an AddModule httpd.conf command,
     * after the file has been linked and the module structure within it
     * teased out...
     */

    if (m->version != MODULE_MAGIC_NUMBER_MAJOR) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                     "%s: module \"%s\" is not compatible with this "
		     "version of Apache.", ap_server_argv0, m->name);
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, "Please contact the vendor for the correct version.");
	exit(1);
    }

    if (m->next == NULL) {
	m->next = top_module;
	top_module = m;
    }
    if (m->module_index == -1) {
	m->module_index = total_modules++;
	dynamic_modules++;

	if (dynamic_modules > DYNAMIC_MODULE_LIMIT) {
	    ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                         "%s: module \"%s\" could not be loaded, because"
		         " the dynamic", ap_server_argv0, m->name);
	    ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                         "module limit was reached. Please increase "
		         "DYNAMIC_MODULE_LIMIT and recompile.");
	    exit(1);
	}
    }

    /* Some C compilers put a complete path into __FILE__, but we want
     * only the filename (e.g. mod_includes.c). So check for path
     * components (Unix and DOS), and remove them.
     */

    if (ap_strrchr_c(m->name, '/'))
	m->name = 1 + ap_strrchr_c(m->name, '/');
    if (ap_strrchr_c(m->name, '\\'))
	m->name = 1 + ap_strrchr_c(m->name, '\\');

#ifdef _OSD_POSIX /* __FILE__="*POSIX(/home/martin/apache/src/modules/standard/mod_info.c)" */
    /* We cannot fix the string in-place, because it's const */
    if (m->name[strlen(m->name)-1]==')') {
	char *tmp = strdup(m->name);	/* FIXME:memory leak, albeit a small one */
	tmp[strlen(tmp)-1] = '\0';
	m->name = tmp;
    }
#endif /*_OSD_POSIX*/

    /* FIXME: is this the right place to call this? */
    ap_register_hooks(m);
}

/* 
 * remove_module undoes what add_module did. There are some caveats:
 * when the module is removed, its slot is lost so all the current
 * per-dir and per-server configurations are invalid. So we should
 * only ever call this function when you are invalidating almost
 * all our current data. I.e. when doing a restart.
 */

AP_DECLARE(void) ap_remove_module(module *m)
{
    module *modp;

    modp = top_module;
    if (modp == m) {
	/* We are the top module, special case */
	top_module = modp->next;
	m->next = NULL;
    }
    else {
	/* Not the top module, find use. When found modp will
	 * point to the module _before_ us in the list
	 */

	while (modp && modp->next != m) {
	    modp = modp->next;
	}
	if (!modp) {
	    /* Uh-oh, this module doesn't exist */
	    ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, NULL,
		"Cannot remove module %s: not found in module list",
		m->name);
	    return;
	}
	/* Eliminate us from the module list */
	modp->next = modp->next->next;
    }

    m->module_index = -1;	/* simulate being unloaded, should
				 * be unnecessary */
    dynamic_modules--;
    total_modules--;
}

AP_DECLARE(void) ap_add_loaded_module(module *mod)
{
    module **m;

    /* 
     *  Add module pointer to top of chained module list 
     */
    ap_add_module(mod);

    /* 
     *  And module pointer to list of loaded modules 
     *
     *  Notes: 1. ap_add_module() would already complain if no more space
     *            exists for adding a dynamically loaded module
     *         2. ap_add_module() accepts double inclusion, so we have
     *            to accept this, too.
     */
    for (m = ap_loaded_modules; *m != NULL; m++)
        ;
    *m++ = mod;
    *m = NULL;
}

AP_DECLARE(void) ap_remove_loaded_module(module *mod)
{
    module **m;
    module **m2;
    int done;

    /* 
     *  Remove module pointer from chained module list 
     */
    ap_remove_module(mod);

    /* 
     *  Remove module pointer from list of loaded modules
     *
     *  Note: 1. We cannot determine if the module was successfully
     *           removed by ap_remove_module().
     *        2. We have not to complain explicity when the module
     *           is not found because ap_remove_module() did it
     *           for us already.
     */
    for (m = m2 = ap_loaded_modules, done = 0; *m2 != NULL; m2++) {
        if (*m2 == mod && done == 0)
            done = 1;
        else
            *m++ = *m2;
    }
    *m = NULL;
}

AP_DECLARE(void) ap_setup_prelinked_modules(process_rec *process)
{
    module **m;
    module **m2;

    ap_global_hook_pool=process->pconf;

    /*
     *  Initialise total_modules variable and module indices
     */
    total_modules = 0;
    for (m = ap_preloaded_modules; *m != NULL; m++)
        (*m)->module_index = total_modules++;

    /* 
     *  Initialise list of loaded modules
     */
    ap_loaded_modules = (module **)apr_palloc(process->pool,
        sizeof(module *)*(total_modules+DYNAMIC_MODULE_LIMIT+1));
    if (ap_loaded_modules == NULL) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                     "Ouch!  Out of memory in ap_setup_prelinked_modules()!");
    }
    for (m = ap_preloaded_modules, m2 = ap_loaded_modules; *m != NULL; )
        *m2++ = *m++;
    *m2 = NULL;

    /*
     *   Initialize chain of linked (=activate) modules
     */
    for (m = ap_prelinked_modules; *m != NULL; m++)
        ap_add_module(*m);

    ap_sort_hooks();
}

AP_DECLARE(const char *) ap_find_module_name(module *m)
{
    return m->name;
}

AP_DECLARE(module *) ap_find_linked_module(const char *name)
{
    module *modp;

    for (modp = top_module; modp; modp = modp->next) {
	if (strcmp(modp->name, name) == 0)
	    return modp;
    }
    return NULL;
}

/* Add a named module.  Returns 1 if module found, 0 otherwise.  */
AP_DECLARE(int) ap_add_named_module(const char *name)
{
    module *modp;
    int i = 0;

    for (modp = ap_loaded_modules[i]; modp; modp = ap_loaded_modules[++i]) {
	if (strcmp(modp->name, name) == 0) {
	    /* Only add modules that are not already enabled.  */
	    if (modp->next == NULL) {
		ap_add_module(modp);
	    }
	    return 1;
	}
    }

    return 0;
}

/* Clear the internal list of modules, in preparation for starting over. */
AP_DECLARE(void) ap_clear_module_list()
{
    module **m = &top_module;
    module **next_m;

    while (*m) {
	next_m = &((*m)->next);
	*m = NULL;
	m = next_m;
    }

    /* This is required; so we add it always.  */
    ap_add_named_module("http_core.c");
}

/*****************************************************************
 *
 * Resource, access, and .htaccess config files now parsed by a common
 * command loop.
 *
 * Let's begin with the basics; parsing the line and
 * invoking the function...
 */

static const char *invoke_cmd(const command_rec *cmd, cmd_parms *parms,
			      void *mconfig, const char *args)
{
    char *w, *w2, *w3;
    const char *errmsg;

    if ((parms->override & cmd->req_override) == 0)
	return apr_pstrcat(parms->pool, cmd->name, " not allowed here", NULL);

    parms->info = cmd->cmd_data;
    parms->cmd = cmd;

    switch (cmd->args_how) {
    case RAW_ARGS:
#ifdef RESOLVE_ENV_PER_TOKEN
	args = ap_resolve_env(parms->pool,args);
#endif
	return cmd->AP_RAW_ARGS(parms, mconfig, args);

    case NO_ARGS:
	if (*args != 0)
	    return apr_pstrcat(parms->pool, cmd->name, " takes no arguments",
			   NULL);

	return cmd->AP_NO_ARGS(parms, mconfig);

    case TAKE1:
	w = ap_getword_conf(parms->pool, &args);

	if (*w == '\0' || *args != 0)
	    return apr_pstrcat(parms->pool, cmd->name, " takes one argument",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return cmd->AP_TAKE1(parms, mconfig, w);

    case TAKE2:
	w = ap_getword_conf(parms->pool, &args);
	w2 = ap_getword_conf(parms->pool, &args);

	if (*w == '\0' || *w2 == '\0' || *args != 0)
	    return apr_pstrcat(parms->pool, cmd->name, " takes two arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return cmd->AP_TAKE2(parms, mconfig, w, w2);

    case TAKE12:

	w = ap_getword_conf(parms->pool, &args);
	w2 = ap_getword_conf(parms->pool, &args);

	if (*w == '\0' || *args != 0)
	    return apr_pstrcat(parms->pool, cmd->name, " takes 1-2 arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return cmd->AP_TAKE2(parms, mconfig, w, *w2 ? w2 : NULL);

    case TAKE3:

	w = ap_getword_conf(parms->pool, &args);
	w2 = ap_getword_conf(parms->pool, &args);
	w3 = ap_getword_conf(parms->pool, &args);

	if (*w == '\0' || *w2 == '\0' || *w3 == '\0' || *args != 0)
	    return apr_pstrcat(parms->pool, cmd->name, " takes three arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

    case TAKE23:

	w = ap_getword_conf(parms->pool, &args);
	w2 = ap_getword_conf(parms->pool, &args);
	w3 = *args ? ap_getword_conf(parms->pool, &args) : NULL;

	if (*w == '\0' || *w2 == '\0' || *args != 0)
	    return apr_pstrcat(parms->pool, cmd->name,
			    " takes two or three arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

    case TAKE123:

	w = ap_getword_conf(parms->pool, &args);
	w2 = *args ? ap_getword_conf(parms->pool, &args) : NULL;
	w3 = *args ? ap_getword_conf(parms->pool, &args) : NULL;

	if (*w == '\0' || *args != 0)
	    return apr_pstrcat(parms->pool, cmd->name,
			    " takes one, two or three arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

    case TAKE13:

	w = ap_getword_conf(parms->pool, &args);
	w2 = *args ? ap_getword_conf(parms->pool, &args) : NULL;
	w3 = *args ? ap_getword_conf(parms->pool, &args) : NULL;

	if (*w == '\0' || (w2 && *w2 && !w3) || *args != 0)
	    return apr_pstrcat(parms->pool, cmd->name,
			    " takes one or three arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

    case ITERATE:

	while (*(w = ap_getword_conf(parms->pool, &args)) != '\0')
	    {
	    if ((errmsg = cmd->AP_TAKE1(parms, mconfig, w)))
		return errmsg;
	    }

	return NULL;

    case ITERATE2:

	w = ap_getword_conf(parms->pool, &args);

	if (*w == '\0' || *args == 0)
	    return apr_pstrcat(parms->pool, cmd->name,
			    " requires at least two arguments",
			    cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

	while (*(w2 = ap_getword_conf(parms->pool, &args)) != '\0')
	    {
	    if ((errmsg = cmd->AP_TAKE2(parms, mconfig, w, w2)))
		return errmsg;
	    }

	return NULL;

    case FLAG:

	w = ap_getword_conf(parms->pool, &args);

	if (*w == '\0' || (strcasecmp(w, "on") && strcasecmp(w, "off")))
	    return apr_pstrcat(parms->pool, cmd->name, " must be On or Off",
			    NULL);

	return cmd->AP_FLAG(parms, mconfig, strcasecmp(w, "off") != 0);

    default:

	return apr_pstrcat(parms->pool, cmd->name,
		    " is improperly configured internally (server bug)",
			NULL);
    }
}

AP_CORE_DECLARE(const command_rec *) ap_find_command(const char *name, const command_rec *cmds)
{
    while (cmds->name)
	if (!strcasecmp(name, cmds->name))
	    return cmds;
	else
	    ++cmds;

    return NULL;
}

AP_CORE_DECLARE(const command_rec *) ap_find_command_in_modules(const char *cmd_name, module **mod)
{
    const command_rec *cmdp;
    module *modp;

    for (modp = *mod; modp; modp = modp->next)
	if (modp->cmds && (cmdp = ap_find_command(cmd_name, modp->cmds))) {
	    *mod = modp;
	    return cmdp;
	}

    return NULL;
}

AP_CORE_DECLARE(void *) ap_set_config_vectors(cmd_parms *parms, void *config, module *mod)
{
    void *mconfig = ap_get_module_config(config, mod);
    void *sconfig = ap_get_module_config(parms->server->module_config, mod);

    if (!mconfig && mod->create_dir_config) {
	mconfig = (*mod->create_dir_config) (parms->pool, parms->path);
	ap_set_module_config(config, mod, mconfig);
    }

    if (!sconfig && mod->create_server_config) {
	sconfig = (*mod->create_server_config) (parms->pool, parms->server);
	ap_set_module_config(parms->server->module_config, mod, sconfig);
    }
    return mconfig;
}

static const char *execute_now(char *cmd_line, const char *args, cmd_parms *parms, 
                         apr_pool_t *p, apr_pool_t *ptemp,
                         ap_directive_t **sub_tree, ap_directive_t *parent);

static const char * ap_build_config_sub(apr_pool_t *p, apr_pool_t *temp_pool,
					const char *l, cmd_parms *parms,
					ap_directive_t **current,
					ap_directive_t **curr_parent,
                                        ap_directive_t **conftree)
{
    const char *args;
    char *cmd_name;
    ap_directive_t *newdir;
    module *mod = top_module;
    const command_rec *cmd;

    if (*l == '#' || *l == '\0')
	return NULL;

#if RESOLVE_ENV_PER_TOKEN
    args = l;
#else
    args = ap_resolve_env(temp_pool, l); 
#endif
    cmd_name = ap_getword_conf(p, &args);
    if (*cmd_name == '\0') {
	/* Note: this branch should not occur. An empty line should have
	 * triggered the exit further above.
	 */
	return NULL;
    }

    newdir = apr_pcalloc(p, sizeof(ap_directive_t));
    newdir->filename = parms->config_file->name;
    newdir->line_num = parms->config_file->line_number;
    newdir->directive = cmd_name;
    newdir->args = apr_pstrdup(p, args);

    if ((cmd = ap_find_command_in_modules(cmd_name, &mod)) != NULL) {
        if (cmd->req_override & EXEC_ON_READ) {
            const char *retval;
            ap_directive_t *sub_tree = NULL;

            parms->err_directive = newdir;
            retval = execute_now(cmd_name, args, parms, p, temp_pool, 
                                 &sub_tree, *curr_parent);
            if (*current) {
                (*current)->next = sub_tree;
            }
            else {
                (*current) = sub_tree;
                if (*curr_parent) {
                    (*curr_parent)->first_child = (*current);
                }
                if (*current) {
                    (*current)->parent = (*curr_parent);
                }
            }
            if (*current) {
                if (!*conftree) {
                    /* Before walking *current to the end of the list,
                     * set the head to *current.
                     */
                    *conftree = *current;
                }
                while ((*current)->next != NULL) {
                    (*current) = (*current)->next;
                    (*current)->parent = (*curr_parent);
                }
            }
            return retval;
        }
    }

    if (cmd_name[0] == '<') {
        if (cmd_name[1] != '/') {
            (*current) = ap_add_node(curr_parent, *current, newdir, 1);
        }
	else if (*curr_parent == NULL) {
            parms->err_directive = newdir;
	    return apr_pstrcat(p, cmd_name,
			      " without matching <", cmd_name + 2,
			      " section", NULL);
	}
	else {
	    char *bracket = cmd_name + strlen(cmd_name) - 1;

	    if (*bracket != '>') {
		return apr_pstrcat(p, cmd_name,
				  "> directive missing closing '>'", NULL);
	    }
	    *bracket = '\0';
	    if (strcasecmp(cmd_name + 2,
			    (*curr_parent)->directive + 1) != 0) {
		return apr_pstrcat(p, "Expected </",
				  (*curr_parent)->directive + 1, "> but saw ",
				  cmd_name, ">", NULL);
	    }
	    *bracket = '>';

	    /* done with this section; move up a level */
            *current = *curr_parent;
            *curr_parent = (*current)->parent;
        }
    }
    else {
        *current = ap_add_node(curr_parent, *current, newdir, 0);
    }

    return NULL;
}

const char *ap_build_cont_config(apr_pool_t *p, apr_pool_t *temp_pool,
				 cmd_parms *parms,
				 ap_directive_t **current,
				 ap_directive_t **curr_parent,
				 char *orig_directive)
{
    char l[MAX_STRING_LEN];
    char *bracket;
    const char *retval;
    ap_directive_t *sub_tree = NULL;

    bracket = apr_pstrcat(p, orig_directive + 1, ">", NULL);
    while (!(ap_cfg_getline(l, MAX_STRING_LEN, parms->config_file))) {
        if (!memcmp(l, "</", 2) &&
            (strcasecmp(l + 2, bracket) == 0) &&
            (*curr_parent == NULL)) {
            break;
        } 
        retval = ap_build_config_sub(p, temp_pool, l, parms, current, 
                                     curr_parent, &sub_tree);
        if (retval != NULL)
            return retval;
        if (sub_tree == NULL && curr_parent != NULL) { 
            sub_tree = *curr_parent;
        }
        if (sub_tree == NULL && current != NULL) {
            sub_tree = *current;
        }
    }
    *current = sub_tree;
    return NULL;
}

static const char *ap_walk_config_sub(const ap_directive_t *current,
				      cmd_parms *parms, void *config)
{
    module *mod = top_module;

    while (1) {
	const command_rec *cmd;

	if (!(cmd = ap_find_command_in_modules(current->directive, &mod))) {
            parms->err_directive = current;
            return apr_pstrcat(parms->pool, "Invalid command '", 
			      current->directive,
			      "', perhaps mis-spelled or defined by a module "
			      "not included in the server configuration",
			      NULL);
	}
	else {
	    void *mconfig = ap_set_config_vectors(parms,config, mod);
	    const char *retval;

	    retval = invoke_cmd(cmd, parms, mconfig, current->args);
	    if (retval == NULL) {
                return NULL;
            }
            if (strcmp(retval, DECLINE_CMD) != 0) {
                /* If the directive in error has already been set, don't
                 * replace it.  Otherwise, an error inside a container 
                 * will be reported as occuring on the first line of the
                 * container.
                 */
                if (!parms->err_directive) {
                    parms->err_directive = current;
                }
		return retval;
            }

	    mod = mod->next;	/* Next time around, skip this one */
	}
    }
    /* NOTREACHED */
}

AP_DECLARE(const char *) ap_walk_config(ap_directive_t *current,
					cmd_parms *parms, void *config)
{
    void *oldconfig = parms->context;

    parms->context = config;

    /* scan through all directives, executing each one */
    for (; current != NULL; current = current->next) {
	const char *errmsg;

	parms->directive = current;

        /* actually parse the command and execute the correct function */
        errmsg = ap_walk_config_sub(current, parms, config);
	if (errmsg != NULL) {
	    /* restore the context (just in case) */
	    parms->context = oldconfig;
	    return errmsg;
	}
    }

    parms->context = oldconfig;
    return NULL;
}


AP_DECLARE(const char *) ap_build_config(cmd_parms *parms,
					 apr_pool_t *p, apr_pool_t *temp_pool,
					 ap_directive_t **conftree)
{
    ap_directive_t *current = *conftree;
    ap_directive_t *curr_parent = NULL;
    char l[MAX_STRING_LEN];
    const char *errmsg;

    if (current != NULL) {
        while (current->next) {
            current = current->next;
        }
    }

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, parms->config_file))) {

	errmsg = ap_build_config_sub(p, temp_pool, l, parms,
				     &current, &curr_parent, conftree);
	if (errmsg != NULL)
	    return errmsg;

        if (*conftree == NULL && curr_parent != NULL) { 
            *conftree = curr_parent;
        }
        if (*conftree == NULL && current != NULL) {
            *conftree = current;
        }
    }

    if (curr_parent != NULL) {
	errmsg = "";
	while (curr_parent != NULL) {
	    errmsg = apr_psprintf(p, "%s%s%s:%u: %s> was not closed.",
				 errmsg,
				 *errmsg == '\0' ? "" : APR_EOL_STR,
				 curr_parent->filename,
				 curr_parent->line_num,
				 curr_parent->directive);
	    curr_parent = curr_parent->parent;
	}
	return errmsg;
    }

    return NULL;
}

/*
 * Generic command functions...
 */

AP_DECLARE_NONSTD(const char *) ap_set_string_slot(cmd_parms *cmd,
						   void *struct_ptr,
						   const char *arg)
{
    /* This one's pretty generic... */

    int offset = (int) (long) cmd->info;
    *(const char **) ((char *)struct_ptr + offset) = arg;
    return NULL;
}

AP_DECLARE_NONSTD(const char *) ap_set_string_slot_lower(cmd_parms *cmd,
							 void *struct_ptr,
							 const char *arg_)
{
    /* This one's pretty generic... */
    char *arg=apr_pstrdup(cmd->pool,arg_);

    int offset = (int) (long) cmd->info;
    ap_str_tolower(arg);
    *(char **) ((char *)struct_ptr + offset) = arg;
    return NULL;
}

AP_DECLARE_NONSTD(const char *) ap_set_flag_slot(cmd_parms *cmd,
                                                 void *struct_ptr_v, int arg)
{
    /* This one's pretty generic too... */

    int offset = (int) (long) cmd->info;
    char *struct_ptr = (char *)struct_ptr_v;
    *(int *) (struct_ptr + offset) = arg ? 1 : 0;
    return NULL;
}

AP_DECLARE_NONSTD(const char *) ap_set_file_slot(cmd_parms *cmd, void *struct_ptr, 
                                                 const char *arg)
{
    /* Prepend server_root to relative arg.
       This allows .htaccess to be independent of server_root,
       so the server can be moved or mirrored with less pain.  */
    char *p;
    int offset = (int) (long) cmd->info;
#ifndef OS2
    arg = ap_os_canonical_filename(cmd->pool, arg);
#endif
    if (ap_os_is_path_absolute(arg))
	p = apr_pstrdup(cmd->pool, arg);
    else
	p = ap_make_full_path(cmd->pool, ap_server_root, arg);
    *(char **) ((char*)struct_ptr + offset) = p;
    return NULL;
}

/*****************************************************************
 *
 * Reading whole config files...
 */

static cmd_parms default_parms =
{NULL, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

AP_DECLARE(const char *) ap_server_root_relative(apr_pool_t *p, const char *file)
{
#ifndef OS2
    file = ap_os_canonical_filename(p, file);
#endif
    if(ap_os_is_path_absolute(file))
	return file;
    return ap_make_full_path(p, ap_server_root, file);
}

AP_DECLARE(const char *) ap_soak_end_container(cmd_parms *cmd, char *directive)
{
    char l[MAX_STRING_LEN];
    const char *args;
    char *cmd_name;

    while(!(ap_cfg_getline(l, MAX_STRING_LEN, cmd->config_file))) {
#if RESOLVE_ENV_PER_TOKEN
        args = l;
#else
        args = ap_resolve_env(cmd->temp_pool, l);
#endif
        cmd_name = ap_getword_conf(cmd->pool, &args);
        if (cmd_name[0] == '<') {
            if (cmd_name[1] == '/') {
                cmd_name[strlen(cmd_name) - 1] = '\0';
                if (strcasecmp(cmd_name + 2, directive + 1) != 0) {
                    return apr_pstrcat(cmd->pool, "Expected </",
                                      directive + 1, "> but saw ",
                                      cmd_name, ">", NULL);
                }
                break;
            }
            else {
                ap_soak_end_container(cmd, cmd_name);
            }
        }
    }
    return NULL;
}

static const char *execute_now(char *cmd_line, const char *args, cmd_parms *parms, 
                         apr_pool_t *p, apr_pool_t *ptemp, 
                         ap_directive_t **sub_tree, ap_directive_t *parent)
{
    module *mod = top_module;
    const command_rec *cmd;

    if (!(cmd = ap_find_command_in_modules(cmd_line, &mod))) {
        return apr_pstrcat(parms->pool, "Invalid command '", 
                          cmd_line,
                          "', perhaps mis-spelled or defined by a module "
                          "not included in the server configuration",
                          NULL);
    }
    else {
        return invoke_cmd(cmd, parms, sub_tree, args);
    }
}

/* This structure and the following functions are needed for the
 * table-based config file reading. They are passed to the
 * cfg_open_custom() routine.
 */

/* Structure to be passed to cfg_open_custom(): it contains an
 * index which is incremented from 0 to nelts on each call to
 * cfg_getline() (which in turn calls arr_elts_getstr())
 * and an apr_array_header_t pointer for the string array.
 */
typedef struct {
    apr_array_header_t *array;
    int curr_idx;
} arr_elts_param_t;


/* arr_elts_getstr() returns the next line from the string array. */
static void *arr_elts_getstr(void *buf, size_t bufsiz, void *param)
{
    arr_elts_param_t *arr_param = (arr_elts_param_t *) param;

    /* End of array reached? */
    if (++arr_param->curr_idx > arr_param->array->nelts)
        return NULL;

    /* return the line */
    apr_cpystrn(buf, ((char **) arr_param->array->elts)[arr_param->curr_idx - 1], bufsiz);

    return buf;
}


/* arr_elts_close(): dummy close routine (makes sure no more lines can be read) */
static int arr_elts_close(void *param)
{
    arr_elts_param_t *arr_param = (arr_elts_param_t *) param;
    arr_param->curr_idx = arr_param->array->nelts;
    return 0;
}

static void process_command_config(server_rec *s, apr_array_header_t *arr, 
                              ap_directive_t **conftree, apr_pool_t *p,
			      apr_pool_t *ptemp)
{
    const char *errmsg;
    cmd_parms parms;
    arr_elts_param_t arr_parms;

    arr_parms.curr_idx = 0;
    arr_parms.array = arr;

    parms = default_parms;
    parms.pool = p;
    parms.temp_pool = ptemp;
    parms.server = s;
    parms.override = (RSRC_CONF | OR_ALL) & ~(OR_AUTHCFG | OR_LIMIT);

    parms.config_file = ap_pcfg_open_custom(p, "-c/-C directives",
			      &arr_parms, NULL,
			      arr_elts_getstr, arr_elts_close);

    errmsg = ap_build_config(&parms, p, ptemp, conftree);
    if (errmsg) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                     "Syntax error in -C/-c directive:" APR_EOL_STR "%s", 
                     errmsg);
        exit(1);
    }

    ap_cfg_closefile(parms.config_file);
}

typedef struct {
    char *fname;
} fnames;

static int fname_alphasort(const void *fn1, const void *fn2)
{
    const fnames *f1 = fn1;
    const fnames *f2 = fn2;

    return strcmp(f1->fname,f2->fname);
}

void ap_process_resource_config(server_rec *s, const char *fname, 
                                ap_directive_t **conftree, apr_pool_t *p, 
                                apr_pool_t *ptemp)
{
    cmd_parms parms;
    apr_finfo_t finfo;
    const char *errmsg;
    configfile_t *cfp;

    fname = ap_server_root_relative(p, fname);

    /* don't require conf/httpd.conf if we have a -C or -c switch */
    if ((ap_server_pre_read_config->nelts
	 || ap_server_post_read_config->nelts)
	&& !(strcmp(fname, ap_server_root_relative(p, SERVER_CONFIG_FILE)))) {
	if (apr_stat(&finfo, fname, p) != APR_SUCCESS)     
	    return;
    }

    /* 
     * here we want to check if the candidate file is really a
     * directory, and most definitely NOT a symlink (to prevent
     * horrible loops).  If so, let's recurse and toss it back into
     * the function.
     */
    if (ap_is_rdirectory(fname)) {
        apr_dir_t *dirp;
	int current;
	apr_array_header_t *candidates = NULL;
	fnames *fnew;

	/*
	 * first course of business is to grok all the directory
	 * entries here and store 'em away. Recall we need full pathnames
	 * for this.
	 */
	fprintf(stderr, "Processing config directory: %s\n", fname);
	if (apr_opendir(&dirp, fname, p) != APR_SUCCESS) {
	    perror("fopen");
	    fprintf(stderr, "%s: could not open config directory %s\n",
		ap_server_argv0, fname);
	    exit(1);
	}
	candidates = apr_make_array(p, 1, sizeof(fnames));
        while (apr_readdir(dirp) == APR_SUCCESS) {
            char *d_name;
	    apr_get_dir_filename(&d_name, dirp);
	    /* strip out '.' and '..' */
	    if (strcmp(d_name, ".") &&
		strcmp(d_name, "..")) {
		fnew = (fnames *) apr_push_array(candidates);
		fnew->fname = ap_make_full_path(p, fname, d_name);
	    }
	}
	apr_closedir(dirp);
	if (candidates->nelts != 0) {
            qsort((void *) candidates->elts, candidates->nelts,
              sizeof(fnames), fname_alphasort);
	    /*
	     * Now recurse these... we handle errors and subdirectories
	     * via the recursion, which is nice
	     */
	    for (current = 0; current < candidates->nelts; ++current) {
	        fnew = &((fnames *) candidates->elts)[current];
		fprintf(stderr, " Processing config file: %s\n", fnew->fname);
		ap_process_resource_config(s, fnew->fname, conftree, p, ptemp);
	    }
	}
	return;
    }
    
    /* GCC's initialization extensions are soooo nice here... */

    parms = default_parms;
    parms.pool = p;
    parms.temp_pool = ptemp;
    parms.server = s;
    parms.override = (RSRC_CONF | OR_ALL) & ~(OR_AUTHCFG | OR_LIMIT);

    if (ap_pcfg_openfile(&cfp, p, fname) != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                     "%s: could not open document config file %s",
		     ap_server_argv0, fname);
	exit(1);
    }

    parms.config_file = cfp;

    errmsg = ap_build_config(&parms, p, ptemp, conftree);

    if (errmsg != NULL) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                     "Syntax error on line %d of %s:",
                     parms.err_directive->line_num, 
                     parms.err_directive->filename);
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s", errmsg);
	exit(1);
    }

    ap_cfg_closefile(cfp);
}

AP_DECLARE(void)ap_process_config_tree(server_rec *s, ap_directive_t *conftree,
                                       apr_pool_t *p, apr_pool_t *ptemp)
{
    const char *errmsg;
    cmd_parms parms;

    parms = default_parms;
    parms.pool = p;
    parms.temp_pool = ptemp;
    parms.server = s;
    parms.override = (RSRC_CONF | OR_ALL) & ~(OR_AUTHCFG | OR_LIMIT);
    parms.limited = -1;

    errmsg = ap_walk_config(conftree, &parms, s->lookup_defaults);
    if (errmsg) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                     "Syntax error on line %d of %s:",
                     parms.err_directive->line_num,
                     parms.err_directive->filename);
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s", errmsg);
        exit(1);
    }
}

int ap_parse_htaccess(void **result, request_rec *r, int override,
		      const char *d, const char *access_name) {
    configfile_t *f = NULL;
    cmd_parms parms;
    char *filename = NULL;
    const struct htaccess_result *cache;
    struct htaccess_result *new;
    void *dc = NULL;
    apr_status_t status;

/* firstly, search cache */
    for (cache = r->htaccess; cache != NULL; cache = cache->next)
	if (cache->override == override && strcmp(cache->dir, d) == 0) {
	    if (cache->htaccess != NULL)
		*result = cache->htaccess;
	    return OK;
	}

    parms = default_parms;
    parms.override = override;
    parms.pool = r->pool;
    parms.temp_pool = r->pool;
    parms.server = r->server;
    parms.path = apr_pstrdup(r->pool, d);

    /* loop through the access names and find the first one */

    while (access_name[0]) {
        filename = ap_make_full_path(r->pool, d,
                                     ap_getword_conf(r->pool, &access_name));
        status = ap_pcfg_openfile(&f, r->pool, filename);

        if (status == APR_SUCCESS) {
	    const char *errmsg;
	    ap_directive_t *temptree = NULL;

            dc = ap_create_per_dir_config(r->pool);

            parms.config_file = f;
            errmsg = ap_build_config(&parms, r->pool, r->pool, &temptree);
	    if (errmsg == NULL)
		errmsg = ap_walk_config(temptree, &parms, dc);

            ap_cfg_closefile(f);

            if (errmsg) {
                ap_log_rerror(APLOG_MARK, APLOG_ALERT|APLOG_NOERRNO, 0, r,
                              "%s: %s", filename, errmsg);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            *result = dc;
            break;
        } else {
	    if (!APR_STATUS_IS_ENOENT(status) && !APR_STATUS_IS_ENOTDIR(status)) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r,
			      "%s pcfg_openfile: unable to check htaccess file, "
			      "ensure it is readable",
			      filename);
		apr_table_setn(r->notes, "error-notes",
			      "Server unable to read htaccess file, denying "
			      "access to be safe");
		return HTTP_FORBIDDEN;
	    }
        }
    }

/* cache it */
    new = apr_palloc(r->pool, sizeof(struct htaccess_result));
    new->dir = parms.path;
    new->override = override;
    new->htaccess = dc;
/* add to head of list */
    new->next = r->htaccess;
    r->htaccess = new;

    return OK;
}

AP_CORE_DECLARE(const char *) ap_init_virtual_host(apr_pool_t *p, const char *hostname,
			      server_rec *main_server, server_rec **ps)
{
    server_rec *s = (server_rec *) apr_pcalloc(p, sizeof(server_rec));

    /* TODO: this crap belongs in http_core */
    s->process = main_server->process;
    s->server_admin = NULL;
    s->server_hostname = NULL;
    s->error_fname = NULL;
    s->timeout = 0;
    s->keep_alive_timeout = 0;
    s->keep_alive = -1;
    s->keep_alive_max = -1;
    s->error_log = main_server->error_log;
    s->loglevel = main_server->loglevel;
    /* useful default, otherwise we get a port of 0 on redirects */
    s->port = main_server->port;
    s->next = NULL;

    s->is_virtual = 1;
    s->names = apr_make_array(p, 4, sizeof(char **));
    s->wild_names = apr_make_array(p, 4, sizeof(char **));

    s->module_config = create_empty_config(p);
    s->lookup_defaults = ap_create_per_dir_config(p);

    s->limit_req_line = main_server->limit_req_line;
    s->limit_req_fieldsize = main_server->limit_req_fieldsize;
    s->limit_req_fields = main_server->limit_req_fields;

    *ps = s;

    return ap_parse_vhost_addrs(p, hostname, s);
}


AP_DECLARE(void) ap_fixup_virtual_hosts(apr_pool_t *p, server_rec *main_server)
{
    server_rec *virt;

    for (virt = main_server->next; virt; virt = virt->next) {
	merge_server_configs(p, main_server->module_config,
			     virt->module_config);

	virt->lookup_defaults =
	    ap_merge_per_dir_configs(p, main_server->lookup_defaults,
				  virt->lookup_defaults);

	if (virt->server_admin == NULL)
	    virt->server_admin = main_server->server_admin;

	if (virt->timeout == 0)
	    virt->timeout = main_server->timeout;

	if (virt->keep_alive_timeout == 0)
	    virt->keep_alive_timeout = main_server->keep_alive_timeout;

	if (virt->keep_alive == -1)
	    virt->keep_alive = main_server->keep_alive;

	if (virt->keep_alive_max == -1)
	    virt->keep_alive_max = main_server->keep_alive_max;

	/* XXX: this is really something that should be dealt with by a
	 * post-config api phase */
	ap_core_reorder_directories(p, virt);
    }
    ap_core_reorder_directories(p, main_server);
}

/*****************************************************************
 *
 * Getting *everything* configured... 
 */

static void init_config_globals(apr_pool_t *p)
{
    /* Global virtual host hash bucket pointers.  Init to null. */
    ap_init_vhost_config(p);
}

static server_rec *init_server_config(process_rec *process, apr_pool_t *p)
{
    server_rec *s = (server_rec *) apr_pcalloc(p, sizeof(server_rec));

    apr_open_stderr(&s->error_log, p);
    s->process = process;
    s->port = 0;
    s->server_admin = DEFAULT_ADMIN;
    s->server_hostname = NULL;
    s->error_fname = DEFAULT_ERRORLOG;
    s->loglevel = DEFAULT_LOGLEVEL;
    s->limit_req_line = DEFAULT_LIMIT_REQUEST_LINE;
    s->limit_req_fieldsize = DEFAULT_LIMIT_REQUEST_FIELDSIZE;
    s->limit_req_fields = DEFAULT_LIMIT_REQUEST_FIELDS;
    s->timeout = DEFAULT_TIMEOUT;     
    s->keep_alive_timeout = DEFAULT_KEEPALIVE_TIMEOUT;
    s->keep_alive_max = DEFAULT_KEEPALIVE;
    s->keep_alive = 1;
    s->next = NULL;
    s->addrs = apr_pcalloc(p, sizeof(server_addr_rec));
    /* NOT virtual host; don't match any real network interface */
    s->addrs->host_addr.s_addr = htonl(INADDR_ANY);
    s->addrs->host_port = 0;	/* matches any port */
    s->addrs->virthost = "";	/* must be non-NULL */
    s->names = s->wild_names = NULL;

    s->module_config = create_server_config(p, s);
    s->lookup_defaults = create_default_per_dir_config(p);

    return s;
}


AP_DECLARE(server_rec*) ap_read_config(process_rec *process, apr_pool_t *ptemp,
                                       const char *confname, 
                                       ap_directive_t **conftree)
{
    apr_pool_t *p = process->pconf;
    server_rec *s = init_server_config(process, p);

    init_config_globals(p);

    /* All server-wide config files now have the SAME syntax... */

    process_command_config(s, ap_server_pre_read_config, conftree,
                                      p, ptemp);

    ap_process_resource_config(s, confname, conftree, p, ptemp);

    process_command_config(s, ap_server_post_read_config, conftree,
                                      p, ptemp);

    return s;
}

void ap_single_module_configure(apr_pool_t *p, server_rec *s, module *m)
{
    if (m->create_server_config)
        ap_set_module_config(s->module_config, m,
                             (*m->create_server_config)(p, s));
    if (m->create_dir_config)
        ap_set_module_config(s->lookup_defaults, m,
                             (*m->create_dir_config)(p, NULL));
}

AP_DECLARE(void) ap_run_rewrite_args(process_rec *process)
{
    module *m;

    for (m = top_module; m; m = m->next)
        if (m->rewrite_args)
            (*m->rewrite_args) (process);
}

AP_DECLARE(void) ap_post_config_hook(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ap_run_post_config(pconf,plog,ptemp,s); 
    init_handlers(pconf);
}

void ap_child_init_hook(apr_pool_t *pchild, server_rec *s)
{
    /* TODO: uh this seems ugly, is there a better way? */
    /*ap_child_init_alloc();    PUT THIS BACK IN XXXXX */

    ap_run_child_init(pchild,s);
}

/********************************************************************
 * Configuration directives are restricted in terms of where they may
 * appear in the main configuration files and/or .htaccess files according
 * to the bitmask req_override in the command_rec structure.
 * If any of the overrides set in req_override are also allowed in the
 * context in which the command is read, then the command is allowed.
 * The context is determined as follows:
 *
 *    inside *.conf --> override = (RSRC_CONF|OR_ALL)&~(OR_AUTHCFG|OR_LIMIT);
 *    within <Directory> or <Location> --> override = OR_ALL|ACCESS_CONF;
 *    within .htaccess --> override = AllowOverride for current directory;
 *
 * the result is, well, a rather confusing set of possibilities for when
 * a particular directive is allowed to be used.  This procedure prints
 * in English where the given (pc) directive can be used.
 */
static void show_overrides(const command_rec *pc, module *pm)
{
    int n = 0;

    printf("\tAllowed in *.conf ");
    if ((pc->req_override & (OR_OPTIONS | OR_FILEINFO | OR_INDEXES)) ||
	((pc->req_override & RSRC_CONF) &&
	 ((pc->req_override & (ACCESS_CONF | OR_AUTHCFG | OR_LIMIT)))))
	printf("anywhere");
    else if (pc->req_override & RSRC_CONF)
	printf("only outside <Directory>, <Files> or <Location>");
    else
	printf("only inside <Directory>, <Files> or <Location>");

    /* Warn if the directive is allowed inside <Directory> or .htaccess
     * but module doesn't support per-dir configuration */

    if ((pc->req_override & (OR_ALL | ACCESS_CONF)) && !pm->create_dir_config)
	printf(" [no per-dir config]");

    if (pc->req_override & OR_ALL) {
	printf(" and in .htaccess\n\twhen AllowOverride");

	if ((pc->req_override & OR_ALL) == OR_ALL)
	    printf(" isn't None");
	else {
	    printf(" includes ");

	    if (pc->req_override & OR_AUTHCFG) {
		if (n++)
		    printf(" or ");
		printf("AuthConfig");
	    }
	    if (pc->req_override & OR_LIMIT) {
		if (n++)
		    printf(" or ");
		printf("Limit");
	    }
	    if (pc->req_override & OR_OPTIONS) {
		if (n++)
		    printf(" or ");
		printf("Options");
	    }
	    if (pc->req_override & OR_FILEINFO) {
		if (n++)
		    printf(" or ");
		printf("FileInfo");
	    }
	    if (pc->req_override & OR_INDEXES) {
		if (n++)
		    printf(" or ");
		printf("Indexes");
	    }
	}
    }
    printf("\n");
}

/* Show the preloaded configuration directives, the help string explaining
 * the directive arguments, in what module they are handled, and in
 * what parts of the configuration they are allowed.  Used for httpd -h.
 */
AP_DECLARE(void) ap_show_directives()
{
    const command_rec *pc;
    int n;

    for (n = 0; ap_loaded_modules[n]; ++n)
	for (pc = ap_loaded_modules[n]->cmds; pc && pc->name; ++pc) {
	    printf("%s (%s)\n", pc->name, ap_loaded_modules[n]->name);
	    if (pc->errmsg)
		printf("\t%s\n", pc->errmsg);
	    show_overrides(pc, ap_loaded_modules[n]);
	}
}

/* Show the preloaded module names.  Used for httpd -l. */
AP_DECLARE(void) ap_show_modules()
{
    int n;

    printf("Compiled in modules:\n");
    for (n = 0; ap_loaded_modules[n]; ++n)
	printf("  %s\n", ap_loaded_modules[n]->name);
}

