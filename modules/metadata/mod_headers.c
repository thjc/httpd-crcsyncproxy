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
 * mod_headers.c: Add/append/remove HTTP response headers
 *     Written by Paul Sutton, paul@ukweb.com, 1 Oct 1996
 *
 * New directive, Header, can be used to add/replace/remove HTTP headers.
 * Valid in both per-server and per-dir configurations.
 *
 * Syntax is:
 *
 *   Header action header value
 *
 * Where action is one of:
 *     set    - set this header, replacing any old value
 *     add    - add this header, possible resulting in two or more
 *              headers with the same name
 *     append - append this text onto any existing header of this same
 *     unset  - remove this header
 *
 * Where action is unset, the third argument (value) should not be given.
 * The header name can include the colon, or not.
 *
 * The Header directive can only be used where allowed by the FileInfo 
 * override.
 *
 * When the request is processed, the header directives are processed in
 * this order: firstly, the main server, then the virtual server handling
 * this request (if any), then any <Directory> sections (working downwards 
 * from the root dir), then an <Location> sections (working down from 
 * shortest URL component), the any <File> sections. This order is
 * important if any 'set' or 'unset' actions are used. For example,
 * the following two directives have different effect if applied in
 * the reverse order:
 *
 *   Header append Author "John P. Doe"
 *   Header unset Author
 *
 * Examples:
 *
 *  To set the "Author" header, use
 *     Header add Author "John P. Doe"
 *
 *  To remove a header:
 *     Header unset Author
 *
 */

#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

typedef enum {
    hdr_add = 'a',              /* add header (could mean multiple hdrs) */
    hdr_set = 's',              /* set (replace old value) */
    hdr_append = 'm',           /* append (merge into any old value) */
    hdr_unset = 'u'             /* unset header */
} hdr_actions;

typedef struct {
    hdr_actions action;
    char *header;
    const char *value;
} header_entry;

/*
 * headers_conf is our per-module configuration. This is used as both
 * a per-dir and per-server config
 */
typedef struct {
    apr_array_header_t *headers;
} headers_conf;

module AP_MODULE_DECLARE_DATA headers_module;

static void *create_headers_config(apr_pool_t *p, server_rec *s)
{
    headers_conf *a =
    (headers_conf *) apr_pcalloc(p, sizeof(headers_conf));

    a->headers = apr_make_array(p, 2, sizeof(header_entry));
    return a;
}

static void *create_headers_dir_config(apr_pool_t *p, char *d)
{
    return (headers_conf *) create_headers_config(p, NULL);
}

static void *merge_headers_config(apr_pool_t *p, void *basev, void *overridesv)
{
    headers_conf *a =
    (headers_conf *) apr_pcalloc(p, sizeof(headers_conf));
    headers_conf *base = (headers_conf *) basev, *overrides = (headers_conf *) overridesv;

    a->headers = apr_append_arrays(p, base->headers, overrides->headers);

    return a;
}


static const char *header_cmd(cmd_parms *cmd, void *indirconf,
                              const char *action, const char *inhdr, const char *value)
{
    headers_conf *dirconf = indirconf;
    char *hdr = apr_pstrdup(cmd->pool, inhdr);
    header_entry *new;
    server_rec *s = cmd->server;
    headers_conf *serverconf =
    (headers_conf *) ap_get_module_config(s->module_config, &headers_module);
    char *colon;

    if (cmd->path) {
        new = (header_entry *) apr_push_array(dirconf->headers);
    }
    else {
        new = (header_entry *) apr_push_array(serverconf->headers);
    }

    if (!strcasecmp(action, "set"))
        new->action = hdr_set;
    else if (!strcasecmp(action, "add"))
        new->action = hdr_add;
    else if (!strcasecmp(action, "append"))
        new->action = hdr_append;
    else if (!strcasecmp(action, "unset"))
        new->action = hdr_unset;
    else
        return "first argument must be add, set, append or unset.";

    if (new->action == hdr_unset) {
        if (value)
            return "Header unset takes two arguments";
    }
    else if (!value)
        return "Header requires three arguments";

    if ((colon = strchr(hdr, ':')))
        *colon = '\0';

    new->header = hdr;
    new->value = value;

    return NULL;
}

static const command_rec headers_cmds[] =
{
    AP_INIT_TAKE23("Header", header_cmd, NULL, OR_FILEINFO,
                   "an action, header and value"),
    {NULL}
};

static void do_headers_fixup(request_rec *r, apr_array_header_t *headers)
{
    int i;

    for (i = 0; i < headers->nelts; ++i) {
        header_entry *hdr = &((header_entry *) (headers->elts))[i];
        switch (hdr->action) {
        case hdr_add:
            apr_table_addn(r->headers_out, hdr->header, hdr->value);
            break;
        case hdr_append:
            apr_table_mergen(r->headers_out, hdr->header, hdr->value);
            break;
        case hdr_set:
            apr_table_setn(r->headers_out, hdr->header, hdr->value);
            break;
        case hdr_unset:
            apr_table_unset(r->headers_out, hdr->header);
            break;
        }
    }

}

static int fixup_headers(request_rec *r)
{
    void *sconf = r->server->module_config;
    headers_conf *serverconf =
    (headers_conf *) ap_get_module_config(sconf, &headers_module);
    void *dconf = r->per_dir_config;
    headers_conf *dirconf =
    (headers_conf *) ap_get_module_config(dconf, &headers_module);

    do_headers_fixup(r, serverconf->headers);
    do_headers_fixup(r, dirconf->headers);

    return DECLINED;
}
static void register_hooks(void)
{
    ap_hook_fixups(fixup_headers,NULL,NULL,AP_HOOK_MIDDLE);
} 
module AP_MODULE_DECLARE_DATA headers_module =
{
    STANDARD20_MODULE_STUFF,
    create_headers_dir_config,  /* dir config creater */
    merge_headers_config,       /* dir merger --- default is to override */
    create_headers_config,      /* server config */
    merge_headers_config,       /* merge server configs */
    headers_cmds,               /* command apr_table_t */
    register_hooks		/* register hooks */
};
