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

#define CORE_PRIVATE
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"	/* For index_of_response().  Grump. */
#include "http_request.h"
#include "http_vhost.h"
#include "http_main.h"		/* For the default_handler below... */
#include "http_log.h"
#include "rfc1413.h"
#include "util_md5.h"
#include "apr_fnmatch.h"
#include "http_connection.h"
#include "ap_buckets.h"
#include "util_filter.h"
#include "util_ebcdic.h"
#include "mpm.h"
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

/* Make sure we don't write less than 4096 bytes at any one time.
 */
#define MIN_BYTES_TO_WRITE  9000

/* LimitXMLRequestBody handling */
#define AP_LIMIT_UNSET                  ((long) -1)
#define AP_DEFAULT_LIMIT_XML_BODY       ((size_t)1000000)

/* Server core module... This module provides support for really basic
 * server operations, including options and commands which control the
 * operation of other modules.  Consider this the bureaucracy module.
 *
 * The core module also defines handlers, etc., do handle just enough
 * to allow a server with the core module ONLY to actually serve documents
 * (though it slaps DefaultType on all of 'em); this was useful in testing,
 * but may not be worth preserving.
 *
 * This file could almost be mod_core.c, except for the stuff which affects
 * the http_conf_globals.
 */

static void *create_core_dir_config(apr_pool_t *a, char *dir)
{
    core_dir_config *conf;

    conf = (core_dir_config *)apr_pcalloc(a, sizeof(core_dir_config));
    if (!dir || dir[strlen(dir) - 1] == '/') {
        conf->d = dir;
    }
    else if (strncmp(dir, "proxy:", 6) == 0) {
        conf->d = apr_pstrdup(a, dir);
    }
    else {
        conf->d = apr_pstrcat(a, dir, "/", NULL);
    }
    conf->d_is_fnmatch = conf->d ? (apr_is_fnmatch(conf->d) != 0) : 0;
    conf->d_components = conf->d ? ap_count_dirs(conf->d) : 0;

    conf->opts = dir ? OPT_UNSET : OPT_UNSET|OPT_ALL;
    conf->opts_add = conf->opts_remove = OPT_NONE;
    conf->override = dir ? OR_UNSET : OR_UNSET|OR_ALL;

    conf->content_md5 = 2;

    conf->use_canonical_name = USE_CANONICAL_NAME_UNSET;

    conf->hostname_lookups = HOSTNAME_LOOKUP_UNSET;
    conf->do_rfc1413 = DEFAULT_RFC1413 | 2; /* set bit 1 to indicate default */
    conf->satisfy = SATISFY_NOSPEC;

#ifdef RLIMIT_CPU
    conf->limit_cpu = NULL;
#endif
#if defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS)
    conf->limit_mem = NULL;
#endif
#ifdef RLIMIT_NPROC
    conf->limit_nproc = NULL;
#endif

    conf->limit_req_body = 0;
    conf->limit_xml_body = AP_LIMIT_UNSET;
    conf->sec = apr_make_array(a, 2, sizeof(void *));
#ifdef WIN32
    conf->script_interpreter_source = INTERPRETER_SOURCE_UNSET;
#endif

    conf->server_signature = srv_sig_unset;

    conf->add_default_charset = ADD_DEFAULT_CHARSET_UNSET;
    conf->add_default_charset_name = DEFAULT_ADD_DEFAULT_CHARSET_NAME;

    conf->output_filters = apr_make_array(a, 2, sizeof(void *));
    conf->input_filters = apr_make_array(a, 2, sizeof(void *));
    return (void *)conf;
}

static void *merge_core_dir_configs(apr_pool_t *a, void *basev, void *newv)
{
    core_dir_config *base = (core_dir_config *)basev;
    core_dir_config *new = (core_dir_config *)newv;
    core_dir_config *conf;
    int i;
  
    conf = (core_dir_config *)apr_palloc(a, sizeof(core_dir_config));
    memcpy((char *)conf, (const char *)base, sizeof(core_dir_config));
    if (base->response_code_strings) {
	conf->response_code_strings =
	    apr_palloc(a, sizeof(*conf->response_code_strings)
		      * RESPONSE_CODES);
	memcpy(conf->response_code_strings, base->response_code_strings,
	       sizeof(*conf->response_code_strings) * RESPONSE_CODES);
    }
    
    conf->d = new->d;
    conf->d_is_fnmatch = new->d_is_fnmatch;
    conf->d_components = new->d_components;
    conf->r = new->r;
    
    if (new->opts & OPT_UNSET) {
	/* there was no explicit setting of new->opts, so we merge
	 * preserve the invariant (opts_add & opts_remove) == 0
	 */
	conf->opts_add = (conf->opts_add & ~new->opts_remove) | new->opts_add;
	conf->opts_remove = (conf->opts_remove & ~new->opts_add)
	                    | new->opts_remove;
	conf->opts = (conf->opts & ~conf->opts_remove) | conf->opts_add;
        if ((base->opts & OPT_INCNOEXEC) && (new->opts & OPT_INCLUDES)) {
            conf->opts = (conf->opts & ~OPT_INCNOEXEC) | OPT_INCLUDES;
	}
    }
    else {
	/* otherwise we just copy, because an explicit opts setting
	 * overrides all earlier +/- modifiers
	 */
	conf->opts = new->opts;
	conf->opts_add = new->opts_add;
	conf->opts_remove = new->opts_remove;
    }

    if (!(new->override & OR_UNSET)) {
        conf->override = new->override;
    }
    if (new->ap_default_type) {
        conf->ap_default_type = new->ap_default_type;
    }
    
    if (new->ap_auth_type) {
        conf->ap_auth_type = new->ap_auth_type;
    }
    if (new->ap_auth_name) {
        conf->ap_auth_name = new->ap_auth_name;
    }
    if (new->ap_requires) {
        conf->ap_requires = new->ap_requires;
    }

    if (new->response_code_strings) {
	if (conf->response_code_strings == NULL) {
	    conf->response_code_strings = apr_palloc(a,
		sizeof(*conf->response_code_strings) * RESPONSE_CODES);
	    memcpy(conf->response_code_strings, new->response_code_strings,
		   sizeof(*conf->response_code_strings) * RESPONSE_CODES);
	}
	else {
	    for (i = 0; i < RESPONSE_CODES; ++i) {
	        if (new->response_code_strings[i] != NULL) {
		    conf->response_code_strings[i]
		        = new->response_code_strings[i];
		}
	    }
	}
    }
    if (new->hostname_lookups != HOSTNAME_LOOKUP_UNSET) {
	conf->hostname_lookups = new->hostname_lookups;
    }
    if ((new->do_rfc1413 & 2) == 0) {
        conf->do_rfc1413 = new->do_rfc1413;
    }
    if ((new->content_md5 & 2) == 0) {
        conf->content_md5 = new->content_md5;
    }
    if (new->use_canonical_name != USE_CANONICAL_NAME_UNSET) {
	conf->use_canonical_name = new->use_canonical_name;
    }

#ifdef RLIMIT_CPU
    if (new->limit_cpu) {
        conf->limit_cpu = new->limit_cpu;
    }
#endif
#if defined(RLIMIT_DATA) || defined(RLIMIT_VMEM) || defined(RLIMIT_AS)
    if (new->limit_mem) {
        conf->limit_mem = new->limit_mem;
    }
#endif
#ifdef RLIMIT_NPROC
    if (new->limit_nproc) {
        conf->limit_nproc = new->limit_nproc;
    }
#endif

    if (new->limit_req_body) {
        conf->limit_req_body = new->limit_req_body;
    }

    if (new->limit_xml_body != AP_LIMIT_UNSET)
        conf->limit_xml_body = new->limit_xml_body;
    else
        conf->limit_xml_body = base->limit_xml_body;

    conf->sec = apr_append_arrays(a, base->sec, new->sec);

    if (new->satisfy != SATISFY_NOSPEC) {
        conf->satisfy = new->satisfy;
    }

#ifdef WIN32
    if (new->script_interpreter_source != INTERPRETER_SOURCE_UNSET) {
        conf->script_interpreter_source = new->script_interpreter_source;
    }
#endif

    if (new->server_signature != srv_sig_unset) {
	conf->server_signature = new->server_signature;
    }

    if (new->add_default_charset != ADD_DEFAULT_CHARSET_UNSET) {
	conf->add_default_charset = new->add_default_charset;
	if (new->add_default_charset_name) {
	    conf->add_default_charset_name = new->add_default_charset_name;
	}
    }
    conf->output_filters = apr_append_arrays(a, base->output_filters, 
                                             new->output_filters);
    conf->input_filters = apr_append_arrays(a, base->input_filters,
                                            new->input_filters);

    return (void*)conf;
}

static void *create_core_server_config(apr_pool_t *a, server_rec *s)
{
    core_server_config *conf;
    int is_virtual = s->is_virtual;
  
    conf = (core_server_config *)apr_pcalloc(a, sizeof(core_server_config));
#ifdef GPROF
    conf->gprof_dir = NULL;
#endif
    conf->access_name = is_virtual ? NULL : DEFAULT_ACCESS_FNAME;
    conf->ap_document_root = is_virtual ? NULL : DOCUMENT_LOCATION;
    conf->sec = apr_make_array(a, 40, sizeof(void *));
    conf->sec_url = apr_make_array(a, 40, sizeof(void *));
    
    return (void *)conf;
}

static void *merge_core_server_configs(apr_pool_t *p, void *basev, void *virtv)
{
    core_server_config *base = (core_server_config *)basev;
    core_server_config *virt = (core_server_config *)virtv;
    core_server_config *conf;

    conf = (core_server_config *)apr_pcalloc(p, sizeof(core_server_config));
    *conf = *virt;
    if (!conf->access_name) {
        conf->access_name = base->access_name;
    }
    if (!conf->ap_document_root) {
        conf->ap_document_root = base->ap_document_root;
    }
    conf->sec = apr_append_arrays(p, base->sec, virt->sec);
    conf->sec_url = apr_append_arrays(p, base->sec_url, virt->sec_url);

    return conf;
}

/* Add per-directory configuration entry (for <directory> section);
 * these are part of the core server config.
 */

AP_CORE_DECLARE(void) ap_add_per_dir_conf(server_rec *s, void *dir_config)
{
    core_server_config *sconf = ap_get_module_config(s->module_config,
						     &core_module);
    void **new_space = (void **)apr_push_array(sconf->sec);
    
    *new_space = dir_config;
}

AP_CORE_DECLARE(void) ap_add_per_url_conf(server_rec *s, void *url_config)
{
    core_server_config *sconf = ap_get_module_config(s->module_config,
						     &core_module);
    void **new_space = (void **)apr_push_array(sconf->sec_url);
    
    *new_space = url_config;
}

AP_CORE_DECLARE(void) ap_add_file_conf(core_dir_config *conf, void *url_config)
{
    void **new_space = (void **)apr_push_array(conf->sec);
    
    *new_space = url_config;
}

/* core_reorder_directories reorders the directory sections such that the
 * 1-component sections come first, then the 2-component, and so on, finally
 * followed by the "special" sections.  A section is "special" if it's a regex,
 * or if it doesn't start with / -- consider proxy: matching.  All movements
 * are in-order to preserve the ordering of the sections from the config files.
 * See directory_walk().
 */

#if defined(HAVE_DRIVE_LETTERS)
#define IS_SPECIAL(entry_core)	\
    ((entry_core)->r != NULL \
	|| ((entry_core)->d[0] != '/' && (entry_core)->d[1] != ':'))
#elif defined(NETWARE)
/* XXX: Fairly certain this is correct... '/' must prefix the path
 *      or else in the case xyz:/ or abc/xyz:/, '/' must follow the ':'.
 *      If there is no leading '/' or embedded ':/', then we are special.
 */
#define IS_SPECIAL(entry_core)	\
    ((entry_core)->r != NULL \
	|| ((entry_core)->d[0] != '/' \
            && strchr((entry_core)->d, ':') \
            && *(strchr((entry_core)->d, ':') + 1) != '/'))
#else
#define IS_SPECIAL(entry_core)	\
    ((entry_core)->r != NULL || (entry_core)->d[0] != '/')
#endif

/* We need to do a stable sort, qsort isn't stable.  So to make it stable
 * we'll be maintaining the original index into the list, and using it
 * as the minor key during sorting.  The major key is the number of
 * components (where a "special" section has infinite components).
 */
struct reorder_sort_rec {
    void *elt;
    int orig_index;
};

static int reorder_sorter(const void *va, const void *vb)
{
    const struct reorder_sort_rec *a = va;
    const struct reorder_sort_rec *b = vb;
    core_dir_config *core_a;
    core_dir_config *core_b;

    core_a = (core_dir_config *)ap_get_module_config(a->elt, &core_module);
    core_b = (core_dir_config *)ap_get_module_config(b->elt, &core_module);
    if (IS_SPECIAL(core_a)) {
	if (!IS_SPECIAL(core_b)) {
	    return 1;
	}
    }
    else if (IS_SPECIAL(core_b)) {
	return -1;
    }
    else {
	/* we know they're both not special */
	if (core_a->d_components < core_b->d_components) {
	    return -1;
	}
	else if (core_a->d_components > core_b->d_components) {
	    return 1;
	}
    }
    /* Either they're both special, or they're both not special and have the
     * same number of components.  In any event, we now have to compare
     * the minor key. */
    return a->orig_index - b->orig_index;
}

void ap_core_reorder_directories(apr_pool_t *p, server_rec *s)
{
    core_server_config *sconf;
    apr_array_header_t *sec;
    struct reorder_sort_rec *sortbin;
    int nelts;
    void **elts;
    int i;
    apr_pool_t *tmp;

    sconf = ap_get_module_config(s->module_config, &core_module);
    sec = sconf->sec;
    nelts = sec->nelts;
    elts = (void **)sec->elts;

    /* we have to allocate tmp space to do a stable sort */
    apr_create_pool(&tmp, p);
    sortbin = apr_palloc(tmp, sec->nelts * sizeof(*sortbin));
    for (i = 0; i < nelts; ++i) {
	sortbin[i].orig_index = i;
	sortbin[i].elt = elts[i];
    }

    qsort(sortbin, nelts, sizeof(*sortbin), reorder_sorter);

    /* and now copy back to the original array */
    for (i = 0; i < nelts; ++i) {
      elts[i] = sortbin[i].elt;
    }

    apr_destroy_pool(tmp);
}

/*****************************************************************
 *
 * There are some elements of the core config structures in which
 * other modules have a legitimate interest (this is ugly, but necessary
 * to preserve NCSA back-compatibility).  So, we have a bunch of accessors
 * here...
 */

AP_DECLARE(int) ap_allow_options(request_rec *r)
{
    core_dir_config *conf = 
      (core_dir_config *)ap_get_module_config(r->per_dir_config, &core_module); 

    return conf->opts; 
} 

AP_DECLARE(int) ap_allow_overrides(request_rec *r) 
{ 
    core_dir_config *conf;
    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
						   &core_module); 

    return conf->override; 
} 

AP_DECLARE(const char *) ap_auth_type(request_rec *r)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
						   &core_module); 
    return conf->ap_auth_type;
}

AP_DECLARE(const char *) ap_auth_name(request_rec *r)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
						   &core_module); 
    return conf->ap_auth_name;
}

AP_DECLARE(const char *) ap_default_type(request_rec *r)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
						   &core_module); 
    return conf->ap_default_type 
               ? conf->ap_default_type 
               : DEFAULT_CONTENT_TYPE;
}

AP_DECLARE(const char *) ap_document_root(request_rec *r) /* Don't use this! */
{
    core_server_config *conf;

    conf = (core_server_config *)ap_get_module_config(r->server->module_config,
						      &core_module); 
    return conf->ap_document_root;
}

AP_DECLARE(const apr_array_header_t *) ap_requires(request_rec *r)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
						   &core_module); 
    return conf->ap_requires;
}

AP_DECLARE(int) ap_satisfies(request_rec *r)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
						   &core_module);

    return conf->satisfy;
}

/* Should probably just get rid of this... the only code that cares is
 * part of the core anyway (and in fact, it isn't publicised to other
 * modules).
 */

char *ap_response_code_string(request_rec *r, int error_index)
{
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
						   &core_module); 

    if (conf->response_code_strings == NULL) {
	return NULL;
    }
    return conf->response_code_strings[error_index];
}


/* Code from Harald Hanche-Olsen <hanche@imf.unit.no> */
static apr_inline void do_double_reverse (conn_rec *conn)
{
    struct hostent *hptr;

    if (conn->double_reverse) {
	/* already done */
	return;
    }
    if (conn->remote_host == NULL || conn->remote_host[0] == '\0') {
	/* single reverse failed, so don't bother */
	conn->double_reverse = -1;
	return;
    }
    hptr = gethostbyname(conn->remote_host);   
    if (hptr) {          
	char **haddr;

	for (haddr = hptr->h_addr_list; *haddr; haddr++) {
	    if (((struct in_addr *)(*haddr))->s_addr
		== conn->remote_addr.sin_addr.s_addr) {
		conn->double_reverse = 1;
		return;
	    }
	}
    }
    conn->double_reverse = -1;
}

AP_DECLARE(const char *) ap_get_remote_host(conn_rec *conn, void *dir_config,
					    int type)
{
    int hostname_lookups;

    /* If we haven't checked the host name, and we want to */
    if (dir_config) {
	hostname_lookups =
	    ((core_dir_config *)ap_get_module_config(dir_config, &core_module))
		->hostname_lookups;
	if (hostname_lookups == HOSTNAME_LOOKUP_UNSET) {
	    hostname_lookups = HOSTNAME_LOOKUP_OFF;
	}
    }
    else {
	/* the default */
	hostname_lookups = HOSTNAME_LOOKUP_OFF;
    }

    if (type != REMOTE_NOLOOKUP
	&& conn->remote_host == NULL
	&& (type == REMOTE_DOUBLE_REV
	    || hostname_lookups != HOSTNAME_LOOKUP_OFF)) {
	if (apr_get_hostname(&conn->remote_host, APR_REMOTE, conn->client_socket)
            == APR_SUCCESS){
	    ap_str_tolower(conn->remote_host);
	   
	    if (hostname_lookups == HOSTNAME_LOOKUP_DOUBLE) {
		do_double_reverse(conn);
		if (conn->double_reverse != 1) {
		    conn->remote_host = NULL;
		}
	    }
	}
	/* if failed, set it to the NULL string to indicate error */
	if (conn->remote_host == NULL) {
	    conn->remote_host = "";
	}
    }
    if (type == REMOTE_DOUBLE_REV) {
	do_double_reverse(conn);
	if (conn->double_reverse == -1) {
	    return NULL;
	}
    }

/*
 * Return the desired information; either the remote DNS name, if found,
 * or either NULL (if the hostname was requested) or the IP address
 * (if any identifier was requested).
 */
    if (conn->remote_host != NULL && conn->remote_host[0] != '\0') {
	return conn->remote_host;
    }
    else {
	if (type == REMOTE_HOST || type == REMOTE_DOUBLE_REV) {
	    return NULL;
	}
	else {
	    return conn->remote_ip;
	}
    }
}

AP_DECLARE(const char *) ap_get_remote_logname(request_rec *r)
{
    core_dir_config *dir_conf;

    if (r->connection->remote_logname != NULL) {
	return r->connection->remote_logname;
    }

/* If we haven't checked the identity, and we want to */
    dir_conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
						       &core_module);

    if (dir_conf->do_rfc1413 & 1) {
	return ap_rfc1413(r->connection, r->server);
    }
    else {
	return NULL;
    }
}

/* There are two options regarding what the "name" of a server is.  The
 * "canonical" name as defined by ServerName and Port, or the "client's
 * name" as supplied by a possible Host: header or full URI.  We never
 * trust the port passed in the client's headers, we always use the
 * port of the actual socket.
 *
 * The DNS option to UseCanonicalName causes this routine to do a
 * reverse lookup on the local IP address of the connectiona and use
 * that for the ServerName. This makes its value more reliable while
 * at the same time allowing Demon's magic virtual hosting to work.
 * The assumption is that DNS lookups are sufficiently quick...
 * -- fanf 1998-10-03
 */
AP_DECLARE(const char *) ap_get_server_name(request_rec *r)
{
    conn_rec *conn = r->connection;
    core_dir_config *d;

    d = (core_dir_config *)ap_get_module_config(r->per_dir_config,
						&core_module);

    if (d->use_canonical_name == USE_CANONICAL_NAME_OFF) {
        return r->hostname ? r->hostname : r->server->server_hostname;
    }
    if (d->use_canonical_name == USE_CANONICAL_NAME_DNS) {
        if (conn->local_host == NULL) {
            if (apr_get_hostname(&conn->local_host, APR_LOCAL, conn->client_socket) != APR_SUCCESS)
                conn->local_host = apr_pstrdup(conn->pool, r->server->server_hostname);
            else
                ap_str_tolower(conn->local_host);
        }
	return conn->local_host;
    }
    /* default */
    return r->server->server_hostname;
}

AP_DECLARE(apr_port_t) ap_get_server_port(const request_rec *r)
{
    apr_port_t port;
    core_dir_config *d =
      (core_dir_config *)ap_get_module_config(r->per_dir_config, &core_module);
    
    port = r->server->port ? r->server->port : ap_default_port(r);

    if (d->use_canonical_name == USE_CANONICAL_NAME_OFF
	|| d->use_canonical_name == USE_CANONICAL_NAME_DNS) {
        if (r->hostname)
           apr_get_port(&port, APR_LOCAL, r->connection->client_socket);
    }
    /* default */
    return port;
}

AP_DECLARE(char *) ap_construct_url(apr_pool_t *p, const char *uri,
				    request_rec *r)
{
    unsigned port = ap_get_server_port(r);
    const char *host = ap_get_server_name(r);

    if (ap_is_default_port(port, r)) {
	return apr_pstrcat(p, ap_http_method(r), "://", host, uri, NULL);
    }
    return apr_psprintf(p, "%s://%s:%u%s", ap_http_method(r), host, port, uri);
}

AP_DECLARE(unsigned long) ap_get_limit_req_body(const request_rec *r)
{
    core_dir_config *d =
      (core_dir_config *)ap_get_module_config(r->per_dir_config, &core_module);
    
    return d->limit_req_body;
}

#ifdef WIN32
static apr_status_t get_win32_registry_default_value(apr_pool_t *p, HKEY hkey,
                                                     char* relativepath, 
                                                     char **value)
{
    HKEY hkeyOpen;
    DWORD type;
    DWORD size = 0;
    DWORD result = RegOpenKeyEx(hkey, relativepath, 0, 
                                KEY_QUERY_VALUE, &hkeyOpen);
    
    if (result != ERROR_SUCCESS) 
        return APR_FROM_OS_ERROR(result);

    /* Read to NULL buffer to determine value size */
    result = RegQueryValueEx(hkeyOpen, "", 0, &type, NULL, &size);
    
   if (result == ERROR_SUCCESS) {
        if ((size < 2) || (type != REG_SZ && type != REG_EXPAND_SZ)) {
            result = ERROR_INVALID_PARAMETER;
        }
        else {
            *value = apr_palloc(p, size);
            /* Read value based on size query above */
            result = RegQueryValueEx(hkeyOpen, "", 0, &type, *value, &size);
        }
    }

    /* TODO: This might look fine, but we need to provide some warning
     * somewhere that some environment variables may -not- be translated,
     * seeing as we may have chopped the environment table down somewhat.
     */
    if ((result == ERROR_SUCCESS) && (type == REG_EXPAND_SZ)) 
    {
        char *tmp = *value;
        size = ExpandEnvironmentStrings(tmp, *value, 0);
        if (size) {
            *value = apr_palloc(p, size);
            size = ExpandEnvironmentStrings(tmp, *value, size);
        }
    }

    RegCloseKey(hkeyOpen);
    return APR_FROM_OS_ERROR(result);
}

static char* get_interpreter_from_win32_registry(apr_pool_t *p, const char* ext,
                                                 char** arguments, int strict)
{
    char execcgi_path[] = "SHELL\\EXECCGI\\COMMAND";
    char execopen_path[] = "SHELL\\OPEN\\COMMAND";
    char typeName[MAX_PATH];
    int cmdOfName = FALSE;
    HKEY hkeyName;
    HKEY hkeyType;
    DWORD type;
    int size;
    int result;
    char *buffer;
    char *s;
    
    if (!ext)
        return NULL;
    /* 
     * Future optimization:
     * When the registry is successfully searched, store the strings for
     * interpreter and arguments in an ext hash to speed up subsequent look-ups
     */

    /* Open the key associated with the script filetype extension */
    result = RegOpenKeyEx(HKEY_CLASSES_ROOT, ext, 0, KEY_QUERY_VALUE, 
                          &hkeyType);

    if (result != ERROR_SUCCESS) 
        return NULL;

    /* Retrieve the name of the script filetype extension */
    size = sizeof(typeName);
    result = RegQueryValueEx(hkeyType, "", NULL, &type, typeName, &size);
    
    if (result == ERROR_SUCCESS && type == REG_SZ && typeName[0]) {
        /* Open the key associated with the script filetype extension */
        result = RegOpenKeyEx(HKEY_CLASSES_ROOT, typeName, 0, 
                              KEY_QUERY_VALUE, &hkeyName);

        if (result == ERROR_SUCCESS)
            cmdOfName = TRUE;
    }

    /* Open the key for the script command path by:
     * 
     *   1) the 'named' filetype key for ExecCGI/Command
     *   2) the extension's type key for ExecCGI/Command
     *
     * and if the strict arg is false, then continue trying:
     *
     *   3) the 'named' filetype key for Open/Command
     *   4) the extension's type key for Open/Command
     */

    if (cmdOfName) {
        result = get_win32_registry_default_value(p, hkeyName, 
                                                  execcgi_path, &buffer);
    }

    if (!cmdOfName || (result != ERROR_SUCCESS)) {
        result = get_win32_registry_default_value(p, hkeyType, 
                                                  execcgi_path, &buffer);
    }

    if (!strict && cmdOfName && (result != ERROR_SUCCESS)) {
        result = get_win32_registry_default_value(p, hkeyName, 
                                                  execopen_path, &buffer);
    }

    if (!strict && (result != ERROR_SUCCESS)) {
        result = get_win32_registry_default_value(p, hkeyType, 
                                                  execopen_path, &buffer);
    }

    if (cmdOfName)
        RegCloseKey(hkeyName);

    RegCloseKey(hkeyType);

    if (result != ERROR_SUCCESS)
        return NULL;

    /*
     * The canonical way shell command entries are entered in the Win32 
     * registry is as follows:
     *   shell [options] "%1" [args]
     * where
     *   shell - full path name to interpreter or shell to run.
     *           E.g., c:\usr\local\ntreskit\perl\bin\perl.exe
     *   options - optional switches
     *              E.g., \C
     *   "%1" - Place holder for file to run the shell against. 
     *          Typically quoted.
     *   options - additional arguments
     *              E.g., /silent
     *
     * If we find a %1 or a quoted %1, lop off the remainder to arguments. 
     */
    if (buffer && *buffer) {
        if ((s = strstr(buffer, "\"%1")))
        {
            *s = '\0';
            *arguments = s + 4;
        }
        else if ((s = strstr(buffer, "%1"))) 
        {
            *s = '\0';
            *arguments = buffer + 2;
        }
        else
            *arguments = strchr(buffer, '\0');
        while (**arguments && isspace(**arguments))
            ++*arguments;
    }

    return buffer;
}

AP_DECLARE (file_type_e) ap_get_win32_interpreter(const  request_rec *r, 
                                                  char** interpreter,
                                                  char** arguments)
{
    HANDLE hFile;
    DWORD nBytesRead;
    BOOLEAN bResult;
    char buffer[1024];
    core_dir_config *d;
    int i;
    file_type_e fileType = eFileTypeUNKNOWN;
    char *ext = NULL;
    char *exename = NULL;

    d = (core_dir_config *)ap_get_module_config(r->per_dir_config, 
                                                &core_module);

    /* Find the file extension */
    exename = strrchr(r->filename, '/');
    if (!exename) {
        exename = strrchr(r->filename, '\\');
    }
    if (!exename) {
        exename = r->filename;
    }
    else {
        exename++;
    }
    ext = strrchr(exename, '.');

    if (ext && (!strcasecmp(ext,".bat") || !strcasecmp(ext,".cmd"))) 
    {
        char *comspec = getenv("COMSPEC");
        if (comspec) {
            *interpreter = apr_pstrcat(r->pool, "\"", comspec, "\" /c ", NULL);
            return eFileTypeSCRIPT;
        }
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r->server,
         "Failed to start a '%s' file as a script." APR_EOL_STR
         "\tCOMSPEC variable is missing from the environment.", ext);
        return eFileTypeUNKNOWN;
    }

    /* If the file has an extension and it is not .com and not .exe and
     * we've been instructed to search the registry, then do it!
     */
    if (ext && strcasecmp(ext,".exe") && strcasecmp(ext,".com") &&
        (d->script_interpreter_source == INTERPRETER_SOURCE_REGISTRY ||
         d->script_interpreter_source == INTERPRETER_SOURCE_REGISTRY_STRICT)) {
         /* Check the registry */
        int strict = (d->script_interpreter_source 
                            == INTERPRETER_SOURCE_REGISTRY_STRICT);
        *interpreter = get_interpreter_from_win32_registry(r->pool, ext, 
                                                           arguments, strict);
        if (*interpreter)
            return eFileTypeSCRIPT;
        else if (d->script_interpreter_source == INTERPRETER_SOURCE_REGISTRY_STRICT) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r->server,
             "ScriptInterpreterSource config directive set to \"registry-strict\"." APR_EOL_STR
             "\tInterpreter not found for files of type '%s'.", ext);
             return eFileTypeUNKNOWN;
        }
        else
        {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r->server,
             "ScriptInterpreterSource config directive set to \"registry\"." APR_EOL_STR
             "\tInterpreter not found for files of type '%s', "
             "trying \"script\" method...", ext);
        }
    }        

    /* Need to peek into the file figure out what it really is... */
    hFile = CreateFile(r->filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return eFileTypeUNKNOWN;
    }
    bResult = ReadFile(hFile, (void*) &buffer, sizeof(buffer) - 1, 
                       &nBytesRead, NULL);
    if (!bResult || (nBytesRead == 0)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, GetLastError(), r,
                      "ReadFile(%s) failed", r->filename);
        CloseHandle(hFile);
        return eFileTypeUNKNOWN;
    }
    CloseHandle(hFile);
    buffer[nBytesRead] = '\0';

    /* Script or executable, that is the question... */
    if ((buffer[0] == '#') && (buffer[1] == '!')) {
        /* Assuming file is a script since it starts with a shebang */
        fileType = eFileTypeSCRIPT;
        for (i = 2; i < sizeof(buffer); i++) {
            if ((buffer[i] == '\r')
                || (buffer[i] == '\n')) {
                break;
            }
        }
        buffer[i] = '\0';
        for (i = 2; buffer[i] == ' ' ; ++i)
            ;
        *interpreter = apr_pstrdup(r->pool, buffer + i ); 
    }
    else {
        /* Not a script, is it an executable? */
        IMAGE_DOS_HEADER *hdr = (IMAGE_DOS_HEADER*)buffer;    
        if ((nBytesRead >= sizeof(IMAGE_DOS_HEADER)) && (hdr->e_magic == IMAGE_DOS_SIGNATURE)) {
            if (hdr->e_lfarlc < 0x40)
                fileType = eFileTypeEXE16;
            else
                fileType = eFileTypeEXE32;
        }
        else
            fileType = eFileTypeUNKNOWN;
    }

    return fileType;
}
#endif

/*****************************************************************
 *
 * Commands... this module handles almost all of the NCSA httpd.conf
 * commands, but most of the old srm.conf is in the the modules.
 */


/* returns a parent if it matches the given directive */
static const ap_directive_t * find_parent(const ap_directive_t *dirp,
					  const char *what)
{
    while (dirp->parent != NULL) {
	dirp = dirp->parent;
	/* ### it would be nice to have atom-ized directives */
	if (strcasecmp(dirp->directive, what) == 0)
	    return dirp;
    }
    return NULL;
}

AP_DECLARE(const char *) ap_check_cmd_context(cmd_parms *cmd,
					      unsigned forbidden)
{
    const char *gt = (cmd->cmd->name[0] == '<'
		      && cmd->cmd->name[strlen(cmd->cmd->name)-1] != '>')
                         ? ">" : "";
    const ap_directive_t *found;

    if ((forbidden & NOT_IN_VIRTUALHOST) && cmd->server->is_virtual) {
	return apr_pstrcat(cmd->pool, cmd->cmd->name, gt,
			  " cannot occur within <VirtualHost> section", NULL);
    }

    if ((forbidden & NOT_IN_LIMIT) && cmd->limited != -1) {
	return apr_pstrcat(cmd->pool, cmd->cmd->name, gt,
			  " cannot occur within <Limit> section", NULL);
    }

    if ((forbidden & NOT_IN_DIR_LOC_FILE) == NOT_IN_DIR_LOC_FILE
	&& cmd->path != NULL) {
	return apr_pstrcat(cmd->pool, cmd->cmd->name, gt,
			  " cannot occur within <Directory/Location/Files> "
			  "section", NULL);
    }
    
    if (((forbidden & NOT_IN_DIRECTORY)
	 && ((found = find_parent(cmd->directive, "<Directory"))
	     || (found = find_parent(cmd->directive, "<DirectoryMatch"))))
	|| ((forbidden & NOT_IN_LOCATION)
	    && ((found = find_parent(cmd->directive, "<Location"))
		|| (found = find_parent(cmd->directive, "<LocationMatch"))))
	|| ((forbidden & NOT_IN_FILES)
	    && ((found = find_parent(cmd->directive, "<Files"))
		|| (found = find_parent(cmd->directive, "<FilesMatch"))))) {
	return apr_pstrcat(cmd->pool, cmd->cmd->name, gt,
			  " cannot occur within ", found->directive,
			  "> section", NULL);
    }

    return NULL;
}

static const char *set_access_name(cmd_parms *cmd, void *dummy,
				   const char *arg)
{
    void *sconf = cmd->server->module_config;
    core_server_config *conf = ap_get_module_config(sconf, &core_module);

    const char *err = ap_check_cmd_context(cmd,
					   NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    conf->access_name = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

#ifdef GPROF
static const char *set_gprof_dir(cmd_parms *cmd, void *dummy, char *arg)
{
    void *sconf = cmd->server->module_config;
    core_server_config *conf = ap_get_module_config(sconf, &core_module);

    const char *err = ap_check_cmd_context(cmd,
					   NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    conf->gprof_dir = apr_pstrdup(cmd->pool, arg);
    return NULL;
}
#endif /*GPROF*/

static const char *set_add_default_charset(cmd_parms *cmd, 
					   void *d_, const char *arg)
{
    core_dir_config *d=d_;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }
    if (!strcasecmp(arg, "Off")) {
       d->add_default_charset = ADD_DEFAULT_CHARSET_OFF;
    }
    else if (!strcasecmp(arg, "On")) {
       d->add_default_charset = ADD_DEFAULT_CHARSET_ON;
       d->add_default_charset_name = DEFAULT_ADD_DEFAULT_CHARSET_NAME;
    }
    else {
       d->add_default_charset = ADD_DEFAULT_CHARSET_ON;
       d->add_default_charset_name = arg;
    }
    return NULL;
}

static const char *set_document_root(cmd_parms *cmd, void *dummy,
				     const char *arg)
{
    void *sconf = cmd->server->module_config;
    core_server_config *conf = ap_get_module_config(sconf, &core_module);
  
    const char *err = ap_check_cmd_context(cmd,
					   NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    arg = ap_os_canonical_filename(cmd->pool, arg);
    if (/* TODO: ap_configtestonly && ap_docrootcheck && */ !ap_is_directory(arg)) {
	if (cmd->server->is_virtual) {
	    ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                         "Warning: DocumentRoot [%s] does not exist",
		         arg);
	}
	else {
	    return "DocumentRoot must be a directory";
	}
    }
    
    conf->ap_document_root = arg;
    return NULL;
}

AP_DECLARE(void) ap_custom_response(request_rec *r, int status, char *string)
{
    core_dir_config *conf = 
	ap_get_module_config(r->per_dir_config, &core_module);
    int idx;

    if(conf->response_code_strings == NULL) {
        conf->response_code_strings = 
	    apr_pcalloc(r->pool,
		    sizeof(*conf->response_code_strings) * 
		    RESPONSE_CODES);
    }

    idx = ap_index_of_response(status);

    conf->response_code_strings[idx] = 
       ((ap_is_url(string) || (*string == '/')) && (*string != '"')) ? 
       apr_pstrdup(r->pool, string) : apr_pstrcat(r->pool, "\"", string, NULL);
}

static const char *set_error_document(cmd_parms *cmd, void *conf_,
				      const char *errno_str, const char *msg)
{
    core_dir_config *conf=conf_;
    int error_number, index_number, idx500;
    enum { MSG, LOCAL_PATH, REMOTE_PATH } what = MSG;
                
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    /* 1st parameter should be a 3 digit number, which we recognize;
     * convert it into an array index
     */
    error_number = atoi(errno_str);
    idx500 = ap_index_of_response(HTTP_INTERNAL_SERVER_ERROR);

    if (error_number == HTTP_INTERNAL_SERVER_ERROR) {
        index_number = idx500;
    }
    else if ((index_number = ap_index_of_response(error_number)) == idx500) {
        return apr_pstrcat(cmd->pool, "Unsupported HTTP response code ",
			  errno_str, NULL);
    }

    /* Heuristic to determine second argument. */
    if (ap_strchr_c(msg,' ')) 
	what = MSG;
    else if (msg[0] == '/')
	what = LOCAL_PATH;
    else if (ap_is_url(msg))
	what = REMOTE_PATH;
    else
        what = MSG;
   
    /* The entry should be ignored if it is a full URL for a 401 error */

    if (error_number == 401 && what == REMOTE_PATH) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, cmd->server,
		     "cannot use a full URL in a 401 ErrorDocument "
		     "directive --- ignoring!");
    }
    else { /* Store it... */
    	if (conf->response_code_strings == NULL) {
	    conf->response_code_strings =
		apr_pcalloc(cmd->pool,
			   sizeof(*conf->response_code_strings) * RESPONSE_CODES);
        }
	/* hack. Prefix a " if it is a msg; as that is what
	 * http_protocol.c relies on to distinguish between
	 * a msg and a (local) path.
	 */
        conf->response_code_strings[index_number] = (what == MSG) ?
		apr_pstrcat(cmd->pool, "\"",msg,NULL) :
		apr_pstrdup(cmd->pool, msg);
    }   

    return NULL;
}

static const char *set_override(cmd_parms *cmd, void *d_, const char *l)
{
    core_dir_config *d=d_;
    char *w;
  
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    d->override = OR_NONE;
    while (l[0]) {
        w = ap_getword_conf(cmd->pool, &l);
	if (!strcasecmp(w, "Limit")) {
	    d->override |= OR_LIMIT;
	}
	else if (!strcasecmp(w, "Options")) {
	    d->override |= OR_OPTIONS;
	}
	else if (!strcasecmp(w, "FileInfo")) {
            d->override |= OR_FILEINFO;
	}
	else if (!strcasecmp(w, "AuthConfig")) {
	    d->override |= OR_AUTHCFG;
	}
	else if (!strcasecmp(w, "Indexes")) {
            d->override |= OR_INDEXES;
	}
	else if (!strcasecmp(w, "None")) {
	    d->override = OR_NONE;
	}
	else if (!strcasecmp(w, "All")) {
	    d->override = OR_ALL;
	}
	else {
	    return apr_pstrcat(cmd->pool, "Illegal override option ", w, NULL);
	}
	d->override &= ~OR_UNSET;
    }

    return NULL;
}

static const char *set_options(cmd_parms *cmd, void *d_, const char *l)
{
    core_dir_config *d=d_;
    allow_options_t opt;
    int first = 1;
    char action;

    while (l[0]) {
        char *w = ap_getword_conf(cmd->pool, &l);
	action = '\0';

	if (*w == '+' || *w == '-') {
	    action = *(w++);
	}
	else if (first) {
  	    d->opts = OPT_NONE;
            first = 0;
        }
	    
	if (!strcasecmp(w, "Indexes")) {
	    opt = OPT_INDEXES;
	}
	else if (!strcasecmp(w, "Includes")) {
	    opt = OPT_INCLUDES;
	}
	else if (!strcasecmp(w, "IncludesNOEXEC")) {
	    opt = (OPT_INCLUDES | OPT_INCNOEXEC);
	}
	else if (!strcasecmp(w, "FollowSymLinks")) {
	    opt = OPT_SYM_LINKS;
	}
	else if (!strcasecmp(w, "SymLinksIfOwnerMatch")) {
	    opt = OPT_SYM_OWNER;
	}
	else if (!strcasecmp(w, "execCGI")) {
	    opt = OPT_EXECCGI;
	}
	else if (!strcasecmp(w, "MultiViews")) {
	    opt = OPT_MULTI;
	}
	else if (!strcasecmp(w, "RunScripts")) { /* AI backcompat. Yuck */
	    opt = OPT_MULTI|OPT_EXECCGI;
	}
	else if (!strcasecmp(w, "None")) {
	    opt = OPT_NONE;
	}
	else if (!strcasecmp(w, "All")) {
	    opt = OPT_ALL;
	}
	else {
	    return apr_pstrcat(cmd->pool, "Illegal option ", w, NULL);
	}

	/* we ensure the invariant (d->opts_add & d->opts_remove) == 0 */
	if (action == '-') {
	    d->opts_remove |= opt;
	    d->opts_add &= ~opt;
	    d->opts &= ~opt;
	}
	else if (action == '+') {
	    d->opts_add |= opt;
	    d->opts_remove &= ~opt;
	    d->opts |= opt;
	}
	else {
	    d->opts |= opt;
	}
    }

    return NULL;
}

static const char *satisfy(cmd_parms *cmd, void *c_, const char *arg)
{
    core_dir_config *c=c_;

    if (!strcasecmp(arg, "all")) {
        c->satisfy = SATISFY_ALL;
    }
    else if (!strcasecmp(arg, "any")) {
        c->satisfy = SATISFY_ANY;
    }
    else {
        return "Satisfy either 'any' or 'all'.";
    }
    return NULL;
}

static const char *require(cmd_parms *cmd, void *c_, const char *arg)
{
    require_line *r;
    core_dir_config *c=c_;

    if (!c->ap_requires) {
        c->ap_requires = apr_make_array(cmd->pool, 2, sizeof(require_line));
    }
    r = (require_line *)apr_push_array(c->ap_requires);
    r->requirement = apr_pstrdup(cmd->pool, arg);
    r->method_mask = cmd->limited;
    return NULL;
}

AP_CORE_DECLARE_NONSTD(const char *) ap_limit_section(cmd_parms *cmd, void *dummy,
						  const char *arg) {
    const char *limited_methods = ap_getword(cmd->pool, &arg, '>');
    void *tog = cmd->cmd->cmd_data;
    int limited = 0;
    const char *errmsg;
  
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    while (limited_methods[0]) {
        char *method = ap_getword_conf(cmd->pool, &limited_methods);
        int  methnum = ap_method_number_of(method);

        if (methnum == M_TRACE && !tog) {
            return "TRACE cannot be controlled by <Limit>";
        }
        else if (methnum == M_INVALID) {
	    char **xmethod;
	    register int i, j, k;

	    /*
	     * Deal with <Limit> by adding the method to the list.
	     */
	    if (!tog) {
		if (cmd->limited_xmethods == NULL) {
		    cmd->limited_xmethods = apr_make_array(cmd->pool, 2,
							   sizeof(char *));
		}
		xmethod = (char **) apr_push_array(cmd->limited_xmethods);
		*xmethod = apr_pstrdup(cmd->pool, method);
	    }
	    /*
	     * <LimitExcept>, so remove any/all occurrences of the method
	     * in the extension array.
	     */
	    else if ((cmd->limited_xmethods != NULL)
		     && (cmd->limited_xmethods->nelts != 0)) {
		xmethod = (char **) cmd->limited_xmethods->elts;
		for (i = 0; i < cmd->limited_xmethods->nelts; ) {
		    if (strcmp(xmethod[i], method) == 0) {
			for (j = i, k = i + 1;
			     k < cmd->limited_xmethods->nelts;
			     ++j, ++k) {
			    xmethod[j] = xmethod[k];
			}
			cmd->limited_xmethods->nelts--;
		    }
		}
	    }
        }
	limited |= (1 << methnum);
    }

    /* Killing two features with one function,
     * if (tog == NULL) <Limit>, else <LimitExcept>
     */
    cmd->limited = tog ? ~limited : limited;

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, cmd->context);

    cmd->limited = -1;

    return errmsg;
}

/* We use this in <DirectoryMatch> and <FilesMatch>, to ensure that 
 * people don't get bitten by wrong-cased regex matches
 */

#ifdef WIN32
#define USE_ICASE REG_ICASE
#else
#define USE_ICASE 0
#endif

/*
 * Report a missing-'>' syntax error.
 */
static char *unclosed_directive(cmd_parms *cmd)
{
    return apr_pstrcat(cmd->pool, cmd->cmd->name,
		      "> directive missing closing '>'", NULL);
}

static const char *dirsection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    core_dir_config *conf;
    void *new_dir_conf = ap_create_per_dir_config(cmd->pool);
    regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;

    const char *err = ap_check_cmd_context(cmd,
					   NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
	return unclosed_directive(cmd);
    }

    arg=apr_pstrndup(cmd->pool, arg, endp-arg);

    cmd->path = ap_getword_conf(cmd->pool, &arg);
    cmd->override = OR_ALL|ACCESS_CONF;

    if (thiscmd->cmd_data) { /* <DirectoryMatch> */
	r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
    else if (!strcmp(cmd->path, "~")) {
	cmd->path = ap_getword_conf(cmd->pool, &arg);
	r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
#if defined(HAVE_DRIVE_LETTERS) || defined(NETWARE)
    else if (strcmp(cmd->path, "/") == 0) {
        /* Treat 'default' path / as an inalienable root */
        cmd->path = apr_pstrdup(cmd->pool, cmd->path);
    }
#endif
#if defined(HAVE_UNC_PATHS)
    else if (strcmp(cmd->path, "//") == 0) {
        /* Treat UNC path // as an inalienable root */
        cmd->path = apr_pstrdup(cmd->pool, cmd->path);
    }
#endif
    else {
	/* Ensure that the pathname is canonical */
	cmd->path = ap_os_canonical_filename(cmd->pool, cmd->path);
    }

    /* initialize our config and fetch it */
    conf = (core_dir_config *)ap_set_config_vectors(cmd, new_dir_conf,
						    &core_module);

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_dir_conf);
    if (errmsg != NULL)
	return errmsg;

    conf->r = r;

    ap_add_per_dir_conf(cmd->server, new_dir_conf);

    if (*arg != '\0') {
	return apr_pstrcat(cmd->pool, "Multiple ", thiscmd->name,
			  "> arguments not (yet) supported.", NULL);
    }

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

static const char *urlsection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    core_dir_config *conf;
    regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;

    void *new_url_conf = ap_create_per_dir_config(cmd->pool);

    const char *err = ap_check_cmd_context(cmd,
					   NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
	return unclosed_directive(cmd);
    }

    arg=apr_pstrndup(cmd->pool, arg, endp-arg);

    cmd->path = ap_getword_conf(cmd->pool, &arg);
    cmd->override = OR_ALL|ACCESS_CONF;

    if (thiscmd->cmd_data) { /* <LocationMatch> */
	r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED);
    }
    else if (!strcmp(cmd->path, "~")) {
	cmd->path = ap_getword_conf(cmd->pool, &arg);
	r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED);
    }

    /* initialize our config and fetch it */
    conf = (core_dir_config *)ap_set_config_vectors(cmd, new_url_conf,
						    &core_module);

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_url_conf);
    if (errmsg != NULL)
	return errmsg;

    conf->d = apr_pstrdup(cmd->pool, cmd->path);	/* No mangling, please */
    conf->d_is_fnmatch = apr_is_fnmatch(conf->d) != 0;
    conf->r = r;

    ap_add_per_url_conf(cmd->server, new_url_conf);
    
    if (*arg != '\0') {
	return apr_pstrcat(cmd->pool, "Multiple ", thiscmd->name,
			  "> arguments not (yet) supported.", NULL);
    }

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

static const char *filesection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    core_dir_config *conf;
    regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;
    core_dir_config *c=mconfig;

    void *new_file_conf = ap_create_per_dir_config(cmd->pool);

    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT|NOT_IN_LOCATION);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
	return unclosed_directive(cmd);
    }

    arg=apr_pstrndup(cmd->pool, arg, endp-arg);

    cmd->path = ap_getword_conf(cmd->pool, &arg);
    /* Only if not an .htaccess file */
    if (!old_path) {
	cmd->override = OR_ALL|ACCESS_CONF;
    }

    if (thiscmd->cmd_data) { /* <FilesMatch> */
        r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
    else if (!strcmp(cmd->path, "~")) {
	cmd->path = ap_getword_conf(cmd->pool, &arg);
	r = ap_pregcomp(cmd->pool, cmd->path, REG_EXTENDED|USE_ICASE);
    }
    else {
	/* Ensure that the pathname is canonical */
	cmd->path = ap_os_canonical_filename(cmd->pool, cmd->path);
    }

    /* initialize our config and fetch it */
    conf = (core_dir_config *)ap_set_config_vectors(cmd, new_file_conf,
						    &core_module);

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_file_conf);
    if (errmsg != NULL)
	return errmsg;

    conf->d = cmd->path;
    conf->d_is_fnmatch = apr_is_fnmatch(conf->d) != 0;
    conf->r = r;

    ap_add_file_conf(c, new_file_conf);

    if (*arg != '\0') {
	return apr_pstrcat(cmd->pool, "Multiple ", thiscmd->name,
			  "> arguments not (yet) supported.", NULL);
    }

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

static const char *start_ifmod(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *endp = ap_strrchr_c(arg, '>');
    int not = (arg[0] == '!');
    module *found;

    if (endp == NULL) {
	return unclosed_directive(cmd);
    }

    arg=apr_pstrndup(cmd->pool, arg, endp-arg);

    if (not) {
        arg++;
    }

    found = ap_find_linked_module(arg);

    if ((!not && found) || (not && !found)) {
        ap_directive_t *parent = NULL;
        ap_directive_t *current = NULL;
        const char *retval;

        retval = ap_build_cont_config(cmd->pool, cmd->temp_pool, cmd, 
                                      &current, &parent, "<IfModule");
        *(ap_directive_t **)mconfig = current;
        return retval;
    }
    else { 
        *(ap_directive_t **)mconfig = NULL;
        return ap_soak_end_container(cmd, "<IfModule");
    }
}

AP_DECLARE(int) ap_exists_config_define(const char *name)
{
    char **defines;
    int i;

    defines = (char **)ap_server_config_defines->elts;
    for (i = 0; i < ap_server_config_defines->nelts; i++) {
        if (strcmp(defines[i], name) == 0) {
            return 1;
	}
    }
    return 0;
}

static const char *start_ifdefine(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *endp;
    int defined;
    int not = 0;

    endp = ap_strrchr_c(arg, '>');
    if (endp == NULL) {
	return unclosed_directive(cmd);
    }

    arg=apr_pstrndup(cmd->pool, arg, endp-arg);

    if (arg[0] == '!') {
        not = 1;
	arg++;
    }

    defined = ap_exists_config_define(arg);
    if ((!not && defined) || (not && !defined)) {
        ap_directive_t *parent = NULL;
        ap_directive_t *current = NULL;
        const char *retval;

        retval = ap_build_cont_config(cmd->pool, cmd->temp_pool, cmd, 
                                      &current, &parent, "<IfDefine");
        *(ap_directive_t **)dummy = current;
        return retval;
    }
    else { 
        *(ap_directive_t **)dummy = NULL;
        return ap_soak_end_container(cmd, "<IfDefine");
    }
}

/* httpd.conf commands... beginning with the <VirtualHost> business */

static const char *virtualhost_section(cmd_parms *cmd, void *dummy,
				       const char *arg)
{
    server_rec *main_server = cmd->server, *s;
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    apr_pool_t *p = cmd->pool;

    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
	return unclosed_directive(cmd);
    }

    arg=apr_pstrndup(cmd->pool, arg, endp-arg);
    
    /* FIXME: There's another feature waiting to happen here -- since you
	can now put multiple addresses/names on a single <VirtualHost>
	you might want to use it to group common definitions and then
	define other "subhosts" with their individual differences.  But
	personally I'd rather just do it with a macro preprocessor. -djg */
    if (main_server->is_virtual) {
	return "<VirtualHost> doesn't nest!";
    }
    
    errmsg = ap_init_virtual_host(p, arg, main_server, &s);
    if (errmsg) {
	return errmsg;
    }

    s->next = main_server->next;
    main_server->next = s;

    s->defn_name = cmd->directive->filename;
    s->defn_line_number = cmd->directive->line_num;

    cmd->server = s;

    errmsg = ap_walk_config(cmd->directive->first_child, cmd,
			    s->lookup_defaults);

    cmd->server = main_server;

    return errmsg;
}

static const char *set_server_alias(cmd_parms *cmd, void *dummy,
				    const char *arg)
{
    if (!cmd->server->names) {
	return "ServerAlias only used in <VirtualHost>";
    }
    while (*arg) {
	char **item, *name = ap_getword_conf(cmd->pool, &arg);
	if (ap_is_matchexp(name)) {
	    item = (char **)apr_push_array(cmd->server->wild_names);
	}
	else {
	    item = (char **)apr_push_array(cmd->server->names);
	}
	*item = name;
    }
    return NULL;
}

static const char *add_filter(cmd_parms *cmd, void *dummy, const char *arg)
{
    core_dir_config *conf = dummy;
    char **newfilter;
    
    newfilter = (char **)apr_push_array(conf->output_filters);
    *newfilter = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *add_input_filter(cmd_parms *cmd, void *dummy, const char *arg)
{
    core_dir_config *conf = dummy;
    char **newfilter;
    
    newfilter = (char **)apr_push_array(conf->input_filters);
    *newfilter = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *add_module_command(cmd_parms *cmd, void *dummy,
				      const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (!ap_add_named_module(arg)) {
	return apr_pstrcat(cmd->pool, "Cannot add module via name '", arg, 
			  "': not in list of loaded modules", NULL);
    }
    *(ap_directive_t **)dummy = NULL;
    return NULL;
}

static const char *clear_module_list_command(cmd_parms *cmd, void *dummy)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_clear_module_list();
    *(ap_directive_t **)dummy = NULL;
    return NULL;
}

static const char *set_server_string_slot(cmd_parms *cmd, void *dummy,
					  const char *arg)
{
    /* This one's pretty generic... */
  
    int offset = (int)(long)cmd->info;
    char *struct_ptr = (char *)cmd->server;
    
    const char *err = ap_check_cmd_context(cmd, 
					   NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    *(const char **)(struct_ptr + offset) = arg;
    return NULL;
}

static const char *server_port(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    int port;

    if (err != NULL) {
	return err;
    }
    port = atoi(arg);
    if (port <= 0 || port >= 65536) { /* 65536 == 1<<16 */
	return apr_pstrcat(cmd->temp_pool, "The port number \"", arg, 
			  "\" is outside the appropriate range "
			  "(i.e., 1..65535).", NULL);
    }
    cmd->server->port = port;
    return NULL;
}

static const char *set_signature_flag(cmd_parms *cmd, void *d_,
				      const char *arg)
{
    core_dir_config *d=d_;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "On") == 0) {
	d->server_signature = srv_sig_on;
    }
    else if (strcasecmp(arg, "Off") == 0) {
        d->server_signature = srv_sig_off;
    }
    else if (strcasecmp(arg, "EMail") == 0) {
	d->server_signature = srv_sig_withmail;
    }
    else {
	return "ServerSignature: use one of: off | on | email";
    }
    return NULL;
}

static const char *set_server_root(cmd_parms *cmd, void *dummy,
				   const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    arg = ap_os_canonical_filename(cmd->pool, arg);

    if (!ap_is_directory(arg)) {
        return "ServerRoot must be a valid directory";
    }
    ap_server_root = arg;
    return NULL;
}

static const char *set_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    cmd->server->timeout = atoi(arg);
    return NULL;
}

static const char *set_keep_alive_timeout(cmd_parms *cmd, void *dummy,
					  const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    cmd->server->keep_alive_timeout = atoi(arg);
    return NULL;
}

static const char *set_keep_alive(cmd_parms *cmd, void *dummy,
				  const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    /* We've changed it to On/Off, but used to use numbers
     * so we accept anything but "Off" or "0" as "On"
     */
    if (!strcasecmp(arg, "off") || !strcmp(arg, "0")) {
	cmd->server->keep_alive = 0;
    }
    else {
	cmd->server->keep_alive = 1;
    }
    return NULL;
}

static const char *set_keep_alive_max(cmd_parms *cmd, void *dummy,
				      const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    cmd->server->keep_alive_max = atoi(arg);
    return NULL;
}

static const char *set_idcheck(cmd_parms *cmd, void *d_, int arg) 
{
    core_dir_config *d=d_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    d->do_rfc1413 = arg != 0;
    return NULL;
}

static const char *set_hostname_lookups(cmd_parms *cmd, void *d_,
					const char *arg)
{
    core_dir_config *d=d_;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    if (!strcasecmp(arg, "on")) {
	d->hostname_lookups = HOSTNAME_LOOKUP_ON;
    }
    else if (!strcasecmp(arg, "off")) {
	d->hostname_lookups = HOSTNAME_LOOKUP_OFF;
    }
    else if (!strcasecmp(arg, "double")) {
	d->hostname_lookups = HOSTNAME_LOOKUP_DOUBLE;
    }
    else {
	return "parameter must be 'on', 'off', or 'double'";
    }
    return NULL;
}

static const char *set_serverpath(cmd_parms *cmd, void *dummy,
				  const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    cmd->server->path = arg;
    cmd->server->pathlen = strlen(arg);
    return NULL;
}

static const char *set_content_md5(cmd_parms *cmd, void *d_, int arg)
{
    core_dir_config *d=d_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    d->content_md5 = arg != 0;
    return NULL;
}

static const char *set_use_canonical_name(cmd_parms *cmd, void *d_,
					  const char *arg)
{
    core_dir_config *d=d_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
	return err;
    }

    if (strcasecmp(arg, "on") == 0) {
        d->use_canonical_name = USE_CANONICAL_NAME_ON;
    }
    else if (strcasecmp(arg, "off") == 0) {
        d->use_canonical_name = USE_CANONICAL_NAME_OFF;
    }
    else if (strcasecmp(arg, "dns") == 0) {
        d->use_canonical_name = USE_CANONICAL_NAME_DNS;
    }
    else {
        return "parameter must be 'on', 'off', or 'dns'";
    }
    return NULL;
}


static const char *include_config (cmd_parms *cmd, void *dummy,
				   const char *name)
{
    ap_directive_t *conftree = NULL;

    ap_process_resource_config(cmd->server,
	ap_server_root_relative(cmd->pool, name),
                               	 &conftree, cmd->pool, cmd->temp_pool);
    *(ap_directive_t **)dummy = conftree;
    return NULL;
}

static const char *set_loglevel(cmd_parms *cmd, void *dummy, const char *arg) 
{
    char *str;
    
    const char *err = ap_check_cmd_context(cmd,
					   NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    if ((str = ap_getword_conf(cmd->pool, &arg))) {
        if (!strcasecmp(str, "emerg")) {
	    cmd->server->loglevel = APLOG_EMERG;
	}
	else if (!strcasecmp(str, "alert")) {
	    cmd->server->loglevel = APLOG_ALERT;
	}
	else if (!strcasecmp(str, "crit")) {
	    cmd->server->loglevel = APLOG_CRIT;
	}
	else if (!strcasecmp(str, "error")) {
	    cmd->server->loglevel = APLOG_ERR;
	}
	else if (!strcasecmp(str, "warn")) {
	    cmd->server->loglevel = APLOG_WARNING;
	}
	else if (!strcasecmp(str, "notice")) {
	    cmd->server->loglevel = APLOG_NOTICE;
	}
	else if (!strcasecmp(str, "info")) {
	    cmd->server->loglevel = APLOG_INFO;
	}
	else if (!strcasecmp(str, "debug")) {
	    cmd->server->loglevel = APLOG_DEBUG;
	}
	else {
            return "LogLevel requires level keyword: one of "
	           "emerg/alert/crit/error/warn/notice/info/debug";
	}
    }
    else {
        return "LogLevel requires level keyword";
    }

    return NULL;
}

AP_DECLARE(const char *) ap_psignature(const char *prefix, request_rec *r)
{
    char sport[20];
    core_dir_config *conf;

    conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
						   &core_module);
    if ((conf->server_signature == srv_sig_off)
	    || (conf->server_signature == srv_sig_unset)) {
	return "";
    }

    apr_snprintf(sport, sizeof sport, "%u", (unsigned) ap_get_server_port(r));

    if (conf->server_signature == srv_sig_withmail) {
	return apr_pstrcat(r->pool, prefix, "<ADDRESS>" AP_SERVER_BASEVERSION
			  " Server at <A HREF=\"mailto:",
			  r->server->server_admin, "\">",
			  ap_get_server_name(r), "</A> Port ", sport,
			  "</ADDRESS>\n", NULL);
    }
    return apr_pstrcat(r->pool, prefix, "<ADDRESS>" AP_SERVER_BASEVERSION
		      " Server at ", ap_get_server_name(r), " Port ", sport,
		      "</ADDRESS>\n", NULL);
}

/*
 * Load an authorisation realm into our location configuration, applying the
 * usual rules that apply to realms.
 */
static const char *set_authname(cmd_parms *cmd, void *mconfig,
				const char *word1)
{
    core_dir_config *aconfig = (core_dir_config *)mconfig;

    aconfig->ap_auth_name = ap_escape_quotes(cmd->pool, word1);
    return NULL;
}

#ifdef _OSD_POSIX /* BS2000 Logon Passwd file */
static const char *set_bs2000_account(cmd_parms *cmd, void *dummy, char *name)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    return os_set_account(cmd->pool, name);
}
#endif /*_OSD_POSIX*/

/*
 * Handle a request to include the server's OS platform in the Server
 * response header field (the ServerTokens directive).  Unfortunately
 * this requires a new global in order to communicate the setting back to
 * http_main so it can insert the information in the right place in the
 * string.
 */

static char *server_version = NULL;
static int version_locked = 0; 

enum server_token_type {
    SrvTk_MIN,          /* eg: Apache/1.3.0 */
    SrvTk_OS,           /* eg: Apache/1.3.0 (UNIX) */
    SrvTk_FULL,         /* eg: Apache/1.3.0 (UNIX) PHP/3.0 FooBar/1.2b */
    SrvTk_PRODUCT_ONLY  /* eg: Apache */
};
static enum server_token_type ap_server_tokens = SrvTk_FULL;

static apr_status_t reset_version(void *dummy)
{
    version_locked = 0;
    ap_server_tokens = SrvTk_FULL;
    server_version = NULL;
    return APR_SUCCESS;
}

AP_DECLARE(const char *) ap_get_server_version(void)
{
    return (server_version ? server_version : AP_SERVER_BASEVERSION);
}

AP_DECLARE(void) ap_add_version_component(apr_pool_t *pconf, const char *component)
{
    if (! version_locked) {
        /*
         * If the version string is null, register our cleanup to reset the
         * pointer on pool destruction. We also know that, if NULL,
         * we are adding the original SERVER_BASEVERSION string.
         */
        if (server_version == NULL) {
            apr_register_cleanup(pconf, NULL, reset_version,
                                apr_null_cleanup);
            server_version = apr_pstrdup(pconf, component);
        }
        else {
            /*
             * Tack the given component identifier to the end of
             * the existing string.
             */
            server_version = apr_pstrcat(pconf, server_version, " ",
                                        component, NULL);
        }
    }
}

/*
 * This routine adds the real server base identity to the version string,
 * and then locks out changes until the next reconfig.
 */
static void ap_set_version(apr_pool_t *pconf)
{
    if (ap_server_tokens == SrvTk_PRODUCT_ONLY) {
        ap_add_version_component(pconf, AP_SERVER_BASEPRODUCT);
    }
    else if (ap_server_tokens == SrvTk_MIN) {
        ap_add_version_component(pconf, AP_SERVER_BASEVERSION);
    }
    else {
        ap_add_version_component(pconf, AP_SERVER_BASEVERSION " (" PLATFORM ")");
    }
    /*
     * Lock the server_version string if we're not displaying
     * the full set of tokens
     */
    if (ap_server_tokens != SrvTk_FULL) {
        version_locked++;
    }
}

static const char *set_serv_tokens(cmd_parms *cmd, void *dummy,
				   const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (!strcasecmp(arg, "OS")) {
        ap_server_tokens = SrvTk_OS;
    }
    else if (!strcasecmp(arg, "Min") || !strcasecmp(arg, "Minimal")) {
        ap_server_tokens = SrvTk_MIN;
    }
    else if (!strcasecmp(arg, "Prod") || !strcasecmp(arg, "ProductOnly")) {
        ap_server_tokens = SrvTk_PRODUCT_ONLY;
    }
    else {
        ap_server_tokens = SrvTk_FULL;
    }
    return NULL;
}

static const char *set_limit_req_line(cmd_parms *cmd, void *dummy,
				      const char *arg)
{
    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    int lim;

    if (err != NULL) {
        return err;
    }
    lim = atoi(arg);
    if (lim < 0) {
        return apr_pstrcat(cmd->temp_pool, "LimitRequestLine \"", arg, 
                          "\" must be a non-negative integer", NULL);
    }
    if (lim > DEFAULT_LIMIT_REQUEST_LINE) {
        return apr_psprintf(cmd->temp_pool, "LimitRequestLine \"%s\" "
                           "must not exceed the precompiled maximum of %d",
                           arg, DEFAULT_LIMIT_REQUEST_LINE);
    }
    cmd->server->limit_req_line = lim;
    return NULL;
}

static const char *set_limit_req_fieldsize(cmd_parms *cmd, void *dummy,
                                           const char *arg)
{
    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    int lim;

    if (err != NULL) {
        return err;
    }
    lim = atoi(arg);
    if (lim < 0) {
        return apr_pstrcat(cmd->temp_pool, "LimitRequestFieldsize \"", arg, 
                          "\" must be a non-negative integer (0 = no limit)",
                          NULL);
    }
    if (lim > DEFAULT_LIMIT_REQUEST_FIELDSIZE) {
        return apr_psprintf(cmd->temp_pool, "LimitRequestFieldsize \"%s\" "
                          "must not exceed the precompiled maximum of %d",
                           arg, DEFAULT_LIMIT_REQUEST_FIELDSIZE);
    }
    cmd->server->limit_req_fieldsize = lim;
    return NULL;
}

static const char *set_limit_req_fields(cmd_parms *cmd, void *dummy,
					const char *arg)
{
    const char *err = ap_check_cmd_context(cmd,
                                           NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    int lim;

    if (err != NULL) {
        return err;
    }
    lim = atoi(arg);
    if (lim < 0) {
        return apr_pstrcat(cmd->temp_pool, "LimitRequestFields \"", arg, 
                          "\" must be a non-negative integer (0 = no limit)",
                          NULL);
    }
    cmd->server->limit_req_fields = lim;
    return NULL;
}

static const char *set_limit_req_body(cmd_parms *cmd, void *conf_,
                                      const char *arg) 
{
    core_dir_config *conf=conf_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    /* WTF: If strtoul is not portable, then write a replacement.
     *      Instead we have an idiotic define in httpd.h that prevents
     *      it from being used even when it is available. Sheesh.
     */
    conf->limit_req_body = (unsigned long)strtol(arg, (char **)NULL, 10);
    return NULL;
}

static const char *set_limit_xml_req_body(cmd_parms *cmd, void *conf_,
                                          const char *arg) 
{
    core_dir_config *conf = conf_;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
    if (err != NULL) {
        return err;
    }

    conf->limit_xml_body = atol(arg);
    if (conf->limit_xml_body < 0)
        return "LimitXMLRequestBody requires a non-negative integer.";

    return NULL;
}

AP_DECLARE(size_t) ap_get_limit_xml_body(const request_rec *r)
{
    core_dir_config *conf;

    conf = ap_get_module_config(r->per_dir_config, &core_module);
    if (conf->limit_xml_body == AP_LIMIT_UNSET)
        return AP_DEFAULT_LIMIT_XML_BODY;
    return (size_t)conf->limit_xml_body;
}

#ifdef WIN32
static const char *set_interpreter_source(cmd_parms *cmd, core_dir_config *d,
                                                char *arg)
{
    if (!strcasecmp(arg, "registry")) {
        d->script_interpreter_source = INTERPRETER_SOURCE_REGISTRY;
    } else if (!strcasecmp(arg, "registry-strict")) {
        d->script_interpreter_source = INTERPRETER_SOURCE_REGISTRY_STRICT;
    } else if (!strcasecmp(arg, "script")) {
        d->script_interpreter_source = INTERPRETER_SOURCE_SHEBANG;
    } else {
        return apr_pstrcat(cmd->temp_pool, "ScriptInterpreterSource \"", arg, 
                          "\" must be \"registry\", \"registry-strict\" or "
                          "\"script\"", NULL);
    }
    return NULL;
}
#endif

#if !defined (RLIMIT_CPU) || !(defined (RLIMIT_DATA) || defined (RLIMIT_VMEM) || defined(RLIMIT_AS)) || !defined (RLIMIT_NPROC)
static const char *no_set_limit(cmd_parms *cmd, void *conf_,
                                const char *arg, const char *arg2)
{
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, cmd->server,
                "%s not supported on this platform", cmd->cmd->name);
    return NULL;
}
#endif

#ifdef RLIMIT_CPU
static const char *set_limit_cpu(cmd_parms *cmd, void *conf_,
                                 const char *arg, const char *arg2)
{
    core_dir_config *conf=conf_;

    unixd_set_rlimit(cmd, &conf->limit_cpu, arg, arg2, RLIMIT_CPU);
    return NULL;
}
#endif

#if defined (RLIMIT_DATA) || defined (RLIMIT_VMEM) || defined(RLIMIT_AS)
static const char *set_limit_mem(cmd_parms *cmd, void *conf_,
                                 const char *arg, const char * arg2)
{
    core_dir_config *conf=conf_;

#if defined(RLIMIT_AS)
    unixd_set_rlimit(cmd, &conf->limit_mem, arg, arg2 ,RLIMIT_AS);
#elif defined(RLIMIT_DATA)
    unixd_set_rlimit(cmd, &conf->limit_mem, arg, arg2, RLIMIT_DATA);
#elif defined(RLIMIT_VMEM)
    unixd_set_rlimit(cmd, &conf->limit_mem, arg, arg2, RLIMIT_VMEM);
#endif
    return NULL;
}
#endif

#ifdef RLIMIT_NPROC
static const char *set_limit_nproc(cmd_parms *cmd, void *conf_,
                                   const char *arg, const char * arg2)
{
    core_dir_config *conf=conf_;

    unixd_set_rlimit(cmd, &conf->limit_nproc, arg, arg2, RLIMIT_NPROC);
    return NULL;
}
#endif

static apr_status_t writev_it_all(apr_socket_t *s, struct iovec *vec, int nvec, 
                                  apr_size_t len, apr_size_t *nbytes)
{
    apr_size_t bytes_written = 0;
    apr_status_t rv;
    apr_size_t n = len;
    apr_size_t i = 0;

    *nbytes = 0;

    /* XXX handle checking for non-blocking socket */
    while (bytes_written != len) {
        rv = apr_sendv(s, vec + i, nvec - i, &n);
        bytes_written += n;
        if (rv != APR_SUCCESS)
            return rv;
        *nbytes += n;

        /* If the write did not complete, adjust the iovecs and issue
         * apr_sendv again
         */
        if (bytes_written < len) {
            /* Skip over the vectors that have already been written */
            apr_size_t cnt = vec[i].iov_len;
            while (n >= cnt && i + 1 < nvec) {
                i++;
                cnt += vec[i].iov_len;
            }
            if (n < cnt) {
                /* Handle partial write of vec i */
                vec[i].iov_base = (char *) vec[i].iov_base + 
                    (vec[i].iov_len - (cnt - n));
                vec[i].iov_len = cnt -n;
            }
        }
        n = len - bytes_written;
    }

    return APR_SUCCESS;
}
/*
 * send_the_file()
 * Sends the contents of file fd along with header/trailer bytes, if any,
 * to the network. send_the_file will return only when all the bytes have been
 * sent (i.e., it handles partial writes) or on a network error condition.
 */
static apr_status_t send_the_file(conn_rec *c, apr_file_t *fd, 
                                  apr_hdtr_t *hdtr, apr_off_t offset, 
                                  apr_size_t length, apr_size_t *nbytes) 
{
    apr_status_t rv = APR_SUCCESS;
    apr_int32_t togo;         /* Remaining number of bytes in the file to send */
    apr_size_t sendlen = 0;
    apr_size_t bytes_sent;
    apr_int32_t i;
    apr_off_t o;              /* Track the file offset for partial writes */
    char buffer[8192];

    *nbytes = 0;

    /* Send the headers 
     * writev_it_all handles partial writes.
     * XXX: optimization... if headers are less than MIN_WRITE_SIZE, copy 
     * them into buffer
     */
    if ( hdtr && hdtr->numheaders > 0 ) {
        for (i = 0; i < hdtr->numheaders; i++) {
            sendlen += hdtr->headers[i].iov_len;
        }
        rv = writev_it_all(c->client_socket, hdtr->headers, hdtr->numheaders,
                           sendlen, &bytes_sent);
        if (rv == APR_SUCCESS)
            *nbytes += bytes_sent;     /* track total bytes sent */
    }

    /* Seek the file to 'offset' */
    if (offset != 0 && rv == APR_SUCCESS) {
        rv = apr_seek(fd, APR_SET, &offset);
    }

    /* Send the file, making sure to handle partial writes */
    togo = length;
    while (rv == APR_SUCCESS && togo) {
        sendlen = togo > sizeof(buffer) ? sizeof(buffer) : togo;
        o = 0;
        rv = apr_read(fd, buffer, &sendlen);
        while (rv == APR_SUCCESS && sendlen) {
            bytes_sent = sendlen;
            rv = apr_send(c->client_socket, &buffer[o], &bytes_sent);
            if (rv == APR_SUCCESS) {
                sendlen -= bytes_sent; /* sendlen != bytes_sent ==> partial write */
                o += bytes_sent;       /* o is where we are in the buffer */
                *nbytes += bytes_sent;
                togo -= bytes_sent;    /* track how much of the file we've sent */
            }
        }
    }

    /* Send the trailers 
     * XXX: optimization... if it will fit, send this on the last send in the 
     * loop above
     */
    sendlen = 0;
    if ( rv == APR_SUCCESS && hdtr && hdtr->numtrailers > 0 ) {
        for (i = 0; i < hdtr->numtrailers; i++) {
            sendlen += hdtr->trailers[i].iov_len;
        }
        rv = writev_it_all(c->client_socket, hdtr->trailers, hdtr->numtrailers,
                           sendlen, &bytes_sent);
        if (rv == APR_SUCCESS)
            *nbytes += bytes_sent;
    }

    return rv;
}

/* Note --- ErrorDocument will now work from .htaccess files.  
 * The AllowOverride of Fileinfo allows webmasters to turn it off
 */

static const command_rec core_cmds[] = {

/* Old access config file commands */

AP_INIT_RAW_ARGS("<Directory", dirsection, NULL, RSRC_CONF, 
  "Container for directives affecting resources located in the specified "
  "directories"),
AP_INIT_RAW_ARGS("<Location", urlsection, NULL, RSRC_CONF,
  "Container for directives affecting resources accessed through the "
  "specified URL paths"),
AP_INIT_RAW_ARGS("<VirtualHost", virtualhost_section, NULL, RSRC_CONF,
  "Container to map directives to a particular virtual host, takes one or "
  "more host addresses"),
AP_INIT_RAW_ARGS("<Files", filesection, NULL, OR_ALL,
  "Container for directives affecting files matching specified patterns"),
AP_INIT_RAW_ARGS("<Limit", ap_limit_section, NULL, OR_ALL,
  "Container for authentication directives when accessed using specified HTTP "
  "methods"),
AP_INIT_RAW_ARGS("<LimitExcept", ap_limit_section, (void*)1, OR_ALL,
  "Container for authentication directives to be applied when any HTTP "
  "method other than those specified is used to access the resource"),
AP_INIT_TAKE1("<IfModule", start_ifmod, NULL, EXEC_ON_READ | OR_ALL,
  "Container for directives based on existance of specified modules"),
AP_INIT_TAKE1("<IfDefine", start_ifdefine, NULL, EXEC_ON_READ | OR_ALL,
  "Container for directives based on existance of command line defines"),
AP_INIT_RAW_ARGS("<DirectoryMatch", dirsection, (void*)1, RSRC_CONF,
  "Container for directives affecting resources located in the "
  "specified directories"),
AP_INIT_RAW_ARGS("<LocationMatch", urlsection, (void*)1, RSRC_CONF,
  "Container for directives affecting resources accessed through the "
  "specified URL paths"),
AP_INIT_RAW_ARGS("<FilesMatch", filesection, (void*)1, OR_ALL,
  "Container for directives affecting files matching specified patterns"),
AP_INIT_TAKE1("AuthType", ap_set_string_slot,
  (void*)XtOffsetOf(core_dir_config, ap_auth_type), OR_AUTHCFG, 
  "An HTTP authorization type (e.g., \"Basic\")"),
AP_INIT_TAKE1("AuthName", set_authname, NULL, OR_AUTHCFG,
  "The authentication realm (e.g. \"Members Only\")"),
AP_INIT_RAW_ARGS("Require", require, NULL, OR_AUTHCFG,
  "Selects which authenticated users or groups may access a protected space"),
AP_INIT_TAKE1("Satisfy", satisfy, NULL, OR_AUTHCFG,
  "access policy if both allow and require used ('all' or 'any')"),
#ifdef GPROF
AP_INIT_TAKE1("GprofDir", set_gprof_dir, NULL, RSRC_CONF,
  "Directory to plop gmon.out files"),
#endif
AP_INIT_TAKE1("AddDefaultCharset", set_add_default_charset, NULL, OR_FILEINFO, 
  "The name of the default charset to add to any Content-Type without one or 'Off' to disable"),

/* Old resource config file commands */
  
AP_INIT_RAW_ARGS("AccessFileName", set_access_name, NULL, RSRC_CONF,
  "Name(s) of per-directory config files (default: .htaccess)"),
AP_INIT_TAKE1("DocumentRoot", set_document_root, NULL, RSRC_CONF,
  "Root directory of the document tree"),
AP_INIT_TAKE2("ErrorDocument", set_error_document, NULL, OR_FILEINFO,
  "Change responses for HTTP errors"),
AP_INIT_RAW_ARGS("AllowOverride", set_override, NULL, ACCESS_CONF,
  "Controls what groups of directives can be configured by per-directory "
  "config files"),
AP_INIT_RAW_ARGS("Options", set_options, NULL, OR_OPTIONS,
  "Set a number of attributes for a given directory"),
AP_INIT_TAKE1("DefaultType", ap_set_string_slot,
  (void*)XtOffsetOf (core_dir_config, ap_default_type),
  OR_FILEINFO, "the default MIME type for untypable files"),

/* Old server config file commands */

AP_INIT_TAKE1("Port", server_port, NULL, RSRC_CONF, "A TCP port number"),
AP_INIT_TAKE1("HostnameLookups", set_hostname_lookups, NULL,
  ACCESS_CONF|RSRC_CONF,
  "\"on\" to enable, \"off\" to disable reverse DNS lookups, or \"double\" to "
  "enable double-reverse DNS lookups"),
AP_INIT_TAKE1("ServerAdmin", set_server_string_slot,
  (void *)XtOffsetOf (server_rec, server_admin), RSRC_CONF,
  "The email address of the server administrator"),
AP_INIT_TAKE1("ServerName", set_server_string_slot,
  (void *)XtOffsetOf (server_rec, server_hostname), RSRC_CONF,
  "The hostname of the server"),
AP_INIT_TAKE1("ServerSignature", set_signature_flag, NULL, OR_ALL,
  "En-/disable server signature (on|off|email)"),
AP_INIT_TAKE1("ServerRoot", set_server_root, NULL, RSRC_CONF,
  "Common directory of server-related files (logs, confs, etc.)"),
AP_INIT_TAKE1("ErrorLog", set_server_string_slot,
  (void *)XtOffsetOf (server_rec, error_fname), RSRC_CONF,
  "The filename of the error log"),
AP_INIT_RAW_ARGS("ServerAlias", set_server_alias, NULL, RSRC_CONF,
  "A name or names alternately used to access the server"),
AP_INIT_TAKE1("ServerPath", set_serverpath, NULL, RSRC_CONF,
  "The pathname the server can be reached at"),
AP_INIT_TAKE1("Timeout", set_timeout, NULL, RSRC_CONF,
  "Timeout duration (sec)"),
AP_INIT_TAKE1("KeepAliveTimeout", set_keep_alive_timeout, NULL, RSRC_CONF,
  "Keep-Alive timeout duration (sec)"),
AP_INIT_TAKE1("MaxKeepAliveRequests", set_keep_alive_max, NULL, RSRC_CONF,
  "Maximum number of Keep-Alive requests per connection, or 0 for infinite"),
AP_INIT_TAKE1("KeepAlive", set_keep_alive, NULL, RSRC_CONF,
  "Whether persistent connections should be On or Off"),
AP_INIT_FLAG("IdentityCheck", set_idcheck, NULL, RSRC_CONF|ACCESS_CONF,
  "Enable identd (RFC 1413) user lookups - SLOW"),
AP_INIT_FLAG("ContentDigest", set_content_md5, NULL, OR_OPTIONS,
  "whether or not to send a Content-MD5 header with each request"),
AP_INIT_TAKE1("UseCanonicalName", set_use_canonical_name, NULL,
  RSRC_CONF|ACCESS_CONF,
  "How to work out the ServerName : Port when constructing URLs"),
/* TODO: RlimitFoo should all be part of mod_cgi, not in the core */
AP_INIT_ITERATE("AddModule", add_module_command, NULL,
  RSRC_CONF, "The name of a module"),
AP_INIT_NO_ARGS("ClearModuleList", clear_module_list_command, NULL,
  RSRC_CONF, NULL),
/* TODO: ListenBacklog in MPM */
AP_INIT_TAKE1("Include", include_config, NULL,
  (RSRC_CONF | ACCESS_CONF | EXEC_ON_READ),
  "Name of the config file to be included"),
AP_INIT_TAKE1("LogLevel", set_loglevel, NULL, RSRC_CONF,
  "Level of verbosity in error logging"),
AP_INIT_TAKE1("NameVirtualHost", ap_set_name_virtual_host, NULL, RSRC_CONF,
  "A numeric IP address:port, or the name of a host"),
#ifdef _OSD_POSIX
AP_INIT_TAKE1("BS2000Account", set_bs2000_account, NULL, RSRC_CONF,
  "Name of server User's bs2000 logon account name"),
#endif
#ifdef WIN32
AP_INIT_TAKE1("ScriptInterpreterSource", set_interpreter_source, NULL,
  OR_FILEINFO,
  "Where to find interpreter to run Win32 scripts (Registry or script shebang line)"),
#endif
AP_INIT_TAKE1("ServerTokens", set_serv_tokens, NULL, RSRC_CONF,
  "Determine tokens displayed in the Server: header - Min(imal), OS or Full"),
AP_INIT_TAKE1("LimitRequestLine", set_limit_req_line, NULL, RSRC_CONF,
  "Limit on maximum size of an HTTP request line"),
AP_INIT_TAKE1("LimitRequestFieldsize", set_limit_req_fieldsize, NULL,
  RSRC_CONF,
  "Limit on maximum size of an HTTP request header field"),
AP_INIT_TAKE1("LimitRequestFields", set_limit_req_fields, NULL, RSRC_CONF,
  "Limit (0 = unlimited) on max number of header fields in a request message"),
AP_INIT_TAKE1("LimitRequestBody", set_limit_req_body,
  (void*)XtOffsetOf(core_dir_config, limit_req_body), OR_ALL,
  "Limit (in bytes) on maximum size of request message body"),
AP_INIT_TAKE1("LimitXMLRequestBody", set_limit_xml_req_body, NULL, OR_ALL,
              "Limit (in bytes) on maximum size of an XML-based request "
              "body"),

/* System Resource Controls */
#ifdef RLIMIT_CPU
AP_INIT_TAKE12("RLimitCPU", set_limit_cpu,
  (void*)XtOffsetOf(core_dir_config, limit_cpu),
  OR_ALL, "Soft/hard limits for max CPU usage in seconds"),
#else
AP_INIT_TAKE12("RLimitCPU", no_set_limit, NULL,
  OR_ALL, "Soft/hard limits for max CPU usage in seconds"),
#endif
#if defined (RLIMIT_DATA) || defined (RLIMIT_VMEM) || defined (RLIMIT_AS)
AP_INIT_TAKE12("RLimitMEM", set_limit_mem,
  (void*)XtOffsetOf(core_dir_config, limit_mem),
  OR_ALL, "Soft/hard limits for max memory usage per process"),
#else
AP_INIT_TAKE12("RLimitMEM", no_set_limit, NULL,
  OR_ALL, "Soft/hard limits for max memory usage per process"),
#endif
#ifdef RLIMIT_NPROC
AP_INIT_TAKE12("RLimitNPROC", set_limit_nproc,
  (void*)XtOffsetOf(core_dir_config, limit_nproc),
  OR_ALL, "soft/hard limits for max number of processes per uid"),
#else
AP_INIT_TAKE12("RLimitNPROC", no_set_limit, NULL,
   OR_ALL, "soft/hard limits for max number of processes per uid"),
#endif
/* XXX These should be allowable in .htaccess files, but currently it won't
 * play well with the Options stuff.  Until that is fixed, I would prefer
 * to leave it just in the conf file.  Other should feel free to disagree
 * with me.  Rbb.
 */
AP_INIT_ITERATE("AddOutputFilter", add_filter, NULL, ACCESS_CONF,
   "filters to be run"),
AP_INIT_ITERATE("AddInputFilter", add_input_filter, NULL, ACCESS_CONF,
   "filters to be run on the request body"),
{ NULL }
};

/*****************************************************************
 *
 * Core handlers for various phases of server operation...
 */

AP_DECLARE_NONSTD(int) ap_core_translate(request_rec *r)
{
    void *sconf = r->server->module_config;
    core_server_config *conf = ap_get_module_config(sconf, &core_module);
  
    if (r->proxyreq) {
        return HTTP_FORBIDDEN;
    }
    if ((r->uri[0] != '/') && strcmp(r->uri, "*")) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		     "Invalid URI in request %s", r->the_request);
	return HTTP_BAD_REQUEST;
    }
    
    if (r->server->path 
	&& !strncmp(r->uri, r->server->path, r->server->pathlen)
	&& (r->server->path[r->server->pathlen - 1] == '/'
	    || r->uri[r->server->pathlen] == '/'
	    || r->uri[r->server->pathlen] == '\0')) {
        r->filename = apr_pstrcat(r->pool, conf->ap_document_root,
				 (r->uri + r->server->pathlen), NULL);
    }
    else {
	/*
         * Make sure that we do not mess up the translation by adding two
         * /'s in a row.  This happens under windows when the document
         * root ends with a /
         */
        if ((conf->ap_document_root[strlen(conf->ap_document_root)-1] == '/')
	    && (*(r->uri) == '/')) {
	    r->filename = apr_pstrcat(r->pool, conf->ap_document_root, r->uri+1,
				     NULL);
	}
	else {
	    r->filename = apr_pstrcat(r->pool, conf->ap_document_root, r->uri,
				     NULL);
	}
    }

    return OK;
}

static int do_nothing(request_rec *r) { return OK; }

static int default_handler(request_rec *r)
{
    core_dir_config *d =
	    (core_dir_config *)ap_get_module_config(r->per_dir_config, &core_module);
    int errstatus;
    apr_file_t *fd = NULL;
    apr_status_t status;
    /* XXX if/when somebody writes a content-md5 filter we either need to
     *     remove this support or coordinate when to use the filter vs.
     *     when to use this code
     *     The current choice of when to compute the md5 here matches the 1.3
     *     support fairly closely (unlike 1.3, we don't handle computing md5
     *     when the charset is translated).
     */
    int bld_content_md5 = 
        (d->content_md5 & 1) && r->output_filters->frec->ftype != AP_FTYPE_CONTENT;

    ap_allow_methods(r, MERGE_ALLOW, "GET", "OPTIONS", "POST", NULL);

    if ((errstatus = ap_discard_request_body(r)) != OK) {
        return errstatus;
    }
    
    if (r->method_number == M_INVALID) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		    "Invalid method in request %s", r->the_request);
	return HTTP_NOT_IMPLEMENTED;
    }
    if (r->method_number == M_OPTIONS) {
        return ap_send_http_options(r);
    }
    if (r->method_number == M_PUT) {
        return HTTP_METHOD_NOT_ALLOWED;
    }
    if (r->finfo.protection == 0 || (r->path_info && *r->path_info)) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
		      "File does not exist: %s",r->path_info ?
		      apr_pstrcat(r->pool, r->filename, r->path_info, NULL)
		      : r->filename);
	return HTTP_NOT_FOUND;
    }
    
    if (r->method_number != M_GET && r->method_number != M_POST) {
        return HTTP_METHOD_NOT_ALLOWED;
    }
	
    if ((status = apr_open(&fd, r->filename, APR_READ | APR_BINARY, 0, r->connection->pool)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
		     "file permissions deny server access: %s", r->filename);
        return HTTP_FORBIDDEN;
    }
    ap_update_mtime(r, r->finfo.mtime);
    ap_set_last_modified(r);
    ap_set_etag(r);
    apr_table_setn(r->headers_out, "Accept-Ranges", "bytes");
    ap_set_content_length(r, r->finfo.size);
    if ((errstatus = ap_meets_conditions(r)) != OK) {
        apr_close(fd);
        return errstatus;
    }

    if (bld_content_md5) {
        apr_table_setn(r->headers_out, "Content-MD5",
                       ap_md5digest(r->pool, fd));
    }

    if (!r->header_only) {
        ap_bucket_brigade *bb = ap_brigade_create(r->pool);
        ap_bucket *e = ap_bucket_create_file(fd, 0, r->finfo.size);

        AP_BRIGADE_INSERT_HEAD(bb, e);
        e = ap_bucket_create_eos();
        AP_BRIGADE_INSERT_TAIL(bb, e);

        ap_pass_brigade(r->output_filters, bb);
    }

    return OK;
}

/*
 * coalesce_filter()
 * This is a simple filter to coalesce many small buckets into one large
 * bucket. 
 *
 * Note:
 * This implementation of coalesce_filter will only coalesce a single
 * contiguous string of coalesable buckets. It will not coalesce multiple
 * non-contiguous buckets. For example, if a brigade contains 10 small 
 * buckets followed by a large bucket (or a pipe or file bucket) followed 
 * by more small buckets, only the first 10 buckets will be coalesced.
 *
 * Yack... Using heap buckets which is really inefficient (multiple byte moves)
 * until we get heap bucket pooling in place.
 */
typedef struct COALESCE_FILTER_CTX {
    char *buf;           /* Start of buffer */
    char *cur;           /* Pointer to next location to write */
    apr_size_t cnt;     /* Number of bytes put in buf */
    apr_size_t avail;   /* Number of bytes available in the buf */
} coalesce_filter_ctx_t;
#define MIN_BUCKET_SIZE 200
static apr_status_t coalesce_filter(ap_filter_t *f, ap_bucket_brigade *b)
{
    apr_status_t rv;
    apr_pool_t *p = f->r->pool;
    ap_bucket *e, *insert_before = NULL, *destroy_me = NULL;
    coalesce_filter_ctx_t *ctx = f->ctx;
    int pass_the_brigade = 0, insert_first = 0;

    if (ctx == NULL) {
        f->ctx = ctx = apr_pcalloc(p, sizeof(coalesce_filter_ctx_t));
        ctx->avail = MIN_BYTES_TO_WRITE;
    }

    if (ctx->cnt) {
        insert_first = 1;
    }

    /* Iterate across the buckets, coalescing the small buckets into a 
     * single buffer 
     */
    AP_BRIGADE_FOREACH(e, b) {
        if (destroy_me) {
            ap_bucket_destroy(destroy_me);
            destroy_me = NULL;
        }
        if (AP_BUCKET_IS_EOS(e)  || AP_BUCKET_IS_FILE(e) ||
            AP_BUCKET_IS_PIPE(e) || AP_BUCKET_IS_FLUSH(e)) {
            pass_the_brigade = 1;
        }
        else {
            const char *str;
            apr_size_t n;
            rv = ap_bucket_read(e, &str, &n, AP_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                /* XXX: log error */
                return rv;
            }
            if ((n < MIN_BUCKET_SIZE) && (n < ctx->avail)) {
                /* Coalesce this bucket into the buffer */
                if (ctx->buf == NULL) {
                    ctx->buf = apr_palloc(p, MIN_BYTES_TO_WRITE);
                    ctx->cur = ctx->buf;
                    ctx->cnt = 0;
                }
                memcpy(ctx->cur, str, n);
                ctx->cnt += n;
                ctx->cur += n;
                ctx->avail -= n;
                /* If this is the first bucket to be coalesced, don't remove it 
                 * from the brigade. Save it as a marker for where to insert 
                 * ctx->buf into the brigade when we're done.
                 */
                if (insert_before || insert_first){
                    AP_BUCKET_REMOVE(e);
                    destroy_me = e;
                }
                else {
                    insert_before = e;
                }
            } 
            else if (insert_before || insert_first) {
                /* This bucket was not able to be coalesced because it either
                 * exceeds MIN_BUCKET_SIZE or its contents will not fit into
                 * buf. We're done...
                 */
                pass_the_brigade = 1;
                break;
            }
            else {
                /* If there is even a single bucket that cannot be coalesced, 
                 * then we must pass the brigade down to the next filter.
                 */
                pass_the_brigade = 1;
            }
        }
    }

    if (destroy_me) {
        ap_bucket_destroy(destroy_me);
        destroy_me = NULL;
    }

    if (pass_the_brigade) {
        /* Insert ctx->buf into the correct spot in the brigade */
        if (insert_first) {
            e = ap_bucket_create_heap(ctx->buf, ctx->cnt, 1, NULL);
            AP_BRIGADE_INSERT_HEAD(b, e);
        } 
        else if (insert_before) {
            e = ap_bucket_create_heap(ctx->buf, ctx->cnt, 1, NULL);
            AP_BUCKET_INSERT_BEFORE(e, insert_before);
            AP_BUCKET_REMOVE(insert_before);
            ap_bucket_destroy(insert_before);
            insert_before = NULL;
        }
        rv = ap_pass_brigade(f->next, b);
        if (rv != APR_SUCCESS) {
            /* XXX: Log the error */
            return rv;
        }
        /* Get ctx->buf ready for the next brigade */
        if (ctx) {
            ctx->cur = ctx->buf;
            ctx->cnt = 0;
            ctx->avail = MIN_BYTES_TO_WRITE;
        }
    }
    else {
        if (insert_before) {
            AP_BUCKET_REMOVE(insert_before);
            ap_bucket_destroy(insert_before);
        }
        /* The brigade should be empty now because all the buckets
         * were coalesced into the coalesce_filter buf
         */
    }

    return APR_SUCCESS;
}
/*
 * HTTP/1.1 chunked transfer encoding filter.
 */
static apr_status_t chunk_filter(ap_filter_t *f, ap_bucket_brigade *b)
{
#define ASCII_CRLF  "\015\012"
#define ASCII_ZERO  "\060"
    ap_bucket_brigade *more = NULL;
    ap_bucket *e;
    apr_status_t rv;

    for (more = NULL; b; b = more, more = NULL) {
	apr_off_t bytes = 0;
        ap_bucket *eos = NULL;
        char chunk_hdr[20]; /* enough space for the snprintf below */

	AP_BRIGADE_FOREACH(e, b) {
	    if (AP_BUCKET_IS_EOS(e)) {
		/* there shouldn't be anything after the eos */
		eos = e;
		break;
	    }
	    else if (e->length == -1) {
                /* unknown amount of data (e.g. a pipe) */
		const char *data;
		apr_size_t len;

		rv = ap_bucket_read(e, &data, &len, AP_BLOCK_READ);
		if (rv != APR_SUCCESS) {
		    return rv;
		}
		if (len > 0) {
		    /*
		     * There may be a new next bucket representing the
		     * rest of the data stream on which a read() may
		     * block so we pass down what we have so far.
		     */
		    bytes += len;
                    more = ap_brigade_split(b, AP_BUCKET_NEXT(e));
		    break;
		}
		else {
		    /* If there was nothing in this bucket then we can
		     * safely move on to the next one without pausing
		     * to pass down what we have counted up so far.
		     */
		    continue;
		}
	    }
	    else {
		bytes += e->length;
	    }
	}

	/*
	 * XXX: if there aren't very many bytes at this point it may
	 * be a good idea to set them aside and return for more,
	 * unless we haven't finished counting this brigade yet.
	 */

        /* if there are content bytes, then wrap them in a chunk */
        if (bytes > 0) {
            apr_size_t hdr_len;

            /*
             * Insert the chunk header, specifying the number of bytes in
             * the chunk.
             */
            /* XXX might be nice to have APR_OFF_T_FMT_HEX */
            hdr_len = apr_snprintf(chunk_hdr, sizeof(chunk_hdr),
                                   "%qx" CRLF, (apr_uint64_t)bytes);
            ap_xlate_proto_to_ascii(chunk_hdr, hdr_len);
            e = ap_bucket_create_transient(chunk_hdr, hdr_len);
            AP_BRIGADE_INSERT_HEAD(b, e);

            /*
             * Insert the end-of-chunk CRLF before the EOS bucket, or
             * appended to the brigade
             */
            e = ap_bucket_create_immortal(ASCII_CRLF, 2);
            if (eos != NULL) {
                AP_BUCKET_INSERT_BEFORE(eos, e);
            }
            else {
                AP_BRIGADE_INSERT_TAIL(b, e);
            }
        }

        /* RFC 2616, Section 3.6.1
         *
         * If there is an EOS bucket, then prefix it with:
         *   1) the last-chunk marker ("0" CRLF)
         *   2) the trailer
         *   3) the end-of-chunked body CRLF
         *
         * If there is no EOS bucket, then do nothing.
         *
         * XXX: it would be nice to combine this with the end-of-chunk
         * marker above, but this is a bit more straight-forward for
         * now.
         */
        if (eos != NULL) {
            /* XXX: (2) trailers ... does not yet exist */
            e = ap_bucket_create_immortal(ASCII_ZERO ASCII_CRLF /* <trailers> */ ASCII_CRLF, 5);
            AP_BUCKET_INSERT_BEFORE(eos, e);
        }

        /* pass the brigade to the next filter. */
	rv = ap_pass_brigade(f->next, b);
	if (rv != APR_SUCCESS || eos != NULL) {
	    return rv;
	}
    }

    return APR_SUCCESS;
}

static int core_input_filter(ap_filter_t *f, ap_bucket_brigade *b, ap_input_mode_t mode)
{
    ap_bucket *e;
    
    if (!f->ctx) {    /* If we haven't passed up the socket yet... */
        f->ctx = (void *)1;
        e = ap_bucket_create_socket(f->c->client_socket);
        AP_BRIGADE_INSERT_TAIL(b, e);
        return APR_SUCCESS;
    }
    else {            
        /* Either some code lost track of the socket
         * bucket or we already found out that the
         * client closed.
         */
        return APR_EOF;
    }
}

/* Default filter.  This filter should almost always be used.  Its only job
 * is to send the headers if they haven't already been sent, and then send
 * the actual data.
 */
typedef struct CORE_OUTPUT_FILTER_CTX {
    ap_bucket_brigade *b;
} core_output_filter_ctx_t;
#define MAX_IOVEC_TO_WRITE 16
static apr_status_t core_output_filter(ap_filter_t *f, ap_bucket_brigade *b)
{
    apr_status_t rv;
    ap_bucket_brigade *more = NULL;
    apr_size_t bytes_sent = 0, nbytes;
    ap_bucket *e;
    conn_rec *c = f->c;
    core_output_filter_ctx_t *ctx = f->ctx;

    apr_size_t nvec = 0;
    apr_size_t nvec_trailers= 0;
    struct iovec vec[MAX_IOVEC_TO_WRITE];
    struct iovec vec_trailers[MAX_IOVEC_TO_WRITE];

    apr_file_t *fd = NULL;
    apr_size_t flen = 0;
    apr_off_t foffset = 0;

    if (ctx == NULL) {
        f->ctx = ctx = apr_pcalloc(c->pool, sizeof(core_output_filter_ctx_t));
    }
    /* If we have a saved brigade, concatenate the new brigade to it */
    if (ctx->b) {
        AP_BRIGADE_CONCAT(ctx->b, b);
        b = ctx->b;
        ctx->b = NULL;
    }

    /* Iterate over the brigade collecting iovecs */
    while (b) {
        nbytes = 0; /* in case more points to another brigade */
        more = NULL;
        AP_BRIGADE_FOREACH(e, b) {
            if (AP_BUCKET_IS_EOS(e) || AP_BUCKET_IS_FLUSH(e)) {
                break;
            }
            else if (AP_BUCKET_IS_FILE(e)) {
                ap_bucket_file *a = e->data;
                /* Assume there is at most one AP_BUCKET_FILE in the brigade */
                fd = a->fd;
                flen = e->length;
                foffset = a->offset;
            }
            else {
                const char *str;
                apr_size_t n;
                rv = ap_bucket_read(e, &str, &n, AP_BLOCK_READ);
                if (n) {
                    nbytes += n;
                    if (!fd) {
                        vec[nvec].iov_base = (char*) str;
                        vec[nvec].iov_len = n;
                        nvec++;
                    }
                    else {
                        /* The bucket is a trailer to a file bucket */
                        vec_trailers[nvec_trailers].iov_base = (char*) str;
                        vec_trailers[nvec_trailers].iov_len = n;
                        nvec_trailers++;
                    }
                }
            }

            if ((nvec == MAX_IOVEC_TO_WRITE) || (nvec_trailers == MAX_IOVEC_TO_WRITE)) {
                /* Split the brigade and break */
                if (AP_BUCKET_NEXT(e) != AP_BRIGADE_SENTINEL(b)) {
                    more = ap_brigade_split(b, AP_BUCKET_NEXT(e));
                }
                break;
            }
        }

        /* Completed iterating over the brigades, now determine if we want to
         * buffer the brigade or send the brigade out on the network
         */
        if ((!fd && (!more) && (nbytes < MIN_BYTES_TO_WRITE) && !AP_BUCKET_IS_FLUSH(e))
            || (AP_BUCKET_IS_EOS(e) && c->keepalive)) {
            
            /* NEVER save an EOS in here.  If we are saving a brigade with an
             * EOS bucket, then we are doing keepalive connections, and we want
             * to process to second request fully.
             */
            if (AP_BUCKET_IS_EOS(e)) {
                AP_BUCKET_REMOVE(e);
                ap_bucket_destroy(e);
            }
            ap_save_brigade(f, &ctx->b, &b);
            return APR_SUCCESS;
        }
        if (fd) {
            apr_hdtr_t hdtr;
#if APR_HAS_SENDFILE
            apr_int32_t flags = 0;
#endif

            memset(&hdtr, '\0', sizeof(hdtr));
            if (nvec) {
                hdtr.numheaders = nvec;
                hdtr.headers = vec;
            }
            if (nvec_trailers) {
                hdtr.numtrailers = nvec_trailers;
                hdtr.trailers = vec_trailers;
            }
#if APR_HAS_SENDFILE
            if (!c->keepalive) {
                /* Prepare the socket to be reused */
                flags |= APR_SENDFILE_DISCONNECT_SOCKET;
            }
            nbytes = flen;
            rv = apr_sendfile(c->client_socket, 
                              fd,       /* The file to send */
                              &hdtr,    /* Header and trailer iovecs */
                              &foffset, /* Offset in file to begin sending from */
                              &nbytes,
                              flags);
            bytes_sent = nbytes;

            /* If apr_sendfile() returns APR_ENOTIMPL, call send_the_file() to
             * loop on apr_read/apr_send to send the file. Our Windows binary 
             * distributions (which work on Windows 9x/NT) are compiled on 
             * Windows NT. TransmitFile is not available on Windows 95/98 and
             * we discover this at runtime when apr_sendfile() returns 
             * APR_ENOTIMPL. Having apr_sendfile() return APR_ENOTIMPL seems
             * the cleanest way to handle this case.
             */
            if (rv == APR_ENOTIMPL) {
#endif

                rv = send_the_file(c, fd, &hdtr, foffset, flen, &bytes_sent);

#if APR_HAS_SENDFILE
            }
#endif
        }
        else {
            rv = writev_it_all(c->client_socket, 
                               vec, nvec, 
                               nbytes, &bytes_sent);
        }

        ap_brigade_destroy(b);
        if (rv != APR_SUCCESS) {
            /* XXX: log the error */
            if (more)
                ap_brigade_destroy(more);
            return rv;
        }
        nvec = 0;
        nvec_trailers = 0;

        b = more;
    }  /* end while () */

    return APR_SUCCESS;
}

static const handler_rec core_handlers[] = {
{ "*/*", default_handler },
{ "default-handler", default_handler },
{ NULL, NULL }
};

static void core_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    ap_init_bucket_types(pconf);
}

static void core_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ap_set_version(pconf);
}

static void core_open_logs(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    ap_open_logs(s, pconf);
}

static const char *core_method(const request_rec *r)
    { return "http"; }

static unsigned short core_port(const request_rec *r)
    { return DEFAULT_HTTP_PORT; }

static void core_insert_filter(request_rec *r)
{
    int i;
    core_dir_config *conf = (core_dir_config *)
                            ap_get_module_config(r->per_dir_config,
						   &core_module); 
    char **items = (char **)conf->output_filters->elts;

    for (i = 0; i < conf->output_filters->nelts; i++) {
        char *foobar = items[i];
        ap_add_output_filter(foobar, NULL, r, r->connection);
    }

    items = (char **)conf->input_filters->elts;
    for (i = 0; i < conf->input_filters->nelts; i++) {
        char *foobar = items[i];
        ap_add_input_filter(foobar, NULL, r, r->connection);
    }
}

static void register_hooks(void)
{
    ap_hook_pre_config(core_pre_config, NULL, NULL, AP_HOOK_REALLY_FIRST);
    ap_hook_post_config(core_post_config,NULL,NULL,AP_HOOK_REALLY_FIRST);
    ap_hook_translate_name(ap_core_translate,NULL,NULL,AP_HOOK_REALLY_LAST);
    ap_hook_pre_connection(ap_pre_http_connection,NULL,NULL,
			       AP_HOOK_REALLY_LAST);
    ap_hook_process_connection(ap_process_http_connection,NULL,NULL,
			       AP_HOOK_REALLY_LAST);
    ap_hook_http_method(core_method,NULL,NULL,AP_HOOK_REALLY_LAST);
    ap_hook_default_port(core_port,NULL,NULL,AP_HOOK_REALLY_LAST);
    ap_hook_open_logs(core_open_logs,NULL,NULL,AP_HOOK_MIDDLE);
    /* FIXME: I suspect we can eliminate the need for these - Ben */
    ap_hook_type_checker(do_nothing,NULL,NULL,AP_HOOK_REALLY_LAST);
    ap_hook_access_checker(do_nothing,NULL,NULL,AP_HOOK_REALLY_LAST);

    /* register the core's insert_filter hook and register core-provided
     * filters
     */
    ap_hook_insert_filter(core_insert_filter, NULL, NULL, AP_HOOK_MIDDLE);

    ap_register_input_filter("HTTP_IN", ap_http_filter, AP_FTYPE_CONNECTION);
    ap_register_input_filter("DECHUNK", ap_dechunk_filter, AP_FTYPE_TRANSCODE);
    ap_register_input_filter("CORE_IN", core_input_filter, AP_FTYPE_NETWORK);
    ap_register_output_filter("HTTP_HEADER", ap_http_header_filter, 
                              AP_FTYPE_HTTP_HEADER);
    ap_register_output_filter("CONTENT_LENGTH", ap_content_length_filter, 
                              AP_FTYPE_HTTP_HEADER);
    ap_register_output_filter("BYTERANGE", ap_byterange_filter, 
                              AP_FTYPE_HTTP_HEADER);
    ap_register_output_filter("CORE", core_output_filter, AP_FTYPE_NETWORK);
    ap_register_output_filter("SUBREQ_CORE", ap_sub_req_output_filter, 
                              AP_FTYPE_CONTENT);
    ap_register_output_filter("CHUNK", chunk_filter, AP_FTYPE_TRANSCODE);
    ap_register_output_filter("COALESCE", coalesce_filter, AP_FTYPE_CONTENT);
}

AP_DECLARE_DATA module core_module = {
    STANDARD20_MODULE_STUFF,
    create_core_dir_config,	/* create per-directory config structure */
    merge_core_dir_configs,	/* merge per-directory config structures */
    create_core_server_config,	/* create per-server config structure */
    merge_core_server_configs,	/* merge per-server config structures */
    core_cmds,			/* command apr_table_t */
    core_handlers,		/* handlers */
    register_hooks		/* register hooks */
};
