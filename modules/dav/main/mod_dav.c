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

/*
** DAV extension module for Apache 2.0.*
**
** This module is repository-independent. It depends on hooks provided by a
** repository implementation.
**
** APACHE ISSUES:
**   - within a DAV hierarchy, if an unknown method is used and we default
**     to Apache's implementation, it sends back an OPTIONS with the wrong
**     set of methods -- there is NO HOOK for us.
**     therefore: we need to manually handle the HTTP_METHOD_NOT_ALLOWED
**       and HTTP_NOT_IMPLEMENTED responses (not ap_send_error_response).
**   - process_mkcol_body() had to dup code from ap_setup_client_block().
**   - it would be nice to get status lines from Apache for arbitrary
**     status codes
**   - it would be nice to be able to extend Apache's set of response
**     codes so that it doesn't return 500 when an unknown code is placed
**     into r->status.
**   - http_vhost functions should apply "const" to their params
**
** DESIGN NOTES:
**   - For PROPFIND, we batch up the entire response in memory before
**     sending it. We may want to reorganize around sending the information
**     as we suck it in from the propdb. Alternatively, we should at least
**     generate a total Content-Length if we're going to buffer in memory
**     so that we can keep the connection open.
*/

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "apr_strings.h"

#include "mod_dav.h"


/* ### what is the best way to set this? */
#define DAV_DEFAULT_PROVIDER    "filesystem"

enum {
    DAV_ENABLED_UNSET = 0,
    DAV_ENABLED_OFF,
    DAV_ENABLED_ON
};

/* per-dir configuration */
typedef struct {
    const char *provider_name;
    const dav_provider *provider;
    const char *dir;
    int locktimeout;
    int allow_depthinfinity;

    apr_table_t *d_params;	/* per-directory DAV config parameters */

} dav_dir_conf;

/* per-server configuration */
typedef struct {
    int unused;

} dav_server_conf;

#define DAV_INHERIT_VALUE(parent, child, field) \
		((child)->field ? (child)->field : (parent)->field)


/* forward-declare for use in configuration lookup */
extern module DAV_DECLARE_DATA dav_module;

static void dav_init_handler(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                             server_rec *s)
{
    /* DBG0("dav_init_handler"); */

    ap_add_version_component(p, "DAV/2");
}

static void *dav_create_server_config(apr_pool_t *p, server_rec *s)
{
    dav_server_conf *newconf;

    newconf = (dav_server_conf *) apr_pcalloc(p, sizeof(*newconf));

    /* ### this isn't used at the moment... */

    return newconf;
}

static void *dav_merge_server_config(apr_pool_t *p, void *base, void *overrides)
{
#if 0
    dav_server_conf *child = overrides;
#endif
    dav_server_conf *newconf;

    newconf = (dav_server_conf *) apr_pcalloc(p, sizeof(*newconf));

    /* ### nothing to merge right now... */

    return newconf;
}

static void *dav_create_dir_config(apr_pool_t *p, char *dir)
{
    /* NOTE: dir==NULL creates the default per-dir config */

    dav_dir_conf *conf;

    conf = (dav_dir_conf *) apr_pcalloc(p, sizeof(*conf));

    /* clean up the directory to remove any trailing slash */
    if (dir != NULL) {
        char *d;
        apr_size_t l;

        d = apr_pstrdup(p, dir);
        l = strlen(d);
        if (l > 1 && d[l - 1] == '/')
            d[l - 1] = '\0';
        conf->dir = d;
    }

    conf->d_params = apr_make_table(p, 1);

    return conf;
}

static void *dav_merge_dir_config(apr_pool_t *p, void *base, void *overrides)
{
    dav_dir_conf *parent = base;
    dav_dir_conf *child = overrides;
    dav_dir_conf *newconf = (dav_dir_conf *) apr_pcalloc(p, sizeof(*newconf));

    /* DBG3("dav_merge_dir_config: new=%08lx  base=%08lx  overrides=%08lx",
       (long)newconf, (long)base, (long)overrides); */

    newconf->provider_name = DAV_INHERIT_VALUE(parent, child, provider_name);
    newconf->provider = DAV_INHERIT_VALUE(parent, child, provider);
    if (parent->provider_name != NULL) {
        if (child->provider_name == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, NULL,
                         "\"DAV Off\" cannot be used to turn off a subtree "
                         "of a DAV-enabled location.");
        }
        else if (strcasecmp(child->provider_name,
                            parent->provider_name) != 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, NULL,
                         "A subtree cannot specify a different DAV provider "
                         "than its parent.");
        }
    }

    newconf->locktimeout = DAV_INHERIT_VALUE(parent, child, locktimeout);
    newconf->dir = DAV_INHERIT_VALUE(parent, child, dir);
    newconf->allow_depthinfinity = DAV_INHERIT_VALUE(parent, child,
                                                     allow_depthinfinity);

    newconf->d_params = apr_copy_table(p, parent->d_params);
    apr_overlap_tables(newconf->d_params, child->d_params,
		      APR_OVERLAP_TABLES_SET);

    return newconf;
}

apr_table_t *dav_get_dir_params(const request_rec *r)
{
    dav_dir_conf *conf;

    conf = ap_get_module_config(r->per_dir_config, &dav_module);
    return conf->d_params;
}

static const dav_provider * dav_get_provider(request_rec *r)
{
    dav_dir_conf *conf;

    conf = ap_get_module_config(r->per_dir_config, &dav_module);
    /* assert: conf->provider_name != NULL
       (otherwise, DAV is disabled, and we wouldn't be here) */

    /* assert: conf->provider != NULL
       (checked when conf->provider_name is set) */
    return conf->provider;
}

const dav_hooks_locks *dav_get_lock_hooks(request_rec *r)
{
    return dav_get_provider(r)->locks;
}

const dav_hooks_propdb *dav_get_propdb_hooks(request_rec *r)
{
    return dav_get_provider(r)->propdb;
}

const dav_hooks_vsn *dav_get_vsn_hooks(request_rec *r)
{
    return dav_get_provider(r)->vsn;
}

const dav_hooks_binding *dav_get_binding_hooks(request_rec *r)
{
    return dav_get_provider(r)->binding;
}

/*
 * Command handler for the DAV directive, which is TAKE1.
 */
static const char *dav_cmd_dav(cmd_parms *cmd, void *config, const char *arg1)
{
    dav_dir_conf *conf = (dav_dir_conf *) config;

    if (strcasecmp(arg1, "on") == 0) {
	conf->provider_name = DAV_DEFAULT_PROVIDER;
    }
    else if (strcasecmp(arg1, "off") == 0) {
	conf->provider_name = NULL;
        conf->provider = NULL;
    }
    else {
        conf->provider_name = apr_pstrdup(cmd->pool, arg1);
    }

    if (conf->provider_name != NULL) {
        /* lookup and cache the actual provider now */
        conf->provider = dav_lookup_provider(conf->provider_name);

        if (conf->provider == NULL) {
            /* by the time they use it, the provider should be loaded and
               registered with us. */
            return apr_psprintf(cmd->pool,
                                "Unknown DAV provider: %s",
                                conf->provider_name);
        }
    }

    return NULL;
}

/*
 * Command handler for the DAVDepthInfinity directive, which is FLAG.
 */
static const char *dav_cmd_davdepthinfinity(cmd_parms *cmd, void *config,
                                            int arg)
{
    dav_dir_conf *conf = (dav_dir_conf *) config;

    if (arg)
	conf->allow_depthinfinity = DAV_ENABLED_ON;
    else
	conf->allow_depthinfinity = DAV_ENABLED_OFF;
    return NULL;
}

/*
 * Command handler for DAVMinTimeout directive, which is TAKE1
 */
static const char *dav_cmd_davmintimeout(cmd_parms *cmd, void *config,
                                         const char *arg1)
{
    dav_dir_conf *conf = (dav_dir_conf *) config;

    conf->locktimeout = atoi(arg1);
    if (conf->locktimeout < 0)
        return "DAVMinTimeout requires a non-negative integer.";

    return NULL;
}

/*
 * Command handler for DAVParam directive, which is TAKE2
 */
static const char *dav_cmd_davparam(cmd_parms *cmd, void *config,
                                    const char *arg1, const char *arg2)
{
    dav_dir_conf *conf = (dav_dir_conf *) config;

    apr_table_set(conf->d_params, arg1, arg2);

    return NULL;
}

/*
** dav_error_response()
**
** Send a nice response back to the user. In most cases, Apache doesn't
** allow us to provide details in the body about what happened. This
** function allows us to completely specify the response body.
*/
static int dav_error_response(request_rec *r, int status, const char *body)
{
    r->status = status;
    r->content_type = "text/html";

    /* since we're returning DONE, ensure the request body is consumed. */
    (void) ap_discard_request_body(r);

    /* begin the response now... */
    ap_send_http_header(r);

    ap_rvputs(r,
	      DAV_RESPONSE_BODY_1,
	      r->status_line,
	      DAV_RESPONSE_BODY_2,
	      &r->status_line[4],
	      DAV_RESPONSE_BODY_3,
	      NULL);

    ap_rputs(body, r);

    ap_rputs(ap_psignature("\n<P><HR>\n", r), r);
    ap_rputs(DAV_RESPONSE_BODY_4, r);

    /* the response has been sent. */
    /*
     * ### Use of DONE obviates logging..!
     */
    return DONE;
}

/*
** Apache's URI escaping does not replace '&' since that is a valid character
** in a URI (to form a query section). We must explicitly handle it so that
** we can embed the URI into an XML document.
*/
static const char *dav_xml_escape_uri(apr_pool_t *p, const char *uri)
{
    const char *e_uri = ap_escape_uri(p, uri);

    /* check the easy case... */
    if (ap_strchr_c(e_uri, '&') == NULL)
	return e_uri;

    /* more work needed... sigh. */

    /*
    ** Note: this is a teeny bit of overkill since we know there are no
    ** '<' or '>' characters, but who cares.
    */
    return ap_xml_quote_string(p, e_uri, 0);
}

static void dav_send_multistatus(request_rec *r, int status,
                                 dav_response *first,
				 apr_array_header_t *namespaces)
{
    /* Set the correct status and Content-Type */
    r->status = status;
    r->content_type = DAV_XML_CONTENT_TYPE;

    /* Send all of the headers now */
    ap_send_http_header(r);

    /* Send the actual multistatus response now... */
    ap_rputs(DAV_XML_HEADER DEBUG_CR
	     "<D:multistatus xmlns:D=\"DAV:\"", r);

    if (namespaces != NULL) {
	int i;

	for (i = namespaces->nelts; i--; ) {
	    ap_rprintf(r, " xmlns:ns%d=\"%s\"", i,
		       AP_XML_GET_URI_ITEM(namespaces, i));
	}
    }

    /* ap_rputc('>', r); */
    ap_rputs(">" DEBUG_CR, r);

    for (; first != NULL; first = first->next) {
	ap_text *t;

	if (first->propresult.xmlns == NULL) {
	    ap_rputs("<D:response>", r);
	}
	else {
	    ap_rputs("<D:response", r);
	    for (t = first->propresult.xmlns; t; t = t->next) {
		ap_rputs(t->text, r);
	    }
	    ap_rputc('>', r);
	}

	ap_rputs(DEBUG_CR "<D:href>", r);
	ap_rputs(dav_xml_escape_uri(r->pool, first->href), r);
	ap_rputs("</D:href>" DEBUG_CR, r);

	if (first->propresult.propstats == NULL) {
	    /* use the Status-Line text from Apache.  Note, this will
	     * default to 500 Internal Server Error if first->status
	     * is not a known (or valid) status code. */
	    ap_rprintf(r,
		       "<D:status>HTTP/1.1 %s</D:status>" DEBUG_CR, 
		       ap_get_status_line(first->status));
	}
	else {
	    /* assume this includes <propstat> and is quoted properly */
	    for (t = first->propresult.propstats; t; t = t->next) {
		ap_rputs(t->text, r);
	    }
	}

	if (first->desc != NULL) {
	    /*
	    ** We supply the description, so we know it doesn't have to
	    ** have any escaping/encoding applied to it.
	    */
	    ap_rputs("<D:responsedescription>", r);
	    ap_rputs(first->desc, r);
	    ap_rputs("</D:responsedescription>" DEBUG_CR, r);
	}

	ap_rputs("</D:response>" DEBUG_CR, r);
    }

    ap_rputs("</D:multistatus>" DEBUG_CR, r);
}

/*
** dav_log_err()
**
** Write error information to the log.
*/
static void dav_log_err(request_rec *r, dav_error *err, int level)
{
    dav_error *errscan;

    /* Log the errors */
    /* ### should have a directive to log the first or all */
    for (errscan = err; errscan != NULL; errscan = errscan->prev) {
	if (errscan->desc == NULL)
	    continue;
	if (errscan->save_errno != 0) {
	    errno = errscan->save_errno;
	    ap_log_rerror(APLOG_MARK, level, errno, r, "%s  [%d, #%d]",
			  errscan->desc, errscan->status, errscan->error_id);
	}
	else {
	    ap_log_rerror(APLOG_MARK, level | APLOG_NOERRNO, 0, r,
			  "%s  [%d, #%d]",
			  errscan->desc, errscan->status, errscan->error_id);
	}
    }
}

/*
** dav_handle_err()
**
** Handle the standard error processing. <err> must be non-NULL.
**
** <response> is set by the following:
**   - dav_validate_request()
**   - dav_add_lock()
**   - repos_hooks->remove_resource
**   - repos_hooks->move_resource
**   - repos_hooks->copy_resource
*/
static int dav_handle_err(request_rec *r, dav_error *err,
			  dav_response *response)
{
    /* log the errors */
    dav_log_err(r, err, APLOG_ERR);

    if (response == NULL) {
	/* our error messages are safe; tell Apache this */
	apr_table_setn(r->notes, "verbose-error-to", "*");
	return err->status;
    }

    /* since we're returning DONE, ensure the request body is consumed. */
    (void) ap_discard_request_body(r);

    /* send the multistatus and tell Apache the request/response is DONE. */
    dav_send_multistatus(r, err->status, response, NULL);
    return DONE;
}

/* handy function for return values of methods that (may) create things */
static int dav_created(request_rec *r, const char *locn, const char *what,
                       int replaced)
{
    const char *body;

    if (locn == NULL) {
	locn = r->uri;
    }

    /* did the target resource already exist? */
    if (replaced) {
	/* Apache will supply a default message */
	return HTTP_NO_CONTENT;
    }

    /* Per HTTP/1.1, S10.2.2: add a Location header to contain the
     * URI that was created. */

    /* Convert locn to an absolute URI, and return in Location header */
    apr_table_setn(r->headers_out, "Location", ap_construct_url(r->pool, locn, r));

    /* ### insert an ETag header? see HTTP/1.1 S10.2.2 */

    /* Apache doesn't allow us to set a variable body for HTTP_CREATED, so
     * we must manufacture the entire response. */
    body = apr_psprintf(r->pool, "%s %s has been created.",
                        what, ap_escape_html(r->pool, locn));
    return dav_error_response(r, HTTP_CREATED, body);
}

/* ### move to dav_util? */
int dav_get_depth(request_rec *r, int def_depth)
{
    const char *depth = apr_table_get(r->headers_in, "Depth");

    if (depth == NULL) {
	return def_depth;
    }
    if (strcasecmp(depth, "infinity") == 0) {
	return DAV_INFINITY;
    }
    else if (strcmp(depth, "0") == 0) {
	return 0;
    }
    else if (strcmp(depth, "1") == 0) {
	return 1;
    }

    /* The caller will return an HTTP_BAD_REQUEST. This will augment the
     * default message that Apache provides. */
    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		  "An invalid Depth header was specified.");
    return -1;
}

static int dav_get_overwrite(request_rec *r)
{
    const char *overwrite = apr_table_get(r->headers_in, "Overwrite");

    if (overwrite == NULL) {
	return 1;		/* default is "T" */
    }

    if ((*overwrite == 'F' || *overwrite == 'f') && overwrite[1] == '\0') {
	return 0;
    }
    if ((*overwrite == 'T' || *overwrite == 't') && overwrite[1] == '\0') {
	return 1;
    }

    /* The caller will return an HTTP_BAD_REQUEST. This will augment the
     * default message that Apache provides. */
    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		  "An invalid Overwrite header was specified.");
    return -1;
}

/* resolve a request URI to a resource descriptor.
 * If target_allowed != 0, then allow the request target to be overridden
 * by either a DAV:version or DAV:label-name element (passed as
 * the target argument), or any Target-Selector header in the request.
 */
static int dav_get_resource(request_rec *r, int target_allowed,
                            ap_xml_elem *target, dav_resource **res_p)
{
    void *data;
    dav_dir_conf *conf;
    const char *target_selector = NULL;
    int is_label = 0;
    int result;

    /* go look for the resource if it isn't already present */
    (void) apr_get_userdata(&data, DAV_KEY_RESOURCE, r->pool);
    if (data != NULL) {
        *res_p = data;
        return OK;
    }

    /* if the request target can be overridden, get any target selector */
    if (target_allowed) {
        if ((result = dav_get_target_selector(r, target,
                                              &target_selector,
                                              &is_label)) != OK)
	    return result;
    }

    conf = ap_get_module_config(r->per_dir_config, &dav_module);
    /* assert: conf->provider != NULL */

    /* resolve the resource */
    *res_p = (*conf->provider->repos->get_resource)(r, conf->dir,
                                                    target_selector, is_label);
    if (*res_p == NULL) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    (void) apr_set_userdata(*res_p, DAV_KEY_RESOURCE, apr_null_cleanup,
                            r->pool);

    /* ### hmm. this doesn't feel like the right place or thing to do */
    /* if there were any input headers requiring a Vary header in the response,
     * add it now */
    dav_add_vary_header(r, r, *res_p);

    return OK;
}

static dav_error * dav_open_lockdb(request_rec *r, int ro, dav_lockdb **lockdb)
{
    const dav_hooks_locks *hooks = DAV_GET_HOOKS_LOCKS(r);

    if (hooks == NULL) {
	*lockdb = NULL;
	return NULL;
    }

    /* open the thing lazily */
    return (*hooks->open_lockdb)(r, ro, 0, lockdb);
}

static int dav_parse_range(request_rec *r,
                           off_t *range_start, off_t *range_end)
{
    const char *range_c;
    char *range;
    char *dash;
    char *slash;

    range_c = apr_table_get(r->headers_in, "content-range");
    if (range_c == NULL)
        return 0;

    range = apr_pstrdup(r->pool, range_c);
    if (strncasecmp(range, "bytes ", 6) != 0
        || (dash = ap_strchr(range, '-')) == NULL
        || (slash = ap_strchr(range, '/')) == NULL) {
        /* malformed header. ignore it (per S14.16 of RFC2616) */
        return 0;
    }

    *dash = *slash = '\0';
    *range_start = atol(range + 6);
    *range_end = atol(dash + 1);
    if (*range_end < *range_start
        || (slash[1] != '*' && atol(slash + 1) <= *range_end)) {
        /* invalid range. ignore it (per S14.16 of RFC2616) */
        return 0;
    }

    /* we now have a valid range */
    return 1;
}

/* handle the GET method */
static int dav_method_get(request_rec *r)
{
    dav_resource *resource;
    int result;

    /* This method should only be called when the resource is not
     * visible to Apache. We will fetch the resource from the repository,
     * then create a subrequest for Apache to handle.
     */
    result = dav_get_resource(r, 1 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;
    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* Check resource type */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR &&
        resource->type != DAV_RESOURCE_TYPE_VERSION &&
        resource->type != DAV_RESOURCE_TYPE_WORKING)
    {
        return dav_error_response(r, HTTP_CONFLICT,
                                  "Cannot GET this type of resource.");
    }

    /* Cannot handle GET of a collection from a repository */
    if (resource->collection) {
	return dav_error_response(r, HTTP_CONFLICT, 
                                  "No default response to GET for a "
                                  "collection.");
    }

    /*
    ** We can use two different approaches for a GET.
    **
    ** 1) get_pathname will return a pathname to a file which should be
    **    sent to the client. If the repository provides this, then we
    **    use it.
    **
    **    This is the best alternative since it allows us to do a sub-
    **    request on the file, which gives the Apache framework a chance
    **    to deal with negotiation, MIME types, or whatever.
    **
    ** 2) open_stream and read_stream.
    */
    if (resource->hooks->get_pathname != NULL) {
	const char *pathname;
	void *fhandle;
	request_rec *new_req;
	
	/* Ask repository for copy of file */
	pathname = (*resource->hooks->get_pathname)(resource, &fhandle);
	if (pathname == NULL) {
	    return HTTP_NOT_FOUND;
	}

	/* Convert to canonical filename, so Apache detects component
	 * separators (on Windows, it only looks for '/', not '\')
	 */
	pathname = ap_os_case_canonical_filename(r->pool, pathname);

	/* Create a sub-request with the new filename */
	new_req = ap_sub_req_lookup_file(pathname, r, NULL);
	if (new_req == NULL) {
	    (*resource->hooks->free_file)(fhandle);
	    return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* This may be a HEAD request */
	new_req->header_only = r->header_only;

	/* ### this enables header generation */
	new_req->assbackwards = 0;

	/* Run the sub-request */
	result = ap_run_sub_req(new_req);
	ap_destroy_sub_req(new_req);

	/* Free resources */
	(*resource->hooks->free_file)(fhandle);

	return result;
    }
    else {
	dav_stream_mode mode;
	dav_stream *stream;
	dav_error *err;
	void *buffer;
        int has_range;
        off_t range_start;
        off_t range_end;

	/* set up the HTTP headers for the response */
	if ((err = (*resource->hooks->set_headers)(r, resource)) != NULL) {
	    err = dav_push_error(r->pool, err->status, 0,
				 "Unable to set up HTTP headers.",
				 err);
	    return dav_handle_err(r, err, NULL);
	}

        /* use plain READ mode unless we see a Content-Range */
	mode = DAV_MODE_READ;

        /* process the Content-Range header (if present) */
        has_range = dav_parse_range(r, &range_start, &range_end);
        if (has_range) {
            /* use a read mode which is seekable */
            mode = DAV_MODE_READ_SEEKABLE;

            /* prep the output */
            r->status = HTTP_PARTIAL_CONTENT;
            apr_table_setn(r->headers_out,
                          "Content-Range",
                          apr_psprintf(r->pool, "bytes %ld-%ld/*",
                                      range_start, range_end));
            ap_set_content_length(r, range_end - range_start + 1);
        }

        if (r->header_only) {
            ap_send_http_header(r);
            return DONE;
        }

	if ((err = (*resource->hooks->open_stream)(resource, mode,
                                                   &stream)) != NULL) {
	    /* ### assuming FORBIDDEN is probably not quite right... */
	    err = dav_push_error(r->pool, HTTP_FORBIDDEN, 0,
				 apr_psprintf(r->pool,
					     "Unable to GET contents for %s.",
					     ap_escape_html(r->pool, r->uri)),
				 err);
	    return dav_handle_err(r, err, NULL);
	}

        if (has_range
            && (err = (*resource->hooks->seek_stream)(stream,
                                                      range_start)) != NULL) {
            err = dav_push_error(r->pool, err->status, 0,
                                 "Could not seek to beginning of the "
                                 "specified Content-Range.", err);
            return dav_handle_err(r, err, NULL);
        }

	/* all set. send the headers now. */
	ap_send_http_header(r);

	buffer = apr_palloc(r->pool, DAV_READ_BLOCKSIZE);
	while (1) {
	    size_t amt;

            if (!has_range)
                amt = DAV_READ_BLOCKSIZE;
            else if ((range_end - range_start + 1) > DAV_READ_BLOCKSIZE)
                amt = DAV_READ_BLOCKSIZE;
            else {
                /* note: range_end - range_start is an ssize_t */
                amt = (size_t)(range_end - range_start + 1);
            }

	    if ((err = (*resource->hooks->read_stream)(stream, buffer,
                                                       &amt)) != NULL) {
		break;
	    }
	    if (amt == 0) {
		/* no more content */
		break;
	    }
	    if (ap_rwrite(buffer, amt, r) < 0) {
		/* ### what to do with this error? */
		break;
	    }

            if (has_range) {
                range_start += amt;
                if (range_start > range_end)
                    break;
            }
	}

	if (err != NULL)
	    return dav_handle_err(r, err, NULL);

        /*
        ** ### range_start should equal range_end+1. if it doesn't, then
        ** ### we did not send enough data to the client. the client will
        ** ### hang (and timeout) waiting for the data.
        **
        ** ### what to do? abort the connection?
        */
	return DONE;
    }

    /* NOTREACHED */
}

/* validate resource on POST, then pass it off to the default handler */
static int dav_method_post(request_rec *r)
{
    dav_resource *resource;
    dav_error *err;
    int result;

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 0 /*target_allowed*/, NULL, &resource);
    if (result != OK) {
        return result;
    }

    /* Note: depth == 0. Implies no need for a multistatus response. */
    if ((err = dav_validate_request(r, resource, 0, NULL, NULL,
				    DAV_VALIDATE_RESOURCE, NULL)) != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, NULL);
    }

    return DECLINED;
}

/* handle the PUT method */
static int dav_method_put(request_rec *r)
{
    dav_resource *resource;
    int resource_state;
    dav_auto_version_info av_info;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    const char *body;
    dav_error *err;
    dav_error *err2;
    int result;
    dav_stream_mode mode;
    dav_stream *stream;
    dav_response *multi_response;
    int has_range;
    off_t range_start;
    off_t range_end;

    if ((result = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK)) != OK) {
	return result;
    }

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 0 /*target_allowed*/, NULL, &resource);
    if (result != OK) {
        return result;
    }

    /* If not a file or collection resource, PUT not allowed */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR) {
        body = apr_psprintf(r->pool,
                           "Cannot create resource %s with PUT.",
                           ap_escape_html(r->pool, r->uri));
	return dav_error_response(r, HTTP_CONFLICT, body);
    }

    /* Cannot PUT a collection */
    if (resource->collection) {
	return dav_error_response(r, HTTP_CONFLICT,
                                  "Cannot PUT to a collection.");

    }

    resource_state = dav_get_resource_state(r, resource);

    /*
    ** Note: depth == 0 normally requires no multistatus response. However,
    ** if we pass DAV_VALIDATE_PARENT, then we could get an error on a URI
    ** other than the Request-URI, thereby requiring a multistatus.
    **
    ** If the resource does not exist (DAV_RESOURCE_NULL), then we must
    ** check the resource *and* its parent. If the resource exists or is
    ** a locknull resource, then we check only the resource.
    */
    if ((err = dav_validate_request(r, resource, 0, NULL, &multi_response,
				    resource_state == DAV_RESOURCE_NULL ?
				    DAV_VALIDATE_PARENT :
				    DAV_VALIDATE_RESOURCE, NULL)) != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, multi_response);
    }

    /* make sure the resource can be modified (if versioning repository) */
    if ((err = dav_ensure_resource_writable(r, resource,
					    0 /* not parent_only */,
					    &av_info)) != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, NULL);
    }

    /* truncate and rewrite the file unless we see a Content-Range */
    mode = DAV_MODE_WRITE_TRUNC;

    has_range = dav_parse_range(r, &range_start, &range_end);
    if (has_range) {
        mode = DAV_MODE_WRITE_SEEKABLE;
    }

    /* Create the new file in the repository */
    if ((err = (*resource->hooks->open_stream)(resource, mode,
                                               &stream)) != NULL) {
	/* ### assuming FORBIDDEN is probably not quite right... */
	err = dav_push_error(r->pool, HTTP_FORBIDDEN, 0,
			     apr_psprintf(r->pool,
					 "Unable to PUT new contents for %s.",
					 ap_escape_html(r->pool, r->uri)),
			     err);
    }

    if (err == NULL && has_range) {
        /* a range was provided. seek to the start */
        err = (*resource->hooks->seek_stream)(stream, range_start);
    }

    if (err == NULL) {
        if (ap_should_client_block(r)) {
	    char *buffer = apr_palloc(r->pool, DAV_READ_BLOCKSIZE);
	    long len;

            /*
            ** Once we start reading the request, then we must read the
            ** whole darn thing. ap_discard_request_body() won't do anything
            ** for a partially-read request.
            */

	    while ((len = ap_get_client_block(r, buffer,
					      DAV_READ_BLOCKSIZE)) > 0) {
		if (err == NULL) {
		    /* write whatever we read, until we see an error */
		    err = (*resource->hooks->write_stream)(stream,
                                                           buffer, len);
		}
	    }

            /*
            ** ### what happens if we read more/less than the amount
            ** ### specified in the Content-Range? eek...
            */

	    if (len == -1) {
		/*
		** Error reading request body. This has precedence over
		** prior errors.
		*/
		err = dav_new_error(r->pool, HTTP_BAD_REQUEST, 0,
				    "An error occurred while reading the "
				    "request body.");
	    }
        }

        err2 = (*resource->hooks->close_stream)(stream,
                                                err == NULL /* commit */);
	if (err2 != NULL && err == NULL) {
	    /* no error during the write, but we hit one at close. use it. */
	    err = err2;
	}
    }

    /*
    ** Ensure that we think the resource exists now.
    ** ### eek. if an error occurred during the write and we did not commit,
    ** ### then the resource might NOT exist (e.g. dav_fs_repos.c)
    */
    if (err == NULL) {
	resource->exists = 1;
    }

    /* restore modifiability of resources back to what they were */
    err2 = dav_revert_resource_writability(r, resource, err != NULL /* undo if error */,
                                           &av_info);

    /* check for errors now */
    if (err != NULL) {
	return dav_handle_err(r, err, NULL);
    }
    if (err2 != NULL) {
	/* just log a warning */
	err2 = dav_push_error(r->pool, err->status, 0,
			      "The PUT was successful, but there "
			      "was a problem reverting the writability of "
			      "the resource or its parent collection.",
			      err2);
	dav_log_err(r, err2, APLOG_WARNING);
    }

    /* ### place the Content-Type and Content-Language into the propdb */

    if (locks_hooks != NULL) {
        dav_lockdb *lockdb;

        if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
	    /* The file creation was successful, but the locking failed. */
	    err = dav_push_error(r->pool, err->status, 0,
				 "The file was PUT successfully, but there "
				 "was a problem opening the lock database "
				 "which prevents inheriting locks from the "
				 "parent resources.",
				 err);
	    return dav_handle_err(r, err, NULL);
        }

	/* notify lock system that we have created/replaced a resource */
	err = dav_notify_created(r, lockdb, resource, resource_state, 0);

	(*locks_hooks->close_lockdb)(lockdb);

	if (err != NULL) {
	    /* The file creation was successful, but the locking failed. */
	    err = dav_push_error(r->pool, err->status, 0,
				 "The file was PUT successfully, but there "
				 "was a problem updating its lock "
				 "information.",
				 err);
	    return dav_handle_err(r, err, NULL);
	}
    }

    /* NOTE: WebDAV spec, S8.7.1 states properties should be unaffected */

    /* return an appropriate response (HTTP_CREATED or HTTP_NO_CONTENT) */
    return dav_created(r, NULL, "Resource", resource_state == DAV_RESOURCE_EXISTS);
}

/* ### move this to dav_util? */
DAV_DECLARE(void) dav_add_response(dav_walk_resource *wres,
                                   int status, dav_get_props_result *propstats)
{
    dav_walker_ctx *ctx = wres->walk_ctx;
    dav_response *resp;

    /* just drop some data into an dav_response */
    resp = apr_pcalloc(ctx->w.pool, sizeof(*resp));
    resp->href = apr_pstrdup(ctx->w.pool, wres->resource->uri);
    resp->status = status;
    if (propstats) {
	resp->propresult = *propstats;
    }

    resp->next = wres->response;
    wres->response = resp;
}

/* handle the DELETE method */
static int dav_method_delete(request_rec *r)
{
    dav_resource *resource;
    dav_auto_version_info av_info;
    dav_error *err;
    dav_error *err2;
    dav_response *multi_response;
    int result;
    int depth;

    /* We don't use the request body right now, so torch it. */
    if ((result = ap_discard_request_body(r)) != OK) {
	return result;
    }

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 0 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;
    if (!resource->exists) {
        /* Apache will supply a default error for this. */
	return HTTP_NOT_FOUND;
    }

    /* 2518 says that depth must be infinity only for collections.
     * For non-collections, depth is ignored, unless it is an illegal value (1).
     */
    depth = dav_get_depth(r, DAV_INFINITY);

    if (resource->collection && depth != DAV_INFINITY) {
	/* This supplies additional information for the default message. */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "Depth must be \"infinity\" for DELETE of a collection.");
	return HTTP_BAD_REQUEST;
    }
    if (!resource->collection && depth == 1) {
	/* This supplies additional information for the default message. */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "Depth of \"1\" is not allowed for DELETE.");
	return HTTP_BAD_REQUEST;
    }

    /*
    ** If any resources fail the lock/If: conditions, then we must fail
    ** the delete. Each of the failing resources will be listed within
    ** a DAV:multistatus body, wrapped into a 424 response.
    **
    ** Note that a failure on the resource itself does not generate a
    ** multistatus response -- only internal members/collections.
    */
    if ((err = dav_validate_request(r, resource, depth, NULL,
				    &multi_response,
				    DAV_VALIDATE_PARENT
                                    | DAV_VALIDATE_USE_424, NULL)) != NULL) {
	err = dav_push_error(r->pool, err->status, 0,
			     apr_psprintf(r->pool,
					 "Could not DELETE %s due to a failed "
					 "precondition (e.g. locks).",
					 ap_escape_html(r->pool, r->uri)),
			     err);
	return dav_handle_err(r, err, multi_response);
    }

    /* ### RFC 2518 s. 8.10.5 says to remove _all_ locks, not just those
     *     locked by the token(s) in the if_header.
     */
    if ((result = dav_unlock(r, resource, NULL)) != OK) {
	return result;
    }

    /* if versioned resource, make sure parent is checked out */
    if ((err = dav_ensure_resource_writable(r, resource, 1 /* parent_only */,
					    &av_info)) != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, NULL);
    }

    /* try to remove the resource */
    err = (*resource->hooks->remove_resource)(resource, &multi_response);

    /* restore writability of parent back to what it was */
    err2 = dav_revert_resource_writability(r, NULL, err != NULL /* undo if error */,
					   &av_info);

    /* check for errors now */
    if (err != NULL) {
	err = dav_push_error(r->pool, err->status, 0,
			     apr_psprintf(r->pool,
					 "Could not DELETE %s.",
					 ap_escape_html(r->pool, r->uri)),
			     err);
	return dav_handle_err(r, err, multi_response);
    }
    if (err2 != NULL) {
	/* just log a warning */
	err = dav_push_error(r->pool, err2->status, 0,
			     "The DELETE was successful, but there "
			     "was a problem reverting the writability of "
			     "its parent collection.",
			     err2);
	dav_log_err(r, err, APLOG_WARNING);
    }

    /* ### HTTP_NO_CONTENT if no body, HTTP_OK if there is a body (some day) */

    /* Apache will supply a default error for this. */
    return HTTP_NO_CONTENT;
}

/* handle the OPTIONS method */
static int dav_method_options(request_rec *r)
{
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    const dav_hooks_binding *binding_hooks = DAV_GET_HOOKS_BINDING(r);
    dav_resource *resource;
    const char *options;
    const char *dav_level;
    const char *vsn_level;
    int result;
    apr_array_header_t *uri_ary;
    const char *uris;

    /* per HTTP/1.1 S9.2, we can discard this body */
    if ((result = ap_discard_request_body(r)) != OK) {
	return result;
    }

    /* no body */
    ap_set_content_length(r, 0);

    /* resolve the resource */
    result = dav_get_resource(r, 0 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;

    /* determine which providers are available */
    dav_level = "1";
    vsn_level = NULL;

    if (locks_hooks != NULL) {
        dav_level = "1,2";
    }

    if (vsn_hooks != NULL
        && (vsn_level = (*vsn_hooks->get_vsn_header)()) != NULL) {
	dav_level = apr_pstrcat(r->pool, dav_level, ",", vsn_level, NULL);
    }

    /* gather property set URIs from all the liveprop providers */
    uri_ary = apr_make_array(r->pool, 5, sizeof(const char *));
    ap_run_gather_propsets(uri_ary);
    uris = apr_array_pstrcat(r->pool, uri_ary, ',');
    if (*uris) {
        dav_level = apr_pstrcat(r->pool, dav_level, ",", uris, NULL);
    }

    /* this tells MSFT products to skip looking for FrontPage extensions */
    apr_table_setn(r->headers_out, "MS-Author-Via", "DAV");

    /*
    ** Three cases:  resource is null (3), is lock-null (7.4), or exists.
    **
    ** All cases support OPTIONS and LOCK.
    ** (Lock-) null resources also support MKCOL and PUT.
    ** Lock-null support PROPFIND and UNLOCK.
    ** Existing resources support lots of stuff.
    */

    /* ### take into account resource type */
    switch (dav_get_resource_state(r, resource))
    {
    case DAV_RESOURCE_EXISTS:
	/* resource exists */
	if (resource->collection) {
	    options = apr_pstrcat(r->pool,
		"OPTIONS, "
		"GET, HEAD, POST, DELETE, TRACE, "
		"PROPFIND, PROPPATCH, COPY, MOVE",
                locks_hooks != NULL ? ", LOCK, UNLOCK" : "",
                NULL);
	}
	else {
	    /* files also support PUT */
	    options = apr_pstrcat(r->pool,
		"OPTIONS, "
		"GET, HEAD, POST, DELETE, TRACE, "
		"PROPFIND, PROPPATCH, COPY, MOVE, PUT",
                locks_hooks != NULL ? ", LOCK, UNLOCK" : "",
                NULL);
	}
	break;

    case DAV_RESOURCE_LOCK_NULL:
	/* resource is lock-null. */
	options = apr_pstrcat(r->pool, "OPTIONS, MKCOL, PUT, PROPFIND",
                             locks_hooks != NULL ? ", LOCK, UNLOCK" : "",
                             NULL);
	break;

    case DAV_RESOURCE_NULL:
	/* resource is null. */
	options = apr_pstrcat(r->pool, "OPTIONS, MKCOL, PUT",
                             locks_hooks != NULL ? ", LOCK" : "",
                             NULL);
	break;

    default:
	/* ### internal error! */
	options = "OPTIONS";
	break;
    }

    /* If there is a versioning provider, add versioning options */
    if (vsn_hooks != NULL) {
        const char *vsn_options = NULL;

        if (!resource->exists) {
            int vsn_control = (*vsn_hooks->versionable)(resource);
            int mkworkspace = vsn_hooks->can_be_workspace != NULL
                              && (*vsn_hooks->can_be_workspace)(resource);

            if (vsn_control && mkworkspace) {
                vsn_options = ", VERSION-CONTROL, MKWORKSPACE";
            }
            else if (vsn_control)
                vsn_options = ", VERSION-CONTROL";
            else if (mkworkspace) {
                vsn_options = ", MKWORKSPACE";
            }
        }
        else if (!resource->versioned) {
            if ((*vsn_hooks->versionable)(resource)) {
                vsn_options = ", VERSION-CONTROL";
            }
        }
        else if (resource->working)
            vsn_options = ", CHECKIN, UNCHECKOUT";
        else if (vsn_hooks->add_label != NULL)
            vsn_options = ", CHECKOUT, LABEL";
        else
            vsn_options = ", CHECKOUT";

        if (vsn_options != NULL)
            options = apr_pstrcat(r->pool, options, vsn_options, NULL);
    }

    /* If there is a bindings provider, see if resource is bindable */
    if (binding_hooks != NULL) {
	dav_level = apr_pstrcat(r->pool, dav_level, ",bindings", NULL);
        if ((*binding_hooks->is_bindable)(resource))
            options = apr_pstrcat(r->pool, options, ", BIND", NULL);
    }

    apr_table_setn(r->headers_out, "Allow", options);
    apr_table_setn(r->headers_out, "DAV", dav_level);

    /* ### this will send a Content-Type. the default OPTIONS does not. */
    ap_send_http_header(r);

    /* ### the default (ap_send_http_options) returns OK, but I believe
     * ### that is because it is the default handler and nothing else
     * ### will run after the thing. */

    /* we've sent everything necessary to the client. */
    return DONE;
}

static void dav_cache_badprops(dav_walker_ctx *ctx)
{
    const ap_xml_elem *elem;
    ap_text_header hdr = { 0 };

    /* just return if we built the thing already */
    if (ctx->propstat_404 != NULL) {
	return;
    }

    ap_text_append(ctx->w.pool, &hdr,
		   "<D:propstat>" DEBUG_CR
		   "<D:prop>" DEBUG_CR);

    elem = dav_find_child(ctx->doc->root, "prop");
    for (elem = elem->first_child; elem; elem = elem->next) {
	ap_text_append(ctx->w.pool, &hdr,
                       ap_xml_empty_elem(ctx->w.pool, elem));
    }

    ap_text_append(ctx->w.pool, &hdr,
		   "</D:prop>" DEBUG_CR
		   "<D:status>HTTP/1.1 404 Not Found</D:status>" DEBUG_CR
		   "</D:propstat>" DEBUG_CR);

    ctx->propstat_404 = hdr.first;
}

static dav_error * dav_propfind_walker(dav_walk_resource *wres, int calltype)
{
    dav_walker_ctx *ctx = wres->walk_ctx;
    dav_error *err;
    dav_propdb *propdb;
    dav_get_props_result propstats = { 0 };

    /*
    ** Note: ctx->doc can only be NULL for DAV_PROPFIND_IS_ALLPROP. Since
    ** dav_get_allprops() does not need to do namespace translation,
    ** we're okay.
    **
    ** Note: we cast to lose the "const". The propdb won't try to change
    ** the resource, however, since we are opening readonly.
    */
    err = dav_open_propdb(ctx->r, ctx->w.lockdb,
			  (dav_resource *)wres->resource, 1,
			  ctx->doc ? ctx->doc->namespaces : NULL, &propdb);
    if (err != NULL) {
	/* ### do something with err! */

	if (ctx->propfind_type == DAV_PROPFIND_IS_PROP) {
	    dav_get_props_result badprops = { 0 };

	    /* some props were expected on this collection/resource */
	    dav_cache_badprops(ctx);
	    badprops.propstats = ctx->propstat_404;
	    dav_add_response(wres, 0, &badprops);
	}
	else {
	    /* no props on this collection/resource */
	    dav_add_response(wres, HTTP_OK, NULL);
	}
	return NULL;
    }
    /* ### what to do about closing the propdb on server failure? */

    if (ctx->propfind_type == DAV_PROPFIND_IS_PROP) {
	propstats = dav_get_props(propdb, ctx->doc);
    }
    else {
	propstats = dav_get_allprops(propdb,
			     ctx->propfind_type == DAV_PROPFIND_IS_ALLPROP);
    }
    dav_close_propdb(propdb);

    dav_add_response(wres, 0, &propstats);

    return NULL;
}

/* handle the PROPFIND method */
static int dav_method_propfind(request_rec *r)
{
    dav_resource *resource;
    int depth;
    dav_error *err;
    int result;
    ap_xml_doc *doc;
    const ap_xml_elem *child;
    dav_walker_ctx ctx = { { 0 } };
    dav_response *multi_status;

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 1 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;

    if (dav_get_resource_state(r, resource) == DAV_RESOURCE_NULL) {
	/* Apache will supply a default error for this. */
	return HTTP_NOT_FOUND;
    }

    if ((depth = dav_get_depth(r, DAV_INFINITY)) < 0) {
	/* dav_get_depth() supplies additional information for the
	 * default message. */
	return HTTP_BAD_REQUEST;
    }

    if (depth == DAV_INFINITY) {
	dav_dir_conf *conf;
	conf = (dav_dir_conf *) ap_get_module_config(r->per_dir_config,
						     &dav_module);
        /* default is to DISALLOW these requests */
	if (conf->allow_depthinfinity != DAV_ENABLED_ON) {
            return dav_error_response(r, HTTP_FORBIDDEN,
                                      apr_psprintf(r->pool,
                                                  "PROPFIND requests with a "
                                                  "Depth of \"infinity\" are "
                                                  "not allowed for %s.",
                                                  ap_escape_html(r->pool,
                                                                 r->uri)));
	}
    }

    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
	return result;
    }
    /* note: doc == NULL if no request body */

    if (doc && !dav_validate_root(doc, "propfind")) {
	/* This supplies additional information for the default message. */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "The \"propfind\" element was not found.");
	return HTTP_BAD_REQUEST;
    }

    /* ### validate that only one of these three elements is present */

    if (doc == NULL
	|| (child = dav_find_child(doc->root, "allprop")) != NULL) {
	/* note: no request body implies allprop */
	ctx.propfind_type = DAV_PROPFIND_IS_ALLPROP;
    }
    else if ((child = dav_find_child(doc->root, "propname")) != NULL) {
	ctx.propfind_type = DAV_PROPFIND_IS_PROPNAME;
    }
    else if ((child = dav_find_child(doc->root, "prop")) != NULL) {
	ctx.propfind_type = DAV_PROPFIND_IS_PROP;
    }
    else {
	/* "propfind" element must have one of the above three children */

	/* This supplies additional information for the default message. */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "The \"propfind\" element does not contain one of "
		      "the required child elements (the specific command).");
	return HTTP_BAD_REQUEST;
    }

    ctx.w.walk_type = DAV_WALKTYPE_NORMAL | DAV_WALKTYPE_AUTH;
    ctx.w.func = dav_propfind_walker;
    ctx.w.walk_ctx = &ctx;
    ctx.w.pool = r->pool;
    ctx.w.root = resource;

    ctx.doc = doc;
    ctx.r = r;

    /* ### should open read-only */
    if ((err = dav_open_lockdb(r, 0, &ctx.w.lockdb)) != NULL) {
	err = dav_push_error(r->pool, err->status, 0,
			     "The lock database could not be opened, "
			     "preventing access to the various lock "
			     "properties for the PROPFIND.",
			     err);
	return dav_handle_err(r, err, NULL);
    }
    if (ctx.w.lockdb != NULL) {
	/* if we have a lock database, then we can walk locknull resources */
	ctx.w.walk_type |= DAV_WALKTYPE_LOCKNULL;
    }

    err = (*resource->hooks->walk)(&ctx.w, depth, &multi_status);

    if (ctx.w.lockdb != NULL) {
	(*ctx.w.lockdb->hooks->close_lockdb)(ctx.w.lockdb);
    }

    if (err != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, NULL);
    }

    /* return a 207 (Multi-Status) response now. */

    /* if a 404 was generated for an HREF, then we need to spit out the
     * doc's namespaces for use by the 404. Note that <response> elements
     * will override these ns0, ns1, etc, but NOT within the <response>
     * scope for the badprops. */
    /* NOTE: propstat_404 != NULL implies doc != NULL */
    if (ctx.propstat_404 != NULL) {
	dav_send_multistatus(r, HTTP_MULTI_STATUS, multi_status,
                             doc->namespaces);
    }
    else {
	dav_send_multistatus(r, HTTP_MULTI_STATUS, multi_status, NULL);
    }

    /* the response has been sent. */
    return DONE;
}

static ap_text * dav_failed_proppatch(apr_pool_t *p,
                                       apr_array_header_t *prop_ctx)
{
    ap_text_header hdr = { 0 };
    int i = prop_ctx->nelts;
    dav_prop_ctx *ctx = (dav_prop_ctx *)prop_ctx->elts;
    dav_error *err424_set = NULL;
    dav_error *err424_delete = NULL;
    const char *s;

    /* ### might be nice to sort by status code and description */

    for ( ; i-- > 0; ++ctx ) {
	ap_text_append(p, &hdr,
		       "<D:propstat>" DEBUG_CR
		       "<D:prop>");
	ap_text_append(p, &hdr, ap_xml_empty_elem(p, ctx->prop));
	ap_text_append(p, &hdr, "</D:prop>" DEBUG_CR);

	if (ctx->err == NULL) {
	    /* nothing was assigned here yet, so make it a 424 */

	    if (ctx->operation == DAV_PROP_OP_SET) {
		if (err424_set == NULL)
		    err424_set = dav_new_error(p, HTTP_FAILED_DEPENDENCY, 0,
					       "Attempted DAV:set operation "
					       "could not be completed due "
					       "to other errors.");
		ctx->err = err424_set;
	    }
	    else if (ctx->operation == DAV_PROP_OP_DELETE) {
		if (err424_delete == NULL)
		    err424_delete = dav_new_error(p, HTTP_FAILED_DEPENDENCY, 0,
						  "Attempted DAV:remove "
						  "operation could not be "
						  "completed due to other "
						  "errors.");
		ctx->err = err424_delete;
	    }
	}

	s = apr_psprintf(p,
			"<D:status>"
			"HTTP/1.1 %d (status)"
			"</D:status>" DEBUG_CR,
			ctx->err->status);
	ap_text_append(p, &hdr, s);

	/* ### we should use compute_desc if necessary... */
	if (ctx->err->desc != NULL) {
	    ap_text_append(p, &hdr, "<D:responsedescription>" DEBUG_CR);
	    ap_text_append(p, &hdr, ctx->err->desc);
	    ap_text_append(p, &hdr, "</D:responsedescription>" DEBUG_CR);
	}

	ap_text_append(p, &hdr, "</D:propstat>" DEBUG_CR);
    }

    return hdr.first;
}

static ap_text * dav_success_proppatch(apr_pool_t *p, apr_array_header_t *prop_ctx)
{
    ap_text_header hdr = { 0 };
    int i = prop_ctx->nelts;
    dav_prop_ctx *ctx = (dav_prop_ctx *)prop_ctx->elts;

    /*
    ** ### we probably need to revise the way we assemble the response...
    ** ### this code assumes everything will return status==200.
    */

    ap_text_append(p, &hdr,
		   "<D:propstat>" DEBUG_CR
		   "<D:prop>" DEBUG_CR);

    for ( ; i-- > 0; ++ctx ) {
	ap_text_append(p, &hdr, ap_xml_empty_elem(p, ctx->prop));
    }

    ap_text_append(p, &hdr,
		    "</D:prop>" DEBUG_CR
		    "<D:status>HTTP/1.1 200 OK</D:status>" DEBUG_CR
		    "</D:propstat>" DEBUG_CR);

    return hdr.first;
}

static void dav_prop_log_errors(dav_prop_ctx *ctx)
{
    dav_log_err(ctx->r, ctx->err, APLOG_ERR);
}

/*
** Call <func> for each context. This can stop when an error occurs, or
** simply iterate through the whole list.
**
** Returns 1 if an error occurs (and the iteration is aborted). Returns 0
** if all elements are processed.
**
** If <reverse> is true (non-zero), then the list is traversed in
** reverse order.
*/
static int dav_process_ctx_list(void (*func)(dav_prop_ctx *ctx),
				apr_array_header_t *ctx_list, int stop_on_error,
				int reverse)
{
    int i = ctx_list->nelts;
    dav_prop_ctx *ctx = (dav_prop_ctx *)ctx_list->elts;

    if (reverse)
	ctx += i;

    while (i--) {
	if (reverse)
	    --ctx;

	(*func)(ctx);
	if (stop_on_error && DAV_PROP_CTX_HAS_ERR(*ctx)) {
	    return 1;
	}

	if (!reverse)
	    ++ctx;
    }

    return 0;
}

/* handle the PROPPATCH method */
static int dav_method_proppatch(request_rec *r)
{
    dav_error *err;
    dav_resource *resource;
    int result;
    ap_xml_doc *doc;
    ap_xml_elem *child;
    dav_propdb *propdb;
    int failure = 0;
    dav_response resp = { 0 };
    ap_text *propstat_text;
    apr_array_header_t *ctx_list;
    dav_prop_ctx *ctx;

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 0 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;
    if (!resource->exists) {
	/* Apache will supply a default error for this. */
	return HTTP_NOT_FOUND;
    }

    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
	return result;
    }
    /* note: doc == NULL if no request body */

    if (doc == NULL || !dav_validate_root(doc, "propertyupdate")) {
	/* This supplies additional information for the default message. */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "The request body does not contain "
		      "a \"propertyupdate\" element.");
	return HTTP_BAD_REQUEST;
    }

    /* Check If-Headers and existing locks */
    /* Note: depth == 0. Implies no need for a multistatus response. */
    if ((err = dav_validate_request(r, resource, 0, NULL, NULL,
				    DAV_VALIDATE_RESOURCE, NULL)) != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, NULL);
    }

    if ((err = dav_open_propdb(r, NULL, resource, 0, doc->namespaces,
			       &propdb)) != NULL) {
	err = dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0,
			     apr_psprintf(r->pool,
					 "Could not open the property "
					 "database for %s.",
					 ap_escape_html(r->pool, r->uri)),
			     err);
	return dav_handle_err(r, err, NULL);
    }
    /* ### what to do about closing the propdb on server failure? */

    /* ### validate "live" properties */

    /* set up an array to hold property operation contexts */
    ctx_list = apr_make_array(r->pool, 10, sizeof(dav_prop_ctx));

    /* do a first pass to ensure that all "remove" properties exist */
    for (child = doc->root->first_child; child; child = child->next) {
	int is_remove;
	ap_xml_elem *prop_group;
	ap_xml_elem *one_prop;

	/* Ignore children that are not set/remove */
	if (child->ns != AP_XML_NS_DAV_ID
	    || (!(is_remove = strcmp(child->name, "remove") == 0)
		&& strcmp(child->name, "set") != 0)) {
	    continue;
	}

	/* make sure that a "prop" child exists for set/remove */
	if ((prop_group = dav_find_child(child, "prop")) == NULL) {
	    dav_close_propdb(propdb);

	    /* This supplies additional information for the default message. */
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
			  "A \"prop\" element is missing inside "
			  "the propertyupdate command.");
	    return HTTP_BAD_REQUEST;
	}

	for (one_prop = prop_group->first_child; one_prop;
	     one_prop = one_prop->next) {

	    ctx = (dav_prop_ctx *)apr_push_array(ctx_list);
	    ctx->propdb = propdb;
	    ctx->operation = is_remove ? DAV_PROP_OP_DELETE : DAV_PROP_OP_SET;
	    ctx->prop = one_prop;

            ctx->r = r;         /* for later use by dav_prop_log_errors() */

	    dav_prop_validate(ctx);

	    if ( DAV_PROP_CTX_HAS_ERR(*ctx) ) {
		failure = 1;
	    }
	}
    }

    /* ### should test that we found at least one set/remove */

    /* execute all of the operations */
    if (!failure && dav_process_ctx_list(dav_prop_exec, ctx_list, 1, 0)) {
	failure = 1;
    }

    /* generate a failure/success response */
    if (failure) {
	(void)dav_process_ctx_list(dav_prop_rollback, ctx_list, 0, 1);
	propstat_text = dav_failed_proppatch(r->pool, ctx_list);
    }
    else {
	(void)dav_process_ctx_list(dav_prop_commit, ctx_list, 0, 0);
	propstat_text = dav_success_proppatch(r->pool, ctx_list);
    }

    /* make sure this gets closed! */
    dav_close_propdb(propdb);

    /* log any errors that occurred */
    (void)dav_process_ctx_list(dav_prop_log_errors, ctx_list, 0, 0);

    resp.href = resource->uri;

    /* ### should probably use something new to pass along this text... */
    resp.propresult.propstats = propstat_text;

    dav_send_multistatus(r, HTTP_MULTI_STATUS, &resp, doc->namespaces);

    /* the response has been sent. */
    return DONE;
}

static int process_mkcol_body(request_rec *r)
{
    /* This is snarfed from ap_setup_client_block(). We could get pretty
     * close to this behavior by passing REQUEST_NO_BODY, but we need to
     * return HTTP_UNSUPPORTED_MEDIA_TYPE (while ap_setup_client_block
     * returns HTTP_REQUEST_ENTITY_TOO_LARGE). */

    const char *tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
    const char *lenp = apr_table_get(r->headers_in, "Content-Length");

    /* make sure to set the Apache request fields properly. */
    r->read_body = REQUEST_NO_BODY;
    r->read_chunked = 0;
    r->remaining = 0;

    if (tenc) {
	if (strcasecmp(tenc, "chunked")) {
	    /* Use this instead of Apache's default error string */
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
			  "Unknown Transfer-Encoding %s", tenc);
	    return HTTP_NOT_IMPLEMENTED;
	}

	r->read_chunked = 1;
    }
    else if (lenp) {
	const char *pos = lenp;

	while (apr_isdigit(*pos) || apr_isspace(*pos)) {
	    ++pos;
	}
	if (*pos != '\0') {
	    /* This supplies additional information for the default message. */
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
			  "Invalid Content-Length %s", lenp);
	    return HTTP_BAD_REQUEST;
	}

	r->remaining = atol(lenp);
    }

    if (r->read_chunked || r->remaining > 0) {
	/* ### log something? */

	/* Apache will supply a default error for this. */
	return HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    /*
    ** Get rid of the body. this will call ap_setup_client_block(), but
    ** our copy above has already verified its work.
    */
    return ap_discard_request_body(r);
}

/* handle the MKCOL method */
static int dav_method_mkcol(request_rec *r)
{
    dav_resource *resource;
    int resource_state;
    dav_auto_version_info av_info;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    dav_error *err;
    dav_error *err2;
    int result;
    dav_dir_conf *conf;
    dav_response *multi_status;

    /* handle the request body */
    /* ### this may move lower once we start processing bodies */
    if ((result = process_mkcol_body(r)) != OK) {
	return result;
    }

    conf = (dav_dir_conf *) ap_get_module_config(r->per_dir_config,
						 &dav_module);

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 0 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;

    if (resource->exists) {
	/* oops. something was already there! */

	/* Apache will supply a default error for this. */
	/* ### we should provide a specific error message! */
	return HTTP_METHOD_NOT_ALLOWED;
    }

    resource_state = dav_get_resource_state(r, resource);

    /*
    ** Check If-Headers and existing locks.
    **
    ** Note: depth == 0 normally requires no multistatus response. However,
    ** if we pass DAV_VALIDATE_PARENT, then we could get an error on a URI
    ** other than the Request-URI, thereby requiring a multistatus.
    **
    ** If the resource does not exist (DAV_RESOURCE_NULL), then we must
    ** check the resource *and* its parent. If the resource exists or is
    ** a locknull resource, then we check only the resource.
    */
    if ((err = dav_validate_request(r, resource, 0, NULL, &multi_status,
				    resource_state == DAV_RESOURCE_NULL ?
				    DAV_VALIDATE_PARENT :
				    DAV_VALIDATE_RESOURCE, NULL)) != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, multi_status);
    }

    /* if versioned resource, make sure parent is checked out */
    if ((err = dav_ensure_resource_writable(r, resource, 1 /* parent_only */,
					    &av_info)) != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, NULL);
    }

    /* try to create the collection */
    resource->collection = 1;
    err = (*resource->hooks->create_collection)(resource);

    /* restore modifiability of parent back to what it was */
    err2 = dav_revert_resource_writability(r, NULL, err != NULL /* undo if error */,
					   &av_info);

    /* check for errors now */
    if (err != NULL) {
	return dav_handle_err(r, err, NULL);
    }
    if (err2 != NULL) {
	/* just log a warning */
	err = dav_push_error(r->pool, err->status, 0,
			     "The MKCOL was successful, but there "
			     "was a problem reverting the writability of "
			     "its parent collection.",
			     err2);
	dav_log_err(r, err, APLOG_WARNING);
    }

    if (locks_hooks != NULL) {
	dav_lockdb *lockdb;

	if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
	    /* The directory creation was successful, but the locking failed. */
	    err = dav_push_error(r->pool, err->status, 0,
				 "The MKCOL was successful, but there "
				 "was a problem opening the lock database "
				 "which prevents inheriting locks from the "
				 "parent resources.",
				 err);
	    return dav_handle_err(r, err, NULL);
	}

	/* notify lock system that we have created/replaced a resource */
	err = dav_notify_created(r, lockdb, resource, resource_state, 0);

	(*locks_hooks->close_lockdb)(lockdb);

	if (err != NULL) {
	    /* The dir creation was successful, but the locking failed. */
	    err = dav_push_error(r->pool, err->status, 0,
				 "The MKCOL was successful, but there "
				 "was a problem updating its lock "
				 "information.",
				 err);
	    return dav_handle_err(r, err, NULL);
	}
    }

    /* return an appropriate response (HTTP_CREATED) */
    return dav_created(r, NULL, "Collection", 0);
}

/* handle the COPY and MOVE methods */
static int dav_method_copymove(request_rec *r, int is_move)
{
    dav_resource *resource;
    dav_auto_version_info src_av_info = { 0 };
    dav_resource *resnew;
    dav_auto_version_info dst_av_info;
    const char *body;
    const char *dest;
    dav_error *err;
    dav_error *err2;
    dav_error *err3;
    dav_response *multi_response;
    dav_lookup_result lookup;
    int is_dir;
    int overwrite;
    int depth;
    int result;
    dav_lockdb *lockdb;
    int replaced;
    int resource_state;

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, !is_move /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;
    if (!resource->exists) {
	/* Apache will supply a default error for this. */
	return HTTP_NOT_FOUND;
    }

    /* If not a file or collection resource, COPY/MOVE not allowed */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR) {
        body = apr_psprintf(r->pool,
                           "Cannot COPY/MOVE resource %s.",
                           ap_escape_html(r->pool, r->uri));
	return dav_error_response(r, HTTP_METHOD_NOT_ALLOWED, body);
    }

    /* get the destination URI */
    dest = apr_table_get(r->headers_in, "Destination");
    if (dest == NULL) {
	/* Look in headers provided by Netscape's Roaming Profiles */
	const char *nscp_host = apr_table_get(r->headers_in, "Host");
	const char *nscp_path = apr_table_get(r->headers_in, "New-uri");

	if (nscp_host != NULL && nscp_path != NULL)
	    dest = apr_psprintf(r->pool, "http://%s%s", nscp_host, nscp_path);
    }
    if (dest == NULL) {
	/* This supplies additional information for the default message. */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "The request is missing a Destination header.");
	return HTTP_BAD_REQUEST;
    }

    lookup = dav_lookup_uri(dest, r);
    if (lookup.rnew == NULL) {
	if (lookup.err.status == HTTP_BAD_REQUEST) {
	    /* This supplies additional information for the default message. */
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
			  lookup.err.desc);
	    return HTTP_BAD_REQUEST;
	}

	/* ### this assumes that dav_lookup_uri() only generates a status
	 * ### that Apache can provide a status line for!! */

	return dav_error_response(r, lookup.err.status, lookup.err.desc);
    }
    if (lookup.rnew->status != HTTP_OK) {
	/* ### how best to report this... */
	return dav_error_response(r, lookup.rnew->status,
				  "Destination URI had an error.");
    }

    /* Resolve destination resource */
    result = dav_get_resource(lookup.rnew, 0 /*target_allowed*/, NULL, &resnew);
    if (result != OK)
        return result;

    /* are the two resources handled by the same repository? */
    if (resource->hooks != resnew->hooks) {
	/* ### this message exposes some backend config, but screw it... */
	return dav_error_response(r, HTTP_BAD_GATEWAY,
				  "Destination URI is handled by a "
				  "different repository than the source URI. "
				  "MOVE or COPY between repositories is "
				  "not possible.");
    }

    /* get and parse the overwrite header value */
    if ((overwrite = dav_get_overwrite(r)) < 0) {
	/* dav_get_overwrite() supplies additional information for the
	 * default message. */
	return HTTP_BAD_REQUEST;
    }

    /* quick failure test: if dest exists and overwrite is false. */
    if (resnew->exists && !overwrite) {
	/* Supply some text for the error response body. */
	return dav_error_response(r, HTTP_PRECONDITION_FAILED,
                                  "Destination is not empty and "
                                  "Overwrite is not \"T\"");
    }

    /* are the source and destination the same? */
    if ((*resource->hooks->is_same_resource)(resource, resnew)) {
	/* Supply some text for the error response body. */
	return dav_error_response(r, HTTP_FORBIDDEN,
                                  "Source and Destination URIs are the same.");

    }

    is_dir = resource->collection;

    /* get and parse the Depth header value. "0" and "infinity" are legal. */
    if ((depth = dav_get_depth(r, DAV_INFINITY)) < 0) {
	/* dav_get_depth() supplies additional information for the
	 * default message. */
	return HTTP_BAD_REQUEST;
    }
    if (depth == 1) {
	/* This supplies additional information for the default message. */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		   "Depth must be \"0\" or \"infinity\" for COPY or MOVE.");
	return HTTP_BAD_REQUEST;
    }
    if (is_move && is_dir && depth != DAV_INFINITY) {
	/* This supplies additional information for the default message. */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		    "Depth must be \"infinity\" when moving a collection.");
	return HTTP_BAD_REQUEST;
    }

    /*
    ** Check If-Headers and existing locks for each resource in the source
    ** if we are performing a MOVE. We will return a 424 response with a
    ** DAV:multistatus body. The multistatus responses will contain the
    ** information about any resource that fails the validation.
    **
    ** We check the parent resource, too, since this is a MOVE. Moving the
    ** resource effectively removes it from the parent collection, so we
    ** must ensure that we have met the appropriate conditions.
    **
    ** If a problem occurs with the Request-URI itself, then a plain error
    ** (rather than a multistatus) will be returned.
    */
    if (is_move
	&& (err = dav_validate_request(r, resource, depth, NULL,
				       &multi_response,
				       DAV_VALIDATE_PARENT
                                       | DAV_VALIDATE_USE_424,
                                       NULL)) != NULL) {
	err = dav_push_error(r->pool, err->status, 0,
			     apr_psprintf(r->pool,
					 "Could not MOVE %s due to a failed "
					 "precondition on the source "
					 "(e.g. locks).",
					 ap_escape_html(r->pool, r->uri)),
			     err);
	return dav_handle_err(r, err, multi_response);
    }

    /*
    ** Check If-Headers and existing locks for destination. Note that we
    ** use depth==infinity since the target (hierarchy) will be deleted
    ** before the move/copy is completed.
    **
    ** Note that we are overwriting the target, which implies a DELETE, so
    ** we are subject to the error/response rules as a DELETE. Namely, we
    ** will return a 424 error if any of the validations fail.
    ** (see dav_method_delete() for more information)
    */
    if ((err = dav_validate_request(lookup.rnew, resnew, DAV_INFINITY, NULL,
				    &multi_response,
				    DAV_VALIDATE_PARENT
                                    | DAV_VALIDATE_USE_424, NULL)) != NULL) {
	err = dav_push_error(r->pool, err->status, 0,
			     apr_psprintf(r->pool,
					 "Could not MOVE/COPY %s due to a "
					 "failed precondition on the "
					 "destination (e.g. locks).",
					 ap_escape_html(r->pool, r->uri)),
			     err);
	return dav_handle_err(r, err, multi_response);
    }

    if (is_dir
	&& depth == DAV_INFINITY
	&& (*resource->hooks->is_parent_resource)(resource, resnew)) {
	/* Supply some text for the error response body. */
	return dav_error_response(r, HTTP_FORBIDDEN,
                                  "Source collection contains the "
                                  "Destination.");

    }
    if (is_dir
	&& (*resnew->hooks->is_parent_resource)(resnew, resource)) {
	/* The destination must exist (since it contains the source), and
	 * a condition above implies Overwrite==T. Obviously, we cannot
	 * delete the Destination before the MOVE/COPY, as that would
	 * delete the Source.
	 */

	/* Supply some text for the error response body. */
	return dav_error_response(r, HTTP_FORBIDDEN,
                                  "Destination collection contains the Source "
                                  "and Overwrite has been specified.");
    }

    /* ### for now, we don't need anything in the body */
    if ((result = ap_discard_request_body(r)) != OK) {
	return result;
    }

    if ((err = dav_open_lockdb(r, 0, &lockdb)) != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, NULL);
    }

    /* remove any locks from the old resources */
    /*
    ** ### this is Yet Another Traversal. if we do a rename(), then we
    ** ### really don't have to do this in some cases since the inode
    ** ### values will remain constant across the move. but we can't
    ** ### know that fact from outside the provider :-(
    **
    ** ### note that we now have a problem atomicity in the move/copy
    ** ### since a failure after this would have removed locks (technically,
    ** ### this is okay to do, but really...)
    */
    if (is_move && lockdb != NULL) {
	/* ### this is wrong! it blasts direct locks on parent resources */
	/* ### pass lockdb! */
	(void)dav_unlock(r, resource, NULL);
    }

    /* remember whether target resource existed */
    replaced = resnew->exists;

    /* if this is a move, then the source parent collection will be modified */
    if (is_move) {
        if ((err = dav_ensure_resource_writable(r, resource, 1 /* parent_only */,
						&src_av_info)) != NULL) {
	    if (lockdb != NULL)
		(*lockdb->hooks->close_lockdb)(lockdb);

	    /* ### add a higher-level description? */
	    return dav_handle_err(r, err, NULL);
        }
    }

    /* prepare the destination collection for modification */
    if ((err = dav_ensure_resource_writable(r, resnew, 1 /* parent_only */,
					    &dst_av_info)) != NULL) {
        /* could not make destination writable:
	 * if move, restore state of source parent
	 */
        if (is_move) {
            (void) dav_revert_resource_writability(r, NULL, 1 /* undo */,
						   &src_av_info);
        }

	if (lockdb != NULL)
	    (*lockdb->hooks->close_lockdb)(lockdb);

	/* ### add a higher-level description? */
	return dav_handle_err(r, err, NULL);
    }

    /* If source and destination parents are the same, then
     * use the same object, so status updates to one are reflected
     * in the other, when reverting their writable states.
     */
    if (src_av_info.parent_resource != NULL
        && (*src_av_info.parent_resource->hooks->is_same_resource)
            (src_av_info.parent_resource, dst_av_info.parent_resource)) {

        dst_av_info.parent_resource = src_av_info.parent_resource;
    }

    /* New resource will be same kind as source */
    resnew->collection = resource->collection;

    resource_state = dav_get_resource_state(lookup.rnew, resnew);

    /* If target exists, remove it first (we know Ovewrite must be TRUE).
     * Then try to copy/move the resource.
     */
    if (resnew->exists)
	err = (*resnew->hooks->remove_resource)(resnew, &multi_response);

    if (err == NULL) {
	if (is_move)
	    err = (*resource->hooks->move_resource)(resource, resnew,
                                                    &multi_response);
	else
	    err = (*resource->hooks->copy_resource)(resource, resnew, depth,
                                                    &multi_response);
    }

    /* restore parent collection states */
    err2 = dav_revert_resource_writability(r, NULL, err != NULL /* undo if error */,
					   &dst_av_info);

    if (is_move) {
        err3 = dav_revert_resource_writability(r, NULL, err != NULL /* undo if error */,
					       &src_av_info);
    }
    else
	err3 = NULL;

    /* check for error from remove/copy/move operations */
    if (err != NULL) {
	if (lockdb != NULL)
	    (*lockdb->hooks->close_lockdb)(lockdb);

	err = dav_push_error(r->pool, err->status, 0,
			     apr_psprintf(r->pool,
					 "Could not MOVE/COPY %s.",
					 ap_escape_html(r->pool, r->uri)),
			     err);
	return dav_handle_err(r, err, multi_response);
    }

    /* check for errors from reverting writability */
    if (err2 != NULL) {
	/* just log a warning */
	err = dav_push_error(r->pool, err2->status, 0,
			     "The MOVE/COPY was successful, but there was a "
			     "problem reverting the writability of the "
			     "source parent collection.",
			     err2);
	dav_log_err(r, err, APLOG_WARNING);
    }
    if (err3 != NULL) {
	/* just log a warning */
	err = dav_push_error(r->pool, err3->status, 0,
			     "The MOVE/COPY was successful, but there was a "
			     "problem reverting the writability of the "
			     "destination parent collection.",
			     err3);
	dav_log_err(r, err, APLOG_WARNING);
    }

    /* propagate any indirect locks at the target */
    if (lockdb != NULL) {

	/* notify lock system that we have created/replaced a resource */
	err = dav_notify_created(r, lockdb, resnew, resource_state, depth);

	(*lockdb->hooks->close_lockdb)(lockdb);

	if (err != NULL) {
	    /* The move/copy was successful, but the locking failed. */
	    err = dav_push_error(r->pool, err->status, 0,
				 "The MOVE/COPY was successful, but there "
				 "was a problem updating the lock "
				 "information.",
				 err);
	    return dav_handle_err(r, err, NULL);
	}
    }

    /* return an appropriate response (HTTP_CREATED or HTTP_NO_CONTENT) */
    return dav_created(r, lookup.rnew->uri, "Destination", replaced);
}

/* dav_method_lock:  Handler to implement the DAV LOCK method
**    Returns appropriate HTTP_* response.
*/
static int dav_method_lock(request_rec *r)
{
    dav_error *err;
    dav_resource *resource;
    const dav_hooks_locks *locks_hooks;
    int result;
    int depth;
    int new_lock_request = 0;
    ap_xml_doc *doc;
    dav_lock *lock;
    dav_response *multi_response = NULL;
    dav_lockdb *lockdb;
    int resource_state;

    /* If no locks provider, decline the request */
    locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    if (locks_hooks == NULL)
        return DECLINED;

    if ((result = ap_xml_parse_input(r, &doc)) != OK)
	return result;

    depth = dav_get_depth(r, DAV_INFINITY);
    if (depth != 0 && depth != DAV_INFINITY) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "Depth must be 0 or \"infinity\" for LOCK.");
	return HTTP_BAD_REQUEST;
    }

    /* Ask repository module to resolve the resource.
     * DeltaV says result of target selector is undefined,
     * so allow it, and let provider reject the lock attempt
     * on a version if it wants to.
     */
    result = dav_get_resource(r, 1 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;

    /*
    ** Open writable. Unless an error occurs, we'll be
    ** writing into the database.
    */
    if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, NULL);
    }

    if (doc != NULL) {
        if ((err = dav_lock_parse_lockinfo(r, resource, lockdb, doc,
	    			           &lock)) != NULL) {
	    /* ### add a higher-level description to err? */
            goto error;
        }
        new_lock_request = 1;

        lock->auth_user = apr_pstrdup(r->pool, r->user);
    }

    resource_state = dav_get_resource_state(r, resource);

    /*
    ** Check If-Headers and existing locks.
    **
    ** If this will create a locknull resource, then the LOCK will affect
    ** the parent collection (much like a PUT/MKCOL). For that case, we must
    ** validate the parent resource's conditions.
    */
    if ((err = dav_validate_request(r, resource, depth, NULL, &multi_response,
                                    (resource_state == DAV_RESOURCE_NULL
                                     ? DAV_VALIDATE_PARENT
                                     : DAV_VALIDATE_RESOURCE)
                                    | (new_lock_request ? lock->scope : 0)
                                    | DAV_VALIDATE_ADD_LD,
                                    lockdb)) != OK) {
	err = dav_push_error(r->pool, err->status, 0,
			     apr_psprintf(r->pool,
					 "Could not LOCK %s due to a failed "
					 "precondition (e.g. other locks).",
					 ap_escape_html(r->pool, r->uri)),
			     err);
	goto error;
    }

    if (new_lock_request == 0) {
	dav_locktoken_list *ltl;
		
	/*
	** Refresh request 
	** ### Assumption:  We can renew multiple locks on the same resource
	** ### at once. First harvest all the positive lock-tokens given in
	** ### the If header. Then modify the lock entries for this resource
	** ### with the new Timeout val.
	*/

	if ((err = dav_get_locktoken_list(r, &ltl)) != NULL) {
	    err = dav_push_error(r->pool, err->status, 0,
				 apr_psprintf(r->pool,
					     "The lock refresh for %s failed "
					     "because no lock tokens were "
					     "specified in an \"If:\" "
					     "header.",
					     ap_escape_html(r->pool, r->uri)),
				 err);
	    goto error;
	}

	if ((err = (*locks_hooks->refresh_locks)(lockdb, resource, ltl,
						 dav_get_timeout(r),
						 &lock)) != NULL) {
	    /* ### add a higher-level description to err? */
	    goto error;
	}
    } else {
	/* New lock request */
        char *locktoken_txt;
	dav_dir_conf *conf;

	conf = (dav_dir_conf *) ap_get_module_config(r->per_dir_config,
						     &dav_module);

	/* apply lower bound (if any) from DAVMinTimeout directive */
	if (lock->timeout != DAV_TIMEOUT_INFINITE
            && lock->timeout < time(NULL) + conf->locktimeout)
	    lock->timeout = time(NULL) + conf->locktimeout;

        err = dav_add_lock(r, resource, lockdb, lock, &multi_response);
	if (err != NULL) {
	    /* ### add a higher-level description to err? */
	    goto error;
	}

        locktoken_txt = apr_pstrcat(r->pool, "<",
				   (*locks_hooks->format_locktoken)(r->pool, lock->locktoken),
				   ">", NULL);

	apr_table_set(r->headers_out, "Lock-Token", locktoken_txt);
    }

    (*locks_hooks->close_lockdb)(lockdb);

    r->status = HTTP_OK;
    r->content_type = DAV_XML_CONTENT_TYPE;

    ap_send_http_header(r);

    ap_rputs(DAV_XML_HEADER DEBUG_CR "<D:prop xmlns:D=\"DAV:\">" DEBUG_CR, r);
    if (lock == NULL)
	ap_rputs("<D:lockdiscovery/>" DEBUG_CR, r);
    else {
	ap_rprintf(r,
		   "<D:lockdiscovery>" DEBUG_CR
		   "%s" DEBUG_CR
		   "</D:lockdiscovery>" DEBUG_CR,
		   dav_lock_get_activelock(r, lock, NULL));
    }
    ap_rputs("</D:prop>", r);

    /* the response has been sent. */
    return DONE;

  error:
    (*locks_hooks->close_lockdb)(lockdb);
    return dav_handle_err(r, err, multi_response);
}

/* dav_method_unlock:  Handler to implement the DAV UNLOCK method
 *    Returns appropriate HTTP_* response.
 */
static int dav_method_unlock(request_rec *r)
{
    dav_error *err;
    dav_resource *resource;
    const dav_hooks_locks *locks_hooks;
    int result;
    const char *const_locktoken_txt;
    char *locktoken_txt;
    dav_locktoken *locktoken = NULL;
    int resource_state;
    dav_response *multi_response;

    /* If no locks provider, decline the request */
    locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    if (locks_hooks == NULL)
        return DECLINED;

    if ((const_locktoken_txt = apr_table_get(r->headers_in, "Lock-Token")) == NULL) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "Unlock failed (%s):  No Lock-Token specified in header", r->filename);
	return HTTP_BAD_REQUEST;
    }

    locktoken_txt = apr_pstrdup(r->pool, const_locktoken_txt);
    if (locktoken_txt[0] != '<') {
	/* ### should provide more specifics... */
	return HTTP_BAD_REQUEST;
    }
    locktoken_txt++;

    if (locktoken_txt[strlen(locktoken_txt) - 1] != '>') {
	/* ### should provide more specifics... */
	return HTTP_BAD_REQUEST;
    }
    locktoken_txt[strlen(locktoken_txt) - 1] = '\0';
		
    if ((err = (*locks_hooks->parse_locktoken)(r->pool, locktoken_txt,
					       &locktoken)) != NULL) {
	err = dav_push_error(r->pool, HTTP_BAD_REQUEST, 0,
			     apr_psprintf(r->pool,
					 "The UNLOCK on %s failed -- an "
					 "invalid lock token was specified "
					 "in the \"If:\" header.",
					 ap_escape_html(r->pool, r->uri)),
			     err);
	return dav_handle_err(r, err, NULL);
    }

    /* Ask repository module to resolve the resource.
     * DeltaV says result of target selector is undefined,
     * so allow it, and let provider reject the unlock attempt
     * on a version if it wants to.
     */
    result = dav_get_resource(r, 1 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;

    resource_state = dav_get_resource_state(r, resource);

    /*
    ** Check If-Headers and existing locks.
    **
    ** Note: depth == 0 normally requires no multistatus response. However,
    ** if we pass DAV_VALIDATE_PARENT, then we could get an error on a URI
    ** other than the Request-URI, thereby requiring a multistatus.
    **
    ** If the resource is a locknull resource, then the UNLOCK will affect
    ** the parent collection (much like a delete). For that case, we must
    ** validate the parent resource's conditions.
    */
    if ((err = dav_validate_request(r, resource, 0, locktoken,
                                    &multi_response,
                                    resource_state == DAV_RESOURCE_LOCK_NULL
                                    ? DAV_VALIDATE_PARENT
                                    : DAV_VALIDATE_RESOURCE, NULL)) != NULL) {
	/* ### add a higher-level description? */
	return dav_handle_err(r, err, multi_response);
    }

    /* ### RFC 2518 s. 8.11: If this resource is locked by locktoken,
     *     _all_ resources locked by locktoken are released.  It does not say
     *     resource has to be the root of an infinte lock.  Thus, an UNLOCK
     *     on any part of an infinte lock will remove the lock on all resources.
     *     
     *     For us, if r->filename represents an indirect lock (part of an infinity lock),
     *     we must actually perform an UNLOCK on the direct lock for this resource.
     */     
    if ((result = dav_unlock(r, resource, locktoken)) != OK) {
	return result;
    }

    return HTTP_NO_CONTENT;
}

static int dav_method_vsn_control(request_rec *r)
{
    dav_resource *resource;
    int resource_state;
    dav_auto_version_info av_info;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    ap_xml_doc *doc;
    const char *target = NULL;
    int result;

    /* if no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    /* ask repository module to resolve the resource */
    result = dav_get_resource(r, 0 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;

    /* remember the pre-creation resource state */
    resource_state = dav_get_resource_state(r, resource);

    /* parse the request body (may be a version-control element) */
    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
	return result;
    }
    /* note: doc == NULL if no request body */

    if (doc != NULL) {
        const ap_xml_elem *child;
        apr_size_t tsize;

        if (!dav_validate_root(doc, "version-control")) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		          "The request body does not contain "
		          "a \"version-control\" element.");
	    return HTTP_BAD_REQUEST;
        }

        /* get the version URI */
        if ((child = dav_find_child(doc->root, "version")) == NULL) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		          "The \"version-control\" element does not contain "
		          "a \"version\" element.");
	    return HTTP_BAD_REQUEST;
        }

        if ((child = dav_find_child(child, "href")) == NULL) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		          "The \"version\" element does not contain "
		          "an \"href\" element.");
	    return HTTP_BAD_REQUEST;
        }

        /* get version URI */
        ap_xml_to_text(r->pool, child, AP_XML_X2T_INNER, NULL, NULL,
                       &target, &tsize);
        if (tsize == 0) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		          "An \"href\" element does not contain a URI.");
	    return HTTP_BAD_REQUEST;
        }
    }

    /* Check request preconditions */

    /* ### need a general mechanism for reporting precondition violations
     * ### (should be returning XML document for 403/409 responses)
     */

    /* if not versioning existing resource, must specify version to select */
    if (!resource->exists && target == NULL) {
        err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
                            "<DAV:initial-version-required/>");
	return dav_handle_err(r, err, NULL);
    }
    else if (resource->exists) {
        /* cannot add resource to existing version history */
        if (target != NULL) {
            err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
                                "<DAV:cannot-add-to-existing-history/>");
	    return dav_handle_err(r, err, NULL);
        }

        /* resource must be unversioned and versionable, or version selector */
        if (resource->type != DAV_RESOURCE_TYPE_REGULAR
            || (!resource->versioned && !(vsn_hooks->versionable)(resource))) {
            err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
                                "<DAV:must-be-versionable/>");
	    return dav_handle_err(r, err, NULL);
        }

        /* the DeltaV spec says if resource is a version selector,
         * then VERSION-CONTROL is a no-op
         */
        if (resource->versioned) {
            /* set the Cache-Control header, per the spec */
            apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

            /* no body */
            ap_set_content_length(r, 0);
            ap_send_http_header(r);

            return DONE;
        }
    }

    /* Check If-Headers and existing locks */
    /* Note: depth == 0. Implies no need for a multistatus response. */
    if ((err = dav_validate_request(r, resource, 0, NULL, NULL,
				    resource_state == DAV_RESOURCE_NULL ?
				    DAV_VALIDATE_PARENT :
				    DAV_VALIDATE_RESOURCE, NULL)) != NULL) {
	return dav_handle_err(r, err, NULL);
    }

    /* if in versioned collection, make sure parent is checked out */
    if ((err = dav_ensure_resource_writable(r, resource, 1 /* parent_only */,
					    &av_info)) != NULL) {
	return dav_handle_err(r, err, NULL);
    }

    /* attempt to version-control the resource */
    if ((err = (*vsn_hooks->vsn_control)(resource, target)) != NULL) {
        dav_revert_resource_writability(r, resource, 1 /*undo*/, &av_info);
	err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
			     apr_psprintf(r->pool,
					 "Could not VERSION-CONTROL resource %s.",
					 ap_escape_html(r->pool, r->uri)),
			     err);
        return dav_handle_err(r, err, NULL);
    }

    /* revert writability of parent directory */
    err = dav_revert_resource_writability(r, resource, 0 /*undo*/, &av_info);
    if (err != NULL) {
        /* just log a warning */
	err = dav_push_error(r->pool, err->status, 0,
			     "The VERSION-CONTROL was successful, but there "
			     "was a problem reverting the writability of "
			     "the parent collection.",
			     err);
        dav_log_err(r, err, APLOG_WARNING);
    }

    /* if the resource is lockable, let lock system know of new resource */
    if (locks_hooks != NULL
	&& (*locks_hooks->get_supportedlock)(resource) != NULL) {
	dav_lockdb *lockdb;

	if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
	    /* The resource creation was successful, but the locking failed. */
	    err = dav_push_error(r->pool, err->status, 0,
				 "The VERSION-CONTROL was successful, but there "
				 "was a problem opening the lock database "
				 "which prevents inheriting locks from the "
				 "parent resources.",
				 err);
	    return dav_handle_err(r, err, NULL);
	}

	/* notify lock system that we have created/replaced a resource */
	err = dav_notify_created(r, lockdb, resource, resource_state, 0);

	(*locks_hooks->close_lockdb)(lockdb);

	if (err != NULL) {
	    /* The dir creation was successful, but the locking failed. */
	    err = dav_push_error(r->pool, err->status, 0,
				 "The VERSION-CONTROL was successful, but there "
				 "was a problem updating its lock "
				 "information.",
				 err);
	    return dav_handle_err(r, err, NULL);
	}
    }

    /* set the Cache-Control header, per the spec */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* return an appropriate response (HTTP_CREATED) */
    return dav_created(r, resource->uri, "Version selector", 0 /*replaced*/);
}

/* handle the CHECKOUT method */
static int dav_method_checkout(request_rec *r)
{
    dav_resource *resource;
    dav_resource *working_resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    int result;
    ap_xml_doc *doc;
    ap_xml_elem *target = NULL;

    /* If no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    if ((result = ap_xml_parse_input(r, &doc)) != OK)
	return result;

    if (doc != NULL) {
        if (!dav_validate_root(doc, "checkout")) {
            /* This supplies additional information for the default msg. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
                          "The request body, if present, must be a "
                          "DAV:checkout element.");
            return HTTP_BAD_REQUEST;
        }

        if ((target = dav_find_child(doc->root, "version")) == NULL)
            target = dav_find_child(doc->root, "label-name");
    }

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 1 /*target_allowed*/, target, &resource);
    if (result != OK)
        return result;
    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* Check the state of the resource: must be a file or collection,
     * must be versioned, and must not already be checked out.
     */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR) {
	return dav_error_response(r, HTTP_CONFLICT,
				  "Cannot checkout this type of resource.");
    }

    if (!resource->versioned) {
	return dav_error_response(r, HTTP_CONFLICT,
				  "Cannot checkout unversioned resource.");
    }

    if (resource->working) {
	return dav_error_response(r, HTTP_CONFLICT,
				  "The resource is already checked out to the workspace.");
    }

    /* ### do lock checks, once behavior is defined */

    /* Do the checkout */
    if ((err = (*vsn_hooks->checkout)(resource, &working_resource)) != NULL) {
	err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
			     apr_psprintf(r->pool,
					 "Could not CHECKOUT resource %s.",
					 ap_escape_html(r->pool, r->uri)),
			     err);
        return dav_handle_err(r, err, NULL);
    }

    /* set the Cache-Control header, per the spec */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* use appropriate URI for Location header */
    if (working_resource == NULL)
        working_resource = resource;

    return dav_created(r, working_resource->uri, "Checked-out resource", 0);
}

/* handle the UNCHECKOUT method */
static int dav_method_uncheckout(request_rec *r)
{
    dav_resource *resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    int result;

    /* If no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    if ((result = ap_discard_request_body(r)) != OK) {
	return result;
    }

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 0 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;
    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* Check the state of the resource: must be a file or collection,
     * must be versioned, and must be checked out.
     */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR) {
	return dav_error_response(r, HTTP_CONFLICT,
				  "Cannot uncheckout this type of resource.");
    }

    if (!resource->versioned) {
	return dav_error_response(r, HTTP_CONFLICT,
				  "Cannot uncheckout unversioned resource.");
    }

    if (!resource->working) {
	return dav_error_response(r, HTTP_CONFLICT,
				  "The resource is not checked out to the workspace.");
    }

    /* ### do lock checks, once behavior is defined */

    /* Do the uncheckout */
    if ((err = (*vsn_hooks->uncheckout)(resource)) != NULL) {
	err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
			     apr_psprintf(r->pool,
					 "Could not UNCHECKOUT resource %s.",
					 ap_escape_html(r->pool, r->uri)),
			     err);
        return dav_handle_err(r, err, NULL);
    }

    /* no body */
    ap_set_content_length(r, 0);
    ap_send_http_header(r);

    return DONE;
}

/* handle the CHECKIN method */
static int dav_method_checkin(request_rec *r)
{
    dav_resource *resource;
    dav_resource *new_version;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    int result;

    /* If no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    if ((result = ap_discard_request_body(r)) != OK) {
	return result;
    }

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 0 /* target_allowed */, NULL, &resource);
    if (result != OK)
        return result;
    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* Check the state of the resource: must be a file or collection,
     * must be versioned, and must be checked out.
     */
    if (resource->type != DAV_RESOURCE_TYPE_REGULAR) {
	return dav_error_response(r, HTTP_CONFLICT,
				  "Cannot checkin this type of resource.");
    }

    if (!resource->versioned) {
	return dav_error_response(r, HTTP_CONFLICT,
				  "Cannot checkin unversioned resource.");
    }

    if (!resource->working) {
	return dav_error_response(r, HTTP_CONFLICT,
				  "The resource is not checked out to the workspace.");
    }

    /* ### do lock checks, once behavior is defined */

    /* Do the checkin */
    if ((err = (*vsn_hooks->checkin)(resource, &new_version)) != NULL) {
	err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
			     apr_psprintf(r->pool,
					 "Could not CHECKIN resource %s.",
					 ap_escape_html(r->pool, r->uri)),
			     err);
        return dav_handle_err(r, err, NULL);
    }

    return dav_created(r, new_version->uri, "Version", 0);
}

/* context maintained during SET-TARGET treewalk */
typedef struct dav_set_target_walker_ctx
{
    /* input: */
    dav_walk_params w;

    /* target specifier */
    const char *target;

    /* flag for whether target is version URI or label */
    int is_label;

    /* version provider hooks */
    const dav_hooks_vsn *vsn_hooks;

} dav_set_target_walker_ctx;

static dav_error * dav_set_target_walker(dav_walk_resource *wres, int calltype)
{
    dav_set_target_walker_ctx *ctx = wres->walk_ctx;
    dav_error *err = NULL;

    /* Check the state of the resource: must be a checked-in version
     * or baseline selector
     */
    /* ### need a general mechanism for reporting precondition violations
     * ### (should be returning XML document for 403/409 responses)
     */
    if (wres->resource->type != DAV_RESOURCE_TYPE_REGULAR
        || !wres->resource->versioned || wres->resource->working) {
	err = dav_new_error(ctx->w.pool, HTTP_CONFLICT, 0,
			    "<DAV:must-be-checked-in-version-selector/>");
    }
    else {
        /* do the set-target operation */
        err = (*ctx->vsn_hooks->set_target)(wres->resource, ctx->target, ctx->is_label);
    }

    if (err != NULL) {
        /* ### need utility routine to add response with description? */
        dav_add_response(wres, err->status, NULL);
        wres->response->desc = err->desc;
    }

    return NULL;
}

static int dav_method_set_target(request_rec *r)
{
    dav_resource *resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    ap_xml_doc *doc;
    ap_xml_elem *child;
    int depth;
    int result;
    apr_size_t tsize;
    dav_error *err;
    dav_set_target_walker_ctx ctx = { { 0 } };
    dav_response *multi_status;

    /* If no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 0 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;
    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    if ((depth = dav_get_depth(r, 0)) < 0) {
	/* dav_get_depth() supplies additional information for the
	 * default message. */
	return HTTP_BAD_REQUEST;
    }

    /* parse the request body */
    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
	return result;
    }

    if (doc == NULL || !dav_validate_root(doc, "set-target")) {
	/* This supplies additional information for the default message. */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "The request body does not contain "
		      "a \"set-target\" element.");
	return HTTP_BAD_REQUEST;
    }

    /* check for label-name or version element */
    if ((child = dav_find_child(doc->root, "label-name")) != NULL) {
        ctx.is_label = 1;
    }
    else if ((child = dav_find_child(doc->root, "version")) != NULL) {
        ctx.is_label = 0;

        /* get the href element */
        if ((child = dav_find_child(child, "href")) == NULL) {
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		          "The version element does not contain "
		          "an \"href\" element.");
	    return HTTP_BAD_REQUEST;
        }
    }
    else {
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "The \"set-target\" element does not contain "
		      "a \"label-name\" or \"version\" element.");
	return HTTP_BAD_REQUEST;
    }

    /* get the target value (a label or a version URI */
    ap_xml_to_text(r->pool, child, AP_XML_X2T_INNER, NULL, NULL,
                   &ctx.target, &tsize);
    if (tsize == 0) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "A \"label-name\" or \"href\" element does not contain "
		      "any content.");
	return HTTP_BAD_REQUEST;
    }

    /* do the set-target operation walk */
    ctx.w.walk_type = DAV_WALKTYPE_NORMAL;
    ctx.w.func = dav_set_target_walker;
    ctx.w.walk_ctx = &ctx;
    ctx.w.pool = r->pool;
    ctx.w.root = resource;
    ctx.vsn_hooks = vsn_hooks;

    err = (*resource->hooks->walk)(&ctx.w, depth, &multi_status);

    if (err != NULL) {
        /* some sort of error occurred which terminated the walk */
        err = dav_push_error(r->pool, err->status, 0,
                             "The SET-TARGET operation was terminated prematurely.",
                             err);
        return dav_handle_err(r, err, multi_status);
    }

    if (multi_status != NULL) {
        /* One or more resources had errors. If depth was zero, convert
         * response to simple error, else make sure there is an
         * overall error to pass to dav_handle_err()
         */
        if (depth == 0) {
            err = dav_new_error(r->pool, multi_status->status, 0, multi_status->desc);
            multi_status = NULL;
        }
        else {
            err = dav_new_error(r->pool, HTTP_MULTI_STATUS, 0,
                                "Errors occurred during the SET-TARGET operation.");
        }

        return dav_handle_err(r, err, multi_status);
    }

    /* set the Cache-Control header, per the spec */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* no body */
    ap_set_content_length(r, 0);
    ap_send_http_header(r);

    return DONE;
}

/* context maintained during LABEL treewalk */
typedef struct dav_label_walker_ctx
{
    /* input: */
    dav_walk_params w;

    /* label being manipulated */
    const char *label;

    /* label operation */
    int label_op;
#define DAV_LABEL_ADD           1
#define DAV_LABEL_SET           2
#define DAV_LABEL_REMOVE        3

    /* version provider hooks */
    const dav_hooks_vsn *vsn_hooks;

} dav_label_walker_ctx;

static dav_error * dav_label_walker(dav_walk_resource *wres, int calltype)
{
    dav_label_walker_ctx *ctx = wres->walk_ctx;
    dav_error *err = NULL;

    /* Check the state of the resource: must be a version or
     * non-checkedout version selector
     */
    /* ### need a general mechanism for reporting precondition violations
     * ### (should be returning XML document for 403/409 responses)
     */
    if (wres->resource->type != DAV_RESOURCE_TYPE_VERSION &&
        (wres->resource->type != DAV_RESOURCE_TYPE_REGULAR
         || !wres->resource->versioned)) {
	err = dav_new_error(ctx->w.pool, HTTP_CONFLICT, 0,
			    "<DAV:must-be-version-or-version-selector/>");
    }
    else if (wres->resource->working) {
	err = dav_new_error(ctx->w.pool, HTTP_CONFLICT, 0,
			    "<DAV:must-not-be-checked-out/>");
    }
    else {
        /* do the label operation */
        if (ctx->label_op == DAV_LABEL_REMOVE)
	    err = (*ctx->vsn_hooks->remove_label)(wres->resource, ctx->label);
        else
	    err = (*ctx->vsn_hooks->add_label)(wres->resource, ctx->label,
                                               ctx->label_op == DAV_LABEL_SET);
    }

    if (err != NULL) {
        /* ### need utility routine to add response with description? */
        dav_add_response(wres, err->status, NULL);
        wres->response->desc = err->desc;
    }

    return NULL;
}

static int dav_method_label(request_rec *r)
{
    dav_resource *resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    ap_xml_doc *doc;
    ap_xml_elem *child;
    int depth;
    int result;
    apr_size_t tsize;
    dav_error *err;
    dav_label_walker_ctx ctx = { { 0 } };
    dav_response *multi_status;

    /* If no versioning provider, or the provider doesn't support
     * labels, decline the request */
    if (vsn_hooks == NULL || vsn_hooks->add_label == NULL)
        return DECLINED;

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 1 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;
    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    if ((depth = dav_get_depth(r, 0)) < 0) {
	/* dav_get_depth() supplies additional information for the
	 * default message. */
	return HTTP_BAD_REQUEST;
    }

    /* parse the request body */
    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
	return result;
    }

    if (doc == NULL || !dav_validate_root(doc, "label")) {
	/* This supplies additional information for the default message. */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "The request body does not contain "
		      "a \"label\" element.");
	return HTTP_BAD_REQUEST;
    }

    /* check for add, set, or remove element */
    if ((child = dav_find_child(doc->root, "add")) != NULL) {
        ctx.label_op = DAV_LABEL_ADD;
    }
    else if ((child = dav_find_child(doc->root, "set")) != NULL) {
        ctx.label_op = DAV_LABEL_SET;
    }
    else if ((child = dav_find_child(doc->root, "remove")) != NULL) {
        ctx.label_op = DAV_LABEL_REMOVE;
    }
    else {
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "The \"label\" element does not contain "
		      "an \"add\", \"set\", or \"remove\" element.");
	return HTTP_BAD_REQUEST;
    }

    /* get the label string */
    if ((child = dav_find_child(child, "label-name")) == NULL) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "The label command element does not contain "
		      "a \"label-name\" element.");
	return HTTP_BAD_REQUEST;
    }

    ap_xml_to_text(r->pool, child, AP_XML_X2T_INNER, NULL, NULL,
                   &ctx.label, &tsize);
    if (tsize == 0) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "A \"label-name\" element does not contain "
		      "a label name.");
	return HTTP_BAD_REQUEST;
    }

    /* do the label operation walk */
    ctx.w.walk_type = DAV_WALKTYPE_NORMAL;
    ctx.w.func = dav_label_walker;
    ctx.w.walk_ctx = &ctx;
    ctx.w.pool = r->pool;
    ctx.w.root = resource;
    ctx.vsn_hooks = vsn_hooks;

    err = (*resource->hooks->walk)(&ctx.w, depth, &multi_status);

    if (err != NULL) {
        /* some sort of error occurred which terminated the walk */
        err = dav_push_error(r->pool, err->status, 0,
                             "The LABEL operation was terminated prematurely.",
                             err);
        return dav_handle_err(r, err, multi_status);
    }

    if (multi_status != NULL) {
        /* One or more resources had errors. If depth was zero, convert
         * response to simple error, else make sure there is an
         * overall error to pass to dav_handle_err()
         */
        if (depth == 0) {
            err = dav_new_error(r->pool, multi_status->status, 0, multi_status->desc);
            multi_status = NULL;
        }
        else {
            err = dav_new_error(r->pool, HTTP_MULTI_STATUS, 0,
                                "Errors occurred during the LABEL operation.");
        }

        return dav_handle_err(r, err, multi_status);
    }

    /* set the Cache-Control header, per the spec */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* no body */
    ap_set_content_length(r, 0);
    ap_send_http_header(r);

    return DONE;
}

static int dav_method_report(request_rec *r)
{
    dav_resource *resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    int result;
    int target_allowed;
    ap_xml_doc *doc;
    ap_text_header hdr = { 0 };
    ap_text *t;
    dav_error *err;

    /* If no versioning provider, decline the request */
    if (vsn_hooks == NULL)
        return DECLINED;

    if ((result = ap_xml_parse_input(r, &doc)) != OK)
	return result;
    if (doc == NULL) {
        /* This supplies additional information for the default msg. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
                      "The request body must specify a report.");
        return HTTP_BAD_REQUEST;
    }

    /* Ask repository module to resolve the resource.
     * First determine whether a Target-Selector header is allowed
     * for this report.
     */
    target_allowed = (*vsn_hooks->report_target_selector_allowed)(doc);
    result = dav_get_resource(r, target_allowed, NULL, &resource);
    if (result != OK)
        return result;
    if (!resource->exists) {
        /* Apache will supply a default error for this. */
        return HTTP_NOT_FOUND;
    }

    /* run report hook */
    /* ### writing large reports to memory could be bad...
     * ### but if provider generated output directly, it would
     * ### have to handle error responses as well.
     */
    if ((err = (*vsn_hooks->get_report)(r, resource, doc, &hdr)) != NULL)
	return dav_handle_err(r, err, NULL);

    /* send the report response */
    r->status = HTTP_OK;
    r->content_type = DAV_XML_CONTENT_TYPE;

    /* send the headers and start a timeout */
    ap_send_http_header(r);

    /* send the response body */
    ap_rputs(DAV_XML_HEADER DEBUG_CR, r);

    for (t = hdr.first; t != NULL; t = t->next)
        ap_rputs(t->text, r);

    return DONE;
}

static int dav_method_make_workspace(request_rec *r)
{
    dav_resource *resource;
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err;
    ap_xml_doc *doc;
    int result;

    /* if no versioning provider, or the provider does not support workspaces,
     * decline the request
     */
    if (vsn_hooks == NULL || vsn_hooks->make_workspace == NULL)
        return DECLINED;

    /* ask repository module to resolve the resource */
    result = dav_get_resource(r, 0 /*target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;

    /* parse the request body (must be a mkworkspace element) */
    if ((result = ap_xml_parse_input(r, &doc)) != OK) {
	return result;
    }

    if (doc == NULL
        || !dav_validate_root(doc, "mkworkspace")) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "The request body does not contain "
		      "a \"mkworkspace\" element.");
	return HTTP_BAD_REQUEST;
    }

    /* Check request preconditions */

    /* ### need a general mechanism for reporting precondition violations
     * ### (should be returning XML document for 403/409 responses)
     */

    /* resource must not already exist */
    if (resource->exists) {
        err = dav_new_error(r->pool, HTTP_CONFLICT, 0,
                            "<DAV:resource-must-be-null/>");
	return dav_handle_err(r, err, NULL);
    }

    /* ### what about locking? */

    /* attempt to create the workspace */
    if ((err = (*vsn_hooks->make_workspace)(resource, doc)) != NULL) {
	err = dav_push_error(r->pool, HTTP_CONFLICT, 0,
			     apr_psprintf(r->pool,
					 "Could not create workspace %s.",
					 ap_escape_html(r->pool, r->uri)),
			     err);
        return dav_handle_err(r, err, NULL);
    }

    /* set the Cache-Control header, per the spec */
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");

    /* return an appropriate response (HTTP_CREATED) */
    return dav_created(r, resource->uri, "Workspace", 0 /*replaced*/);
}

static int dav_method_make_activity(request_rec *r)
{
    /* ### */
    return HTTP_METHOD_NOT_ALLOWED;
}

static int dav_method_baseline_control(request_rec *r)
{
    /* ### */
    return HTTP_METHOD_NOT_ALLOWED;
}

static int dav_method_merge(request_rec *r)
{
    /* ### */
    return HTTP_METHOD_NOT_ALLOWED;
}

static int dav_method_bind(request_rec *r)
{
    dav_resource *resource;
    dav_resource *binding;
    dav_auto_version_info av_info;
    const dav_hooks_binding *binding_hooks = DAV_GET_HOOKS_BINDING(r);
    const char *dest;
    dav_error *err;
    dav_error *err2;
    dav_response *multi_response = NULL;
    dav_lookup_result lookup;
    int overwrite;
    int result;

    /* If no bindings provider, decline the request */
    if (binding_hooks == NULL)
        return DECLINED;

    /* Ask repository module to resolve the resource */
    result = dav_get_resource(r, 0 /*!target_allowed*/, NULL, &resource);
    if (result != OK)
        return result;
    if (!resource->exists) {
	/* Apache will supply a default error for this. */
	return HTTP_NOT_FOUND;
    }

    /* get the destination URI */
    dest = apr_table_get(r->headers_in, "Destination");
    if (dest == NULL) {
	/* This supplies additional information for the default message. */
	ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		      "The request is missing a Destination header.");
	return HTTP_BAD_REQUEST;
    }

    lookup = dav_lookup_uri(dest, r);
    if (lookup.rnew == NULL) {
	if (lookup.err.status == HTTP_BAD_REQUEST) {
	    /* This supplies additional information for the default message. */
	    ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
			  lookup.err.desc);
	    return HTTP_BAD_REQUEST;
	}
        else if (lookup.err.status == HTTP_BAD_GATEWAY) {
            /* ### Bindings protocol draft 02 says to return 507
             * ### (Cross Server Binding Forbidden); Apache already defines 507
             * ### as HTTP_INSUFFICIENT_STORAGE. So, for now, we'll return
             * ### HTTP_FORBIDDEN
             */
             return dav_error_response(r, HTTP_FORBIDDEN,
                                       "Cross server bindings are not allowed by this server.");
        }

	/* ### this assumes that dav_lookup_uri() only generates a status
	 * ### that Apache can provide a status line for!! */

	return dav_error_response(r, lookup.err.status, lookup.err.desc);
    }
    if (lookup.rnew->status != HTTP_OK) {
	/* ### how best to report this... */
	return dav_error_response(r, lookup.rnew->status,
				  "Destination URI had an error.");
    }

    /* resolve binding resource */
    result = dav_get_resource(lookup.rnew, 0 /*!target_allowed*/, NULL, &binding);
    if (result != OK)
        return result;

    /* are the two resources handled by the same repository? */
    if (resource->hooks != binding->hooks) {
	/* ### this message exposes some backend config, but screw it... */
	return dav_error_response(r, HTTP_BAD_GATEWAY,
				  "Destination URI is handled by a "
				  "different repository than the source URI. "
				  "BIND between repositories is not possible.");
    }

    /* get and parse the overwrite header value */
    if ((overwrite = dav_get_overwrite(r)) < 0) {
	/* dav_get_overwrite() supplies additional information for the
	 * default message. */
	return HTTP_BAD_REQUEST;
    }

    /* quick failure test: if dest exists and overwrite is false. */
    if (binding->exists && !overwrite) {
	return dav_error_response(r, HTTP_PRECONDITION_FAILED,
			          "Destination is not empty and "
			          "Overwrite is not \"T\"");
    }

    /* are the source and destination the same? */
    if ((*resource->hooks->is_same_resource)(resource, binding)) {
	return dav_error_response(r, HTTP_FORBIDDEN,
			          "Source and Destination URIs are the same.");
    }

    /*
    ** Check If-Headers and existing locks for destination. Note that we
    ** use depth==infinity since the target (hierarchy) will be deleted
    ** before the move/copy is completed.
    **
    ** Note that we are overwriting the target, which implies a DELETE, so
    ** we are subject to the error/response rules as a DELETE. Namely, we
    ** will return a 424 error if any of the validations fail.
    ** (see dav_method_delete() for more information)
    */
    if ((err = dav_validate_request(lookup.rnew, binding, DAV_INFINITY, NULL,
				    &multi_response,
				    DAV_VALIDATE_PARENT
                                    | DAV_VALIDATE_USE_424, NULL)) != NULL) {
	err = dav_push_error(r->pool, err->status, 0,
			     apr_psprintf(r->pool,
					 "Could not BIND %s due to a "
					 "failed precondition on the "
					 "destination (e.g. locks).",
					 ap_escape_html(r->pool, r->uri)),
			     err);
	return dav_handle_err(r, err, multi_response);
    }

    /* guard against creating circular bindings */
    if (resource->collection
	&& (*resource->hooks->is_parent_resource)(resource, binding)) {
	return dav_error_response(r, HTTP_FORBIDDEN,
			          "Source collection contains the Destination.");
    }
    if (resource->collection
	&& (*resource->hooks->is_parent_resource)(binding, resource)) {
	/* The destination must exist (since it contains the source), and
	 * a condition above implies Overwrite==T. Obviously, we cannot
	 * delete the Destination before the BIND, as that would
	 * delete the Source.
	 */

	return dav_error_response(r, HTTP_FORBIDDEN,
			          "Destination collection contains the Source and "
			          "Overwrite has been specified.");
    }

    /* prepare the destination collection for modification */
    if ((err = dav_ensure_resource_writable(r, binding, 1 /* parent_only */,
					    &av_info)) != NULL) {
        /* could not make destination writable */
	return dav_handle_err(r, err, NULL);
    }

    /* If target exists, remove it first (we know Ovewrite must be TRUE).
     * Then try to bind to the resource.
     */
    if (binding->exists)
	err = (*resource->hooks->remove_resource)(binding, &multi_response);

    if (err == NULL) {
	err = (*binding_hooks->bind_resource)(resource, binding);
    }

    /* restore parent collection states */
    err2 = dav_revert_resource_writability(r, NULL,
					   err != NULL /* undo if error */,
					   &av_info);

    /* check for error from remove/bind operations */
    if (err != NULL) {
	err = dav_push_error(r->pool, err->status, 0,
			     apr_psprintf(r->pool,
					 "Could not BIND %s.",
					 ap_escape_html(r->pool, r->uri)),
			     err);
	return dav_handle_err(r, err, multi_response);
    }

    /* check for errors from reverting writability */
    if (err2 != NULL) {
	/* just log a warning */
	err = dav_push_error(r->pool, err2->status, 0,
			     "The BIND was successful, but there was a "
			     "problem reverting the writability of the "
			     "source parent collection.",
			     err2);
	dav_log_err(r, err, APLOG_WARNING);
    }

    /* return an appropriate response (HTTP_CREATED) */
    /* ### spec doesn't say what happens when destination was replaced */
    return dav_created(r, lookup.rnew->uri, "Binding", 0);
}


/*
 * Response handler for DAV resources
 */
static int dav_handler(request_rec *r)
{
    dav_dir_conf *conf;

    /* quickly ignore any HTTP/0.9 requests */
    if (r->assbackwards) {
	return DECLINED;
    }

    /* ### do we need to do anything with r->proxyreq ?? */

    conf = (dav_dir_conf *) ap_get_module_config(r->per_dir_config,
						 &dav_module);

    /*
     * Set up the methods mask, since that's one of the reasons this handler
     * gets called, and lower-level things may need the info.
     *
     * First, set the mask to the methods we handle directly.  Since by
     * definition we own our managed space, we unconditionally set
     * the r->allowed field rather than ORing our values with anything
     * any other module may have put in there.
     *
     * These are the HTTP-defined methods that we handle directly.
     */
    r->allowed = 0
        | (1 << M_GET)
	| (1 << M_PUT)
	| (1 << M_DELETE)
	| (1 << M_OPTIONS)
	| (1 << M_INVALID);
    /*
     * These are the DAV methods we handle.
     */
    r->allowed |= 0
	| (1 << M_COPY)
	| (1 << M_LOCK)
	| (1 << M_UNLOCK)
	| (1 << M_MKCOL)
	| (1 << M_MOVE)
	| (1 << M_PROPFIND)
	| (1 << M_PROPPATCH);
    /*
     * These are methods that we don't handle directly, but let the
     * server's default handler do for us as our agent.
     */
    r->allowed |= 0
	| (1 << M_POST);
 
    /* ### hrm. if we return HTTP_METHOD_NOT_ALLOWED, then an Allow header
     * ### is sent; it will need the other allowed states; since the default
     * ### handler is not called on error, then it doesn't add the other
     * ### allowed states, so we must */
    /* ### we might need to refine this for just where we return the error.
     * ### also, there is the issue with other methods (see ISSUES) */
    /* ### more work necessary, now that we have M_foo for DAV methods */

    /* dispatch the appropriate method handler */
    if (r->method_number == M_GET) {
	return dav_method_get(r);
    }

    if (r->method_number == M_PUT) {
	return dav_method_put(r);
    }

    if (r->method_number == M_POST) {
	return dav_method_post(r);
    }

    if (r->method_number == M_DELETE) {
	return dav_method_delete(r);
    }

    if (r->method_number == M_OPTIONS) {
	return dav_method_options(r);
    }

    if (r->method_number == M_PROPFIND) {
	return dav_method_propfind(r);
    }

    if (r->method_number == M_PROPPATCH) {
	return dav_method_proppatch(r);
    }

    if (r->method_number == M_MKCOL) {
	return dav_method_mkcol(r);
    }

    if (r->method_number == M_COPY) {
	return dav_method_copymove(r, DAV_DO_COPY);
    }

    if (r->method_number == M_MOVE) {
	return dav_method_copymove(r, DAV_DO_MOVE);
    }

    if (r->method_number == M_LOCK) {
	return dav_method_lock(r);
    }

    if (r->method_number == M_UNLOCK) {
	return dav_method_unlock(r);
    }

    /*
     * NOTE: When Apache moves creates defines for the add'l DAV methods,
     *       then it will no longer use M_INVALID. This code must be
     *       updated each time Apache adds method defines.
     */
    if (r->method_number != M_INVALID) {
	return DECLINED;
    }

    if (!strcmp(r->method, "VERSION-CONTROL")) {
	return dav_method_vsn_control(r);
    }

    if (!strcmp(r->method, "CHECKOUT")) {
	return dav_method_checkout(r);
    }

    if (!strcmp(r->method, "UNCHECKOUT")) {
	return dav_method_uncheckout(r);
    }

    if (!strcmp(r->method, "CHECKIN")) {
	return dav_method_checkin(r);
    }

    if (!strcmp(r->method, "SET-TARGET")) {
	return dav_method_set_target(r);
    }

    if (!strcmp(r->method, "LABEL")) {
	return dav_method_label(r);
    }

    if (!strcmp(r->method, "REPORT")) {
	return dav_method_report(r);
    }

    if (!strcmp(r->method, "MKWORKSPACE")) {
	return dav_method_make_workspace(r);
    }

    if (!strcmp(r->method, "MKACTIVITY")) {
	return dav_method_make_activity(r);
    }

    if (!strcmp(r->method, "BASELINE-CONTROL")) {
	return dav_method_baseline_control(r);
    }

    if (!strcmp(r->method, "MERGE")) {
	return dav_method_merge(r);
    }

    if (!strcmp(r->method, "BIND")) {
	return dav_method_bind(r);
    }

    /* ### add'l methods for Advanced Collections, ACLs, DASL */

    return DECLINED;
}

static int dav_type_checker(request_rec *r)
{
    dav_dir_conf *conf;

    conf = (dav_dir_conf *) ap_get_module_config(r->per_dir_config,
						 &dav_module);

    /* if DAV is not enabled, then we've got nothing to do */
    if (conf->provider == NULL) {
	return DECLINED;
    }

    if (r->method_number == M_GET) {
	/*
	** ### need some work to pull Content-Type and Content-Language
	** ### from the property database.
	*/
	    
	/*
	** If the repository hasn't indicated that it will handle the
	** GET method, then just punt.
	**
	** ### this isn't quite right... taking over the response can break
	** ### things like mod_negotiation. need to look into this some more.
	*/
	if (!conf->provider->repos->handle_get) {
	    return DECLINED;
        }
    }

    /* ### we should (instead) trap the ones that we DO understand */
    /* ### the handler DOES handle POST, so we need to fix one of these */
    if (r->method_number != M_POST) {

	/*
	** ### anything else to do here? could another module and/or
	** ### config option "take over" the handler here? i.e. how do
	** ### we lock down this hierarchy so that we are the ultimate
	** ### arbiter? (or do we simply depend on the administrator
	** ### to avoid conflicting configurations?)
	**
	** ### I think the OK stops running type-checkers. need to look.
	*/
	r->handler = "dav-handler";
	return OK;
    }

    return DECLINED;
}

static void register_hooks(void)
{
    ap_hook_post_config(dav_init_handler, NULL, NULL, AP_HOOK_MIDDLE);
    ap_hook_type_checker(dav_type_checker, NULL, NULL, AP_HOOK_FIRST);
}

/*---------------------------------------------------------------------------
**
** Configuration info for the module
*/

static const command_rec dav_cmds[] =
{
    /* per directory/location */
    AP_INIT_TAKE1("DAV", dav_cmd_dav, NULL, ACCESS_CONF,
                  "specify the DAV provider for a directory or location"),

    /* per directory/location, or per server */
    AP_INIT_TAKE1("DAVMinTimeout", dav_cmd_davmintimeout, NULL,
                  ACCESS_CONF|RSRC_CONF,
                  "specify minimum allowed timeout"),

    /* per directory/location, or per server */
    AP_INIT_FLAG("DAVDepthInfinity", dav_cmd_davdepthinfinity, NULL,
                 ACCESS_CONF|RSRC_CONF,
                 "allow Depth infinity PROPFIND requests"),

    /* per directory/location, or per server */
    AP_INIT_TAKE2("DAVParam", dav_cmd_davparam, NULL,
                  ACCESS_CONF|RSRC_CONF,
                  "DAVParam <parameter name> <parameter value>"),

    { NULL }
};

static const handler_rec dav_handlers[] =
{
    {"dav-handler", dav_handler},
    { NULL }
};

module DAV_DECLARE_DATA dav_module =
{
    STANDARD20_MODULE_STUFF,
    dav_create_dir_config,	/* dir config creater */
    dav_merge_dir_config,	/* dir merger --- default is to override */
    dav_create_server_config,	/* server config */
    dav_merge_server_config,	/* merge server config */
    dav_cmds,			/* command table */
    dav_handlers,		/* handlers */
    register_hooks,             /* register hooks */
};

AP_HOOK_STRUCT(
    AP_HOOK_LINK(gather_propsets)
    AP_HOOK_LINK(find_liveprop)
    AP_HOOK_LINK(insert_all_liveprops)
    )
AP_IMPLEMENT_EXTERNAL_HOOK_VOID(DAV, gather_propsets,
                                (apr_array_header_t *uris),
                                (uris))
AP_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(DAV, int, find_liveprop,
                                     (request_rec *r, const char *ns_uri,
                                      const char *name,
                                      const dav_hooks_liveprop **hooks),
                                     (r, ns_uri, name, hooks), 0);
AP_IMPLEMENT_EXTERNAL_HOOK_VOID(DAV, insert_all_liveprops,
                                (request_rec *r, const dav_resource *resource,
                                 int insvalue, ap_text_header *phdr),
                                (r, resource, insvalue, phdr));
