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
 * http_auth: authentication
 * 
 * Rob McCool & Brian Behlendorf.
 * 
 * Adapted to Apache by rst.
 *
 * dirkx - Added Authoritative control to allow passing on to lower  
 *         modules if and only if the userid is not known to this
 *         module. A known user with a faulty or absent password still
 *         causes an AuthRequired. The default is 'Authoritative', i.e.
 *         no control is passed along.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/
#include "apr_lib.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#if defined(AP_AUTH_DBM_USE_APR)
#include "apr_dbm.h"
#define DBM apr_dbm_t
#define datum apr_datum_t
#define dbm_open apr_dbm_open
#define dbm_fetch apr_dbm_fetch
#define dbm_close apr_dbm_close
#elif defined(__GLIBC__) && defined(__GLIBC_MINOR__) \
    && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
#include <db1/ndbm.h>
#else
#include <ndbm.h>
#endif

/*
 * Module definition information - the part between the -START and -END
 * lines below is used by Configure. This could be stored in a separate
 * instead.
 *
 * XXX: this needs updating for apache-2.0 configuration method
 * MODULE-DEFINITION-START
 * Name: dbm_auth_module
 * ConfigStart
    . ./helpers/find-dbm-lib
 * ConfigEnd
 * MODULE-DEFINITION-END
 */

typedef struct {

    char *auth_dbmpwfile;
    char *auth_dbmgrpfile;
    int auth_dbmauthoritative;

} dbm_auth_config_rec;

static void *create_dbm_auth_dir_config(apr_pool_t *p, char *d)
{
    dbm_auth_config_rec *sec
    = (dbm_auth_config_rec *) apr_pcalloc(p, sizeof(dbm_auth_config_rec));

    sec->auth_dbmpwfile = NULL;
    sec->auth_dbmgrpfile = NULL;
    sec->auth_dbmauthoritative = 1;	/* fortress is secure by default */

    return sec;
}

static const char *set_dbm_slot(cmd_parms *cmd, void *offset, const char *f, const char *t)
{
    if (!t || strcmp(t, "dbm"))
	return DECLINE_CMD;

    return ap_set_file_slot(cmd, offset, f);
}

static const command_rec dbm_auth_cmds[] =
{
    AP_INIT_TAKE1("AuthDBMUserFile", ap_set_file_slot,
     (void *) XtOffsetOf(dbm_auth_config_rec, auth_dbmpwfile),
     OR_AUTHCFG, NULL),
    AP_INIT_TAKE1("AuthDBMGroupFile", ap_set_file_slot,
     (void *) XtOffsetOf(dbm_auth_config_rec, auth_dbmgrpfile),
     OR_AUTHCFG, NULL),
    AP_INIT_TAKE12("AuthUserFile", set_dbm_slot,
     (void *) XtOffsetOf(dbm_auth_config_rec, auth_dbmpwfile),
     OR_AUTHCFG, NULL),
    AP_INIT_TAKE12("AuthGroupFile", set_dbm_slot,
     (void *) XtOffsetOf(dbm_auth_config_rec, auth_dbmgrpfile),
     OR_AUTHCFG, NULL),
    AP_INIT_FLAG("AuthDBMAuthoritative", ap_set_flag_slot,
     (void *) XtOffsetOf(dbm_auth_config_rec, auth_dbmauthoritative),
     OR_AUTHCFG, "Set to 'no' to allow access control to be passed along to lower modules, if the UserID is not known in this module"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA dbm_auth_module;

static char *get_dbm_pw(request_rec *r, char *user, char *auth_dbmpwfile)
{
    DBM *f;
    datum d, q;
    char *pw = NULL;
#ifdef AP_AUTH_DBM_USE_APR
    apr_status_t retval;
#endif
    q.dptr = user;
#ifndef NETSCAPE_DBM_COMPAT
    q.dsize = strlen(q.dptr);
#else
    q.dsize = strlen(q.dptr) + 1;
#endif

#ifdef AP_AUTH_DBM_USE_APR
    if (!(retval = dbm_open(&f, auth_dbmpwfile, APR_DBM_READONLY, r->pool))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, retval, r,
		    "could not open sdbm auth file: %s", auth_dbmpwfile);
	return NULL;
    }
    if (dbm_fetch(f, q, &d) == APR_SUCCESS)
        /* sorry for the obscurity ... falls through to the 
         * if (d.dptr) {  block ...
         */

#else
    if (!(f = dbm_open(auth_dbmpwfile, O_RDONLY, 0664))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
		    "could not open dbm auth file: %s", auth_dbmpwfile);
	return NULL;
    }
    d = dbm_fetch(f, q);

#endif

    if (d.dptr) {
	pw = apr_palloc(r->pool, d.dsize + 1);
	strncpy(pw, d.dptr, d.dsize);
	pw[d.dsize] = '\0';	/* Terminate the string */
    }

    dbm_close(f);
    return pw;
}

/* We do something strange with the group file.  If the group file
 * contains any : we assume the format is
 *      key=username value=":"groupname [":"anything here is ignored]
 * otherwise we now (0.8.14+) assume that the format is
 *      key=username value=groupname
 * The first allows the password and group files to be the same 
 * physical DBM file;   key=username value=password":"groupname[":"anything]
 *
 * mark@telescope.org, 22Sep95
 */

static char *get_dbm_grp(request_rec *r, char *user, char *auth_dbmgrpfile)
{
    char *grp_data = get_dbm_pw(r, user, auth_dbmgrpfile);
    char *grp_colon;
    char *grp_colon2;

    if (grp_data == NULL)
	return NULL;

    if ((grp_colon = strchr(grp_data, ':')) != NULL) {
	grp_colon2 = strchr(++grp_colon, ':');
	if (grp_colon2)
	    *grp_colon2 = '\0';
	return grp_colon;
    }
    return grp_data;
}

static int dbm_authenticate_basic_user(request_rec *r)
{
    dbm_auth_config_rec *sec =
    (dbm_auth_config_rec *) ap_get_module_config(r->per_dir_config,
					      &dbm_auth_module);
    const char *sent_pw;
    char *real_pw, *colon_pw;
    apr_status_t invalid_pw;
    int res;

    if ((res = ap_get_basic_auth_pw(r, &sent_pw)))
	return res;

    if (!sec->auth_dbmpwfile)
	return DECLINED;

    if (!(real_pw = get_dbm_pw(r, r->user, sec->auth_dbmpwfile))) {
	if (!(sec->auth_dbmauthoritative))
	    return DECLINED;
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		    "DBM user %s not found: %s", r->user, r->filename);
	ap_note_basic_auth_failure(r);
	return HTTP_UNAUTHORIZED;
    }
    /* Password is up to first : if exists */
    colon_pw = strchr(real_pw, ':');
    if (colon_pw) {
	*colon_pw = '\0';
    }
    invalid_pw = apr_password_validate(sent_pw, real_pw);
    if (invalid_pw != APR_SUCCESS) {
	ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		      "DBM user %s: authentication failure for \"%s\": "
                      "Password Mismatch",
		      r->user, r->uri);
	ap_note_basic_auth_failure(r);
	return HTTP_UNAUTHORIZED;
    }
    return OK;
}

/* Checking ID */

static int dbm_check_auth(request_rec *r)
{
    dbm_auth_config_rec *sec =
    (dbm_auth_config_rec *) ap_get_module_config(r->per_dir_config,
					      &dbm_auth_module);
    char *user = r->user;
    int m = r->method_number;

    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

    register int x;
    const char *t;
    char *w;

    if (!sec->auth_dbmgrpfile)
	return DECLINED;
    if (!reqs_arr)
	return DECLINED;

    for (x = 0; x < reqs_arr->nelts; x++) {

	if (!(reqs[x].method_mask & (1 << m)))
	    continue;

	t = reqs[x].requirement;
	w = ap_getword_white(r->pool, &t);

	if (!strcmp(w, "group") && sec->auth_dbmgrpfile) {
	    const char *orig_groups, *groups;
	    char *v;

	    if (!(groups = get_dbm_grp(r, user, sec->auth_dbmgrpfile))) {
		if (!(sec->auth_dbmauthoritative))
		    return DECLINED;
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			    "user %s not in DBM group file %s: %s",
			    user, sec->auth_dbmgrpfile, r->filename);
		ap_note_basic_auth_failure(r);
		return HTTP_UNAUTHORIZED;
	    }
	    orig_groups = groups;
	    while (t[0]) {
		w = ap_getword_white(r->pool, &t);
		groups = orig_groups;
		while (groups[0]) {
		    v = ap_getword(r->pool, &groups, ',');
		    if (!strcmp(v, w))
			return OK;
		}
	    }
	    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			"user %s not in right group: %s",
			user, r->filename);
	    ap_note_basic_auth_failure(r);
	    return HTTP_UNAUTHORIZED;
	}
    }

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(dbm_authenticate_basic_user, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker(dbm_check_auth, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA dbm_auth_module =
{
    STANDARD20_MODULE_STUFF,
    create_dbm_auth_dir_config,	/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server config */
    dbm_auth_cmds,		/* command apr_table_t */
    register_hooks              /* register hooks */
};
