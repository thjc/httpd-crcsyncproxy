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

#include "apr_strings.h"
#include "apr_md5.h"            /* for apr_password_validate */

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"


typedef struct {
    int authoritative;
} authz_default_config_rec;

static void *create_authz_default_dir_config(apr_pool_t *p, char *d)
{
    authz_default_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->authoritative = 1; /* keep the fortress secure by default */
    return conf;
}

static const command_rec authz_default_cmds[] =
{
    AP_INIT_FLAG("AuthzDefaultAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authz_default_config_rec, authoritative),
                 OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules. (default is On.)"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_default_module;

static int check_user_access(request_rec *r)
{
    authz_default_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                 &authz_default_module);
    const char *note = apr_table_get(r->notes, AUTHZ_ACCESS_PASSED_NOTE);

    /* If we got here and access checker passed, assume access is OK */
    if (note && (note[0] == 'Y') && (ap_satisfies(r) == SATISFY_ANY)) {
        return OK;
    }

    /* If we got here and there isn't any authz required, assume access is OK */
    if (!ap_some_auth_required(r)) {
        return OK;
    }

    if (!(conf->authoritative)) {
        return DECLINED;
    }

    /* if we aren't authoritative, any require directive could be
     * considered valid even if noone groked it.  However, if we are
     * authoritative, we can warn the user they did something wrong.
     *
     * That something could be a missing "AuthAuthoritative off", but
     * more likely is a typo in the require directive.
     */
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "access to %s failed, reason: require directives "
                          "present and no Authoritative handler.", r->uri);

    ap_note_auth_failure(r);
    return HTTP_UNAUTHORIZED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_authz(check_user_access, NULL, NULL, APR_HOOK_LAST,
                        AP_AUTH_INTERNAL_PER_CONF);
}

module AP_MODULE_DECLARE_DATA authz_default_module =
{
    STANDARD20_MODULE_STUFF,
    create_authz_default_dir_config, /* dir config creater */
    NULL,                            /* dir merger --- default is to override */
    NULL,                            /* server config */
    NULL,                            /* merge server config */
    authz_default_cmds,              /* command apr_table_t */
    register_hooks                   /* register hooks */
};
