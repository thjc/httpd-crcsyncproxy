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

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_scache.c
 *  Session Cache Abstraction
 */
                             /* ``Open-Source Software: generous
                                  programmers from around the world all
                                  join forces to help you shoot
                                  yourself in the foot for free.''
                                                 -- Unknown         */
#include "ssl_private.h"
#include "mod_status.h"

/*  _________________________________________________________________
**
**  Session Cache: Common Abstraction Layer
**  _________________________________________________________________
*/

void ssl_scache_init(server_rec *s, apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    apr_status_t rv;
    void *data;
    const char *userdata_key = "ssl_scache_init";
    
    /* The very first invocation of this function will be the
     * post_config invocation during server startup; do nothing for
     * this first (and only the first) time through, since the pool
     * will be immediately cleared anyway.  For every subsequent
     * invocation, initialize the configured cache. */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
        return;
    }

    /*
     * Warn the user that he should use the session cache.
     * But we can operate without it, of course.
     */
    if (mc->sesscache == NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "Init: Session Cache is not configured "
                     "[hint: SSLSessionCache]");
        return;
    }

    rv = mc->sesscache->init(s, &mc->sesscache_context, p);
    if (rv) {
        /* ABORT ABORT etc. */
        ssl_die();
    }
}

void ssl_scache_kill(server_rec *s)
{
    SSLModConfigRec *mc = myModConfig(s);
    
    if (mc->sesscache) {
        mc->sesscache->destroy(mc->sesscache_context, s);
    }
}

BOOL ssl_scache_store(server_rec *s, UCHAR *id, int idlen,
                      time_t expiry, SSL_SESSION *sess,
                      apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    unsigned char encoded[SSL_SESSION_MAX_DER], *ptr;
    unsigned int len;

    /* Serialise the session. */
    len = i2d_SSL_SESSION(sess, NULL);
    if (len > sizeof encoded) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "session is too big (%u bytes)", len);
        return FALSE;
    }

    ptr = encoded;
    len = i2d_SSL_SESSION(sess, &ptr);

    return mc->sesscache->store(mc->sesscache_context, s, id, idlen, 
                                expiry, encoded, len);
}

SSL_SESSION *ssl_scache_retrieve(server_rec *s, UCHAR *id, int idlen,
                                 apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);
    unsigned char dest[SSL_SESSION_MAX_DER];
    unsigned int destlen = SSL_SESSION_MAX_DER;
    MODSSL_D2I_SSL_SESSION_CONST unsigned char *ptr;
    
    if (mc->sesscache->retrieve(mc->sesscache_context, s, id, idlen, 
                                dest, &destlen, p) == FALSE) {
        return NULL;
    }

    ptr = dest;

    return d2i_SSL_SESSION(NULL, &ptr, destlen);
}

void ssl_scache_remove(server_rec *s, UCHAR *id, int idlen,
                       apr_pool_t *p)
{
    SSLModConfigRec *mc = myModConfig(s);

    mc->sesscache->delete(mc->sesscache_context, s, id, idlen, p);

    return;
}

/*  _________________________________________________________________
**
**  SSL Extension to mod_status
**  _________________________________________________________________
*/
static int ssl_ext_status_hook(request_rec *r, int flags)
{
    SSLModConfigRec *mc = myModConfig(r->server);

    if (mc == NULL || flags & AP_STATUS_SHORT)
        return OK;

    ap_rputs("<hr>\n", r);
    ap_rputs("<table cellspacing=0 cellpadding=0>\n", r);
    ap_rputs("<tr><td bgcolor=\"#000000\">\n", r);
    ap_rputs("<b><font color=\"#ffffff\" face=\"Arial,Helvetica\">SSL/TLS Session Cache Status:</font></b>\r", r);
    ap_rputs("</td></tr>\n", r);
    ap_rputs("<tr><td bgcolor=\"#ffffff\">\n", r);

    mc->sesscache->status(mc->sesscache_context, r, flags, r->pool);

    ap_rputs("</td></tr>\n", r);
    ap_rputs("</table>\n", r);
    return OK;
}

void ssl_scache_status_register(apr_pool_t *p)
{
    APR_OPTIONAL_HOOK(ap, status_hook, ssl_ext_status_hook, NULL, NULL,
                      APR_HOOK_MIDDLE);
}

