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
 * Info Module.  Display configuration information for the server and
 * all included modules.
 *
 * <Location /server-info>
 * SetHandler server-info
 * </Location>
 *
 * GET /server-info - Returns full configuration page for server and all modules
 * GET /server-info?server - Returns server configuration only
 * GET /server-info?module_name - Returns configuration for a single module
 * GET /server-info?list - Returns quick list of included modules
 *
 * Rasmus Lerdorf <rasmus@vex.net>, May 1996
 *
 * 05.01.96 Initial Version
 *
 * Lou Langholtz <ldl@usi.utah.edu>, July 1997
 *
 * 07.11.97 Addition of the AddModuleInfo directive
 *
 * Ryan Morgan <rmorgan@covalent.net>
 * 
 * 8.11.00 Port to Apache 2.0.  Read configuation from the configuration
 * tree rather than reparse the entire configuation file.
 * 
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"
#include "http_conf_globals.h"
#if APR_HAVE_STRINGS_H
#include <strings.h>
#endif

typedef struct {
    const char *name;                 /* matching module name */
    const char *info;                 /* additional info */
} info_entry;

typedef struct {
    apr_array_header_t *more_info;
} info_svr_conf;

module AP_MODULE_DECLARE_DATA info_module;

extern module *top_module;
extern ap_directive_t *ap_conftree;

static void *create_info_config(apr_pool_t *p, server_rec *s)
{
    info_svr_conf *conf = (info_svr_conf *) apr_pcalloc(p, sizeof(info_svr_conf));

    conf->more_info = apr_array_make(p, 20, sizeof(info_entry));
    return conf;
}

static void *merge_info_config(apr_pool_t *p, void *basev, void *overridesv)
{
    info_svr_conf *new = (info_svr_conf *) apr_pcalloc(p, sizeof(info_svr_conf));
    info_svr_conf *base = (info_svr_conf *) basev;
    info_svr_conf *overrides = (info_svr_conf *) overridesv;

    new->more_info = apr_array_append(p, overrides->more_info, base->more_info);
    return new;
}

static char *mod_info_html_cmd_string(const char *string, char *buf, size_t buf_len, int close)
{
    const char *s;
    char *t;
    char *end_buf;

    s = string;
    t = buf;
    /* keep space for \0 byte */
    end_buf = buf + buf_len - 1;
    while ((*s) && (t < end_buf)) {
        if (*s == '<') {
	    if (close) {
	        strncpy(t, "&lt;/,", end_buf -t);
	        t += 5;
	    } else {
                strncpy(t, "&lt;", end_buf - t);
                t += 4;
	    }
        }
        else if (*s == '>') {
            strncpy(t, "&gt;", end_buf - t);
            t += 4;
        }
        else if (*s == '&') {
            strncpy(t, "&amp;", end_buf - t);
            t += 5;
        }
	else if (*s == ' ') {
	    if (close) {
	        strncpy(t, "&gt;", end_buf -t);
	        t += 4;
	        break;
	    } else {
	      *t++ = *s;
            }
	} else {
            *t++ = *s;
        }
        s++;
    }
    /* oops, overflowed... don't overwrite */
    if (t > end_buf) {
	*end_buf = '\0';
    }
    else {
	*t = '\0';
    }
    return (buf);
}

static void mod_info_module_cmds(request_rec * r, const command_rec * cmds,
				 ap_directive_t * conftree)
{
    const command_rec *cmd;
    ap_directive_t *tmptree = conftree;

    char buf[MAX_STRING_LEN];
    char htmlstring[MAX_STRING_LEN];
    int block_start = 0;
    int nest = 0;

    while (tmptree != NULL) {
	cmd = cmds;
	while (cmd->name) {
	    if (!strcasecmp(cmd->name, tmptree->directive)) {
		if (nest > block_start) {
		    block_start++;
		    apr_snprintf(htmlstring, sizeof(htmlstring), "%s %s",
				tmptree->parent->directive,
				tmptree->parent->args);
		    ap_rprintf(r, "<dd><tt>%s</tt><br>\n",
			       mod_info_html_cmd_string(htmlstring, buf,
							sizeof(buf), 0));
		}
		if (nest == 2) {
		    ap_rprintf(r, "<dd><tt>&nbsp;&nbsp;&nbsp;&nbsp;%s "
			       "<i>%s</i></tt><br>\n",
			       tmptree->directive, tmptree->args);
		} else if (nest == 1) {
		    ap_rprintf(r,
			       "<dd><tt>&nbsp;&nbsp;%s <i>%s</i></tt><br>\n",
			       tmptree->directive, tmptree->args);
		} else {
		    ap_rprintf(r, "<dd><tt>%s <i>%s</i></tt><br>\n",
			       mod_info_html_cmd_string(tmptree->directive,
							buf, sizeof(buf),
							0), tmptree->args);
		}
	    }
	    ++cmd;
	}
	if (tmptree->first_child != NULL) {
	    tmptree = tmptree->first_child;
	    nest++;
	} else if (tmptree->next != NULL) {
	    tmptree = tmptree->next;
	} else {
	    if (block_start) {
		apr_snprintf(htmlstring, sizeof(htmlstring), "%s %s",
			    tmptree->parent->directive,
			    tmptree->parent->args);
		ap_rprintf(r, "<dd><tt>%s</tt><br>\n",
			   mod_info_html_cmd_string(htmlstring, buf,
						    sizeof(buf), 1));
		block_start--;
	    }
            if (tmptree->parent) {
                tmptree = tmptree->parent->next;
            }
            else {
                tmptree = NULL;
            }
	    nest--;
	}

    }
}
static const char *find_more_info(server_rec *s, const char *module_name)
{
    int i;
    info_svr_conf *conf = (info_svr_conf *) ap_get_module_config(s->module_config,
                                                              &info_module);
    info_entry *entry = (info_entry *) conf->more_info->elts;

    if (!module_name) {
        return 0;
    }
    for (i = 0; i < conf->more_info->nelts; i++) {
        if (!strcmp(module_name, entry->name)) {
            return entry->info;
        }
        entry++;
    }
    return 0;
}

static int display_info(request_rec *r)
{
    module *modp = NULL;
    char buf[MAX_STRING_LEN];
    const char *cfname;
    const char *more_info;
    const command_rec *cmd = NULL;
#ifdef NEVERMORE
    const handler_rec *hand = NULL;
#endif
    server_rec *serv = r->server;
    int comma = 0;

    if (strcmp(r->handler, "server-info"))
        return DECLINED;

    r->allowed |= (1 << M_GET);
    if (r->method_number != M_GET)
	return DECLINED;

    r->content_type = "text/html";
    ap_send_http_header(r);
    if (r->header_only) {
        return 0;
    }

    ap_rputs(DOCTYPE_HTML_3_2
	     "<html><head><title>Server Information</title></head>\n", r);
    ap_rputs("<body><h1 align=center>Apache Server Information</h1>\n", r);
    if (!r->args || strcasecmp(r->args, "list")) {
        cfname = ap_server_root_relative(r->pool, SERVER_CONFIG_FILE);
        if (!r->args) {
            ap_rputs("<tt><a href=\"#server\">Server Settings</a>, ", r);
            for (modp = top_module; modp; modp = modp->next) {
                ap_rprintf(r, "<a href=\"#%s\">%s</a>", modp->name, modp->name);
                if (modp->next) {
                    ap_rputs(", ", r);
                }
            }
            ap_rputs("</tt><hr>", r);

        }
        if (!r->args || !strcasecmp(r->args, "server")) {
            ap_rprintf(r, "<a name=\"server\"><strong>Server Version:</strong> "
                        "<font size=+1><tt>%s</tt></a></font><br>\n",
                        ap_get_server_version());
            ap_rprintf(r, "<strong>Server Built:</strong> "
                        "<font size=+1><tt>%s</tt></a></font><br>\n",
                        ap_get_server_built());
            ap_rprintf(r, "<strong>API Version:</strong> "
                        "<tt>%d:%d</tt><br>\n",
                        MODULE_MAGIC_NUMBER_MAJOR, MODULE_MAGIC_NUMBER_MINOR);
            ap_rprintf(r, "<strong>Hostname/port:</strong> "
                        "<tt>%s:%u</tt><br>\n",
                        serv->server_hostname, serv->port);
            ap_rprintf(r, "<strong>Timeouts:</strong> "
                        "<tt>connection: %d &nbsp;&nbsp; "
                        "keep-alive: %d</tt><br>",
                        serv->timeout, serv->keep_alive_timeout);
            ap_rprintf(r, "<strong>Server Root:</strong> "
                        "<tt>%s</tt><br>\n", ap_server_root);
            ap_rprintf(r, "<strong>Config File:</strong> "
		       "<tt>%s</tt><br>\n", SERVER_CONFIG_FILE);
        }
        ap_rputs("<hr><dl>", r);
        for (modp = top_module; modp; modp = modp->next) {
            if (!r->args || !strcasecmp(modp->name, r->args)) {
                ap_rprintf(r, "<dt><a name=\"%s\"><strong>Module Name:</strong> "
                            "<font size=+1><tt>%s</tt></a></font>\n",
                            modp->name, modp->name);
                ap_rputs("<dt><strong>Content handlers:</strong>", r);
#ifdef NEVERMORE
                hand = modp->handlers;
                if (hand) {
                    while (hand) {
                        if (hand->content_type) {
                            ap_rprintf(r, " <tt>%s</tt>\n", hand->content_type);
                        }
                        else {
                            break;
                        }
                        hand++;
                        if (hand && hand->content_type) {
                            ap_rputs(",", r);
                        }
                    }
                }
                else {
                    ap_rputs("<tt> <EM>none</EM></tt>", r);
                }
#else
                ap_rputs("<tt> <EM>(code broken)</EM></tt>", r);
#endif
                ap_rputs("<dt><strong>Configuration Phase Participation:</strong> \n",
                      r);
                if (modp->create_dir_config) {
                    if (comma) {
                        ap_rputs(", ", r);
                    }
                    ap_rputs("<tt>Create Directory Config</tt>", r);
                    comma = 1;
                }
                if (modp->merge_dir_config) {
                    if (comma) {
                        ap_rputs(", ", r);
                    }
                    ap_rputs("<tt>Merge Directory Configs</tt>", r);
                    comma = 1;
                }
                if (modp->create_server_config) {
                    if (comma) {
                        ap_rputs(", ", r);
                    }
                    ap_rputs("<tt>Create Server Config</tt>", r);
                    comma = 1;
                }
                if (modp->merge_server_config) {
                    if (comma) {
                        ap_rputs(", ", r);
                    }
                    ap_rputs("<tt>Merge Server Configs</tt>", r);
                    comma = 1;
                }
                if (!comma)
                    ap_rputs("<tt> <EM>none</EM></tt>", r);
                comma = 0;
                ap_rputs("<dt><strong>Module Directives:</strong> ", r);
                cmd = modp->cmds;
                if (cmd) {
                    while (cmd) {
                        if (cmd->name) {
                            ap_rprintf(r, "<dd><tt>%s - <i>",
				    mod_info_html_cmd_string(cmd->name,
					buf, sizeof(buf), 0));
                            if (cmd->errmsg) {
                                ap_rputs(cmd->errmsg, r);
                            }
                            ap_rputs("</i></tt>\n", r);
                        }
                        else {
                            break;
                        }
                        cmd++;
                    }
                    ap_rputs("<dt><strong>Current Configuration:</strong>\n", r);
                    mod_info_module_cmds(r, modp->cmds, ap_conftree);
                }
                else {
                    ap_rputs("<tt> none</tt>\n", r);
                }
                more_info = find_more_info(serv, modp->name);
                if (more_info) {
                    ap_rputs("<dt><strong>Additional Information:</strong>\n<dd>",
                          r);
                    ap_rputs(more_info, r);
                }
                ap_rputs("<dt><hr>\n", r);
                if (r->args) {
                    break;
                }
            }
        }
        if (!modp && r->args && strcasecmp(r->args, "server")) {
            ap_rputs("<b>No such module</b>\n", r);
        }
    }
    else {
        for (modp = top_module; modp; modp = modp->next) {
            ap_rputs(modp->name, r);
            if (modp->next) {
                ap_rputs("<br>", r);
            }
        }
    }
    ap_rputs("</dl>\n", r);
    ap_rputs(ap_psignature("",r), r);
    ap_rputs("</body></html>\n", r);
    /* Done, turn off timeout, close file and return */
    return 0;
}

static const char *add_module_info(cmd_parms *cmd, void *dummy, 
                                   const char *name, const char *info)
{
    server_rec *s = cmd->server;
    info_svr_conf *conf = (info_svr_conf *) ap_get_module_config(s->module_config,
                                                              &info_module);
    info_entry *new = apr_array_push(conf->more_info);

    new->name = name;
    new->info = info;
    return NULL;
}

static const command_rec info_cmds[] =
{
    AP_INIT_TAKE2("AddModuleInfo", add_module_info, NULL, RSRC_CONF,
                  "a module name and additional information on that module"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(display_info, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA info_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    create_info_config,         /* server config */
    merge_info_config,          /* merge server config */
    info_cmds,                  /* command apr_table_t */
    register_hooks
};
