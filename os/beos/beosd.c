/* ====================================================================
 * Copyright (c) 1998-1999 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

#include "httpd.h"
#include "http_config.h"
#include "http_main.h"
#include "http_log.h"
#include "beosd.h"

beosd_config_rec beosd_config;

void beosd_detach(void)
{
/*    int x;  This isn't needed due to the fork() issue */
    pid_t pgrp;

    chdir("/");

/* 
 * fork() is evil if we're also doing spawn_thread...so we don't use it.
 * This means that it won't detach properly, so we'll have to find a way
 * round this. 
 */
/*
    if ((x = fork()) > 0)
	exit(0);
    else if (x == -1) {
	perror("fork");
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s: unable to fork new process", ap_server_argv0);
	exit(1);
    }
*/
    RAISE_SIGSTOP(DETACH);

    if ((pgrp = setsid()) == -1) {
	perror("setsid");
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s: setsid failed", ap_server_argv0);
	exit(1);
    }

    /* close out the standard file descriptors */
    if (freopen("/dev/null", "r", stdin) == NULL) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s: unable to replace stdin with /dev/null: %s",
		ap_server_argv0, strerror(errno));
	/* continue anyhow -- note we can't close out descriptor 0 because we
	 * have nothing to replace it with, and if we didn't have a descriptor
	 * 0 the next file would be created with that value ... leading to
	 * havoc.
	 */
    }
    if (freopen("/dev/null", "w", stdout) == NULL) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s: unable to replace stdout with /dev/null: %s",
		ap_server_argv0, strerror(errno));
    }
    /* stderr is a tricky one, we really want it to be the error_log,
     * but we haven't opened that yet.  So leave it alone for now and it'll
     * be reopened moments later.
     */
}

/* Set group privileges.
 *
 * Note that we use the username as set in the config files, rather than
 * the lookup of to uid --- the same uid may have multiple passwd entries,
 * with different sets of groups for each.
 */

static int set_group_privs(void)
{
    if (!geteuid()) {
	char *name;

	/* Get username if passed as a uid */

	if (beosd_config.user_name[0] == '#') {
	    struct passwd *ent;
	    uid_t uid = atoi(&beosd_config.user_name[1]);

	    if ((ent = getpwuid(uid)) == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			 "getpwuid: couldn't determine user name from uid %u, "
			 "you probably need to modify the User directive",
			 (unsigned)uid);
		return -1;
	    }

	    name = ent->pw_name;
	}
	else
	    name = beosd_config.user_name;

	if (setgid(beosd_config.group_id) == -1) {
	    ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			"setgid: unable to set group id to Group %u",
			(unsigned)beosd_config.group_id);
	    return -1;
	}

	/* Reset `groups' attributes. */

	if (initgroups(name, beosd_config.group_id) == -1) {
	    ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			"initgroups: unable to set groups for User %s "
			"and Group %u", name, (unsigned)beosd_config.group_id);
	    return -1;
	}
    }
    return 0;
}


int beosd_setup_child(void)
{
    if (set_group_privs()) {
	return -1;
    }

    /* Only try to switch if we're running as root */
    if (!geteuid() && (
	setuid(beosd_config.user_id) == -1)) {
	ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
		    "setuid: unable to change uid");
	return -1;
    }
    return 0;
}


const char *beosd_set_user(cmd_parms *cmd, void *dummy, char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    beosd_config.user_name = arg;
    beosd_config.user_id = ap_uname2id(arg);
#if !defined (BIG_SECURITY_HOLE) && !defined (OS2)
    if (beosd_config.user_id == 0) {
	return "Error:\tApache has not been designed to serve pages while\n"
		"\trunning as root.  There are known race conditions that\n"
		"\twill allow any local user to read any file on the system.\n"
		"\tIf you still desire to serve pages as root then\n"
		"\tadd -DBIG_SECURITY_HOLE to the EXTRA_CFLAGS line in your\n"
		"\tsrc/Configuration file and rebuild the server.  It is\n"
		"\tstrongly suggested that you instead modify the User\n"
		"\tdirective in your httpd.conf file to list a non-root\n"
		"\tuser.\n";
    }
#endif

    return NULL;
}

const char *beosd_set_group(cmd_parms *cmd, void *dummy, char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    beosd_config.group_id = ap_gname2id(arg);

    return NULL;
}

void beosd_pre_config(void)
{
    beosd_config.user_name = DEFAULT_USER;
    beosd_config.user_id = ap_uname2id(DEFAULT_USER);
    beosd_config.group_id = ap_gname2id(DEFAULT_GROUP);
}
