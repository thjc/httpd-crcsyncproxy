/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
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

#ifndef AP_MMN_H
#define AP_MMN_H

/* run until a restart/shutdown is indicated, return 1 for shutdown
   0 otherwise */
API_EXPORT(int) ap_mpm_run(pool *pconf, pool *plog, server_rec *server_conf);

/* predicate indicating if a graceful stop has been requested ...
   used by the connection loop */
API_EXPORT(int) ap_mpm_graceful_stop(void);

/* a mutex which synchronizes threads within one process */
typedef struct ap_thread_mutex ap_thread_mutex;
API_EXPORT(ap_thread_mutex *) ap_thread_mutex_new(void);
API_EXPORT(void) ap_thread_mutex_lock(ap_thread_mutex *);
API_EXPORT(void) ap_thread_mutex_unlock(ap_thread_mutex *);
API_EXPORT(void) ap_thread_mutex_destroy(ap_thread_mutex *);

#ifdef HAS_OTHER_CHILD
/*
 * register an other_child -- a child which the main loop keeps track of
 * and knows it is different than the rest of the scoreboard.
 *
 * pid is the pid of the child.
 *
 * maintenance is a function that is invoked with a reason, the data
 * pointer passed here, and when appropriate a status result from waitpid().
 *
 * write_fd is an fd that is probed for writing by select() if it is ever
 * unwritable, then maintenance is invoked with reason OC_REASON_UNWRITABLE.
 * This is useful for log pipe children, to know when they've blocked.  To
 * disable this feature, use -1 for write_fd.
 */
API_EXPORT(void) ap_register_other_child(int pid,
       void (*maintenance) (int reason, void *data, ap_wait_t status), void *data,
				      int write_fd);
#define OC_REASON_DEATH		0	/* child has died, caller must call
					 * unregister still */
#define OC_REASON_UNWRITABLE	1	/* write_fd is unwritable */
#define OC_REASON_RESTART	2	/* a restart is occuring, perform
					 * any necessary cleanup (including
					 * sending a special signal to child)
					 */
#define OC_REASON_UNREGISTER	3	/* unregister has been called, do
					 * whatever is necessary (including
					 * kill the child) */
#define OC_REASON_LOST		4	/* somehow the child exited without
					 * us knowing ... buggy os? */

/*
 * unregister an other_child.  Note that the data pointer is used here, and
 * is assumed to be unique per other_child.  This is because the pid and
 * write_fd are possibly killed off separately.
 */
API_EXPORT(void) ap_unregister_other_child(void *data);

#endif

#endif
