/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
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

/* The purpose of this MPM is to fix the design flaws in the threaded
 * model.  Because of the way that pthreads and mutex locks interact,
 * it is basically impossible to cleanly gracefully shutdown a child
 * process if multiple threads are all blocked in accept.  This model
 * fixes those problems.
 */

#include "apr.h"
#include "apr_portable.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"
#include "apr_thread_mutex.h"
#include "apr_proc_mutex.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if APR_HAVE_SYS_WAIT_H
#include <sys/wait.h> 
#endif
#ifdef HAVE_SYS_PROCESSOR_H
#include <sys/processor.h> /* for bindprocessor() */
#endif

#if !APR_HAS_THREADS
#error The Worker MPM requires APR threads, but they are unavailable.
#endif

#define CORE_PRIVATE 
 
#include "ap_config.h"
#include "httpd.h" 
#include "http_main.h" 
#include "http_log.h" 
#include "http_config.h"	/* for read_config */ 
#include "http_core.h"		/* for get_remote_host */ 
#include "http_connection.h"
#include "ap_mpm.h"
#include "unixd.h"
#include "mpm_common.h"
#include "ap_listen.h"
#include "scoreboard.h" 
#include "fdqueue.h"

#include <signal.h>
#include <limits.h>             /* for INT_MAX */

/*
 * Actual definitions of config globals
 */

int ap_threads_per_child=0;         /* Worker threads per child */
static int ap_daemons_to_start=0;
static int min_spare_threads=0;
static int max_spare_threads=0;
static int ap_daemons_limit=0;
static int dying = 0;
static int workers_may_exit = 0;
static int requests_this_child;
static int num_listensocks = 0;
static fd_queue_t *worker_queue;

/* The structure used to pass unique initialization info to each thread */
typedef struct {
    int pid;
    int tid;
    int sd;
} proc_info;

/* Structure used to pass information to the thread responsible for 
 * creating the rest of the threads.
 */
typedef struct {
    apr_thread_t **threads;
    int child_num_arg;
    apr_threadattr_t *threadattr;
} thread_starter;

/*
 * The max child slot ever assigned, preserved across restarts.  Necessary
 * to deal with MaxClients changes across AP_SIG_GRACEFUL restarts.  We 
 * use this value to optimize routines that have to scan the entire 
 * scoreboard.
 */
int ap_max_daemons_limit = -1;

char ap_coredump_dir[MAX_STRING_LEN];

static apr_file_t *pipe_of_death_in = NULL;
static apr_file_t *pipe_of_death_out = NULL;
/* insures that a child process only consumes one character */
static apr_thread_mutex_t *pipe_of_death_mutex;

/* *Non*-shared http_main globals... */

server_rec *ap_server_conf;

/* The worker MPM respects a couple of runtime flags that can aid
 * in debugging. Setting the -DNO_DETACH flag will prevent the root process
 * from detaching from its controlling terminal. Additionally, setting
 * the -DONE_PROCESS flag (which implies -DNO_DETACH) will get you the
 * child_main loop running in the process which originally started up.
 * This gives you a pretty nice debugging environment.  (You'll get a SIGHUP
 * early in standalone_main; just continue through.  This is the server
 * trying to kill off any child processes which it might have lying
 * around --- Apache doesn't keep track of their pids, it just sends
 * SIGHUP to the process group, ignoring it in the root process.
 * Continue through and you'll be fine.).
 */

static int one_process = 0;

#ifdef DEBUG_SIGSTOP
int raise_sigstop_flags;
#endif

static apr_pool_t *pconf;		/* Pool for config stuff */
static apr_pool_t *pchild;		/* Pool for httpd child stuff */

static pid_t ap_my_pid; /* Linux getpid() doesn't work except in main 
                           thread. Use this instead */
static pid_t parent_pid;
/* Keep track of the number of worker threads currently active */
static int worker_thread_count;
static apr_thread_mutex_t *worker_thread_count_mutex;

/* Locks for accept serialization */
static apr_proc_mutex_t *accept_mutex;
static const char *lock_fname;

#ifdef NO_SERIALIZED_ACCEPT
#define SAFE_ACCEPT(stmt) APR_SUCCESS
#else
#define SAFE_ACCEPT(stmt) (stmt)
#endif

static void signal_workers(void)
{
    workers_may_exit = 1;
    /* XXX: This will happen naturally on a graceful, and we don't care otherwise.
    ap_queue_signal_all_wakeup(worker_queue); */
    ap_queue_interrupt_all(worker_queue);
}

AP_DECLARE(apr_status_t) ap_mpm_query(int query_code, int *result)
{
    switch(query_code){
        case AP_MPMQ_MAX_DAEMON_USED:
            *result = ap_max_daemons_limit;
            return APR_SUCCESS;
        case AP_MPMQ_IS_THREADED:
            *result = AP_MPMQ_STATIC;
            return APR_SUCCESS;
        case AP_MPMQ_IS_FORKED:
            *result = AP_MPMQ_DYNAMIC;
            return APR_SUCCESS;
        case AP_MPMQ_HARD_LIMIT_DAEMONS:
            *result = HARD_SERVER_LIMIT;
            return APR_SUCCESS;
        case AP_MPMQ_HARD_LIMIT_THREADS:
            *result = HARD_THREAD_LIMIT;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_THREADS:
            *result = ap_threads_per_child;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MIN_SPARE_THREADS:    
            *result = min_spare_threads;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_DAEMONS:
            *result = 0;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_SPARE_THREADS:
            *result = max_spare_threads;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_REQUESTS_DAEMON:
            *result = ap_max_requests_per_child;
            return APR_SUCCESS;
        case AP_MPMQ_MAX_DAEMONS:
            *result = ap_daemons_limit;
            return APR_SUCCESS;
    }
    return APR_ENOTIMPL;
}

/* a clean exit from a child with proper cleanup */ 
static void clean_child_exit(int code) __attribute__ ((noreturn));
static void clean_child_exit(int code)
{
    if (pchild) {
	apr_pool_destroy(pchild);
    }
    exit(code);
}

/* handle all varieties of core dumping signals */
static void sig_coredump(int sig)
{
    chdir(ap_coredump_dir);
    apr_signal(sig, SIG_DFL);
    if (ap_my_pid == parent_pid) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                     0, ap_server_conf,
                     "seg fault or similar nasty error detected "
                     "in the parent process");
        
        /* XXX we can probably add some rudimentary cleanup code here,
         * like getting rid of the pid file.  If any additional bad stuff
         * happens, we are protected from recursive errors taking down the
         * system since this function is no longer the signal handler   GLA
         */
    }
    kill(ap_my_pid, sig);
    /* At this point we've got sig blocked, because we're still inside
     * the signal handler.  When we leave the signal handler it will
     * be unblocked, and we'll take the signal... and coredump or whatever
     * is appropriate for this particular Unix.  In addition the parent
     * will see the real signal we received -- whereas if we called
     * abort() here, the parent would only see SIGABRT.
     */
}

static void just_die(int sig)
{
    clean_child_exit(0);
}

/*****************************************************************
 * Connection structures and accounting...
 */

/* volatile just in case */
static int volatile shutdown_pending;
static int volatile restart_pending;
static int volatile is_graceful;
static volatile int child_fatal;
ap_generation_t volatile ap_my_generation;

/*
 * ap_start_shutdown() and ap_start_restart(), below, are a first stab at
 * functions to initiate shutdown or restart without relying on signals. 
 * Previously this was initiated in sig_term() and restart() signal handlers, 
 * but we want to be able to start a shutdown/restart from other sources --
 * e.g. on Win32, from the service manager. Now the service manager can
 * call ap_start_shutdown() or ap_start_restart() as appropiate.  Note that
 * these functions can also be called by the child processes, since global
 * variables are no longer used to pass on the required action to the parent.
 *
 * These should only be called from the parent process itself, since the
 * parent process will use the shutdown_pending and restart_pending variables
 * to determine whether to shutdown or restart. The child process should
 * call signal_parent() directly to tell the parent to die -- this will
 * cause neither of those variable to be set, which the parent will
 * assume means something serious is wrong (which it will be, for the
 * child to force an exit) and so do an exit anyway.
 */

static void ap_start_shutdown(void)
{
    if (shutdown_pending == 1) {
	/* Um, is this _probably_ not an error, if the user has
	 * tried to do a shutdown twice quickly, so we won't
	 * worry about reporting it.
	 */
	return;
    }
    shutdown_pending = 1;
}

/* do a graceful restart if graceful == 1 */
static void ap_start_restart(int graceful)
{

    if (restart_pending == 1) {
	/* Probably not an error - don't bother reporting it */
	return;
    }
    restart_pending = 1;
    is_graceful = graceful;
    if (is_graceful) {
        apr_pool_cleanup_kill(pconf, NULL, ap_cleanup_scoreboard);
    }
}

static void sig_term(int sig)
{
    ap_start_shutdown();
}

static void restart(int sig)
{
    ap_start_restart(sig == AP_SIG_GRACEFUL);
}

static void set_signals(void)
{
#ifndef NO_USE_SIGACTION
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (!one_process) {
	sa.sa_handler = sig_coredump;
#if defined(SA_ONESHOT)
	sa.sa_flags = SA_ONESHOT;
#elif defined(SA_RESETHAND)
	sa.sa_flags = SA_RESETHAND;
#endif
	if (sigaction(SIGSEGV, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGSEGV)");
#ifdef SIGBUS
	if (sigaction(SIGBUS, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGBUS)");
#endif
#ifdef SIGABORT
	if (sigaction(SIGABORT, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGABORT)");
#endif
#ifdef SIGABRT
	if (sigaction(SIGABRT, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGABRT)");
#endif
#ifdef SIGILL
	if (sigaction(SIGILL, &sa, NULL) < 0)
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGILL)");
#endif
	sa.sa_flags = 0;
    }
    sa.sa_handler = sig_term;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGTERM)");
#ifdef SIGINT
    if (sigaction(SIGINT, &sa, NULL) < 0)
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGINT)");
#endif
#ifdef SIGXCPU
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGXCPU, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGXCPU)");
#endif
#ifdef SIGXFSZ
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGXFSZ, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGXFSZ)");
#endif
#ifdef SIGPIPE
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGPIPE)");
#endif

    /* we want to ignore HUPs and AP_SIG_GRACEFUL while we're busy 
     * processing one */
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, AP_SIG_GRACEFUL);
    sa.sa_handler = restart;
    if (sigaction(SIGHUP, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(SIGHUP)");
    if (sigaction(AP_SIG_GRACEFUL, &sa, NULL) < 0)
	ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "sigaction(" AP_SIG_GRACEFUL_STRING ")");
#else
    if (!one_process) {
	apr_signal(SIGSEGV, sig_coredump);
#ifdef SIGBUS
	apr_signal(SIGBUS, sig_coredump);
#endif /* SIGBUS */
#ifdef SIGABORT
	apr_signal(SIGABORT, sig_coredump);
#endif /* SIGABORT */
#ifdef SIGABRT
	apr_signal(SIGABRT, sig_coredump);
#endif /* SIGABRT */
#ifdef SIGILL
	apr_signal(SIGILL, sig_coredump);
#endif /* SIGILL */
#ifdef SIGXCPU
	apr_signal(SIGXCPU, SIG_DFL);
#endif /* SIGXCPU */
#ifdef SIGXFSZ
	apr_signal(SIGXFSZ, SIG_DFL);
#endif /* SIGXFSZ */
    }

    apr_signal(SIGTERM, sig_term);
#ifdef SIGHUP
    apr_signal(SIGHUP, restart);
#endif /* SIGHUP */
#ifdef AP_SIG_GRACEFUL
    apr_signal(AP_SIG_GRACEFUL, restart);
#endif /* AP_SIG_GRACEFUL */
#ifdef SIGPIPE
    apr_signal(SIGPIPE, SIG_IGN);
#endif /* SIGPIPE */

#endif
}

/*****************************************************************
 * Here follows a long bunch of generic server bookkeeping stuff...
 */

int ap_graceful_stop_signalled(void)
    /* XXX this is really a bad confusing obsolete name
     * maybe it should be ap_mpm_process_exiting?
     */
{
    return workers_may_exit;
}

/*****************************************************************
 * Child process main loop.
 */

static void process_socket(apr_pool_t *p, apr_socket_t *sock, int my_child_num, int my_thread_num)
{
    conn_rec *current_conn;
    long conn_id = AP_ID_FROM_CHILD_THREAD(my_child_num, my_thread_num);
    int csd;

    apr_os_sock_get(&csd, sock);

    if (csd >= FD_SETSIZE) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, NULL,
                     "new file descriptor %d is too large; you probably need "
                     "to rebuild Apache with a larger FD_SETSIZE "
                     "(currently %d)", 
                     csd, FD_SETSIZE);
        apr_socket_close(sock);
        return;
    }

    current_conn = ap_run_create_connection(p, ap_server_conf, sock, conn_id);
    if (current_conn) {
        ap_process_connection(current_conn);
        ap_lingering_close(current_conn);
    }
}

/* requests_this_child has gone to zero or below.  See if the admin coded
   "MaxRequestsPerChild 0", and keep going in that case.  Doing it this way
   simplifies the hot path in worker_thread */
static void check_infinite_requests(void)
{
    if (ap_max_requests_per_child) {
        signal_workers();
    }
    else {
        /* wow! if you're executing this code, you may have set a record.
         * either this child process has served over 2 billion requests, or
         * you're running a threaded 2.0 on a 16 bit machine.  
         *
         * I'll buy pizza and beers at Apachecon for the first person to do
         * the former without cheating (dorking with INT_MAX, or running with
         * uncommitted performance patches, for example).    
         *
         * for the latter case, you probably deserve a beer too.   Greg Ames
         */
            
        requests_this_child = INT_MAX;      /* keep going */ 
    }
}

/* Sets workers_may_exit if we received a character on the pipe_of_death */
static apr_status_t check_pipe_of_death(void **csd, ap_listen_rec *lr, apr_pool_t *ptrans)
{
    *csd = NULL;
    apr_thread_mutex_lock(pipe_of_death_mutex);
    if (!workers_may_exit) {
        apr_status_t ret;
        char pipe_read_char;
	apr_size_t n = 1;

        ret = apr_recv(lr->sd, &pipe_read_char, &n);
        if (APR_STATUS_IS_EAGAIN(ret)) {
            /* It lost the lottery. It must continue to suffer
             * through a life of servitude. */
        }
        else {
            /* It won the lottery (or something else is very
             * wrong). Embrace death with open arms. */
            signal_workers();
        }
    }
    apr_thread_mutex_unlock(pipe_of_death_mutex);
    /* This is a hack to get us back to the top of the accept loop.
     * we should probably have a better way to do this though.
     */
    return APR_EINTR;
}

static void *listener_thread(apr_thread_t *thd, void * dummy)
{
    proc_info * ti = dummy;
    int process_slot = ti->pid;
    int thread_slot = ti->tid;
    apr_pool_t *tpool = apr_thread_pool_get(thd);
    void *csd = NULL;
    apr_pool_t *ptrans;		/* Pool for per-transaction stuff */
    int n;
    apr_pollfd_t *pollset;
    apr_status_t rv;
    ap_listen_rec *lr, *last_lr = ap_listeners;

    free(ti);

    apr_thread_mutex_lock(worker_thread_count_mutex);
    worker_thread_count++;
    apr_thread_mutex_unlock(worker_thread_count_mutex);

    apr_poll_setup(&pollset, num_listensocks, tpool);
    for(lr = ap_listeners ; lr != NULL ; lr = lr->next)
	apr_poll_socket_add(pollset, lr->sd, APR_POLLIN);

    /* TODO: Switch to a system where threads reuse the results from earlier
       poll calls - manoj */
    while (1) {
        /* TODO: requests_this_child should be synchronized - aaron */
        if (requests_this_child <= 0) {
            check_infinite_requests();
        }
        if (workers_may_exit) break;

        if ((rv = SAFE_ACCEPT(apr_proc_mutex_lock(accept_mutex)))
            != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                         "apr_proc_mutex_lock failed. Attempting to shutdown "
                         "process gracefully.");
            signal_workers();
        }

        while (!workers_may_exit) {
	    apr_status_t ret;
	    apr_int16_t event;

            ret = apr_poll(pollset, &n, -1);
            if (ret != APR_SUCCESS) {
                if (APR_STATUS_IS_EINTR(ret)) {
                    continue;
                }

                /* apr_poll() will only return errors in catastrophic
                 * circumstances. Let's try exiting gracefully, for now. */
                ap_log_error(APLOG_MARK, APLOG_ERR, ret, (const server_rec *)
                             ap_server_conf, "apr_poll: (listen)");
                signal_workers();
            }

            if (workers_may_exit) break;

            if (ap_listeners->next == NULL) {
                /* only one listener */
                lr = ap_listeners;
                goto got_fd;
            }
            else {
                /* find a listener */
                lr = last_lr;
                do {
                    lr = lr->next;
                    if (lr == NULL) {
                        lr = ap_listeners;
                    }
                    /* XXX: Should we check for POLLERR? */
		    apr_poll_revents_get(&event, lr->sd, pollset);
                    if (event & APR_POLLIN) {
                        last_lr = lr;
                        goto got_fd;
                    }
                } while (lr != last_lr);
            }
        }
    got_fd:
        if (!workers_may_exit) {
            /* create a new transaction pool for each accepted socket */
            apr_pool_create(&ptrans, tpool);

            rv = lr->accept_func(&csd, lr, ptrans);

            if (rv == APR_EGENERAL) {
                signal_workers();
            }
            if ((rv = SAFE_ACCEPT(apr_proc_mutex_unlock(accept_mutex)))
                != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                             "apr_proc_mutex_lock failed. Attempting to "
                             "shutdown process gracefully.");
                signal_workers();
            }
            if (csd != NULL) {
                rv = ap_queue_push(worker_queue, csd, ptrans);
                if (rv) {
                    /* trash the connection; we couldn't queue the connected
                     * socket to a worker 
                     */
                    apr_socket_close(csd);
                    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, ap_server_conf,
                                 "ap_queue_push failed with error code %d",
                                 rv);
                }
            }
        }
        else {
            if ((rv = SAFE_ACCEPT(apr_proc_mutex_unlock(accept_mutex)))
                != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                             "apr_proc_mutex_unlock failed. Attempting to "
                             "shutdown process gracefully.");
                signal_workers();
            }
            break;
        }
    }

    ap_update_child_status(process_slot, thread_slot, (dying) ? SERVER_DEAD : SERVER_GRACEFUL,
        (request_rec *) NULL);
    dying = 1;
    ap_scoreboard_image->parent[process_slot].quiescing = 1;
    kill(ap_my_pid, SIGTERM);

/* Unsure if this can be safely uncommented. -aaron
    apr_thread_exit(thd, APR_SUCCESS);
*/
    return NULL;
}

static void *worker_thread(apr_thread_t *thd, void * dummy)
{
    proc_info * ti = dummy;
    int process_slot = ti->pid;
    int thread_slot = ti->tid;
    apr_socket_t *csd = NULL;
    apr_pool_t *ptrans;		/* Pool for per-transaction stuff */
    apr_status_t rv;

    free(ti);

    ap_update_child_status(process_slot, thread_slot, SERVER_STARTING, NULL);
    while (!workers_may_exit) {
        ap_update_child_status(process_slot, thread_slot, SERVER_READY, NULL);
        rv = ap_queue_pop(worker_queue, &csd, &ptrans);
        /* We get FD_QUEUE_EINTR whenever ap_queue_pop() has been interrupted
         * from an explicit call to ap_queue_interrupt_all(). This allows
         * us to unblock threads stuck in ap_queue_pop() when a shutdown
         * is pending. */
        if (rv == FD_QUEUE_EINTR || !csd) {
            continue;
        }
        process_socket(ptrans, csd, process_slot, thread_slot);
        requests_this_child--; /* FIXME: should be synchronized - aaron */
        apr_pool_destroy(ptrans);
    }

    ap_update_child_status(process_slot, thread_slot,
        (dying) ? SERVER_DEAD : SERVER_GRACEFUL, (request_rec *) NULL);
    apr_thread_mutex_lock(worker_thread_count_mutex);
    worker_thread_count--;
    apr_thread_mutex_unlock(worker_thread_count_mutex);

    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

static int check_signal(int signum)
{
    switch (signum) {
        case SIGTERM:
        case SIGINT:
            return 1;
    }                                                                           
    return 0;
}

static void *start_threads(apr_thread_t *thd, void *dummy)
{
    thread_starter *ts = dummy;
    apr_thread_t **threads = ts->threads;
    apr_threadattr_t *thread_attr = ts->threadattr;
    int child_num_arg = ts->child_num_arg;
    int my_child_num = child_num_arg;
    proc_info *my_info = NULL;
    apr_status_t rv;
    int i = 0;
    int threads_created = 0;
    apr_thread_t *listener;

    /* We must create the fd queues before we start up the listener
     * and worker threads. */
    worker_queue = apr_pcalloc(pchild, sizeof(*worker_queue));
    ap_queue_init(worker_queue, ap_threads_per_child, pchild);

    my_info = (proc_info *)malloc(sizeof(proc_info));
    my_info->pid = my_child_num;
    my_info->tid = i;
    my_info->sd = 0;
    apr_thread_create(&listener, thread_attr, listener_thread, my_info, pchild);
    while (1) {
        /* ap_threads_per_child does not include the listener thread */
        for (i = 0; i < ap_threads_per_child; i++) {
            int status = ap_scoreboard_image->servers[child_num_arg][i].status;

            if (status != SERVER_GRACEFUL && status != SERVER_DEAD) {
                continue;
            }

   	    my_info = (proc_info *)malloc(sizeof(proc_info));
            if (my_info == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ALERT, errno, ap_server_conf,
		             "malloc: out of memory");
                clean_child_exit(APEXIT_CHILDFATAL);
            }
	    my_info->pid = my_child_num;
            my_info->tid = i;
	    my_info->sd = 0;
	
  	    /* We are creating threads right now */
	    ap_update_child_status(my_child_num, i, SERVER_STARTING, NULL);
            /* We let each thread update its own scoreboard entry.  This is
             * done because it lets us deal with tid better.
	     */
	    if ((rv = apr_thread_create(&threads[i], thread_attr, worker_thread, my_info, pchild))) {
	        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf,
			     "apr_thread_create: unable to create worker thread");
                /* In case system resources are maxxed out, we don't want
                   Apache running away with the CPU trying to fork over and
                   over and over again if we exit. */
                sleep(10);
	        clean_child_exit(APEXIT_CHILDFATAL);
	    }
            threads_created++;
        }
        if (workers_may_exit || threads_created == ap_threads_per_child) {
            break;
        }
        sleep(1); /* wait for previous generation to clean up an entry */
    }
    
    /* What state should this child_main process be listed as in the scoreboard...?
     *  ap_update_child_status(my_child_num, i, SERVER_STARTING, (request_rec *) NULL);
     * 
     *  This state should be listed separately in the scoreboard, in some kind
     *  of process_status, not mixed in with the worker threads' status.   
     *  "life_status" is almost right, but it's in the worker's structure, and 
     *  the name could be clearer.   gla
     */
    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

static void child_main(int child_num_arg)
{
    apr_thread_t **threads;
    int i;
    apr_status_t rv;
    thread_starter *ts;
    apr_threadattr_t *thread_attr;
    apr_thread_t *start_thread_id;

    ap_my_pid = getpid();
    apr_pool_create(&pchild, pconf);

    /*stuff to do before we switch id's, so we have permissions.*/
    reopen_scoreboard(pchild);

    rv = SAFE_ACCEPT(apr_proc_mutex_child_init(&accept_mutex, lock_fname,
                                               pchild));
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                     "Couldn't initialize cross-process lock in child");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    if (unixd_setup_child()) {
	clean_child_exit(APEXIT_CHILDFATAL);
    }

    ap_run_child_init(pchild, ap_server_conf);

    /* done with init critical section */

    rv = apr_setup_signal_thread();
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf,
                     "Couldn't initialize signal thread");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    if (ap_max_requests_per_child) {
        requests_this_child = ap_max_requests_per_child;
    }
    else {
        /* coding a value of zero means infinity */
        requests_this_child = INT_MAX;
    }
    
    /* Setup worker threads */

    /* clear the storage; we may not create all our threads immediately, and we want
     * a 0 entry to indicate a thread which was not created
     */
    threads = (apr_thread_t **)calloc(1, sizeof(apr_thread_t *) * ap_threads_per_child);
    if (threads == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, ap_server_conf,
                     "malloc: out of memory");
        clean_child_exit(APEXIT_CHILDFATAL);
    }
    worker_thread_count = 0;
    apr_thread_mutex_create(&worker_thread_count_mutex,
                            APR_THREAD_MUTEX_DEFAULT, pchild);
    apr_thread_mutex_create(&pipe_of_death_mutex,
                            APR_THREAD_MUTEX_DEFAULT, pchild);

    ts = (thread_starter *)apr_palloc(pchild, sizeof(*ts));

    apr_threadattr_create(&thread_attr, pchild);
    apr_threadattr_detach_set(thread_attr, 0);    /* 0 means PTHREAD_CREATE_JOINABLE */

    ts->threads = threads;
    ts->child_num_arg = child_num_arg;
    ts->threadattr = thread_attr;

    if ((rv = apr_thread_create(&start_thread_id, thread_attr, start_threads, ts, pchild))) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf,
                     "apr_thread_create: unable to create worker thread");
        /* In case system resources are maxxed out, we don't want
           Apache running away with the CPU trying to fork over and
           over and over again if we exit. */
        sleep(10);
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    apr_signal_thread(check_signal);

    signal_workers();       /* helps us terminate a little more quickly when 
                             * the dispatch of the signal thread
                             * beats the Pipe of Death and the browsers
                             */
    
    /* A terminating signal was received. Now join each of the workers to clean them up.
     *   If the worker already exited, then the join frees their resources and returns.
     *   If the worker hasn't exited, then this blocks until they have (then cleans up).
     */
    apr_thread_join(&rv, start_thread_id);
    for (i = 0; i < ap_threads_per_child; i++) {
        if (threads[i]) { /* if we ever created this thread */
            apr_thread_join(&rv, threads[i]);
        }
    }

    free(threads);

    clean_child_exit(0);
}

static int make_child(server_rec *s, int slot) 
{
    int pid;

    if (slot + 1 > ap_max_daemons_limit) {
	ap_max_daemons_limit = slot + 1;
    }

    if (one_process) {
	set_signals();
        ap_scoreboard_image->parent[slot].pid = getpid();
	child_main(slot);
    }

    if ((pid = fork()) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s, "fork: Unable to fork new process");

        /* fork didn't succeed. Fix the scoreboard or else
         * it will say SERVER_STARTING forever and ever
         */
        ap_update_child_status(slot, 0, SERVER_DEAD, NULL);

	/* In case system resources are maxxed out, we don't want
	   Apache running away with the CPU trying to fork over and
	   over and over again. */
	sleep(10);

	return -1;
    }

    if (!pid) {
#ifdef HAVE_BINDPROCESSOR
        /* By default, AIX binds to a single processor.  This bit unbinds
	 * children which will then bind to another CPU.
         */
        int status = bindprocessor(BINDPROCESS, (int)getpid(),
			       PROCESSOR_CLASS_ANY);
	if (status != OK)
	    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, errno, ap_server_conf,
			 "processor unbind failed %d", status);
#endif
        RAISE_SIGSTOP(MAKE_CHILD);

        apr_signal(SIGTERM, just_die);
        child_main(slot);

        clean_child_exit(0);
    }
    /* else */
    ap_scoreboard_image->parent[slot].quiescing = 0;
    ap_scoreboard_image->parent[slot].pid = pid;
    return 0;
}

/* If there aren't many connections coming in from the network, the child 
 * processes may need to be awakened from their network i/o waits.
 * The pipe of death is an effective prod.
 */
   
static void wake_up_and_die(void) 
{
    int i;
    char char_of_death = '!';
    apr_size_t one = 1;
    apr_status_t rv;
    
    for (i = 0; i < ap_daemons_limit;) {
        if ((rv = apr_file_write(pipe_of_death_out, &char_of_death, &one)) 
                                 != APR_SUCCESS) {
            if (APR_STATUS_IS_EINTR(rv)) continue;
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf, 
                         "write pipe_of_death");
        }
        i++;
    }
}

/* start up a bunch of children */
static void startup_children(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < ap_daemons_limit; ++i) {
	if (ap_scoreboard_image->parent[i].pid != 0) {
	    continue;
	}
	if (make_child(ap_server_conf, i) < 0) {
	    break;
	}
	--number_to_start;
    }
}


/*
 * idle_spawn_rate is the number of children that will be spawned on the
 * next maintenance cycle if there aren't enough idle servers.  It is
 * doubled up to MAX_SPAWN_RATE, and reset only when a cycle goes by
 * without the need to spawn.
 */
static int idle_spawn_rate = 1;
#ifndef MAX_SPAWN_RATE
#define MAX_SPAWN_RATE	(32)
#endif
static int hold_off_on_exponential_spawning;

static void perform_idle_server_maintenance(void)
{
    int i, j;
    int idle_thread_count;
    worker_score *ws;
    process_score *ps;
    int free_length;
    int totally_free_length = 0;
    int free_slots[MAX_SPAWN_RATE];
    int last_non_dead;
    int total_non_dead;
    apr_size_t one = 1;
    apr_status_t rv;

    /* initialize the free_list */
    free_length = 0;

    idle_thread_count = 0;
    last_non_dead = -1;
    total_non_dead = 0;

    ap_sync_scoreboard_image();
    for (i = 0; i < ap_daemons_limit; ++i) {
	/* Initialization to satisfy the compiler. It doesn't know
	 * that ap_threads_per_child is always > 0 */
	int status = SERVER_DEAD;
	int any_dying_threads = 0;
	int any_dead_threads = 0;
	int all_dead_threads = 1;

	if (i >= ap_max_daemons_limit && totally_free_length == idle_spawn_rate)
	    break;
        ps = &ap_scoreboard_image->parent[i];
	for (j = 0; j < ap_threads_per_child; j++) {
            ws = &ap_scoreboard_image->servers[i][j];
	    status = ws->status;

            /* XXX any_dying_threads is probably no longer needed    GLA */
	    any_dying_threads = any_dying_threads || (status == SERVER_GRACEFUL);
	    any_dead_threads = any_dead_threads || (status == SERVER_DEAD);
	    all_dead_threads = all_dead_threads &&
                                   (status == SERVER_DEAD ||
                                    status == SERVER_GRACEFUL);

	    /* We consider a starting server as idle because we started it
	     * at least a cycle ago, and if it still hasn't finished starting
	     * then we're just going to swamp things worse by forking more.
	     * So we hopefully won't need to fork more if we count it.
	     * This depends on the ordering of SERVER_READY and SERVER_STARTING.
	     */
	    if (status <= SERVER_READY && status != SERVER_DEAD &&
                    !ps->quiescing &&
                    ps->generation == ap_my_generation &&
                 /* XXX the following shouldn't be necessary if we clean up 
                  *     properly after seg faults, but we're not yet    GLA 
                  */     
                    ps->pid != 0) {
	        ++idle_thread_count;
	    }
	}
        if (any_dead_threads && totally_free_length < idle_spawn_rate 
                && (!ps->pid               /* no process in the slot */
                    || ps->quiescing)) {   /* or at least one is going away */
            if (all_dead_threads) {
                /* great! we prefer these, because the new process can
                 * start more threads sooner.  So prioritize this slot 
                 * by putting it ahead of any slots with active threads.
                 *
                 * first, make room by moving a slot that's potentially still
                 * in use to the end of the array
                 */
                free_slots[free_length] = free_slots[totally_free_length];
                free_slots[totally_free_length++] = i;
            }
            else {
                /* slot is still in use - back of the bus
                 */
	    free_slots[free_length] = i;
            }
	    ++free_length;
	}
        /* XXX if (!ps->quiescing)     is probably more reliable  GLA */
	if (!any_dying_threads) {
            last_non_dead = i;
            ++total_non_dead;
        }
    }
    ap_max_daemons_limit = last_non_dead + 1;

    if (idle_thread_count > max_spare_threads) {
        char char_of_death = '!';
        /* Kill off one child */
        if ((rv = apr_file_write(pipe_of_death_out, &char_of_death, &one)) != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf, "write pipe_of_death");
        }
        idle_spawn_rate = 1;
    }
    else if (idle_thread_count < min_spare_threads) {
        /* terminate the free list */
        if (free_length == 0) {
	    /* only report this condition once */
	    static int reported = 0;
	    
	    if (!reported) {
	        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, ap_server_conf,
			     "server reached MaxClients setting, consider"
			     " raising the MaxClients setting");
		reported = 1;
	    }
	    idle_spawn_rate = 1;
	}
	else {
            if (free_length > idle_spawn_rate) {
                free_length = idle_spawn_rate;
            }
	    if (idle_spawn_rate >= 8) {
	        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, ap_server_conf,
			     "server seems busy, (you may need "
			     "to increase StartServers, ThreadsPerChild "
                             "or Min/MaxSpareThreads), "
			     "spawning %d children, there are around %d idle "
                             "threads, and %d total children", free_length,
			     idle_thread_count, total_non_dead);
	    }
	    for (i = 0; i < free_length; ++i) {
	        make_child(ap_server_conf, free_slots[i]);
	    }
	    /* the next time around we want to spawn twice as many if this
	     * wasn't good enough, but not if we've just done a graceful
	     */
	    if (hold_off_on_exponential_spawning) {
	        --hold_off_on_exponential_spawning;
	    }
	    else if (idle_spawn_rate < MAX_SPAWN_RATE) {
	        idle_spawn_rate *= 2;
	    }
	}
    }
    else {
      idle_spawn_rate = 1;
    }
}

static void server_main_loop(int remaining_children_to_start)
{
    int child_slot;
    apr_exit_why_e exitwhy;
    int status;
    apr_proc_t pid;
    int i;

    while (!restart_pending && !shutdown_pending) {
        ap_wait_or_timeout(&exitwhy, &status, &pid, pconf);
        
        if (pid.pid != -1) {
            if (ap_process_child_status(&pid, exitwhy, status) == APEXIT_CHILDFATAL) {
                shutdown_pending = 1;
                child_fatal = 1;
                return;
            }
            /* non-fatal death... note that it's gone in the scoreboard. */
            child_slot = find_child_by_pid(&pid);
            if (child_slot >= 0) {
                for (i = 0; i < ap_threads_per_child; i++)
                    ap_update_child_status(child_slot, i, SERVER_DEAD, (request_rec *) NULL);
                
                ap_scoreboard_image->parent[child_slot].pid = 0;
                ap_scoreboard_image->parent[child_slot].quiescing = 0;
		if (remaining_children_to_start
		    && child_slot < ap_daemons_limit) {
		    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
		    make_child(ap_server_conf, child_slot);
		    --remaining_children_to_start;
		}
#if APR_HAS_OTHER_CHILD
	    }
	    else if (apr_proc_other_child_read(&pid, status) == 0) {
		/* handled */
#endif
	    }
	    else if (is_graceful) {
		/* Great, we've probably just lost a slot in the
		 * scoreboard.  Somehow we don't know about this child.
		 */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0,
		             ap_server_conf,
		             "long lost child came home! (pid %ld)",
		             (long)pid.pid);
	    }
	    /* Don't perform idle maintenance when a child dies,
             * only do it when there's a timeout.  Remember only a
             * finite number of children can die, and it's pretty
             * pathological for a lot to die suddenly.
             */
	    continue;
	}
	else if (remaining_children_to_start) {
	    /* we hit a 1 second timeout in which none of the previous
	     * generation of children needed to be reaped... so assume
	     * they're all done, and pick up the slack if any is left.
	     */
	    startup_children(remaining_children_to_start);
	    remaining_children_to_start = 0;
	    /* In any event we really shouldn't do the code below because
	     * few of the servers we just started are in the IDLE state
	     * yet, so we'd mistakenly create an extra server.
	     */
	    continue;
	}

	perform_idle_server_maintenance();
    }
}

static void make_pipe_of_death(int *num_listeners, apr_pool_t *p)
{
    ap_listen_rec *lr = apr_palloc(p, sizeof(*lr));
    int filedes;
    apr_socket_t *sd = NULL;
    apr_status_t rv;

    rv = apr_file_pipe_create(&pipe_of_death_in, &pipe_of_death_out, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv,
                     (const server_rec*) ap_server_conf,
                     "apr_file_pipe_create (pipe_of_death)");
        exit(1);
    }

    if ((rv = apr_file_pipe_timeout_set(pipe_of_death_in, 0)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv,
                     (const server_rec*) ap_server_conf,
                     "apr_file_pipe_timeout_set (pipe_of_death)");
        exit(1);
    }

    apr_os_file_get(&filedes, pipe_of_death_in);
    apr_os_sock_put(&sd, &filedes, p);

    lr->sd = sd;
    lr->active = 1;
    lr->accept_func = check_pipe_of_death;
    /* We are not bound to a real address.  So, indicate that. */
    lr->bind_addr = 0;
    lr->next = ap_listeners;
    ap_listeners = lr;
    (*num_listeners)++;
}

int ap_mpm_run(apr_pool_t *_pconf, apr_pool_t *plog, server_rec *s)
{
    int remaining_children_to_start;
    apr_status_t rv;

    pconf = _pconf;
    ap_server_conf = s;

    if ((num_listensocks = ap_setup_listeners(ap_server_conf)) < 1) {
        /* XXX: hey, what's the right way for the mpm to indicate a fatal error? */
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ALERT, 0, s,
            "no listening sockets available, shutting down");
        return 1;
    }
    make_pipe_of_death(&num_listensocks, pconf);
    ap_log_pid(pconf, ap_pid_fname);

    /* Initialize cross-process accept lock */
    lock_fname = apr_psprintf(_pconf, "%s.%" APR_OS_PROC_T_FMT,
                             ap_server_root_relative(_pconf, lock_fname),
                             ap_my_pid);
    rv = apr_proc_mutex_create_np(&accept_mutex, lock_fname, 
                                  ap_accept_lock_mech, _pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                     "Couldn't create accept lock");
        return 1;
    }

#if APR_USE_SYSVSEM_SERIALIZE
    if (ap_accept_lock_mech == APR_LOCK_DEFAULT || 
        ap_accept_lock_mech == APR_LOCK_SYSVSEM) {
#else
    if (ap_accept_lock_mech == APR_LOCK_SYSVSEM) {
#endif
        rv = unixd_set_proc_mutex_perms(accept_mutex);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, s,
                         "Couldn't set permissions on cross-process lock");
            return 1;
        }
    }

    if (!is_graceful) {
        ap_run_pre_mpm(pconf, SB_SHARED);
    }

    set_signals();
    /* Don't thrash... */
    if (max_spare_threads < min_spare_threads + ap_threads_per_child)
	max_spare_threads = min_spare_threads + ap_threads_per_child;

    /* If we're doing a graceful_restart then we're going to see a lot
     * of children exiting immediately when we get into the main loop
     * below (because we just sent them AP_SIG_GRACEFUL).  This happens pretty
     * rapidly... and for each one that exits we'll start a new one until
     * we reach at least daemons_min_free.  But we may be permitted to
     * start more than that, so we'll just keep track of how many we're
     * supposed to start up without the 1 second penalty between each fork.
     */
    remaining_children_to_start = ap_daemons_to_start;
    if (remaining_children_to_start > ap_daemons_limit) {
	remaining_children_to_start = ap_daemons_limit;
    }
    if (!is_graceful) {
	startup_children(remaining_children_to_start);
	remaining_children_to_start = 0;
    }
    else {
	/* give the system some time to recover before kicking into
	    * exponential mode */
	hold_off_on_exponential_spawning = 10;
    }

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		"%s configured -- resuming normal operations",
		ap_get_server_version());
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, ap_server_conf,
		"Server built: %s", ap_get_server_built());
    restart_pending = shutdown_pending = 0;

    server_main_loop(remaining_children_to_start);

    if (shutdown_pending) {
        /* Time to gracefully shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        wake_up_and_die();

        if (unixd_killpg(getpgrp(), SIGTERM) < 0) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "killpg SIGTERM");
        }
        ap_reclaim_child_processes(1);		/* Start with SIGTERM */

        if (!child_fatal) {
            /* cleanup pid file on normal shutdown */
            const char *pidfile = NULL;
            pidfile = ap_server_root_relative (pconf, ap_pid_fname);
            if ( pidfile != NULL && unlink(pidfile) == 0)
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0,
            		 ap_server_conf,
            		 "removed PID file %s (pid=%ld)",
            		 pidfile, (long)getpid());
    
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                         ap_server_conf, "caught SIGTERM, shutting down");
        }
	return 1;
    }

    /* we've been told to restart */
    apr_signal(SIGHUP, SIG_IGN);

    if (one_process) {
	/* not worth thinking about */
	return 1;
    }

    /* advance to the next generation */
    /* XXX: we really need to make sure this new generation number isn't in
     * use by any of the children.
     */
    ++ap_my_generation;
    ap_scoreboard_image->global.running_generation = ap_my_generation;
    update_scoreboard_global();
    
    /* wake up the children...time to die.  But we'll have more soon */
    wake_up_and_die();
    
    if (is_graceful) {
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		    AP_SIG_GRACEFUL_STRING " received.  Doing graceful restart");

	/* This is mostly for debugging... so that we know what is still
         * gracefully dealing with existing request.
         */
	
    }
    else {
      /* Kill 'em all.  Since the child acts the same on the parents SIGTERM 
       * and a SIGHUP, we may as well use the same signal, because some user
       * pthreads are stealing signals from us left and right.
       */
	if (unixd_killpg(getpgrp(), SIGTERM) < 0) {
	    ap_log_error(APLOG_MARK, APLOG_WARNING, errno, ap_server_conf, "killpg SIGTERM");
	}
        ap_reclaim_child_processes(1);		/* Start with SIGTERM */
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, ap_server_conf,
		    "SIGHUP received.  Attempting to restart");
    }
    return 0;
}

static void worker_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static int restart_num = 0;
    int no_detach, debug;
    ap_directive_t *pdir;
    ap_directive_t *max_clients = NULL;

    /* make sure that "ThreadsPerChild" gets set before "MaxClients" */
    for (pdir = ap_conftree; pdir != NULL; pdir = pdir->next) {
        if (strncasecmp(pdir->directive, "ThreadsPerChild", 15) == 0) {
            if (!max_clients) {
                break; /* we're in the clear, got ThreadsPerChild first */
            }
            else {
                /* now to swap the data */
                ap_directive_t temp;

                temp.directive = pdir->directive;
                temp.args = pdir->args;
                /* Make sure you don't change 'next', or you may get loops! */
                /* XXX: first_child, parent, and data can never be set
                 * for these directives, right? -aaron */
                temp.filename = pdir->filename;
                temp.line_num = pdir->line_num;

                pdir->directive = max_clients->directive;
                pdir->args = max_clients->args;
                pdir->filename = max_clients->filename;
                pdir->line_num = max_clients->line_num;
                
                max_clients->directive = temp.directive;
                max_clients->args = temp.args;
                max_clients->filename = temp.filename;
                max_clients->line_num = temp.line_num;
                break;
            }
        }
        else if (!max_clients
                && strncasecmp(pdir->directive, "MaxClients", 10) == 0) {
            max_clients = pdir;
        }
    }

    debug = ap_exists_config_define("DEBUG");

    if (debug)
        no_detach = one_process = 1;
    else
    {
        one_process = ap_exists_config_define("ONE_PROCESS");
        no_detach = ap_exists_config_define("NO_DETACH");
    }

    /* sigh, want this only the second time around */
    if (restart_num++ == 1) {
	is_graceful = 0;

	if (!one_process && !no_detach) {
	    apr_proc_detach();
	}
	parent_pid = ap_my_pid = getpid();
    }

    unixd_pre_config(ptemp);
    ap_listen_pre_config();
    ap_daemons_to_start = DEFAULT_START_DAEMON;
    min_spare_threads = DEFAULT_MIN_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    max_spare_threads = DEFAULT_MAX_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    ap_daemons_limit = HARD_SERVER_LIMIT;
    ap_threads_per_child = DEFAULT_THREADS_PER_CHILD;
    ap_pid_fname = DEFAULT_PIDLOG;
    ap_scoreboard_fname = DEFAULT_SCOREBOARD;
    lock_fname = DEFAULT_LOCKFILE;
    ap_max_requests_per_child = DEFAULT_MAX_REQUESTS_PER_CHILD;
    ap_extended_status = 0;

    apr_cpystrn(ap_coredump_dir, ap_server_root, sizeof(ap_coredump_dir));
}

static void worker_hooks(apr_pool_t *p)
{
    one_process = 0;

    ap_hook_pre_config(worker_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *set_daemons_to_start(cmd_parms *cmd, void *dummy,
					const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_to_start = atoi(arg);
    return NULL;
}

static const char *set_min_spare_threads(cmd_parms *cmd, void *dummy,
					 const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    min_spare_threads = atoi(arg);
    if (min_spare_threads <= 0) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "WARNING: detected MinSpareThreads set to non-positive.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "Resetting to 1 to avoid almost certain Apache failure.");
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "Please read the documentation.");
       min_spare_threads = 1;
    }
       
    return NULL;
}

static const char *set_max_spare_threads(cmd_parms *cmd, void *dummy,
					 const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_spare_threads = atoi(arg);
    return NULL;
}

static const char *set_server_limit (cmd_parms *cmd, void *dummy,
				     const char *arg) 
{
    int max_clients;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    /* It is ok to use ap_threads_per_child here because we are
     * sure that it gets set before MaxClients in the pre_config stage. */
    max_clients = atoi(arg);
    if (max_clients < ap_threads_per_child) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "WARNING: MaxClients (%d) must be at least as large",
                    max_clients);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " large as ThreadsPerChild (%d). Automatically",
                    ap_threads_per_child);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " increasing MaxClients to %d.",
                    ap_threads_per_child);
       max_clients = ap_threads_per_child;
    }
    ap_daemons_limit = max_clients / ap_threads_per_child;
    if ((max_clients > 0) && (max_clients % ap_threads_per_child)) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "WARNING: MaxClients (%d) is not an integer multiple",
                    max_clients);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " of ThreadsPerChild (%d), lowering MaxClients to %d",
                    ap_threads_per_child,
                    ap_daemons_limit * ap_threads_per_child);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " for a maximum of %d child processes,",
                    ap_daemons_limit);
       max_clients = ap_daemons_limit * ap_threads_per_child; 
    }
    if (ap_daemons_limit > HARD_SERVER_LIMIT) {
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    "WARNING: MaxClients of %d would require %d servers,",
                    max_clients, ap_daemons_limit);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " and would exceed the compile time limit of %d.",
                    HARD_SERVER_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " Automatically lowering MaxClients to %d.  To increase,",
                    HARD_SERVER_LIMIT);
       ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                    " please see the HARD_SERVER_LIMIT define in %s.",
                    AP_MPM_HARD_LIMITS_FILE);
       ap_daemons_limit = HARD_SERVER_LIMIT;
    } 
    else if (ap_daemons_limit < 1) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, "WARNING: Require MaxClients > 0, setting to 1");
	ap_daemons_limit = 1;
    }
    return NULL;
}

static const char *set_threads_per_child (cmd_parms *cmd, void *dummy,
					  const char *arg) 
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_threads_per_child = atoi(arg);
    if (ap_threads_per_child > HARD_THREAD_LIMIT) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "WARNING: ThreadsPerChild of %d exceeds compile time "
                     "limit of %d threads,", ap_threads_per_child,
                     HARD_THREAD_LIMIT);
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     " lowering ThreadsPerChild to %d. To increase, please"
                     " see the", HARD_THREAD_LIMIT);
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     " HARD_THREAD_LIMIT define in %s.",
                     AP_MPM_HARD_LIMITS_FILE);
        ap_threads_per_child = HARD_THREAD_LIMIT;
    }
    else if (ap_threads_per_child < 1) {
	ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "WARNING: Require ThreadsPerChild > 0, setting to 1");
	ap_threads_per_child = 1;
    }
    return NULL;
}

static const command_rec worker_cmds[] = {
UNIX_DAEMON_COMMANDS,
LISTEN_COMMANDS,
AP_INIT_TAKE1("StartServers", set_daemons_to_start, NULL, RSRC_CONF,
  "Number of child processes launched at server startup"),
AP_INIT_TAKE1("MinSpareThreads", set_min_spare_threads, NULL, RSRC_CONF,
  "Minimum number of idle children, to handle request spikes"),
AP_INIT_TAKE1("MaxSpareThreads", set_max_spare_threads, NULL, RSRC_CONF,
  "Maximum number of idle children"),
AP_INIT_TAKE1("MaxClients", set_server_limit, NULL, RSRC_CONF,
  "Maximum number of children alive at the same time"),
AP_INIT_TAKE1("ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF,
  "Number of threads each child creates"),
{ NULL }
};

module AP_MODULE_DECLARE_DATA mpm_worker_module = {
    MPM20_MODULE_STUFF,
    NULL,                       /* hook to run before apache parses args */
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    NULL,			/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    worker_cmds,		/* command apr_table_t */
    worker_hooks		/* register_hooks */
};

