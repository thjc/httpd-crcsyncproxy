/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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

#include "httpd.h"
#include "http_log.h"
#include "mpm_winnt.h"
#include "apr_strings.h"
#include "apr_lib.h"

#include "apr_dbg_win32_handles.h"


static char  *display_name  = NULL;
static HANDLE stderr_thread = NULL;
static HANDLE stderr_ready;

static DWORD WINAPI service_stderr_thread(LPVOID hPipe)
{
    HANDLE hPipeRead = (HANDLE) hPipe;
    HANDLE hEventSource;
    char errbuf[256];
    char *errmsg = errbuf;
    const char *errarg[9];
    DWORD errres;
    HKEY hk;
    
    errarg[0] = "The Apache service named";
    errarg[1] = display_name;
    errarg[2] = "reported the following error:\r\n>>>";
    errarg[3] = errbuf;
    errarg[4] = NULL;
    errarg[5] = NULL;
    errarg[6] = NULL;
    errarg[7] = NULL;
    errarg[8] = NULL;

    /* What are we going to do in here, bail on the user?  not. */
    if (!RegCreateKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services"
                      "\\EventLog\\Application\\Apache Service", &hk)) 
    {
        /* The stock message file */
        char *netmsgkey = "%SystemRoot%\\System32\\netmsg.dll";
        DWORD dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | 
                       EVENTLOG_INFORMATION_TYPE; 
 
        RegSetValueEx(hk, "EventMessageFile", 0, REG_EXPAND_SZ,
                          (LPBYTE) netmsgkey, strlen(netmsgkey) + 1);
        
        RegSetValueEx(hk, "TypesSupported", 0, REG_DWORD,
                          (LPBYTE) &dwData, sizeof(dwData));
        RegCloseKey(hk);
    }

    hEventSource = RegisterEventSource(NULL, "Apache Service");

    SetEvent(stderr_ready);

    while (ReadFile(hPipeRead, errmsg, 1, &errres, NULL) && (errres == 1))
    {
        if ((errmsg > errbuf) || !isspace(*errmsg))
        {
            ++errmsg;
            if ((*(errmsg - 1) == '\n') 
                    || (errmsg >= errbuf + sizeof(errbuf) - 1))
            {
                while ((errmsg > errbuf) && isspace(*(errmsg - 1))) {
                    --errmsg;
                }
                *errmsg = '\0';

                /* Generic message: '%1 %2 %3 %4 %5 %6 %7 %8 %9'
                 * The event code in netmsg.dll is 3299
                 */
                ReportEvent(hEventSource, EVENTLOG_ERROR_TYPE, 0, 
                            3299, NULL, 9, 0, errarg, NULL);
                errmsg = errbuf;
            }
        }
    }

    if ((errres = GetLastError()) != ERROR_BROKEN_PIPE) {
        apr_snprintf(errbuf, sizeof(errbuf),
                     "Win32 error %d reading stderr pipe stream\r\n", 
                     GetLastError());

        ReportEvent(hEventSource, EVENTLOG_ERROR_TYPE, 0, 
                    3299, NULL, 9, 0, errarg, NULL);
    }

    CloseHandle(hPipeRead);
    DeregisterEventSource(hEventSource);
    CloseHandle(stderr_thread);
    stderr_thread = NULL;
    return 0;
}


void mpm_nt_eventlog_stderr_flush(void)
{
    HANDLE cleanup_thread = stderr_thread;

    if (cleanup_thread) {
        HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
        fclose(stderr);
        CloseHandle(hErr);
        WaitForSingleObject(cleanup_thread, 30000);
        CloseHandle(cleanup_thread);
    }
}


void mpm_nt_eventlog_stderr_open(char *argv0, apr_pool_t *p)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE hProc = GetCurrentProcess();
    HANDLE hPipeRead = NULL;
    HANDLE hPipeWrite = NULL;
    HANDLE hDup = NULL;
    DWORD  threadid;
    int    fd;

    display_name = argv0;

    /* Create a pipe to send stderr messages to the system error log.
     *
     * _dup2() duplicates the write handle inheritable for us.
     */
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;
    CreatePipe(&hPipeRead, &hPipeWrite, NULL, 0); 
    ap_assert(hPipeRead && hPipeWrite);

    stderr_ready = CreateEvent(NULL, FALSE, FALSE, NULL);
    stderr_thread = CreateThread(NULL, 0, service_stderr_thread,
                                 (LPVOID) hPipeRead, 0, &threadid);
    ap_assert(stderr_ready && stderr_thread);

    WaitForSingleObject(stderr_ready, INFINITE);

    /* Flush stderr and unset its buffer, then commit and replace stderr.
     * This is typically a noop for Win2K/XP since services with NULL std 
     * handles [but valid FILE *'s, oddly enough], but is required 
     * for NT 4.0 and to use this code outside of services.
     */
    fflush(stderr);
    setvbuf(stderr, NULL, _IONBF, 0);
    _commit(2 /* stderr */);
    fd = _open_osfhandle((long) hPipeWrite, 
                         _O_WRONLY | _O_BINARY);
    _dup2(fd, 2);
    _close(fd);
    _setmode(2, _O_BINARY);

    /* hPipeWrite was _close()'ed above, and _dup2()'ed
     * to fd 2 creating a new, inherited Win32 handle.
     * Recover that real handle from fd 2.
     */
    hPipeWrite = (HANDLE)_get_osfhandle(2);

    SetStdHandle(STD_ERROR_HANDLE, hPipeWrite);

    /* The code above _will_ corrupt the StdHandle... 
     * and we must do so anyways.  We set this up only
     * after we initialized the posix stderr API.
     */
    ap_open_stderr_log(p);
}
