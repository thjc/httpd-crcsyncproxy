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
 * mod_isapi.c - Internet Server Application (ISA) module for Apache
 * by Alexei Kosut <akosut@apache.org>
 *
 * This module implements Microsoft's ISAPI, allowing Apache (when running
 * under Windows) to load Internet Server Applications (ISAPI extensions).
 * It implements all of the ISAPI 2.0 specification, except for the 
 * "Microsoft-only" extensions dealing with asynchronous I/O. All ISAPI
 * extensions that use only synchronous I/O and are compatible with the
 * ISAPI 2.0 specification should work (most ISAPI 1.0 extensions should
 * function as well).
 *
 * To load, simply place the ISA in a location in the document tree.
 * Then add an "AddHandler isapi-isa dll" into your config file.
 * You should now be able to load ISAPI DLLs just be reffering to their
 * URLs. Make sure the ExecCGI option is active in the directory
 * the ISA is in.
 */

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "util_script.h"
#include "apr_portable.h"
#include "apr_strings.h"


/* We use the exact same header file as the original */
#include <HttpExt.h>

/* TODO: Unknown errors that must be researched for correct codes */

#define TODO_ERROR 1

/* Seems IIS does not enforce the requirement for \r\n termination on HSE_REQ_SEND_RESPONSE_HEADER,
   define this to conform */
#define RELAX_HEADER_RULE

module isapi_module;

static DWORD ReadAheadBuffer = 49152;
static int LogNotSupported = -1;
static int AppendLogToErrors = 0;
static int AppendLogToQuery = 0;

/* Declare the ISAPI functions */

BOOL WINAPI GetServerVariable (HCONN hConn, LPSTR lpszVariableName,
                               LPVOID lpvBuffer, LPDWORD lpdwSizeofBuffer);
BOOL WINAPI WriteClient (HCONN ConnID, LPVOID Buffer, LPDWORD lpwdwBytes,
                         DWORD dwReserved);
BOOL WINAPI ReadClient (HCONN ConnID, LPVOID lpvBuffer, LPDWORD lpdwSize);
BOOL WINAPI ServerSupportFunction (HCONN hConn, DWORD dwHSERequest,
                                   LPVOID lpvBuffer, LPDWORD lpdwSize,
                                   LPDWORD lpdwDataType);

/*
    The optimiser blows it totally here. What happens is that autos are addressed relative to the
    stack pointer, which, of course, moves around. The optimiser seems to lose track of it somewhere
    between setting HttpExtensionProc's address and calling through it. We work around the problem by 
    forcing it to use frame pointers.

    The revisions below may eliminate this artifact.
*/
#pragma optimize("y",off)

/* Our loaded isapi module description structure */

typedef struct {
    HINSTANCE handle;
    HSE_VERSION_INFO *pVer;
    PFN_GETEXTENSIONVERSION GetExtensionVersion;
    PFN_HTTPEXTENSIONPROC   HttpExtensionProc;
    PFN_TERMINATEEXTENSION  TerminateExtension;
    int   refcount;
    DWORD timeout;
    BOOL  fakeasync;
    DWORD reportversion;
} isapi_loaded;

/* Our "Connection ID" structure */

typedef struct {
    LPEXTENSION_CONTROL_BLOCK ecb;
    isapi_loaded *isa;
    request_rec  *r;
    PFN_HSE_IO_COMPLETION completion;
    PVOID  completion_arg;
    HANDLE complete;
    apr_status_t retval;
} isapi_cid;

apr_status_t isapi_handler (request_rec *r)
{
    apr_table_t *e = r->subprocess_env;
    isapi_loaded *isa;
    isapi_cid *cid;
    DWORD read;
    char *fspec;
    char *p;
    int res;

    /* Use similar restrictions as CGIs
     *
     * If this fails, it's pointless to load the isapi dll.
     */
    if (!(ap_allow_options(r) & OPT_EXECCGI))
        return HTTP_FORBIDDEN;

    if (r->finfo.filetype == APR_NOFILE)
        return HTTP_NOT_FOUND;

    if (r->finfo.filetype != APR_REG)
        return HTTP_FORBIDDEN;

    /* Load the module...
     * per PR2555, the LoadLibraryEx function is very picky about slashes.
     * Debugging on NT 4 SP 6a reveals First Chance Exception within NTDLL.
     * LoadLibrary in the MS PSDK also reveals that it -explicitly- states
     * that backslashes must be used.
     *
     * Transpose '\' for '/' in the filename.
     */
    p = fspec = apr_pstrdup(r->pool, r->filename);
    while (*p) {
        if (*p == '/')
            *p = '\\';
        ++p;
    }

    /* Load the module 
     *
     * TODO: Critical section
     *
     * Warning: cid should not be allocated from request pool if we 
     * cache the isapi process in-memory.
     *
     * This code could use cacheing... everything that follows
     * should only be performed on the first isapi dll invocation, 
     * not with every HttpExtensionProc()
     */
    isa = apr_pcalloc(r->pool, sizeof(isapi_module));
    isa->pVer = apr_pcalloc(r->pool, sizeof(HSE_VERSION_INFO));
    isa->refcount = 0;

    /* TODO: These may need to become overrideable, so that we
     * assure a given isapi can be fooled into behaving well.
     */
    isa->timeout = INFINITE; /* microsecs */
    isa->fakeasync = TRUE;
    isa->reportversion = MAKELONG(0, 5); /* Revision 5.0 */
    
    if (!(isa->handle = LoadLibraryEx(r->filename, NULL,
                                      LOAD_WITH_ALTERED_SEARCH_PATH))) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, GetLastError(), r,
                      "ISAPI %s failed to load", r->filename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!(isa->GetExtensionVersion =
          (void *)(GetProcAddress(isa->handle, "GetExtensionVersion")))) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, GetLastError(), r,
                      "ISAPI %s is missing GetExtensionVersion()",
                      r->filename);
        FreeLibrary(isa->handle);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!(isa->HttpExtensionProc =
          (void *)(GetProcAddress(isa->handle, "HttpExtensionProc")))) {
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, GetLastError(), r,
                      "ISAPI %s is missing HttpExtensionProc()",
                      r->filename);
        FreeLibrary(isa->handle);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* TerminateExtension() is an optional interface */

    isa->TerminateExtension = (void *)(GetProcAddress(isa->handle, "TerminateExtension"));

    /* Run GetExtensionVersion() */

    if (!(*isa->GetExtensionVersion)(isa->pVer)) {
        /* ### euh... we're passing the wrong type of error code here */
        ap_log_rerror(APLOG_MARK, APLOG_ALERT, HTTP_INTERNAL_SERVER_ERROR, r,
                      "ISAPI %s call GetExtensionVersion() failed", 
                      r->filename);
        FreeLibrary(isa->handle);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Load of this module completed, this is the point at which *isa
     * could be cached for later invocation.
     *
     * on to invoking this request... 
     */
    
    /* Set up variables */
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);
    apr_table_setn(r->subprocess_env, "UNMAPPED_REMOTE_USER", "REMOTE_USER");
    apr_table_setn(r->subprocess_env, "SERVER_PORT_SECURE", "0");
    apr_table_setn(r->subprocess_env, "URL", r->uri);

    /* Set up connection structure and ecb */
    cid = apr_pcalloc(r->pool, sizeof(isapi_cid));
    cid->ecb = apr_pcalloc(r->pool, sizeof(struct _EXTENSION_CONTROL_BLOCK));
    cid->ecb->ConnID = (HCONN)cid;
    /* TODO: Critical section */
    ++isa->refcount;
    cid->isa = isa;
    cid->r = r;
    cid->r->status = 0;
    cid->complete = NULL;
    cid->completion = NULL;
    cid->retval = APR_SUCCESS;

    cid->ecb->cbSize = sizeof(EXTENSION_CONTROL_BLOCK);
    cid->ecb->dwVersion = isa->reportversion;
    cid->ecb->dwHttpStatusCode = 0;
    strcpy(cid->ecb->lpszLogData, "");
    // TODO: are copies really needed here?
    cid->ecb->lpszMethod = apr_pstrdup(r->pool, (char*) r->method);
    cid->ecb->lpszQueryString = apr_pstrdup(r->pool, 
                                (char*) apr_table_get(e, "QUERY_STRING"));
    cid->ecb->lpszPathInfo = apr_pstrdup(r->pool, 
                             (char*) apr_table_get(e, "PATH_INFO"));
    cid->ecb->lpszPathTranslated = apr_pstrdup(r->pool, 
                                   (char*) apr_table_get(e, "PATH_TRANSLATED"));
    cid->ecb->lpszContentType = apr_pstrdup(r->pool, 
                                (char*) apr_table_get(e, "CONTENT_TYPE"));
    /* Set up the callbacks */
    cid->ecb->GetServerVariable = &GetServerVariable;
    cid->ecb->WriteClient = &WriteClient;
    cid->ecb->ReadClient = &ReadClient;
    cid->ecb->ServerSupportFunction = &ServerSupportFunction;

    
    /* Set up client input */
    cid->retval = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
    if (cid->retval) {
        if (isa->TerminateExtension) {
            (*isa->TerminateExtension)(HSE_TERM_MUST_UNLOAD);
        }
        FreeLibrary(isa->handle);
        return cid->retval;
    }

    if (ap_should_client_block(r)) {
        /* Time to start reading the appropriate amount of data,
         * and allow the administrator to tweak the number
         * TODO: add the httpd.conf option for ReadAheadBuffer.
         */
        if (r->remaining) {
            cid->ecb->cbTotalBytes = r->remaining;
            if (cid->ecb->cbTotalBytes > ReadAheadBuffer)
                cid->ecb->cbAvailable = ReadAheadBuffer;
            else
                cid->ecb->cbAvailable = cid->ecb->cbTotalBytes;
        }
        else
        {
            cid->ecb->cbTotalBytes = 0xffffffff;
            cid->ecb->cbAvailable = ReadAheadBuffer;
        }

        cid->ecb->lpbData = apr_pcalloc(r->pool, cid->ecb->cbAvailable + 1);

        p = cid->ecb->lpbData;
        read = 0;
        while (read < cid->ecb->cbAvailable &&
               ((res = ap_get_client_block(r, cid->ecb->lpbData + read,
                                      cid->ecb->cbAvailable - read)) > 0)) {
            read += res;
        }

        if (res < 0) {
            cid->retval = HTTP_INTERNAL_SERVER_ERROR;
            goto contentfailure;
        }

        /* Although its not to spec, IIS seems to null-terminate
         * its lpdData string. So we will too.
         */
        if (res == 0)
            cid->ecb->cbAvailable = cid->ecb->cbTotalBytes = read;
        else
            cid->ecb->cbAvailable = read;
        cid->ecb->lpbData[read] = '\0';
    }
    else {
        cid->ecb->cbTotalBytes = 0;
        cid->ecb->cbAvailable = 0;
        cid->ecb->lpbData = NULL;
    }

    /* All right... try and run the sucker */
    cid->retval = (*isa->HttpExtensionProc)(cid->ecb);

    /* Set the status (for logging) */
    if (cid->ecb->dwHttpStatusCode) {
        cid->r->status = cid->ecb->dwHttpStatusCode;
    }

    /* Check for a log message - and log it */
    if (cid->ecb->lpszLogData && *cid->ecb->lpszLogData)
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                      "ISAPI %s: %s", r->filename, cid->ecb->lpszLogData);

    switch(cid->retval) {
        case HSE_STATUS_SUCCESS:
        case HSE_STATUS_SUCCESS_AND_KEEP_CONN:
            /* Ignore the keepalive stuff; Apache handles it just fine without
             * the ISA's "advice".
             * Per Microsoft: "In IIS versions 4.0 and later, the return
             * values HSE_STATUS_SUCCESS and HSE_STATUS_SUCCESS_AND_KEEP_CONN
             * are functionally identical: Keep-Alive connections are
             * maintained, if supported by the client."
             * ... so we were pat all this time
             */
            break;
            
        case HSE_STATUS_PENDING:    
            /* emulating async behavior...
             *
             * Create a cid->completed event and wait on it for some timeout
             * so that the app thinks is it running async.
             *
             * All async ServerSupportFunction calls will be handled through
             * the registered IO_COMPLETION hook.
             */
            
            if (!isa->fakeasync) {
                if (LogNotSupported)
                {
                     ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                                   "ISAPI %s asynch I/O request refused", 
                                   r->filename);
                     cid->retval = APR_ENOTIMPL;
                }
            }
            else {
                cid->complete = CreateEvent(NULL, FALSE, FALSE, NULL);
                if (WaitForSingleObject(cid->complete, isa->timeout)
                        == WAIT_TIMEOUT) {
                    /* TODO: Now what... if this hung, then do we kill our own
                     * thread to force it's death?  For now leave timeout = -1
                     */
                }
            }
            break;

        case HSE_STATUS_ERROR:    
            /* end response if we have yet to do so.
             */
            cid->retval = HTTP_INTERNAL_SERVER_ERROR;
            break;

        default:
            /* TODO: log unrecognized retval for debugging 
             */
            cid->retval = HTTP_INTERNAL_SERVER_ERROR;
            break;
    }

contentfailure:
    /* All done with the DLL... get rid of it...
     *
     * If optionally cached, pass HSE_TERM_ADVISORY_UNLOAD,
     * and if it returns TRUE, unload, otherwise, cache it.
     */
    if (isa->TerminateExtension) {
        (*isa->TerminateExtension)(HSE_TERM_MUST_UNLOAD);
    }
    FreeLibrary(isa->handle);
    /* TODO: Crit section */
    cid->isa = NULL;
    --isa->refcount;
    isa->handle = NULL;
    
    return cid->retval;
}
#pragma optimize("",on)

BOOL WINAPI GetServerVariable (HCONN hConn, LPSTR lpszVariableName,
                               LPVOID lpvBuffer, LPDWORD lpdwSizeofBuffer)
{
    request_rec *r = ((isapi_cid *)hConn)->r;
    apr_table_t *e = r->subprocess_env;
    const char *result;

    /* Mostly, we just grab it from the environment, but there are
     * a couple of special cases
     */

    if (!strcasecmp(lpszVariableName, "UNMAPPED_REMOTE_USER")) {
        /* We don't support NT users, so this is always the same as
         * REMOTE_USER
         */
        result = apr_table_get(e, "REMOTE_USER");
    }
    else if (!strcasecmp(lpszVariableName, "SERVER_PORT_SECURE")) {
        /* Apache doesn't support secure requests inherently, so
         * we have no way of knowing. We'll be conservative, and say
         * all requests are insecure.
         */
        result = "0";
    }
    else if (!strcasecmp(lpszVariableName, "URL")) {
        result = r->uri;
    }
    else {
        result = apr_table_get(e, lpszVariableName);
    }

    if (result) {
        if (strlen(result) > *lpdwSizeofBuffer) {
            *lpdwSizeofBuffer = strlen(result);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        strncpy(lpvBuffer, result, *lpdwSizeofBuffer);
        return TRUE;
    }

    /* Didn't find it */
    SetLastError(ERROR_INVALID_INDEX);
    return FALSE;
}

BOOL WINAPI WriteClient (HCONN ConnID, LPVOID Buffer, LPDWORD lpwdwBytes,
                         DWORD dwReserved)
{
    request_rec *r = ((isapi_cid *)ConnID)->r;
    int writ;   /* written, actually, but why shouldn't I make up words? */

    /* We only support synchronous writing */
    if (dwReserved && dwReserved != HSE_IO_SYNC) {
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          "ISAPI %s  asynch I/O request refused",
                          r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if ((writ = ap_rwrite(Buffer, *lpwdwBytes, r)) == EOF) {
        SetLastError(WSAEDISCON); /* TODO: Find the right error code */
        return FALSE;
    }

    *lpwdwBytes = writ;
    return TRUE;
}

BOOL WINAPI ReadClient (HCONN ConnID, LPVOID lpvBuffer, LPDWORD lpdwSize)
{
    request_rec *r = ((isapi_cid *)ConnID)->r;
    DWORD read = 0;
    int res;

    if (r->remaining < (long) *lpdwSize)
        *lpdwSize = r->remaining;

    while (read < *lpdwSize &&
           ((res = ap_get_client_block(r, (char*)lpvBuffer + read,
                                       *lpdwSize - read)) > 0)) {
        if (res < 0) {
            *lpdwSize = 0;
            if (!GetLastError())
                SetLastError(TODO_ERROR); /* XXX: Find the right error code */
            return FALSE;
        }

        read += res;
    }

    *lpdwSize = read;
    return TRUE;
}

static BOOL SendResponseHeaderEx(isapi_cid *cid, const char *stat,
                                 const char *head, size_t statlen,
                                 size_t headlen)
{
    int termarg;
    char *termch;

    if (!stat || !*stat) {
        stat = "Status: 200 OK";
    }
    else {
        char *newstat;
        if (statlen == 0)
            statlen = strlen(stat);
        /* Whoops... not NULL terminated */
        newstat = apr_palloc(cid->r->pool, statlen + 9);
        strcpy(newstat, "Status: ");
        strncpy(newstat + 8, stat, statlen);
        stat = newstat;
    }

    if (!head || !*head) {
        head = "\r\n";
    }
    else if ((headlen >= 0) && head[headlen]) {
        /* Whoops... not NULL terminated */
        head = apr_pstrndup(cid->r->pool, head, headlen);
    }

    /* Parse them out, or die trying */
    cid->retval = ap_scan_script_header_err_strs(cid->r, NULL, &termch,
                                                 &termarg, stat, head, NULL);
    cid->ecb->dwHttpStatusCode = cid->r->status;

    /* All the headers should be set now */
    ap_send_http_header(cid->r);

    /* Any data left should now be sent directly,
     * it may be raw if headlen was provided.
     */
    if (termch && (termarg == 1)) {
        if (headlen == -1 && *termch)
            ap_rputs(termch, cid->r);
        else if (headlen > (size_t) (termch - head))
            ap_rwrite(termch, headlen - (termch - head), cid->r);
    }

    if (cid->retval == HTTP_INTERNAL_SERVER_ERROR)
        return FALSE;
    return TRUE;
}

/* XXX: Is there is still an O(n^2) attack possible here?  Please detail. */
BOOL WINAPI ServerSupportFunction (HCONN hConn, DWORD dwHSERequest,
                                   LPVOID lpvBuffer, LPDWORD lpdwSize,
                                   LPDWORD lpdwDataType)
{
    isapi_cid *cid = (isapi_cid *)hConn;
    request_rec *r = cid->r;
    request_rec *subreq;

    switch (dwHSERequest) {
    case 1: /* HSE_REQ_SEND_URL_REDIRECT_RESP */
        /* Set the status to be returned when the HttpExtensionProc()
         * is done.
         * WARNING: Microsoft now advertises HSE_REQ_SEND_URL_REDIRECT_RESP
         *          and HSE_REQ_SEND_URL as equivalant per the Jan 2000 SDK.
         *          They most definately are not, even in their own samples.
         */
        apr_table_set (r->headers_out, "Location", lpvBuffer);
        cid->r->status = cid->ecb->dwHttpStatusCode 
                                               = HTTP_MOVED_TEMPORARILY;
        return TRUE;

    case 2: /* HSE_REQ_SEND_URL */
        /* Soak up remaining input */
        if (r->remaining > 0) {
            char argsbuffer[HUGE_STRING_LEN];
            while (ap_get_client_block(r, argsbuffer, HUGE_STRING_LEN));
        }

        /* Reset the method to GET */
        r->method = apr_pstrdup(r->pool, "GET");
        r->method_number = M_GET;

        /* Don't let anyone think there's still data */
        apr_table_unset(r->headers_in, "Content-Length");

        /* AV fault per PR3598 - redirected path is lost! */
        (char*)lpvBuffer = apr_pstrdup(r->pool, (char*)lpvBuffer);
        ap_internal_redirect((char*)lpvBuffer, r);
        return TRUE;

    case 3: /* HSE_REQ_SEND_RESPONSE_HEADER */
        /* Parse them out, or die trying */
        return SendResponseHeaderEx(cid, (char*) lpvBuffer,
                                    (char*) lpdwDataType, -1, -1);


        case HSE_REQ_DONE_WITH_SESSION:
            /* Signal to resume the thread completing this request
             */
            if (cid->complete)
                SetEvent(cid->complete);
            return TRUE;

    case 1001: /* HSE_REQ_MAP_URL_TO_PATH */
    {
        /* Map a URL to a filename */
        char *file = (char *)lpvBuffer;
        subreq = ap_sub_req_lookup_uri(apr_pstrndup(r->pool, file, *lpdwSize), r);

        strncpy(file, subreq->filename, *lpdwSize - 1);
        file[*lpdwSize - 1] = '\0';

        /* IIS puts a trailing slash on directories, Apache doesn't */
        if (subreq->finfo.filetype == APR_DIR) {
            DWORD l = strlen(file);
            if (l < *lpdwSize - 1) {
                file[l] = '\\';
                file[l + 1] = '\0';
            }
        }
        return TRUE;
    }

    case 1002: /* HSE_REQ_GET_SSPI_INFO */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                           "ISAPI ServerSupportFunction HSE_REQ_GET_SSPI_INFO "
                           "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
        
    case 1003: /* HSE_APPEND_LOG_PARAMETER */
        /* Log lpvBuffer, of lpdwSize bytes, in the URI Query (cs-uri-query) field
         */
        apr_table_set(r->notes, "isapi-parameter", (char*) lpvBuffer);
        if (AppendLogToQuery) {
            if (r->args)
                r->args = apr_pstrcat(r->pool, r->args, (char*) lpvBuffer, NULL);
            else
                r->args = apr_pstrdup(r->pool, (char*) lpvBuffer);
        }
        if (AppendLogToErrors)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                          "ISAPI %s: %s", cid->r->filename,
                          (char*) lpvBuffer);
        return TRUE;
        
    case 1005: /* HSE_REQ_IO_COMPLETION */
        /* TODO: Emulate a completion port, if we can...
         * Record the callback address and user defined argument...
         * we will call this after any async request (e.g. transmitfile)
         * as if the request had completed async execution.
         * Per MS docs... HSE_REQ_IO_COMPLETION replaces any prior call
         * to HSE_REQ_IO_COMPLETION, and lpvBuffer may be set to NULL.
         */
        if (!cid->isa->fakeasync)
            return FALSE;
        cid->completion = (PFN_HSE_IO_COMPLETION) lpvBuffer;
        cid->completion_arg = (PVOID) lpdwDataType;
        return TRUE;

    case 1006: /* HSE_REQ_TRANSMIT_FILE */
        /* Use TransmitFile... nothing wrong with that :)
         * Just not quite ready yet...
         */

        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          "ISAPI asynchronous I/O not supported: %s", 
                          r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
            
    case 1007: /* HSE_REQ_REFRESH_ISAPI_ACL */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          "ISAPI ServerSupportFunction "
                          "HSE_REQ_REFRESH_ISAPI_ACL "
                          "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    case 1008: /* HSE_REQ_IS_KEEP_CONN */
        *((LPBOOL) lpvBuffer) = (r->connection->keepalive == 1);
        return TRUE;

    case 1010: /* HSE_REQ_ASYNC_READ_CLIENT */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          "ISAPI asynchronous I/O not supported: %s", 
                          r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    case 1011: /* HSE_REQ_GET_IMPERSONATION_TOKEN  Added in ISAPI 4.0 */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          "ISAPI ServerSupportFunction "
                          "HSE_REQ_GET_IMPERSONATION_TOKEN "
                          "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    case 1012: /* HSE_REQ_MAP_URL_TO_PATH_EX */
    {
        /* Map a URL to a filename */
        LPHSE_URL_MAPEX_INFO info = (LPHSE_URL_MAPEX_INFO) lpdwDataType;
        char* test_uri = apr_pstrndup(r->pool, (char *)lpvBuffer, *lpdwSize);

        subreq = ap_sub_req_lookup_uri(test_uri, r);
        info->lpszPath[MAX_PATH - 1] = '\0';
        strncpy(info->lpszPath, subreq->filename, MAX_PATH - 1);
        info->cchMatchingURL = strlen(test_uri);        
        info->cchMatchingPath = strlen(info->lpszPath);
        /* Mapping started with assuming both strings matched.
         * Now roll on the path_info as a mismatch and handle
         * terminating slashes for directory matches.
         */
        if (subreq->path_info && *subreq->path_info) {
            strncpy(info->lpszPath + info->cchMatchingPath, subreq->path_info,
                    MAX_PATH - info->cchMatchingPath - 1);
            info->cchMatchingURL -= strlen(subreq->path_info);
            if (subreq->finfo.filetype == APR_DIR
                 && info->cchMatchingPath < MAX_PATH - 1) {
                /* roll forward over path_info's first slash */
                ++info->cchMatchingPath;
                ++info->cchMatchingURL;
            }
        }
        else if (subreq->finfo.filetype == APR_DIR
                 && info->cchMatchingPath < MAX_PATH - 1) {
            /* Add a trailing slash for directory */
            info->lpszPath[info->cchMatchingPath++] = '/';
            info->lpszPath[info->cchMatchingPath] = '\0';
        }

        /* If the matched isn't a file, roll match back to the prior slash */
        if (subreq->finfo.filetype == APR_NOFILE) {
            while (info->cchMatchingPath && info->cchMatchingURL) {
                if (info->lpszPath[info->cchMatchingPath - 1] == '/') 
                    break;
                --info->cchMatchingPath;
                --info->cchMatchingURL;
            }
        }
        
        /* Paths returned with back slashes */
        for (test_uri = info->lpszPath; *test_uri; ++test_uri)
            if (*test_uri == '/')
                *test_uri = '\\';
        
        /* is a combination of:
         * HSE_URL_FLAGS_READ         0x001 Allow read
         * HSE_URL_FLAGS_WRITE        0x002 Allow write
         * HSE_URL_FLAGS_EXECUTE      0x004 Allow execute
         * HSE_URL_FLAGS_SSL          0x008 Require SSL
         * HSE_URL_FLAGS_DONT_CACHE   0x010 Don't cache (VRoot only)
         * HSE_URL_FLAGS_NEGO_CERT    0x020 Allow client SSL cert
         * HSE_URL_FLAGS_REQUIRE_CERT 0x040 Require client SSL cert
         * HSE_URL_FLAGS_MAP_CERT     0x080 Map client SSL cert to account
         * HSE_URL_FLAGS_SSL128       0x100 Require 128-bit SSL cert
         * HSE_URL_FLAGS_SCRIPT       0x200 Allow script execution
         *
         * XxX: As everywhere, EXEC flags could use some work...
         *      and this could go further with more flags, as desired.
         */ 
        info->dwFlags = (subreq->finfo.protection & APR_UREAD    ? 0x001 : 0)
                      | (subreq->finfo.protection & APR_UWRITE   ? 0x002 : 0)
                      | (subreq->finfo.protection & APR_UEXECUTE ? 0x204 : 0);
        return TRUE;
    }

    case 1014: /* HSE_REQ_ABORTIVE_CLOSE */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          "ISAPI ServerSupportFunction HSE_REQ_ABORTIVE_CLOSE"
                          " is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;

    case 1015: /* HSE_REQ_GET_CERT_INFO_EX  Added in ISAPI 4.0 */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          "ISAPI ServerSupportFunction "
                          "HSE_REQ_GET_CERT_INFO_EX "
                          "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;

    case 1016: /* HSE_REQ_SEND_RESPONSE_HEADER_EX  Added in ISAPI 4.0 */
    {
        LPHSE_SEND_HEADER_EX_INFO shi
                                  = (LPHSE_SEND_HEADER_EX_INFO) lpvBuffer;
        /* XXX: ignore shi->fKeepConn?  We shouldn't need the advise */
        /* r->connection->keepalive = shi->fKeepConn; */
        return SendResponseHeaderEx(cid, shi->pszStatus, shi->pszHeader,
                                         shi->cchStatus, shi->cchHeader);
    }

    case 1017: /* HSE_REQ_CLOSE_CONNECTION  Added after ISAPI 4.0 */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          "ISAPI ServerSupportFunction "
                          "HSE_REQ_CLOSE_CONNECTION "
                          "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    case 1018: /* HSE_REQ_IS_CONNECTED  Added after ISAPI 4.0 */
        /* Returns True if client is connected c.f. MSKB Q188346
         * XXX: That statement is very ambigious... assuming the 
         * identical return mechanism as HSE_REQ_IS_KEEP_CONN.
         */
        *((LPBOOL) lpvBuffer) = (r->connection->aborted == 0);
        return TRUE;

    case 1020: /* HSE_REQ_EXTENSION_TRIGGER  Added after ISAPI 4.0 */
        /*  Undocumented - defined by the Microsoft Jan '00 Platform SDK
         */
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          "ISAPI ServerSupportFunction "
                          "HSE_REQ_EXTENSION_TRIGGER "
                          "is not supported: %s", r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;

    default:
        if (LogNotSupported)
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          "ISAPI ServerSupportFunction (%d) not supported: "
                          "%s", dwHSERequest, r->filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
}

/*
 * Command handler for the ISAPIReadAheadBuffer directive, which is TAKE1
 */
static const char *isapi_cmd_readaheadbuffer(cmd_parms *cmd, void *config, 
                                             char *arg)
{
    long val;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (((val = strtol(arg, (char **) &err, 10)) <= 0) || *err)
        return "ISAPIReadAheadBuffer must be a legitimate value.";
    
    ReadAheadBuffer = val;
    return NULL;
}

/*
 * Command handler for the ISAPIReadAheadBuffer directive, which is TAKE1
 */
static const char *isapi_cmd_lognotsupported(cmd_parms *cmd, void *config, 
                                             char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "on") == 0) {
        LogNotSupported = -1;
    }
    else if (strcasecmp(arg, "off") == 0) {
        LogNotSupported = 0;
    }
    else {
        return "ISAPILogNotSupported must be on or off";
    }
    return NULL;
}

static const char *isapi_cmd_appendlogtoerrors(cmd_parms *cmd, void *config, 
                                               char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "on") == 0) {
        AppendLogToErrors = -1;
    }
    else if (strcasecmp(arg, "off") == 0) {
        AppendLogToErrors = 0;
    }
    else {
        return "ISAPIAppendLogToErrors must be on or off";
    }
    return NULL;
}

static const char *isapi_cmd_appendlogtoquery(cmd_parms *cmd, void *config, 
                                               char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "on") == 0) {
        AppendLogToQuery = -1;
    }
    else if (strcasecmp(arg, "off") == 0) {
        AppendLogToQuery = 0;
    }
    else {
        return "ISAPIAppendLogToQuery must be on or off";
    }
    return NULL;
}

static const command_rec isapi_cmds[] = {
{ "ISAPIReadAheadBuffer", isapi_cmd_readaheadbuffer, NULL, RSRC_CONF, TAKE1, 
  "Maximum bytes to initially pass to the ISAPI handler" },
{ "ISAPILogNotSupported", isapi_cmd_lognotsupported, NULL, RSRC_CONF, TAKE1, 
  "Log requests not supported by the ISAPI server" },
{ "ISAPIAppendLogToErrors", isapi_cmd_appendlogtoerrors, NULL, RSRC_CONF, TAKE1, 
  "Send all Append Log requests to the error log" },
{ "ISAPIAppendLogToQuery", isapi_cmd_appendlogtoquery, NULL, RSRC_CONF, TAKE1, 
  "Append Log requests are concatinated to the query args" },
{ NULL }
};

handler_rec isapi_handlers[] = {
    { "isapi-isa", isapi_handler },
    { NULL}
};

module isapi_module = {
   STANDARD20_MODULE_STUFF,
   NULL,                        /* create per-dir config */
   NULL,                        /* merge per-dir config */
   NULL,                        /* server config */
   NULL,                        /* merge server config */
   isapi_cmds,                  /* command apr_table_t */
   isapi_handlers,              /* handlers */
   NULL                         /* register hooks */
};
