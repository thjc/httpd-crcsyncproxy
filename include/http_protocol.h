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

#ifndef APACHE_HTTP_PROTOCOL_H
#define APACHE_HTTP_PROTOCOL_H

#include "ap_hooks.h"
#include "apr_portable.h"
#include "apr_mmap.h"
#include "util_filter.h"
#include "ap_buckets.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @package HTTP protocol handling
 */

/*
 * Prototypes for routines which either talk directly back to the user,
 * or control the ones that eventually do.
 */

/**
 * Read a request and fill in the fields.
 * @param c The current connection
 * @return The new request_rec
 */ 
request_rec *ap_read_request(conn_rec *c);

/**
 * Send a single HTTP header field
 * @param r The current request
 * @param fieldname The Header field to send
 * @param fieldval The value of the header
 * @deffunc int ap_send_header_field(request_rec *r, const char *fieldname, const char *fieldval)
 */
API_EXPORT_NONSTD(int) ap_send_header_field(request_rec *r, const char *fieldname,
                      const char *fieldval);

/**
 * Send the minimal part of an HTTP response header.
 * @param r The current request
 * @warning Modules should be very careful about using this, and should 
 *          prefer ap_send_http_header().  Much of the HTTP/1.1 implementation 
 *          correctness depends on code in ap_send_http_header().
 * @deffunc void ap_basic_http_header(request_rec *r)
 */
API_EXPORT(void) ap_basic_http_header(request_rec *r);

/**
 * Send the Status-Line and header fields for HTTP response
 * @param l The current request
 * @deffunc void ap_send_http_header(request_rec *l)
 */
API_EXPORT(void) ap_send_http_header(request_rec *l);

/* Send the response to special method requests */

API_EXPORT(int) ap_send_http_trace(request_rec *r);
int ap_send_http_options(request_rec *r);

/* Finish up stuff after a request */

/**
 * Called at completion of sending the response.  It sends the terminating
 * protocol information.
 * @param r The current request
 * @deffunc void ap_finalize_request_protocol(request_rec *r)
 */
API_EXPORT(void) ap_finalize_request_protocol(request_rec *r);

/**
 * Send error back to client.
 * @param r The current request
 * @param recursive_error last arg indicates error status in case we get 
 *      an error in the process of trying to deal with an ErrorDocument 
 *      to handle some other error.  In that case, we print the default 
 *      report for the first thing that went wrong, and more briefly report 
 *      on the problem with the ErrorDocument.
 * @deffunc void ap_send_error_response(request_rec *r, int recursive_error)
 */
API_EXPORT(void) ap_send_error_response(request_rec *r, int recursive_error);

/* Set last modified header line from the lastmod date of the associated file.
 * Also, set content length.
 *
 * May return an error status, typically HTTP_NOT_MODIFIED (that when the
 * permit_cache argument is set to one).
 */

/**
 * Set the content length for this request
 * @param r The current request
 * @param length The new content length
 * @return Always 0, can be safely ignored
 * @deffunc int ap_set_content_length(request_rec *r, long length)
 */
API_EXPORT(int) ap_set_content_length(request_rec *r, long length);
/**
 * Set the keepalive status for this request
 * @param r The current request
 * @return 1 if keepalive can be set, 0 otherwise
 * @deffunc int ap_set_keepalive(request_rec *r)
 */
API_EXPORT(int) ap_set_keepalive(request_rec *r);
/**
 * Return the latest rational time from a request/mtime pair.  Mtime is 
 * returned unless it's in the future, in which case we return the current time.
 * @param r The current request
 * @param mtime The last modified time
 * @return the latest rational time.
 * @deffunc apr_time_t ap_rationalize_mtime(request_rec *r, apr_time_t mtime)
 */
API_EXPORT(apr_time_t) ap_rationalize_mtime(request_rec *r, apr_time_t mtime);
/**
 * Construct an entity tag from the resource information.  If it's a real
 * file, build in some of the file characteristics.
 * @param r The current request
 * @param force_weak Force the entity tag to be weak - it could be modified
 *                   again in as short an interval.
 * @return The entity tag
 * @deffunc char *ap_make_etag(request_rec *r, int force_weak)
 */ 
API_EXPORT(char *) ap_make_etag(request_rec *r, int force_weak);
/**
 * Set the E-tag outgoing header
 * @param The current request
 * @deffunc void ap_set_etag(request_rec *r)
 */
API_EXPORT(void) ap_set_etag(request_rec *r);
/**
 * Set the last modified time for the file being sent
 * @param r The current request
 * @deffunc void ap_set_last_modified(request_rec *r)
 */
API_EXPORT(void) ap_set_last_modified(request_rec *r);
/**
 * Implements condition GET rules for HTTP/1.1 specification.  This function
 * inspects the client headers and determines if the response fulfills 
 * the requirements specified.
 * @param r The current request
 * @return 1 if the response fulfills the condition GET rules, 0 otherwise
 * @deffunc int ap_meets_conditions(request_rec *r)
 */
API_EXPORT(int) ap_meets_conditions(request_rec *r);

/* Other ways to send stuff at the client.  All of these keep track
 * of bytes_sent automatically.  This indirection is intended to make
 * it a little more painless to slide things like HTTP-NG packetization
 * underneath the main body of the code later.  In the meantime, it lets
 * us centralize a bit of accounting (bytes_sent).
 *
 * These also return the number of bytes written by the call.
 * They should only be called with a timeout registered, for obvious reaasons.
 * (Ditto the send_header stuff).
 */

/**
 * Send an entire file to the client, using sendfile if supported by the 
 * current platform
 * @param fd The file to send.
 * @param r The current request
 * @param offset Offset into the file to start sending.
 * @param length Amount of data to send
 * @param nbytes Amount of data actually sent
 * @deffunc apr_status_t ap_send_fd(apr_file_t *fd, request_rec *r, apr_off_t offset, apr_size_t length, apr_size_t *nbytes);
 */
API_EXPORT(apr_status_t) ap_send_fd(apr_file_t *fd, request_rec *r, apr_off_t offset, 
                                   apr_size_t length, apr_size_t *nbytes);
/**
 * Send an MMAP'ed file to the client
 * @param mm The MMAP'ed file to send
 * @param r The current request
 * @param offset The offset into the MMAP to start sending
 * @param length The amount of data to send
 * @return The number of bytes sent
 * @deffunc size_t ap_send_mmap(apr_mmap_t *mm, request_rec *r, size_t offset, size_t length)
 */
API_EXPORT(size_t) ap_send_mmap(apr_mmap_t *mm, request_rec *r, size_t offset,
                             size_t length);

/**
 * Create a new method list with the specified number of preallocated
 * slots for extension methods.
 *
 * @param   p       Pointer to a pool in which the structure should be
 *                  allocated.
 * @param   nelts   Number of preallocated extension slots
 * @return  Pointer to the newly created structure.
 * @deffunc ap_method_list_t ap_make_method_list(apr_pool_t *p, int nelts)
 */
API_EXPORT(ap_method_list_t *) ap_make_method_list(apr_pool_t *p, int nelts);
API_EXPORT(void) ap_copy_method_list(ap_method_list_t *dest,
				     ap_method_list_t *src);
API_EXPORT_NONSTD(void) ap_method_list_do(int (*comp) (void *urec, const char *mname,
						       int mnum),
				          void *rec,
				          const ap_method_list_t *ml, ...);
API_EXPORT(void) ap_method_list_vdo(int (*comp) (void *urec, const char *mname,
						 int mnum),
				    void *rec, const ap_method_list_t *ml,
				    va_list vp);
/**
 * Search for an HTTP method name in an ap_method_list_t structure, and
 * return true if found.
 *
 * @param   method  String containing the name of the method to check.
 * @param   l       Pointer to a method list, such as cmd->methods_limited.
 * @return  1 if method is in the list, otherwise 0
 * @deffunc int ap_method_in_list(const char *method, ap_method_list_t *l)
 */
API_EXPORT(int) ap_method_in_list(ap_method_list_t *l, const char *method);

/**
 * Add an HTTP method name to an ap_method_list_t structure if it isn't
 * already listed.
 *
 * @param   method  String containing the name of the method to check.
 * @param   l       Pointer to a method list, such as cmd->methods_limited.
 * @return  None.
 * @deffunc void ap_method_in_list(ap_method_list_t *l, const char *method)
 */
API_EXPORT(void) ap_method_list_add(ap_method_list_t *l, const char *method);
    
/**
 * Remove an HTTP method name from an ap_method_list_t structure.
 *
 * @param   l       Pointer to a method list, such as cmd->methods_limited.
 * @param   method  String containing the name of the method to remove.
 * @return  None.
 * @deffunc void ap_method_list_remove(ap_method_list_t *l, const char *method)
 */
API_EXPORT(void) ap_method_list_remove(ap_method_list_t *l,
				       const char *method);

/**
 * Reset a method list to be completely empty.
 *
 * @param   l       Pointer to a method list, such as cmd->methods_limited.
 * @return  None.
 * @deffunc void ap_clear_method_list(ap_method_list_t *l)
 */
API_EXPORT(void) ap_clear_method_list(ap_method_list_t *l);
    
/* Hmmm... could macrofy these for now, and maybe forever, though the
 * definitions of the macros would get a whole lot hairier.
 */

/**
 * Output one character for this request
 * @param c the character to output
 * @param r the current request
 * @return The number of bytes sent
 * @deffunc int ap_rputc(int c, request_rec *r)
 */
API_EXPORT(int) ap_rputc(int c, request_rec *r);
/**
 * Output a string for the current request
 * @param str The string to output
 * @param r The current request
 * @return The number of bytes sent
 * @deffunc int ap_rputs(const char *str, request_rec *r)
 */
API_EXPORT(int) ap_rputs(const char *str, request_rec *r);
/**
 * Write a buffer for the current request
 * @param buf The buffer to write
 * @param nbyte The number of bytes to send from the buffer
 * @param r The current request
 * @return The number of bytes sent
 * @deffunc int ap_rwrite(const void *buf, int nbyte, request_rec *r)
 */
API_EXPORT(int) ap_rwrite(const void *buf, int nbyte, request_rec *r);
/**
 * Write an unspecified number of strings to the request
 * @param r The current request
 * @param ... The strings to write
 * @return The number of bytes sent
 * @deffunc int ap_rvputs(request_rec *r, ...)
 */
API_EXPORT_NONSTD(int) ap_rvputs(request_rec *r,...);
/**
 * Output data to the client in a printf format
 * @param r The current request
 * @param fmt The format string
 * @param vlist The arguments to use to fill out the format string
 * @return The number of bytes sent
 * @deffunc int ap_vrprintf(request_rec *r, const char *fmt, va_list vlist)
 */
API_EXPORT(int) ap_vrprintf(request_rec *r, const char *fmt, va_list vlist);
/**
 * Output data to the client in a printf format
 * @param r The current request
 * @param fmt The format string
 * @param ... The arguments to use to fill out the format string
 * @return The number of bytes sent
 * @deffunc int ap_rprintf(request_rec *r, const char *fmt, ...)
 */
API_EXPORT_NONSTD(int) ap_rprintf(request_rec *r, const char *fmt,...)
				__attribute__((format(printf,2,3)));
/**
 * Flush all of the data for the current request to the client
 * @param r The current request
 * @return The number of bytes sent
 * @deffunc int ap_rflush(request_rec *r)
 */
API_EXPORT(int) ap_rflush(request_rec *r);

/**
 * Index used in custom_responses array for a specific error code
 * (only use outside protocol.c is in getting them configured).
 * @param status HTTP status code
 * @return The index of the response
 * @deffunc int ap_index_of_response(int status)
 */
API_EXPORT(int) ap_index_of_response(int status);

/** 
 * Return the Status-Line for a given status code (excluding the
 * HTTP-Version field). If an invalid or unknown status code is
 * passed, "500 Internal Server Error" will be returned. 
 * @param status The HTTP status code
 * @return The Status-Line
 * @deffunc const char *ap_get_status_line(int status)
 */
API_EXPORT(const char *) ap_get_status_line(int status);

/* Reading a block of data from the client connection (e.g., POST arg) */

/**
 * Setup the client to allow Apache to read the request body.
 * @param r The current request
 * @param read_policy How the server should interpret a chunked 
 *                    transfer-encoding.  One of: <PRE>
 *    REQUEST_NO_BODY          Send 413 error if message has any body
 *    REQUEST_CHUNKED_ERROR    Send 411 error if body without Content-Length
 *    REQUEST_CHUNKED_DECHUNK  If chunked, remove the chunks for me.
 *    REQUEST_CHUNKED_PASS     Pass the chunks to me without removal.
 * </PRE>
 * @return either OK or an error code
 * @deffunc int ap_setup_cleint_block(request_rec *r, int read_policy)
 */
API_EXPORT(int) ap_setup_client_block(request_rec *r, int read_policy);
/**
 * Determine if the client has sent any data.  This also sends a 
 * 100 Continue resposne to HTTP/1.1 clients, so modules should not be called
 * until the module is ready to read content.
 * @warning Never call this function more than once.
 * @param r The current request
 * @return 0 if there is no message to read, 1 otherwise
 * @deffunc int ap_should_client_block(request_rec *r)
 */
API_EXPORT(int) ap_should_client_block(request_rec *r);
/**
 * Call this in a loop.  It will put data into a buffer and return the length
 * of the input block
 * @param r The current request
 * @param buffer The buffer in which to store the data
 * @param bufsiz The size of the buffer
 * @return Number of bytes inserted into the buffer.  When done reading, 0
 *         if EOF, or -1 if there was an error
 * @deffunc long ap_get_client_block(request_rec *r, char *buffer, int bufsiz)
 */
API_EXPORT(long) ap_get_client_block(request_rec *r, char *buffer, int bufsiz);
/**
 * In HTTP/1.1, any method can have a body.  However, most GET handlers
 * wouldn't know what to do with a request body if they received one.
 * This helper routine tests for and reads any message body in the request,
 * simply discarding whatever it receives.  We need to do this because
 * failing to read the request body would cause it to be interpreted
 * as the next request on a persistent connection.
 * @param r The current request
 * @return error status if request is malformed, OK otherwise 
 * @deffunc int ap_discard_request_body(request_rec *r)
 */
API_EXPORT(int) ap_discard_request_body(request_rec *r);

/* Sending a byterange */

/**
 * Setup the request to send Byte Range requests
 * @param r the current request
 * @return 1 if request was setup for byte range requests, 0 otherwise
 * @deffunc int ap_set_byterange(request_rec *r)
 */
API_EXPORT(int) ap_set_byterange(request_rec *r);
/**
 * Send one byte range chunk for a byte range request
 * @param r The current request
 * @param offset Set to the position it should be after the chunk is sent
 * @param length Set to the length in should be after the chunk is sent
 * @deffunc int ap_each_byterange(request_rec *r, apr_off_t *offset, apr_size_t *length)
 */
API_EXPORT(int) ap_each_byterange(request_rec *r, apr_off_t *offset,
				  apr_size_t *length);
/**
 * Setup the output headers so that the client knows how to authenticate
 * itself the next time, if an authentication request failed.  This function
 * works for both basic and digest authentication
 * @param r The current request
 * @deffunc void ap_note_auth_failure(request_rec *r)
 */ 
API_EXPORT(void) ap_note_auth_failure(request_rec *r);
/**
 * Setup the output headers so that the client knows how to authenticate
 * itself the next time, if an authentication request failed.  This function
 * works only for basic authentication
 * @param r The current request
 * @deffunc void ap_note_basic_auth_failure(request_rec *r)
 */ 
API_EXPORT(void) ap_note_basic_auth_failure(request_rec *r);
/**
 * Setup the output headers so that the client knows how to authenticate
 * itself the next time, if an authentication request failed.  This function
 * works only for digest authentication
 * @param r The current request
 * @deffunc void ap_note_digest_auth_failure(request_rec *r)
 */ 
API_EXPORT(void) ap_note_digest_auth_failure(request_rec *r);
/**
 * Get the password from the request headers
 * @param r The current request
 * @param pw The password as set in the headers
 * @return 0 (OK) if it set the 'pw' argument (and assured
 *         a correct value in r->connection->user); otherwise it returns 
 *         an error code, either HTTP_INTERNAL_SERVER_ERROR if things are 
 *         really confused, HTTP_UNAUTHORIZED if no authentication at all 
 *         seemed to be in use, or DECLINED if there was authentication but 
 *         it wasn't Basic (in which case, the caller should presumably 
 *         decline as well).
 * @deffunc int ap_get_basic_auth_pw(request_rec *r, const char **pw)
 */
API_EXPORT(int) ap_get_basic_auth_pw(request_rec *r, const char **pw);

/*
 * Setting up the protocol fields for subsidiary requests...
 * Also, a wrapup function to keep the internal accounting straight.
 */

void ap_set_sub_req_protocol(request_rec *rnew, const request_rec *r);
void ap_finalize_sub_req_protocol(request_rec *sub_r);

/**
 * parse_uri: break apart the uri
 * @warning Side Effects: <PRE>
 *    - sets r->args to rest after '?' (or NULL if no '?')
 *    - sets r->uri to request uri (without r->args part)
 *    - sets r->hostname (if not set already) from request (scheme://host:port)
 * </PRE>
 * @param r The current request
 * @param uri The uri to break apart
 * @deffunc void ap_parse_uri(request_rec *r, const char *uri)
 */
CORE_EXPORT(void) ap_parse_uri(request_rec *r, const char *uri);

/**
 * Get the method number associated with the given string, assumed to
 * contain an HTTP method.  Returns M_INVALID if not recognized.
 * @param method A string containing a valid HTTP method
 * @return The method number
 * @deffunc int ap_method_number_of(const char *method)
 */
API_EXPORT(int) ap_method_number_of(const char *method);

/**
 * Get the method name associated with the given internal method
 * number.  Returns NULL if not recognized.
 * @param methnum An integer value corresponding to an internal method number
 * @return The name corresponding to the method number
 * @deffunc const char *ap_method_name_of(int methnum)
 */
API_EXPORT(const char *) ap_method_name_of(int methnum);

int http_filter(ap_filter_t *f, ap_bucket_brigade *b, apr_ssize_t length);

  /* Hooks */
  /*
   * post_read_request --- run right after read_request or internal_redirect,
   *                  and not run during any subrequests.
   */
/**
 * This hook allows modules to affect the request immediately after the request
 * has been read, and before any other phases have been processes.  This allows
 * modules to make decisions based upon the input header fields
 * @param r The current request
 * @return OK or DECLINED
 * @deffunc ap_run_post_read_request(request_rec *r)
 */
AP_DECLARE_HOOK(int,post_read_request,(request_rec *))
/**
 * This hook allows modules to perform any module-specific logging activities
 * over and above the normal server things.
 * @param r The current request
 * @return OK, DECLINED, or HTTP_...
 * @deffunc int ap_run_log_transaction(request_rec *r)
 */
AP_DECLARE_HOOK(int,log_transaction,(request_rec *))
/**
 * This hook allows modules to retrieve the http method from a request.  This
 * allows Apache modules to easily extend the methods that Apache understands
 * @param r The current request
 * @return The http method from the request
 * @deffunc const char *ap_run_http_method(const request_rec *r)
 */
AP_DECLARE_HOOK(const char *,http_method,(const request_rec *))
/**
 * Return the default port from the current request
 * @param r The current request
 * @return The current port
 * @deffunc unsigned short ap_run_default_port(const request_rec *r)
 */
AP_DECLARE_HOOK(unsigned short,default_port,(const request_rec *))

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_HTTP_PROTOCOL_H */
