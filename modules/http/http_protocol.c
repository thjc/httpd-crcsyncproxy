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

/*
 * http_protocol.c --- routines which directly communicate with the client.
 *
 * Code originally by Rob McCool; much redone by Robert S. Thau
 * and the Apache Software Foundation.
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_signal.h"

#define APR_WANT_STDIO          /* for sscanf */
#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#define CORE_PRIVATE
#include "util_filter.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_request.h"
#include "http_vhost.h"
#include "http_log.h"           /* For errors detected in basic auth common
                                 * support code... */
#include "util_date.h"          /* For parseHTTPdate and BAD_DATE */
#include "util_charset.h"
#include "util_ebcdic.h"

#include "mod_core.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif


AP_DECLARE(int) ap_set_keepalive(request_rec *r)
{
    int ka_sent = 0;
    int wimpy = ap_find_token(r->pool,
                           apr_table_get(r->headers_out, "Connection"), "close");
    const char *conn = apr_table_get(r->headers_in, "Connection");

    /* The following convoluted conditional determines whether or not
     * the current connection should remain persistent after this response
     * (a.k.a. HTTP Keep-Alive) and whether or not the output message
     * body should use the HTTP/1.1 chunked transfer-coding.  In English,
     *
     *   IF  we have not marked this connection as errored;
     *   and the response body has a defined length due to the status code
     *       being 304 or 204, the request method being HEAD, already
     *       having defined Content-Length or Transfer-Encoding: chunked, or
     *       the request version being HTTP/1.1 and thus capable of being set
     *       as chunked [we know the (r->chunked = 1) side-effect is ugly];
     *   and the server configuration enables keep-alive;
     *   and the server configuration has a reasonable inter-request timeout;
     *   and there is no maximum # requests or the max hasn't been reached;
     *   and the response status does not require a close;
     *   and the response generator has not already indicated close;
     *   and the client did not request non-persistence (Connection: close);
     *   and    we haven't been configured to ignore the buggy twit
     *       or they're a buggy twit coming through a HTTP/1.1 proxy
     *   and    the client is requesting an HTTP/1.0-style keep-alive
     *       or the client claims to be HTTP/1.1 compliant (perhaps a proxy);
     *   THEN we can be persistent, which requires more headers be output.
     *
     * Note that the condition evaluation order is extremely important.
     */
    if ((r->connection->keepalive != -1)
	&& ((r->status == HTTP_NOT_MODIFIED)
	    || (r->status == HTTP_NO_CONTENT)
	    || r->header_only
	    || apr_table_get(r->headers_out, "Content-Length")
	    || ap_find_last_token(r->pool,
				  apr_table_get(r->headers_out,
						"Transfer-Encoding"),
				  "chunked")
	    || ((r->proto_num >= HTTP_VERSION(1,1))
		&& (r->chunked = 1))) /* THIS CODE IS CORRECT, see comment above. */
        && r->server->keep_alive
	&& (r->server->keep_alive_timeout > 0)
	&& ((r->server->keep_alive_max == 0)
	    || (r->server->keep_alive_max > r->connection->keepalives))
	&& !ap_status_drops_connection(r->status)
	&& !wimpy
	&& !ap_find_token(r->pool, conn, "close")
	&& (!apr_table_get(r->subprocess_env, "nokeepalive")
	    || apr_table_get(r->headers_in, "Via"))
	&& ((ka_sent = ap_find_token(r->pool, conn, "keep-alive"))
	    || (r->proto_num >= HTTP_VERSION(1,1)))) {
        int left = r->server->keep_alive_max - r->connection->keepalives;

        r->connection->keepalive = 1;
        r->connection->keepalives++;

        /* If they sent a Keep-Alive token, send one back */
        if (ka_sent) {
            if (r->server->keep_alive_max)
		apr_table_setn(r->headers_out, "Keep-Alive",
		    apr_psprintf(r->pool, "timeout=%d, max=%d",
                            r->server->keep_alive_timeout, left));
            else
		apr_table_setn(r->headers_out, "Keep-Alive",
		    apr_psprintf(r->pool, "timeout=%d",
                            r->server->keep_alive_timeout));
            apr_table_mergen(r->headers_out, "Connection", "Keep-Alive");
        }

        return 1;
    }

    /* Otherwise, we need to indicate that we will be closing this
     * connection immediately after the current response.
     *
     * We only really need to send "close" to HTTP/1.1 clients, but we
     * always send it anyway, because a broken proxy may identify itself
     * as HTTP/1.0, but pass our request along with our HTTP/1.1 tag
     * to a HTTP/1.1 client. Better safe than sorry.
     */
    if (!wimpy)
	apr_table_mergen(r->headers_out, "Connection", "close");

    r->connection->keepalive = 0;

    return 0;
}

AP_DECLARE(int) ap_meets_conditions(request_rec *r)
{
    const char *etag = apr_table_get(r->headers_out, "ETag");
    const char *if_match, *if_modified_since, *if_unmodified, *if_nonematch;
    apr_time_t mtime;

    /* Check for conditional requests --- note that we only want to do
     * this if we are successful so far and we are not processing a
     * subrequest or an ErrorDocument.
     *
     * The order of the checks is important, since ETag checks are supposed
     * to be more accurate than checks relative to the modification time.
     * However, not all documents are guaranteed to *have* ETags, and some
     * might have Last-Modified values w/o ETags, so this gets a little
     * complicated.
     */

    if (!ap_is_HTTP_SUCCESS(r->status) || r->no_local_copy) {
        return OK;
    }

    /* XXX: we should define a "time unset" constant */
    mtime = (r->mtime != 0) ? r->mtime : apr_time_now();

    /* If an If-Match request-header field was given
     * AND the field value is not "*" (meaning match anything)
     * AND if our strong ETag does not match any entity tag in that field,
     *     respond with a status of 412 (Precondition Failed).
     */
    if ((if_match = apr_table_get(r->headers_in, "If-Match")) != NULL) {
        if (if_match[0] != '*'
	    && (etag == NULL || etag[0] == 'W'
		|| !ap_find_list_item(r->pool, if_match, etag))) {
            return HTTP_PRECONDITION_FAILED;
        }
    }
    else {
        /* Else if a valid If-Unmodified-Since request-header field was given
         * AND the requested resource has been modified since the time
         * specified in this field, then the server MUST
         *     respond with a status of 412 (Precondition Failed).
         */
        if_unmodified = apr_table_get(r->headers_in, "If-Unmodified-Since");
        if (if_unmodified != NULL) {
            apr_time_t ius = ap_parseHTTPdate(if_unmodified);

            if ((ius != BAD_DATE) && (mtime > ius)) {
                return HTTP_PRECONDITION_FAILED;
            }
        }
    }

    /* If an If-None-Match request-header field was given
     * AND the field value is "*" (meaning match anything)
     *     OR our ETag matches any of the entity tags in that field, fail.
     *
     * If the request method was GET or HEAD, failure means the server
     *    SHOULD respond with a 304 (Not Modified) response.
     * For all other request methods, failure means the server MUST
     *    respond with a status of 412 (Precondition Failed).
     *
     * GET or HEAD allow weak etag comparison, all other methods require
     * strong comparison.  We can only use weak if it's not a range request.
     */
    if_nonematch = apr_table_get(r->headers_in, "If-None-Match");
    if (if_nonematch != NULL) {
        if (r->method_number == M_GET) {
            if (if_nonematch[0] == '*') {
		return HTTP_NOT_MODIFIED;
	    }
            if (etag != NULL) {
                if (apr_table_get(r->headers_in, "Range")) {
                    if (etag[0] != 'W'
			&& ap_find_list_item(r->pool, if_nonematch, etag)) {
                        return HTTP_NOT_MODIFIED;
                    }
                }
                else if (ap_strstr_c(if_nonematch, etag)) {
                    return HTTP_NOT_MODIFIED;
                }
            }
        }
        else if (if_nonematch[0] == '*'
		 || (etag != NULL
		     && ap_find_list_item(r->pool, if_nonematch, etag))) {
            return HTTP_PRECONDITION_FAILED;
        }
    }
    /* Else if a valid If-Modified-Since request-header field was given
     * AND it is a GET or HEAD request
     * AND the requested resource has not been modified since the time
     * specified in this field, then the server MUST
     *    respond with a status of 304 (Not Modified).
     * A date later than the server's current request time is invalid.
     */
    else if ((r->method_number == M_GET)
             && ((if_modified_since =
                  apr_table_get(r->headers_in,
				"If-Modified-Since")) != NULL)) {
        apr_time_t ims = ap_parseHTTPdate(if_modified_since);

	if ((ims >= mtime) && (ims <= r->request_time)) {
            return HTTP_NOT_MODIFIED;
        }
    }
    return OK;
}

/*
 * This function sets the Last-Modified output header field to the value
 * of the mtime field in the request structure - rationalized to keep it from
 * being in the future.
 */
AP_DECLARE(void) ap_set_last_modified(request_rec *r)
{
    apr_time_t mod_time = ap_rationalize_mtime(r, r->mtime);
    char *datestr = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
    apr_rfc822_date(datestr, mod_time);
    apr_table_setn(r->headers_out, "Last-Modified", datestr);
}

/* Get the method number associated with the given string, assumed to
 * contain an HTTP method.  Returns M_INVALID if not recognized.
 *
 * This is the first step toward placing method names in a configurable
 * list.  Hopefully it (and other routines) can eventually be moved to
 * something like a mod_http_methods.c, complete with config stuff.
 */
AP_DECLARE(int) ap_method_number_of(const char *method)
{
    switch (*method) {
        case 'H':
           if (strcmp(method, "HEAD") == 0)
               return M_GET;   /* see header_only in request_rec */
           break;
        case 'G':
           if (strcmp(method, "GET") == 0)
               return M_GET;
           break;
        case 'P':
           if (strcmp(method, "POST") == 0)
               return M_POST;
           if (strcmp(method, "PUT") == 0)
               return M_PUT;
           if (strcmp(method, "PATCH") == 0)
               return M_PATCH;
           if (strcmp(method, "PROPFIND") == 0)
               return M_PROPFIND;
           if (strcmp(method, "PROPPATCH") == 0)
               return M_PROPPATCH;
           break;
        case 'D':
           if (strcmp(method, "DELETE") == 0)
               return M_DELETE;
           break;
        case 'C':
           if (strcmp(method, "CONNECT") == 0)
               return M_CONNECT;
           if (strcmp(method, "COPY") == 0)
               return M_COPY;
           break;
        case 'M':
           if (strcmp(method, "MKCOL") == 0)
               return M_MKCOL;
           if (strcmp(method, "MOVE") == 0)
               return M_MOVE;
           break;
        case 'O':
           if (strcmp(method, "OPTIONS") == 0)
               return M_OPTIONS;
           break;
        case 'T':
           if (strcmp(method, "TRACE") == 0)
               return M_TRACE;
           break;
        case 'L':
           if (strcmp(method, "LOCK") == 0)
               return M_LOCK;
           break;
        case 'U':
           if (strcmp(method, "UNLOCK") == 0)
               return M_UNLOCK;
           break;
    }
    return M_INVALID;
}

/*
 * Turn a known method number into a name.  Doesn't work for
 * extension methods, obviously.
 */
AP_DECLARE(const char *) ap_method_name_of(int methnum)
{
    static const char *AP_HTTP_METHODS[METHODS] = { NULL };

    /*
     * This is ugly, but the previous incantation made Windows C
     * varf.  I'm not even sure it was ANSI C.  However, ugly as it
     * is, this works, and we only have to do it once.
     */
    if (AP_HTTP_METHODS[0] == NULL) {
	AP_HTTP_METHODS[M_GET]       = "GET";
	AP_HTTP_METHODS[M_PUT]       = "PUT";
	AP_HTTP_METHODS[M_POST]      = "POST";
	AP_HTTP_METHODS[M_DELETE]    = "DELETE";
	AP_HTTP_METHODS[M_CONNECT]   = "CONNECT";
	AP_HTTP_METHODS[M_OPTIONS]   = "OPTIONS";
	AP_HTTP_METHODS[M_TRACE]     = "TRACE";
	AP_HTTP_METHODS[M_PATCH]     = "PATCH";
	AP_HTTP_METHODS[M_PROPFIND]  = "PROPFIND";
	AP_HTTP_METHODS[M_PROPPATCH] = "PROPPATCH";
	AP_HTTP_METHODS[M_MKCOL]     = "MKCOL";
	AP_HTTP_METHODS[M_COPY]      = "COPY";
	AP_HTTP_METHODS[M_MOVE]      = "MOVE";
	AP_HTTP_METHODS[M_LOCK]      = "LOCK";
	AP_HTTP_METHODS[M_UNLOCK]    = "UNLOCK";
	AP_HTTP_METHODS[M_INVALID]   = NULL;
	/*
	 * Since we're using symbolic names, make sure we only do
	 * this once by forcing a value into the first slot IFF it's
	 * still NULL.
	 */
	if (AP_HTTP_METHODS[0] == NULL) {
	    AP_HTTP_METHODS[0] = "INVALID";
	}
    }

    if ((methnum == M_INVALID) || (methnum >= METHODS)) {
	return NULL;
    }
    return AP_HTTP_METHODS[methnum];
}

struct dechunk_ctx {
    apr_size_t chunk_size;
    apr_size_t bytes_delivered;
    enum {WANT_HDR /* must have value zero */, WANT_BODY, WANT_TRL} state;
};

static long get_chunk_size(char *);

apr_status_t ap_dechunk_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                               ap_input_mode_t mode)
{
    apr_status_t rv;
    struct dechunk_ctx *ctx = f->ctx;
    apr_bucket *b;
    const char *buf;
    apr_size_t len;

    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(struct dechunk_ctx));
    }

    do {
        if (ctx->chunk_size == ctx->bytes_delivered) {
            /* Time to read another chunk header or trailer...  ap_http_filter() is 
             * the next filter in line and it knows how to return a brigade with 
             * one line.
             */
            char line[30];
            
            if ((rv = ap_getline(line, sizeof(line), f->r, 0)) < 0) {
                return rv;
            }
            switch(ctx->state) {
            case WANT_HDR:
                ctx->chunk_size = get_chunk_size(line);
                ctx->bytes_delivered = 0;
                if (ctx->chunk_size == 0) {
                    ctx->state = WANT_TRL;
                }
                else {
                    ctx->state = WANT_BODY;
                }
                break;
            case WANT_TRL:
                /* XXX sanity check end chunk here */
                if (strlen(line)) {
                    /* bad trailer */
                }
                if (ctx->chunk_size == 0) { /* we just finished the last chunk? */
                    /* append eos bucket and get out */
                    b = apr_bucket_eos_create();
                    APR_BRIGADE_INSERT_TAIL(bb, b);
                    return APR_SUCCESS;
                }
                ctx->state = WANT_HDR;
                break;
            default:
                ap_assert(ctx->state == WANT_HDR || ctx->state == WANT_TRL);
            }
        }
    } while (ctx->state != WANT_BODY);

    if (ctx->state == WANT_BODY) {
        /* Tell ap_http_filter() how many bytes to deliver. */
        f->c->remain = ctx->chunk_size - ctx->bytes_delivered;
        if ((rv = ap_get_brigade(f->next, bb, mode)) != APR_SUCCESS) {
            return rv;
        }
        /* Walk through the body, accounting for bytes, and removing an eos bucket if
         * ap_http_filter() delivered the entire chunk.
         */
        b = APR_BRIGADE_FIRST(bb);
        while (b != APR_BRIGADE_SENTINEL(bb) && !APR_BUCKET_IS_EOS(b)) {
            apr_bucket_read(b, &buf, &len, mode);
            AP_DEBUG_ASSERT(len <= ctx->chunk_size - ctx->bytes_delivered);
            ctx->bytes_delivered += len;
            b = APR_BUCKET_NEXT(b);
        }
        if (ctx->bytes_delivered == ctx->chunk_size) {
            AP_DEBUG_ASSERT(APR_BUCKET_IS_EOS(b));
            apr_bucket_delete(b);
            ctx->state = WANT_TRL;
        }
    }

    return APR_SUCCESS;
}

typedef struct http_filter_ctx {
    apr_bucket_brigade *b;
} http_ctx_t;

apr_status_t ap_http_filter(ap_filter_t *f, apr_bucket_brigade *b, ap_input_mode_t mode)
{
    apr_bucket *e;
    char *buff;
    apr_size_t len;
    char *pos;
    http_ctx_t *ctx = f->ctx;
    apr_status_t rv;

    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(f->c->pool, sizeof(*ctx));
        ctx->b = apr_brigade_create(f->c->pool);
    }

    if (mode == AP_MODE_PEEK) {
        apr_bucket *e;
        const char *str;
        apr_size_t length;

        /* The purpose of this loop is to ignore any CRLF (or LF) at the end
         * of a request.  Many browsers send extra lines at the end of POST
         * requests.  We use the PEEK method to determine if there is more
         * data on the socket, so that we know if we should delay sending the
         * end of one request until we have served the second request in a
         * pipelined situation.  We don't want to actually delay sending a
         * response if the server finds a CRLF (or LF), becuause that doesn't
         * mean that there is another request, just a blank line.
         */
        while (1) {
            if (APR_BRIGADE_EMPTY(ctx->b)) {
                e = NULL;
            }
            else {
                e = APR_BRIGADE_FIRST(ctx->b);
            }
            if (!e || apr_bucket_read(e, &str, &length, APR_NONBLOCK_READ) != APR_SUCCESS) {
                return APR_EOF;
            }
            else {
                const char *c = str;
                while (c - str < length) {
                    if (*c == APR_ASCII_LF)
                        c++;
                    else if (*c == APR_ASCII_CR && *(c + 1) == APR_ASCII_LF)
                        c += 2;
                    else return APR_SUCCESS;
                }
                apr_bucket_delete(e);
            }
        }
    }

    if (APR_BRIGADE_EMPTY(ctx->b)) {
        if ((rv = ap_get_brigade(f->next, ctx->b, mode)) != APR_SUCCESS) {
            return rv;
        }
    }

    if (f->c->remain) {
        while (!APR_BRIGADE_EMPTY(ctx->b)) {
            const char *ignore;

            e = APR_BRIGADE_FIRST(ctx->b);
            if ((rv = apr_bucket_read(e, &ignore, &len, mode)) != APR_SUCCESS) {
                /* probably APR_IS_EAGAIN(rv); socket state isn't correct;
                 * remove log once we get this squared away */
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, f->c->base_server, 
                             "apr_bucket_read");
                return rv;
            }

            if (len) {
                if (f->c->remain < len) {
                    apr_bucket_split(e, f->c->remain);
                    f->c->remain = 0;
                }
                else {
                    f->c->remain -= len;
                }
                APR_BUCKET_REMOVE(e);
                APR_BRIGADE_INSERT_TAIL(b, e);
                break; /* once we've gotten some data, deliver it to caller */
            }
            apr_bucket_delete(e);
        }
        if (f->c->remain == 0) {
            apr_bucket *eos = apr_bucket_eos_create();
                
            APR_BRIGADE_INSERT_TAIL(b, eos);
        }
        return APR_SUCCESS;
    }

    while (!APR_BRIGADE_EMPTY(ctx->b)) {
        e = APR_BRIGADE_FIRST(ctx->b);
        if ((rv = apr_bucket_read(e, (const char **)&buff, &len, mode)) != APR_SUCCESS) {
            return rv;
        }

        pos = memchr(buff, APR_ASCII_LF, len);
        if (pos != NULL) {
            apr_bucket_split(e, pos - buff + 1);
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(b, e);
            return APR_SUCCESS;
        }
        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(b, e);
    }
    return APR_SUCCESS;
}

/* New Apache routine to map status codes into array indicies
 *  e.g.  100 -> 0,  101 -> 1,  200 -> 2 ...
 * The number of status lines must equal the value of RESPONSE_CODES (httpd.h)
 * and must be listed in order.
 */

#ifdef UTS21
/* The second const triggers an assembler bug on UTS 2.1.
 * Another workaround is to move some code out of this file into another,
 *   but this is easier.  Dave Dykstra, 3/31/99 
 */
static const char * status_lines[RESPONSE_CODES] =
#else
static const char * const status_lines[RESPONSE_CODES] =
#endif
{
    "100 Continue",
    "101 Switching Protocols",
    "102 Processing",
#define LEVEL_200  3
    "200 OK",
    "201 Created",
    "202 Accepted",
    "203 Non-Authoritative Information",
    "204 No Content",
    "205 Reset Content",
    "206 Partial Content",
    "207 Multi-Status",
#define LEVEL_300 11
    "300 Multiple Choices",
    "301 Moved Permanently",
    "302 Found",
    "303 See Other",
    "304 Not Modified",
    "305 Use Proxy",
    "306 unused",
    "307 Temporary Redirect",
#define LEVEL_400 19
    "400 Bad Request",
    "401 Authorization Required",
    "402 Payment Required",
    "403 Forbidden",
    "404 Not Found",
    "405 Method Not Allowed",
    "406 Not Acceptable",
    "407 Proxy Authentication Required",
    "408 Request Time-out",
    "409 Conflict",
    "410 Gone",
    "411 Length Required",
    "412 Precondition Failed",
    "413 Request Entity Too Large",
    "414 Request-URI Too Large",
    "415 Unsupported Media Type",
    "416 Requested Range Not Satisfiable",
    "417 Expectation Failed",
    "418 unused",
    "419 unused",
    "420 unused",
    "421 unused",
    "422 Unprocessable Entity",
    "423 Locked",
    "424 Failed Dependency",
#define LEVEL_500 44
    "500 Internal Server Error",
    "501 Method Not Implemented",
    "502 Bad Gateway",
    "503 Service Temporarily Unavailable",
    "504 Gateway Time-out",
    "505 HTTP Version Not Supported",
    "506 Variant Also Negotiates",
    "507 Insufficient Storage",
    "508 unused",
    "509 unused",
    "510 Not Extended"
};

/* The index is found by its offset from the x00 code of each level.
 * Although this is fast, it will need to be replaced if some nutcase
 * decides to define a high-numbered code before the lower numbers.
 * If that sad event occurs, replace the code below with a linear search
 * from status_lines[shortcut[i]] to status_lines[shortcut[i+1]-1];
 */
AP_DECLARE(int) ap_index_of_response(int status)
{
    static int shortcut[6] = {0, LEVEL_200, LEVEL_300, LEVEL_400,
    LEVEL_500, RESPONSE_CODES};
    int i, pos;

    if (status < 100)           /* Below 100 is illegal for HTTP status */
        return LEVEL_500;

    for (i = 0; i < 5; i++) {
        status -= 100;
        if (status < 100) {
            pos = (status + shortcut[i]);
            if (pos < shortcut[i + 1]) {
                return pos;
	    }
            else {
                return LEVEL_500;       /* status unknown (falls in gap) */
	    }
        }
    }
    return LEVEL_500;           /* 600 or above is also illegal */
}

AP_DECLARE(const char *) ap_get_status_line(int status)
{
    return status_lines[ap_index_of_response(status)];
}

typedef struct header_struct {
    apr_pool_t *pool;
    apr_bucket_brigade *bb;
} header_struct;

/* Send a single HTTP header field to the client.  Note that this function
 * is used in calls to table_do(), so their interfaces are co-dependent.
 * In other words, don't change this one without checking table_do in alloc.c.
 * It returns true unless there was a write error of some kind.
 */
static int form_header_field(header_struct *h,
                             const char *fieldname, const char *fieldval)
{
    char *headfield;

    headfield = apr_pstrcat(h->pool, fieldname, ": ", fieldval, CRLF, NULL);
    ap_xlate_proto_to_ascii(headfield, strlen(headfield));
    apr_brigade_puts(h->bb, NULL, NULL, headfield);
    return 1;
}

static void basic_http_header_check(request_rec *r, 
                                    const char **protocol)
{
    if (r->assbackwards)
        return;

    if (!r->status_line)
        r->status_line = status_lines[ap_index_of_response(r->status)];

    /* mod_proxy is only HTTP/1.0, so avoid sending HTTP/1.1 error response;
     * kluge around broken browsers when indicated by force-response-1.0
     */
    if (r->proxyreq
        || (r->proto_num == HTTP_VERSION(1,0)
            && apr_table_get(r->subprocess_env, "force-response-1.0"))) {

        *protocol = "HTTP/1.0";
        r->connection->keepalive = -1;
    }
    else {
        *protocol = AP_SERVER_PROTOCOL;
    }
}

static void basic_http_header(request_rec *r, apr_bucket_brigade *bb, const char *protocol)
{
    char *date = NULL;
    char *tmp;
    header_struct h;

    if (r->assbackwards)
        return;

    /* Output the HTTP/1.x Status-Line and the Date and Server fields */

    tmp = apr_pstrcat(r->pool, protocol, " ", r->status_line, CRLF, NULL);
    ap_xlate_proto_to_ascii(tmp, strlen(tmp));
    apr_brigade_puts(bb, NULL, NULL, tmp);

    date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
    apr_rfc822_date(date, r->request_time);

    h.pool = r->pool;
    h.bb = bb;
    form_header_field(&h, "Date", date);
    form_header_field(&h, "Server", ap_get_server_version());

    apr_table_unset(r->headers_out, "Date");        /* Avoid bogosity */
    apr_table_unset(r->headers_out, "Server");
}

AP_DECLARE(void) ap_basic_http_header(request_rec *r, apr_bucket_brigade *bb)
{
    const char *protocol;

    basic_http_header_check(r, &protocol);
    basic_http_header(r, bb, protocol);
}

/* Navigator versions 2.x, 3.x and 4.0 betas up to and including 4.0b2
 * have a header parsing bug.  If the terminating \r\n occur starting
 * at offset 256, 257 or 258 of output then it will not properly parse
 * the headers.  Curiously it doesn't exhibit this problem at 512, 513.
 * We are guessing that this is because their initial read of a new request
 * uses a 256 byte buffer, and subsequent reads use a larger buffer.
 * So the problem might exist at different offsets as well.
 *
 * This should also work on keepalive connections assuming they use the
 * same small buffer for the first read of each new request.
 *
 * At any rate, we check the bytes written so far and, if we are about to
 * tickle the bug, we instead insert a bogus padding header.  Since the bug
 * manifests as a broken image in Navigator, users blame the server.  :(
 * It is more expensive to check the User-Agent than it is to just add the
 * bytes, so we haven't used the BrowserMatch feature here.
 */
static void terminate_header(apr_bucket_brigade *bb)
{
    char tmp[] = "X-Pad: avoid browser bug" CRLF;
    char crlf[] = CRLF;
    apr_ssize_t len;

    (void) apr_brigade_length(bb, 1, &len);

    if (len >= 255 && len <= 257) {
        ap_xlate_proto_to_ascii(tmp, strlen(tmp));
        apr_brigade_puts(bb, NULL, NULL, tmp);
    }
    ap_xlate_proto_to_ascii(crlf, strlen(crlf));
    apr_brigade_puts(bb, NULL, NULL, crlf);
}

/*
 * Create a new method list with the specified number of preallocated
 * extension slots.
 */
AP_DECLARE(ap_method_list_t *) ap_make_method_list(apr_pool_t *p, int nelts)
{
    ap_method_list_t *ml;

    ml = (ap_method_list_t *) apr_palloc(p, sizeof(ap_method_list_t));
    ml->method_mask = 0;
    ml->method_list = apr_array_make(p, sizeof(char *), nelts);
    return ml;
}

/*
 * Make a copy of a method list (primarily for subrequests that may
 * subsequently change it; don't want them changing the parent's, too!).
 */
AP_DECLARE(void) ap_copy_method_list(ap_method_list_t *dest,
				     ap_method_list_t *src)
{
    int i;
    char **imethods;
    char **omethods;

    dest->method_mask = src->method_mask;
    imethods = (char **) src->method_list->elts;
    for (i = 0; i < src->method_list->nelts; ++i) {
	omethods = (char **) apr_array_push(dest->method_list);
	*omethods = apr_pstrdup(dest->method_list->cont, imethods[i]);
    }
}

/*
 * Invoke a callback routine for each method in the specified list.
 */
AP_DECLARE_NONSTD(void) ap_method_list_do(int (*comp) (void *urec, const char *mname,
						       int mnum),
				          void *rec,
				          const ap_method_list_t *ml, ...)
{
    va_list vp;
    va_start(vp, ml);
    ap_method_list_vdo(comp, rec, ml, vp);
    va_end(vp);  
}

AP_DECLARE(void) ap_method_list_vdo(int (*comp) (void *mrec,
						 const char *mname,
						 int mnum),
				    void *rec, const ap_method_list_t *ml,
				    va_list vp)
{
    
}

/*
 * Return true if the specified HTTP method is in the provided
 * method list.
 */
AP_DECLARE(int) ap_method_in_list(ap_method_list_t *l, const char *method)
{
    int methnum;
    int i;
    char **methods;

    /*
     * If it's one of our known methods, use the shortcut and check the
     * bitmask.
     */
    methnum = ap_method_number_of(method);
    if (methnum != M_INVALID) {
	return (l->method_mask & (1 << methnum));
    }
    /*
     * Otherwise, see if the method name is in the array or string names
     */
    if ((l->method_list = NULL) || (l->method_list->nelts == 0)) {
	return 0;
    }
    methods = (char **)l->method_list->elts;
    for (i = 0; i < l->method_list->nelts; ++i) {
	if (strcmp(method, methods[i]) == 0) {
	    return 1;
	}
    }
    return 0;
}

/*
 * Add the specified method to a method list (if it isn't already there).
 */
AP_DECLARE(void) ap_method_list_add(ap_method_list_t *l, const char *method)
{
    int methnum;
    int i;
    const char **xmethod;
    char **methods;

    /*
     * If it's one of our known methods, use the shortcut and use the
     * bitmask.
     */
    methnum = ap_method_number_of(method);
    l->method_mask |= (1 << methnum);
    if (methnum != M_INVALID) {
	return;
    }
    /*
     * Otherwise, see if the method name is in the array of string names.
     */
    if (l->method_list->nelts != 0) {
        methods = (char **)l->method_list->elts;
	for (i = 0; i < l->method_list->nelts; ++i) {
	    if (strcmp(method, methods[i]) == 0) {
		return;
	    }
	}
    }
    xmethod = (const char **) apr_array_push(l->method_list);
    *xmethod = method;
}
    
/*
 * Remove the specified method from a method list.
 */
AP_DECLARE(void) ap_method_list_remove(ap_method_list_t *l,
				       const char *method)
{
    int methnum;
    char **methods;

    /*
     * If it's one of our known methods, use the shortcut and use the
     * bitmask.
     */
    methnum = ap_method_number_of(method);
    l->method_mask |= ~(1 << methnum);
    if (methnum != M_INVALID) {
	return;
    }
    /*
     * Otherwise, see if the method name is in the array of string names.
     */
    if (l->method_list->nelts != 0) {
	register int i, j, k;
        methods = (char **)l->method_list->elts;
	for (i = 0; i < l->method_list->nelts; ) {
	    if (strcmp(method, methods[i]) == 0) {
		for (j = i, k = i + 1; k < l->method_list->nelts; ++j, ++k) {
		    methods[j] = methods[k];
		}
		--l->method_list->nelts;
	    }
	    else {
		++i;
	    }
	}
    }
}

/*
 * Reset a method list to be completely empty.
 */
AP_DECLARE(void) ap_clear_method_list(ap_method_list_t *l)
{
    l->method_mask = 0;
    l->method_list->nelts = 0;
}

/* Build the Allow field-value from the request handler method mask.
 * Note that we always allow TRACE, since it is handled below.
 */
static char *make_allow(request_rec *r)
{
    char *list;
    int mask;

    mask = r->allowed_methods->method_mask;
    list = apr_pstrcat(r->pool,
		       (mask & (1 << M_GET))	   ? ", GET, HEAD" : "",
		       (mask & (1 << M_POST))	   ? ", POST"      : "",
		       (mask & (1 << M_PUT))	   ? ", PUT"       : "",
		       (mask & (1 << M_DELETE))	   ? ", DELETE"    : "",
		       (mask & (1 << M_CONNECT))   ? ", CONNECT"   : "",
		       (mask & (1 << M_OPTIONS))   ? ", OPTIONS"   : "",
		       (mask & (1 << M_PATCH))	   ? ", PATCH"     : "",
		       (mask & (1 << M_PROPFIND))  ? ", PROPFIND"  : "",
		       (mask & (1 << M_PROPPATCH)) ? ", PROPPATCH" : "",
		       (mask & (1 << M_MKCOL))	   ? ", MKCOL"     : "",
		       (mask & (1 << M_COPY))	   ? ", COPY"      : "",
		       (mask & (1 << M_MOVE))	   ? ", MOVE"      : "",
		       (mask & (1 << M_LOCK))	   ? ", LOCK"      : "",
		       (mask & (1 << M_UNLOCK))	   ? ", UNLOCK"    : "",
		       ", TRACE",
		       NULL);
    if ((mask & (1 << M_INVALID))
	&& (r->allowed_methods->method_list != NULL)
	&& (r->allowed_methods->method_list->nelts != 0)) {
	int i;
	char **xmethod = (char **) r->allowed_methods->method_list->elts;

	/*
	 * Append all of the elements of r->allowed_methods->method_list
	 */
	for (i = 0; i < r->allowed_methods->method_list->nelts; ++i) {
	    list = apr_pstrcat(r->pool, list, ", ", xmethod[i], NULL);
	}
    }
    /*
     * Space past the leading ", ".  Wastes two bytes, but that's better
     * than futzing around to find the actual length.
     */
    return list + 2;
}

AP_DECLARE(int) ap_send_http_trace(request_rec *r)
{
    int rv;

    /* Get the original request */
    while (r->prev)
        r = r->prev;

    if ((rv = ap_setup_client_block(r, REQUEST_NO_BODY)))
        return rv;

    r->content_type = "message/http";
    ap_send_http_header(r);

    /* Now we recreate the request, and echo it back */

    ap_rvputs(r, r->the_request, CRLF, NULL);

    apr_table_do((int (*) (void *, const char *, const char *))
                form_header_field, (void *) r, r->headers_in, NULL);
    ap_rputs(CRLF, r);

    return OK;
}

int ap_send_http_options(request_rec *r)
{
    apr_bucket_brigade *bb = apr_brigade_create(r->pool);
    header_struct h;

    if (r->assbackwards)
        return DECLINED;
    
    ap_basic_http_header(r, bb);

    apr_table_setn(r->headers_out, "Content-Length", "0");
    apr_table_setn(r->headers_out, "Allow", make_allow(r));
    ap_set_keepalive(r);

    h.pool = r->pool;
    h.bb = bb;

    apr_table_do((int (*) (void *, const char *, const char *)) form_header_field,
             (void *) &h, r->headers_out, NULL);

    terminate_header(bb);

    r->bytes_sent = 0;

    ap_pass_brigade(r->output_filters, bb);

    return OK;
}

/* This routine is called by apr_table_do and merges all instances of
 * the passed field values into a single array that will be further
 * processed by some later routine.  Originally intended to help split
 * and recombine multiple Vary fields, though it is generic to any field
 * consisting of comma/space-separated tokens.
 */
static int uniq_field_values(void *d, const char *key, const char *val)
{
    apr_array_header_t *values;
    char *start;
    char *e;
    char **strpp;
    int  i;

    values = (apr_array_header_t *)d;

    e = apr_pstrdup(values->cont, val);

    do {
        /* Find a non-empty fieldname */

        while (*e == ',' || apr_isspace(*e)) {
            ++e;
        }
        if (*e == '\0') {
            break;
        }
        start = e;
        while (*e != '\0' && *e != ',' && !apr_isspace(*e)) {
            ++e;
        }
        if (*e != '\0') {
            *e++ = '\0';
        }

        /* Now add it to values if it isn't already represented.
         * Could be replaced by a ap_array_strcasecmp() if we had one.
         */
        for (i = 0, strpp = (char **) values->elts; i < values->nelts;
             ++i, ++strpp) {
            if (*strpp && strcasecmp(*strpp, start) == 0) {
                break;
            }
        }
        if (i == values->nelts) {  /* if not found */
	    *(char **)apr_array_push(values) = start;
        }
    } while (*e != '\0');

    return 1;
}

/*
 * Since some clients choke violently on multiple Vary fields, or
 * Vary fields with duplicate tokens, combine any multiples and remove
 * any duplicates.
 */
static void fixup_vary(request_rec *r)
{
    apr_array_header_t *varies;

    varies = apr_array_make(r->pool, 5, sizeof(char *));

    /* Extract all Vary fields from the headers_out, separate each into
     * its comma-separated fieldname values, and then add them to varies
     * if not already present in the array.
     */
    apr_table_do((int (*)(void *, const char *, const char *))uniq_field_values,
		(void *) varies, r->headers_out, "Vary", NULL);

    /* If we found any, replace old Vary fields with unique-ified value */

    if (varies->nelts > 0) {
	apr_table_setn(r->headers_out, "Vary",
		       apr_array_pstrcat(r->pool, varies, ','));
    }
}

AP_DECLARE(void) ap_send_http_header(request_rec *r)
{
}

typedef struct header_filter_cts {
    int headers_sent;
} header_filter_ctx;
AP_CORE_DECLARE_NONSTD(apr_status_t) ap_http_header_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
    int i;
    char *date = NULL;
    request_rec *r = f->r;
    const char *clheader;
    const char *protocol;
    apr_bucket *e;
    apr_bucket_brigade *b2;
    apr_size_t len = 0;
    header_struct h;
    header_filter_ctx *ctx = f->ctx;

    AP_DEBUG_ASSERT(!r->main);

    if (!ctx) {
        ctx = apr_pcalloc(r->pool, sizeof(*ctx));
    }

    if (ctx->headers_sent) {
        apr_brigade_destroy(b);
        return OK;
    }

    APR_BRIGADE_FOREACH(e, b) {
        if (e->type == &ap_bucket_type_error) {
            ap_bucket_error *eb = e->data;

            ap_die(eb->status, r);
            return AP_FILTER_ERROR;
        }
    }

    if (r->assbackwards) {
        r->bytes_sent = 0;
        r->sent_bodyct = 1;
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, b);
    }

    /*
     * Now that we are ready to send a response, we need to combine the two
     * header field tables into a single table.  If we don't do this, our
     * later attempts to set or unset a given fieldname might be bypassed.
     */
    if (!apr_is_empty_table(r->err_headers_out))
        r->headers_out = apr_table_overlay(r->pool, r->err_headers_out,
                                        r->headers_out);

    /*
     * Remove the 'Vary' header field if the client can't handle it.
     * Since this will have nasty effects on HTTP/1.1 caches, force
     * the response into HTTP/1.0 mode.
     */
    if (apr_table_get(r->subprocess_env, "force-no-vary") != NULL) {
	apr_table_unset(r->headers_out, "Vary");
	r->proto_num = HTTP_VERSION(1,0);
	apr_table_set(r->subprocess_env, "force-response-1.0", "1");
    }
    else {
	fixup_vary(r);
    }

    /* Need to add a fudge factor so that the CRLF at the end of the headers
     * and the basic http headers don't overflow this buffer.
     */
    len += strlen(ap_get_server_version()) + 100;
    basic_http_header_check(r, &protocol);
    ap_set_keepalive(r);

    if (r->chunked) {
        apr_table_mergen(r->headers_out, "Transfer-Encoding", "chunked");
        apr_table_unset(r->headers_out, "Content-Length");

    }

    apr_table_setn(r->headers_out, "Content-Type", ap_make_content_type(r,
        r->content_type));

    if (r->content_encoding) {
        apr_table_setn(r->headers_out, "Content-Encoding",
		       r->content_encoding);
    }

    if (r->content_languages && r->content_languages->nelts) {
        for (i = 0; i < r->content_languages->nelts; ++i) {
            apr_table_mergen(r->headers_out, "Content-Language",
			     ((char **) (r->content_languages->elts))[i]);
        }
    }
    else if (r->content_language) {
        apr_table_setn(r->headers_out, "Content-Language",
		       r->content_language);
    }

    /*
     * Control cachability for non-cachable responses if not already set by
     * some other part of the server configuration.
     */
    if (r->no_cache && !apr_table_get(r->headers_out, "Expires")) {
	date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
        apr_rfc822_date(date, r->request_time);
        apr_table_addn(r->headers_out, "Expires", date);
    }

    /* This is a hack, but I can't find anyway around it.  The idea is that
     * we don't want to send out 0 Content-Lengths if it is a head request.
     * This happens when modules try to outsmart the server, and return
     * if they see a HEAD request.  Apache 1.3 handlers were supposed to
     * just return in that situation, and the core handled the HEAD.  In
     * 2.0, if a handler returns, then the core sends an EOS bucket down
     * the filter stack, and the content-length filter computes a C-L of
     * zero and that gets put in the headers, and we end up sending a 
     * zero C-L to the client.  We can't just remove the C-L filter,
     * because well behaved 2.0 handlers will send their data down the stack, 
     * and we will compute a real C-L for the head request. RBB
     */
    if (r->header_only && 
        (clheader = apr_table_get(r->headers_out, "Content-Length")) &&
        !strcmp(clheader, "0")) {
        apr_table_unset(r->headers_out, "Content-Length");
    }

    b2 = apr_brigade_create(r->pool);
    basic_http_header(r, b2, protocol);

    h.pool = r->pool;
    h.bb = b2;

    if (r->status == HTTP_NOT_MODIFIED) {
        apr_table_do((int (*)(void *, const char *, const char *)) form_header_field,
                    (void *) &h, r->headers_out,
                    "Connection",
                    "Keep-Alive",
                    "ETag",
                    "Content-Location",
                    "Expires",
                    "Cache-Control",
                    "Vary",
                    "Warning",
                    "WWW-Authenticate",
                    "Proxy-Authenticate",
                    NULL);
    }
    else {
        apr_table_do((int (*) (void *, const char *, const char *)) form_header_field,
		 (void *) &h, r->headers_out, NULL);
    }

    terminate_header(b2);

    r->sent_bodyct = 1;         /* Whatever follows is real body stuff... */

    ap_pass_brigade(f->next, b2);

    if (r->header_only) {
        apr_brigade_destroy(b);
        return OK;
    }

    if (r->chunked) {
        /* We can't add this filter until we have already sent the headers.
         * If we add it before this point, then the headers will be chunked
         * as well, and that is just wrong.
         */
        ap_add_output_filter("CHUNK", NULL, r, r->connection);
    }

    /* Don't remove this filter until after we have added the CHUNK filter.
     * Otherwise, f->next won't be the CHUNK filter and thus the first
     * brigade won't be chunked properly.
     */
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, b);
}

/* Here we deal with getting the request message body from the client.
 * Whether or not the request contains a body is signaled by the presence
 * of a non-zero Content-Length or by a Transfer-Encoding: chunked.
 *
 * Note that this is more complicated than it was in Apache 1.1 and prior
 * versions, because chunked support means that the module does less.
 *
 * The proper procedure is this:
 *
 * 1. Call setup_client_block() near the beginning of the request
 *    handler. This will set up all the necessary properties, and will
 *    return either OK, or an error code. If the latter, the module should
 *    return that error code. The second parameter selects the policy to
 *    apply if the request message indicates a body, and how a chunked
 *    transfer-coding should be interpreted. Choose one of
 *
 *    REQUEST_NO_BODY          Send 413 error if message has any body
 *    REQUEST_CHUNKED_ERROR    Send 411 error if body without Content-Length
 *    REQUEST_CHUNKED_DECHUNK  If chunked, remove the chunks for me.
 *
 *    In order to use the last two options, the caller MUST provide a buffer
 *    large enough to hold a chunk-size line, including any extensions.
 *
 * 2. When you are ready to read a body (if any), call should_client_block().
 *    This will tell the module whether or not to read input. If it is 0,
 *    the module should assume that there is no message body to read.
 *    This step also sends a 100 Continue response to HTTP/1.1 clients,
 *    so should not be called until the module is *definitely* ready to
 *    read content. (otherwise, the point of the 100 response is defeated).
 *    Never call this function more than once.
 *
 * 3. Finally, call get_client_block in a loop. Pass it a buffer and its size.
 *    It will put data into the buffer (not necessarily a full buffer), and
 *    return the length of the input block. When it is done reading, it will
 *    return 0 if EOF, or -1 if there was an error.
 *    If an error occurs on input, we force an end to keepalive.
 */

AP_DECLARE(int) ap_setup_client_block(request_rec *r, int read_policy)
{
    const char *tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
    const char *lenp = apr_table_get(r->headers_in, "Content-Length");
    long max_body;

    r->read_body = read_policy;
    r->read_chunked = 0;
    r->remaining = 0;

    if (tenc) {
        if (strcasecmp(tenc, "chunked")) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "Unknown Transfer-Encoding %s", tenc);
            return HTTP_NOT_IMPLEMENTED;
        }
        if (r->read_body == REQUEST_CHUNKED_ERROR) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "chunked Transfer-Encoding forbidden: %s", r->uri);
            return (lenp) ? HTTP_BAD_REQUEST : HTTP_LENGTH_REQUIRED;
        }

        r->read_chunked = 1;
        ap_add_input_filter("DECHUNK", NULL, r, r->connection);
    }
    else if (lenp) {
        const char *pos = lenp;

        while (apr_isdigit(*pos) || apr_isspace(*pos)) {
            ++pos;
	}
        if (*pos != '\0') {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "Invalid Content-Length %s", lenp);
            return HTTP_BAD_REQUEST;
        }

        r->connection->remain = r->remaining = atol(lenp);
    }

    if ((r->read_body == REQUEST_NO_BODY) &&
        (r->read_chunked || (r->remaining > 0))) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		      "%s with body is not allowed for %s", r->method, r->uri);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    max_body = ap_get_limit_req_body(r);
    if (max_body && (r->remaining > max_body)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		      "Request content-length of %s is larger than "
		      "the configured limit of %lu", lenp, max_body);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

#ifdef AP_DEBUG
    {
        /* Make sure ap_getline() didn't leave any droppings. */
        core_request_config *req_cfg = 
            (core_request_config *)ap_get_module_config(r->request_config,
                                                        &core_module);
        AP_DEBUG_ASSERT(APR_BRIGADE_EMPTY(req_cfg->bb));
    }
#endif

    return OK;
}

AP_DECLARE(int) ap_should_client_block(request_rec *r)
{
    /* First check if we have already read the request body */

    if (r->read_length || (!r->read_chunked && (r->remaining <= 0)))
        return 0;

    if (r->expecting_100 && r->proto_num >= HTTP_VERSION(1,1)) {
        char *tmp;
        apr_bucket *e;
        apr_bucket_brigade *bb;

        /* sending 100 Continue interim response */
        tmp = apr_pstrcat(r->pool, AP_SERVER_PROTOCOL, " ", status_lines[0],
                                CRLF CRLF, NULL);
        bb = apr_brigade_create(r->pool);
        e = apr_bucket_pool_create(tmp, strlen(tmp), r->pool);
        APR_BRIGADE_INSERT_HEAD(bb, e);
        e = apr_bucket_flush_create();
        APR_BRIGADE_INSERT_TAIL(bb, e);

        ap_pass_brigade(r->connection->output_filters, bb);
    }

    return 1;
}

static long get_chunk_size(char *b)
{
    long chunksize = 0;

    while (apr_isxdigit(*b)) {
        int xvalue = 0;

        if (*b >= '0' && *b <= '9') {
            xvalue = *b - '0';
	}
        else if (*b >= 'A' && *b <= 'F') {
            xvalue = *b - 'A' + 0xa;
	}
        else if (*b >= 'a' && *b <= 'f') {
            xvalue = *b - 'a' + 0xa;
	}

        chunksize = (chunksize << 4) | xvalue;
        ++b;
    }

    return chunksize;
}

/* get_client_block is called in a loop to get the request message body.
 * This is quite simple if the client includes a content-length
 * (the normal case), but gets messy if the body is chunked. Note that
 * r->remaining is used to maintain state across calls and that
 * r->read_length is the total number of bytes given to the caller
 * across all invocations.  It is messy because we have to be careful not
 * to read past the data provided by the client, since these reads block.
 * Returns 0 on End-of-body, -1 on error or premature chunk end.
 *
 * Reading the chunked encoding requires a buffer size large enough to
 * hold a chunk-size line, including any extensions. For now, we'll leave
 * that to the caller, at least until we can come up with a better solution.
 */
AP_DECLARE(long) ap_get_client_block(request_rec *r, char *buffer, int bufsiz)
{
    apr_size_t len_read, total;
    apr_status_t rv;
    apr_bucket *b, *old;
    const char *tempbuf;
    core_request_config *req_cfg =
	(core_request_config *)ap_get_module_config(r->request_config,
                                                    &core_module);
    apr_bucket_brigade *bb = req_cfg->bb;

    do {
        if (APR_BRIGADE_EMPTY(bb)) {
            if (ap_get_brigade(r->input_filters, bb, AP_MODE_BLOCKING) != APR_SUCCESS) {
                /* if we actually fail here, we want to just return and
                 * stop trying to read data from the client.
                 */
                r->connection->keepalive = -1;
                apr_brigade_destroy(bb);
                return -1;
            }
        }
        b = APR_BRIGADE_FIRST(bb);
    } while (APR_BRIGADE_EMPTY(bb));

    if (APR_BUCKET_IS_EOS(b)) {         /* reached eos on previous invocation */
        apr_bucket_delete(b);
        return 0;
    }

    total = 0;
    while (total < bufsiz &&  b != APR_BRIGADE_SENTINEL(bb) && !APR_BUCKET_IS_EOS(b)) {
        if ((rv = apr_bucket_read(b, &tempbuf, &len_read, APR_BLOCK_READ)) != APR_SUCCESS) {
            return -1;
        }
        if (total + len_read > bufsiz) {
            apr_bucket_split(b, bufsiz - total);
            len_read = bufsiz - total;
        }
        memcpy(buffer, tempbuf, len_read);
        buffer += len_read;
        total += len_read;
        /* XXX the next two fields shouldn't be mucked with here, as they are in terms
         * of bytes in the unfiltered body; gotta see if anybody else actually uses 
         * these
         */
        r->read_length += len_read;      /* XXX yank me? */
        r->remaining -= len_read;        /* XXX yank me? */
        old = b;
        b = APR_BUCKET_NEXT(b);
        apr_bucket_delete(old);
    }

    return total;
}

/* In HTTP/1.1, any method can have a body.  However, most GET handlers
 * wouldn't know what to do with a request body if they received one.
 * This helper routine tests for and reads any message body in the request,
 * simply discarding whatever it receives.  We need to do this because
 * failing to read the request body would cause it to be interpreted
 * as the next request on a persistent connection.
 *
 * Since we return an error status if the request is malformed, this
 * routine should be called at the beginning of a no-body handler, e.g.,
 *
 *    if ((retval = ap_discard_request_body(r)) != OK)
 *        return retval;
 */
AP_DECLARE(int) ap_discard_request_body(request_rec *r)
{
    int rv;

    if ((rv = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK)))
        return rv;

    /* In order to avoid sending 100 Continue when we already know the
     * final response status, and yet not kill the connection if there is
     * no request body to be read, we need to duplicate the test from
     * ap_should_client_block() here negated rather than call it directly.
     */
    if ((r->read_length == 0) && (r->read_chunked || (r->remaining > 0))) {
        char dumpbuf[HUGE_STRING_LEN];

        if (r->expecting_100) {
            r->connection->keepalive = -1;
            return OK;
        }

        while ((rv = ap_get_client_block(r, dumpbuf, HUGE_STRING_LEN)) > 0)
            continue;

        if (rv < 0)
            return HTTP_BAD_REQUEST;
    }
    return OK;
}

static const char *add_optional_notes(request_rec *r, 
                                      const char *prefix,
                                      const char *key, 
                                      const char *suffix)
{
    const char *notes, *result;
    
    if ((notes = apr_table_get(r->notes, key)) == NULL) {
        result = prefix;
    }
    else {
        result = apr_pstrcat(r->pool, prefix, notes, suffix, NULL);
    }

    return result;
}

static const char *get_canned_error_string(int status, 
                                           request_rec *r,
                                           const char *location) 

/* construct and return the default error message for a given 
 * HTTP defined error code
 */
{	
    apr_pool_t *p = r->pool;
    const char *error_notes, *h1, *s1;

	switch (status) {
	case HTTP_MOVED_PERMANENTLY:
	case HTTP_MOVED_TEMPORARILY:
	case HTTP_TEMPORARY_REDIRECT:
	    return(apr_pstrcat(p,
                           "The document has moved <A HREF=\"",
		                   ap_escape_html(r->pool, location), 
						   "\">here</A>.<P>\n",
                           NULL));
	case HTTP_SEE_OTHER:
	    return(apr_pstrcat(p,
                           "The answer to your request is located <A HREF=\"",
		                   ap_escape_html(r->pool, location), 
                           "\">here</A>.<P>\n",
                           NULL));
	case HTTP_USE_PROXY:
	    return(apr_pstrcat(p,
                           "This resource is only accessible "
		                   "through the proxy\n",
		                   ap_escape_html(r->pool, location),
		                   "<BR>\nYou will need to "
		                   "configure your client to use that proxy.<P>\n",
						   NULL));
	case HTTP_PROXY_AUTHENTICATION_REQUIRED:
	case HTTP_UNAUTHORIZED:
	    return("This server could not verify that you\n"
	           "are authorized to access the document\n"
	           "requested.  Either you supplied the wrong\n"
	           "credentials (e.g., bad password), or your\n"
	           "browser doesn't understand how to supply\n"
	           "the credentials required.<P>\n");
	case HTTP_BAD_REQUEST:
        return(add_optional_notes(r,  
	                              "Your browser sent a request that "
	                              "this server could not understand.<P>\n",
                                  "error-notes", 
                                  "<P>\n"));
	case HTTP_FORBIDDEN:
	    return(apr_pstrcat(p,
                           "You don't have permission to access ",
		                   ap_escape_html(r->pool, r->uri),
		                   "\non this server.<P>\n",
                           NULL));
	case HTTP_NOT_FOUND:
	    return(apr_pstrcat(p,
                           "The requested URL ",
		                   ap_escape_html(r->pool, r->uri),
		                   " was not found on this server.<P>\n",
                           NULL));
	case HTTP_METHOD_NOT_ALLOWED:
	    return(apr_pstrcat(p,
                           "The requested method ", r->method,
		                   " is not allowed for the URL ", 
                           ap_escape_html(r->pool, r->uri),
		                   ".<P>\n",
                           NULL));
	case HTTP_NOT_ACCEPTABLE:
	    s1 = apr_pstrcat(p,
	                     "An appropriate representation of the "
		                 "requested resource ",
		                 ap_escape_html(r->pool, r->uri),
		                 " could not be found on this server.<P>\n",
                         NULL);
        return(add_optional_notes(r, s1, "variant-list", ""));
	case HTTP_MULTIPLE_CHOICES:
        return(add_optional_notes(r, "", "variant-list", ""));
	case HTTP_LENGTH_REQUIRED:
	    s1 = apr_pstrcat(p, 
                        "A request of the requested method ", 
                         r->method,
		                 " requires a valid Content-length.<P>\n", 
                         NULL);
		return(add_optional_notes(r, s1, "error-notes", "<P>\n"));
	case HTTP_PRECONDITION_FAILED:
	    return(apr_pstrcat(p,
                           "The precondition on the request for the URL ",
		                   ap_escape_html(r->pool, r->uri),
		                   " evaluated to false.<P>\n",
                           NULL));
	case HTTP_NOT_IMPLEMENTED:
	    s1 = apr_pstrcat(p, 
                         ap_escape_html(r->pool, r->method), " to ",
		                 ap_escape_html(r->pool, r->uri),
		                 " not supported.<P>\n", 
                         NULL);
		return(add_optional_notes(r, s1, "error-notes", "<P>\n"));
	case HTTP_BAD_GATEWAY:
	    s1 = "The proxy server received an invalid" CRLF
	         "response from an upstream server.<P>" CRLF;
		return(add_optional_notes(r, s1, "error-notes", "<P>\n"));
	case HTTP_VARIANT_ALSO_VARIES:
	    return(apr_pstrcat(p,
                           "A variant for the requested resource\n<PRE>\n",
		                   ap_escape_html(r->pool, r->uri),
		                   "\n</PRE>\nis itself a negotiable resource. "
		                   "This indicates a configuration error.<P>\n",
                           NULL));
	case HTTP_REQUEST_TIME_OUT:
	    return("I'm tired of waiting for your request.\n");
	case HTTP_GONE:
	    return(apr_pstrcat(p,
                           "The requested resource<BR>",
		                   ap_escape_html(r->pool, r->uri),
		                   "<BR>\nis no longer available on this server "
		                   "and there is no forwarding address.\n"
		                   "Please remove all references to this resource.\n",
                           NULL));
	case HTTP_REQUEST_ENTITY_TOO_LARGE:
	    return(apr_pstrcat(p,
                           "The requested resource<BR>",
		                   ap_escape_html(r->pool, r->uri), "<BR>\n",
		                   "does not allow request data with ", 
                           r->method,
                           " requests, or the amount of data provided in\n"
		                   "the request exceeds the capacity limit.\n",
                           NULL));
	case HTTP_REQUEST_URI_TOO_LARGE:
	    s1 = "The requested URL's length exceeds the capacity\n"
	         "limit for this server.<P>\n";
        return(add_optional_notes(r, s1, "error-notes", "<P>\n"));
	case HTTP_UNSUPPORTED_MEDIA_TYPE:
	    return("The supplied request data is not in a format\n"
	           "acceptable for processing by this resource.\n");
	case HTTP_RANGE_NOT_SATISFIABLE:
	    return("None of the range-specifier values in the Range\n"
	           "request-header field overlap the current extent\n"
	           "of the selected resource.\n");
	case HTTP_EXPECTATION_FAILED:
	    return(apr_pstrcat(p, 
                           "The expectation given in the Expect request-header"
	                       "\nfield could not be met by this server.<P>\n"
	                       "The client sent<PRE>\n    Expect: ",
	                       apr_table_get(r->headers_in, "Expect"), "\n</PRE>\n"
	                       "but we only allow the 100-continue expectation.\n",
	                       NULL));
	case HTTP_UNPROCESSABLE_ENTITY:
	    return("The server understands the media type of the\n"
	           "request entity, but was unable to process the\n"
	           "contained instructions.\n");
	case HTTP_LOCKED:
	    return("The requested resource is currently locked.\n"
	           "The lock must be released or proper identification\n"
	           "given before the method can be applied.\n");
	case HTTP_FAILED_DEPENDENCY:
	    return("The method could not be performed on the resource\n"
	           "because the requested action depended on another\n"
	           "action and that other action failed.\n");
	case HTTP_INSUFFICIENT_STORAGE:
	    return("The method could not be performed on the resource\n"
	           "because the server is unable to store the\n"
	           "representation needed to successfully complete the\n"
	           "request.  There is insufficient free space left in\n"
	           "your storage allocation.\n");
	case HTTP_SERVICE_UNAVAILABLE:
	    return("The server is temporarily unable to service your\n"
	           "request due to maintenance downtime or capacity\n"
	           "problems. Please try again later.\n");
	case HTTP_GATEWAY_TIME_OUT:
	    return("The proxy server did not receive a timely response\n"
	           "from the upstream server.\n");
	case HTTP_NOT_EXTENDED:
	    return("A mandatory extension policy in the request is not\n"
	           "accepted by the server for this resource.\n");
	default:            /* HTTP_INTERNAL_SERVER_ERROR */
	    /*
	     * This comparison to expose error-notes could be modified to
	     * use a configuration directive and export based on that 
	     * directive.  For now "*" is used to designate an error-notes
	     * that is totally safe for any user to see (ie lacks paths,
	     * database passwords, etc.)
	     */
	    if (((error_notes = apr_table_get(r->notes, "error-notes")) != NULL)
		&& (h1 = apr_table_get(r->notes, "verbose-error-to")) != NULL
		&& (strcmp(h1, "*") == 0)) {
	        return(apr_pstrcat(p, error_notes, "<P>\n", NULL));
	    }
	    else {
	        return(apr_pstrcat(p, 
                         "The server encountered an internal error or\n"
	                     "misconfiguration and was unable to complete\n"
	                     "your request.<P>\n"
	                     "Please contact the server administrator,\n ",
	                     ap_escape_html(r->pool, r->server->server_admin),
	                     " and inform them of the time the error occurred,\n"
	                     "and anything you might have done that may have\n"
	                     "caused the error.<P>\n"
		                 "More information about this error may be available\n"
		                 "in the server error log.<P>\n", 
                         NULL));
	    }
	 /*
	  * It would be nice to give the user the information they need to
	  * fix the problem directly since many users don't have access to
	  * the error_log (think University sites) even though they can easily
	  * get this error by misconfiguring an htaccess file.  However, the
	  e error notes tend to include the real file pathname in this case,
	  * which some people consider to be a breach of privacy.  Until we
	  * can figure out a way to remove the pathname, leave this commented.
	  *
	  * if ((error_notes = apr_table_get(r->notes, "error-notes")) != NULL) {
	  *     return(apr_pstrcat(p, error_notes, "<P>\n", NULL);
	  * }
      * else {
      *     return "";
      * }
	  */
	}
}

static void reset_filters(request_rec *r)
{
    ap_filter_t *f = r->output_filters;

    while (f) {
        if (!strcasecmp(f->frec->name, "CORE") ||
            !strcasecmp(f->frec->name, "CONTENT_LENGTH") ||
            !strcasecmp(f->frec->name, "HTTP_HEADER")) {
            f = f->next;
            continue;
        }
        else {
            ap_remove_output_filter(f);
            f = f->next;
        }
    }
}

/* We should have named this send_canned_response, since it is used for any
 * response that can be generated by the server from the request record.
 * This includes all 204 (no content), 3xx (redirect), 4xx (client error),
 * and 5xx (server error) messages that have not been redirected to another
 * handler via the ErrorDocument feature.
 */
AP_DECLARE(void) ap_send_error_response(request_rec *r, int recursive_error)
{
    int status = r->status;
    int idx = ap_index_of_response(status);
    char *custom_response;
    const char *location = apr_table_get(r->headers_out, "Location");

    /* At this point, we are starting the response over, so we have to reset
     * this value.
     */
    r->eos_sent = 0;
    reset_filters(r);

    /*
     * It's possible that the Location field might be in r->err_headers_out
     * instead of r->headers_out; use the latter if possible, else the
     * former.
     */
    if (location == NULL) {
	location = apr_table_get(r->err_headers_out, "Location");
    }
    /* We need to special-case the handling of 204 and 304 responses,
     * since they have specific HTTP requirements and do not include a
     * message body.  Note that being assbackwards here is not an option.
     */
    if (status == HTTP_NOT_MODIFIED) {
        ap_finalize_request_protocol(r);
        return;
    }

    if (status == HTTP_NO_CONTENT) {
        ap_send_http_header(r);
        ap_finalize_request_protocol(r);
        return;
    }

    if (!r->assbackwards) {
        apr_table_t *tmp = r->headers_out;

        /* For all HTTP/1.x responses for which we generate the message,
         * we need to avoid inheriting the "normal status" header fields
         * that may have been set by the request handler before the
         * error or redirect, except for Location on external redirects.
         */
        r->headers_out = r->err_headers_out;
        r->err_headers_out = tmp;
        apr_table_clear(r->err_headers_out);

        if (ap_is_HTTP_REDIRECT(status) || (status == HTTP_CREATED)) {
            if ((location != NULL) && *location) {
	        apr_table_setn(r->headers_out, "Location", location);
            }
            else {
                location = "";   /* avoids coredump when printing, below */
            }
        }

        r->content_language = NULL;
        r->content_languages = NULL;
        r->content_encoding = NULL;
        r->clength = 0;
        r->content_type = "text/html; charset=iso-8859-1";

        if ((status == HTTP_METHOD_NOT_ALLOWED)
            || (status == HTTP_NOT_IMPLEMENTED)) {
            apr_table_setn(r->headers_out, "Allow", make_allow(r));
        }

        ap_send_http_header(r);

        if (r->header_only) {
            ap_finalize_request_protocol(r);
            return;
        }
    }

    if ((custom_response = ap_response_code_string(r, idx))) {
        /*
         * We have a custom response output. This should only be
         * a text-string to write back. But if the ErrorDocument
         * was a local redirect and the requested resource failed
         * for any reason, the custom_response will still hold the
         * redirect URL. We don't really want to output this URL
         * as a text message, so first check the custom response
         * string to ensure that it is a text-string (using the
         * same test used in ap_die(), i.e. does it start with a ").
         * If it doesn't, we've got a recursive error, so find
         * the original error and output that as well.
         */
        if (custom_response[0] == '\"') {
            ap_rputs(custom_response + 1, r);
            ap_finalize_request_protocol(r);
            return;
        }
        /*
         * Redirect failed, so get back the original error
         */
        while (r->prev && (r->prev->status != HTTP_OK))
            r = r->prev;
    }
    {
        const char *title = status_lines[idx];
        const char *h1;

        /* XXX This is a major hack that should be fixed cleanly.  The
         * problem is that we have the information we need in a previous
         * request, but the text of the page must be sent down the last
         * request_rec's filter stack.  rbb
         */
        request_rec *rlast = r;
        while (rlast->next) {
            rlast = rlast->next;
        }

        /* Accept a status_line set by a module, but only if it begins
         * with the 3 digit status code
         */
        if (r->status_line != NULL
            && strlen(r->status_line) > 4       /* long enough */
            && apr_isdigit(r->status_line[0])
            && apr_isdigit(r->status_line[1])
            && apr_isdigit(r->status_line[2])
            && apr_isspace(r->status_line[3])
            && apr_isalnum(r->status_line[4])) {
            title = r->status_line;
        }

        /* folks decided they didn't want the error code in the H1 text */
        h1 = &title[4];

        /* can't count on a charset filter being in place here, 
         * so do ebcdic->ascii translation explicitly (if needed)
         */

        ap_rvputs_proto_in_ascii(rlast,
                  DOCTYPE_HTML_2_0
                  "<HTML><HEAD>\n<TITLE>", title,
                  "</TITLE>\n</HEAD><BODY>\n<H1>", h1, "</H1>\n",
                  NULL);
        
        ap_rvputs_proto_in_ascii(rlast,
                                 get_canned_error_string(status, r, location),
                                 NULL); 

        if (recursive_error) {
            ap_rvputs_proto_in_ascii(rlast, "<P>Additionally, a ",
                      status_lines[ap_index_of_response(recursive_error)],
                      "\nerror was encountered while trying to use an "
                      "ErrorDocument to handle the request.\n", NULL);
        }
        ap_rvputs_proto_in_ascii(rlast, ap_psignature("<HR>\n", r), NULL);
        ap_rvputs_proto_in_ascii(rlast, "</BODY></HTML>\n", NULL);
    }
    ap_finalize_request_protocol(r);
}

