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
 * http_protocol.c --- routines which directly communicate with the client.
 *
 * Code originally by Rob McCool; much redone by Robert S. Thau
 * and the Apache Software Foundation.
 */

#define CORE_PRIVATE
#include "ap_buckets.h"
#include "util_filter.h"
#include "ap_config.h"
#include "apr_strings.h"
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
#include "mpm_status.h"
#ifdef APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

AP_HOOK_STRUCT(
	    AP_HOOK_LINK(post_read_request)
	    AP_HOOK_LINK(log_transaction)
	    AP_HOOK_LINK(http_method)
	    AP_HOOK_LINK(default_port)
)

/* if this is the first error, then log an INFO message and shut down the
 * connection.
 */
static void check_first_conn_error(const request_rec *r, const char *operation,
                                   apr_status_t status)
{
    if (!r->connection->aborted) {
        if (status == 0)
            status = ap_berror(r->connection->client);
        ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r,
                      "client stopped connection before %s completed",
                      operation);
        r->connection->aborted = 1;
    }
}

static int checked_bputstrs(request_rec *r, ...)
{
    va_list va;
    int n;

    if (r->connection->aborted)
        return EOF;

    va_start(va, r);
    n = ap_vbputstrs(r->connection->client, va);
    va_end(va);

    if (n < 0) {
        check_first_conn_error(r, "checked_bputstrs", 0);
        return EOF;
    }

    return n;
}

/*
 * Builds the content-type that should be sent to the client from the
 * content-type specified.  The following rules are followed:
 *    - if type is NULL, type is set to ap_default_type(r)
 *    - if charset adding is disabled, stop processing and return type.
 *    - then, if there are no parameters on type, add the default charset
 *    - return type
 */
static const char *make_content_type(request_rec *r, const char *type)
{
    static const char *needcset[] = {
	"text/plain",
	"text/html",
	NULL };
    const char **pcset;
    core_dir_config *conf =
	(core_dir_config *)ap_get_module_config(r->per_dir_config,
						&core_module);

    if (!type) {
	type = ap_default_type(r);
    }
    if (conf->add_default_charset != ADD_DEFAULT_CHARSET_ON) {
	return type;
    }

    if (ap_strcasestr(type, "charset=") != NULL) {
	/* already has parameter, do nothing */
	/* XXX we don't check the validity */
	;
    }
    else {
    	/* see if it makes sense to add the charset. At present,
	 * we only add it if the Content-type is one of needcset[]
	 */
	for (pcset = needcset; *pcset ; pcset++) {
	    if (ap_strcasestr(type, *pcset) != NULL) {
		type = apr_pstrcat(r->pool, type, "; charset=", 
				   conf->add_default_charset_name, NULL);
		break;
	    }
	}
    }
    return type;
}

static int parse_byterange(char *range, apr_off_t clength,
                           apr_off_t *start, apr_off_t *end)
{
    char *dash = strchr(range, '-');

    if (!dash)
        return 0;

    if ((dash == range)) {
        /* In the form "-5" */
        *start = clength - atol(dash + 1);
        *end = clength - 1;
    }
    else {
        *dash = '\0';
        dash++;
        *start = atol(range);
        if (*dash)
            *end = atol(dash);
        else                    /* "5-" */
            *end = clength - 1;
    }

    if (*start < 0)
	*start = 0;

    if (*end >= clength)
        *end = clength - 1;

    if (*start > *end)
	return 0;

    return (*start > 0 || *end < clength - 1);
}

/* forward declare */
static int internal_byterange(int realreq, apr_off_t *tlength, request_rec *r,
                              const char **r_range, apr_off_t *offset,
                              apr_size_t *length);

AP_DECLARE(int) ap_set_byterange(request_rec *r)
{
    const char *range;
    const char *if_range;
    const char *match;
    apr_off_t range_start;
    apr_off_t range_end;

    if (!r->clength || r->assbackwards)
        return 0;

    /* Check for Range request-header (HTTP/1.1) or Request-Range for
     * backwards-compatibility with second-draft Luotonen/Franks
     * byte-ranges (e.g. Netscape Navigator 2-3).
     *
     * We support this form, with Request-Range, and (farther down) we
     * send multipart/x-byteranges instead of multipart/byteranges for
     * Request-Range based requests to work around a bug in Netscape
     * Navigator 2-3 and MSIE 3.
     */

    if (!(range = apr_table_get(r->headers_in, "Range")))
        range = apr_table_get(r->headers_in, "Request-Range");

    if (!range || strncasecmp(range, "bytes=", 6)) {
        return 0;
    }

    /* Check the If-Range header for Etag or Date.
     * Note that this check will return false (as required) if either
     * of the two etags are weak.
     */
    if ((if_range = apr_table_get(r->headers_in, "If-Range"))) {
        if (if_range[0] == '"') {
            if (!(match = apr_table_get(r->headers_out, "Etag")) ||
                (strcmp(if_range, match) != 0))
                return 0;
        }
        else if (!(match = apr_table_get(r->headers_out, "Last-Modified")) ||
                 (strcmp(if_range, match) != 0))
            return 0;
    }

    if (!ap_strchr_c(range, ',')) {
        /* A single range */
        if (!parse_byterange(apr_pstrdup(r->pool, range + 6), r->clength,
                             &range_start, &range_end))
            return 0;

        r->byterange = 1;

        apr_table_setn(r->headers_out, "Content-Range",
                       apr_psprintf(r->pool,
                                    "bytes %" APR_OFF_T_FMT "-%" APR_OFF_T_FMT
                                    "/%" APR_OFF_T_FMT,
                                    range_start, range_end, r->clength));
        apr_table_setn(r->headers_out, "Content-Length",
                       apr_psprintf(r->pool, "%" APR_OFF_T_FMT,
                                    range_end - range_start + 1));
    }
    else {
        /* a multiple range */
        const char *r_range = apr_pstrdup(r->pool, range + 6);
        apr_off_t tlength = 0;

        r->byterange = 2;
        r->boundary = apr_psprintf(r->pool, "%qx%lx",
				r->request_time, (long) getpid());
        while (internal_byterange(0, &tlength, r, &r_range, NULL, NULL))
            continue;
        apr_table_setn(r->headers_out, "Content-Length",
                       apr_psprintf(r->pool, "%" APR_OFF_T_FMT, tlength));
    }

    r->status = HTTP_PARTIAL_CONTENT;
    r->range = range + 6;

    return 1;
}

AP_DECLARE(int) ap_each_byterange(request_rec *r, apr_off_t *offset,
				  apr_size_t *length)
{
    return internal_byterange(1, NULL, r, &r->range, offset, length);
}

/* If this function is called with realreq=1, it will spit out
 * the correct headers for a byterange chunk, and set offset and
 * length to the positions they should be.
 *
 * If it is called with realreq=0, it will add to tlength the length
 * it *would* have used with realreq=1.
 *
 * Either case will return 1 if it should be called again, and 0
 * when done.
 */
static int internal_byterange(int realreq, apr_off_t *tlength, request_rec *r,
                              const char **r_range, apr_off_t *offset,
                              apr_size_t *length)
{
    apr_off_t range_start;
    apr_off_t range_end;
    char *range;

    if (!**r_range) {
        if (r->byterange > 1) {
            if (realreq) {
                /* ### this isn't "content" so we can't use ap_rvputs(), but
                 * ### it should be processed by non-processing filters. We
                 * ### have no "in-between" APIs yet, so send it to the
                 * ### network for now
                 */
                (void) checked_bputstrs(r, CRLF "--", r->boundary, "--" CRLF,
                                        NULL);
            }
	    else {
                *tlength += 4 + strlen(r->boundary) + 4;
            }
        }
        return 0;
    }

    range = ap_getword(r->pool, r_range, ',');
    if (!parse_byterange(range, r->clength, &range_start, &range_end)) {
        /* Skip this one */
        return internal_byterange(realreq, tlength, r, r_range, offset,
                                  length);
    }

    if (r->byterange > 1) {
        const char *ct = make_content_type(r, r->content_type);
        char ts[MAX_STRING_LEN];

        apr_snprintf(ts, sizeof(ts),
                     "%" APR_OFF_T_FMT "-%" APR_OFF_T_FMT "/%" APR_OFF_T_FMT,
                     range_start, range_end, r->clength);
        if (realreq)
            (void) checked_bputstrs(r, CRLF "--", r->boundary,
                                    CRLF "Content-type: ", ct,
                                    CRLF "Content-range: bytes ", ts,
                                    CRLF CRLF, NULL);
        else
            *tlength += 4 + strlen(r->boundary) + 16 + strlen(ct) + 23 +
                        strlen(ts) + 4;
    }

    if (realreq) {
        *offset = range_start;

        /* ### we need to change ap_each_byterange() to fix this */
        *length = (apr_size_t) (range_end - range_start + 1);
    }
    else {
        *tlength += range_end - range_start + 1;
    }
    return 1;
}

AP_DECLARE(void) ap_set_content_length(request_rec *r, apr_off_t clength)
{
    r->clength = clength;
    apr_table_setn(r->headers_out, "Content-Length",
                   apr_psprintf(r->pool, "%" APR_OFF_T_FMT, clength));
}

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

/*
 * Return the latest rational time from a request/mtime (modification time)
 * pair.  We return the mtime unless it's in the future, in which case we
 * return the current time.  We use the request time as a reference in order
 * to limit the number of calls to time().  We don't check for futurosity
 * unless the mtime is at least as new as the reference.
 */
AP_DECLARE(apr_time_t) ap_rationalize_mtime(request_rec *r, apr_time_t mtime)
{
    apr_time_t now;

    /* For all static responses, it's almost certain that the file was
     * last modified before the beginning of the request.  So there's
     * no reason to call time(NULL) again.  But if the response has been
     * created on demand, then it might be newer than the time the request
     * started.  In this event we really have to call time(NULL) again
     * so that we can give the clients the most accurate Last-Modified.  If we
     * were given a time in the future, we return the current time - the
     * Last-Modified can't be in the future.
     */
    now = (mtime < r->request_time) ? r->request_time : apr_now();
    return (mtime > now) ? now : mtime;
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
    mtime = (r->mtime != 0) ? r->mtime : apr_now();

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
 * Construct an entity tag (ETag) from resource information.  If it's a real
 * file, build in some of the file characteristics.  If the modification time
 * is newer than (request-time minus 1 second), mark the ETag as weak - it
 * could be modified again in as short an interval.  We rationalize the
 * modification time we're given to keep it from being in the future.
 */
AP_DECLARE(char *) ap_make_etag(request_rec *r, int force_weak)
{
    char *etag;
    char *weak;

    /*
     * Make an ETag header out of various pieces of information. We use
     * the last-modified date and, if we have a real file, the
     * length and inode number - note that this doesn't have to match
     * the content-length (i.e. includes), it just has to be unique
     * for the file.
     *
     * If the request was made within a second of the last-modified date,
     * we send a weak tag instead of a strong one, since it could
     * be modified again later in the second, and the validation
     * would be incorrect.
     */
    
    weak = ((r->request_time - r->mtime > APR_USEC_PER_SEC)
	    && !force_weak) ? "" : "W/";

    if (r->finfo.protection != 0) {
        etag = apr_psprintf(r->pool,
			    "%s\"%lx-%lx-%lx\"", weak,
			    (unsigned long) r->finfo.inode,
			    (unsigned long) r->finfo.size,
			    (unsigned long) r->mtime);
    }
    else {
        etag = apr_psprintf(r->pool, "%s\"%lx\"", weak,
			    (unsigned long) r->mtime);
    }

    return etag;
}

AP_DECLARE(void) ap_set_etag(request_rec *r)
{
    char *etag;
    char *variant_etag, *vlv;
    int vlv_weak;

    if (!r->vlist_validator) {
        etag = ap_make_etag(r, 0);
    }
    else {
        /* If we have a variant list validator (vlv) due to the
         * response being negotiated, then we create a structured
         * entity tag which merges the variant etag with the variant
         * list validator (vlv).  This merging makes revalidation
         * somewhat safer, ensures that caches which can deal with
         * Vary will (eventually) be updated if the set of variants is
         * changed, and is also a protocol requirement for transparent
         * content negotiation.
         */

        /* if the variant list validator is weak, we make the whole
         * structured etag weak.  If we would not, then clients could
         * have problems merging range responses if we have different
         * variants with the same non-globally-unique strong etag.
         */

        vlv = r->vlist_validator;
        vlv_weak = (vlv[0] == 'W');
               
        variant_etag = ap_make_etag(r, vlv_weak);

        /* merge variant_etag and vlv into a structured etag */

        variant_etag[strlen(variant_etag) - 1] = '\0';
        if (vlv_weak)
            vlv += 3;
        else
            vlv++;
        etag = apr_pstrcat(r->pool, variant_etag, ";", vlv, NULL);
    }

    apr_table_setn(r->headers_out, "ETag", etag);
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
static int getline(char *s, int n, request_rec *r, int fold);

apr_status_t ap_dechunk_filter(ap_filter_t *f, ap_bucket_brigade *bb,
                               ap_input_mode_t mode)
{
    apr_status_t rv;
    struct dechunk_ctx *ctx = f->ctx;
    ap_bucket *b;
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
            
            if ((rv = getline(line, sizeof(line), f->r, 0)) < 0) {
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
                    b = ap_bucket_create_eos();
                    AP_BRIGADE_INSERT_TAIL(bb, b);
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
        b = AP_BRIGADE_FIRST(bb);
        while (b != AP_BRIGADE_SENTINEL(bb) && !AP_BUCKET_IS_EOS(b)) {
            ap_bucket_read(b, &buf, &len, AP_BLOCK_READ);
            AP_DEBUG_ASSERT(len <= ctx->chunk_size - ctx->bytes_delivered);
            ctx->bytes_delivered += len;
            b = AP_BUCKET_NEXT(b);
        }
        if (ctx->bytes_delivered == ctx->chunk_size) {
            AP_DEBUG_ASSERT(AP_BUCKET_IS_EOS(b));
            AP_BUCKET_REMOVE(b);
            ap_bucket_destroy(b);
            ctx->state = WANT_TRL;
        }
    }

    return APR_SUCCESS;
}

typedef struct http_filter_ctx {
    ap_bucket_brigade *b;
} http_ctx_t;

apr_status_t ap_http_filter(ap_filter_t *f, ap_bucket_brigade *b, ap_input_mode_t mode)
{
#define ASCII_BLANK  '\040'
#define ASCII_CR     '\015'
#define ASCII_LF     '\012'
#define ASCII_TAB    '\011' 
    ap_bucket *e;
    char *buff;
    apr_size_t len;
    char *pos;
    http_ctx_t *ctx = f->ctx;
    apr_status_t rv;

    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(f->c->pool, sizeof(*ctx));
        ctx->b = ap_brigade_create(f->c->pool);
    }

    if (mode == AP_MODE_PEEK) {
        /* XXX make me *try* to read from the network if AP_BRIGADE_EMPTY().
         * For now, we can't do a non-blocking read so we bypass this.
         */
        ap_bucket *e;
        const char *str;
        apr_size_t length;

        e = AP_BRIGADE_FIRST(ctx->b);
        while (e->length == 0) {
            AP_BUCKET_REMOVE(e);
            ap_bucket_destroy(e);

        if (AP_BRIGADE_EMPTY(ctx->b)) {
                e = NULL;
                break;
            }

            e = AP_BRIGADE_FIRST(ctx->b);
        }    

        if (!e || ap_bucket_read(e, &str, &length, AP_NONBLOCK_READ) != APR_SUCCESS) {
            return APR_EOF;
        }
        else {
            return APR_SUCCESS;
        }
    }

    if (AP_BRIGADE_EMPTY(ctx->b)) {
        if ((rv = ap_get_brigade(f->next, ctx->b, mode)) != APR_SUCCESS) {
            return rv;
        }
    }

    if (f->c->remain) {
        e = AP_BRIGADE_FIRST(ctx->b);
        while (e != AP_BRIGADE_SENTINEL(ctx->b)) {
            const char *ignore;

            if ((rv = ap_bucket_read(e, &ignore, &len, AP_BLOCK_READ)) != APR_SUCCESS) {
                /* probably APR_IS_EAGAIN(rv); socket state isn't correct;
                 * remove log once we get this squared away */
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, f->c->base_server, 
                             "ap_bucket_read");
                return rv;
            }

            if (len) {
                if (f->c->remain < len) {
                    ap_bucket_split(e, f->c->remain);
                    f->c->remain = 0;
                }
                else {
                    f->c->remain -= len;
                }
                AP_BUCKET_REMOVE(e);
                AP_BRIGADE_INSERT_TAIL(b, e);
                break; /* once we've gotten some data, deliver it to caller */
            }
            else {
                AP_BUCKET_REMOVE(e);
                ap_bucket_destroy(e);
            }
            e = AP_BUCKET_NEXT(e);
        }
        if (f->c->remain == 0) {
            ap_bucket *eos = ap_bucket_create_eos();
                
            AP_BRIGADE_INSERT_TAIL(b, eos);
        }
        return APR_SUCCESS;
    }

    while (!AP_BRIGADE_EMPTY(ctx->b)) {
        e = AP_BRIGADE_FIRST(ctx->b);
        if ((rv = ap_bucket_read(e, (const char **)&buff, &len, AP_BLOCK_READ)) != APR_SUCCESS) {
            return rv;
        }

        pos = memchr(buff, ASCII_LF, len);
        if (pos != NULL) {
            ap_bucket_split(e, pos - buff + 1);
            AP_BUCKET_REMOVE(e);
            AP_BRIGADE_INSERT_TAIL(b, e);
            return APR_SUCCESS;
        }
        AP_BUCKET_REMOVE(e);
        AP_BRIGADE_INSERT_TAIL(b, e);
    }
    return APR_SUCCESS;
}

/* Get a line of protocol input, including any continuation lines
 * caused by MIME folding (or broken clients) if fold != 0, and place it
 * in the buffer s, of size n bytes, without the ending newline.
 *
 * Returns -1 on error, or the length of s.  
 *
 * Notes: Because the buffer uses 1 char for NUL, the most we can return is 
 *        (n - 1) actual characters.  
 *
 *        If no LF is detected on the last line due to a dropped connection 
 *        or a full buffer, that's considered an error.
 */
static int getline(char *s, int n, request_rec *r, int fold)
{
    char *pos = s;
    char *last_char;
    char *beyond_buff = s + n;
    const char *temp;
    int retval;
    int total = 0;
    int looking_ahead = 0;
    apr_size_t length;
    conn_rec *c = r->connection;
    core_request_config *req_cfg;
    ap_bucket_brigade *b;
    ap_bucket *e;

    req_cfg = (core_request_config *)
                ap_get_module_config(r->request_config, &core_module);
    b = req_cfg->bb;
    /* make sure it's empty unless we're folding */ 
    AP_DEBUG_ASSERT(fold || AP_BRIGADE_EMPTY(b));

    while (1) {
        if (AP_BRIGADE_EMPTY(b)) {
            if (ap_get_brigade(c->input_filters, b, AP_MODE_BLOCKING) != APR_SUCCESS ||
                AP_BRIGADE_EMPTY(b)) {
                return -1;
            }
        }
        e = AP_BRIGADE_FIRST(b); 
        if (e->length == 0) {
            AP_BUCKET_REMOVE(e);
            ap_bucket_destroy(e);
            continue;
        }
        retval = ap_bucket_read(e, &temp, &length, AP_BLOCK_READ);

        if (retval != APR_SUCCESS) {
            total = ((length < 0) && (total == 0)) ? -1 : total;
            break;
        }

        if ((looking_ahead) && (*temp != ASCII_BLANK) && (*temp != ASCII_TAB)) { 
            /* can't fold because next line isn't indented, 
             * so return what we have.  lookahead brigade is 
             * stashed on req_cfg->bb
             */
            AP_DEBUG_ASSERT(!AP_BRIGADE_EMPTY(req_cfg->bb));
            break;
        }
        last_char = pos + length - 1;
        if (last_char < beyond_buff) {
            memcpy(pos, temp, length);
            AP_BUCKET_REMOVE(e);
            ap_bucket_destroy(e);
        }
        else {
            /* input line was larger than the caller's buffer */
            ap_brigade_destroy(b); 
            
            /* don't need to worry about req_cfg->bb being bogus.
             * the request is about to die, and ErrorDocument
             * redirects get a new req_cfg->bb
             */
            
            return -1;
        }
        
        pos = last_char;        /* Point at the last character           */

        if (*pos == ASCII_LF) { /* Did we get a full line of input?      */
                
            if (pos > s && *(pos - 1) == ASCII_CR) {
                --pos;          /* zap optional CR before LF             */
            }
                
            /*
             * Trim any extra trailing spaces or tabs except for the first
             * space or tab at the beginning of a blank string.  This makes
             * it much easier to check field values for exact matches, and
             * saves memory as well.  Terminate string at end of line.
             */
            while (pos > (s + 1) && 
                   (*(pos - 1) == ASCII_BLANK || *(pos - 1) == ASCII_TAB)) {
                --pos;          /* trim extra trailing spaces or tabs    */
            }
            *pos = '\0';        /* zap end of string                     */
            total = pos - s;    /* update total string length            */

            /* look ahead another line if line folding is desired 
             * and this line isn't empty
             */
            if (fold && total) {
                looking_ahead = 1;
            }
            else {
                AP_DEBUG_ASSERT(AP_BRIGADE_EMPTY(req_cfg->bb));
                break;
            }
        }
        else {
            /* no LF yet...character mode client (telnet)...keep going
             * bump past last character read,   
             * and set total in case we bail before finding a LF   
             */
            total = ++pos - s;    
            looking_ahead = 0;  /* only appropriate right after LF       */ 
        }
    }
    ap_xlate_proto_from_ascii(s, total);
    return total;
}

/* parse_uri: break apart the uri
 * Side Effects:
 * - sets r->args to rest after '?' (or NULL if no '?')
 * - sets r->uri to request uri (without r->args part)
 * - sets r->hostname (if not set already) from request (scheme://host:port)
 */
AP_CORE_DECLARE(void) ap_parse_uri(request_rec *r, const char *uri)
{
    int status = HTTP_OK;

    r->unparsed_uri = apr_pstrdup(r->pool, uri);

    if (r->method_number == M_CONNECT) {
	status = ap_parse_hostinfo_components(r->pool, uri, &r->parsed_uri);
    }
    else {
	/* Simple syntax Errors in URLs are trapped by parse_uri_components(). */
	status = ap_parse_uri_components(r->pool, uri, &r->parsed_uri);
    }

    if (ap_is_HTTP_SUCCESS(status)) {
	/* if it has a scheme we may need to do absoluteURI vhost stuff */
	if (r->parsed_uri.scheme
	    && !strcasecmp(r->parsed_uri.scheme, ap_http_method(r))) {
	    r->hostname = r->parsed_uri.hostname;
	}
	else if (r->method_number == M_CONNECT) {
	    r->hostname = r->parsed_uri.hostname;
	}
	r->args = r->parsed_uri.query;
	r->uri = r->parsed_uri.path ? r->parsed_uri.path
				    : apr_pstrdup(r->pool, "/");
#if defined(OS2) || defined(WIN32)
	/* Handle path translations for OS/2 and plug security hole.
	 * This will prevent "http://www.wherever.com/..\..\/" from
	 * returning a directory for the root drive.
	 */
	{
	    char *x;

	    for (x = r->uri; (x = strchr(x, '\\')) != NULL; )
		*x = '/';
	}
#endif  /* OS2 || WIN32 */
    }
    else {
	r->args = NULL;
	r->hostname = NULL;
	r->status = status;             /* set error status */
	r->uri = apr_pstrdup(r->pool, uri);
    }
}

static int read_request_line(request_rec *r)
{
    char l[DEFAULT_LIMIT_REQUEST_LINE + 2]; /* getline's two extra for \n\0 */
    const char *ll = l;
    const char *uri;
    conn_rec *conn = r->connection;
    int major = 1, minor = 0;   /* Assume HTTP/1.0 if non-"HTTP" protocol */
    int len;

    /* Read past empty lines until we get a real request line,
     * a read error, the connection closes (EOF), or we timeout.
     *
     * We skip empty lines because browsers have to tack a CRLF on to the end
     * of POSTs to support old CERN webservers.  But note that we may not
     * have flushed any previous response completely to the client yet.
     * We delay the flush as long as possible so that we can improve
     * performance for clients that are pipelining requests.  If a request
     * is pipelined then we won't block during the (implicit) read() below.
     * If the requests aren't pipelined, then the client is still waiting
     * for the final buffer flush from us, and we will block in the implicit
     * read().  B_SAFEREAD ensures that the BUFF layer flushes if it will
     * have to block during a read.
     */
    ap_bsetflag(conn->client, B_SAFEREAD, 1); 
    ap_bflush(conn->client);
    while ((len = getline(l, sizeof(l), r, 0)) <= 0) {
        if (len < 0) {             /* includes EOF */
	    ap_bsetflag(conn->client, B_SAFEREAD, 0);
	    /* this is a hack to make sure that request time is set,
	     * it's not perfect, but it's better than nothing 
	     */
	    r->request_time = apr_now();
            return 0;
        }
    }
    /* we've probably got something to do, ignore graceful restart requests */

    /* XXX - sigwait doesn't work if the signal has been SIG_IGNed (under
     * linux 2.0 w/ glibc 2.0, anyway), and this step isn't necessary when
     * we're running a sigwait thread anyway. If/when unthreaded mode is
     * put back in, we should make sure to ignore this signal iff a sigwait
     * thread isn't used. - mvsk

#ifdef SIGWINCH
    apr_signal(SIGWINCH, SIG_IGN);
#endif
    */

    ap_bsetflag(conn->client, B_SAFEREAD, 0);

    r->request_time = apr_now();
    r->the_request = apr_pstrdup(r->pool, l);
    r->method = ap_getword_white(r->pool, &ll);
    ap_update_connection_status(conn->id, "Method", r->method);
    uri = ap_getword_white(r->pool, &ll);

    /* Provide quick information about the request method as soon as known */

    r->method_number = ap_method_number_of(r->method);
    if (r->method_number == M_GET && r->method[0] == 'H') {
        r->header_only = 1;
    }

    ap_parse_uri(r, uri);

    /* getline returns (size of max buffer - 1) if it fills up the
     * buffer before finding the end-of-line.  This is only going to
     * happen if it exceeds the configured limit for a request-line.
     */
    if (len > r->server->limit_req_line) {
        r->status    = HTTP_REQUEST_URI_TOO_LARGE;
        r->proto_num = HTTP_VERSION(1,0);
        r->protocol  = apr_pstrdup(r->pool, "HTTP/1.0");
        return 0;
    }

    r->assbackwards = (ll[0] == '\0');
    r->protocol = apr_pstrdup(r->pool, ll[0] ? ll : "HTTP/0.9");
    ap_update_connection_status(conn->id, "Protocol", r->protocol);

    if (2 == sscanf(r->protocol, "HTTP/%u.%u", &major, &minor)
      && minor < HTTP_VERSION(1,0))	/* don't allow HTTP/0.1000 */
	r->proto_num = HTTP_VERSION(major, minor);
    else
	r->proto_num = HTTP_VERSION(1,0);

    return 1;
}

static void get_mime_headers(request_rec *r)
{
    char field[DEFAULT_LIMIT_REQUEST_FIELDSIZE + 2]; /* getline's two extra */
    char *value;
    char *copy;
    int len;
    int fields_read = 0;
    apr_table_t *tmp_headers;

    /* We'll use apr_overlap_tables later to merge these into r->headers_in. */
    tmp_headers = apr_make_table(r->pool, 50);

    /*
     * Read header lines until we get the empty separator line, a read error,
     * the connection closes (EOF), reach the server limit, or we timeout.
     */
    while ((len = getline(field, sizeof(field), r, 1)) > 0) {

        if (r->server->limit_req_fields &&
            (++fields_read > r->server->limit_req_fields)) {
            r->status = HTTP_BAD_REQUEST;
            apr_table_setn(r->notes, "error-notes",
			   "The number of request header fields exceeds "
			   "this server's limit.<P>\n");
            return;
        }
        /* getline returns (size of max buffer - 1) if it fills up the
         * buffer before finding the end-of-line.  This is only going to
         * happen if it exceeds the configured limit for a field size.
         */
        if (len > r->server->limit_req_fieldsize) {
            r->status = HTTP_BAD_REQUEST;
            apr_table_setn(r->notes, "error-notes",
			   apr_pstrcat(r->pool,
				       "Size of a request header field "
				       "exceeds server limit.<P>\n"
				       "<PRE>\n",
				       ap_escape_html(r->pool, field),
				       "</PRE>\n", NULL));
            return;
        }
        copy = apr_palloc(r->pool, len + 1);
        memcpy(copy, field, len + 1);

        if (!(value = strchr(copy, ':'))) {     /* Find the colon separator */
            r->status = HTTP_BAD_REQUEST;       /* or abort the bad request */
            apr_table_setn(r->notes, "error-notes",
			   apr_pstrcat(r->pool,
				       "Request header field is missing "
				       "colon separator.<P>\n"
				       "<PRE>\n",
				       ap_escape_html(r->pool, copy),
				       "</PRE>\n", NULL));
            return;
        }

        *value = '\0';
        ++value;
        while (*value == ' ' || *value == '\t') {
            ++value;            /* Skip to start of value   */
	}

	apr_table_addn(tmp_headers, copy, value);
    }

    apr_overlap_tables(r->headers_in, tmp_headers, APR_OVERLAP_TABLES_MERGE);
}

request_rec *ap_read_request(conn_rec *conn)
{
    request_rec *r;
    apr_pool_t *p;
    const char *expect;
    int access_status;
    core_request_config *req_cfg;

    apr_create_pool(&p, conn->pool);
    r = apr_pcalloc(p, sizeof(request_rec));
    r->pool            = p;
    r->connection      = conn;
    r->server          = conn->base_server;

    conn->keptalive    = conn->keepalive == 1;
    conn->keepalive    = 0;

    r->user            = NULL;
    r->ap_auth_type    = NULL;

    r->allowed_methods = ap_make_method_list(p, 2);

    r->headers_in      = apr_make_table(r->pool, 50);
    r->subprocess_env  = apr_make_table(r->pool, 50);
    r->headers_out     = apr_make_table(r->pool, 12);
    r->err_headers_out = apr_make_table(r->pool, 5);
    r->notes           = apr_make_table(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);
    req_cfg = apr_pcalloc(r->pool, sizeof(core_request_config));
    req_cfg->bb = ap_brigade_create(r->pool);
    ap_set_module_config(r->request_config, &core_module, req_cfg);
                    
    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct     = 0;                      /* bytect isn't for body */

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_REQUEST_TIME_OUT;  /* Until we get a request */
    r->the_request     = NULL;
    r->output_filters  = conn->output_filters;
    r->input_filters   = conn->input_filters;

    apr_setsocketopt(conn->client_socket, APR_SO_TIMEOUT, 
                     conn->keptalive
                     ? r->server->keep_alive_timeout * APR_USEC_PER_SEC
                     : r->server->timeout * APR_USEC_PER_SEC);
                     
    ap_add_output_filter("CONTENT_LENGTH", NULL, r, r->connection);
    ap_add_output_filter("HTTP_HEADER", NULL, r, r->connection);

    /* Get the request... */
    if (!read_request_line(r)) {
        if (r->status == HTTP_REQUEST_URI_TOO_LARGE) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "request failed: URI too long");
            ap_send_error_response(r, 0);
            ap_run_log_transaction(r);
            return r;
        }
        return NULL;
    }
    if (r->connection->keptalive) {
        apr_setsocketopt(r->connection->client_socket, APR_SO_TIMEOUT,
                         r->server->timeout * APR_USEC_PER_SEC);
    }
    if (!r->assbackwards) {
        get_mime_headers(r);
        if (r->status != HTTP_REQUEST_TIME_OUT) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
			  "request failed: error reading the headers");
            ap_send_error_response(r, 0);
            ap_run_log_transaction(r);
            return r;
        }
    }
    else {
        if (r->header_only) {
            /*
             * Client asked for headers only with HTTP/0.9, which doesn't send
             * headers! Have to dink things just to make sure the error message
             * comes through...
             */
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                          "client sent invalid HTTP/0.9 request: HEAD %s",
                          r->uri);
            r->header_only = 0;
            r->status = HTTP_BAD_REQUEST;
            ap_send_error_response(r, 0);
            ap_run_log_transaction(r);
            return r;
        }
    }

    r->status = HTTP_OK;                         /* Until further notice. */

    /* update what we think the virtual host is based on the headers we've
     * now read. may update status.
     */
    ap_update_vhost_from_headers(r);

    /* we may have switched to another server */
    r->per_dir_config = r->server->lookup_defaults;

    conn->keptalive = 0;        /* We now have a request to play with */

    if ((!r->hostname && (r->proto_num >= HTTP_VERSION(1,1))) ||
        ((r->proto_num == HTTP_VERSION(1,1)) &&
         !apr_table_get(r->headers_in, "Host"))) {
        /*
         * Client sent us an HTTP/1.1 or later request without telling us the
         * hostname, either with a full URL or a Host: header. We therefore
         * need to (as per the 1.1 spec) send an error.  As a special case,
         * HTTP/1.1 mentions twice (S9, S14.23) that a request MUST contain
         * a Host: header, and the server MUST respond with 400 if it doesn't.
         */
        r->status = HTTP_BAD_REQUEST;
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      "client sent HTTP/1.1 request without hostname "
                      "(see RFC2068 section 9, and 14.23): %s", r->uri);
    }
    if (r->status != HTTP_OK) {
        ap_send_error_response(r, 0);
        ap_run_log_transaction(r);
        return r;
    }
    if (((expect = apr_table_get(r->headers_in, "Expect")) != NULL) &&
        (expect[0] != '\0')) {
        /*
         * The Expect header field was added to HTTP/1.1 after RFC 2068
         * as a means to signal when a 100 response is desired and,
         * unfortunately, to signal a poor man's mandatory extension that
         * the server must understand or return 417 Expectation Failed.
         */
        if (strcasecmp(expect, "100-continue") == 0) {
            r->expecting_100 = 1;
        }
        else {
            r->status = HTTP_EXPECTATION_FAILED;
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                          "client sent an unrecognized expectation value of "
                          "Expect: %s", expect);
            ap_send_error_response(r, 0);
            (void) ap_discard_request_body(r);
            ap_run_log_transaction(r);
            return r;
        }
    }

    if ((access_status = ap_run_post_read_request(r))) {
        ap_die(access_status, r);
        ap_run_log_transaction(r);
        return NULL;
    }

    return r;
}

/*
 * A couple of other functions which initialize some of the fields of
 * a request structure, as appropriate for adjuncts of one kind or another
 * to a request in progress.  Best here, rather than elsewhere, since
 * *someone* has to set the protocol-specific fields...
 */

void ap_set_sub_req_protocol(request_rec *rnew, const request_rec *r)
{
    rnew->the_request     = r->the_request;  /* Keep original request-line */

    rnew->assbackwards    = 1;   /* Don't send headers from this. */
    rnew->no_local_copy   = 1;   /* Don't try to send HTTP_NOT_MODIFIED for a
                                  * fragment. */
    rnew->method          = "GET";
    rnew->method_number   = M_GET;
    rnew->protocol        = "INCLUDED";

    rnew->status          = HTTP_OK;

    rnew->headers_in      = r->headers_in;
    rnew->subprocess_env  = apr_copy_table(rnew->pool, r->subprocess_env);
    rnew->headers_out     = apr_make_table(rnew->pool, 5);
    rnew->err_headers_out = apr_make_table(rnew->pool, 5);
    rnew->notes           = apr_make_table(rnew->pool, 5);

    rnew->expecting_100   = r->expecting_100;
    rnew->read_length     = r->read_length;
    rnew->read_body       = REQUEST_NO_BODY;

    rnew->main = (request_rec *) r;
}

static void end_output_stream(request_rec *r)
{
    ap_bucket_brigade *bb;
    ap_bucket *b;

    bb = ap_brigade_create(r->pool);
    b = ap_bucket_create_eos();
    AP_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);
}

void ap_finalize_sub_req_protocol(request_rec *sub)
{
    end_output_stream(sub); 
}

/*
 * Support for the Basic authentication protocol, and a bit for Digest.
 */

AP_DECLARE(void) ap_note_auth_failure(request_rec *r)
{
    if (!strcasecmp(ap_auth_type(r), "Basic"))
        ap_note_basic_auth_failure(r);
    else if (!strcasecmp(ap_auth_type(r), "Digest"))
        ap_note_digest_auth_failure(r);
}

AP_DECLARE(void) ap_note_basic_auth_failure(request_rec *r)
{
    if (strcasecmp(ap_auth_type(r), "Basic"))
        ap_note_auth_failure(r);
    else
        apr_table_setn(r->err_headers_out,
                  r->proxyreq ? "Proxy-Authenticate" : "WWW-Authenticate",
                  apr_pstrcat(r->pool, "Basic realm=\"", ap_auth_name(r), "\"",
                          NULL));
}

AP_DECLARE(void) ap_note_digest_auth_failure(request_rec *r)
{
    apr_table_setn(r->err_headers_out,
	    r->proxyreq ? "Proxy-Authenticate" : "WWW-Authenticate",
	    apr_psprintf(r->pool, "Digest realm=\"%s\", nonce=\"%llx\"",
		ap_auth_name(r), r->request_time));
}

AP_DECLARE(int) ap_get_basic_auth_pw(request_rec *r, const char **pw)
{
    const char *auth_line = apr_table_get(r->headers_in,
                                      r->proxyreq ? "Proxy-Authorization"
                                                  : "Authorization");
    const char *t;

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "Basic"))
        return DECLINED;

    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
		      0, r, "need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!auth_line) {
        ap_note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
        /* Client tried to authenticate using wrong auth scheme */
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
		      "client used wrong authentication scheme: %s", r->uri);
        ap_note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    while (*auth_line== ' ' || *auth_line== '\t') {
        auth_line++;
    }

    t = ap_pbase64decode(r->pool, auth_line);
    /* Note that this allocation has to be made from r->connection->pool
     * because it has the lifetime of the connection.  The other allocations
     * are temporary and can be tossed away any time.
     */
    r->user = ap_getword_nulls (r->pool, &t, ':');
    r->ap_auth_type = "Basic";

    *pw = t;

    return OK;
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
    request_rec *r;
    char *buf;
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

    headfield = apr_pstrcat(h->r->pool, fieldname, ": ", fieldval, CRLF, NULL);
    ap_xlate_proto_to_ascii(headfield, strlen(headfield));
    apr_cpystrn(h->buf, headfield, strlen(headfield) + 1);
    h->buf += strlen(headfield);
    return 1;
}

static int compute_header_len(apr_size_t *length, const char *fieldname, 
                              const char *fieldval)
{
    /* The extra five are for ": " and CRLF, plus one for a '\0'. */
    *length = *length + strlen(fieldname) + strlen(fieldval) + 6;
    return 1;
}

AP_DECLARE(void) ap_basic_http_header(request_rec *r, char *buf)
{
    char *protocol;
    char *date = NULL;
    char *tmp;
    header_struct h;

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

        protocol = "HTTP/1.0";
        r->connection->keepalive = -1;
    }
    else {
        protocol = AP_SERVER_PROTOCOL;
    }

    /* Output the HTTP/1.x Status-Line and the Date and Server fields */

    tmp = apr_pstrcat(r->pool, protocol, " ", r->status_line, CRLF, NULL);
    apr_cpystrn(buf, tmp, strlen(tmp) + 1);
    buf += strlen(tmp);

    date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
    apr_rfc822_date(date, r->request_time);

    h.r = r;
    h.buf = buf;
    form_header_field(&h, "Date", date);
    form_header_field(&h, "Server", ap_get_server_version());

    apr_table_unset(r->headers_out, "Date");        /* Avoid bogosity */
    apr_table_unset(r->headers_out, "Server");
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
static void terminate_header(char *buf)
{
    int len = strlen(buf);
    char *headfield = buf + len;
    char *tmp = "X-Pad: avoid browser bug" CRLF;

    if (len >= 255 && len <= 257) {
        apr_cpystrn(headfield, tmp, strlen(tmp) + 1);
        headfield += strlen(tmp);
    }
    apr_cpystrn(headfield, CRLF, strlen(CRLF) + 1);
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
    ml->method_list = apr_make_array(p, sizeof(char *), nelts);
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
	omethods = (char **) apr_push_array(dest->method_list);
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
    xmethod = (const char **) apr_push_array(l->method_list);
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
    char *buff;
    ap_bucket *b;
    ap_bucket_brigade *bb;
    apr_size_t len;
    header_struct h;

    if (r->assbackwards)
        return DECLINED;

    apr_table_do((int (*) (void *, const char *, const char *)) compute_header_len,
                 (void *) &len, r->headers_out, NULL);
    
    /* Need to add a fudge factor so that the CRLF at the end of the headers
     * and the basic http headers don't overflow this buffer.
     */
    len += strlen(ap_get_server_version()) + 100;
    buff = apr_pcalloc(r->pool, len);
    ap_basic_http_header(r, buff);

    apr_table_setn(r->headers_out, "Content-Length", "0");
    apr_table_setn(r->headers_out, "Allow", make_allow(r));
    ap_set_keepalive(r);

    h.r = r;
    h.buf = buff;

    apr_table_do((int (*) (void *, const char *, const char *)) form_header_field,
             (void *) &h, r->headers_out, NULL);

    terminate_header(buff);

    r->bytes_sent = 0;

    bb = ap_brigade_create(r->pool);
    b = ap_bucket_create_pool(buff, strlen(buff), r->pool);
    AP_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);

    return OK;
}

/*
 * Here we try to be compatible with clients that want multipart/x-byteranges
 * instead of multipart/byteranges (also see above), as per HTTP/1.1. We
 * look for the Request-Range header (e.g. Netscape 2 and 3) as an indication
 * that the browser supports an older protocol. We also check User-Agent
 * for Microsoft Internet Explorer 3, which needs this as well.
 */
static int use_range_x(request_rec *r)
{
    const char *ua;
    return (apr_table_get(r->headers_in, "Request-Range") ||
            ((ua = apr_table_get(r->headers_in, "User-Agent"))
             && ap_strstr_c(ua, "MSIE 3")));
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
	    *(char **)apr_push_array(values) = start;
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

    varies = apr_make_array(r->pool, 5, sizeof(char *));

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

struct content_length_ctx {
    ap_bucket_brigade *saved;
    int hold_data;    /* Whether or not to buffer the data. */
};

/* This filter computes the content length, but it also computes the number
 * of bytes sent to the client.  This means that this filter will always run
through all of the buckets in all brigades */
AP_CORE_DECLARE_NONSTD(apr_status_t) ap_content_length_filter(ap_filter_t *f,
                                                              ap_bucket_brigade *b)
{
    request_rec *r = f->r;
    struct content_length_ctx *ctx;
    apr_status_t rv;
    ap_bucket *e;
    int send_it = 0;

    ctx = f->ctx;
    if (!ctx) { /* first time through */
        f->ctx = ctx = apr_pcalloc(r->pool, sizeof(struct content_length_ctx));

        /* We won't compute a content length if one of the following is true:
         * . subrequest
         * . HTTP/0.9
         * . status HTTP_NOT_MODIFIED or HTTP_NO_CONTENT
         * . HEAD
         * . content length already computed
         * . can be chunked
         * . body already chunked
         * Much of this should correspond to checks in ap_set_keepalive().
         */
        if (r->assbackwards 
            || r->status == HTTP_NOT_MODIFIED 
            || r->status == HTTP_NO_CONTENT
            || r->header_only
            || apr_table_get(r->headers_out, "Content-Length")
            || r->proto_num == HTTP_VERSION(1,1)
            || ap_find_last_token(f->r->pool,
                                  apr_table_get(r->headers_out,
                                                "Transfer-Encoding"),
                                                "chunked")) {
            ctx->hold_data = 0;
        }
        else {
            ctx->hold_data = 1;
        }
    }

    AP_BRIGADE_FOREACH(e, b) {
        const char *ignored;
        apr_size_t length;

        if (AP_BUCKET_IS_EOS(e) || AP_BUCKET_IS_FLUSH(e)) {
            ctx->hold_data = 0;
            send_it = 1;
        }
        rv = ap_bucket_read(e, &ignored, &length, AP_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        r->bytes_sent += length;
    }

    /* save the brigade; we can't pass any data to the next
     * filter until we have the entire content length
     */
    if (ctx->hold_data && !send_it) {
        ap_save_brigade(f, &ctx->saved, &b);
        return APR_SUCCESS;
    }

    if (ctx->saved) {
        AP_BRIGADE_CONCAT(ctx->saved, b);
        b = ctx->saved;
    }

    ap_set_content_length(r, r->bytes_sent);
    return ap_pass_brigade(f->next, b);
}

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_http_header_filter(ap_filter_t *f, ap_bucket_brigade *b)
{
    int i;
    char *date = NULL;
    request_rec *r = f->r;
    char *buff, *buff_start;
    ap_bucket *e;
    ap_bucket_brigade *b2;
    apr_size_t len = 0;
    header_struct h;

    AP_DEBUG_ASSERT(!r->main);

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
        r->headers_out = apr_overlay_tables(r->pool, r->err_headers_out,
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

    ap_set_keepalive(r);

    if (r->chunked) {
        apr_table_mergen(r->headers_out, "Transfer-Encoding", "chunked");
        apr_table_unset(r->headers_out, "Content-Length");
        /* Disable the buffer filter because it may be masking bugs in the 
         * bucket brigade code  */
/*      ap_add_output_filter("COALESCE", NULL, r, r->connection); */
    }

    if (r->byterange > 1) {
        apr_table_setn(r->headers_out, "Content-Type",
		       apr_pstrcat(r->pool, "multipart",
				   use_range_x(r) ? "/x-" : "/",
				   "byteranges; boundary=",
				   r->boundary, NULL));
    }
    else {
	apr_table_setn(r->headers_out, "Content-Type",
		       make_content_type(r, r->content_type));
    }

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

    apr_table_do((int (*) (void *, const char *, const char *)) compute_header_len,
                 (void *) &len, r->headers_out, NULL);
    
    /* Need to add a fudge factor so that the CRLF at the end of the headers
     * and the basic http headers don't overflow this buffer.
     */
    len += strlen(ap_get_server_version()) + 100;
    buff_start = buff = apr_pcalloc(r->pool, len);
    ap_basic_http_header(r, buff);
    buff += strlen(buff);

    h.r = r;
    h.buf = buff;

    apr_table_do((int (*) (void *, const char *, const char *)) form_header_field,
		 (void *) &h, r->headers_out, NULL);

    terminate_header(buff);

    r->sent_bodyct = 1;         /* Whatever follows is real body stuff... */

    b2 = ap_brigade_create(r->pool);
    e = ap_bucket_create_pool(buff_start, strlen(buff_start), r->pool);
    AP_BRIGADE_INSERT_HEAD(b2, e);
    ap_pass_brigade(f->next, b2);

    if (r->chunked) {
        /* We can't add this filters until we have already sent the headers.
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

/* finalize_request_protocol is called at completion of sending the
 * response.  Its sole purpose is to send the terminating protocol
 * information for any wrappers around the response message body
 * (i.e., transfer encodings).  It should have been named finalize_response.
 */
AP_DECLARE(void) ap_finalize_request_protocol(request_rec *r)
{
    while (r->next) {
        r = r->next;
    }
    /* tell the filter chain there is no more content coming */
    if (!r->eos_sent) {
        end_output_stream(r);
    }
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
        /* Make sure getline() didn't leave any droppings. */
        core_request_config *req_cfg = 
            (core_request_config *)ap_get_module_config(r->request_config,
                                                        &core_module);
        AP_DEBUG_ASSERT(AP_BRIGADE_EMPTY(req_cfg->bb));
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
        ap_bucket *e;
        ap_bucket_brigade *bb;

        /* sending 100 Continue interim response */
        tmp = apr_pstrcat(r->pool, AP_SERVER_PROTOCOL, " ", status_lines[0],
                                CRLF CRLF, NULL);
        bb = ap_brigade_create(r->pool);
        e = ap_bucket_create_pool(tmp, strlen(tmp), r->pool);
        AP_BRIGADE_INSERT_HEAD(bb, e);
        e = ap_bucket_create_flush();
        AP_BRIGADE_INSERT_TAIL(bb, e);

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
    ap_bucket *b, *old;
    const char *tempbuf;
    core_request_config *req_cfg =
	(core_request_config *)ap_get_module_config(r->request_config,
                                                    &core_module);
    ap_bucket_brigade *bb = req_cfg->bb;

    do {
        if (AP_BRIGADE_EMPTY(bb)) {
            if (ap_get_brigade(r->input_filters, bb, AP_MODE_BLOCKING) != APR_SUCCESS) {
                /* if we actually fail here, we want to just return and
                 * stop trying to read data from the client.
                 */
                r->connection->keepalive = -1;
                ap_brigade_destroy(bb);
                return -1;
            }
        }
        b = AP_BRIGADE_FIRST(bb);
    } while (AP_BRIGADE_EMPTY(bb));

    if (AP_BUCKET_IS_EOS(b)) {         /* reached eos on previous invocation */
        AP_BUCKET_REMOVE(b);
        ap_bucket_destroy(b);
        return 0;
    }

    total = 0;
    while (total < bufsiz &&  b != AP_BRIGADE_SENTINEL(bb) && !AP_BUCKET_IS_EOS(b)) {
        if ((rv = ap_bucket_read(b, &tempbuf, &len_read, AP_BLOCK_READ)) != APR_SUCCESS) {
            return -1;
        }
        if (total + len_read > bufsiz) {
            ap_bucket_split(b, bufsiz - total);
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
        b = AP_BUCKET_NEXT(b);
        AP_BUCKET_REMOVE(old);
        ap_bucket_destroy(old);
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

/*
 * Send the body of a response to the client.
 */
AP_DECLARE(apr_status_t) ap_send_fd(apr_file_t *fd, request_rec *r, apr_off_t offset, 
                                    apr_size_t len, apr_size_t *nbytes) 
{
    ap_bucket_brigade *bb = NULL;
    ap_bucket *b;
    apr_status_t rv;

    bb = ap_brigade_create(r->pool);
    b = ap_bucket_create_file(fd, offset, len);
    AP_BRIGADE_INSERT_TAIL(bb, b);

    rv = ap_pass_brigade(r->output_filters, bb);
    if (rv != APR_SUCCESS) {
        *nbytes = 0; /* no way to tell how many were actually sent */
    }
    else {
        *nbytes = len;
    }

    return rv;
}

#ifdef AP_USE_MMAP_FILES

/* The code writes MMAP_SEGMENT_SIZE bytes at a time.  This is due to Apache's
 * timeout model, which is a timeout per-write rather than a time for the
 * entire transaction to complete.  Essentially this should be small enough
 * so that in one Timeout period, your slowest clients should be reasonably
 * able to receive this many bytes.
 *
 * To take advantage of zero-copy TCP under Solaris 2.6 this should be a
 * multiple of 16k.  (And you need a SunATM2.0 network card.)
 */
#ifndef MMAP_SEGMENT_SIZE
#define MMAP_SEGMENT_SIZE       32768
#endif

/* send data from an in-memory buffer */
AP_DECLARE(size_t) ap_send_mmap(apr_mmap_t *mm, request_rec *r, size_t offset,
                             size_t length)
{
    ap_bucket_brigade *bb = NULL;
    ap_bucket *b;

    bb = ap_brigade_create(r->pool);
    b = ap_bucket_create_mmap(mm, offset, length);
    AP_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);

    return mm->size; /* XXX - change API to report apr_status_t? */
}
#endif /* AP_USE_MMAP_FILES */

AP_DECLARE(int) ap_rputc(int c, request_rec *r)
{
    ap_bucket_brigade *bb = NULL;
    ap_bucket *b;
    char c2 = (char)c;

    if (r->connection->aborted) {
	return EOF;
    }

    bb = ap_brigade_create(r->pool);
    b = ap_bucket_create_transient(&c2, 1);
    AP_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);

    return c;
}

AP_DECLARE(int) ap_rputs(const char *str, request_rec *r)
{
    ap_bucket_brigade *bb = NULL;
    ap_bucket *b;
    apr_size_t len;

    if (r->connection->aborted)
        return EOF;
    if (*str == '\0')
        return 0;

    len = strlen(str);
    bb = ap_brigade_create(r->pool);
    b = ap_bucket_create_transient(str, len);
    AP_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);

    return len;
}

AP_DECLARE(int) ap_rwrite(const void *buf, int nbyte, request_rec *r)
{
    ap_bucket_brigade *bb = NULL;
    ap_bucket *b;

    if (r->connection->aborted)
        return EOF;
    if (nbyte == 0)
        return 0;

    bb = ap_brigade_create(r->pool);
    b = ap_bucket_create_transient(buf, nbyte);
    AP_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);
    return nbyte;
}

AP_DECLARE(int) ap_vrprintf(request_rec *r, const char *fmt, va_list va)
{
    ap_bucket_brigade *bb = NULL;
    apr_size_t written;

    if (r->connection->aborted)
        return EOF;

    bb = ap_brigade_create(r->pool);
    written = ap_brigade_vprintf(bb, fmt, va);
    if (written != 0)
        ap_pass_brigade(r->output_filters, bb);
    return written;
}

/* TODO:  Make ap pa_bucket_vprintf that printfs directly into a
 * bucket.
 */
AP_DECLARE_NONSTD(int) ap_rprintf(request_rec *r, const char *fmt, ...)
{
    va_list va;
    int n;

    if (r->connection->aborted)
        return EOF;

    va_start(va, fmt);
    n = ap_vrprintf(r, fmt, va);
    va_end(va);

    return n;
}

AP_DECLARE_NONSTD(int) ap_rvputs(request_rec *r, ...)
{
    ap_bucket_brigade *bb = NULL;
    apr_size_t written;
    va_list va;

    if (r->connection->aborted)
        return EOF;
    bb = ap_brigade_create(r->pool);
    va_start(va, r);
    written = ap_brigade_vputstrs(bb, va);
    va_end(va);
    if (written != 0)
        ap_pass_brigade(r->output_filters, bb);
    return written;
}

AP_DECLARE(int) ap_rflush(request_rec *r)
{
    /* we should be using a flush bucket to flush the stack, not buff code. */
    ap_bucket_brigade *bb;
    ap_bucket *b;

    bb = ap_brigade_create(r->pool);
    b = ap_bucket_create_flush();
    AP_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);
    return 0;
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
        char *buff;
        header_struct h;
        ap_bucket *e;
        ap_bucket_brigade *bb;
        apr_size_t len = 0;

        if (!apr_is_empty_table(r->err_headers_out))
            r->headers_out = apr_overlay_tables(r->pool, r->err_headers_out,
						r->headers_out);

        apr_table_do((int (*) (void *, const char *, const char *)) compute_header_len,
                     (void *) &len, r->headers_out, NULL);
     
        /* Need to add a fudge factor so that the CRLF at the end of the headers
         * and the basic http headers don't overflow this buffer.
         */
        len += strlen(ap_get_server_version()) + 100;
        buff = apr_pcalloc(r->pool, len);
        e = ap_bucket_create_pool(buff, len, r->pool);
        ap_basic_http_header(r, buff);
        ap_set_keepalive(r);

        h.r = r;
        h.buf = buff;

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

        terminate_header(buff);
       
        bb = ap_brigade_create(r->pool);
        AP_BRIGADE_INSERT_HEAD(bb, e);
        ap_pass_brigade(r->connection->output_filters, bb);

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
        apr_clear_table(r->err_headers_out);

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

        ap_rvputs(r,
                  DOCTYPE_HTML_2_0
                  "<HTML><HEAD>\n<TITLE>", title,
                  "</TITLE>\n</HEAD><BODY>\n<H1>", h1, "</H1>\n",
                  NULL);
        
        ap_rputs(get_canned_error_string(status, r, location),r); 

        if (recursive_error) {
            ap_rvputs(r, "<P>Additionally, a ",
                      status_lines[ap_index_of_response(recursive_error)],
                      "\nerror was encountered while trying to use an "
                      "ErrorDocument to handle the request.\n", NULL);
        }
        ap_rputs(ap_psignature("<HR>\n", r), r);
        ap_rputs("</BODY></HTML>\n", r);
    }
    ap_finalize_request_protocol(r);
}

AP_IMPLEMENT_HOOK_RUN_ALL(int,post_read_request,
                          (request_rec *r),(r),OK,DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,log_transaction,
                          (request_rec *r),(r),OK,DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(const char *,http_method,
                            (const request_rec *r),(r),NULL)
AP_IMPLEMENT_HOOK_RUN_FIRST(unsigned short,default_port,
                            (const request_rec *r),(r),0)
