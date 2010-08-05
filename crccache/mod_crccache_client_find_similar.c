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
 *
 * Find a page for a similar URL as the newly requested page
 *  Created on: 02/08/2010
 *      Author: Alex Wulms
 */

#include <apr.h>

#include <apr_strings.h>
#include <apr_lib.h>

#if APR_HAVE_UNISTD_H
/* for getpid() */
#include <unistd.h>
#endif


#include <httpd.h>
#include <http_log.h>


#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include "crccache.h"
#include "mod_crccache_client_find_similar.h"
#include "ap_log_helper.h"
#include "rmm_hash.h"

RMM_OFF_T_DECLARE(char);

typedef struct vary_headers_s vary_headers_t;
RMM_OFF_T_DECLARE(vary_headers_t);
struct vary_headers_s {
	RMM_OFF_T(vary_headers_t) next;
	RMM_OFF_T(char) name;
	RMM_OFF_T(char) value;
};


typedef struct cached_files_info_s cached_files_info_t;
RMM_OFF_T_DECLARE(cached_files_info_t);
struct cached_files_info_s {
	RMM_OFF_T(cached_files_info_t) prev;
	RMM_OFF_T(cached_files_info_t) next;
	RMM_OFF_T(char) basepath; // Path without .header or .data postfix
	RMM_OFF_T(char) uri; // URI of the page (useful for logging purposes)
	RMM_OFF_T(vary_headers_t) vary_headers;
};

typedef struct sp_per_content_type_s sp_per_content_type_t;
RMM_OFF_T_DECLARE(sp_per_content_type_t);
struct sp_per_content_type_s {
	RMM_OFF_T(sp_per_content_type_t) next;
	RMM_OFF_T(char) content_type;
	RMM_OFF_T(cached_files_info_t) cached_files_info;
	RMM_OFF_T(rmm_hash_t) cached_files_info_by_path;
	RMM_OFF_T(cached_files_info_t) tail_file_info;
};

typedef struct sp_per_regex_s sp_per_regex_t;
RMM_OFF_T_DECLARE(sp_per_regex_t);
struct sp_per_regex_s {
	RMM_OFF_T(sp_per_regex_t) next;
	/* The regex parameter stored here is the non-compiled regex string.
	 * The compiled version must be cached in a per-process cache pool.
	 * Reason is that the ap_regex compiler allocates an internal structure
	 * for the compiled data using malloc. The ap_preg structure does not provide
	 * any info about that internal structure (like the length) and as such,
	 * the internal structure can not be transferred to the shared memory :-(
	 */
	RMM_OFF_T(char) regex;
	apr_size_t regex_len;
	RMM_OFF_T(sp_per_content_type_t) similar_pages_per_content_type;
};

RMM_OFF_T_DECLARE(int);
struct similar_page_cache_s {
    const char* cache_root;
    apr_size_t cache_root_len;

    apr_global_mutex_t *fs_cache_lock;
    apr_size_t cache_bytes;     /* Size (in bytes) of shared memory cache */
#if APR_HAS_SHARED_MEMORY
    apr_shm_t *shm;
#endif
    apr_rmm_t *rmm;
    RMM_OFF_T(rmm_hash_t) similar_pages_per_host;
    const char *cache_file; /* filename for shm backing cache file */
    const char *lock_file; /* filename for shm lock mutex */
    RMM_OFF_T(int) lock_is_available; /* lock is available in all threads/subprocesses */
    apr_hash_t *similar_pages_regexs; /* compiled regular expressions for similar pages */
    RMM_OFF_T(rmm_hash_t) vary_headers_cache;
    int similar_pages_cache_initialized;
};

/**
 * Returns 1 when the lock is available in all threads/subprocesses and 0 otherwise
 */
static int is_lock_available(similar_page_cache_t *sp_cache)
{
	return *APR_RMM_ADDR_GET(int, sp_cache->rmm, sp_cache->lock_is_available);
}

/**
 * Duplicate a string value into the a memory segment allocated from the relocatable memory.
 * Returns: RMM_OFF_NULL on memory allocation error
 *          offset of duplicated string when all fine
 */
static RMM_OFF_T(char) rmm_strdup(apr_rmm_t *rmm, const char *value)
{
	size_t valuelen = strlen(value);
	RMM_OFF_T(char) rslt = apr_rmm_malloc(rmm, valuelen+1);
	if (rslt == RMM_OFF_NULL)
	{
		return RMM_OFF_NULL;
	}
	memcpy(APR_RMM_ADDR_GET(char, rmm, rslt), value, valuelen+1);
	return rslt;
}

static apr_status_t similar_page_cache_kill(void *data)
{
	similar_page_cache_t *sp_cache = data;

	sp_cache->similar_pages_cache_initialized = 0;
    if (sp_cache->rmm != NULL)
    {
    	apr_rmm_destroy(sp_cache->rmm);
    	sp_cache->rmm = NULL;
    }
#if APR_HAS_SHARED_MEMORY
    if (sp_cache->shm != NULL) {
        apr_status_t result = apr_shm_destroy(sp_cache->shm);
        sp_cache->shm = NULL;
        return result;
    }
#endif
    return APR_SUCCESS;
}

typedef struct  {
	int compiled;
	ap_regex_t *preg;
} compiled_regex_info_t;

static int fsp_regex_match(request_rec *r, const char *regex, const char *uri_key, similar_page_cache_t *sp_cache)
{
	if (sp_cache->similar_pages_regexs == NULL) {
		sp_cache->similar_pages_regexs = apr_hash_make(r->server->process->pool);
		if (sp_cache->similar_pages_regexs == NULL)
		{
			// Not enough memory to cache the regexs, so probably also not enough memory to
			// compile the regex.
			return 0;  // Return a mismatch
		}
	}
	compiled_regex_info_t *regex_info = (compiled_regex_info_t *)apr_hash_get(sp_cache->similar_pages_regexs, regex, APR_HASH_KEY_STRING);
	if (regex_info == NULL)
	{
		regex_info = apr_palloc(r->server->process->pool, sizeof(compiled_regex_info_t));
		if (regex_info == NULL)
		{
			ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r->server, "Could not allocate memory for regex_info");
			return 0; // Return a mismatch
		}
		regex_info->preg = apr_palloc(r->server->process->pool, sizeof(ap_regex_t));
		if (regex_info->preg == NULL)
		{
			ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r->server, "Could not allocate memory for regex_info->preg");
			return 0; // Return a mismatch
		}
		int rslt = ap_regcomp(regex_info->preg, regex, 0);
		if (rslt != 0)
		{
			ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r->server, "Could not compile regexp %s, return code: %d", regex, rslt);
			regex_info->compiled = 0;
		}
		else
		{
			regex_info->compiled = 1;
		}
		// Store the 'compiled' regex even when the compilation failed. This prevents the same warning from re-appearing. Otherwise, the
		// compilation will fail on each request for a page that might match this regex.
		apr_hash_set(sp_cache->similar_pages_regexs, regex, APR_HASH_KEY_STRING, regex_info);
	}
	if (regex_info->compiled)
	{
		return ap_regexec(regex_info->preg, uri_key, 0, NULL, AP_REG_ICASE) == 0;
	}
	return 0; // Compilation of regex has failed at least once. Return a mismatch
}

/*****************************************************************
 * Record of available info on a media type specified by the client
 * (we also use 'em for encodings and languages)
 * 
 *  - Taken from mod_negotation.c
 */
typedef struct accept_rec {
    char *name;                 /* MUST be lowercase */
    float quality;
    float level;
    char *charset;              /* for content-type only */
} accept_rec;

/*****************************************************************
 * parse quality value. atof(3) is not well-usable here, because it
 * depends on the locale (argh).
 *
 * However, RFC 2616 states:
 * 3.9 Quality Values
 *
 * [...] HTTP/1.1 applications MUST NOT generate more than three digits
 * after the decimal point. User configuration of these values SHOULD also
 * be limited in this fashion.
 *
 *     qvalue         = ( "0" [ "." 0*3DIGIT ] )
 *                    | ( "1" [ "." 0*3("0") ] )
 *
 * This is quite easy. If the supplied string doesn't match the above
 * definition (loosely), we simply return 1 (same as if there's no qvalue)
 *
 *  - Taken from mod_negotation.c
 */
static float atoq(const char *string)
{
    if (!string || !*string) {
        return  1.0f;
    }

    while (*string && apr_isspace(*string)) {
        ++string;
    }

    /* be tolerant and accept qvalues without leading zero
     * (also for backwards compat, where atof() was in use)
     */
    if (*string != '.' && *string++ != '0') {
        return 1.0f;
    }

    if (*string == '.') {
        /* better only one division later, than dealing with fscking
         * IEEE format 0.1 factors ...
         */
        int i = 0;

        if (*++string >= '0' && *string <= '9') {
            i += (*string - '0') * 100;

            if (*++string >= '0' && *string <= '9') {
                i += (*string - '0') * 10;

                if (*++string > '0' && *string <= '9') {
                    i += (*string - '0');
                }
            }
        }

        return (float)i / 1000.0f;
    }

    return 0.0f;
}

/*****************************************************************
 * Get a single mime type entry --- one media type and parameters;
 * enter the values we recognize into the argument accept_rec
 *
 *  - Taken from mod_negotation.c
 */
static const char *get_accept_entry(apr_pool_t *p, accept_rec *result,
                             const char *accept_line)
{
    result->quality = 1.0f;
    result->level = 0.0f;
    result->charset = "";

    /*
     * Note that this handles what I gather is the "old format",
     *
     *    Accept: text/html text/plain moo/zot
     *
     * without any compatibility kludges --- if the token after the
     * MIME type begins with a semicolon, we know we're looking at parms,
     * otherwise, we know we aren't.  (So why all the pissing and moaning
     * in the CERN server code?  I must be missing something).
     */

    result->name = ap_get_token(p, &accept_line, 0);
    ap_str_tolower(result->name);     /* You want case insensitive,
                                       * you'll *get* case insensitive.
                                       */

    /* KLUDGE!!! Default HTML to level 2.0 unless the browser
     * *explicitly* says something else.
     */

    if (!strcmp(result->name, "text/html") && (result->level == 0.0)) {
        result->level = 2.0f;
    }
    else if (!strcmp(result->name, INCLUDES_MAGIC_TYPE)) {
        result->level = 2.0f;
    }
    else if (!strcmp(result->name, INCLUDES_MAGIC_TYPE3)) {
        result->level = 3.0f;
    }

    while (*accept_line == ';') {
        /* Parameters ... */

        char *parm;
        char *cp;
        char *end;

        ++accept_line;
        parm = ap_get_token(p, &accept_line, 1);

        /* Look for 'var = value' --- and make sure the var is in lcase. */

        for (cp = parm; (*cp && !apr_isspace(*cp) && *cp != '='); ++cp) {
            *cp = apr_tolower(*cp);
        }

        if (!*cp) {
            continue;           /* No '='; just ignore it. */
        }

        *cp++ = '\0';           /* Delimit var */
        while (*cp && (apr_isspace(*cp) || *cp == '=')) {
            ++cp;
        }

        if (*cp == '"') {
            ++cp;
            for (end = cp;
                 (*end && *end != '\n' && *end != '\r' && *end != '\"');
                 end++);
        }
        else {
            for (end = cp; (*end && !apr_isspace(*end)); end++);
        }
        if (*end) {
            *end = '\0';        /* strip ending quote or return */
        }
        ap_str_tolower(cp);

        if (parm[0] == 'q'
            && (parm[1] == '\0' || (parm[1] == 's' && parm[2] == '\0'))) {
            result->quality = atoq(cp);
        }
        else if (parm[0] == 'l' && !strcmp(&parm[1], "evel")) {
            result->level = (float)atoi(cp);
        }
        else if (!strcmp(parm, "charset")) {
            result->charset = cp;
        }
    }

    if (*accept_line == ',') {
        ++accept_line;
    }

    return accept_line;
}


/*****************************************************************
 * Dealing with Accept... header lines ...
 * Accept, Accept-Charset, Accept-Language and Accept-Encoding
 * are handled by do_header_line() - they all have the same
 * basic structure of a list of items of the format
 *    name; q=N; charset=TEXT
 *
 * where charset is only valid in Accept.
 * 
 *  - Taken from mod_negotation.c
 */
static apr_array_header_t *parse_accept_line(apr_pool_t *p,
                                          const char *accept_line)
{
    apr_array_header_t *accept_recs;

    if (!accept_line) {
        return NULL;
    }

    accept_recs = apr_array_make(p, 40, sizeof(accept_rec));
    if (accept_recs == NULL)
    {
    	return NULL; // Nothing to allocate
    }
    while (*accept_line) {
        accept_rec *new = (accept_rec *) apr_array_push(accept_recs);
        accept_line = get_accept_entry(p, new, accept_line);
        if (!strcmp(new->name, "*/*"))
        {
        	apr_array_pop(accept_recs); // Discard this entry
        }
    }

    return accept_recs;
}


static int match_accept_type_vs_mime_type(const char *mime_type, const char *accept_type)
{
	while (*mime_type && *accept_type && *mime_type == *accept_type)
	{
		mime_type++;
		accept_type++;
	}
	return (*mime_type == 0 && *accept_type == 0) || (*accept_type == '*');
}


// TODO: Refine. Current logic is simplistic. It only checks the mime-type part of the content-type
//        header of the cached page (e.g. it ignores the charset) and furthermore, it ignores
//        the 'quality'/'level' indicates in the accept header. The function returns true
//        if the mime-type of the cached page matches at least one of the content-types indicated
//        in the accept header
//        Note that the foundation for more fine-grained logic has been laid. The accept-header
//        is parsed and broken down in all the constituting elements, using code copied from
//        module mod-negotation
static int fsp_accept_matches_content_type(similar_page_cache_t *sp_cache, 
		request_rec *r, RMM_OFF_T(char) content_type)
{
	apr_array_header_t *accepts = parse_accept_line(r->pool, apr_table_get(r->headers_in, ACCEPT_HEADER));
	const char *content_type_line = APR_RMM_ADDR_GET(char, sp_cache->rmm, content_type);
	
	if (accepts == NULL)
	{
		return 0; // Can't validate content type versus accept header
	}
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
			"Comparing content type line %s versus accept line %s", 
			content_type_line, apr_table_get(r->headers_in, ACCEPT_HEADER));

	// Only look at the mime-type (e.g. text/html) of the content-type line.
	// Discard any other parameters like the charset
	char *mime_type = ap_get_token(r->pool, &content_type_line, 0);
	ap_str_tolower(mime_type);
	
	accept_rec *accept_elts = (accept_rec *)accepts->elts;
	int cnt;
	for (cnt = 0; cnt != accepts->nelts; cnt++)
	{
		const char *accept_type = accept_elts[cnt].name;
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, 
				"Comparing mime type %s versus accept type %s",	mime_type, accept_type);
		if (match_accept_type_vs_mime_type(mime_type, accept_type))
		{
			return 1; // A good-enough match found. Use this page.
		}
	}
	return 0; // No match found.Skip this page
}

static void clear_rmm_field(apr_rmm_t *rmm, apr_rmm_off_t *offset_ptr)
{
	if (*offset_ptr != RMM_OFF_NULL) {
		apr_rmm_free(rmm, *offset_ptr);
		*offset_ptr = RMM_OFF_NULL;
	}
}

/*
 * Free all memory used by a cached_files_info_t structure
 * Be aware that this function might get called while the structure is not yet complete. E.g.
 * it gets called when an out-of-memory condition occurs during the construction
 */
static void free_cached_files_info(apr_rmm_t *rmm, sp_per_content_type_t *sp_per_ct_physical, RMM_OFF_T(cached_files_info_t) cached_file_info)
{
	cached_files_info_t *cfi_physical = APR_RMM_ADDR_GET(cached_files_info_t, rmm, cached_file_info);

	// Delete the entry from the hash table
	if (sp_per_ct_physical->cached_files_info_by_path != RMM_OFF_NULL && cfi_physical->basepath != RMM_OFF_NULL) {
		rmm_hash_set(rmm, sp_per_ct_physical->cached_files_info_by_path, cfi_physical->basepath, APR_HASH_KEY_STRING, RMM_OFF_NULL);
	}

	// Update the tail entry if this was the tail entry
	if (cached_file_info == sp_per_ct_physical->tail_file_info) {
		sp_per_ct_physical->tail_file_info = cfi_physical->prev;
	}
	
	// Remove the entry from the (double-linked) list
	if (cfi_physical->next != RMM_OFF_NULL) {
		APR_RMM_ADDR_GET(cached_files_info_t, rmm, cfi_physical->next)->prev = cfi_physical->prev;
	}
	if (cfi_physical->prev != RMM_OFF_NULL) {
		APR_RMM_ADDR_GET(cached_files_info_t, rmm, cfi_physical->prev)->next = cfi_physical->next;
	}
	else {
		sp_per_ct_physical->cached_files_info = cfi_physical->next;
	}
	
	clear_rmm_field(rmm, &cfi_physical->basepath);
	clear_rmm_field(rmm, &cfi_physical->uri);
	apr_rmm_free(rmm, cached_file_info);
}

/**
 * Verify if the cached file contains a vary header. If yes, then match the headers in the request with
 * the corresponding headers in the cached page.
 * Returns true if there is no vary header or if the vary headers match correctly
 * TODO: refine the logic to match the header values. According to the RFC, the comparison may
 * ignore white-space characters in the header values (accordingly to the BNF/syntax of that specific header...).
 * At the moment, the header values are compared literally, so in theory, this comparison is too restrictive.
 */
static int match_vary_headers(similar_page_cache_t *sp_cache, request_rec *r, RMM_OFF_T(vary_headers_t)vary_headers)
{
	if (vary_headers == RMM_OFF_NULL) {
		return 1; // The cached page did not specify vary header, so the new request matches by definition
	}
	apr_rmm_t *rmm = sp_cache->rmm;
	while (vary_headers != RMM_OFF_NULL) {
		vary_headers_t *vary_headers_physical = APR_RMM_ADDR_GET(vary_headers_t, rmm, vary_headers);
		const char *headername =  APR_RMM_ADDR_GET(char, rmm, vary_headers_physical->name);
	    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "Comparing vary header %s", headername);
		if (strcmp(headername, "*") == 0) {
			// The special 'header name' * signifies that the server always varies stuff in an undisclosed manner.
			// The similar page matching will probably yield bad results. Ignore this page.
			return 0; 
		}
		const char *cached_headervalue = (vary_headers_physical->value == RMM_OFF_NULL) ? 
				NULL : APR_RMM_ADDR_GET(char, rmm, vary_headers_physical->value);
		const char *req_headervalue = apr_table_get(r->headers_in, headername);
	    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "Cached value: %s, request value: %s", 
	    		cached_headervalue,	req_headervalue);
		if (req_headervalue == NULL && cached_headervalue != NULL) {
			return 0; // Expecting a value but did not get one
		}
		if (req_headervalue != NULL && cached_headervalue == NULL) {
			return 0; // Expecting empty header but got a value
		}
		if (req_headervalue != NULL && strcmp(req_headervalue, cached_headervalue) != 0) {
			return 0; // The new and old header value differ
		}
		vary_headers = vary_headers_physical->next;
	}
	return 1; // All vary headers are the same
}

/**
 * Try to open the file indicated in cfi_physical structure
 * Returns APR_SUCCESS if the file was successfully opened, in which case the dobj structure
 * will have been properly updated.
 * Returns other error codes in case of problems.
 * WARNING: When the file no longer exists, the structure cfi_physical will be deleted from memory and
 * from the linked-list. It means that the caller should evaluate cfi_physical->next *before* invoking
 * this function.
 */ 
static apr_status_t open_cached_file(disk_cache_object_t *dobj, request_rec *r, 
		similar_page_cache_t *sp_cache,	sp_per_content_type_t *sp_per_ct_physical, 
		RMM_OFF_T(cached_files_info_t) cached_file_info)
{
	apr_rmm_t *rmm = sp_cache->rmm;
	cached_files_info_t *cfi_physical = APR_RMM_ADDR_GET(cached_files_info_t, sp_cache->rmm, cached_file_info);
	const char *fullpath = apr_pstrcat(r->pool, sp_cache->cache_root, "/", 
			APR_RMM_ADDR_GET(char, rmm, cfi_physical->basepath), CACHE_DATA_SUFFIX, NULL);
    int flags = APR_READ|APR_BINARY;
#ifdef APR_SENDFILE_ENABLED
    flags |= APR_SENDFILE_ENABLED;
#endif
    apr_status_t rc = apr_file_open(&dobj->fd, fullpath, flags, 0, r->pool);
	if (rc == APR_SUCCESS)
	{
		// Successfully opened the file. Try to obtain the file-size and return the completed dobj
		// to the caller
		apr_finfo_t finfo;
	    rc = apr_file_info_get(&finfo, APR_FINFO_SIZE, dobj->fd);
	    if (rc == APR_SUCCESS) {
	        dobj->file_size = finfo.size;
		    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server,
		    		"Basing CRCSYNC/delta-http for requested URL on cached page for URL %s of size %" APR_SIZE_T_FMT,
		    		APR_RMM_ADDR_GET(char, sp_cache->rmm, cfi_physical->uri), dobj->file_size);
		    return APR_SUCCESS;
	    }
    	// Could not obtain file info for a mysterious reason. Skip this file.
    	apr_file_close(dobj->fd);
	}
	else
	{
		// Apparently the cached file is no longer there. Maybe it got cleaned by htcacheclean?
		if (is_lock_available(sp_cache)) {
			// Remove the entry. But only if this process could obtain the semaphore...
			free_cached_files_info(rmm, sp_per_ct_physical, cached_file_info);
		}
	}
	return rc; // Could not open file or obtain file-info for whatever reason.
}

/**
 * Critical section of the code to find similar pages. While this code is in progress, no updates to the data
 * structures may happen by other threads/processes, like by function 'update_or_add_similar_page(...), which is invoked
 * when a new file has been saved to the disk cache.
 * 
 * Please note that this function itself can update the 'free-pages' list if the code discovers that the data
 * structure is referencing a file that no longer exists. Apart from that update-block, the code is fully re-entrant.
 * With other words: multiple requests can enter this code concurrently, as long as they don't update the 'free-pages'
 * list and as long as it does not happen concurrently with the 'update_or_add_similar_page(...) function
 * 
 * At the moment, the code block that updates the 'free-pages' list checks if a lock could be obtained. If no lock could
 * be obtained, it does not update the list. It only updates the list if a lock could be obtained.
 * 
 * The locking is currently rather coarse grained: when locks are available, the (global mutex) makes sure that the access
 * to this function and to the 'update_or_add_similar_page(...) function is exclusive. On the other hand, when the
 * global mutex could not be initialized and as such is not available, the 'update_or_add_similar_page(...) function
 * is disabled and only the 'find-similar-page' function works, for data that got loaded during the server startup.
 * 
 * In order to increase the scalability, a more fine-grained locking could be implemented by carefully assessing which
 * parts of the 'update_or_add_similar_page(...) function conflict with data structures used by this 'find_similar_page'
 * function and then adding the appropriate locks where required.
 */
static apr_status_t find_similar_page_cs(disk_cache_object_t *dobj, request_rec *r, similar_page_cache_t *sp_cache, const char *host)
{
	apr_rmm_t *rmm = sp_cache->rmm;
	RMM_OFF_T(sp_per_regex_t) sp_per_regex = rmm_hash_get(rmm, sp_cache->similar_pages_per_host, host, APR_HASH_KEY_STRING);
	while (sp_per_regex != RMM_OFF_NULL)
	{
		sp_per_regex_t *sp_per_regex_physical = APR_RMM_ADDR_GET(sp_per_regex_t, rmm, sp_per_regex);
		if (fsp_regex_match(r, APR_RMM_ADDR_GET(char, rmm, sp_per_regex_physical->regex), r->unparsed_uri, sp_cache))
		{
			// Found the largest matching regex. Find a group of pages with an appropriate content type
			RMM_OFF_T(sp_per_content_type_t) sp_per_ct = sp_per_regex_physical->similar_pages_per_content_type;
			while (sp_per_ct != RMM_OFF_NULL)
			{
				sp_per_content_type_t *sp_per_ct_physical = APR_RMM_ADDR_GET(sp_per_content_type_t, rmm, sp_per_ct);
				if (fsp_accept_matches_content_type(sp_cache, r, sp_per_ct_physical->content_type))
				{
					// Found list of pages with appropriate content type for the matching regex
					// Now try to open a page associated with this regex and content type
					RMM_OFF_T(cached_files_info_t) cached_file_info = sp_per_ct_physical->cached_files_info;
					while (cached_file_info != RMM_OFF_NULL)
					{
						cached_files_info_t *cfi_physical = APR_RMM_ADDR_GET(cached_files_info_t, sp_cache->rmm, cached_file_info);
						RMM_OFF_T(cached_files_info_t) next_cfi = cfi_physical->next; 
						if (match_vary_headers(sp_cache, r, cfi_physical->vary_headers)) {
							if (open_cached_file(dobj, r, sp_cache, sp_per_ct_physical, cached_file_info) == APR_SUCCESS) {
								return APR_SUCCESS; // File successfully opened. Done.
							}
						}
						cached_file_info = next_cfi;
					} // while (cached_file_info != RMM_OFF_NULL)
				} // if (find_similar_page_accept_matches_content_type(sp_cache, r, sp_per_ct_physical->content_type))
				sp_per_ct = sp_per_ct_physical->next;
			} // while (sp_per_ct != RMM_OFF_NULL)
		} // if (find_similar_page_regex_match(r, APR_RMM_ADDR_GET(char, rmm, sp_per_regex_physical->regex), r->unparsed_uri, sp_cache))
		sp_per_regex = sp_per_regex_physical->next;
	} // while (sp_per_regex != RMM_OFF_NULL)
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "Could not find a similar page for the requesed URL");
	return DECLINED;
}

/**
 * Find a page in the cache for an URL that is similar to the requested URL and that can
 * fullfill at least one of the expected mime-types indicated in the "Accept" header
 * This page can then be used by the CRCCache as basis for the CRCSYNC/Delta-http encoding.
 */
apr_status_t find_similar_page(disk_cache_object_t *dobj, request_rec *r, similar_page_cache_t *sp_cache)
{
	if (!sp_cache->similar_pages_cache_initialized)
	{
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "Similar page cache is not initialized");
		return DECLINED;
	}
	const char *host = apr_table_get(r->headers_in, HOST_HEADER);
	if (!host) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "Can't find host header in the request");
		return DECLINED;
	}
	
    apr_status_t findrslt;
    if (is_lock_available(sp_cache)) {
    	apr_status_t lockrslt = apr_global_mutex_lock(sp_cache->fs_cache_lock);
	    if (lockrslt != APR_SUCCESS)
	    {
			ap_log_error(APLOG_MARK, APLOG_WARNING, lockrslt, r->server, "Can't obtain the lock");
			return lockrslt;
	    }
	    findrslt = find_similar_page_cs(dobj, r, sp_cache, host);
    	lockrslt = apr_global_mutex_unlock(sp_cache->fs_cache_lock);
	    if (lockrslt != APR_SUCCESS)
	    {
			ap_log_error(APLOG_MARK, APLOG_WARNING, lockrslt, r->server, "Can't release the lock");
	    }
    }
    else {
    	findrslt = find_similar_page_cs(dobj, r, sp_cache, host);
    }
    return findrslt;
}

/**
 * Create info about a cached file
 * Returns RMM_OFF_NULL when a memory allocation error has occured.
 */
static RMM_OFF_T(cached_files_info_t) create_cached_files_info(apr_rmm_t *rmm,
		const char *basepath, const char *uri, RMM_OFF_T(vary_headers_t) vary_headers)
{
	RMM_OFF_T(cached_files_info_t) cached_files_info = apr_rmm_calloc(rmm, sizeof(cached_files_info_t));
	if (cached_files_info == RMM_OFF_NULL)
	{
		return cached_files_info;
	}
	cached_files_info_t *cfi_physical = APR_RMM_ADDR_GET(cached_files_info_t, rmm, cached_files_info);
	cfi_physical->basepath = rmm_strdup(rmm, basepath);
	cfi_physical->uri = rmm_strdup(rmm, uri);
	if (cfi_physical->basepath == RMM_OFF_NULL || cfi_physical->uri == RMM_OFF_NULL)
	{
		clear_rmm_field(rmm, &cfi_physical->basepath);
		clear_rmm_field(rmm, &cfi_physical->uri);
		apr_rmm_free(rmm, cached_files_info);
		return RMM_OFF_NULL;
	}
	cfi_physical->prev = RMM_OFF_NULL;
	cfi_physical->next = RMM_OFF_NULL;
	cfi_physical->vary_headers = vary_headers;
	
	return cached_files_info;
}

/*
 * Create a 'similar pages per content type' structure for the current basepath, uri and content_type
 * Returns NULL when a memory allocation error has occured
 */
static RMM_OFF_T(sp_per_content_type_t) create_sp_per_content_type(apr_rmm_t *rmm, 
		const char *basepath, const char *uri, const char *content_type, RMM_OFF_T(vary_headers_t)vary_headers)
{
	RMM_OFF_T(sp_per_content_type_t) sp_per_ct = apr_rmm_calloc(rmm, sizeof(sp_per_content_type_t));
	if (sp_per_ct == RMM_OFF_NULL)
	{
		return RMM_OFF_NULL; // Memory allocation failure!
	}
	sp_per_content_type_t *sp_per_ct_physical = APR_RMM_ADDR_GET(sp_per_content_type_t, rmm, sp_per_ct);
	sp_per_ct_physical->next = RMM_OFF_NULL;
	sp_per_ct_physical->content_type = rmm_strdup(rmm, content_type);
	if (sp_per_ct_physical->content_type == RMM_OFF_NULL)
	{
		apr_rmm_free(rmm, sp_per_ct);
		return RMM_OFF_NULL;
	}

	sp_per_ct_physical->cached_files_info = create_cached_files_info(rmm, basepath, uri, vary_headers);
	if (sp_per_ct_physical->cached_files_info == RMM_OFF_NULL)
	{
		apr_rmm_free(rmm, sp_per_ct_physical->content_type);
		apr_rmm_free(rmm, sp_per_ct);
		return RMM_OFF_NULL;
	}
	sp_per_ct_physical->tail_file_info = sp_per_ct_physical->cached_files_info;

	sp_per_ct_physical->cached_files_info_by_path = rmm_hash_make(rmm);
	if (sp_per_ct_physical->cached_files_info_by_path == RMM_OFF_NULL)
	{
		free_cached_files_info(rmm, sp_per_ct_physical, sp_per_ct_physical->cached_files_info);
		apr_rmm_free(rmm, sp_per_ct_physical->content_type);
		apr_rmm_free(rmm, sp_per_ct);
		return RMM_OFF_NULL;
	}
	// FIXME: rmm_hash_set should be able to return an out-of-memory condition when appropriate so that *this* function can properly handle
	//        the error condition...
	rmm_hash_set(rmm, sp_per_ct_physical->cached_files_info_by_path, 
			APR_RMM_ADDR_GET(cached_files_info_t, rmm, sp_per_ct_physical->cached_files_info)->basepath, APR_HASH_KEY_STRING,
			sp_per_ct_physical->cached_files_info);
	
	return sp_per_ct;
}


/*
 * Create a 'similar pages per regex' structure for the current regex, basepath, uri and content_type
 * Returns NULL when a memory allocation error has occured
 */
static RMM_OFF_T(sp_per_regex_t) create_sp_per_regex(apr_rmm_t *rmm, 
		const char *regex, const char *basepath, const char *uri, const char *content_type, RMM_OFF_T(vary_headers_t)vary_headers)
{
	RMM_OFF_T(sp_per_regex_t) sp_per_regex = apr_rmm_calloc(rmm, sizeof(sp_per_regex_t));
	if (sp_per_regex == RMM_OFF_NULL)
	{
		return RMM_OFF_NULL; // Memory allocation failure!
	}
	sp_per_regex_t *sp_per_regex_physical = APR_RMM_ADDR_GET(sp_per_regex_t, rmm, sp_per_regex);
	sp_per_regex_physical->next = RMM_OFF_NULL;
	sp_per_regex_physical->regex_len = strlen(regex);
	sp_per_regex_physical->regex = rmm_strdup(rmm, regex);
	if (sp_per_regex_physical->regex == RMM_OFF_NULL)
	{
		apr_rmm_free(rmm, sp_per_regex);
		return RMM_OFF_NULL;
	}
	sp_per_regex_physical->similar_pages_per_content_type = create_sp_per_content_type(rmm, basepath, uri, content_type, vary_headers);
	if (sp_per_regex_physical->similar_pages_per_content_type == RMM_OFF_NULL)
	{
		apr_rmm_free(rmm, sp_per_regex_physical->regex);
		apr_rmm_free(rmm, sp_per_regex);
		return RMM_OFF_NULL;
	}
	return sp_per_regex;
}

/**
 * Add a new cached file to the list of cached files for the current content type or update the entry if it
 * is already present
 * Returns: 1 on memory allocation error
 *          0 when all fine
 */
static int add_cached_file_to_content_type(similar_page_cache_t *sp_cache, sp_per_content_type_t *sp_per_ct_physical,
		const char *basepath, const char *uri, RMM_OFF_T(vary_headers_t) vary_headers)
{
	apr_rmm_t *rmm = sp_cache->rmm;
	RMM_OFF_T(cached_files_info_t) cached_file_info;
	cached_files_info_t *cfi_physical;

	// Make the cached_file_info record
	cached_file_info = create_cached_files_info(rmm, basepath, uri, vary_headers);
	if (cached_file_info == RMM_OFF_NULL) {
		return 1; // Could not allocate memory. Can't store the info.
	}
	cfi_physical = APR_RMM_ADDR_GET(cached_files_info_t, rmm, cached_file_info);
	
	// Insert the new entry at the head of the list
	cfi_physical->next = sp_per_ct_physical->cached_files_info;
	if (cfi_physical->next != RMM_OFF_NULL) {
		// There was already something in the list. Make the old head entry point back to 
		// this new head entry
		APR_RMM_ADDR_GET(cached_files_info_t, rmm, cfi_physical->next)->prev = cached_file_info;
	}
	else {
		// The list was empty. This new entry is now by definition a tail entry
		sp_per_ct_physical->tail_file_info = cached_file_info;
	}
	sp_per_ct_physical->cached_files_info = cached_file_info;

	// Remove old version of the page (if it exists) from the list
	RMM_OFF_T(cached_files_info_t) old_cached_file = rmm_hash_get(rmm, 
			sp_per_ct_physical->cached_files_info_by_path, 
			basepath, APR_HASH_KEY_STRING);
	if (old_cached_file != RMM_OFF_NULL) {
		free_cached_files_info(rmm, sp_per_ct_physical, old_cached_file);
	}

	// Add the new version to the reverse index
	// FIXME: deal with failure of rmm_hash_set (once rmm_hash_set has been fixed to return an out-of-memory condition
	//        when appropriate
	rmm_hash_set(rmm, sp_per_ct_physical->cached_files_info_by_path, cfi_physical->basepath, APR_HASH_KEY_STRING, cached_file_info);
	
	if (rmm_hash_count(rmm, sp_per_ct_physical->cached_files_info_by_path) > 40 /* TODO: make this threshold configurable */)
	{
		// Only maintain info about the (40) most recently cached pages per host per regex per content-type
		// The chance that all of them point to meanwhile deleted/obsolete files is very small, considering
		// the fact that each freshly cached file gets inserted at the head of the list, so it does not make
		// much sense to fill-up the memory with a longer list.
		free_cached_files_info(rmm, sp_per_ct_physical, sp_per_ct_physical->tail_file_info);
	}
		
	return 0; // Cached file info successfully added
}

/**
 * Add a new cached file to the list of cached files for the current regular expression or update the page if it
 * is already present
 * Returns: 1 on memory allocation error
 *          0 when all fine
 */
static int add_cached_file_to_regex(similar_page_cache_t *sp_cache, sp_per_regex_t *sp_per_regex_physical, 
		const char *basepath, const char *uri, const char *content_type, RMM_OFF_T(vary_headers_t)vary_headers)
{
	RMM_OFF_T(sp_per_content_type_t) sp_per_ct;
	apr_rmm_t *rmm = sp_cache->rmm;
	sp_per_ct = sp_per_regex_physical->similar_pages_per_content_type;
	while (sp_per_ct != RMM_OFF_NULL) {
		sp_per_content_type_t *sp_per_ct_physical = APR_RMM_ADDR_GET(sp_per_content_type_t, rmm, sp_per_ct);
		if (!strcmp(content_type, APR_RMM_ADDR_GET(char, rmm, sp_per_ct_physical->content_type))) {
			// Found the correct entry. Add or update the page here
			return add_cached_file_to_content_type(sp_cache, sp_per_ct_physical, basepath, uri, vary_headers);
		}
		sp_per_ct = sp_per_ct_physical->next;
	}
	// There is nothing yet for this content type. Add it to the list
	sp_per_ct = create_sp_per_content_type(rmm, basepath, uri, content_type, vary_headers);
	if (sp_per_ct == RMM_OFF_NULL) {
		return 1;
	}
	// Add it to the head of the list
	APR_RMM_ADDR_GET(sp_per_content_type_t, rmm, sp_per_ct)->next = sp_per_regex_physical->similar_pages_per_content_type;
	sp_per_regex_physical->similar_pages_per_content_type = sp_per_ct;
	return 0;
}


/**
 * Add a new page to the list of similar pages for current host or update an existing page
 * Returns: 1 on memory allocation error
 *          0 when all fine
 */
static int add_similar_pages_info(similar_page_cache_t *sp_cache, RMM_OFF_T(sp_per_regex_t) *sp_per_regex_p, 
		const char *regex,	const char *basepath, const char *uri, const char *content_type, RMM_OFF_T(vary_headers_t)vary_headers)
{
	apr_rmm_t *rmm = sp_cache->rmm;
	size_t regex_len = strlen(regex);
	while (1)
	{
		RMM_OFF_T(sp_per_regex_t) curr_sp_per_regex = *sp_per_regex_p;
		sp_per_regex_t *sp_per_regex_physical = APR_RMM_ADDR_GET(sp_per_regex_t, rmm, curr_sp_per_regex);
		if (regex_len == sp_per_regex_physical->regex_len && strcmp(regex, APR_RMM_ADDR_GET(char, rmm, sp_per_regex_physical->regex))==0)
		{
			// Found a perfect match. Add or update the page to the head of the current pages list
			return add_cached_file_to_regex(sp_cache, sp_per_regex_physical, basepath, uri, content_type, vary_headers);
		}
		else
		{
			if (regex_len > sp_per_regex_physical->regex_len )
			{
				// No matching regex found that is longer then the current regex.
				// Insert the new entry here in the list, so that the list remains sorted in descending order on regex_len
				RMM_OFF_T(sp_per_regex_t) new_sp_per_regex =  create_sp_per_regex(rmm, regex, basepath, uri, content_type, vary_headers);
				if (new_sp_per_regex == RMM_OFF_NULL)
				{
					return 1; // Out of memory condition occurred
				}
				APR_RMM_ADDR_GET(sp_per_regex_t, rmm, new_sp_per_regex)->next = curr_sp_per_regex;
				*sp_per_regex_p = new_sp_per_regex;
				return 0; // New page succesfully inserted
			}
			else
			{
				if (sp_per_regex_physical->next == RMM_OFF_NULL)
				{
					// Reached tail of the list. The new regex is shorter then any of the existing ones
					// Insert new entry to the end of the list
					RMM_OFF_T(sp_per_regex_t) new_sp_per_regex =  create_sp_per_regex(rmm, regex, basepath, uri, content_type, vary_headers);
					if (new_sp_per_regex == RMM_OFF_NULL)
					{
						return 1; // Out of memory condition occurred
					}
					sp_per_regex_physical->next = new_sp_per_regex;
					return 0; // New page succesfully inserted
				}
				// Evaluate the next entry
				sp_per_regex_p = &sp_per_regex_physical->next;
			}
		}
	}
	return 0;
}

/**
 * Add (or update) a cached page to the 'similar pages' cache
 * Returns: 1 on memory allocation error
 *          0 when all fine
 * The invoking function may want to log a warning in case of memory 
 * allocation error so that the system administrator can tune the cache
 * parameters if this happens too often
 */
static int add_cached_page(similar_page_cache_t *sp_cache, const char *regex, const char *host, 
		const char *basepath, const char *uri, const char *content_type, RMM_OFF_T(vary_headers_t)vary_headers)
{
	apr_rmm_t *rmm = sp_cache->rmm;
	RMM_OFF_T(sp_per_regex_t) sp_per_regex = rmm_hash_get(rmm, sp_cache->similar_pages_per_host, host, APR_HASH_KEY_STRING);
	if (sp_per_regex == RMM_OFF_NULL)
	{
		// There is no info yet for the current host. Make the first entry.
		RMM_OFF_T(char) host_offset = rmm_strdup(rmm, host);
		if (host_offset == RMM_OFF_NULL) {
			return 1; // Could not allocate memory
		}
		sp_per_regex = create_sp_per_regex(rmm, regex, basepath, uri, content_type, vary_headers);
		if (sp_per_regex == RMM_OFF_NULL)	{
			apr_rmm_free(rmm, host_offset);
			return 1; // Could not allocate memory!
		}
		rmm_hash_set(rmm, sp_cache->similar_pages_per_host, host_offset, APR_HASH_KEY_STRING, sp_per_regex);
		return 0; // All fine
	}
	else
	{
		// The current entry already contains similar pages info. Add new or updated page to the list
		int rslt = add_similar_pages_info(sp_cache, &sp_per_regex, regex, basepath, uri, content_type, vary_headers);
		return rslt;
	}
}

/**
 * Allocate and initialze an empty similar page cache
 */
static apr_status_t similar_page_cache_init(apr_pool_t *pool, server_rec *s, similar_page_cache_t *sp_cache)
{
#if APR_HAS_SHARED_MEMORY
    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s, "APR supports shared memory"); 
    apr_status_t result;
    apr_size_t requested_size;
    apr_size_t retrieved_size;

    if (sp_cache->cache_file) {
        /* Remove any existing shm segment with this name. */
        apr_shm_remove(sp_cache->cache_file, pool);
    }

    requested_size = APR_ALIGN_DEFAULT(sp_cache->cache_bytes);
    result = apr_shm_create(&sp_cache->shm, requested_size, sp_cache->cache_file, pool);
    if (result != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, result, s, 
        		"Unable to obtain %" APR_SIZE_T_FMT " bytes shared memory", requested_size); 
        return result;
    }

    /* Determine the usable size of the shm segment. */
    retrieved_size = apr_shm_size_get(sp_cache->shm);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s, 
    		"Requested %" APR_SIZE_T_FMT " bytes shared memory, retrieved %" APR_SIZE_T_FMT " bytes",
    		requested_size, retrieved_size); 

    /* This will create a rmm "handler" to get into the shared memory area */
    result = apr_rmm_init(&sp_cache->rmm, NULL,
                          apr_shm_baseaddr_get(sp_cache->shm), retrieved_size,
                          pool);
    if (result != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, result, s, "Unable to initialize rmm handler for (shared) memory"); 
        return result;
    }
#else
    void *local_memory = apr_palloc(pool, sp_cache->cache_bytes);
    if (local_memory == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, result, s, 
        		"Unable to obtain %" APR_SIZE_T_FMT " bytes of memory", requested_size); 
    }

    /* This will create a rmm "handler" to get into the memory area */
    result = apr_rmm_init(&sp_cache->rmm, NULL,
                          local_memory, sp_cache->cache_bytes,
                          pool);
    if (result != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, result, s, "Unable to initialize rmm handler for (shared) memory"); 
        return result;
    }
    
#endif

    apr_pool_cleanup_register(pool, sp_cache, similar_page_cache_kill, apr_pool_cleanup_null);

    sp_cache->similar_pages_per_host = rmm_hash_make(sp_cache->rmm);
    if (sp_cache->similar_pages_per_host == RMM_OFF_NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s, "Unable to allocate memory for similar pages info cache"); 
    	return APR_EGENERAL;
    }
    
    sp_cache->lock_is_available = apr_rmm_calloc(sp_cache->rmm, sizeof(int));
    if (sp_cache->lock_is_available == RMM_OFF_NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s, "Unable to allocate memory for similar pages info cache"); 
    	return APR_EGENERAL;
    }
    
    sp_cache->vary_headers_cache = rmm_hash_make(sp_cache->rmm);
    if (sp_cache->vary_headers_cache == RMM_OFF_NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EGENERAL, s, "Unable to allocate memory for similar pages info cache"); 
    	return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

static apr_status_t make_vary_headers(apr_pool_t *p, server_rec *s, similar_page_cache_t *sp_cache, 
		apr_table_t *req_hdrs, apr_table_t *resp_hdrs, RMM_OFF_T(vary_headers_t) *vary_headers_p)
{
	*vary_headers_p = RMM_OFF_NULL;
	apr_rmm_t *rmm = sp_cache->rmm;
	const char *vary = apr_table_get(resp_hdrs, VARY_HEADER);
	if (vary != NULL)
	{
		char *headername;
		char *vary_cache_key = "";
		char *separator="";
		while ((headername = ap_get_token(p, &vary, 1)) != NULL && strlen(headername) != 0)
		{
			// Ignore 'Accept-Encoding' vary header; we transform anything anyway to identity coding before storing it in the cache
			// so it does not matter what the server has done with respect to the content-encoding.
			if (strcmp(headername, ACCEPT_ENCODING_HEADER) != 0) {
				vary_cache_key = apr_pstrcat(p, vary_cache_key, separator, headername, "=", apr_table_get(req_hdrs, headername), NULL);
				separator=", ";
			}
		}
		if (*vary_cache_key == 0) {
			// Apparently the content only varies based on the 'Accept-Encoding', which we ignore.
			return APR_SUCCESS;
		}
		RMM_OFF_T(vary_headers_t) vary_headers = rmm_hash_get(sp_cache->rmm, sp_cache->vary_headers_cache, vary_cache_key, APR_HASH_KEY_STRING);
		ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s, "Vary cache key: %s, found in cache?: %s", 
				vary_cache_key,	(vary_headers == RMM_OFF_NULL) ? "No" : "Yes");
		if (vary_headers == RMM_OFF_NULL) {
			// This vary headers combination is not yet cached. Make the structure and cache it
			vary = apr_table_get(resp_hdrs, VARY_HEADER); // Get again the vary header
			while ((headername = ap_get_token(p, &vary, 1)) != NULL && strlen(headername) != 0)
			{
				// Ignore 'Accept-Encoding' vary header; we transform anything anyway to identity coding before storing it in the cache
				// so it does not matter what the server has done with respect to the content-encoding.
				if (strcmp(headername, ACCEPT_ENCODING_HEADER) != 0) {
					// Allocate the new entry
					RMM_OFF_T(vary_headers_t) new_vary_header = apr_rmm_malloc(rmm, sizeof(vary_headers_t));
					if (new_vary_header == RMM_OFF_NULL) {
						return 1; // Could not allocate memory
					}
					vary_headers_t *new_vh_physical = APR_RMM_ADDR_GET(vary_headers_t, rmm, new_vary_header);
	
					// Put the new vary header at the head of the list of entries
					new_vh_physical->next = vary_headers;
					vary_headers = new_vary_header;
					
					if ((new_vh_physical->name = rmm_strdup(rmm, headername)) == RMM_OFF_NULL) {
						return 1;
					}
	
					new_vh_physical->value = RMM_OFF_NULL;
					const char *value = apr_table_get(req_hdrs, headername);
					if (value != NULL) 
					{
						if ((new_vh_physical->value = rmm_strdup(rmm, value)) == RMM_OFF_NULL) {
							return 1;
						}
					}
				}
			}
			rmm_hash_set(sp_cache->rmm, sp_cache->vary_headers_cache, rmm_strdup(rmm, vary_cache_key), APR_HASH_KEY_STRING, vary_headers);

		}
		*vary_headers_p = vary_headers;
	}
	return APR_SUCCESS;
}

/**
 * Load the info from the file-cache into the 'find similar page' cache
 */
static apr_status_t similar_page_cache_load(apr_pool_t *ptemp, server_rec *s, const char *abs_dirname, const char *rel_dirname, similar_page_cache_t *sp_cache)
{
	apr_status_t result;
	apr_dir_t *dirinfo; // structure for referencing directories
	apr_finfo_t fileinfo; // file information structure

	// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s, "Opening directory %s", abs_dirname);
	result = apr_dir_open(&dirinfo, abs_dirname, ptemp);
	// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s, "Result: %d", result);
	if (result != APR_SUCCESS)
	{
		ap_log_error(APLOG_MARK, APLOG_WARNING, result, s, "Unable to open directory %s", abs_dirname);
		return result;
	}
	while (apr_dir_read(&fileinfo, 0, dirinfo) == APR_SUCCESS)
	{
		if (!strcmp(fileinfo.name, ".") || !strcmp(fileinfo.name, ".."))
		{
			// Do not recursively go into current or parent directory!
			continue;
		}
		if (fileinfo.filetype == APR_DIR)
		{
			const char *sub_abs_dirname = apr_pstrcat(ptemp, abs_dirname, "/", fileinfo.name, NULL);
			const char *sub_rel_dirname =	(*rel_dirname == 0) ? apr_pstrdup(ptemp, fileinfo.name) : 
					apr_pstrcat(ptemp, rel_dirname, "/", fileinfo.name, NULL);
			if (similar_page_cache_load(ptemp, s, sub_abs_dirname, sub_rel_dirname, sp_cache) != APR_SUCCESS)
			{
				continue; // skip this sub directory and process the next one
			}
		}
		else if (fileinfo.filetype == APR_REG)
		{
			// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s, "About to open file: %s", fileinfo.name);
			if (strstr(fileinfo.name, CACHE_HEADER_SUFFIX) != NULL)
			{
				// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s, "Its a header file");
				// Build the key (basepath) for the cache. 
				// It consists of the relative path name exluding the .header extension
				char *basepath = apr_pstrdup(ptemp, fileinfo.name);
				*strstr(basepath, CACHE_HEADER_SUFFIX)=0;
				basepath = apr_pstrcat(ptemp, rel_dirname, "/", basepath, NULL);
				// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s, "Basepath: %s", basepath);
				
				char *full_filepath = apr_pstrcat(ptemp, abs_dirname, "/", fileinfo.name, NULL);
				// ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s, "Full_filepath: %s", full_filepath);
				
				apr_file_t *fd;
				result = apr_file_open(&fd, full_filepath, APR_READ|APR_BINARY|APR_BUFFERED, 0, ptemp);
				if (result != APR_SUCCESS)
				{
					ap_log_error(APLOG_MARK, APLOG_WARNING, result, s, "Failed to open file %s", full_filepath);
					continue; // Skip this file
				}
				
				apr_uint32_t format;
				apr_size_t len;

				/* Read and evaluate the format from the cache file */
			    len = sizeof(format);
			    apr_file_read_full(fd, &format, len, &len);
			    if (format == VARY_FORMAT_VERSION) {
			    	// TODO: Smartly handle "vary" header files. But skip them for the time being.
			    	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s, "Skipping vary header file %s", full_filepath);
					apr_file_close(fd);
					continue; // Skip this file
			    }
			    if (format != DISK_FORMAT_VERSION) {
			    	ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, s,
			    			"File %s has a version mismatch. File had version %d, but expected version is %d",
			    			full_filepath, format, DISK_FORMAT_VERSION);
					apr_file_close(fd);
					continue; // Skip this file
			    }
			    // Format OK, rewind to file begin
		    	apr_off_t offset = 0;
		    	apr_file_seek(fd, APR_SET, &offset);

		    	// Read metadata from file
		    	cache_object_t *obj = apr_pcalloc(ptemp, sizeof(cache_object_t));;
		    	disk_cache_object_t *dobj = apr_pcalloc(ptemp, sizeof(disk_cache_object_t));;
		    	cache_info_t *cache_info = &(obj->info);
		    	result = file_cache_recall_mydata(ptemp, fd, cache_info, dobj, 0);
		    	if (result != APR_SUCCESS)
		    	{
		    		ap_log_error(APLOG_MARK, APLOG_WARNING, result, s, 
		    				"Problem encountered reading meta data from %s", full_filepath);
					apr_file_close(fd);
					continue; // Skip this file
		    	}
		    	
		    	// Read request and response headers
				apr_table_t *req_hdrs = apr_table_make(ptemp, 20);
				apr_table_t *resp_hdrs = apr_table_make(ptemp, 20);
				result = read_table(s, resp_hdrs, fd);
				if (result != APR_SUCCESS)
				{
					ap_log_error(APLOG_MARK, APLOG_WARNING, result, s, "Failed to read response headers from file %s", full_filepath);
					apr_file_close(fd);
					continue; // Skip this file
				}
				result = read_table(s, req_hdrs, fd);
				apr_file_close(fd);
				if (result != APR_SUCCESS)
				{
					ap_log_error(APLOG_MARK, APLOG_WARNING, result, s, "Failed to read request headers from file %s", full_filepath);
					continue; // Skip this file
				}
				
				// Add file to 'similar pages' cache if host, crcsync_similar and content_type headers are present
				const char *hostname = apr_table_get(req_hdrs, HOST_HEADER);
				const char *crcsync_similar = apr_table_get(resp_hdrs, CRCSYNC_SIMILAR_HEADER);
				const char *content_type = apr_table_get(resp_hdrs, CONTENT_TYPE_HEADER);
				if (hostname != NULL && crcsync_similar != NULL && content_type != NULL)
				{
					RMM_OFF_T(vary_headers_t) vary_headers;
					result = make_vary_headers(ptemp, s, sp_cache, req_hdrs, resp_hdrs, &vary_headers);
					if (result != 0) {
						ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, s, 
								"Could not allocate memory to cache vary headers");
						continue; // Skip this file
					}
					result = add_cached_page(sp_cache, crcsync_similar, hostname, basepath, cache_info->uri, content_type, vary_headers);
					if (result == 0)
					{
						ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s, 
								"Successfully added file %s to 'find similar page' cache (host: %s, content-type: %s, regex: %s, uri: %s)",
								basepath, hostname, content_type, crcsync_similar, cache_info->uri);
					}
					else
					{
						ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, s, 
								"Failed to add file %s with regex %s for host %s, content-type %s, uri %s to 'find similar page' cache, result: %d",
								basepath, crcsync_similar, hostname, content_type, cache_info->uri, result);
					}
				}
			}
		}
		else
		{
			ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, s, "Unknown file type %d for file %s/%s", 
					fileinfo.filetype, abs_dirname, fileinfo.name);
		}
	}

	apr_dir_close(dirinfo);
	return APR_SUCCESS;
}

const char *crccache_client_fsp_set_cache_bytes(cmd_parms *parms, void *in_struct_ptr,
		const char *arg, similar_page_cache_t *sp_cache)
{
	apr_size_t val = atol(arg);
	if (val < 0)
		return "CRCClientSharedCacheSize value must be an integer greater than or equal to 0";
	sp_cache->cache_bytes = val;
	return NULL;

}

similar_page_cache_t *create_similar_page_cache(apr_pool_t *p)
{
	similar_page_cache_t *sp_cache = apr_pcalloc(p, sizeof(similar_page_cache_t));
	if (sp_cache != NULL) {
		sp_cache->cache_bytes = 10*1024*1024; // Default to 10 MB
	}
	return sp_cache;
}

static void create_global_mutex(similar_page_cache_t *sp_cache, apr_pool_t *p, apr_pool_t *ptemp, server_rec *s)
{
	apr_status_t result;
    result = apr_global_mutex_create(&sp_cache->fs_cache_lock,
                                     sp_cache->lock_file, APR_LOCK_DEFAULT,
                                     p);
    if (result != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, result, s,
                 "Failed to allocate mutex on vhost %s. Similar page cache will only be loaded on start-up but not maintained for new pages cached while the server is running", 
                 format_hostinfo(ptemp, s));
        sp_cache->fs_cache_lock = NULL;
        return;
    }

#ifdef AP_NEED_SET_MUTEX_PERMS
    result = unixd_set_global_mutex_perms(sp_cache->fs_cache_lock);
    if (result != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, result, s,
                "Failed to set mutex permissions on vhost %s. Similar page cache will only be loaded on start-up but not maintained for new pages cached while the server is running", 
                format_hostinfo(ptemp, s));
        apr_global_mutex_destroy(sp_cache->fs_cache_lock);
        sp_cache->fs_cache_lock = NULL;
        return;
    }
#endif

    // Lock is available for all threads/subprocesses
    *APR_RMM_ADDR_GET(int, sp_cache->rmm, sp_cache->lock_is_available)=1;
}

int crccache_client_fsp_post_config_per_virtual_host(apr_pool_t *p, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s, similar_page_cache_t *sp_cache, const char *cache_root)
{
    apr_status_t result;

    /*
     * Set-up the shared memory block and the mutex for the 'find similar page' memory cache
     */
    
    // Need to know the CacheRootClient value in order to make the SHM
	// cache backing file and the mutex lock backing file

    const char *cache_file_tmp = apr_pstrcat(ptemp, cache_root, "/crccache_client_shm", NULL);
    const char *lock_file_tmp = apr_pstrcat(ptemp, cache_file_tmp, ".lck", NULL);
    void *data;
    const char *userdata_key = apr_pstrcat(p, "crccache_client_init:", cache_root, NULL);

	/* util_crccache_client_post_config() will be called twice. Don't bother
     * going through all of the initialization on the first call
     * because it will just be thrown away.*/
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,"vhost %s, data=%s", 
			format_hostinfo(ptemp, s),
			data == NULL ? "null" : "not null");
    if (!data) {
    	// This code-block is only executed on first invocation of post_config
        apr_pool_userdata_set((const void *)1, userdata_key,
                               apr_pool_cleanup_null, s->process->pool);
#if APR_HAS_SHARED_MEMORY
        /* If the lock file already exists then delete it. Otherwise we are
         * going to run into problems creating the shared memory mutex. */
        if (lock_file_tmp) {
            apr_file_remove(lock_file_tmp, ptemp);
        }
#endif
        return OK;
        
    }

    // Below code-block is only executed on second invocation of post_config
    sp_cache->cache_root = cache_root;
    sp_cache->cache_root_len = strlen(cache_root);
    sp_cache->cache_file = apr_pstrdup(p, cache_file_tmp);
    sp_cache->lock_file = apr_pstrdup(p, lock_file_tmp);

#if APR_HAS_SHARED_MEMORY
    /* initializing cache if we don't have shm address
     */
    if (!sp_cache->shm) {
#endif
        /* initializing cache if shared memory size or entries is not zero
         */
    	if (sp_cache->cache_bytes > 0) {
            result = similar_page_cache_init(p, s, sp_cache);
            if (result != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, result, s,
                         "Could not initialize in-memory cache to efficiently find similar pages on vhost %s. Find similar page functionality is disabled", 
                         format_hostinfo(ptemp, s));
                return DONE;
            }

            create_global_mutex(sp_cache, p, ptemp, s);
            
            result = similar_page_cache_load(ptemp, s, sp_cache->cache_root, "", sp_cache);
            if (result != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, result, s,
                        "Failed to load data into in-memory cache to efficiently find similar pages on vhost %s. Find similar page functionality is disabled", 
                         format_hostinfo(ptemp, s));
                return result;
            }
            
            sp_cache->similar_pages_regexs = apr_hash_make(p); // Set-up cache for compiled regular expressions for similar page lookup
            sp_cache->similar_pages_cache_initialized = 1; // Similar page cache has finally been successfully set-up and is ready to be used

            ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
                         "Successfully initialized shared memory cache for this context (%s)",
                         format_hostinfo(ptemp, s));
    	}
        else {
            ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, s,
                         "CRCCacheClientSharedCacheSize is zero on vhost %s. Find similar page functionality is disabled",
                         format_hostinfo(ptemp, s));
        }
#if APR_HAS_SHARED_MEMORY
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "vhost (%s): Weird. Shared memory cache is already initialized for this context",
                     format_hostinfo(ptemp, s));
    }
#endif
    return OK;
}

void crccache_client_fsp_child_init_per_virtual_host(apr_pool_t *p, server_rec *s, similar_page_cache_t *sp_cache)
{
	apr_status_t sts;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, s,
                 "mod_crccache_client.child_init_per_vhost (%s): cache_lock: %s", 
                 format_hostinfo(p, s),
                 sp_cache->fs_cache_lock ? "defined" : "empty");

    if (sp_cache->fs_cache_lock)
    {
	    sts = apr_global_mutex_child_init(&sp_cache->fs_cache_lock,
	                                      sp_cache->lock_file, p);
	    if (sts != APR_SUCCESS) {
	        ap_log_error(APLOG_MARK, APLOG_WARNING, sts, s,
	                     "Failed to initialise global mutex %s in child process %" APR_PID_T_FMT ". The similar page cache will not be maintained for newly cached pages",
	                     sp_cache->lock_file, getpid());
            sp_cache->fs_cache_lock = NULL; // Disable the global mutex in this child process
            *APR_RMM_ADDR_GET(int, sp_cache->rmm, sp_cache->lock_is_available) = 0; // Disable global mutex in all child processes
	    }
	    else
	    {
	        ap_log_error(APLOG_MARK, APLOG_DEBUG, sts, s,
	                     "Successfully initialized global mutex %s in child process %" APR_PID_T_FMT ".",
	                     sp_cache->lock_file, getpid());	    	
	    }
    }
}

void update_or_add_similar_page(disk_cache_object_t *dobj, request_rec *r, similar_page_cache_t *sp_cache)
{
    if (!is_lock_available(sp_cache)) {
    	return; // Lock is not available. Can't start doing updates
    }

	if (strlen(dobj->hdrsfile)+1 < sp_cache->cache_root_len || 
			memcmp(dobj->hdrsfile, sp_cache->cache_root, sp_cache->cache_root_len) || 
			dobj->hdrsfile[sp_cache->cache_root_len] != '/') {
	    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_EGENERAL, r->server,
	                 "FIXME: Header file name %s does not start with cache root path %s while it should",
	                 dobj->hdrsfile, sp_cache->cache_root);
	    return; 
	}
	char *basepath = apr_pstrdup(r->pool, dobj->hdrsfile+sp_cache->cache_root_len+1);
	apr_size_t suffix_len=strlen(CACHE_HEADER_SUFFIX);
	apr_size_t basepath_len = strlen(basepath);
	if (basepath_len < suffix_len || memcmp(basepath+(basepath_len-suffix_len), CACHE_HEADER_SUFFIX, suffix_len)) {
	    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_EGENERAL, r->server,
	                 "FIXME: Header file name %s does not end on %s suffix",
	                 dobj->hdrsfile, CACHE_HEADER_SUFFIX);
	    return; 
		
	}
	*(basepath+(basepath_len-suffix_len)) = 0; // Terminate the suffix location
	
	const char *hostname = apr_table_get(r->headers_in, HOST_HEADER);
	const char *crcsync_similar = apr_table_get(r->headers_out, CRCSYNC_SIMILAR_HEADER);
	const char *content_type = apr_table_get(r->headers_out, CONTENT_TYPE_HEADER);
	if (hostname != NULL && crcsync_similar != NULL && content_type != NULL)
	{
		apr_status_t lockrslt = apr_global_mutex_lock(sp_cache->fs_cache_lock);
	    if (lockrslt != APR_SUCCESS)
	    {
			ap_log_error(APLOG_MARK, APLOG_WARNING, lockrslt, r->server, "Can't obtain the lock");
			return;
	    }
		RMM_OFF_T(vary_headers_t) vary_headers;
		int addrslt = make_vary_headers(r->pool, r->server, sp_cache, r->headers_in, r->headers_out, &vary_headers);
		if (addrslt != 0)
		{
			ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r->server, 
					"Could not allocate memory to cache vary headers");
		}
		else 
		{
			addrslt = add_cached_page(sp_cache, crcsync_similar, hostname, basepath, dobj->name, content_type, vary_headers);
			if (addrslt == 0)
			{
				ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, 
						"Successfully added file %s to 'find similar page' cache (host: %s, content-type: %s, regex: %s, uri: %s)",
						basepath, hostname, content_type, crcsync_similar, dobj->name);
			}
			else
			{
				ap_log_error(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r->server, 
						"Failed to add file %s with regex %s for host %s, content-type %s, uri %s to 'find similar page' cache, result: %d",
						basepath, crcsync_similar, hostname, content_type, dobj->name, addrslt);
			}
		}
        lockrslt = apr_global_mutex_unlock(sp_cache->fs_cache_lock);
        if (lockrslt != APR_SUCCESS)
        {
			ap_log_error(APLOG_MARK, APLOG_WARNING, lockrslt, r->server, "Can't release the lock");
        }
	}
}
