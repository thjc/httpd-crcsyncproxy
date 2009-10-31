/*
 * cache.h
 *
 *  Created on: 26/10/2009
 *      Author: tcollett
 */

#ifndef CACHE_H_
#define CACHE_H_

#include <apr-1.0/apr_time.h>
#include <apr-1.0/apr_tables.h>
#include <apr-1.0/apr_file_info.h>
#include <apr-1.0/apr_file_io.h>
#include <apr-1.0/apr_buckets.h>

#include <util_filter.h>
#include <httpd.h>

/* cache info information */
typedef struct cache_info cache_info;
struct cache_info {
    /**
     * HTTP status code of the cached entity. Though not neccessarily the
     * status code finally issued to the request.
     */
    int status;
    /**
     * the original time corresponding to the 'Date:' header of the request
     * served
     */
    apr_time_t date;
    /** a time when the cached entity is due to expire */
    apr_time_t expire;
    /** r->request_time from the same request */
    apr_time_t request_time;
    /** apr_time_now() at the time the entity was acutally cached */
    apr_time_t response_time;
};


/* XXX TODO On the next structure change/MMN bump,
 * count must become an apr_off_t, representing
 * the potential size of disk cached objects.
 * Then dig for
 * "XXX Bad Temporary Cast - see cache_object_t notes"
 */
typedef struct cache_object cache_object_t;
struct cache_object {
    const char *key;
    cache_object_t *next;
    cache_info info;
    /* Opaque portion (specific to the implementation) of the cache object */
    void *vobj;
    /* FIXME: These are only required for mod_mem_cache. */
    apr_size_t count;   /* Number of body bytes written to the cache so far */
    int complete;
    apr_uint32_t refcount;  /* refcount and bit flag to cleanup object */
};


/* cache handle information */
typedef struct cache_handle cache_handle_t;
struct cache_handle {
    cache_object_t *cache_obj;
    apr_table_t *req_hdrs;        /* cached request headers */
    apr_table_t *resp_hdrs;       /* cached response headers */
};

/*
 * include for mod_disk_cache: Disk Based HTTP 1.1 Cache.
 */

#define VARY_FORMAT_VERSION 3
#define DISK_FORMAT_VERSION 4

#define CACHE_HEADER_SUFFIX ".header"
#define CACHE_DATA_SUFFIX   ".data"
#define CACHE_VDIR_SUFFIX   ".vary"

#define AP_TEMPFILE_PREFIX "/"
#define AP_TEMPFILE_BASE   "aptmp"
#define AP_TEMPFILE_SUFFIX "XXXXXX"
#define AP_TEMPFILE_BASELEN strlen(AP_TEMPFILE_BASE)
#define AP_TEMPFILE_NAMELEN strlen(AP_TEMPFILE_BASE AP_TEMPFILE_SUFFIX)
#define AP_TEMPFILE AP_TEMPFILE_PREFIX AP_TEMPFILE_BASE AP_TEMPFILE_SUFFIX

typedef struct {
    /* Indicates the format of the header struct stored on-disk. */
    apr_uint32_t format;
    /* The HTTP status code returned for this response.  */
    int status;
    /* The size of the entity name that follows. */
    apr_size_t name_len;
    /* The number of times we've cached this entity. */
    apr_size_t entity_version;
    /* Miscellaneous time values. */
    apr_time_t date;
    apr_time_t expire;
    apr_time_t request_time;
    apr_time_t response_time;
} disk_cache_info_t;

/*
 * disk_cache_object_t
 * Pointed to by cache_object_t::vobj
 */
typedef struct disk_cache_object {
    const char *root;        /* the location of the cache directory */
    apr_size_t root_len;
    char *tempfile;    /* temp file tohold the content */
    const char *prefix;
    const char *datafile;    /* name of file where the data will go */
    const char *hdrsfile;    /* name of file where the hdrs will go */
    const char *hashfile;    /* Computed hash key for this URI */
    const char *name;   /* Requested URI without vary bits - suitable for mortals. */
    const char *key;    /* On-disk prefix; URI with Vary bits (if present) */
    apr_file_t *fd;          /* data file */
    apr_file_t *hfd;         /* headers file */
    apr_file_t *tfd;         /* temporary file for data */
    apr_off_t file_size;     /*  File size of the cached data file  */
    disk_cache_info_t disk_info; /* Header information. */
} disk_cache_object_t;

/* per request cache information */
typedef struct {
//    cache_provider_list *providers;     /* possible cache providers */
//    const cache_provider *provider;     /* current cache provider */
//    const char *provider_name;          /* current cache provider name */
    int fresh;                          /* is the entitey fresh? */
    cache_handle_t *handle;             /* current cache handle */
    cache_handle_t *stale_handle;       /* stale cache handle */
    apr_table_t *stale_headers;         /* original request headers. */
    int in_checked;                     /* CACHE_SAVE must cache the entity */
    int block_response;                 /* CACHE_SAVE must block response. */
    apr_bucket_brigade *saved_brigade;  /* copy of partial response */
    apr_off_t saved_size;               /* length of saved_brigade */
    apr_time_t exp;                     /* expiration */
    apr_time_t lastmod;                 /* last-modified time */
    cache_info *info;                   /* current cache info */
    ap_filter_t *remove_url_filter;     /* Enable us to remove the filter */
    char *key;                          /* The cache key created for this
                                         * request
                                         */
} cache_request_rec;

/*
 * mod_disk_cache configuration
 */
/* TODO: Make defaults OS specific */
#define CACHEFILE_LEN 20        /* must be less than HASH_LEN/2 */
#define DEFAULT_DIRLEVELS 2
#define DEFAULT_DIRLENGTH 2
#define DEFAULT_MIN_FILE_SIZE 1
#define DEFAULT_MAX_FILE_SIZE 1000000

/* Create a set of CACHE_DECLARE(type), CACHE_DECLARE_NONSTD(type) and
 * CACHE_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define CACHE_DECLARE(type)            type
#define CACHE_DECLARE_NONSTD(type)     type
#define CACHE_DECLARE_DATA
#elif defined(CACHE_DECLARE_STATIC)
#define CACHE_DECLARE(type)            type __stdcall
#define CACHE_DECLARE_NONSTD(type)     type
#define CACHE_DECLARE_DATA
#elif defined(CACHE_DECLARE_EXPORT)
#define CACHE_DECLARE(type)            __declspec(dllexport) type __stdcall
#define CACHE_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define CACHE_DECLARE_DATA             __declspec(dllexport)
#else
#define CACHE_DECLARE(type)            __declspec(dllimport) type __stdcall
#define CACHE_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define CACHE_DECLARE_DATA             __declspec(dllimport)
#endif


/* cache_util.c */
/* do a HTTP/1.1 age calculation */
CACHE_DECLARE(apr_time_t) ap_cache_current_age(cache_info *info, const apr_time_t age_value,
                                               apr_time_t now);

/**
 * Merge in cached headers into the response
 * @param h cache_handle_t
 * @param r request_rec
 * @param preserve_orig If 1, the values in r->headers_out are preserved.
 *        Otherwise, they are overwritten by the cached value.
 */
CACHE_DECLARE(void) ap_cache_accept_headers(cache_handle_t *h, request_rec *r,
                                            int preserve_orig);

CACHE_DECLARE(apr_time_t) ap_cache_hex2usec(const char *x);
CACHE_DECLARE(void) ap_cache_usec2hex(apr_time_t j, char *y);
CACHE_DECLARE(char *) ap_cache_generate_name(apr_pool_t *p, int dirlevels,
                                             int dirlength,
                                             const char *name);
//CACHE_DECLARE(cache_provider_list *)ap_cache_get_providers(request_rec *r, cache_server_conf *conf, apr_uri_t uri);
CACHE_DECLARE(int) ap_cache_liststr(apr_pool_t *p, const char *list,
                                    const char *key, char **val);
CACHE_DECLARE(const char *)ap_cache_tokstr(apr_pool_t *p, const char *list, const char **str);

/* Create a new table consisting of those elements from an
 * headers table that are allowed to be stored in a cache.
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_headers(apr_pool_t *pool,
                                                        apr_table_t *t,
                                                        server_rec *s);

/* Create a new table consisting of those elements from an input
 * headers table that are allowed to be stored in a cache.
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_headers_in(request_rec *r);

/* Create a new table consisting of those elements from an output
 * headers table that are allowed to be stored in a cache;
 * ensure there is a content type and capture any errors.
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_headers_out(request_rec *r);

/* Legacy call - functionally equivalent to ap_cache_cacheable_headers.
 * @deprecated @see ap_cache_cacheable_headers
 */
CACHE_DECLARE(apr_table_t *)ap_cache_cacheable_hdrs_out(apr_pool_t *pool,
                                                        apr_table_t *t,
                                                        server_rec *s);

/**
 * cache_storage.c
 */
int cache_create_entity(request_rec *r, apr_off_t size);
apr_status_t cache_generate_key_default( request_rec *r, apr_pool_t*p, char**key );
/**
 * create a key for the cache based on the request record
 * this is the 'default' version, which can be overridden by a default function
 */
const char* cache_create_key( request_rec*r );

#define MSEC_ONE_DAY    ((apr_time_t)(86400*APR_USEC_PER_SEC)) /* one day, in microseconds */
#define MSEC_ONE_HR     ((apr_time_t)(3600*APR_USEC_PER_SEC))  /* one hour, in microseconds */
#define MSEC_ONE_MIN    ((apr_time_t)(60*APR_USEC_PER_SEC))    /* one minute, in microseconds */
#define MSEC_ONE_SEC    ((apr_time_t)(APR_USEC_PER_SEC))       /* one second, in microseconds */
#define DEFAULT_CACHE_MAXEXPIRE MSEC_ONE_DAY
#define DEFAULT_CACHE_MINEXPIRE 0
#define DEFAULT_CACHE_EXPIRE    MSEC_ONE_HR
#define DEFAULT_CACHE_LMFACTOR  (0.1)


#ifndef MAX
#define MAX(a,b)                ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b)                ((a) < (b) ? (a) : (b))
#endif

/* Forward declarations */
int remove_entity(cache_handle_t *h);
apr_status_t store_headers(cache_handle_t *h, request_rec *r,
		cache_info *i);
apr_status_t store_body(cache_handle_t *h, request_rec *r,
		apr_bucket_brigade *b);
apr_status_t recall_headers(cache_handle_t *h, request_rec *r);
apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p,
		apr_bucket_brigade *bb);
apr_status_t read_array(request_rec *r, apr_array_header_t* arr,
		apr_file_t *file);

int create_entity(cache_handle_t *h, request_rec *r, const char *key, apr_off_t len);
int open_entity(cache_handle_t *h, request_rec *r, const char *key);

apr_status_t read_table(cache_handle_t *handle, request_rec *r, apr_table_t *table, apr_file_t *file);


#endif /* CACHE_H_ */
