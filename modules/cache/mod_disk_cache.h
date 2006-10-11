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
 */

#ifndef MOD_DISK_CACHE_H
#define MOD_DISK_CACHE_H

/*
 * include for mod_disk_cache: Disk Based HTTP 1.1 Cache.
 */

#define VARY_FORMAT_VERSION 3
#define DISK_FORMAT_VERSION_OLD 4
#define DISK_FORMAT_VERSION 5

#define CACHE_HEADER_SUFFIX ".header"
#define CACHE_DATA_SUFFIX   ".data"
#define CACHE_VDIR_SUFFIX   ".vary"

#define CACHE_BUF_SIZE 65536

/* How long to sleep before retrying while looping */
#define CACHE_LOOP_SLEEP 200000


#define AP_TEMPFILE_PREFIX "/"
#define AP_TEMPFILE_BASE   "aptmp"
#define AP_TEMPFILE_SUFFIX "XXXXXX"
#define AP_TEMPFILE_BASELEN strlen(AP_TEMPFILE_BASE)
#define AP_TEMPFILE_NAMELEN strlen(AP_TEMPFILE_BASE AP_TEMPFILE_SUFFIX)
#define AP_TEMPFILE AP_TEMPFILE_PREFIX AP_TEMPFILE_BASE AP_TEMPFILE_SUFFIX

/* Indicates the format of the header struct stored on-disk. */
typedef apr_uint32_t disk_cache_format_t;

typedef struct {
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
    /* The body size forced to 64bit to not break when people go from non-LFS
     * to LFS builds */
    apr_int64_t file_size;
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
    apr_file_t *fd;          /* data file */
    apr_file_t *hfd;         /* headers file */
    apr_file_t *tfd;         /* temporary file for data */
    apr_off_t file_size;     /*  File size of the cached data file  */
    apr_off_t initial_size;  /*  Initial file size reported by caller */
    disk_cache_info_t disk_info; /* Header information. */

    apr_interval_time_t updtimeout; /* Cache update timeout */

    int skipstore;              /* Set if we should skip storing stuff */
    int store_body_called;      /* Number of times store_body() has executed */
} disk_cache_object_t;


/*
 * mod_disk_cache configuration
 */
/* TODO: Make defaults OS specific */
#define CACHEFILE_LEN 20        /* must be less than HASH_LEN/2 */
#define DEFAULT_DIRLEVELS 3
#define DEFAULT_DIRLENGTH 2
#define DEFAULT_MIN_FILE_SIZE 1
#define DEFAULT_MAX_FILE_SIZE 1000000
#define DEFAULT_UPDATE_TIMEOUT apr_time_from_sec(10)

typedef struct {
    const char* cache_root;
    apr_size_t cache_root_len;
    int dirlevels;               /* Number of levels of subdirectories */
    int dirlength;               /* Length of subdirectory names */
    apr_off_t minfs;             /* minimum file size for cached files */
    apr_off_t maxfs;             /* maximum file size for cached files */
    apr_interval_time_t updtimeout;   /* Cache update timeout */
} disk_cache_conf;

#define CACHE_ENODATA (APR_OS_START_USERERR+1)
#define CACHE_EDECLINED (APR_OS_START_USERERR+2)
#define CACHE_EEXIST (APR_OS_START_USERERR+3)


typedef struct diskcache_bucket_data diskcache_bucket_data;
struct diskcache_bucket_data {
    /* Number of buckets using this memory */
    apr_bucket_refcount  refcount;
    apr_file_t  *fd;
    /* The pool into which any needed structures should
     *  be created while reading from this file bucket */
    apr_pool_t *readpool;
    /* Cache update timeout */
    apr_interval_time_t updtimeout;

};


#endif /*MOD_DISK_CACHE_H*/
