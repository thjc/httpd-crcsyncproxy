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

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  ssl_scache_shmcb.c
 *  Session Cache via Shared Memory (Cyclic Buffer Variant)
 */

#include "ssl_private.h"

/* 
 * This shared memory based SSL session cache implementation was
 * originally written by Geoff Thorpe <geoff geoffthorpe.net> for C2Net
 * Europe as a contribution to Ralf Engelschall's mod_ssl project.
 *
 * Since rewritten by GT to not use alignment-fudging memcpys and reduce
 * complexity.
 */

/*
 * Header structure - the start of the shared-mem segment
 */
typedef struct {
    /* Stats for cache operations */
    unsigned long stat_stores;
    unsigned long stat_expiries;
    unsigned long stat_scrolled;
    unsigned long stat_retrieves_hit;
    unsigned long stat_retrieves_miss;
    unsigned long stat_removes_hit;
    unsigned long stat_removes_miss;
    /* Number of subcaches */
    unsigned int subcache_num;
    /* How many indexes each subcache's queue has */
    unsigned int index_num;
    /* How large each subcache is, including the queue and data */
    unsigned int subcache_size;
    /* How far into each subcache the data area is (optimisation) */
    unsigned int subcache_data_offset;
    /* How large the data area in each subcache is (optimisation) */
    unsigned int subcache_data_size;
} SHMCBHeader;

/* 
 * Subcache structure - the start of each subcache, followed by
 * indexes then data
 */
typedef struct {
    /* The start position and length of the cyclic buffer of indexes */
    unsigned int idx_pos, idx_used;
    /* Same for the data area */
    unsigned int data_pos, data_used;
} SHMCBSubcache;

/* 
 * Index structure - each subcache has an array of these
 */
typedef struct {
    /* absolute time this entry expires */
    time_t expires;
    /* location within the subcache's data area */
    unsigned int data_pos;
    /* size (most logic ignores this, we keep it only to minimise memcpy) */
    unsigned int data_used;
    /* length of the used data which contains the id */
    unsigned int id_len;
    /* Used to mark explicitly-removed sessions */
    unsigned char removed;
} SHMCBIndex;

struct context {
    const char *data_file;
    apr_size_t shm_size;
    apr_shm_t *shm;
    SHMCBHeader *header;
};

/* The SHM data segment is of fixed size and stores data as follows.
 *
 *   [ SHMCBHeader | Subcaches ]
 *
 * The SHMCBHeader header structure stores metadata concerning the
 * cache and the contained subcaches.
 *
 * Subcaches is a hash table of header->subcache_num SHMCBSubcache
 * structures.  The hash table is indexed by SHMCB_MASK(id). Each
 * SHMCBSubcache structure has a fixed size (header->subcache_size),
 * which is determined at creation time, and looks like the following:
 *
 *   [ SHMCBSubcache | Indexes | Data ]
 *
 * Each subcache is prefixed by the SHMCBSubcache structure.
 *
 * The subcache's "Data" segment is a single cyclic data buffer, of
 * total size header->subcache_data_size; data inside is referenced
 * using byte offsets. The offset marking the beginning of the cyclic
 * buffer is subcache->data_pos the buffer's length is
 * subcache->data_used.
 *
 * "Indexes" is an array of header->index_num SHMCBIndex structures,
 * which is used as a cyclic queue; subcache->idx_pos gives the array
 * index of the first in use, subcache->idx_used gives the number in
 * use.  Both ->idx_* values have a range of [0, header->index_num)
 *
 * Each in-use SHMCBIndex structure represents a single SSL session.
 * The ID and data segment are stored consecutively in the subcache's
 * cyclic data buffer.  The "Data" segment can thus be seen to 
 * look like this, for example
 *
 * offset:  [ 0     1     2     3     4     5     6    ...
 * contents:[ ID1   Data1       ID2   Data2       ID3  ...
 *
 * where the corresponding indices would look like:
 *
 * idx1 = { data_pos = 0, data_used = 3, id_len = 1, ...}
 * idx2 = { data_pos = 3, data_used = 3, id_len = 1, ...}
 * ...
 */

/* This macro takes a pointer to the header and a zero-based index and returns
 * a pointer to the corresponding subcache. */
#define SHMCB_SUBCACHE(pHeader, num) \
                (SHMCBSubcache *)(((unsigned char *)(pHeader)) + \
                        sizeof(SHMCBHeader) + \
                        (num) * ((pHeader)->subcache_size))

/* This macro takes a pointer to the header and a session id and returns a
 * pointer to the corresponding subcache. */
#define SHMCB_MASK(pHeader, id) \
                SHMCB_SUBCACHE((pHeader), *(id) & ((pHeader)->subcache_num - 1))

/* This macro takes the same params as the last, generating two outputs for use
 * in ap_log_error(...). */
#define SHMCB_MASK_DBG(pHeader, id) \
                *(id), (*(id) & ((pHeader)->subcache_num - 1))

/* This macro takes a pointer to a subcache and a zero-based index and returns
 * a pointer to the corresponding SHMCBIndex. */
#define SHMCB_INDEX(pSubcache, num) \
                ((SHMCBIndex *)(((unsigned char *)pSubcache) + \
                                sizeof(SHMCBSubcache)) + num)

/* This macro takes a pointer to the header and a subcache and returns a
 * pointer to the corresponding data area. */
#define SHMCB_DATA(pHeader, pSubcache) \
                ((unsigned char *)(pSubcache) + (pHeader)->subcache_data_offset)

/*
 * Cyclic functions - assists in "wrap-around"/modulo logic
 */

/* Addition modulo 'mod' */
#define SHMCB_CYCLIC_INCREMENT(val,inc,mod) \
                (((val) + (inc)) % (mod))

/* Subtraction (or "distance between") modulo 'mod' */
#define SHMCB_CYCLIC_SPACE(val1,val2,mod) \
                ((val2) >= (val1) ? ((val2) - (val1)) : \
                        ((val2) + (mod) - (val1)))

/* A "normal-to-cyclic" memcpy. */
static void shmcb_cyclic_ntoc_memcpy(unsigned int buf_size, unsigned char *data,
                                     unsigned int dest_offset, unsigned char *src,
                                     unsigned int src_len)
{
    if (dest_offset + src_len < buf_size)
        /* It be copied all in one go */
        memcpy(data + dest_offset, src, src_len);
    else {
        /* Copy the two splits */
        memcpy(data + dest_offset, src, buf_size - dest_offset);
        memcpy(data, src + buf_size - dest_offset,
               src_len + dest_offset - buf_size);
    }
}

/* A "cyclic-to-normal" memcpy. */
static void shmcb_cyclic_cton_memcpy(unsigned int buf_size, unsigned char *dest,
                                     unsigned char *data, unsigned int src_offset,
                                     unsigned int src_len)
{
    if (src_offset + src_len < buf_size)
        /* It be copied all in one go */
        memcpy(dest, data + src_offset, src_len);
    else {
        /* Copy the two splits */
        memcpy(dest, data + src_offset, buf_size - src_offset);
        memcpy(dest + buf_size - src_offset, data,
               src_len + src_offset - buf_size);
    }
}

/* A memcmp against a cyclic data buffer.  Compares SRC of length
 * SRC_LEN against the contents of cyclic buffer DATA (which is of
 * size BUF_SIZE), starting at offset DEST_OFFSET. Got that?  Good. */
static int shmcb_cyclic_memcmp(unsigned int buf_size, unsigned char *data,
                               unsigned int dest_offset, 
                               const unsigned char *src,
                               unsigned int src_len)
{
    if (dest_offset + src_len < buf_size)
        /* It be compared all in one go */
        return memcmp(data + dest_offset, src, src_len);
    else {
        /* Compare the two splits */
        int diff;
        
        diff = memcmp(data + dest_offset, src, buf_size - dest_offset);
        if (diff) {
            return diff;
        }
        return memcmp(data, src + buf_size - dest_offset,
                      src_len + dest_offset - buf_size);
    }
}


/* Prototypes for low-level subcache operations */
static void shmcb_subcache_expire(server_rec *, SHMCBHeader *, SHMCBSubcache *);
static BOOL shmcb_subcache_store(server_rec *s, SHMCBHeader *header,
                                 SHMCBSubcache *subcache, 
                                 UCHAR *data, unsigned int data_len,
                                 UCHAR *id, unsigned int id_len,
                                 time_t expiry);
static BOOL shmcb_subcache_retrieve(server_rec *, SHMCBHeader *, SHMCBSubcache *,
                                    const UCHAR *id, unsigned int idlen,
                                    UCHAR *data, unsigned int *datalen);
                                    
static BOOL shmcb_subcache_remove(server_rec *, SHMCBHeader *, SHMCBSubcache *,
                                 UCHAR *, unsigned int);

/*
 * High-Level "handlers" as per ssl_scache.c
 * subcache internals are deferred to shmcb_subcache_*** functions lower down
 */

static const char *ssl_scache_shmcb_create(void **context, const char *arg, 
                                           apr_pool_t *tmp, apr_pool_t *p)
{
    struct context *ctx;
    char *path, *cp, *cp2;

    /* Allocate the context. */
    *context = ctx = apr_pcalloc(p, sizeof *ctx);
    
    ctx->data_file = path = ap_server_root_relative(p, arg);
    ctx->shm_size  = 1024*512; /* 512KB */

    cp = strchr(path, '(');
    if (cp) {
        *cp++ = NUL;

        if (!(cp2 = strchr(cp, ')'))) {
            return "Invalid argument: no closing parenthesis";
        }
            
        *cp2 = NUL;
        
        ctx->shm_size = atoi(cp);
        
        if (ctx->shm_size < 8192) {
            return "Invalid argument: size has to be >= 8192 bytes";
            
        }
        
        if (ctx->shm_size >= APR_SHM_MAXSIZE) {
            return apr_psprintf(tmp,
                                "Invalid argument: size has "
                                "to be < %d bytes on this platform", 
                                APR_SHM_MAXSIZE);
            
        }
    }

    return NULL;
}

static apr_status_t ssl_scache_shmcb_init(void *context, server_rec *s, apr_pool_t *p)
{
    void *shm_segment;
    apr_size_t shm_segsize;
    apr_status_t rv;
    SHMCBHeader *header;
    unsigned int num_subcache, num_idx, loop;
    struct context *ctx = context;

    /* Create shared memory segment */
    if (ctx->data_file == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "SSLSessionCache required");
        return APR_EINVAL;
    }

    /* Use anonymous shm by default, fall back on name-based. */
    rv = apr_shm_create(&ctx->shm, ctx->shm_size, NULL, p);
    if (APR_STATUS_IS_ENOTIMPL(rv)) {
        /* For a name-based segment, remove it first in case of a
         * previous unclean shutdown. */
        apr_shm_remove(ctx->data_file, p);

        rv = apr_shm_create(&ctx->shm, ctx->shm_size, ctx->data_file, p);
    }

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "could not allocate shared memory for shmcb "
                     "session cache");
        return rv;
    }

    shm_segment = apr_shm_baseaddr_get(ctx->shm);
    shm_segsize = apr_shm_size_get(ctx->shm);
    if (shm_segsize < (5 * sizeof(SHMCBHeader))) {
        /* the segment is ridiculously small, bail out */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "shared memory segment too small");
        return APR_ENOSPC;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "shmcb_init allocated %" APR_SIZE_T_FMT
                 " bytes of shared memory",
                 shm_segsize);
    /* Discount the header */
    shm_segsize -= sizeof(SHMCBHeader);
    /* Select the number of subcaches to create and how many indexes each
     * should contain based on the size of the memory (the header has already
     * been subtracted). Typical non-client-auth sslv3/tlsv1 sessions are
     * around 180 bytes (148 bytes data and 32 bytes for the id), so
     * erring to division by 150 helps ensure we would exhaust data
     * storage before index storage (except sslv2, where it's
     * *slightly* the other way). From there, we select the number of
     * subcaches to be a power of two, such that the number of indexes
     * per subcache at least twice the number of subcaches. */
    num_idx = (shm_segsize) / 150;
    num_subcache = 256;
    while ((num_idx / num_subcache) < (2 * num_subcache))
        num_subcache /= 2;
    num_idx /= num_subcache;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "for %" APR_SIZE_T_FMT " bytes (%" APR_SIZE_T_FMT 
                 " including header), recommending %u subcaches, "
                 "%u indexes each", shm_segsize,
                 shm_segsize + sizeof(SHMCBHeader), num_subcache, num_idx);
    if (num_idx < 5) {
        /* we're still too small, bail out */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "shared memory segment too small");
        return APR_ENOSPC;
    }
    /* OK, we're sorted */
    ctx->header = header = shm_segment;
    header->stat_stores = 0;
    header->stat_expiries = 0;
    header->stat_scrolled = 0;
    header->stat_retrieves_hit = 0;
    header->stat_retrieves_miss = 0;
    header->stat_removes_hit = 0;
    header->stat_removes_miss = 0;
    header->subcache_num = num_subcache;
    /* Convert the subcache size (in bytes) to a value that is suitable for
     * structure alignment on the host platform, by rounding down if necessary.
     * This assumes that sizeof(unsigned long) provides an appropriate
     * alignment unit.  */
    header->subcache_size = ((size_t)(shm_segsize / num_subcache) &
                             ~(size_t)(sizeof(unsigned long) - 1));
    header->subcache_data_offset = sizeof(SHMCBSubcache) +
                                   num_idx * sizeof(SHMCBIndex);
    header->subcache_data_size = header->subcache_size -
                                 header->subcache_data_offset;
    header->index_num = num_idx;

    /* Output trace info */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "shmcb_init_memory choices follow");
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "subcache_num = %u", header->subcache_num);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "subcache_size = %u", header->subcache_size);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "subcache_data_offset = %u", header->subcache_data_offset);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "subcache_data_size = %u", header->subcache_data_size);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "index_num = %u", header->index_num);
    /* The header is done, make the caches empty */
    for (loop = 0; loop < header->subcache_num; loop++) {
        SHMCBSubcache *subcache = SHMCB_SUBCACHE(header, loop);
        subcache->idx_pos = subcache->idx_used = 0;
        subcache->data_pos = subcache->data_used = 0;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "Shared memory session cache initialised");
    /* Success ... */

    return APR_SUCCESS;
}

static void ssl_scache_shmcb_kill(void *context, server_rec *s)
{
    struct context *ctx = context;

    if (ctx && ctx->shm) {
        apr_shm_destroy(ctx->shm);
        ctx->shm = NULL;
    }
}

static BOOL ssl_scache_shmcb_store(void *context, server_rec *s, 
                                   UCHAR *id, int idlen,
                                   time_t timeout, 
                                   unsigned char *encoded,
                                   unsigned int len_encoded)
{
    struct context *ctx = context;
    SHMCBHeader *header = ctx->header;
    SHMCBSubcache *subcache = SHMCB_MASK(header, id);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "ssl_scache_shmcb_store (0x%02x -> subcache %d)",
                 SHMCB_MASK_DBG(header, id));
    if (idlen < 4) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "unusably short session_id provided "
                "(%u bytes)", idlen);
        return FALSE;
    }
    if (!shmcb_subcache_store(s, header, subcache, encoded,
                              len_encoded, id, idlen, timeout)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "can't store a session!");
        return FALSE;
    }
    header->stat_stores++;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "leaving ssl_scache_shmcb_store successfully");
    return TRUE;
}

static BOOL ssl_scache_shmcb_retrieve(void *context, server_rec *s, 
                                      const UCHAR *id, int idlen,
                                      unsigned char *dest, unsigned int *destlen,
                                      apr_pool_t *p)
{
    struct context *ctx = context;
    SHMCBHeader *header = ctx->header;
    SHMCBSubcache *subcache = SHMCB_MASK(header, id);
    BOOL rv;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "ssl_scache_shmcb_retrieve (0x%02x -> subcache %d)",
                 SHMCB_MASK_DBG(header, id));

    /* Get the session corresponding to the session_id or NULL if it doesn't
     * exist (or is flagged as "removed"). */
    rv = shmcb_subcache_retrieve(s, header, subcache, id, idlen,
                                 dest, destlen);
    if (rv)
        header->stat_retrieves_hit++;
    else
        header->stat_retrieves_miss++;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "leaving ssl_scache_shmcb_retrieve successfully");

    return rv;
}

static void ssl_scache_shmcb_remove(void *context, server_rec *s, 
                                    UCHAR *id, int idlen, apr_pool_t *p)
{
    struct context *ctx = context;
    SHMCBHeader *header = ctx->header;
    SHMCBSubcache *subcache = SHMCB_MASK(header, id);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "ssl_scache_shmcb_remove (0x%02x -> subcache %d)",
                 SHMCB_MASK_DBG(header, id));
    if (idlen < 4) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "unusably short session_id provided "
                "(%u bytes)", idlen);
        return;
    }
    if (shmcb_subcache_remove(s, header, subcache, id, idlen))
        header->stat_removes_hit++;
    else
        header->stat_removes_miss++;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "leaving ssl_scache_shmcb_remove successfully");
}

static void ssl_scache_shmcb_status(void *context, request_rec *r, 
                                    int flags, apr_pool_t *p)
{
    server_rec *s = r->server;
    struct context *ctx = context;
    SHMCBHeader *header = ctx->header;
    unsigned int loop, total = 0, cache_total = 0, non_empty_subcaches = 0;
    time_t idx_expiry, min_expiry = 0, max_expiry = 0, average_expiry = 0;
    time_t now = time(NULL);
    double expiry_total = 0;
    int index_pct, cache_pct;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "inside shmcb_status");
    /* Perform the iteration inside the mutex to avoid corruption or invalid
     * pointer arithmetic. The rest of our logic uses read-only header data so
     * doesn't need the lock. */
    /* Iterate over the subcaches */
    for (loop = 0; loop < header->subcache_num; loop++) {
        SHMCBSubcache *subcache = SHMCB_SUBCACHE(header, loop);
        shmcb_subcache_expire(s, header, subcache);
        total += subcache->idx_used;
        cache_total += subcache->data_used;
        if (subcache->idx_used) {
            SHMCBIndex *idx = SHMCB_INDEX(subcache, subcache->idx_pos);
            non_empty_subcaches++;
            idx_expiry = idx->expires;
            expiry_total += (double)idx_expiry;
            max_expiry = ((idx_expiry > max_expiry) ? idx_expiry : max_expiry);
            if (!min_expiry)
                min_expiry = idx_expiry;
            else
                min_expiry = ((idx_expiry < min_expiry) ? idx_expiry : min_expiry);
        }
    }
    index_pct = (100 * total) / (header->index_num *
                                 header->subcache_num);
    cache_pct = (100 * cache_total) / (header->subcache_data_size *
                                       header->subcache_num);
    /* Generate HTML */
    ap_rprintf(r, "cache type: <b>SHMCB</b>, shared memory: <b>%" APR_SIZE_T_FMT "</b> "
               "bytes, current sessions: <b>%d</b><br>",
               ctx->shm_size, total);
    ap_rprintf(r, "subcaches: <b>%d</b>, indexes per subcache: <b>%d</b><br>",
               header->subcache_num, header->index_num);
    if (non_empty_subcaches) {
        average_expiry = (time_t)(expiry_total / (double)non_empty_subcaches);
        ap_rprintf(r, "time left on oldest entries' SSL sessions: ");
        if (now < average_expiry)
            ap_rprintf(r, "avg: <b>%d</b> seconds, (range: %d...%d)<br>",
                       (int)(average_expiry - now),
                       (int)(min_expiry - now),
                       (int)(max_expiry - now));
        else
            ap_rprintf(r, "expiry_threshold: <b>Calculation error!</b><br>");
    }

    ap_rprintf(r, "index usage: <b>%d%%</b>, cache usage: <b>%d%%</b><br>",
               index_pct, cache_pct);
    ap_rprintf(r, "total sessions stored since starting: <b>%lu</b><br>",
               header->stat_stores);
    ap_rprintf(r, "total sessions expired since starting: <b>%lu</b><br>",
               header->stat_expiries);
    ap_rprintf(r, "total (pre-expiry) sessions scrolled out of the cache: "
               "<b>%lu</b><br>", header->stat_scrolled);
    ap_rprintf(r, "total retrieves since starting: <b>%lu</b> hit, "
               "<b>%lu</b> miss<br>", header->stat_retrieves_hit,
               header->stat_retrieves_miss);
    ap_rprintf(r, "total removes since starting: <b>%lu</b> hit, "
               "<b>%lu</b> miss<br>", header->stat_removes_hit,
               header->stat_removes_miss);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "leaving shmcb_status");
}

/*
 * Subcache-level cache operations 
 */

static void shmcb_subcache_expire(server_rec *s, SHMCBHeader *header,
                                  SHMCBSubcache *subcache)
{
    time_t now = time(NULL);
    unsigned int loop = 0;
    unsigned int new_idx_pos = subcache->idx_pos;
    SHMCBIndex *idx = NULL;

    while (loop < subcache->idx_used) {
        idx = SHMCB_INDEX(subcache, new_idx_pos);
        if (idx->expires > now)
            /* it hasn't expired yet, we're done iterating */
            break;
        loop++;
        new_idx_pos = SHMCB_CYCLIC_INCREMENT(new_idx_pos, 1, header->index_num);
    }
    if (!loop)
        /* Nothing to do */
        return;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "will be expiring %u sessions", loop);
    if (loop == subcache->idx_used) {
        /* We're expiring everything, piece of cake */
        subcache->idx_used = 0;
        subcache->data_used = 0;
    } else {
        /* There remain other indexes, so we can use idx to adjust 'data' */
        unsigned int diff = SHMCB_CYCLIC_SPACE(subcache->data_pos,
                                               idx->data_pos,
                                               header->subcache_data_size);
        /* Adjust the indexes */
        subcache->idx_used -= loop;
        subcache->idx_pos = new_idx_pos;
        /* Adjust the data area */
        subcache->data_used -= diff;
        subcache->data_pos = idx->data_pos;
    }
    header->stat_expiries += loop;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "we now have %u sessions", subcache->idx_used);
}

static BOOL shmcb_subcache_store(server_rec *s, SHMCBHeader *header,
                                 SHMCBSubcache *subcache, 
                                 UCHAR *data, unsigned int data_len,
                                 UCHAR *id, unsigned int id_len,
                                 time_t expiry)
{
    unsigned int data_offset, new_idx, id_offset;
    SHMCBIndex *idx;
    unsigned int total_len = id_len + data_len;

    /* Sanity check the input */
    if (total_len > header->subcache_data_size) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "inserting session larger (%d) than subcache data area (%d)",
                     total_len, header->subcache_data_size);
        return FALSE;
    }

    /* If there are entries to expire, ditch them first. */
    shmcb_subcache_expire(s, header, subcache);

    /* Loop until there is enough space to insert */
    if (header->subcache_data_size - subcache->data_used < total_len
        || subcache->idx_used == header->index_num) {
        unsigned int loop = 0;

        idx = SHMCB_INDEX(subcache, subcache->idx_pos);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "about to force-expire, subcache: idx_used=%d, "
                     "data_used=%d", subcache->idx_used, subcache->data_used);
        do {
            SHMCBIndex *idx2;

            /* Adjust the indexes by one */
            subcache->idx_pos = SHMCB_CYCLIC_INCREMENT(subcache->idx_pos, 1,
                                                       header->index_num);
            subcache->idx_used--;
            if (!subcache->idx_used) {
                /* There's nothing left */
                subcache->data_used = 0;
                break;
            }
            /* Adjust the data */
            idx2 = SHMCB_INDEX(subcache, subcache->idx_pos);
            subcache->data_used -= SHMCB_CYCLIC_SPACE(idx->data_pos, idx2->data_pos,
                                                      header->subcache_data_size);
            subcache->data_pos = idx2->data_pos;
            /* Stats */
            header->stat_scrolled++;
            /* Loop admin */
            idx = idx2;
            loop++;
        } while (header->subcache_data_size - subcache->data_used < total_len);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "finished force-expire, subcache: idx_used=%d, "
                     "data_used=%d", subcache->idx_used, subcache->data_used);
    }

    /* HERE WE ASSUME THAT THE NEW SESSION SHOULD GO ON THE END! I'M NOT
     * CHECKING WHETHER IT SHOULD BE GENUINELY "INSERTED" SOMEWHERE.
     *
     * We either fix that, or find out at a "higher" (read "mod_ssl")
     * level whether it is possible to have distinct session caches for
     * any attempted tomfoolery to do with different session timeouts.
     * Knowing in advance that we can have a cache-wide constant timeout
     * would make this stuff *MUCH* more efficient. Mind you, it's very
     * efficient right now because I'm ignoring this problem!!!
     */
    /* Insert the id */
    id_offset = SHMCB_CYCLIC_INCREMENT(subcache->data_pos, subcache->data_used,
                                       header->subcache_data_size);
    shmcb_cyclic_ntoc_memcpy(header->subcache_data_size,
                             SHMCB_DATA(header, subcache), id_offset,
                             id, id_len);
    subcache->data_used += id_len;
    /* Insert the data */
    data_offset = SHMCB_CYCLIC_INCREMENT(subcache->data_pos, subcache->data_used,
                                         header->subcache_data_size);
    shmcb_cyclic_ntoc_memcpy(header->subcache_data_size,
                             SHMCB_DATA(header, subcache), data_offset,
                             data, data_len);
    subcache->data_used += data_len;
    /* Insert the index */
    new_idx = SHMCB_CYCLIC_INCREMENT(subcache->idx_pos, subcache->idx_used,
                                     header->index_num);
    idx = SHMCB_INDEX(subcache, new_idx);
    idx->expires = expiry;
    idx->data_pos = id_offset;
    idx->data_used = total_len;
    idx->id_len = id_len;
    idx->removed = 0;
    subcache->idx_used++;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "insert happened at idx=%d, data=(%u:%u)", new_idx, 
                 id_offset, data_offset);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "finished insert, subcache: idx_pos/idx_used=%d/%d, "
                 "data_pos/data_used=%d/%d",
                 subcache->idx_pos, subcache->idx_used,
                 subcache->data_pos, subcache->data_used);
    return TRUE;
}

static BOOL shmcb_subcache_retrieve(server_rec *s, SHMCBHeader *header,
                                    SHMCBSubcache *subcache, 
                                    const UCHAR *id, unsigned int idlen,
                                    UCHAR *dest, unsigned int *destlen)
{
    unsigned int pos;
    unsigned int loop = 0;

    /* If there are entries to expire, ditch them first. */
    shmcb_subcache_expire(s, header, subcache);
    pos = subcache->idx_pos;

    while (loop < subcache->idx_used) {
        SHMCBIndex *idx = SHMCB_INDEX(subcache, pos);

        /* Only consider 'idx' if the id matches, and the "removed"
         * flag isn't set; check the data length too to avoid a buffer
         * overflow in case of corruption, which should be impossible,
         * but it's cheap to be safe. */
        if (!idx->removed
            && idx->id_len == idlen && (idx->data_used - idx->id_len) < *destlen
            && shmcb_cyclic_memcmp(header->subcache_data_size,
                                   SHMCB_DATA(header, subcache),
                                   idx->data_pos, id, idx->id_len) == 0) {
            unsigned int data_offset;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "match at idx=%d, data=%d", pos, idx->data_pos);

            /* Find the offset of the data segment, after the id */
            data_offset = SHMCB_CYCLIC_INCREMENT(idx->data_pos, 
                                                 idx->id_len,
                                                 header->subcache_data_size);

            *destlen = idx->data_used - idx->id_len;

            /* Copy out the data */
            shmcb_cyclic_cton_memcpy(header->subcache_data_size,
                                     dest, SHMCB_DATA(header, subcache),
                                     data_offset, *destlen);

            return TRUE;
        }
        /* Increment */
        loop++;
        pos = SHMCB_CYCLIC_INCREMENT(pos, 1, header->index_num);
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "shmcb_subcache_retrieve found no match");
    return FALSE;
}

static BOOL shmcb_subcache_remove(server_rec *s, SHMCBHeader *header,
                                  SHMCBSubcache *subcache,
                                  UCHAR *id, unsigned int idlen)
{
    unsigned int pos;
    unsigned int loop = 0;
    BOOL to_return = FALSE;

    /* Unlike the others, we don't do an expire-run first. This is to keep
     * consistent statistics where a "remove" operation may actually be the
     * higher layer spotting an expiry issue prior to us. Our caller is
     * handling stats, so a failure return would be inconsistent if the
     * intended session was in fact removed by an expiry run. */

    pos = subcache->idx_pos;
    while (!to_return && (loop < subcache->idx_used)) {
        SHMCBIndex *idx = SHMCB_INDEX(subcache, pos);

        /* Only consider 'idx' if the id matches, and the "removed"
         * flag isn't set. */
        if (!idx->removed && idx->id_len == idlen
            && shmcb_cyclic_memcmp(header->subcache_data_size,
                                   SHMCB_DATA(header, subcache),
                                   idx->data_pos, id, idx->id_len) == 0) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "possible match at idx=%d, data=%d", pos, idx->data_pos);
            /* Found the matching session, remove it quietly. */
            idx->removed = 1;
            to_return = TRUE;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                             "shmcb_subcache_remove removing matching session");
        }
        /* Increment */
        loop++;
        pos = SHMCB_CYCLIC_INCREMENT(pos, 1, header->index_num);
    }

    return to_return;
}

const modssl_sesscache_provider modssl_sesscache_shmcb = {
    "shmcb",
    MODSSL_SESSCACHE_FLAG_NOTMPSAFE,
    ssl_scache_shmcb_create,
    ssl_scache_shmcb_init,
    ssl_scache_shmcb_kill,
    ssl_scache_shmcb_store,
    ssl_scache_shmcb_retrieve,
    ssl_scache_shmcb_remove,
    ssl_scache_shmcb_status
};
