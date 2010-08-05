/*
 * crccache.h
 *
 * Common files for crccache client and server apache modules
 *
 *  Created on: 21/02/2009
 *      Author: Toby Collett
 *      Contributor: Alex Wulms
 */

#ifndef CRCCACHE_H_
#define CRCCACHE_H_

#include <stdint.h>

#ifndef MAX
#define MAX(a,b)                ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b)                ((a) < (b) ? (a) : (b))
#endif

#define CRCCACHE_ENCODING "crcsync"
#define ACCEPT_ENCODING_HEADER "Accept-Encoding"
#define CAPABILITY_HEADER "Capability"
#define CRCSYNC_SIMILAR_HEADER "Crcsync-Similar"
#define ENCODING_HEADER "Content-Encoding"
#define BLOCK_HEADER "If-Block"
#define VARY_HEADER "Vary"
#define VARY_VALUE "If-Block"
#define ETAG_HEADER "ETag"
#define HOST_HEADER "Host"
#define CONTENT_TYPE_HEADER "Content-Type"
#define ACCEPT_HEADER "Accept"

 // bits per hash, 30 bits is 5 bytes base 64
#define HASH_SIZE 64

// HASH_SIZE_BYTES*FULL_BLOCK_COUNT*4/3 rounded up to the nearest multiple of 3
// 8*40*4/3 = 438
#define HASH_HEADER_SIZE 427


#define ENCODING_LITERAL 'L'
#define ENCODING_BLOCK 'B'
#define ENCODING_COMPRESSED 'Z'
#define ENCODING_HASH 'S'

#define ENCODING_COMPRESSED_HEADER_SIZE  1 /* 1 byte indicator */
#define ENCODING_LITERAL_HEADER_SIZE (1+4) /* 1 byte indicator + 4 bytes length */
#define ENCODING_BLOCK_HEADER_SIZE (1+1) /* 1 byte indicator + 1 byte block */

#endif /* CRCCACHE_H_ */
