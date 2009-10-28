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

const char * CRCCACHE_ENCODING = "crcsync";
const char * ENCODING_HEADER = "Content-Encoding";
const char * BLOCK_HEADER = "If-Block";
const char * VARY_HEADER = "Vary";
const char * VARY_VALUE = "If-Block";
const int HASH_SIZE=64; // bits per has, 30 bits is 5 bytes base 64

// HASH_SIZE_BYTES*FULL_BLOCK_COUNT*4/3 rounded up to the nearest multiple of 3
// 8*40*4/3 = 438
const int HASH_HEADER_SIZE=427;


const unsigned char ENCODING_LITERAL='L';
const unsigned char ENCODING_BLOCK='B';
const unsigned char ENCODING_COMPRESSED='Z';
const unsigned char ENCODING_HASH='S';

const int ENCODING_COMPRESSED_HEADER_SIZE = 1;// 1 byte indicator
const int ENCODING_LITERAL_HEADER_SIZE = 1+4;// 1 byte indicator + 4 bytes length
const int ENCODING_BLOCK_HEADER_SIZE = 1+1;// 1 byte indicator + 1 byte block

#endif /* CRCCACHE_H_ */
