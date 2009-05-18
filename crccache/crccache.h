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

const char * CRCCACHE_ENCODING = "crcsync";
const char * ENCODING_HEADER = "IM";
const char * BLOCK_HEADER = "If-Block";
const char * FILE_SIZE_HEADER = "File-Size";
// hashes per file, 40x5 gives us 200 bytes, acceptable overhead
#define FULL_BLOCK_COUNT 40
const int HASH_SIZE=30; // bits per has, 30 bits is 5 bytes base 64
const int HASH_BASE64_SIZE_TX=5; //HASH_SIZE/6;
const int HASH_BASE64_SIZE_ACTUAL=8; // decoded/coded in blocks of 4 into three bytes
const int HASH_BASE64_SIZE_PADDING=3; // decoded/coded in blocks of 4 into three bytes

const int HASH_HEADER_SIZE=205;//(FULL_BLOCK_COUNT+1)*HASH_BASE64_SIZE_TX;


//const unsigned char ENCODING_LITERAL='L';
const unsigned char ENCODING_BLOCK='B';
const unsigned char ENCODING_COMPRESSED='Z';

const int ENCODING_COMPRESSED_HEADER_SIZE = 1;// 1 byte indicator
//const int ENCODING_LITERAL_HEADER_SIZE = 1+4;// 1 byte indicator + 4 bytes length
const int ENCODING_BLOCK_HEADER_SIZE = 1+1;// 1 byte indicator + 1 byte block

unsigned decode_30bithash(const char * source);
char * encode_30bithash(unsigned hash, char * target);



#endif /* CRCCACHE_H_ */
