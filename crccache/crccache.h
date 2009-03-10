/*
 * crccache.h
 *
 *  Created on: 21/02/2009
 *      Author: tcollett
 */

#ifndef CRCCACHE_H_
#define CRCCACHE_H_

const char * CRCCACHE_ENCODING = "crccache";
// hashes per file, 20x5 gives us 100 bytes, acceptable overhead
#define BLOCK_COUNT 20
const int HASH_SIZE=30; // bits per has, 30 bits is 5 bytes base 64
const int HASH_BASE64_SIZE_TX=5; //HASH_SIZE/6;
const int HASH_BASE64_SIZE_ACTUAL=8; // decoded/coded in blocks of 4 into three bytes
const int HASH_BASE64_SIZE_PADDING=3; // decoded/coded in blocks of 4 into three bytes

const int HASH_HEADER_SIZE=100;//BLOCK_COUNT*HASH_BASE64_SIZE;


const unsigned char ENCODING_LITERAL='L';
const unsigned char ENCODING_BLOCK='B';

const int ENCODING_LITERAL_HEADER_SIZE = 1+4;// 1 byte indicator + 4 bytes length
const int ENCODING_BLOCK_HEADER_SIZE = 1+1;// 1 byte indicator + 1 byte block

unsigned decode_30bithash(const char * source);
char * encode_30bithash(unsigned hash, char * target);



#endif /* CRCCACHE_H_ */
