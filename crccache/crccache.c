/*
 * crccache.c
 *
 *  Created on: 22/02/2009
 *      Author: Toby Collett
 */

#include <string.h>
#include <assert.h>
#include <apr_base64.h>
#include <stdio.h>

int is_big_endian()
{
	int i = 1;
	if (((unsigned char *) &i)[0]==1)
		return 0;
	return 1;
}

// we need our data in big endian order so we discard the correct bytes 
// probably a better way of doing this, use htnol or something? 
void SWAP_BYTES_64(uint64_t * input) 
{
		unsigned char * value = (unsigned char *) input;
		unsigned char temp[4];
		memcpy(temp,value,4);
		value[0] = value[7];
		value[1] = value[6];
		value[2] = value[5];
		value[3] = value[4];
		value[4] = temp[3];
		value[5] = temp[2];
		value[6] = temp[1];
		value[7] = temp[0];
}
/* 
base 64 encodes an arbitrary number of bits without padding

This will produce ceil(number_bits/6) + 1 bytes of data including the null terminator,
so target must have this much space available.

*/
char * encode_bithash(uint64_t hash, char * target, unsigned number_bits)
{
	if (number_bits != 64)
		hash &= ((uint64_t)1 << number_bits)-1;

	// first align the hash in the most significant bits
	hash = hash << (64-number_bits);
	
	// one byte per 6 bits or part there of (excluding null)
	int result_size = number_bits / 6 + (number_bits % 6 ? 1 : 0);

	// worst case is a 64bit hash to encode
	if (!is_big_endian())
	{
		SWAP_BYTES_64(&hash);
	}
	unsigned char * source = (unsigned char *) &hash;

	char temp_result[13];
	apr_base64_encode (temp_result, (void *)source, 8);
	memcpy(target,temp_result,result_size);
	target[result_size]='\0';
	return target;
}

/* 
base 64 decodes an arbitrary number of bits without padding

*/
uint64_t decode_bithash(char * source, unsigned number_bits)
{
	// one byte per 6 bits or part there of (excluding null)
	int source_size = number_bits / 6 + (number_bits % 6 ? 1 : 0);
	// nearest multiple of 3 that will contain our source.
	int true_base64_size = (source_size/3 + (source_size % 3 ? 1 : 0))*3;
	
	char temp_source[13];
	unsigned char target[9];
	memset(&temp_source,'A',sizeof(temp_source));
	memset(&target,0,sizeof(target));
	memcpy(temp_source,source,source_size);
	temp_source[true_base64_size]='\0';
	apr_base64_decode_binary ((void*)target, temp_source);
	uint64_t result = *(uint64_t *) target;
	if (!is_big_endian())
	{
		SWAP_BYTES_64(&result);
	}

	// move the hash back to the least significant bits
	result = result >> (64-number_bits);
	if (number_bits != 64)
		result &= ((uint64_t)1 << number_bits)-1;
	return result;
}


