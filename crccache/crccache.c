/*
 * crccache.c
 *
 *  Created on: 22/02/2009
 *      Author: Toby Collett
 */

#include <string.h>
#include <apr_base64.h>

/* fills in the first 5 bytes of target with the base64 bit encoded hash

it is endian safe, and adds a null terminator, so target must have space for 6 bytes
*/
char * encode_30bithash(unsigned hash, char * target)
{
	char temp_result[9];
	unsigned char source[4];
	// possibly a faster way, but needs to be endian safe, including bit endianness
	source[0]=(hash&0x3fc00000)>>22;
	source[1]=(hash&0x003fc000)>>14;
	source[2]=(hash&0x00003fc0)>>6;
	source[3]=(hash&0x0000003f)<<2;

	apr_base64_encode (temp_result, (void *)source, 4);
	memcpy(target,temp_result,5);
	target[5]='\0';
	return target;
}


/* decodes a 5 bytes base 64bit string to the lower 30 bits of an int

it is endian safe, and assumes an input string of 5 bytes
*/
unsigned decode_30bithash(const char * source)
{
	char temp_source[9];
	unsigned char target[7];
	memcpy(temp_source,source,5);
	temp_source[5]='0';
	temp_source[6]='0';
	temp_source[7]='0';
	temp_source[8]='\0';

	apr_base64_decode ((void*)target, temp_source);
	unsigned result;
	result  = target[0] << 22;
	result |= target[1] << 14;
	result |= target[2] << 6;
	result |= target[3] >> 2;

	return result;
}
