#include "crccache.h"

#include <stdio.h>
#include <stdint.h>

int sizes[5] = {0,1,30,60,64};
int main()
{
	char result[12];
	int i;
	uint64_t hash = 0x8877665544332211;
	for (i = 0; i < sizeof(sizes)/sizeof(sizes[0]); ++i)
	{
		printf("encoding %d bits of 0x%0lx: %s\n", sizes[i], hash, encode_bithash(hash, result,sizes[i]));
		printf("decoding %d bits of 0x%0lx: %0lx\n", sizes[i], hash, decode_bithash(result,sizes[i]));
	}
return 0;
}
