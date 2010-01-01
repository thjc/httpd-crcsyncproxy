#include <sys/types.h>
#include <crcsync/crcsync.h>
#include <stdio.h>
#include <string.h>


void validate(struct crc_context *crcctx)
{
	char *getpos = "XXXXXX0123XXXXXXXXXX456789ABXCDEFZZX"; // same data but starting with two mismatch characters 
	ssize_t remaining = strlen(getpos);
	long rd_block_rslt;
	while (remaining != 0)
	{
		size_t ndigested = crc_read_block(crcctx, &rd_block_rslt, getpos, (remaining > 3) ? 3: remaining);
		printf("read block rslt: %ld, ndigested: %zd\n", rd_block_rslt, ndigested);
		getpos += ndigested;
		remaining -= ndigested;
	}
	rd_block_rslt = crc_read_flush(crcctx);
	printf("flush rslt: %ld\n", rd_block_rslt);
	crc_reset_running_crcs(crcctx);
}

int main(int argc, char *argv[])
{
	char *tstdata = "0123456789ABCDEFZ";
	size_t nblocks = 4;
	uint64_t hashes[nblocks];
	size_t datalen = strlen(tstdata);
	size_t block_size = datalen/nblocks;
	crc_of_blocks(tstdata, datalen, block_size, 64, true, hashes); // set-up hashes
	
	
	size_t tail_size = block_size + datalen%nblocks;
	printf("block_size: %zd, tail_size: %zd, nblocks: %zd\n", block_size, tail_size, nblocks);
	struct crc_context *crcctx = crc_context_new(block_size, 64, hashes, nblocks, tail_size);
	printf("context initialized\n");

	validate(crcctx);
	validate(crcctx);
	
	crc_context_free(crcctx);


	return 0;
}