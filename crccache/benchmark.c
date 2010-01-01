#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <gcrypt.h>
#include "zlib.h"
#include <crcsync/crcsync.h>

#define FULL_BLOCK_COUNT 40
const int HASH_SIZE = 64;
const int TEST_ITERATIONS_COUNT = 100;

void error(char *msg)
{
	printf("Error code: %d, msg: %s", errno, msg);
	exit(1);
}

typedef struct
{
	unsigned char *buf;
	size_t bufsize;
	size_t datasize;
} data_t;

data_t *init_data()
{
	data_t *data = malloc(sizeof(data));
	if (data == NULL)
	{
		error("Can not allocate data_t structure");
	}
	data->bufsize = 10000;
	data->datasize = 0;
	data->buf = malloc(data->bufsize);
	if (data->buf == NULL)
	{
		error("Can not allocate databuf");
	}
	return data;
}

void append_data(data_t *data, unsigned char *buf, ssize_t bufsize)
{
	while (data->datasize + bufsize > data->bufsize)
	{
		unsigned char *newdatabuf = realloc(data->buf, data->bufsize*2);
		if (newdatabuf == NULL)
		{
			error("Can not re-allocate databuf");
		}
		data->buf = newdatabuf;
		data->bufsize *= 2;
	}
	memcpy(data->buf + data->datasize, buf, bufsize);
	data->datasize += bufsize;
}

void free_data(data_t *data)
{
	free(data->buf);
	free(data);
}

data_t *read_file_to_data(char *fname)
{
	int fh = open(fname, O_RDONLY);
	if (fh == -1)
	{
		error("Can not open file");
	}
	
	data_t *data = init_data();
	unsigned char readbuf[1000];
	ssize_t nread;
	while ((nread = read(fh, readbuf, sizeof(readbuf))) != 0)
	{
		append_data(data, readbuf, nread);
	}
	
	close(fh);
	
	return data;
}


void crcvalidate_data(data_t *data, struct crc_context *crcctx)
{

	long rd_block_rslt;
	unsigned char *getpos = data->buf;
	ssize_t remaining = data->datasize;
	// printf("rslts: ");
	while (remaining != 0)
	{
		size_t ndigested = crc_read_block(crcctx, &rd_block_rslt, getpos, remaining);
		// printf("%ld ", rd_block_rslt);
		getpos += ndigested;
		remaining -= ndigested;
	}
	rd_block_rslt = crc_read_flush(crcctx);
	// printf("%ld ", rd_block_rslt);
	// printf("\n");
	crc_reset_running_crcs(crcctx);	
}

void sha256_data(data_t *data)
{
	/* Length of resulting sha1 hash - gcry_md_get_algo_dlen
	* returns digest lenght for an algo */
	int hash_len = gcry_md_get_algo_dlen( GCRY_MD_SHA256 );

	/* output SHA256 hash - this will be binary data */
	unsigned char hash[ hash_len ];
	
	/* calculate the SHA256 digest. This is a bit of a shortcut function
	* most gcrypt operations require the creation of a handle, etc. */
	gcry_md_hash_buffer( GCRY_MD_SHA1, hash, data->buf, data->datasize );

	
}

ssize_t compress_tst(unsigned char *org_data_buf, size_t orglen, unsigned char *compressed_data_buf, size_t compressed_size)
{
	z_stream compression_stream;
	compression_stream.zalloc = Z_NULL;
	compression_stream.zfree = Z_NULL;
	compression_stream.opaque = Z_NULL;
	int zRC = deflateInit(&compression_stream, Z_DEFAULT_COMPRESSION);
	if (zRC != Z_OK)
	{
		error("deflateInit returned an error code");
	}
	compression_stream.avail_in = orglen;
	compression_stream.next_in = org_data_buf;
	compression_stream.avail_out = compressed_size;
	compression_stream.next_out = compressed_data_buf;
	zRC = deflate(&compression_stream, Z_FINISH);
	if (zRC == Z_STREAM_ERROR)
	{
		error("deflate returned Z_ERROR");
	}
	if (compression_stream.avail_in != 0)
	{
		error("decompression buffer was too small");
	}
	return compressed_size - compression_stream.avail_out;
}

ssize_t decompress_tst(unsigned char *org_data_buf, size_t org_size, unsigned char *compressed_data_buf, size_t compressed_len)
{
	z_stream decompression_stream;
	decompression_stream.zalloc = Z_NULL;
	decompression_stream.zfree = Z_NULL;
	decompression_stream.opaque = Z_NULL;
	decompression_stream.avail_in = 0;
	decompression_stream.next_in = Z_NULL;
	int zRC = inflateInit(&decompression_stream);
	if (zRC != Z_OK)
	{
		error("inflateInit returned an error code");
	}
	decompression_stream.avail_in = compressed_len;
	decompression_stream.next_in = compressed_data_buf;
	decompression_stream.avail_out = org_size;
	decompression_stream.next_out = org_data_buf;
	zRC = inflate(&decompression_stream, Z_NO_FLUSH);
	if (zRC == Z_NEED_DICT || zRC == Z_DATA_ERROR || zRC == Z_MEM_ERROR)
	{
		error("inflate returned Z_NEED_DIC, Z_DATA_ERROR or Z_MEM_ERROR");
	}
	if (decompression_stream.avail_in != 0)
	{
		error("org data buffer was too small");
	}
	if (zRC != Z_STREAM_END)
	{
		error("inflate did not return Z_STREAM_END");
	}
	return org_size - decompression_stream.avail_out;
}


int contains(uint64_t *hashes, uint64_t value, int cnt)
{
	while (cnt-- != 0)
	{
		if (hashes[cnt] == value)
		{
			return 1;
		}
	}
	return 0;
}

typedef struct
{
	clock_t start;
	clock_t end;
} benchmark_t;

double duration_ms(benchmark_t *bm)
{
	return 1000 * (bm->end - bm->start + 0.0)/CLOCKS_PER_SEC;
}

int main(int argc, char *argv[])
{
	int cnt;

	int merge_trailing_blocks_in_last_block;
	for (merge_trailing_blocks_in_last_block = 0; merge_trailing_blocks_in_last_block != 2; merge_trailing_blocks_in_last_block++)
	{
	// Load the data
	data_t *original_data = read_file_to_data(argv[1]);
	printf("Original data size: %zu\n", original_data->datasize);
	
	//Set-up buffer for compressed data. Make it twice as long as the original_data
	// so that even in a worst-case scenario of totally non-compressable data, it will still
	// fit, withouth causing an buffer overflow
	data_t *compressed_data = init_data();
	append_data(compressed_data, original_data->buf, original_data->bufsize);
	append_data(compressed_data, original_data->buf, original_data->bufsize);
	// Benchmark the compression
	benchmark_t bm_compress;
	bm_compress.start = clock();
	for (cnt=0; cnt != TEST_ITERATIONS_COUNT; cnt++)
	{
		compressed_data->datasize = compress_tst(original_data->buf, original_data->datasize, compressed_data->buf, compressed_data->bufsize);
	}
	bm_compress.end = clock();
	printf("Compressed data size: %zu\n", compressed_data->datasize);

	
	// Parameters for the hashes
	size_t block_size = original_data->datasize/FULL_BLOCK_COUNT;
	size_t tail_block_size = original_data->datasize%FULL_BLOCK_COUNT;
	if (merge_trailing_blocks_in_last_block)
	{
		tail_block_size += block_size;
	}
	size_t block_count_including_final_block = FULL_BLOCK_COUNT + (tail_block_size != 0 && !merge_trailing_blocks_in_last_block);

	// Set-up hashes for a perfect match and benchmark how long it takes
	uint64_t match_hashes[block_count_including_final_block];
	benchmark_t bm_crccalculate;
	bm_crccalculate.start = clock();
	for (cnt=0; cnt != TEST_ITERATIONS_COUNT; cnt++)
	{
		crc_of_blocks(original_data->buf, original_data->datasize, block_size, HASH_SIZE, merge_trailing_blocks_in_last_block, match_hashes);
	}
	bm_crccalculate.end = clock();
	
	// Benchmark reconstructing a page from literal blocks
	unsigned char *reconstructed_buf = malloc(original_data->datasize);
	benchmark_t bm_reconstruct;
	bm_reconstruct.start = clock();
	for (cnt=0; cnt != TEST_ITERATIONS_COUNT; cnt++)
	{
		int blocks_cnt;
		for (blocks_cnt=0; blocks_cnt != FULL_BLOCK_COUNT; blocks_cnt++)
		{
			memcpy(reconstructed_buf+blocks_cnt*block_size, (original_data->buf)+blocks_cnt*block_size, block_size);
		}
		if (tail_block_size != 0 && !merge_trailing_blocks_in_last_block)
		{
			memcpy(reconstructed_buf+blocks_cnt*block_size, (original_data->buf)+blocks_cnt*block_size, tail_block_size);
		}
	}
	bm_reconstruct.end = clock();
	
	// Set-up hashes for a perfect mismatch
	uint64_t nomatch_hashes[block_count_including_final_block];
	uint64_t value = 0;
	for (cnt=0; cnt != block_count_including_final_block; cnt++)
	{
		while (contains(match_hashes, value, block_count_including_final_block))
		{
			value++;
		}
		nomatch_hashes[cnt] = value;
	}
	
	struct crc_context *crcctx;
	benchmark_t bm_crc_context_new;
	bm_crc_context_new.start = clock();
	for (cnt=0; cnt != TEST_ITERATIONS_COUNT; cnt++)
	{
		crcctx = crc_context_new(block_size, HASH_SIZE, match_hashes, block_count_including_final_block, tail_block_size);
	}
	bm_crc_context_new.end = clock();
	
	benchmark_t bm_crcvalidate_match;
	bm_crcvalidate_match.start = clock();
	for (cnt=0; cnt != TEST_ITERATIONS_COUNT; cnt++)
	{
		crcvalidate_data(original_data, crcctx);
	}
	bm_crcvalidate_match.end = clock();

	crcctx = crc_context_new(block_size, HASH_SIZE, nomatch_hashes, block_count_including_final_block, tail_block_size);
	benchmark_t bm_crcvalidate_nomatch;
	bm_crcvalidate_nomatch.start = clock();
	for (cnt=0; cnt != TEST_ITERATIONS_COUNT; cnt++)
	{
		crcvalidate_data(original_data, crcctx);
	}
	bm_crcvalidate_nomatch.end = clock();

	crc_context_free(crcctx);

	benchmark_t bm_sha256;
	bm_sha256.start = clock();
	for (cnt=0; cnt != TEST_ITERATIONS_COUNT; cnt++)
	{
		sha256_data(original_data);
	}
	bm_sha256.end = clock();

	benchmark_t bm_decompress;
	bm_decompress.start = clock();
	for (cnt=0; cnt != TEST_ITERATIONS_COUNT; cnt++)
	{
		original_data->datasize = decompress_tst(original_data->buf, original_data->bufsize, compressed_data->buf, compressed_data->datasize);
	}
	bm_decompress.end = clock();
	printf("Original data size after decompression: %zd\n", original_data->datasize);
	
	printf(
			"Nblocks: %zd, Block size: %zd, Tail block size: %zd, Compress: %.4f ms, Decompress: %.4f ms, Copy blocks: %.4f ms, New CRCCTX: %.4f ms, Calculate CRCs: %.4f ms, Validate match: %.4f ms, Validate nomatch: %.4f ms, SHA256: %.4f ms\n", 
			block_count_including_final_block, block_size, tail_block_size,
			duration_ms(&bm_compress)/TEST_ITERATIONS_COUNT,
			duration_ms(&bm_decompress)/TEST_ITERATIONS_COUNT,
			duration_ms(&bm_reconstruct)/TEST_ITERATIONS_COUNT,
			duration_ms(&bm_crc_context_new)/TEST_ITERATIONS_COUNT,
			duration_ms(&bm_crccalculate)/TEST_ITERATIONS_COUNT,
			duration_ms(&bm_crcvalidate_match)/TEST_ITERATIONS_COUNT,
			duration_ms(&bm_crcvalidate_nomatch)/TEST_ITERATIONS_COUNT,
			duration_ms(&bm_sha256)/TEST_ITERATIONS_COUNT
			);
//	printf(
//			"Nblocks: %zd, Block size: %zd, Tail block size: %zd, New CRCCTX: %.4f ms, Calculate CRCs: %.4f ms, Validate match: %.4f ms, Validate nomatch: %.4f ms\n", 
//			block_count_including_final_block, block_size, tail_block_size,
//			duration_ms(&bm_crc_context_new)/TEST_ITERATIONS_COUNT,
//			duration_ms(&bm_crccalculate)/TEST_ITERATIONS_COUNT,
//			duration_ms(&bm_crcvalidate_match)/TEST_ITERATIONS_COUNT,
//			duration_ms(&bm_crcvalidate_nomatch)/TEST_ITERATIONS_COUNT
//			);

	free_data(original_data);
	}
	return 0;
}
