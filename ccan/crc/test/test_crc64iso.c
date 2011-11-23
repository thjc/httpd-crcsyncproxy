#include "crc/crc.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

static int show_results(char *description, uint64_t rslt_pd_slow, uint64_t rslt_pd_fast, uint64_t expected)
{
	int mismatch=(rslt_pd_slow != expected) | (rslt_pd_fast != expected);
	printf(
		"%-15.15s %016"PRIx64" %016"PRIx64" %016"PRIx64" %s\n",
		description, rslt_pd_slow, rslt_pd_fast, expected, mismatch? "Wrong": "Ok"
	);
	return mismatch;
}

static int test_crc64(char *filename, uint64_t expected)
{
	char buf[1024];
	int fh = open(filename, O_RDONLY);
	if (fh == -1) {
		printf("Unable to open file %s\n", filename);
		exit(1);
	}
	size_t filesize = 0;
	size_t nread = 0;
	while ((nread = read(fh, buf+filesize, 1024-filesize)) != 0) {
		filesize += nread;
	}
	close(fh);
	return show_results(
		filename,
		crcSlow(0, (uint64_t)0, (const unsigned char *)buf, filesize),
		crcFast(0, (uint64_t)0, (const unsigned char *)buf, filesize),
		expected
	);
}

void dump_crcTableRow(const uint64_t *values, int ncols)
{
	while (ncols--) {
		printf("%016"PRIx64" ", *values++);
	}
}

void dump_crcTable()
{
	printf("CRC Table for fast CRC calculation\n");
	crc *crcTable = getCrcTable();
	int cnt=0;
	int ncols=4;
	for (cnt=0; cnt != 256; cnt+=ncols) {
		dump_crcTableRow(crcTable + cnt, ncols);
		printf("\n");
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	dump_crcTable();

	int errors=0;
	printf("%-15.15s %-16.16s %-16.16s %-16.16s Status\n", 
		"Description", "CRC-Slow", "CRC-Fast", "Expected");
	errors += test_crc64("zeros.dat", (uint64_t)0);
	errors += test_crc64("random.dat", (uint64_t)0xee3b6bcbb8c787fb);
	errors += show_results(
		"123456789",
		crcSlow(0, (uint64_t)0, (unsigned char *)"123456789", 9),
		crcFast(0, (uint64_t)0, (unsigned char *)"123456789", 9),
		0x46a5a9388a5beffe
	);
	return errors;
}
