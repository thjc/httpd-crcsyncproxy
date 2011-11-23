#include "crcsync.h"
#include <ccan/crc/crc.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

/* FIXME: That 64-bit CRC takes a while to warm the lower bits.  Do
 * some quantitative tests and replace it?  Meanwhile, use upper bits. */
static uint64_t mask_of(unsigned int crcbits)
{
	return -1ULL << (64 - crcbits);
}

void crc_of_blocks(const void *data, size_t len, unsigned int normal_block_size,
		   unsigned int tail_block_size,
		   unsigned int crcbits, uint64_t crc[])
{
	unsigned int n_normalblocks = (len-tail_block_size)/normal_block_size;
	unsigned int i;
	const uint8_t *buf = data;
	uint64_t crcmask = mask_of(crcbits);

	for (i = 0; i < n_normalblocks; i++) {
		crc[i] = (crcFast(0, 0, buf, normal_block_size) & crcmask);
		buf += normal_block_size;
		len -= normal_block_size;
	}
	if (tail_block_size != 0) {
		crc[i] = (crcFast(0, 0, buf, len) & crcmask);
	}
}

struct crc_hash_record {
	uint64_t crc;
	int value;
};

struct crc_hash_table {
	unsigned mask;
	struct crc_hash_record *records;
};

struct crc_context {
	const uint64_t *crc64_iso_tab;
	size_t normal_block_size;
	size_t tail_block_size;
	size_t max_block_size;
	uint64_t crcmask;

	/* Saved old buffer bytes (max_block_size bytes). */
	void *buffer;
	size_t buffer_size;
	void *buffer_end; /* invariant to be enforced in code: buffer_end = buffer + buffer_size */

	/* Progress so far. */
	uint64_t running_normal_crc;
	uint64_t running_tail_crc;;
	size_t literal_bytes;
	size_t total_bytes;
	int have_match;

	/* Uncrc tab. */
	uint64_t normal_uncrc_tab[256];
	uint64_t tail_uncrc_tab[256];

	/* last CRC is special */
	uint64_t tail_crc;
	/* This doesn't count the last CRC. */
	unsigned int num_crcs;
	struct crc_hash_table crcs;
};

static uint64_t crc64_over_zeros(const uint64_t *crc64_iso_tab, uint64_t crc, int size)
{	
	while (size--)
	{
		crc = crc64_iso_tab[crc & 0xFFL] ^ (crc >> 8);
	}
	return crc;
}



/* Initialize one table that is used to calculate how the crc changes when we take a give
 * char out of the crc'd area. This function is to be used when there is no tail block */
static void init_uncrc_tab(const uint64_t *crc64_iso_tab, uint64_t uncrc_tab[], unsigned int wsize)
{
	unsigned int i;
	uint64_t part_crc;

	part_crc = crc64_over_zeros(crc64_iso_tab, 0, wsize-1);
	for (i=0; i < 256; i++)
		uncrc_tab[i] = crc64_over_zeros(crc64_iso_tab, crc64_iso_tab[i], wsize-1) ^ part_crc;
}

/* Initialize two tables that are used to calculate how the crc changes when we take a give
 * char out of the crc'd area. This function is to be used when there is a tail block.
 * The function initializes one table for the tail block and another one for the normal block.
 * You must pass the params for the smalles block first followed by the params for the largest block */
static void init_uncrc_tabs(const uint64_t *crc64_iso_tab, uint64_t small_uncrc_tab[], unsigned int small_wsize, uint64_t large_uncrc_tab[], unsigned int large_wsize)
{
	unsigned int i;
	unsigned int delta_wsize = large_wsize - small_wsize;
	uint64_t small_part_crc;
	uint64_t large_part_crc;
	uint64_t crc;

	small_part_crc = crc64_over_zeros(crc64_iso_tab, 0, small_wsize-1);
	large_part_crc = crc64_over_zeros(crc64_iso_tab, small_part_crc, delta_wsize);
	for (i=0; i < 256; i++) {
		crc = crc64_over_zeros(crc64_iso_tab, crc64_iso_tab[i], small_wsize-1);
		small_uncrc_tab[i] = crc ^ small_part_crc;
		crc = crc64_over_zeros(crc64_iso_tab, crc, delta_wsize);
		large_uncrc_tab[i] = crc ^ large_part_crc;
	}
}

static unsigned crc_hashtable_getpos(const struct crc_hash_table *crcs, uint64_t crc)
{
	unsigned mask = crcs->mask;
	struct crc_hash_record *records = crcs->records;
	unsigned pos = (crc >> 32) & mask; // Use highest 32 bits of the checksum as start position
	unsigned step = (1 + (crc & 0x1e)); // Step with an odd-number of steps, exact value depends on crc lowest 5 bits
	
	while (records[pos].value != -1 && records[pos].crc != crc)
	{
		// This position is already taken by another crc record. Go to next position
		pos = (pos + step) & mask;
	}
	return pos;
}

static void crc_hashtable_put(struct crc_hash_table *crcs, uint64_t crc, int value)
{
	unsigned pos = crc_hashtable_getpos(crcs, crc);
	crcs->records[pos].value = value;
	crcs->records[pos].crc = crc;
}

static int crc_hashtable_get(const struct crc_hash_table *crcs, uint64_t crc)
{
	unsigned pos = crc_hashtable_getpos(crcs, crc);
	// Found an empty position (with value -1) or found the entry for the requested CRC
	return crcs->records[pos].value;
}

struct crc_context *crc_context_new(size_t normal_block_size, unsigned crcbits,
				    const uint64_t crc[], unsigned num_crcs,
				    size_t tail_block_size)
{
	struct crc_context *ctx;

	assert(num_crcs > 0);
	assert(normal_block_size > 0);
	assert(tail_block_size >= 0);

	ctx = malloc(sizeof(*ctx) + sizeof(crc[0])*num_crcs);
	if (ctx) {
		ctx->crc64_iso_tab = getCrcTable();
		ctx->normal_block_size = normal_block_size;
		if (tail_block_size == normal_block_size)
		{
			tail_block_size = 0; // treat a tail block with normal block size as a normal block
		}
		ctx->tail_block_size = tail_block_size;
		ctx->max_block_size = (tail_block_size > normal_block_size) ?
					tail_block_size : normal_block_size;
		if (tail_block_size)
			ctx->tail_crc = crc[--num_crcs];

		ctx->crcmask = mask_of(crcbits);
		ctx->num_crcs = num_crcs;
		unsigned crc_hashtable_size = 4;
		while (crc_hashtable_size < 2*num_crcs)
		{
			crc_hashtable_size <<= 1;
		}
		ctx->crcs.mask = crc_hashtable_size-1;
		ctx->crcs.records = malloc(sizeof(struct crc_hash_record)*crc_hashtable_size);
		unsigned cnt;
		for (cnt=0; cnt != crc_hashtable_size; cnt++)
		{
			ctx->crcs.records[cnt].value = -1;
		}
		for (cnt=0; cnt != num_crcs; cnt++)
		{
			crc_hashtable_put(&ctx->crcs, crc[cnt], cnt);
		}
		// memcpy(ctx->crc, crc, sizeof(crc[0])*num_crcs);
		ctx->running_normal_crc = 0;
		ctx->literal_bytes = 0;
		ctx->total_bytes = 0;
		ctx->have_match = -1;
		if (tail_block_size)
		{
			if (tail_block_size < normal_block_size)
				init_uncrc_tabs(ctx->crc64_iso_tab, ctx->tail_uncrc_tab, tail_block_size, ctx->normal_uncrc_tab, normal_block_size);
			else
				init_uncrc_tabs(ctx->crc64_iso_tab, ctx->normal_uncrc_tab, normal_block_size, ctx->tail_uncrc_tab, tail_block_size);
		}
		else
		{
			init_uncrc_tab(ctx->crc64_iso_tab, ctx->normal_uncrc_tab, normal_block_size);
		}
		
		ctx->buffer = malloc(ctx->max_block_size);
		if (!ctx->buffer) {
			free(ctx);
			ctx = NULL;
		}
		else {
			ctx->buffer_size = 0;
			ctx->buffer_end = ctx->buffer;
		}
	}
	return ctx;
}

/* Return -1 or index into matching crc. */
/* Only invoke once you have read enough literal bytes! */
static int crc_matches(const struct crc_context *ctx)
{
	return crc_hashtable_get(&ctx->crcs, ctx->running_normal_crc & ctx->crcmask);
}

/* Return -1 or index of tail crc */
/* Only invoke once you have read enough literal bytes! */
static int tail_matches(const struct crc_context *ctx)
{
	return (ctx->running_tail_crc & ctx->crcmask) == ctx->tail_crc ? ctx->num_crcs : -1;
}

static uint64_t crc_add_byte(const uint64_t *crc64_iso_tab, uint64_t crc, uint8_t newbyte)
{
	return crc64_iso_tab[(crc ^ newbyte) & 0xFFL] ^ (crc >> 8);
}

static uint64_t crc_remove_byte(uint64_t crc, uint8_t oldbyte,
				const uint64_t uncrc_tab[])
{
	return crc ^ uncrc_tab[oldbyte];
}

static uint64_t crc_roll(const uint64_t *crc64_iso_tab, uint64_t crc, uint8_t oldbyte, uint8_t newbyte,
			 const uint64_t uncrc_tab[])
{
	return crc_add_byte(crc64_iso_tab, crc_remove_byte(crc, oldbyte, uncrc_tab), newbyte);
}

enum RB_PHASE { non_rolling, only_tail_rolling, only_normal_rolling, both_rolling };
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

size_t crc_read_block(struct crc_context *ctx, long *result,
		      const void *buf, size_t buflen)
{
	size_t consumed = 0, len;
	int crcmatch = -1;
	const uint8_t *normal_old, *tail_old, *get_pos = buf;
	enum RB_PHASE phase;

	/* Simple optimization, if we found a match last time. */
	if (ctx->have_match >= 0) {
		crcmatch = ctx->have_match;
		goto have_match;
	}

	/* normal_old is the trailing edge of the normal checksum window. */
	if (ctx->buffer_size >= ctx->normal_block_size)
		normal_old = ctx->buffer_end - ctx->normal_block_size;
	else
		normal_old = NULL;

	/* tail_old is the trailing edge of the tail checksum window. */
	if (ctx->tail_block_size != 0 && ctx->buffer_size >= ctx->tail_block_size)
		tail_old = ctx->buffer_end - ctx->tail_block_size;
	else
		tail_old = NULL;

	if (normal_old == NULL && tail_old == NULL)
		phase = non_rolling;
	else 
		if (normal_old == NULL)
			phase = only_tail_rolling;
		else
			if (tail_old == NULL)
				phase = only_normal_rolling;
			else
				phase = both_rolling;

	while (consumed != buflen && crcmatch == -1) {
		size_t old_consumed = consumed;
		switch (phase)
		{
		case non_rolling:
			{
				size_t nbytes;
				if (ctx->tail_block_size)
				{
					nbytes = MIN(buflen - consumed, MIN(ctx->normal_block_size - ctx->literal_bytes, ctx->tail_block_size - ctx->literal_bytes));
					ctx->running_tail_crc = ctx->running_normal_crc = crcFast(0, ctx->running_normal_crc, get_pos, nbytes);
				}
				else
				{
					nbytes = MIN(buflen - consumed, ctx->normal_block_size - ctx->literal_bytes);
					ctx->running_normal_crc = crcFast(0, ctx->running_normal_crc, get_pos, nbytes);
				}
				consumed += nbytes;
				ctx->literal_bytes += nbytes;
				get_pos += nbytes;
				if (ctx->literal_bytes == ctx->normal_block_size) {
					/* Reached the end of a normal block. Check CRC
					   and start rolling the CRC at next iteration */
					if ((crcmatch = crc_matches(ctx)) != -1)
						break;
					normal_old = (ctx->buffer_size != 0) ? ctx->buffer : buf;
					phase = only_normal_rolling;
				}
				else if (ctx->literal_bytes == ctx->tail_block_size) {
					/* Reached the end of a tail block. Check tail CRC
					   and start rolling the CRC at next iteration */
					if ((crcmatch = tail_matches(ctx)) != -1)
						break;
					tail_old = (ctx->buffer_size != 0) ? ctx->buffer : buf;
					phase = only_tail_rolling;
				}
			}
			break;
		case only_normal_rolling:
			while (consumed != buflen)
			{
				consumed++;
				ctx->literal_bytes++;
				ctx->running_normal_crc = crc_roll(ctx->crc64_iso_tab,
								ctx->running_normal_crc,
							    *normal_old, *get_pos,
							    ctx->normal_uncrc_tab);
				if ((crcmatch = crc_matches(ctx)) != -1)
					break;
				/* Advance trailing pointer for normal CRC */
				if (++normal_old == ctx->buffer_end)
					normal_old = buf;
				if (ctx->tail_block_size) {
					ctx->running_tail_crc = crc_add_byte(ctx->crc64_iso_tab, ctx->running_tail_crc, *get_pos++);
					if (ctx->literal_bytes == ctx->tail_block_size)
					{
						if ((crcmatch = tail_matches(ctx)) != -1)
							break;
						tail_old = (ctx->buffer_size != 0) ? ctx->buffer : buf;
						phase = both_rolling;
						break;
					}		
				}
				else
					get_pos++;
			}
			break;
		case only_tail_rolling:
			while (consumed != buflen)
			{
				consumed++;
				ctx->literal_bytes++;
				ctx->running_tail_crc = crc_roll(ctx->crc64_iso_tab,
								ctx->running_tail_crc,
							    *tail_old, *get_pos,
							    ctx->tail_uncrc_tab);
				if ((crcmatch = tail_matches(ctx)) != -1)
					break;
				/* Advance trailing pointer for tail CRC */
				if (++tail_old == ctx->buffer_end)
					tail_old = buf;
				ctx->running_normal_crc = crc_add_byte(ctx->crc64_iso_tab, ctx->running_normal_crc, *get_pos++);
				if (ctx->literal_bytes == ctx->normal_block_size)
				{
					if ((crcmatch = crc_matches(ctx)) != -1)
						break;
					normal_old = (ctx->buffer_size != 0) ? ctx->buffer : buf;
					phase = both_rolling;
					break;
				}
			}
			break;
		case both_rolling:
			while (consumed != buflen)
			{
				consumed++;
				ctx->running_normal_crc = crc_roll(ctx->crc64_iso_tab,
								ctx->running_normal_crc,
							    *normal_old, *get_pos,
							    ctx->normal_uncrc_tab);
				if ((crcmatch = crc_matches(ctx)) != -1)
					break;
				/* Advance trailing pointer for normal CRC */
				if (++normal_old == ctx->buffer_end)
					normal_old = buf;
				ctx->running_tail_crc = crc_roll(ctx->crc64_iso_tab,
								ctx->running_tail_crc,
							    *tail_old, *get_pos,
							    ctx->tail_uncrc_tab);
				if ((crcmatch = tail_matches(ctx)) != -1)
					break;
				/* Advance trailing pointer for tail CRC */
				if (++tail_old == ctx->buffer_end)
					tail_old = buf;
				get_pos++;
			}
			ctx->literal_bytes += (consumed - old_consumed);
			break;
		}
		ctx->total_bytes += (consumed - old_consumed);
	}
	
	if (crcmatch >= 0) {
		/* We have a match! */
		size_t matched_block_size = (crcmatch == ctx->num_crcs) ?
			ctx->tail_block_size : ctx->normal_block_size;
		if (ctx->literal_bytes > matched_block_size) {
			/* Output literal first. */
			*result = ctx->literal_bytes - matched_block_size;
			ctx->literal_bytes = matched_block_size;
			/* Remember for next time! */
			ctx->have_match = crcmatch;
		} else {
		have_match:
			*result = -crcmatch-1;
			if (crcmatch == ctx->num_crcs)
				assert(ctx->literal_bytes == ctx->tail_block_size);
			else
				assert(ctx->literal_bytes == ctx->normal_block_size);
			ctx->literal_bytes = 0;
			ctx->have_match = -1;
			ctx->running_normal_crc = 0;
			ctx->running_tail_crc = 0;
			/* Nothing more in the buffer. */
			ctx->buffer_size = 0;
			ctx->buffer_end = ctx->buffer;
		}
	} else {
		/* Output literal if it's more than 1 block ago and 
		   keep exactly one block of data for future matching. */
		if (ctx->literal_bytes > ctx->max_block_size) {
			*result = ctx->literal_bytes - ctx->max_block_size;
			ctx->literal_bytes = ctx->max_block_size; 
			/* Advance buffer. */
			if (*result >= ctx->buffer_size) {
				ctx->buffer_size = 0;
				ctx->buffer_end = ctx->buffer;
			}
			else
			{
				memmove(ctx->buffer, ctx->buffer + *result,
					ctx->buffer_size);
				ctx->buffer_size -= *result;
				ctx->buffer_end -= *result;
			}
		} else
			*result = 0;

		/* Now save any literal bytes we'll need in future. */
		len = ctx->literal_bytes - ctx->buffer_size;
		memcpy(ctx->buffer_end, buf + buflen - len, len);
		ctx->buffer_size += len;
		ctx->buffer_end += len;
		assert(ctx->buffer_size <= ctx->max_block_size);
	}
	return consumed;
}

long crc_read_flush(struct crc_context *ctx)
{
	long ret;

	/* We might have ended right on a matched block. */
	if (ctx->have_match != -1) {
		size_t matched_block_size = (ctx->have_match == ctx->num_crcs) ?
			ctx->tail_block_size : ctx->normal_block_size;
		ctx->literal_bytes -= matched_block_size;
		assert(ctx->literal_bytes == 0);
		ret = -ctx->have_match-1;
		ctx->have_match = -1;
		ctx->running_normal_crc = 0;
		ctx->running_tail_crc = 0;
		/* Nothing more in the buffer. */
		ctx->buffer_size = 0;
		ctx->buffer_end = ctx->buffer;
		return ret;
	}

	/* The rest is just a literal. */
	ret = ctx->buffer_size;
	assert(ctx->literal_bytes == ret);
	ctx->buffer_size = 0;
	ctx->buffer_end = ctx->buffer;
	ctx->literal_bytes = 0;
	return ret;
}

void crc_reset_running_crcs(struct crc_context *ctx)
{
	ctx->running_normal_crc = 0;
	ctx->running_tail_crc = 0;
}

/**
 * crc_context_free - free a context returned from crc_context_new.
 * @ctx: the context returned from crc_context_new, or NULL.
 */
void crc_context_free(struct crc_context *ctx)
{
	free(ctx->buffer);
	free(ctx);
}
