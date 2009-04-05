#include "crcsync.h"
#include <ccan/crc/crc.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

void crc_of_blocks(const void *data, size_t len, unsigned int block_size,
		   unsigned int crcbits, uint32_t crc[])
{
	unsigned int i;
	const uint8_t *buf = data;
	uint32_t crcmask = crcbits < 32 ? (1 << crcbits) - 1 : 0xFFFFFFFF;

	for (i = 0; len >= block_size; i++) {
		crc[i] = (crc32c(0, buf, block_size) & crcmask);
		buf += block_size;
		len -= block_size;
	}
	if (len)
		crc[i] = (crc32c(0, buf, len) & crcmask);
}

struct crc_context {
	size_t block_size;
	uint32_t crcmask;

	/* Saved old buffer bytes (block_size bytes). */
	void *buffer;
	size_t buffer_start, buffer_end;

	/* Progress so far. */
	uint32_t running_crc;
	size_t literal_bytes;
	size_t total_bytes;
	int have_match;

	/* Final block is special (if a different size) */
	size_t final_size;
	uint32_t final_crc;

	/* Uncrc tab. */
	uint32_t uncrc_tab[256];

	/* This doesn't count the last CRC. */
	unsigned int num_crcs;
	uint32_t crc[];
};

/* Calculate the how the crc changes when we take a give char out of the
 * crc'd area. */
static void init_uncrc_tab(uint32_t uncrc_tab[], unsigned int wsize)
{
	unsigned int i;
	uint32_t part_crc;
	uint8_t buffer[wsize];

	/* Calculate crc(buffer+1, wsize-1) once, since it doesn't change. */
	memset(buffer, 0, wsize);
	part_crc = crc32c(0, buffer+1, wsize-1);

	for (i = 0; i < 256; i++) {
		buffer[0] = i;
		uncrc_tab[i] = (crc32c(0, buffer, wsize) ^ part_crc);
	}
}

struct crc_context *crc_context_new(size_t block_size, unsigned crcbits,
				    const uint32_t crc[], unsigned num_crcs,
				    size_t final_size)
{
	struct crc_context *ctx;

	assert(num_crcs > 0);
	assert(block_size > 0);
	assert(final_size < block_size);

	ctx = malloc(sizeof(*ctx) + sizeof(crc[0])*num_crcs);
	if (ctx) {
		ctx->block_size = block_size;
		ctx->final_size = final_size; // If it is 0, we never compare against it
		if (final_size != 0) {
			ctx->final_crc = crc[--num_crcs];
		}

		/* Technically, 1 << 32 is undefined. */
		if (crcbits >= 32)
			ctx->crcmask = 0xFFFFFFFF;
		else
			ctx->crcmask = (1 << crcbits)-1;
		ctx->num_crcs = num_crcs;
		memcpy(ctx->crc, crc, sizeof(crc[0])*num_crcs);
		ctx->buffer_end = 0;
		ctx->buffer_start = 0;
		ctx->running_crc = 0;
		ctx->literal_bytes = 0;
		ctx->total_bytes = 0;
		ctx->have_match = -1;
		init_uncrc_tab(ctx->uncrc_tab, block_size);
		ctx->buffer = malloc(block_size);
		if (!ctx->buffer) {
			free(ctx);
			ctx = NULL;
		}
	}
	return ctx;
}

/* Return -1 or index into matching crc. */
static int crc_matches(const struct crc_context *ctx)
{
	unsigned int i;

	if (ctx->literal_bytes < ctx->block_size)
		return -1;

	for (i = 0; i < ctx->num_crcs; i++)
		if ((ctx->running_crc & ctx->crcmask) == ctx->crc[i])
			return i;
	return -1;
}

static bool final_matches(const struct crc_context *ctx)
{
	if (ctx->literal_bytes != ctx->final_size)
		return false;

	return (ctx->running_crc & ctx->crcmask) == ctx->final_crc;
}

static uint32_t crc_add_byte(uint32_t crc, uint8_t newbyte)
{
	return crc32c(crc, &newbyte, 1);
}

static uint32_t crc_remove_byte(uint32_t crc, uint8_t oldbyte,
				const uint32_t uncrc_tab[])
{
	return crc ^ uncrc_tab[oldbyte];
}

static uint32_t crc_roll(uint32_t crc, uint8_t oldbyte, uint8_t newbyte,
			 const uint32_t uncrc_tab[])
{
	return crc_add_byte(crc_remove_byte(crc, oldbyte, uncrc_tab), newbyte);
}

static size_t buffer_size(const struct crc_context *ctx)
{
	return ctx->buffer_end - ctx->buffer_start;
}

size_t crc_read_block(struct crc_context *ctx, long *result,
		      const void *buf, size_t buflen)
{
	size_t consumed = 0, len;
	int crcmatch = -1;
	const uint8_t *old, *p = buf;

	/* Simple optimization, if we found a match last time. */
	if (ctx->have_match >= 0) {
		crcmatch = ctx->have_match;
		goto have_match;
	}

	/* old is the trailing edge of the checksum window. */
	if (buffer_size(ctx) >= ctx->block_size)
		old = ctx->buffer + ctx->buffer_start;
	else
		old = NULL;

	while (ctx->literal_bytes < ctx->block_size
	       || (crcmatch = crc_matches(ctx)) < 0) {
		if (consumed == buflen)
			break;

		/* Increment these now in case we hit goto: below. */
		ctx->literal_bytes++;
		ctx->total_bytes++;
		consumed++;

		/* Update crc. */
		if (old) {
			ctx->running_crc = crc_roll(ctx->running_crc,
						    *old, *p,
						    ctx->uncrc_tab);
			old++;
			/* End of stored buffer?  Start on data they gave us. */
			if (old == ctx->buffer + ctx->buffer_end)
				old = buf;
		} else {
			ctx->running_crc = crc_add_byte(ctx->running_crc, *p);
			if (p == (uint8_t *)buf + ctx->block_size - 1)
				old = buf;
			/* We don't roll this csum, we only look for it after
			 * a block match.  It's simpler and faster. */
			if (final_matches(ctx)) {
				crcmatch = ctx->num_crcs;
				goto have_match;
			}
		}
		p++;
	}

	if (crcmatch >= 0) {
		/* We have a match! */
		if (ctx->literal_bytes > ctx->block_size) {
			/* Output literal first. */
			*result = ctx->literal_bytes - ctx->block_size;
			ctx->literal_bytes = ctx->block_size;
			/* Remember for next time! */
			ctx->have_match = crcmatch;
		} else {
		have_match:
			*result = -crcmatch-1;
			if (crcmatch == ctx->num_crcs)
				assert(ctx->literal_bytes == ctx->final_size);
			else
				assert(ctx->literal_bytes == ctx->block_size);
			ctx->literal_bytes = 0;
			ctx->have_match = -1;
			ctx->running_crc = 0;
			/* Nothing more in the buffer. */
			ctx->buffer_start = ctx->buffer_end = 0;
		}
	} else {
		/* Output literal if it's more than 1 block ago. */
		if (ctx->literal_bytes > ctx->block_size) {
			*result = ctx->literal_bytes - ctx->block_size;
			ctx->literal_bytes -= *result;
			/* Advance buffer. */
			if (*result >= buffer_size(ctx))
				ctx->buffer_start = ctx->buffer_end = 0;
			else
				ctx->buffer_start += *result;
		} else
			*result = 0;

		/* Now save any literal bytes we'll need in future. */
		len = ctx->literal_bytes - buffer_size(ctx);

		/* Move down old data if we don't have room.  */
		if (ctx->buffer_end + len > ctx->block_size) {
			memmove(ctx->buffer, ctx->buffer + ctx->buffer_start,
				buffer_size(ctx));
			ctx->buffer_end -= ctx->buffer_start;
			ctx->buffer_start = 0;
		}

		/* Copy len bytes from tail of buffer. */
		memcpy(ctx->buffer + ctx->buffer_end, buf + buflen - len, len);
		ctx->buffer_end += len;
		assert(buffer_size(ctx) <= ctx->block_size);
	}
	return consumed;
}

long crc_read_flush(struct crc_context *ctx)
{
	long ret;

	/* We might have ended right on a matched block. */
	if (ctx->have_match != -1) {
		ctx->literal_bytes -= ctx->block_size;
		assert(ctx->literal_bytes == 0);
		ret = -ctx->have_match-1;
		ctx->have_match = -1;
		ctx->running_crc = 0;
		/* Nothing more in the buffer. */
		ctx->buffer_start = ctx->buffer_end;
		return ret;
	}

	/* The rest is just a literal. */
	ret = buffer_size(ctx);
	assert(ctx->literal_bytes == ret);
	ctx->buffer_start = ctx->buffer_end = 0;
	ctx->literal_bytes = 0;
	return ret;
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
