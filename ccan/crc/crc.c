/**********************************************************************
 *
 * Filename:    crc.c
 * 
 * Description: Slow and fast implementations of the CRC standards.
 *
 * Notes:       The parameters for each supported CRC standard are
 *				defined in the header file crc.h.  The implementations
 *				here should stand up to further additions to that list.
 *
 * 
 * Copyright (c) 2000 by Michael Barr.  This software is placed into
 * the public domain and may be used for any purpose.  However, this
 * notice must not be changed or removed and no warranty is either
 * expressed or implied by its publication or distribution.
 *
 * Updates performed on 2011-11-20 by Alex Wulms:
 *   - Added support for CRC64_ISO
 *   - Optimized situation whereby REFLECT_DATA and REFLECT_REMAINDER
 *     are both TRUE_CRC (like in the case of CRC64_ISO)
 *   - Exposed CRC lookup table to client programs
 * These modifications are available under the same conditions as the
 * original code by Michael Barr.
 **********************************************************************/
 
#include "crc.h"


/*
 * Derive parameters from the standard-specific parameters in crc.h.
 */
#define WIDTH    (8 * sizeof(crc))
#define TOPBIT   (((crc)1) << (WIDTH - 1))

#if (REFLECT_DATA == TRUE_CRC)
#define REFLECT_DATA_FUNC(X)			((uint8_t) reflect((X), 8))
#else
#define REFLECT_DATA_FUNC(X)			(X)
#endif

#if (REFLECT_REMAINDER == TRUE_CRC)
#define REFLECT_REMAINDER_FUNC(X)	((crc) reflect((X), WIDTH))
#else
#define REFLECT_REMAINDER_FUNC(X)	(X)
#endif


/*********************************************************************
 *
 * Function:    reflect()
 * 
 * Description: Reorder the bits of a binary sequence, by reflecting
 *				them about the middle position.
 *
 * Notes:		No checking is done that nBits <= sizeof(crc).
 *
 * Returns:		The reflection of the original data.
 *
 *********************************************************************/
#if (REFLECT_DATA == TRUE_CRC) || (REFLECT_REMAINDER == TRUE_CRC)
static crc
reflect(crc data, uint8_t nBits)
{
	crc reflection = 0;

	/*
	 * Reflect the data about the center bit.
	 */
	while (nBits--)
	{
		reflection <<= 1;
		reflection |= (data & 0x01);
		data >>= 1;
	}

	return reflection;

}	/* reflect() */
#endif

/*********************************************************************
 *
 * Function:    crcSlow()
 * 
 * Description: Compute the CRC of a given message.
 *
 * Notes:		
 *
 * Returns:		The CRC of the message.
 *
 *********************************************************************/
#if REFLECT_REMAINDER == TRUE_CRC && REFLECT_DATA == TRUE_CRC
crc
crcSlow(int reset, crc start_crc, const uint8_t *message, int nBytes)
{
    crc     remainder = (reset ? INITIAL_REMAINDER : start_crc);
	uint8_t bit;
	crc     reflected_polynomial = REFLECT_REMAINDER_FUNC(POLYNOMIAL);

    /*
     * Perform modulo-2 division, a byte at a time.
     */
    while (nBytes--)
    {
        /*
         * Bring the next byte into the remainder.
         */
        remainder ^= (crc)(*message++);

        /*
         * Perform modulo-2 division, a bit at a time, LSB to MSB order.
         */
        for (bit = 8; bit > 0; --bit)
        {
            /*
             * Try to divide the current data bit.
             */
            if (remainder & 1)
            {
                remainder = (remainder >> 1) ^ reflected_polynomial;
            }
            else
            {
                remainder = (remainder >> 1);
            }
        }
    }

    /*
     * The final remainder is the CRC result.
     */
    return (remainder ^ FINAL_XOR_VALUE);

}   /* crcSlow() */
#else
crc
crcSlow(int reset, crc start_crc, const uint8_t *message, int nBytes)
{
    crc     remainder = (reset ? INITIAL_REMAINDER : REFLECT_REMAINDER_FUNC(start_crc));
	uint8_t bit;


    /*
     * Perform modulo-2 division, a byte at a time.
     */
    while (nBytes--)
    {
        /*
         * Bring the next byte into the remainder.
         */
        remainder ^= (((crc)REFLECT_DATA_FUNC(*message++)) << (WIDTH - 8));

        /*
         * Perform modulo-2 division, a bit at a time, MSB to LSB order.
         */
        for (bit = 8; bit > 0; --bit)
        {
            /*
             * Try to divide the current data bit.
             */
            if (remainder & TOPBIT)
            {
                remainder = (remainder << 1) ^ POLYNOMIAL;
            }
            else
            {
                remainder = (remainder << 1);
            }
        }
    }

    /*
     * The final remainder is the CRC result.
     */
    return (REFLECT_REMAINDER_FUNC(remainder) ^ FINAL_XOR_VALUE);

}   /* crcSlow() */
#endif

static crc internalCrcTable[256];
static int crc_initialized = 0;


/*********************************************************************
 *
 * Function:    crc *getCrcTable(void)
 * 
 * Description: Populate the partial CRC lookup table and return it.
 *
 * Notes:		This function must be rerun any time the CRC standard
 *				is changed.  If desired, it can be run "offline" and
 *				the table results stored in an embedded system's ROM.
 *
 * Returns:		None defined.
 *
 *********************************************************************/
crc *getCrcTable(void)
{
    crc	    remainder;
	crc	    dividend;
	uint8_t bit;

	if (crc_initialized != 0) {
		return internalCrcTable;
	}

#if REFLECT_REMAINDER == TRUE_CRC && REFLECT_DATA == TRUE_CRC
	crc     reflected_polynomial = REFLECT_REMAINDER_FUNC(POLYNOMIAL);

    /*
     * Compute the remainder of each possible dividend.
     */
    for (dividend = 0; dividend < 256; ++dividend)
    {
        /*
         * Start with the dividend followed by zeros.
         */
        remainder = dividend;

        /*
         * Perform modulo-2 division, a bit at a time, LSB to MSB order.
         */
        for (bit = 8; bit > 0; --bit)
        {
            /*
             * Try to divide the current data bit.
             */			
            if (remainder & 1)
            {
                remainder = (remainder >> 1) ^ reflected_polynomial;
            }
            else
            {
                remainder = (remainder >> 1);
            }
        }

        /*
         * Store the result into the table.
         */
        internalCrcTable[dividend] = remainder;
    }
#else
    /*
     * Compute the remainder of each possible dividend.
     */
    for (dividend = 0; dividend < 256; ++dividend)
    {
        /*
         * Start with the dividend followed by zeros.
         */
        remainder = dividend << (WIDTH - 8);

        /*
         * Perform modulo-2 division, a bit at a time, MSB to LSB order.
         */
        for (bit = 8; bit > 0; --bit)
        {
            /*
             * Try to divide the current data bit.
             */			
            if (remainder & TOPBIT)
            {
                remainder = (remainder << 1) ^ POLYNOMIAL;
            }
            else
            {
                remainder = (remainder << 1);
            }
        }

        /*
         * Store the result into the table.
         */
        internalCrcTable[dividend] = remainder;
    }
#endif
    crc_initialized = 1;
    return internalCrcTable;
}   /* getCrcTable() */

/*********************************************************************
 *
 * Function:    crcFast()
 * 
 * Description: Compute the CRC of a given message.
 *
 * Notes:		crcInit() must be called first.
 *
 * Returns:		The CRC of the message.
 *
 *********************************************************************/
#if REFLECT_REMAINDER == TRUE_CRC && REFLECT_DATA == TRUE_CRC
crc
crcFast(int reset, crc start_crc, const uint8_t *message, int nBytes)
{
    crc      remainder = (reset ? INITIAL_REMAINDER : start_crc);
    uint8_t  data;
    crc		*crcTable = getCrcTable();

    /*
     * Divide the message by the polynomial, a byte at a time, LSB to MSB order.
     */
    while (nBytes--)
    {
        data = *message++ ^ remainder;
  		remainder = crcTable[data] ^ (remainder >> 8);
    }

    /*
     * The final remainder is the CRC.
     */
    return (remainder ^ FINAL_XOR_VALUE);

}   /* crcFast() */
#else
crc
crcFast(int reset, crc start_crc, const uint8_t *message, int nBytes)
{
    crc	    remainder = (reset ? INITIAL_REMAINDER : REFLECT_REMAINDER_FUNC(start_crc));
    uint8_t data;
    crc		*crcTable = getCrcTable();

    /*
     * Divide the message by the polynomial, a byte at a time, MSB to LSB order.
     */
    while (nBytes--)
    {
        data = REFLECT_DATA_FUNC(*message++) ^ (remainder >> (WIDTH - 8));
  		remainder = crcTable[data] ^ (remainder << 8);
    }

    /*
     * The final remainder is the CRC.
     */
    return (REFLECT_REMAINDER_FUNC(remainder) ^ FINAL_XOR_VALUE);

}   /* crcFast() */
#endif
