/**********************************************************************
 *
 * Filename:    crc.h
 * 
 * Description: A header file describing the various CRC standards.
 *
 * Notes:       
 *
 * 
 * Copyright (c) 2000 by Michael Barr.  This software is placed into
 * the public domain and may be used for any purpose.  However, this
 * notice must not be changed or removed and no warranty is either
 * expressed or implied by its publication or distribution.
 *
 * Updates performed on 2011-11-20 by Alex Wulms:
 *   - Added support for CRC64_ISO
 *   - Changed types to uintX_t variations for cross-platform
 *     compatibility (e.g. 32-bit versus 64-bit architecture)
 *   - Exposed CRC lookup table to client programs
 *   --- The CRC lookup table gets initialized by invoking crcInit()
 *   --- The CRC lookup table is based on the reflected polynomial
 *       when REFLECT_DATA and REFLECT_REMAINDER are both TRUE_CRC
 * These modifications are available under the same conditions as the
 * original code by Michael Barr.
 **********************************************************************/

#include <inttypes.h>

#ifndef _crc_h
#define _crc_h


#define FALSE_CRC	0
#define TRUE_CRC	!FALSE_CRC

/*
 * Select the CRC standard from the list that follows.
 */
#define CRC64_ISO


#if defined(CRC_CCITT)

typedef uint16_t  crc;
#define CRC_FORMAT "04X"

#define CRC_NAME			"CRC-CCITT"
#define POLYNOMIAL			0x1021
#define INITIAL_REMAINDER	0xFFFF
#define FINAL_XOR_VALUE		0x0000
#define REFLECT_DATA		FALSE_CRC
#define REFLECT_REMAINDER	FALSE_CRC
#define CHECK_VALUE			0x29B1

#elif defined(CRC16)

typedef uint16_t  crc;
#define CRC_FORMAT "04X"

#define CRC_NAME			"CRC-16"
#define POLYNOMIAL			0x8005
#define INITIAL_REMAINDER	0x0000
#define FINAL_XOR_VALUE		0x0000
#define REFLECT_DATA		TRUE_CRC
#define REFLECT_REMAINDER	TRUE_CRC
#define CHECK_VALUE			0xBB3D

#elif defined(CRC32)

typedef uint32_t  crc;
#define CRC_FORMAT "08X"

#define CRC_NAME			"CRC-32"
#define POLYNOMIAL			0x04C11DB7
#define INITIAL_REMAINDER	0xFFFFFFFF
#define FINAL_XOR_VALUE		0xFFFFFFFF
#define REFLECT_DATA		TRUE_CRC
#define REFLECT_REMAINDER	TRUE_CRC
#define CHECK_VALUE			0xCBF43926

#elif defined(CRC64_ISO)

typedef uint64_t  crc;
#define CRC_FORMAT "016"PRIx64

#define CRC_NAME			"CRC-64-ISO"
#define POLYNOMIAL			0x000000000000001B
#define INITIAL_REMAINDER	0x0000000000000000
#define FINAL_XOR_VALUE		0x0000000000000000
#define REFLECT_DATA		TRUE_CRC
#define REFLECT_REMAINDER	TRUE_CRC
#define CHECK_VALUE			0xe4ffbea588933790

#else

#error "One of CRC_CCITT, CRC16, CRC32 or CRC64_ISO must be #define'd."

#endif


crc   crcSlow(int reset, crc start_crc, const uint8_t *message, int nBytes);
crc   crcFast(int reset, crc start_crc, const uint8_t *message, int nBytes);

crc *getCrcTable(void);

#endif /* _crc_h */
