/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#ifndef _MOD_INCLUDE_H
#define _MOD_INCLUDE_H 1



#define STARTING_SEQUENCE "<!--#"
#define ENDING_SEQUENCE "-->"

#define DEFAULT_ERROR_MSG "[an error occurred while processing this directive]"
#define DEFAULT_TIME_FORMAT "%A, %d-%b-%Y %H:%M:%S %Z"
#define SIZEFMT_BYTES 0
#define SIZEFMT_KMG 1
#define TMP_BUF_SIZE 1024
#if APR_CHARSET_EBCDIC
#define RAW_ASCII_CHAR(ch)  apr_xlate_conv_byte(ap_hdrs_from_ascii, (unsigned char)ch)
#else /*APR_CHARSET_EBCDIC*/
#define RAW_ASCII_CHAR(ch)  (ch)
#endif /*APR_CHARSET_EBCDIC*/

module AP_MODULE_DECLARE_DATA includes_module;

/* just need some arbitrary non-NULL pointer which can't also be a request_rec */
#define NESTED_INCLUDE_MAGIC	(&includes_module)

/****************************************************************************
 * Used to keep context information during parsing of a request for SSI tags.
 * This is especially useful if the tag stretches across multiple buckets or
 * brigades. This keeps track of which buckets need to be replaced with the
 * content generated by the SSI tag.
 *
 * state: PRE_HEAD - State prior to finding the first character of the 
 *                   STARTING_SEQUENCE. Next state is PARSE_HEAD.
 *        PARSE_HEAD - State entered once the first character of the
 *                     STARTING_SEQUENCE is found and exited when the
 *                     the full STARTING_SEQUENCE has been matched or
 *                     a match failure occurs. Next state is PRE_HEAD
 *                     or PARSE_TAG.
 *        PARSE_TAG - State entered once the STARTING sequence has been
 *                    matched. It is exited when the first character in
 *                    ENDING_SEQUENCE is found. Next state is PARSE_TAIL.
 *        PARSE_TAIL - State entered from PARSE_TAG state when the first
 *                     character in ENDING_SEQUENCE is encountered. This
 *                     state is exited when the ENDING_SEQUENCE has been
 *                     completely matched, or when a match failure occurs.
 *                     Next state is PARSE_TAG or PARSED.
 *        PARSED - State entered from PARSE_TAIL once the complete 
 *                 ENDING_SEQUENCE has been matched. The SSI tag is
 *                 processed and the SSI buckets are replaced with the
 *                 SSI content during this state.
 * parse_pos: Current matched position within the STARTING_SEQUENCE or
 *            ENDING_SEQUENCE during the PARSE_HEAD and PARSE_TAIL states.
 *            This is especially useful when the sequence spans brigades.
 * X_start_bucket: These point to the buckets containing the first character
 *                 of the STARTING_SEQUENCE, the first non-whitespace
 *                 character of the tag, and the first character in the
 *                 ENDING_SEQUENCE (head_, tag_, and tail_ respectively).
 *                 The buckets are kept intact until the PARSED state is
 *                 reached, at which time the tag is consolidated and the
 *                 buckets are released. The buckets that these point to
 *                 have all been set aside in the ssi_tag_brigade (along
 *                 with all of the intervening buckets).
 * X_start_index: The index points within the specified bucket contents
 *                where the first character of the STARTING_SEQUENCE,
 *                the first non-whitespace character of the tag, and the
 *                first character in the ENDING_SEQUENCE can be found
 *                (head_, tag_, and tail_ respectively).
 * combined_tag: Once the PARSED state is reached the tag is collected from
 *               the bucket(s) in the ssi_tag_brigade into this contiguous
 *               buffer. The buckets in the ssi_tag_brigade are released
 *               and the tag is processed.
 * curr_tag_pos: Ptr to the combined_tag buffer indicating the current
 *               parse position.
 * tag_length: The number of bytes in the actual tag (excluding the
 *             STARTING_SEQUENCE, leading and trailing whitespace,
 *             and ENDING_SEQUENCE). This length is computed as the
 *             buckets are parsed and set aside during the PARSE_TAG state.
 * ssi_tag_brigade: The temporary brigade used by this filter to set aside
 *                  the buckets containing parts of the ssi tag and headers.
 */
typedef enum {PRE_HEAD, PARSE_HEAD, PARSE_DIRECTIVE, PARSE_TAG, PARSE_TAIL, PARSED} states;
typedef struct include_filter_ctx {
    states       state;
    long         flags;    /* See the FLAG_XXXXX definitions. */
    int          if_nesting_level;
    apr_size_t   parse_pos;
    
    apr_bucket   *head_start_bucket;
    apr_size_t   head_start_index;

    apr_bucket   *tag_start_bucket;
    apr_size_t   tag_start_index;

    apr_bucket   *tail_start_bucket;
    apr_size_t   tail_start_index;

    char        *combined_tag;
    char        *curr_tag_pos;
    apr_size_t   directive_length;
    apr_size_t   tag_length;

    apr_size_t   error_length;
    char         error_str[MAX_STRING_LEN];
    char         time_str[MAX_STRING_LEN];

    apr_bucket_brigade *ssi_tag_brigade;
} include_ctx_t;

/* These flags are used to set flag bits. */
#define FLAG_PRINTING         0x00000001  /* Printing conditional lines. */
#define FLAG_COND_TRUE        0x00000002  /* Conditional eval'd to true. */
#define FLAG_SIZE_IN_BYTES    0x00000004  /* Sizes displayed in bytes.   */
#define FLAG_NO_EXEC          0x00000008  /* No Exec in current context. */

/* These flags are used to clear flag bits. */
#define FLAG_SIZE_ABBREV      0xFFFFFFFB  /* Reset SIZE_IN_BYTES bit.    */
#define FLAG_CLEAR_PRINT_COND 0xFFFFFFFC  /* Reset PRINTING and COND_TRUE*/
#define FLAG_CLEAR_PRINTING   0xFFFFFFFE  /* Reset just PRINTING bit.    */

#define CREATE_ERROR_BUCKET(cntx, t_buck, h_ptr, ins_head)        \
{                                                                 \
    apr_size_t e_wrt;                                             \
    t_buck = apr_bucket_create_heap(cntx->error_str,               \
                                   ctx->error_length, 1, &e_wrt); \
    APR_BUCKET_INSERT_BEFORE(h_ptr, t_buck);                       \
                                                                  \
    if (ins_head == NULL) {                                       \
        ins_head = t_buck;                                        \
    }                                                             \
}

#define SPLIT_AND_PASS_PRETAG_BUCKETS(brgd, cntxt)               \
if ((APR_BRIGADE_EMPTY(cntxt->ssi_tag_brigade)) &&                \
    (cntxt->head_start_bucket != NULL)) {                        \
    apr_bucket_brigade *tag_plus;                                 \
                                                                 \
    tag_plus = apr_brigade_split(brgd, cntxt->head_start_bucket); \
    ap_pass_brigade(f->next, brgd);                              \
    brgd = tag_plus;                                             \
}

typedef int (*handler)(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                       request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                       apr_bucket **inserted_head);

void ap_register_include_handler(char *tag, handler func);

#endif /* MOD_INCLUDE */
