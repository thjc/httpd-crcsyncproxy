/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ap_expr.h
 * @brief Expression parser
 */

#ifndef AP_EXPR_H
#define AP_EXPR_H

#include "httpd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* conditional expression parser stuff */
typedef enum {
    TOKEN_STRING,
    TOKEN_RE,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_NOT,
    TOKEN_EQ,
    TOKEN_NE,
    TOKEN_RBRACE,
    TOKEN_LBRACE,
    TOKEN_GROUP,
    TOKEN_GE,
    TOKEN_LE,
    TOKEN_GT,
    TOKEN_LT,
    TOKEN_ACCESS
} token_type_t;

typedef struct {
    token_type_t  type;
    const char   *value;
#ifdef DEBUG_INCLUDE
    const char   *s;
#endif
} token_t;

typedef struct parse_node {
    struct parse_node *parent;
    struct parse_node *left;
    struct parse_node *right;
    token_t token;
    int value;
    int done;
#ifdef DEBUG_INCLUDE
    int dump_done;
#endif
} parse_node_t;

typedef struct {
    const char *source;
    const char *rexp;
    apr_size_t  nsub;
    ap_regmatch_t match[AP_MAX_REG_MATCH];
} backref_t;

typedef char *(*string_func_t)(request_rec*, const char*);
typedef int (*opt_func_t)(request_rec*, parse_node_t*, string_func_t);

/**
 * Parse an expression into a parse tree
 * @param pool Pool
 * @param expr The expression to parse
 * @param was_error On return, set to zero if parse successful, nonzero on error
 * @return The parse tree
 */
AP_DECLARE(parse_node_t*) ap_expr_parse(apr_pool_t *pool, const char *expr,
                                        int *was_error);
/**
 * Evaluate a parse tree
 * @param r The current request
 * @param root The root node of the parse tree
 * @param was_error On return, set to zero if parse successful, nonzero on error
 * @param reptr Regular expression memory for backreferencing if a regexp was parsed
 * @param string_func String parser function - perform variable substitutions
 * @param eval_func Option evaluation function (e.g. -A filename)
 * @return the value the expression parsed to
 */
AP_DECLARE(int) ap_expr_eval(request_rec *r, parse_node_t *root,
                             int *was_error, backref_t **reptr,
                             string_func_t string_func, opt_func_t eval_func);
/**
 * Evaluate an expression
 * @param r The current request
 * @param expr The expression to parse
 * @param was_error On return, set to zero if parse successful, nonzero on error
 * @param reptr Regular expression memory for backreferencing if a regexp was parsed
 * @param string_func String parser function - perform variable substitutions
 * @param eval_func Option evaluation function (e.g. -A filename)
 * @return the value the expression parsed to
 */
AP_DECLARE(int) ap_expr_evalstring(request_rec *r, const char *expr,
                                   int *was_error, backref_t **reptr,
                                   string_func_t string_func,
                                   opt_func_t eval_func);

#ifdef __cplusplus
}
#endif

#endif /* AP_EXPR_H */
