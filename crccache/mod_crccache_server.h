/*
 * mod_crccache_server.h
 *
 *  Created on: 15/03/2009
 *      Author: awulms
 */

#ifndef MOD_CRCCACHE_SERVER_H
#define MOD_CRCCACHE_SERVER_H

#include <ap_config.h>
#include <http_config.h>

extern module AP_MODULE_DECLARE_DATA crccache_server_module;

typedef struct encodings_s {
	struct encodings_s *next;
	const char *encoding;
} encodings_t;

typedef struct decoder_modules_s {
	struct decoder_modules_s *next;
	const char *name;
	encodings_t *encodings;
} decoder_modules_t;

typedef struct regexs_s {
	struct regexs_s *next;
	ap_regex_t *preg;
	const char *regex;
} regexs_t;

/* Static information about the crccache server */
typedef struct {
	int enabled;
	decoder_modules_t *decoder_modules;
	unsigned decoder_modules_cnt;
	regexs_t *regexs;
	regexs_t *regexs_tail;
} crccache_server_conf;

#endif /*MOD_CRCCACHE_SERVER_H*/

