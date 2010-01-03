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

struct encodings_t {
	struct encodings_t *next;
	const char *encoding;
};

struct decoder_modules_t {
	struct decoder_modules_t *next;
	const char *name;
	struct encodings_t *encodings;
};

/* Static information about the crccache server */
typedef struct {
	int enabled;
	struct decoder_modules_t *decoder_modules;
	unsigned decoder_modules_cnt;
} crccache_server_conf;

#endif /*MOD_CRCCACHE_SERVER_H*/

