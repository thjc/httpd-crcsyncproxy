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


/* Static information about the crccache server */
typedef struct {
	int enabled;
//	disk_cache_conf *disk_cache_conf;
} crccache_server_conf;

#endif /*MOD_CRCCACHE_SERVER_H*/

