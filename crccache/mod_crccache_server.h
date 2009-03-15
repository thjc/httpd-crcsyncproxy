/*
 * crccache.h
 *
 *  Created on: 15/03/2009
 *      Author: awulms
 */

#ifndef MOD_CRCCACHE_SERVER_H
#define MOD_CRCCACHE_SERVER_H

/* Static information about the crccache server */
typedef struct {
	int enabled;
	disk_cache_conf *disk_cache_conf;
} crccache_server_conf;

#endif /*MOD_CRCCACHE_SERVER_H*/

