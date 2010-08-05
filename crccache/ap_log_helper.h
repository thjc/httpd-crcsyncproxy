#ifndef AP_WRAPPER_H
#define AP_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif
	
void ap_log_hex(const char *file, int line, int level, apr_status_t status, const server_rec *s, unsigned char *buf, size_t len);

char *format_hostinfo(apr_pool_t *p, server_rec *s);

#ifdef __cplusplus
}
#endif

#endif	/* !AP_WRAPPER_H */
