#ifndef AP_WRAPPER_H
#define AP_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif
	
void ap_log_error_wrapper(const char *file, int line, int level, apr_status_t status, const server_rec *s,
		const char *fmt, ...)
		__attribute__((format(printf,6,7)));

void ap_log_hex(const char *file, int line, int level, apr_status_t status, const server_rec *s, unsigned char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif	/* !AP_WRAPPER_H */
