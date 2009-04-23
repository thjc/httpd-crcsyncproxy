#include <stdarg.h>

#include "httpd.h"
#include "http_log.h"

/**
 * ap_log_error does not support %zd or %zu conversion for type_t arguments
 * So with ap_log_error one would have to specify either %d or %ld, depending on the 
 * platform (32-bit or 64-bit). This violates the whole purpose of type_t, which 
 * was introduced in C exactly to provide cross-platform compatibility...
 * This wrapper function supports %zd and %zu conversion parameters.
 * Note that it truncates the logged message to 1000 bytes, so don't use it to log messages that might
 * be longer
 */
void ap_log_error_wrapper(const char *file, int line, int level, apr_status_t status, const server_rec *s,
		const char *fmt, ...)
{
	char msg[1000];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	ap_log_error(file, line, level, status, s, "%s", msg);
}