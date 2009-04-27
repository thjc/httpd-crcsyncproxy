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

void ap_log_hex(const char *file, int line, int level, apr_status_t status, const server_rec *s, unsigned char *buf, size_t len)
{
	size_t cnt;
	for (cnt=0; cnt < len; cnt += 32)
	{
		size_t cnt2;
		char hexbuf[3*32+1];
		for (cnt2=cnt; cnt2 != cnt+32 && cnt2 != len; cnt2++)
		{
			sprintf(hexbuf+3*(cnt2-cnt), "%02x.", buf[cnt2]);
		}
		ap_log_error(file, line, level, status, s, "%s", hexbuf);
	}
}
