#include <stdarg.h>

#include "httpd.h"
#include "http_log.h"
#include <apr_strings.h>

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

char *format_hostinfo(apr_pool_t *p, server_rec *s)
{
	return s->is_virtual ? apr_psprintf(p, "virtual host %s:%d", s->addrs->virthost, s->addrs->host_port) : "main server";
}

