/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/* Utility routines for Apache proxy */
#include "mod_proxy.h"


static int proxy_match_ipaddr(struct dirconn_entry *This, request_rec *r);
static int proxy_match_domainname(struct dirconn_entry *This, request_rec *r);
static int proxy_match_hostname(struct dirconn_entry *This, request_rec *r);
static int proxy_match_word(struct dirconn_entry *This, request_rec *r);
static struct per_thread_data *get_per_thread_data(void);

/* already called in the knowledge that the characters are hex digits */
int ap_proxy_hex2c(const char *x)
{
    int i, ch;

#if !APR_CHARSET_EBCDIC
    ch = x[0];
    if (apr_isdigit(ch))
	i = ch - '0';
    else if (apr_isupper(ch))
	i = ch - ('A' - 10);
    else
	i = ch - ('a' - 10);
    i <<= 4;

    ch = x[1];
    if (apr_isdigit(ch))
	i += ch - '0';
    else if (apr_isupper(ch))
	i += ch - ('A' - 10);
    else
	i += ch - ('a' - 10);
    return i;
#else /*APR_CHARSET_EBCDIC*/
    return (1 == sscanf(x, "%2x", &i)) ? os_toebcdic[i&0xFF] : 0;
#endif /*APR_CHARSET_EBCDIC*/
}

void ap_proxy_c2hex(int ch, char *x)
{
#if !APR_CHARSET_EBCDIC
    int i;

    x[0] = '%';
    i = (ch & 0xF0) >> 4;
    if (i >= 10)
	x[1] = ('A' - 10) + i;
    else
	x[1] = '0' + i;

    i = ch & 0x0F;
    if (i >= 10)
	x[2] = ('A' - 10) + i;
    else
	x[2] = '0' + i;
#else /*APR_CHARSET_EBCDIC*/
    static const char ntoa[] = { "0123456789ABCDEF" };
    ch &= 0xFF;
    x[0] = '%';
    x[1] = ntoa[(os_toascii[ch]>>4)&0x0F];
    x[2] = ntoa[os_toascii[ch]&0x0F];
    x[3] = '\0';
#endif /*APR_CHARSET_EBCDIC*/
}

/*
 * canonicalise a URL-encoded string
 */

/*
 * Convert a URL-encoded string to canonical form.
 * It decodes characters which need not be encoded,
 * and encodes those which must be encoded, and does not touch
 * those which must not be touched.
 */
char *ap_proxy_canonenc(apr_pool_t *p, const char *x, int len, enum enctype t,
	int isenc)
{
    int i, j, ch;
    char *y;
    char *allowed;	/* characters which should not be encoded */
    char *reserved;	/* characters which much not be en/de-coded */

/* N.B. in addition to :@&=, this allows ';' in an http path
 * and '?' in an ftp path -- this may be revised
 * 
 * Also, it makes a '+' character in a search string reserved, as
 * it may be form-encoded. (Although RFC 1738 doesn't allow this -
 * it only permits ; / ? : @ = & as reserved chars.)
 */
    if (t == enc_path)
	allowed = "$-_.+!*'(),;:@&=";
    else if (t == enc_search)
	allowed = "$-_.!*'(),;:@&=";
    else if (t == enc_user)
	allowed = "$-_.+!*'(),;@&=";
    else if (t == enc_fpath)
	allowed = "$-_.+!*'(),?:@&=";
    else			/* if (t == enc_parm) */
	allowed = "$-_.+!*'(),?/:@&=";

    if (t == enc_path)
	reserved = "/";
    else if (t == enc_search)
	reserved = "+";
    else
	reserved = "";

    y = apr_palloc(p, 3 * len + 1);

    for (i = 0, j = 0; i < len; i++, j++) {
/* always handle '/' first */
	ch = x[i];
	if (strchr(reserved, ch)) {
	    y[j] = ch;
	    continue;
	}
/* decode it if not already done */
	if (isenc && ch == '%') {
	    if (!ap_isxdigit(x[i + 1]) || !ap_isxdigit(x[i + 2]))
		return NULL;
	    ch = ap_proxy_hex2c(&x[i + 1]);
	    i += 2;
	    if (ch != 0 && strchr(reserved, ch)) {	/* keep it encoded */
		ap_proxy_c2hex(ch, &y[j]);
		j += 2;
		continue;
	    }
	}
/* recode it, if necessary */
	if (!apr_isalnum(ch) && !strchr(allowed, ch)) {
	    ap_proxy_c2hex(ch, &y[j]);
	    j += 2;
	}
	else
	    y[j] = ch;
    }
    y[j] = '\0';
    return y;
}

/*
 * Parses network-location.
 *    urlp           on input the URL; on output the path, after the leading /
 *    user           NULL if no user/password permitted
 *    password       holder for password
 *    host           holder for host
 *    port           port number; only set if one is supplied.
 *
 * Returns an error string.
 */
char *
     ap_proxy_canon_netloc(apr_pool_t *p, char **const urlp, char **userp,
			char **passwordp, char **hostp, apr_port_t *port)
{
    apr_port_t i;
    char *strp, *host, *url = *urlp;
    char *user = NULL, *password = NULL;

    if (url[0] != '/' || url[1] != '/')
	return "Malformed URL";
    host = url + 2;
    url = strchr(host, '/');
    if (url == NULL)
	url = "";
    else
	*(url++) = '\0';	/* skip seperating '/' */

    /* find _last_ '@' since it might occur in user/password part */
    strp = strrchr(host, '@');

    if (strp != NULL) {
	*strp = '\0';
	user = host;
	host = strp + 1;

/* find password */
	strp = strchr(user, ':');
	if (strp != NULL) {
	    *strp = '\0';
	    password = ap_proxy_canonenc(p, strp + 1, strlen(strp + 1), enc_user, 1);
	    if (password == NULL)
		return "Bad %-escape in URL (password)";
	}

	user = ap_proxy_canonenc(p, user, strlen(user), enc_user, 1);
	if (user == NULL)
	    return "Bad %-escape in URL (username)";
    }
    if (userp != NULL) {
	*userp = user;
    }
    if (passwordp != NULL) {
	*passwordp = password;
    }

    strp = strrchr(host, ':');
    if (strp != NULL) {
	*(strp++) = '\0';

	for (i = 0; strp[i] != '\0'; i++)
	    if (!apr_isdigit(strp[i]))
		break;

	/* if (i == 0) the no port was given; keep default */
	if (strp[i] != '\0') {
	    return "Bad port number in URL";
	} else if (i > 0) {
	    *port = atoi(strp);
	    if (*port > 65535)
		return "Port number in URL > 65535";
	}
    }
    ap_str_tolower(host);		/* DNS names are case-insensitive */
    if (*host == '\0')
	return "Missing host in URL";
/* check hostname syntax */
    for (i = 0; host[i] != '\0'; i++)
	if (!apr_isdigit(host[i]) && host[i] != '.')
	    break;
    /* must be an IP address */
#if defined(WIN32) || defined(NETWARE) || defined(TPF) || defined(BEOS)
    if (host[i] == '\0' && (inet_addr(host) == -1))
#else
    if (host[i] == '\0' && (ap_inet_addr(host) == -1 || inet_network(host) == -1))
#endif
    {
	return "Bad IP address in URL";
    }

/*    if (strchr(host,'.') == NULL && domain != NULL)
   host = pstrcat(p, host, domain, NULL);
 */
    *urlp = url;
    *hostp = host;

    return NULL;
}

static const char * const lwday[7] =
{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};

/*
 * If the date is a valid RFC 850 date or asctime() date, then it
 * is converted to the RFC 1123 format, otherwise it is not modified.
 * This routine is not very fast at doing conversions, as it uses
 * sscanf and sprintf. However, if the date is already correctly
 * formatted, then it exits very quickly.
 */
const char *
     ap_proxy_date_canon(apr_pool_t *p, const char *x1)
{
    char *x = apr_pstrdup(p, x1);
    int wk, mday, year, hour, min, sec, mon;
    char *q, month[4], zone[4], week[4];

    q = strchr(x, ',');
    /* check for RFC 850 date */
    if (q != NULL && q - x > 3 && q[1] == ' ') {
	*q = '\0';
	for (wk = 0; wk < 7; wk++)
	    if (strcmp(x, lwday[wk]) == 0)
		break;
	*q = ',';
	if (wk == 7)
	    return x;		/* not a valid date */
	if (q[4] != '-' || q[8] != '-' || q[11] != ' ' || q[14] != ':' ||
	    q[17] != ':' || strcmp(&q[20], " GMT") != 0)
	    return x;
	if (sscanf(q + 2, "%u-%3s-%u %u:%u:%u %3s", &mday, month, &year,
		   &hour, &min, &sec, zone) != 7)
	    return x;
	if (year < 70)
	    year += 2000;
	else
	    year += 1900;
    }
    else {
/* check for acstime() date */
	if (x[3] != ' ' || x[7] != ' ' || x[10] != ' ' || x[13] != ':' ||
	    x[16] != ':' || x[19] != ' ' || x[24] != '\0')
	    return x;
	if (sscanf(x, "%3s %3s %u %u:%u:%u %u", week, month, &mday, &hour,
		   &min, &sec, &year) != 7)
	    return x;
	for (wk = 0; wk < 7; wk++)
	    if (strcmp(week, ap_day_snames[wk]) == 0)
		break;
	if (wk == 7)
	    return x;
    }

/* check date */
    for (mon = 0; mon < 12; mon++)
	if (strcmp(month, ap_month_snames[mon]) == 0)
	    break;
    if (mon == 12)
	return x;

    q = apr_palloc(p, 30);
    apr_snprintf(q, 30, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT", ap_day_snames[wk],
       mday, ap_month_snames[mon], year, hour, min, sec);
    return q;
}

request_rec *make_fake_req(conn_rec *c, request_rec *r)
{
    request_rec *rp = apr_pcalloc(c->pool, sizeof(*r));
    core_request_config *req_cfg;

    rp->pool            = c->pool;
    rp->status          = HTTP_OK;

    rp->headers_in      = apr_table_make(c->pool, 50);
    rp->subprocess_env  = apr_table_make(c->pool, 50);
    rp->headers_out     = apr_table_make(c->pool, 12);
    rp->err_headers_out = apr_table_make(c->pool, 5);
    rp->notes           = apr_table_make(c->pool, 5);

    rp->server = r->server;
    rp->request_time = r->request_time;
    rp->connection      = c;
    rp->output_filters  = c->output_filters;
    rp->input_filters   = c->input_filters;

    rp->request_config  = ap_create_request_config(c->pool);
    req_cfg = apr_pcalloc(rp->pool, sizeof(core_request_config));
    req_cfg->bb = apr_brigade_create(c->pool);
    ap_set_module_config(rp->request_config, &core_module, req_cfg);

    return rp;
}

/*
 * Reads headers from a buffer and returns an array of headers.
 * Returns NULL on file error
 * This routine tries to deal with too long lines and continuation lines.
 * @@@: XXX: FIXME: currently the headers are passed thru un-merged. 
 * Is that okay, or should they be collapsed where possible?
 */
apr_table_t *ap_proxy_read_headers(request_rec *r, request_rec *rr, char *buffer, int size, conn_rec *c)
{
    apr_table_t *headers_out;
    int len;
    char *value, *end;
    char field[MAX_STRING_LEN];

    headers_out = ap_make_table(r->pool, 20);

    /*
     * Read header lines until we get the empty separator line, a read error,
     * the connection closes (EOF), or we timeout.
     */
    while ((len = ap_getline(buffer, size, rr, 1)) > 0) {

	if (!(value = strchr(buffer, ':'))) {     /* Find the colon separator */

	    /* Buggy MS IIS servers sometimes return invalid headers
	     * (an extra "HTTP/1.0 200, OK" line sprinkled in between
	     * the usual MIME headers). Try to deal with it in a sensible
	     * way, but log the fact.
	     * XXX: The mask check is buggy if we ever see an HTTP/1.10 */

	    if (!ap_checkmask(buffer, "HTTP/#.# ###*")) {
		/* Nope, it wasn't even an extra HTTP header. Give up. */
		return NULL;
	    }

	    ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r->server,
			 "proxy: Ignoring duplicate HTTP header "
			 "returned by %s (%s)", r->uri, r->method);
	    continue;
	}

        *value = '\0';
        ++value;
	/* XXX: RFC2068 defines only SP and HT as whitespace, this test is
	 * wrong... and so are many others probably.
	 */
        while (apr_isspace(*value))
            ++value;            /* Skip to start of value   */

	/* should strip trailing whitespace as well */
	for (end = &value[strlen(value)-1]; end > value && apr_isspace(*end); --end)
	    *end = '\0';

        apr_table_add(headers_out, buffer, value);

	/* the header was too long; at the least we should skip extra data */
	if (len >= size - 1) { 
	    while ((len = ap_getline(field, MAX_STRING_LEN, rr, 1))
		    >= MAX_STRING_LEN - 1) {
		/* soak up the extra data */
	    }
	    if (len == 0) /* time to exit the larger loop as well */
		break;
	}
    }
    return headers_out;
}


/*
 * list is a comma-separated list of case-insensitive tokens, with
 * optional whitespace around the tokens.
 * The return returns 1 if the token val is found in the list, or 0
 * otherwise.
 */
int ap_proxy_liststr(const char *list, const char *val)
{
    int len, i;
    const char *p;

    len = strlen(val);

    while (list != NULL) {
	p = ap_strchr_c(list, ',');
	if (p != NULL) {
	    i = p - list;
	    do
		p++;
	    while (apr_isspace(*p));
	}
	else
	    i = strlen(list);

	while (i > 0 && apr_isspace(list[i - 1]))
	    i--;
	if (i == len && strncasecmp(list, val, len) == 0)
	    return 1;
	list = p;
    }
    return 0;
}

/*
 * list is a comma-separated list of case-insensitive tokens, with
 * optional whitespace around the tokens.
 * The return returns 1 if the token val is found in the list, or 0
 * otherwise.
 */
char *ap_proxy_removestr(apr_pool_t *pool, const char *list, const char *val)
{
    int len, i;
    const char *p;
    char *new = NULL;

    len = strlen(val);

    while (list != NULL) {
	p = ap_strchr_c(list, ',');
	if (p != NULL) {
	    i = p - list;
	    do
		p++;
	    while (apr_isspace(*p));
	}
	else
	    i = strlen(list);

	while (i > 0 && apr_isspace(list[i - 1]))
	    i--;
	if (i == len && strncasecmp(list, val, len) == 0) {
	    /* do nothing */
	}
	else {
	    if (new)
		new = apr_pstrcat(pool, new, ",", apr_pstrndup(pool, list, i), NULL);
	    else
		new = apr_pstrndup(pool, list, i);
	}
	list = p;
    }
    return new;
}

/*
 * Converts 8 hex digits to a time integer
 */
int ap_proxy_hex2sec(const char *x)
{
    int i, ch;
    unsigned int j;

    for (i = 0, j = 0; i < 8; i++) {
	ch = x[i];
	j <<= 4;
	if (apr_isdigit(ch))
	    j |= ch - '0';
	else if (apr_isupper(ch))
	    j |= ch - ('A' - 10);
	else
	    j |= ch - ('a' - 10);
    }
    if (j == 0xffffffff)
	return -1;		/* so that it works with 8-byte ints */
    else
	return j;
}

/*
 * Converts a time integer to 8 hex digits
 */
void ap_proxy_sec2hex(int t, char *y)
{
    int i, ch;
    unsigned int j = t;

    for (i = 7; i >= 0; i--) {
	ch = j & 0xF;
	j >>= 4;
	if (ch >= 10)
	    y[i] = ch + ('A' - 10);
	else
	    y[i] = ch + '0';
    }
    y[8] = '\0';
}

int ap_proxyerror(request_rec *r, int statuscode, const char *message)
{
    apr_table_setn(r->notes, "error-notes",
	apr_pstrcat(r->pool, 
		"The proxy server could not handle the request "
		"<EM><A HREF=\"", ap_escape_uri(r->pool, r->uri),
		"\">", ap_escape_html(r->pool, r->method),
		"&nbsp;", 
		ap_escape_html(r->pool, r->uri), "</A></EM>.<P>\n"
		"Reason: <STRONG>",
		ap_escape_html(r->pool, message), 
		"</STRONG>", NULL));

    /* Allow "error-notes" string to be printed by ap_send_error_response() */
    apr_table_setn(r->notes, "verbose-error-to", apr_pstrdup(r->pool, "*"));

    r->status_line = apr_psprintf(r->pool, "%3.3u Proxy Error", statuscode);
    return statuscode;
}

/*
 * This routine returns its own error message
 */
const char *ap_proxy_host2addr(const char *host, struct hostent *reqhp)
{
    int i;
    struct hostent *hp;
    struct per_thread_data *ptd = get_per_thread_data();

    for (i = 0; host[i] != '\0'; i++)
	if (!apr_isdigit(host[i]) && host[i] != '.')
	    break;

    if (host[i] != '\0') {
	hp = gethostbyname(host);
	if (hp == NULL)
	    return "Host not found";
    }
    else {
	ptd->ipaddr = ap_inet_addr(host);
	hp = gethostbyaddr((char *) &ptd->ipaddr, sizeof(ptd->ipaddr), AF_INET);
	if (hp == NULL) {
	    memset(&ptd->hpbuf, 0, sizeof(ptd->hpbuf));
	    ptd->hpbuf.h_name = 0;
	    ptd->hpbuf.h_addrtype = AF_INET;
	    ptd->hpbuf.h_length = sizeof(ptd->ipaddr);
	    ptd->hpbuf.h_addr_list = ptd->charpbuf;
	    ptd->hpbuf.h_addr_list[0] = (char *) &ptd->ipaddr;
	    ptd->hpbuf.h_addr_list[1] = 0;
	    hp = &ptd->hpbuf;
	}
    }
    *reqhp = *hp;
    return NULL;
}

static const char *
     proxy_get_host_of_request(request_rec *r)
{
    char *url, *user = NULL, *password = NULL, *err, *host;
    apr_port_t port = -1;

    if (r->hostname != NULL)
	return r->hostname;

    /* Set url to the first char after "scheme://" */
    if ((url = strchr(r->uri, ':')) == NULL
	|| url[1] != '/' || url[2] != '/')
	return NULL;

    url = apr_pstrdup(r->pool, &url[1]);	/* make it point to "//", which is what proxy_canon_netloc expects */

    err = ap_proxy_canon_netloc(r->pool, &url, &user, &password, &host, &port);

    if (err != NULL)
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
		     "%s", err);

    r->hostname = host;

    return host;		/* ought to return the port, too */
}

/* Return TRUE if addr represents an IP address (or an IP network address) */
int ap_proxy_is_ipaddr(struct dirconn_entry *This, apr_pool_t *p)
{
    const char *addr = This->name;
    long ip_addr[4];
    int i, quads;
    long bits;

    /* if the address is given with an explicit netmask, use that */
    /* Due to a deficiency in ap_inet_addr(), it is impossible to parse */
    /* "partial" addresses (with less than 4 quads) correctly, i.e.  */
    /* 192.168.123 is parsed as 192.168.0.123, which is not what I want. */
    /* I therefore have to parse the IP address manually: */
    /*if (proxy_readmask(This->name, &This->addr.s_addr, &This->mask.s_addr) == 0) */
    /* addr and mask were set by proxy_readmask() */
    /*return 1; */

    /* Parse IP addr manually, optionally allowing */
    /* abbreviated net addresses like 192.168. */

    /* Iterate over up to 4 (dotted) quads. */
    for (quads = 0; quads < 4 && *addr != '\0'; ++quads) {
	char *tmp;

	if (*addr == '/' && quads > 0)	/* netmask starts here. */
	    break;

	if (!apr_isdigit(*addr))
	    return 0;		/* no digit at start of quad */

	ip_addr[quads] = strtol(addr, &tmp, 0);

	if (tmp == addr)	/* expected a digit, found something else */
	    return 0;

	if (ip_addr[quads] < 0 || ip_addr[quads] > 255) {
	    /* invalid octet */
	    return 0;
	}

	addr = tmp;

	if (*addr == '.' && quads != 3)
	    ++addr;		/* after the 4th quad, a dot would be illegal */
    }

    for (This->addr.s_addr = 0, i = 0; i < quads; ++i)
	This->addr.s_addr |= htonl(ip_addr[i] << (24 - 8 * i));

    if (addr[0] == '/' && apr_isdigit(addr[1])) {	/* net mask follows: */
	char *tmp;

	++addr;

	bits = strtol(addr, &tmp, 0);

	if (tmp == addr)	/* expected a digit, found something else */
	    return 0;

	addr = tmp;

	if (bits < 0 || bits > 32)	/* netmask must be between 0 and 32 */
	    return 0;

    }
    else {
	/* Determine (i.e., "guess") netmask by counting the */
	/* number of trailing .0's; reduce #quads appropriately */
	/* (so that 192.168.0.0 is equivalent to 192.168.)        */
	while (quads > 0 && ip_addr[quads - 1] == 0)
	    --quads;

	/* "IP Address should be given in dotted-quad form, optionally followed by a netmask (e.g., 192.168.111.0/24)"; */
	if (quads < 1)
	    return 0;

	/* every zero-byte counts as 8 zero-bits */
	bits = 8 * quads;

	if (bits != 32)		/* no warning for fully qualified IP address */
            ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
	      "Warning: NetMask not supplied with IP-Addr; guessing: %s/%ld\n",
		 inet_ntoa(This->addr), bits);
    }

    This->mask.s_addr = htonl(APR_INADDR_NONE << (32 - bits));

    if (*addr == '\0' && (This->addr.s_addr & ~This->mask.s_addr) != 0) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
	    "Warning: NetMask and IP-Addr disagree in %s/%ld\n",
		inet_ntoa(This->addr), bits);
	This->addr.s_addr &= This->mask.s_addr;
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
	    "         Set to %s/%ld\n",
		inet_ntoa(This->addr), bits);
    }

    if (*addr == '\0') {
	This->matcher = proxy_match_ipaddr;
	return 1;
    }
    else
	return (*addr == '\0');	/* okay iff we've parsed the whole string */
}

/* Return TRUE if addr represents an IP address (or an IP network address) */
static int proxy_match_ipaddr(struct dirconn_entry *This, request_rec *r)
{
    int i;
    int ip_addr[4];
    struct in_addr addr;
    struct in_addr *ip_list;
    char **ip_listptr;
    const char *found;
    const char *host = proxy_get_host_of_request(r);

    if (host == NULL)   /* oops! */
       return 0;

    memset(&addr, '\0', sizeof addr);
    memset(ip_addr, '\0', sizeof ip_addr);

    if (4 == sscanf(host, "%d.%d.%d.%d", &ip_addr[0], &ip_addr[1], &ip_addr[2], &ip_addr[3])) {
	for (addr.s_addr = 0, i = 0; i < 4; ++i)
	    addr.s_addr |= htonl(ip_addr[i] << (24 - 8 * i));

	if (This->addr.s_addr == (addr.s_addr & This->mask.s_addr)) {
#if DEBUGGING
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                         "1)IP-Match: %s[%s] <-> ", host, inet_ntoa(addr));
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                         "%s/", inet_ntoa(This->addr));
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                         "%s", inet_ntoa(This->mask));
#endif
	    return 1;
	}
#if DEBUGGING
	else {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                         "1)IP-NoMatch: %s[%s] <-> ", host, inet_ntoa(addr));
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                         "%s/", inet_ntoa(This->addr));
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                         "%s", inet_ntoa(This->mask));
	}
#endif
    }
    else {
	struct hostent the_host;

	memset(&the_host, '\0', sizeof the_host);
	found = ap_proxy_host2addr(host, &the_host);

	if (found != NULL) {
#if DEBUGGING
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                         "2)IP-NoMatch: hostname=%s msg=%s", host, found);
#endif
	    return 0;
	}

	if (the_host.h_name != NULL)
	    found = the_host.h_name;
	else
	    found = host;

	/* Try to deal with multiple IP addr's for a host */
	for (ip_listptr = the_host.h_addr_list; *ip_listptr; ++ip_listptr) {
	    ip_list = (struct in_addr *) *ip_listptr;
	    if (This->addr.s_addr == (ip_list->s_addr & This->mask.s_addr)) {
#if DEBUGGING
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                       "3)IP-Match: %s[%s] <-> ", found, inet_ntoa(*ip_list));
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                       "%s/", inet_ntoa(This->addr));
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                       "%s", inet_ntoa(This->mask));
#endif
		return 1;
	    }
#if DEBUGGING
	    else {
                ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                       "3)IP-NoMatch: %s[%s] <-> ", found, inet_ntoa(*ip_list));
                ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                       "%s/", inet_ntoa(This->addr));
                ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                       "%s", inet_ntoa(This->mask));
	    }
#endif
	}
    }

    return 0;
}

/* Return TRUE if addr represents a domain name */
int ap_proxy_is_domainname(struct dirconn_entry *This, apr_pool_t *p)
{
    char *addr = This->name;
    int i;

    /* Domain name must start with a '.' */
    if (addr[0] != '.')
	return 0;

    /* rfc1035 says DNS names must consist of "[-a-zA-Z0-9]" and '.' */
    for (i = 0; apr_isalnum(addr[i]) || addr[i] == '-' || addr[i] == '.'; ++i)
	continue;

#if 0
    if (addr[i] == ':') {
    ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL,
                     "@@@@ handle optional port in proxy_is_domainname()");
	/* @@@@ handle optional port */
    }
#endif

    if (addr[i] != '\0')
	return 0;

    /* Strip trailing dots */
    for (i = strlen(addr) - 1; i > 0 && addr[i] == '.'; --i)
	addr[i] = '\0';

    This->matcher = proxy_match_domainname;
    return 1;
}

/* Return TRUE if host "host" is in domain "domain" */
static int proxy_match_domainname(struct dirconn_entry *This, request_rec *r)
{
    const char *host = proxy_get_host_of_request(r);
    int d_len = strlen(This->name), h_len;

    if (host == NULL)		/* some error was logged already */
	return 0;

    h_len = strlen(host);

    /* @@@ do this within the setup? */
    /* Ignore trailing dots in domain comparison: */
    while (d_len > 0 && This->name[d_len - 1] == '.')
	--d_len;
    while (h_len > 0 && host[h_len - 1] == '.')
	--h_len;
    return h_len > d_len
	&& strncasecmp(&host[h_len - d_len], This->name, d_len) == 0;
}

/* Create a copy of a "struct hostent" record; it was presumably returned
 * from a call to gethostbyname() and lives in static storage.
 * By creating a copy we can tuck it away for later use.
 */
static struct hostent * pduphostent(apr_pool_t *p, const struct hostent *hp)
{
    struct hostent *newent;
    char	  **ptrs;
    char	  **aliases;
    struct in_addr *addrs;
    int		   i = 0, j = 0;

    if (hp == NULL)
	return NULL;

    /* Count number of alias entries */
    if (hp->h_aliases != NULL)
	for (; hp->h_aliases[j] != NULL; ++j)
	    continue;

    /* Count number of in_addr entries */
    if (hp->h_addr_list != NULL)
	for (; hp->h_addr_list[i] != NULL; ++i)
	    continue;

    /* Allocate hostent structure, alias ptrs, addr ptrs, addrs */
    newent = (struct hostent *) apr_palloc(p, sizeof(*hp));
    aliases = (char **) apr_palloc(p, (j+1) * sizeof(char*));
    ptrs = (char **) apr_palloc(p, (i+1) * sizeof(char*));
    addrs  = (struct in_addr *) apr_palloc(p, (i+1) * sizeof(struct in_addr));

    *newent = *hp;
    newent->h_name = apr_pstrdup(p, hp->h_name);
    newent->h_aliases = aliases;
    newent->h_addr_list = (char**) ptrs;

    /* Copy Alias Names: */
    for (j = 0; hp->h_aliases[j] != NULL; ++j) {
       aliases[j] = apr_pstrdup(p, hp->h_aliases[j]);
    }
    aliases[j] = NULL;

    /* Copy address entries */
    for (i = 0; hp->h_addr_list[i] != NULL; ++i) {
	ptrs[i] = (char*) &addrs[i];
	addrs[i] = *(struct in_addr *) hp->h_addr_list[i];
    }
    ptrs[i] = NULL;

    return newent;
}

/* Return TRUE if addr represents a host name */
int ap_proxy_is_hostname(struct dirconn_entry *This, apr_pool_t *p)
{
    struct hostent host;
    char *addr = This->name;
    int i;

    /* Host names must not start with a '.' */
    if (addr[0] == '.')
	return 0;

    /* rfc1035 says DNS names must consist of "[-a-zA-Z0-9]" and '.' */
    for (i = 0; apr_isalnum(addr[i]) || addr[i] == '-' || addr[i] == '.'; ++i);

    if (addr[i] != '\0' || ap_proxy_host2addr(addr, &host) != NULL)
	return 0;

    This->hostentry = pduphostent (p, &host);

    /* Strip trailing dots */
    for (i = strlen(addr) - 1; i > 0 && addr[i] == '.'; --i)
	addr[i] = '\0';

    This->matcher = proxy_match_hostname;
    return 1;
}

/* Return TRUE if host "host" is equal to host2 "host2" */
static int proxy_match_hostname(struct dirconn_entry *This, request_rec *r)
{
    char *host = This->name;
    const char *host2 = proxy_get_host_of_request(r);
    int h2_len;
    int h1_len;

    if (host == NULL || host2 == NULL)
       return 0; /* oops! */

    h2_len = strlen(host2);
    h1_len = strlen(host);

#if 0
    unsigned long *ip_list;

    /* Try to deal with multiple IP addr's for a host */
    for (ip_list = *This->hostentry->h_addr_list; *ip_list != 0UL; ++ip_list)
	if (*ip_list == ? ? ? ? ? ? ? ? ? ? ? ? ?)
	    return 1;
#endif

    /* Ignore trailing dots in host2 comparison: */
    while (h2_len > 0 && host2[h2_len - 1] == '.')
	--h2_len;
    while (h1_len > 0 && host[h1_len - 1] == '.')
	--h1_len;
    return h1_len == h2_len
	&& strncasecmp(host, host2, h1_len) == 0;
}

/* Return TRUE if addr is to be matched as a word */
int ap_proxy_is_word(struct dirconn_entry *This, apr_pool_t *p)
{
    This->matcher = proxy_match_word;
    return 1;
}

/* Return TRUE if string "str2" occurs literally in "str1" */
static int proxy_match_word(struct dirconn_entry *This, request_rec *r)
{
    const char *host = proxy_get_host_of_request(r);
    return host != NULL && ap_strstr_c(host, This->name) != NULL;
}

/* checks whether a host in uri_addr matches proxyblock */
int ap_proxy_checkproxyblock(request_rec *r, proxy_server_conf *conf, 
                             apr_sockaddr_t *uri_addr)
{
    int j;
    /* XXX FIXME: conf->noproxies->elts is part of an opaque structure */
    for (j = 0; j < conf->noproxies->nelts; j++) {
        struct noproxy_entry *npent = (struct noproxy_entry *) conf->noproxies->elts;
	struct apr_sockaddr_t *conf_addr = npent[j].addr;
	ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
		     "proxy: checking remote machine [%s] against [%s]", uri_addr->hostname, npent[j].name);
	if ((npent[j].name && ap_strstr_c(uri_addr->hostname, npent[j].name))
            || npent[j].name[0] == '*') {
	    ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r->server,
			 "proxy: connect to remote machine %s blocked: name %s matched", uri_addr->hostname, npent[j].name);
	    return HTTP_FORBIDDEN;
	}
	while (conf_addr) {
	    while (uri_addr) {
		char *conf_ip;
		char *uri_ip;
		apr_sockaddr_ip_get(&conf_ip, conf_addr);
		apr_sockaddr_ip_get(&uri_ip, uri_addr);
		ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r->server,
			     "proxy: ProxyBlock comparing %s and %s", conf_ip, uri_ip);
		if (!apr_strnatcasecmp(conf_ip, uri_ip)) {
		    ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r->server,
				 "proxy: connect to remote machine %s blocked: IP %s matched", uri_addr->hostname, conf_ip);
		    return HTTP_FORBIDDEN;
		}
		uri_addr = uri_addr->next;
	    }
	    conf_addr = conf_addr->next;
	}
    }
    return OK;
}

/* set up the minimal filter set */
int ap_proxy_pre_http_connection(conn_rec *c, request_rec *r)
{
    ap_add_input_filter("HTTP_IN", NULL, r, c);
    ap_add_input_filter("CORE_IN", NULL, r, c);
    ap_add_output_filter("CORE", NULL, r, c);
    return OK;
}

/* converts a series of buckets into a string */
apr_status_t ap_proxy_string_read(conn_rec *c, apr_bucket_brigade *bb,
				  char *buff, size_t bufflen, int *eos)
{
    apr_bucket *e;
    apr_status_t rv;
    apr_size_t readbytes = 0;	/* line-at-a-time */
    char *pos = buff;
    char *response;
    int found = 0;
    apr_size_t len;

    /* start with an empty string */
    buff[0] = 0;
    *eos = 0;

    /* loop through each brigade */
    while (!found) {

	/* get brigade from network one line at a time */
	if (APR_SUCCESS != (rv = ap_get_brigade(c->input_filters, bb, AP_MODE_BLOCKING, &readbytes))) {
	    return rv;
	}

	/* loop through each bucket */
	while (!found && !APR_BRIGADE_EMPTY(bb)) {
	    e = APR_BRIGADE_FIRST(bb);
	    if (APR_BUCKET_IS_EOS(e)) {
		*eos = 1;
	    }
	    if (APR_SUCCESS != apr_bucket_read(e, (const char **)&response, &len, APR_BLOCK_READ)) {
		return rv;
	    }
	    /* is string LF terminated? */
	    if (memchr(response, APR_ASCII_LF, len)) {
		found = 1;
	    }
	    /* concat strings until buff is full - then throw the data away */
	    if (len > ((bufflen-1)-(pos-buff))) {
		len = (bufflen-1)-(pos-buff);
	    }
	    if (len > 0) {
		pos = apr_cpystrn(pos, response, len);
	    }
	    APR_BUCKET_REMOVE(e);
	    apr_bucket_destroy(e);
	}
    }

    return APR_SUCCESS;

}

/* remove other filters (like DECHUNK) from filter stack */
void ap_proxy_reset_output_filters(conn_rec *c)
{
    ap_filter_t *f = c->output_filters;

    while (f) {
        if (!strcasecmp(f->frec->name, "CORE") ||
            !strcasecmp(f->frec->name, "CONTENT_LENGTH") ||
            !strcasecmp(f->frec->name, "HTTP_HEADER")) {
            f = f->next;
            continue;
        }
        else {
            ap_remove_output_filter(f);
            f = f->next;
        }
    }
}

#if defined WIN32

static DWORD tls_index;

BOOL WINAPI DllMain (HINSTANCE dllhandle, DWORD reason, LPVOID reserved)
{
    LPVOID memptr;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
	tls_index = TlsAlloc();
    case DLL_THREAD_ATTACH: /* intentional no break */
	TlsSetValue (tls_index, malloc (sizeof (struct per_thread_data)));
	break;
    case DLL_THREAD_DETACH:
	memptr = TlsGetValue (tls_index);
	if (memptr) {
	    free (memptr);
	    TlsSetValue (tls_index, 0);
	}
	break;
    }

    return TRUE;
}

#endif

static struct per_thread_data *get_per_thread_data(void)
{
    return NULL;
}
