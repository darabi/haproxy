/*
 * HA-Proxy : High Availability-enabled HTTP/TCP proxy
 * Copyright 2000-2015  Willy Tarreau <w@1wt.eu>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Please refer to RFC2068 or RFC2616 for informations about HTTP protocol, and
 * RFC2965 for informations about cookies usage. More generally, the IETF HTTP
 * Working Group's web site should be consulted for protocol related changes :
 *
 *     http://ftp.ics.uci.edu/pub/ietf/http/
 *
 * Pending bugs (may be not fixed because never reproduced) :
 *   - solaris only : sometimes, an HTTP proxy with only a dispatch address causes
 *     the proxy to terminate (no core) if the client breaks the connection during
 *     the response. Seen on 1.1.8pre4, but never reproduced. May not be related to
 *     the snprintf() bug since requests were simple (GET / HTTP/1.0), but may be
 *     related to missing setsid() (fixed in 1.1.15)
 *   - a proxy with an invalid config will prevent the startup even if disabled.
 *
 * ChangeLog has moved to the CHANGELOG file.
 *
 */

#include <common/compiler.h>

int main(int argc, char **argv)
{
	haproxy_main(argc, argv);

	exit(0);
}


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
