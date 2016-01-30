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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <syslog.h>
#include <grp.h>
#ifdef USE_CPU_AFFINITY
#include <sched.h>
#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/cpuset.h>
#endif
#endif

#ifdef DEBUG_FULL
#include <assert.h>
#endif

#include <common/base64.h>
#include <common/cfgparse.h>
#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/defaults.h>
#include <common/errors.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/namespace.h>
#include <common/regex.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/capture.h>
#include <types/global.h>
#include <types/acl.h>
#include <types/peers.h>

#include <proto/acl.h>
#include <proto/applet.h>
#include <proto/arg.h>
#include <proto/auth.h>
#include <proto/backend.h>
#include <proto/channel.h>
#include <proto/checks.h>
#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/hdr_idx.h>
#include <proto/hlua.h>
#include <proto/cffi.h>
#include <proto/listener.h>
#include <proto/log.h>
#include <proto/pattern.h>
#include <proto/protocol.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/signal.h>
#include <proto/task.h>
#include <proto/dns.h>

#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#endif

#ifdef USE_DEVICEATLAS
#include <import/da.h>
#endif

#ifdef USE_51DEGREES
#include <import/51d.h>
#endif

/*********************************************************************/

extern const struct comp_algo comp_algos[];

/*********************************************************************/

/* list of config files */
extern struct list cfg_cfgfiles;

extern int  pid;			/* current process id */
extern int  relative_pid;		/* process id starting at 1 */

/* global options */
extern struct global global;

/*********************************************************************/

extern int stopping;	/* non zero means stopping in progress */
extern int jobs;   /* number of active jobs (conns, listeners, active tasks, ...) */

/* Here we store informations about the pids of the processes we may pause
 * or kill. We will send them a signal every 10 ms until we can bind to all
 * our ports. With 200 retries, that's about 2 seconds.
 */
#define MAX_START_RETRIES	200
extern int *oldpids;
extern int oldpids_sig; /* use USR1 or TERM */


/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
