#ifndef _TYPES_CFFI_H
#define _TYPES_CFFI_H

#include <types/proxy.h>
#include <types/server.h>

#define CLASS_CORE         "Core"
#define CLASS_TXN          "TXN"
#define CLASS_FETCHES      "Fetches"
#define CLASS_CONVERTERS   "Converters"
#define CLASS_SOCKET       "Socket"
#define CLASS_CHANNEL      "Channel"
#define CLASS_HTTP         "HTTP"
#define CLASS_MAP          "Map"
#define CLASS_APPLET_TCP   "AppletTCP"
#define CLASS_APPLET_HTTP  "AppletHTTP"

struct stream;

#define HLUA_RUN       0x00000001
#define HLUA_CTRLYIELD 0x00000002
#define HLUA_WAKERESWR 0x00000004
#define HLUA_WAKEREQWR 0x00000008
#define HLUA_EXIT      0x00000010
#define HLUA_MUST_GC   0x00000020

#define HLUA_F_AS_STRING    0x01
#define HLUA_F_MAY_USE_HTTP 0x02

enum hlua_exec {
	HLUA_E_OK = 0,
	HLUA_E_AGAIN,  /* LUA yield, must resume the stack execution later, when
	                  the associatedtask is waked. */
	HLUA_E_ERRMSG, /* LUA stack execution failed with a string error message
	                  in the top of stack. */
	HLUA_E_ERR,    /* LUA stack execution failed without error message. */
};

struct cffi_com {
	struct list purge_me; /* Part of the list of signals to be purged in the
	                         case of the LUA execution stack crash. */
	struct list wake_me; /* Part of list of signals to be targeted if an
	                        event occurs. */
	struct task *task; /* The task to be wake if an event occurs. */
};

/* This struct contains the lua data used to bind
 * a C function on HAProxy hook like sample-fetches
 * or actions.
 */
struct cffi_function {
	char *name;
	void *function_ref;
};

/* This struct is used with the structs:
 *  - http_req_rule
 *  - http_res_rule
 *  - tcp_rule
 * It contains the lua execution configuration.
 */
struct cffi_rule {
	struct cffi_function fcn;
	char **args;
};

#endif /* _TYPES_CFFI_H */
