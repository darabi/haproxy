#include <sys/socket.h>

#include <ctype.h>
#include <setjmp.h>

#include <types/cffi.h>

#include <ebpttree.h>

#include <common/cfgparse.h>

#include <types/connection.h>
#include <types/hlua.h>
#include <types/proxy.h>

#include <proto/arg.h>
#include <proto/applet.h>
#include <proto/channel.h>
#include <proto/hdr_idx.h>
#include <proto/hlua.h>
#include <proto/map.h>
#include <proto/obj_type.h>
#include <proto/pattern.h>
#include <proto/payload.h>
#include <proto/proto_http.h>
#include <proto/proto_tcp.h>
#include <proto/raw_sock.h>
#include <proto/sample.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/stream.h>
#include <proto/ssl_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>
#include <proto/vars.h>

/* Lua uses longjmp to perform yield or throwing errors. This
 * macro is used only for identifying the function that can
 * not return because a longjmp is executed.
 *   __LJMP marks a prototype of hlua file that can use longjmp.
 *   WILL_LJMP() marks an lua function that will use longjmp.
 *   MAY_LJMP() marks an lua function that may use longjmp.
 */
#define __LJMP
#define WILL_LJMP(func) func
#define MAY_LJMP(func) func

/* Applet status flags */
#define APPLET_DONE     0x01 /* applet processing is done. */
#define APPLET_100C     0x02 /* 100 continue expected. */
#define APPLET_HDR_SENT 0x04 /* Response header sent. */
#define APPLET_CHUNKED  0x08 /* Use transfer encoding chunked. */
#define APPLET_LAST_CHK 0x10 /* Last chunk sent. */
#define APPLET_HTTP11   0x20 /* Last chunk sent. */

#define HTTP_100C "HTTP/1.1 100 Continue\r\n\r\n"

/*
 * If this pointer is non-null, it will be called by cffi_load
 *
 */
static int (*cffi_load_callback)(char **args, int section_type, struct proxy *curpx,
				 struct proxy *defpx, const char *file, int line,
				 char **err) = NULL;

/* This is the memory pool containing all the signal structs. These
 * struct are used to store each requiered signal between two tasks.
 */
struct pool_head *pool2_cffi_com;

/* List head of the function called at the initialisation time. */
struct list hlua_init_functions = LIST_HEAD_INIT(hlua_init_functions);

/* Global Lua execution timeout. By default Lua, execution linked
 * with stream (actions, sample-fetches and converters) have a
 * short timeout. Lua linked with tasks doesn't have a timeout
 * because a task may remain alive during all the haproxy execution.
 */
static unsigned int hlua_timeout_session = 4000; /* session timeout. */
static unsigned int hlua_timeout_task = TICK_ETERNITY; /* task timeout. */
static unsigned int hlua_timeout_applet = 4000; /* applet timeout. */

static unsigned int cffi_timeout_applet = 4000; /* applet timeout. */

static const char error_500[] =
	"HTTP/1.0 500 Server Error\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n"
	"<html><body><h1>500 Server Error</h1>\nAn internal server error occured.\n</body></html>\n";

#define SEND_ERR(__be, __fmt, __args...) \
	do { \
		send_log(__be, LOG_ERR, __fmt, ## __args); \
		if (!(global.mode & MODE_QUIET) || (global.mode & MODE_VERBOSE)) \
			Alert(__fmt, ## __args); \
	} while (0)

void cffi_set_load_callback(int (*new_callback)(char **args, int section_type, struct proxy *curpx,
						     struct proxy *defpx, const char *file, int line,
						     char **err)) {
  cffi_load_callback = new_callback;
}
/* This function is used to send logs. It try to send on screen (stderr)
 * and on the default syslog server.
 */
static inline void cffi_sendlog(struct proxy *px, int level, const char *msg)
{
	struct tm tm;
	char *p;

	/* Cleanup the log message. */
	p = trash.str;
	for (; *msg != '\0'; msg++, p++) {
		if (p >= trash.str + trash.size - 1) {
			/* Break the message if exceed the buffer size. */
			*(p-4) = ' ';
			*(p-3) = '.';
			*(p-2) = '.';
			*(p-1) = '.';
			break;
		}
		if (isprint(*msg))
			*p = *msg;
		else
			*p = '.';
	}
	*p = '\0';

	send_log(px, level, "%s\n", trash.str);
	if (!(global.mode & MODE_QUIET) || (global.mode & (MODE_VERBOSE | MODE_STARTING))) {
		get_localtime(date.tv_sec, &tm);
		fprintf(stderr, "[%s] %03d/%02d%02d%02d (%d) : %s\n",
			log_levels[level], tm.tm_yday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			(int)getpid(), trash.str);
		fflush(stderr);
	}
}

/*
 *
 *
 * Class AppletHTTP
 *
 *
 */

/* This function creates and push in the stack an Applet object
 * according with a current TXN.
 */
static int hlua_applet_http_new(void *L, struct appctx *ctx)
{
	return 1;
}

int cffi_log(int level, char *msg)
{
	if (level < 0 || level >= NB_LOG_LEVELS)
		Alert("Invalid loglevel.");

	cffi_sendlog(NULL, level, msg);
	return 0;
}

struct task *hlua_applet_wakeup(struct task *t)
{
	struct appctx *ctx = t->context;
	struct stream_interface *si = ctx->owner;

	/* If the applet is wake up without any expected work, the sheduler
	 * remove it from the run queue. This flag indicate that the applet
	 * is waiting for write. If the buffer is full, the main processing
	 * will send some data and after call the applet, otherwise it call
	 * the applet ASAP.
	 */
	si_applet_cant_put(si);
	appctx_wakeup(ctx);
	return NULL;
}

/* The function returns 1 if the initialisation is complete, 0 if
 * an errors occurs and -1 if more data are required for initializing
 * the applet.
 */
static int cffi_applet_http_init(struct appctx *ctx, struct proxy *px, struct stream *strm)
{
	struct stream_interface *si = ctx->owner;
	struct channel *req = si_oc(si);
	struct http_msg *msg;
	struct http_txn *txn;
	// struct hlua *hlua = &ctx->ctx.hlua_apphttp.hlua;
	// char **arg;
	struct hdr_ctx hdr;
	struct task *task;
	struct sample smp; /* just used for a valid call to smp_prefetch_http. */

	/* Wait for a full HTTP request. */
	if (!smp_prefetch_http(px, strm, 0, NULL, &smp, 0)) {
		if (smp.flags & SMP_F_MAY_CHANGE)
			return -1;
		return 0;
	}
	txn = strm->txn;
	msg = &txn->req;

	/* We want two things in HTTP mode :
	 *  - enforce server-close mode if we were in keep-alive, so that the
	 *    applet is released after each response ;
	 *  - enable request body transfer to the applet in order to resync
	 *    with the response body.
	 */
	if ((txn->flags & TX_CON_WANT_MSK) == TX_CON_WANT_KAL)
		txn->flags = (txn->flags & ~TX_CON_WANT_MSK) | TX_CON_WANT_SCL;

	// HLUA_INIT(hlua);
	ctx->ctx.hlua_apphttp.left_bytes = -1;
	ctx->ctx.hlua_apphttp.flags = 0;

	if (txn->req.flags & HTTP_MSGF_VER_11)
		ctx->ctx.hlua_apphttp.flags |= APPLET_HTTP11;

	/* Create task used by signal to wakeup applets. */
	task = task_new();
	if (!task) {
		SEND_ERR(px, "Lua applet http '%s': out of memory.\n",
			 ctx->rule->arg.cffi_rule->fcn.name);
		return 0;
	}
	task->nice = 0;
	task->context = ctx;
	task->process = hlua_applet_wakeup;
	ctx->ctx.hlua_apphttp.task = task;

	/* In the execution wrappers linked with a stream, the
	 * Lua context can be not initialized. This behavior
	 * permits to save performances because a systematic
	 * Lua initialization cause 5% performances loss.
	 */
	/* if (!hlua_ctx_init(hlua, task)) { */
	/* 	SEND_ERR(px, "Cffi applet http '%s': can't initialize Lua context.\n", */
	/* 	         ctx->rule->arg.hlua_rule->fcn.name); */
	/* 	return 0; */
	/* } */

	/* Set timeout according with the applet configuration. */
	// hlua->max_time = ctx->applet->timeout;

	/* The following Lua calls can fail. */
	/* if (!SET_SAFE_LJMP(hlua->T)) { */
	/* 	SEND_ERR(px, "Lua applet http '%s': critical error.\n", */
	/* 	         ctx->rule->arg.hlua_rule->fcn.name); */
	/* 	return 0; */
	/* } */

	/* Check stack available size. */
	/* if (!lua_checkstack(hlua->T, 1)) { */
	/* 	SEND_ERR(px, "Lua applet http '%s': full stack.\n", */
	/* 	         ctx->rule->arg.hlua_rule->fcn.name); */
	/* 	RESET_SAFE_LJMP(hlua->T); */
	/* 	return 0; */
	/* } */

	/* Restore the function in the stack. */
	/* lua_rawgeti(hlua->T, LUA_REGISTRYINDEX, ctx->rule->arg.hlua_rule->fcn.function_ref); */

	/* Create and and push object stream in the stack. */
	if (!hlua_applet_http_new(NULL, ctx)) {
		SEND_ERR(px, "Cffi applet http '%s': full stack.\n",
			 ctx->rule->arg.cffi_rule->fcn.name);
		return 0;
	}
	// hlua->nargs = 1;

	/* Look for a 100-continue expected. */
	if (msg->flags & HTTP_MSGF_VER_11) {
		hdr.idx = 0;
		if (http_find_header2("Expect", 6, req->buf->p, &txn->hdr_idx, &hdr) &&
		    unlikely(hdr.vlen == 12 && strncasecmp(hdr.line+hdr.val, "100-continue", 12) == 0))
			ctx->ctx.hlua_apphttp.flags |= APPLET_100C;
	}

	/* push keywords in the stack. */
	/* for (arg = ctx->rule->arg.hlua_rule->args; arg && *arg; arg++) { */
	/* 	if (!lua_checkstack(hlua->T, 1)) { */
	/* 		SEND_ERR(px, "Lua applet http '%s': full stack.\n", */
	/* 		         ctx->rule->arg.hlua_rule->fcn.name); */
	/* 		RESET_SAFE_LJMP(hlua->T); */
	/* 		return 0; */
	/* 	} */
	/* 	lua_pushstring(hlua->T, *arg); */
	/* 	hlua->nargs++; */
	/* } */

	/* RESET_SAFE_LJMP(hlua->T); */

	/* Wakeup the applet when data is ready for read. */
	si_applet_cant_get(si);

	return 1;
}

void cffi_applet_http_fct(struct appctx *ctx)
{
	struct stream_interface *si = ctx->owner;
	struct stream *strm = si_strm(si);
	struct channel *res = si_ic(si);
	struct act_rule *rule = ctx->rule;
	struct proxy *px = strm->be;
	// struct hlua *hlua = &ctx->ctx.hlua_apphttp.hlua;
	char *blk1;
	int len1;
	char *blk2;
	int len2;
	int ret;
	int (*func)(struct appctx *);

	cffi_log(LOG_DEBUG, "Entering cffi_applet_http_fct\n");
	/* If the stream is disconnect or closed, ldo nothing. */
	if (unlikely(si->state == SI_ST_DIS || si->state == SI_ST_CLO))
		return;

	/* Set the currently running flag. */
	if (!HLUA_IS_RUNNING(hlua) &&
	    !(ctx->ctx.hlua_apphttp.flags & APPLET_DONE)) {

		/* Wait for full HTTP analysys. */
		if (unlikely(strm->txn->req.msg_state < HTTP_MSG_BODY)) {
			si_applet_cant_get(si);
			return;
		}

		/* Store the max amount of bytes that we can read. */
		ctx->ctx.hlua_apphttp.left_bytes = strm->txn->req.body_len;

		/* We need to flush the request header. This left the body
		 * for the Lua.
		 */

		/* Read the maximum amount of data avalaible. */
		ret = bo_getblk_nc(si_oc(si), &blk1, &len1, &blk2, &len2);
		if (ret == -1)
			return;

		/* No data available, ask for more data. */
		if (ret == 1)
			len2 = 0;
		if (ret == 0)
			len1 = 0;
		if (len1 + len2 < strm->txn->req.eoh + 2) {
			si_applet_cant_get(si);
			return;
		}

		/* skip the requests bytes. */
		bo_skip(si_oc(si), strm->txn->req.eoh + 2);
	}

	/* Executes The applet if it is not done. */
	if (!(ctx->ctx.hlua_apphttp.flags & APPLET_DONE)) {

		/* Execute the function. */
		cffi_log(LOG_DEBUG, "In cffi_applet_http_fct: calling function_ref\n");
		func = rule->arg.cffi_rule->fcn.function_ref;
		switch (func(ctx)) {
		/* finished. */
		case HLUA_E_OK:
			ctx->ctx.hlua_apphttp.flags |= APPLET_DONE;
			break;

		/* yield. */
		case HLUA_E_AGAIN:
			return;

		/* finished with error. */
		case HLUA_E_ERRMSG:
			/* Display log. */
			SEND_ERR(px, "Cffi applet http '%s' had an error.\n",
				 rule->arg.cffi_rule->fcn.name);
			goto error;

		case HLUA_E_ERR:
			/* Display log. */
			SEND_ERR(px, "Lua applet http '%s' return an unknown error.\n",
				 rule->arg.cffi_rule->fcn.name);
			goto error;

		default:
			goto error;
		}
	}

	if (ctx->ctx.hlua_apphttp.flags & APPLET_DONE) {

		/* We must send the final chunk. */
		if (ctx->ctx.hlua_apphttp.flags & APPLET_CHUNKED &&
		    !(ctx->ctx.hlua_apphttp.flags & APPLET_LAST_CHK)) {

			/* sent last chunk at once. */
			ret = bi_putblk(res, "0\r\n\r\n", 5);

			/* critical error. */
			if (ret == -2 || ret == -3) {
				SEND_ERR(px, "Cffi applet http '%s'cannont send last chunk.\n",
					 rule->arg.cffi_rule->fcn.name);
				goto error;
			}

			/* no enough space error. */
			if (ret == -1) {
				si_applet_cant_put(si);
				return;
			}

			/* set the last chunk sent. */
			ctx->ctx.hlua_apphttp.flags |= APPLET_LAST_CHK;
		}

		/* close the connection. */

		/* status / log */
		strm->txn->status = ctx->ctx.hlua_apphttp.status;
		strm->logs.tv_request = now;

		/* eat the whole request */
		bo_skip(si_oc(si), si_ob(si)->o);
		res->flags |= CF_READ_NULL;
		si_shutr(si);

		return;
	}

error:

	/* If we are in HTTP mode, and we are not send any
	 * data, return a 500 server error in best effort:
	 * if there are no room avalaible in the buffer,
	 * just close the connection.
	 */
	bi_putblk(res, error_500, strlen(error_500));
	if (!(strm->flags & SF_ERR_MASK))
		strm->flags |= SF_ERR_RESOURCE;
	si_shutw(si);
	si_shutr(si);
	ctx->ctx.hlua_apphttp.flags |= APPLET_DONE;
}

static void cffi_applet_http_release(struct appctx *ctx)
{
	task_free(ctx->ctx.hlua_apphttp.task);
	ctx->ctx.hlua_apphttp.task = NULL;
	hlua_ctx_destroy(&ctx->ctx.hlua_apphttp.hlua);
}

enum act_parse_ret cffi_register_service_http(const char **args, int *cur_arg, struct proxy *px,
					      struct act_rule *rule, char **err)
{
	struct cffi_function *fcn = (struct cffi_function *)rule->kw->private;

	/* HTTP applets are forbidden in tcp-request rules.
	 * HTTP applet request requires everything initilized by
	 * "http_process_request" (analyzer flag AN_REQ_HTTP_INNER).
	 * The applet will be immediately initilized, but its before
	 * the call of this analyzer.
	 */
	if (rule->from != ACT_F_HTTP_REQ) {
		memprintf(err, "HTTP applets are forbidden from 'tcp-request' rulesets");
		return ACT_RET_PRS_ERR;
	}

	/* Memory for the rule. */
	rule->arg.cffi_rule = calloc(1, sizeof(*rule->arg.cffi_rule));
	if (!rule->arg.cffi_rule) {
		memprintf(err, "out of memory error");
		return ACT_RET_PRS_ERR;
	}

	/* Reference the Lua function and store the reference. */
	rule->arg.cffi_rule->fcn = *fcn;

	/* TODO: later accept arguments. */
	rule->arg.cffi_rule->args = NULL;

	/* Add applet pointer in the rule. */
	rule->applet.obj_type = OBJ_TYPE_APPLET;
	rule->applet.name = fcn->name;
	// FIXME darabi: implement this
	rule->applet.init = cffi_applet_http_init;
	// FIXME darabi: implement this
	rule->applet.fct = cffi_applet_http_fct;
	// FIXME darabi: implement this
	rule->applet.release = cffi_applet_http_release;
	// FIXME darabi: implement this
	rule->applet.timeout = cffi_timeout_applet;

	return ACT_RET_PRS_OK;
}

/* enum act_parse_ret cffi_register_service_tcp(const char **args, int *cur_arg, struct proxy *px, */
/*                                                       struct act_rule *rule, char **err) */
/* { */
/* 	struct hlua_function *fcn = (struct hlua_function *)rule->kw->private; */
/*  */
/* 	/\* Memory for the rule. *\/ */
/* 	rule->arg.hlua_rule = calloc(1, sizeof(*rule->arg.hlua_rule)); */
/* 	if (!rule->arg.hlua_rule) { */
/* 		memprintf(err, "out of memory error"); */
/* 		return ACT_RET_PRS_ERR; */
/* 	} */
/*  */
/* 	/\* Reference the Lua function and store the reference. *\/ */
/* 	rule->arg.hlua_rule->fcn = *fcn; */
/*  */
/* 	/\* TODO: later accept arguments. *\/ */
/* 	rule->arg.hlua_rule->args = NULL; */
/*  */
/* 	/\* Add applet pointer in the rule. *\/ */
/* 	rule->applet.obj_type = OBJ_TYPE_APPLET; */
/* 	rule->applet.name = fcn->name; */
/* 	rule->applet.init = hlua_applet_tcp_init; */
/* 	rule->applet.fct = hlua_applet_tcp_fct; */
/* 	rule->applet.release = hlua_applet_tcp_release; */
/* 	rule->applet.timeout = hlua_timeout_applet; */
/*  */
/* 	return 0; */
/* } */

/* This function is a C function used for registering
 * C callbacks as service functions. It expects a converter name used
 * in the haproxy configuration file, 'tcp' or 'http' as env, and a C
 * function pointer.
 *
 *
 * Returns the error code, 0 if OK, or any combination of :
 *  - ERR_ABORT: must abort ASAP
 *  - ERR_FATAL: we can continue parsing but not start the service
 *  - ERR_WARN: a warning has been emitted
 *  - ERR_ALERT: an alert has been emitted
 * Only the two first ones can stop processing, the two others are just
 * indicators.
 */
int cffi_register_service(char *name, char *env, void *callback)
{
	struct action_kw_list *akl;
	int len;
	struct cffi_function *fcn;

	cffi_log(LOG_DEBUG, "Entering cffi_register_service for following service:");
	cffi_log(LOG_DEBUG, name);

	/* Check required environment. Only accepted "http" or "tcp". */
	/* Allocate and fill the sample fetch keyword struct. */
	akl = calloc(1, sizeof(*akl) + sizeof(struct action_kw) * 2);
	if (!akl) {
		Alert("cffi out of memory error.");
		return ERR_ABORT;
	}
	fcn = calloc(1, sizeof(*fcn));
	if (!fcn) {
		Alert("cffi out of memory error.");
		return ERR_ABORT;
	}
	/* Fill fcn. */
	len = strlen("<cffi.>") + strlen(name) + 1;
	fcn->name = calloc(1, len);
	if (!fcn->name) {
		Alert("cffi out of memory error.");
		return ERR_ABORT;
	}
	snprintf((char *)fcn->name, len, "<cffi.%s>", name);
	fcn->function_ref = callback;

	/* List head */
	akl->list.n = akl->list.p = NULL;

	/* converter keyword. */
	len = strlen("cffi.") + strlen(name) + 1;
	akl->kw[0].kw = calloc(1, len);
	if (!akl->kw[0].kw) {
		Alert("cffi out of memory error.");
		return ERR_ABORT;
	}

	snprintf((char *)akl->kw[0].kw, len, "cffi.%s", name);

	if (strcmp(env, "tcp") == 0)
	  ;
	  // akl->kw[0].parse = cffi_register_service_tcp;
	else if (strcmp(env, "http") == 0)
		akl->kw[0].parse = cffi_register_service_http;
	else {
	  Alert("lua service environment '%s' is unknown. 'tcp' or 'http' are expected.", env);
		return ERR_ABORT;
	}
	akl->kw[0].match_pfx = 0;
	akl->kw[0].private = fcn;

	/* End of array. */
	memset(&akl->kw[1], 0, sizeof(*akl->kw));

	/* Register this new converter */
	service_keywords_register(akl);

	return 0;
}

static int cffi_read_timeout(char **args, int section_type, struct proxy *curpx,
			     struct proxy *defpx, const char *file, int line,
			     char **err, unsigned int *timeout)
{
	const char *error;

	error = parse_time_err(args[1], timeout, TIME_UNIT_MS);
	if (error && *error != '\0') {
		memprintf(err, "%s: invalid timeout", args[0]);
		return -1;
	}
	return 0;
}

static int cffi_session_timeout(char **args, int section_type, struct proxy *curpx,
				struct proxy *defpx, const char *file, int line,
				char **err)
{
	return cffi_read_timeout(args, section_type, curpx, defpx,
				 file, line, err, &hlua_timeout_session);
}

static int cffi_task_timeout(char **args, int section_type, struct proxy *curpx,
			     struct proxy *defpx, const char *file, int line,
			     char **err)
{
	return cffi_read_timeout(args, section_type, curpx, defpx,
				 file, line, err, &hlua_timeout_task);
}

static int cffi_applet_timeout(char **args, int section_type, struct proxy *curpx,
			       struct proxy *defpx, const char *file, int line,
			       char **err)
{
	return cffi_read_timeout(args, section_type, curpx, defpx,
				 file, line, err, &hlua_timeout_applet);
}

static int cffi_forced_yield(char **args, int section_type, struct proxy *curpx,
			     struct proxy *defpx, const char *file, int line,
			     char **err)
{
	return 0;
}

static int cffi_parse_maxmem(char **args, int section_type, struct proxy *curpx,
			     struct proxy *defpx, const char *file, int line,
			     char **err)
{
	return 0;
}

/* This function is called by the main configuration key "cffi-load". It loads and
 * execute an lua file during the parsing of the HAProxy configuration file. It is
 * the main lua entry point.
 *
 * This funtion runs with the HAProxy keywords API. It returns -1 if an error is
 * occured, otherwise it returns 0.
 *
 * In some error case, LUA set an error message in top of the stack. This function
 * returns this error message in the HAProxy logs and pop it from the stack.
 *
 * This function can fail with an abort() due to an Lua critical error.
 * We are in the configuration parsing process of HAProxy, this abort() is
 * tolerated.
 */
static int cffi_load(char **args, int section_type, struct proxy *curpx,
		     struct proxy *defpx, const char *file, int line,
		     char **err)
{
	cffi_log(LOG_DEBUG, "Entering cffi_load\n");
	if(cffi_load_callback != NULL) {
	  return cffi_load_callback(args, section_type, curpx, defpx, file, line, err);
	}
	return 0;
}

/* configuration keywords declaration */
static struct cfg_kw_list cfg_kws = {{ },{
	{ CFG_GLOBAL, "cffi-load",                 cffi_load },
	{ CFG_GLOBAL, "tune.cffi.session-timeout", cffi_session_timeout },
	{ CFG_GLOBAL, "tune.cffi.task-timeout",    cffi_task_timeout },
	{ CFG_GLOBAL, "tune.cffi.service-timeout", cffi_applet_timeout },
	{ CFG_GLOBAL, "tune.cffi.forced-yield",    cffi_forced_yield },
	{ CFG_GLOBAL, "tune.cffi.maxmem",          cffi_parse_maxmem },
	{ 0, NULL, NULL },
}};

/* Ithis function can fail with an abort() due to an Lua critical error.
 * We are in the initialisation process of HAProxy, this abort() is
 * tolerated.
 */
void cffi_init(void)
{
	/* int i; */
	/* int idx; */
	/* struct sample_fetch *sf; */
	/* struct sample_conv *sc; */
	/* char *p; */
	cffi_log(LOG_DEBUG, "Entering cffi_init\n");

	/* Register configuration keywords. */
	cfg_register_keywords(&cfg_kws);
}
