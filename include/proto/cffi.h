#ifndef _PROTO_CFFI_H
#define _PROTO_CFFI_H

#include <types/cffi.h>
#include <types/proxy.h>

/* CFFI HAProxy integration functions. */
// void cffi_ctx_destroy(struct hlua *lua);
void cffi_init();
void cffi_set_load_callback(int (*new_callback)(char **args, int section_type, struct proxy *curpx,
                                                struct proxy *defpx, const char *file, int line,
                                                char **err));

#endif /* _PROTO_CFFI_H */
