#ifndef EXECMEM_FTRACE_ENUM_H
#define EXECMEM_FTRACE_ENUM_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "common.h"

struct ftrace_hash {
	unsigned long		size_bits;
	struct hlist_head	*buckets;
	unsigned long		count;
	unsigned long		flags;
	struct rcu_head		rcu;
};
/*
struct ftrace_ops_hash {
	struct ftrace_hash __rcu	*notrace_hash;
	struct ftrace_hash __rcu	*filter_hash;
	struct mutex			regex_lock;
};
*/

struct ftrace_enum_ops {
    struct ftrace_ops *next;
};

typedef char *(*kallsyms_lookup_fn)(
    unsigned long addr,
    unsigned long *symbolsize,
    unsigned long *offset,
    char **modname,
    char *name
);

struct ftrace_ops_info {
    unsigned long address;       /* struct ftrace_ops address */

    unsigned long callback;      /* ops->func */

    unsigned long trampoline;    /* ops->trampoline */
    unsigned long trampoline_size;

    unsigned long direct_call;   /* ops->direct_call, if applicable */

    unsigned long flags;
    bool traces_all;

    unsigned long *traced_ips;
    unsigned int traced_count;
};

struct ftrace_ops_info_array {
    struct ftrace_ops_info *ops;
    unsigned int count;
};

struct traced_function_info {
    unsigned long ip;
    char *name;

    unsigned long *callbacks;
    unsigned int callbacks_count;
};

struct traced_function_info_array {
    struct traced_function_info *functions;
    unsigned int count;
};

/* Function declarations */
int ftrace_enum(struct ftrace_ops_info_array *ops_result,
                struct traced_function_info_array *functions_result);
void free_ftrace_info(struct ftrace_ops_info_array *result,
		struct traced_function_info_array *functions_result);

#endif
