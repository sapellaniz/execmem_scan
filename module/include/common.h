#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kprobes.h>

/* Function declarations */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *);
unsigned long resolve_symbol(const char *name);
