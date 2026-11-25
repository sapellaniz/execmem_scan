#ifndef EXECMEM_ES_CLASSIFIER_H
#define EXECMEM_ES_CLASSIFIER_H

#include <linux/types.h>
#include "vmap_enum.h"
#include "module_enum.h"
#include "ftrace_enum.h"

enum suspicious_type {
    SUSPICIOUS_TEXT,
    SUSPICIOUS_BPF,
    SUSPICIOUS_MOD_DATA,
    SUSPICIOUS_MOD_RODATA,
};

struct suspicious_page {
    enum suspicious_type type;
    unsigned long base_address;
};

struct suspicious_page_array {
    struct suspicious_page *pages;
    unsigned int count;
};

/* Function declarations */
int es_classify(
    const struct areas *areas,
    const struct module_info_array *modules,
    const struct ftrace_ops_info_array *ftrace_info,
    struct suspicious_page_array *result
);

void free_suspicious_pages(struct suspicious_page_array *result);

#endif
