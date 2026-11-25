#ifndef EXECMEM_MODULE_ENUM_H
#define EXECMEM_MODULE_ENUM_H

#include "common.h"

#define MODULE_NAME_LEN_MAX MODULE_NAME_LEN

struct module_mem_range {
    enum mod_mem_type type;
    unsigned long start;
    unsigned long end;      /* Exclusive */
    unsigned int size;
};

struct module_info {
    char name[MODULE_NAME_LEN_MAX];

    struct module_mem_range ranges[MOD_MEM_NUM_TYPES];
    unsigned int nr_ranges;
};

struct module_info_array {
    struct module_info *modules;
    unsigned int count;
};

/* Function declarations */
int module_enum(struct module_info_array *result);
void free_module_info(struct module_info_array *result);

#endif
