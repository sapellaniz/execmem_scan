#include "module_enum.h"

static void collect_module_info(struct module *mod,
                               struct module_info *info)
{
    enum mod_mem_type type;

    memset(info, 0, sizeof(*info));

    strscpy(info->name, mod->name, sizeof(info->name));

    for (type = 0; type < MOD_MEM_NUM_TYPES; type++) {
        struct module_memory *mem = &mod->mem[type];
        struct module_mem_range *range;

        if (!mem->size)
            continue;

        range = &info->ranges[info->nr_ranges++];

        range->type  = type;
        range->start = (unsigned long)mem->base;
        range->end   = range->start + mem->size;
        range->size  = mem->size;

    }
}

int module_enum(struct module_info_array *result)
{
    struct list_head *module_list;
    struct module *mod;
    unsigned int count = 0;
    unsigned int i = 0;
 
    module_list = (struct list_head *)resolve_symbol("modules");
    if (!module_list)
	return -1;

    if (!module_list || !result)
        return -1;

    result->modules = NULL;
    result->count = 0;

    // First pass: count modules
    list_for_each_entry(mod, module_list, list)
        count++;

    if (!count)
        return 0;

    result->modules = kcalloc(count, sizeof(*result->modules),
                              GFP_KERNEL);
    if (!result->modules)
        return -1;

    // Second pass: collect information
    list_for_each_entry(mod, module_list, list) {
        if (i >= count)
            break;

        collect_module_info(mod, &result->modules[i]);
        i++;
    }

    result->count = i;

    return 0;
}

void free_module_info(struct module_info_array *modules)
{
    if (!modules)
        return;

    kfree(modules->modules);

    memset(modules, 0, sizeof(*modules));
}
