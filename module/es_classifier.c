#include "es_classifier.h"

static bool page_is_filled_cc(unsigned long addr)
{
    void *mapped;
    bool result;
    struct page *page;

    page = vmalloc_to_page((void *)addr);
    if (!page)
        return false;

    mapped = kmap_local_page(page);

    result = (memchr_inv(mapped, 0xCC, PAGE_SIZE) == NULL);

    kunmap_local(mapped);

    return result;
}

static bool belongs_to_module(
    unsigned long address,
    const struct module_info_array *modules)
{
    unsigned int i, j;

    for (i = 0; i < modules->count; i++) {
        const struct module_info *mod = &modules->modules[i];

        for (j = 0; j < mod->nr_ranges; j++) {
            const struct module_mem_range *range = &mod->ranges[j];

            if (address >= range->start && address < range->end)
                return true;
        }
    }

    return false;
}

static bool belongs_to_ftrace(
    unsigned long page_start,
    const struct ftrace_ops_info_array *ops_result)
{
    unsigned long page_end = page_start + PAGE_SIZE;
    unsigned long trampoline_end;
    struct ftrace_ops_info *ops;
    unsigned int i;

    if (!ops_result)
        return false;

    for (i = 0; i < ops_result->count; i++) {
        ops = &ops_result->ops[i];

        /* Check whether callback falls inside the page. */
        if (ops->callback >= page_start &&
            ops->callback < page_end)
            return true;

        /* Check trampoline overlap with the page. */
        if (!ops->trampoline || !ops->trampoline_size)
            continue;

        trampoline_end = ops->trampoline +
                         ops->trampoline_size;

        if (ops->trampoline < page_end &&
            trampoline_end > page_start)
            return true;
    }

    return false;
}

static int add_suspicious_page(
    struct suspicious_page_array *result,
    unsigned long address,
    enum suspicious_type type)
{
    struct suspicious_page *pages;

    pages = krealloc_array(
        result->pages,
        result->count + 1,
        sizeof(*result->pages),
        GFP_KERNEL
    );

    if (!pages)
        return -1;

    result->pages = pages;

    result->pages[result->count].base_address = address;
    result->pages[result->count].type = type;

    result->count++;

    return 0;
}

static int classify_ranges(
    const struct range_array *ranges,
    enum suspicious_type type,
    const struct module_info_array *module_info,
    const struct ftrace_ops_info_array *ftrace_info,
    struct suspicious_page_array *result)
{
    size_t i;
    unsigned long addr;
    int ret;

    for (i = 0; i < ranges->count; i++) {
        for (addr = ranges->ranges[i].start;
             addr < ranges->ranges[i].end;
             addr += PAGE_SIZE) {

	    if (page_is_filled_cc(addr))
		continue;

            if (belongs_to_module(addr, module_info))
                continue;
            
	    if (belongs_to_ftrace(addr, ftrace_info))
                continue;

            ret = add_suspicious_page(result, addr, type);
            if (ret)
                return ret;
        }
    }

    return 0;
}

int es_classify(
    const struct areas *areas,
    const struct module_info_array *module_info,
    const struct ftrace_ops_info_array *ftrace_info,
    struct suspicious_page_array *result)
{
    int ret;

    if (!areas || !module_info || !ftrace_info || !result)
        return -EINVAL;

    result->pages = NULL;
    result->count = 0;

    ret = classify_ranges(&areas->text, SUSPICIOUS_TEXT, module_info, ftrace_info, result);
    if (ret)
        goto error;

    /* BPF is not supported yet
    ret = classify_ranges(&areas->bpf, SUSPICIOUS_BPF, module_info, result);
    if (ret)
        goto error;
    */

    ret = classify_ranges(&areas->mod_data, SUSPICIOUS_MOD_DATA, module_info, ftrace_info, result);
    if (ret)
        goto error;

    ret = classify_ranges(&areas->mod_rodata, SUSPICIOUS_MOD_RODATA, module_info, ftrace_info, result);
    if (ret)
        goto error;

    return 0;

error:
    free_suspicious_pages(result);
    return ret;
}

void free_suspicious_pages(struct suspicious_page_array *result)
{
    if (!result)
        return;

    kfree(result->pages);

    result->pages = NULL;
    result->count = 0;
}
