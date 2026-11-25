#include "ftrace_enum.h"

typedef char *(*kallsyms_lookup_fn)(
    unsigned long addr,
    unsigned long *symbolsize,
    unsigned long *offset,
    char **modname,
    char *name
);

static int ftrace_ops_populate(struct ftrace_ops_info *info,
                               struct ftrace_ops *ops);

static int ftrace_ops_add(struct ftrace_ops_info_array *result,
                          struct ftrace_ops *ops);

static int ftrace_ops_list_enum(struct ftrace_ops_info_array *result);

static int ftrace_ops_trampoline_list_enum(
    struct ftrace_ops_info_array *result);

static struct ftrace_ops_info *
ftrace_ops_find(struct ftrace_ops_info_array *result,
                unsigned long address);

static struct traced_function_info *
traced_function_find(struct traced_function_info_array *result,
                     unsigned long ip);

static int traced_function_add(
    struct traced_function_info_array *result,
    unsigned long ip,
    struct traced_function_info **entry);

static int traced_function_add_callback(
    struct traced_function_info *function,
    unsigned long callback);

static int ftrace_ops_add_ip(struct ftrace_ops_info *ops,
                             unsigned long ip);

static int ftrace_hash_enum(
    struct ftrace_ops_info *ops_info,
    struct ftrace_hash *filter_hash,
    struct traced_function_info_array *functions_result);

static int traced_functions_populate(
    struct ftrace_ops_info_array *ops_result,
    struct traced_function_info_array *functions_result);

static char *ftrace_symbol_name(unsigned long ip)
{
    kallsyms_lookup_fn lookup;
    char namebuf[KSYM_NAME_LEN];
    char *modname = NULL;
    char *name;
    unsigned long symbolsize = 0;
    unsigned long offset = 0;

    lookup = (kallsyms_lookup_fn)resolve_symbol("kallsyms_lookup");

    if (!lookup)
        return NULL;

    name = lookup(ip, &symbolsize, &offset, &modname, namebuf);

    if (!name)
        return NULL;

    return kstrdup(name, GFP_KERNEL);
}

static struct ftrace_ops_info *
ftrace_ops_find(struct ftrace_ops_info_array *result,
                unsigned long address)
{
    unsigned int i;

    for (i = 0; i < result->count; i++) {
        if (result->ops[i].address == address)
            return &result->ops[i];
    }

    return NULL;
}

static int ftrace_ops_add(struct ftrace_ops_info_array *result,
                          struct ftrace_ops *ops)
{
    struct ftrace_ops_info info = {0};
    struct ftrace_ops_info *tmp;
    int ret;

    if (!result || !ops)
        return -EINVAL;

    if (ftrace_ops_find(result, (unsigned long)ops))
        return 0;
    
    info.address = (unsigned long)ops;

    ret = ftrace_ops_populate(&info, ops);
    if (ret)
        goto error;

    tmp = krealloc_array(result->ops,
                         result->count + 1,
                         sizeof(*result->ops),
                         GFP_KERNEL);

    if (!tmp) {
        ret = -ENOMEM;
        goto error;
    }

    result->ops = tmp;
    result->ops[result->count++] = info;

    return 0;

error:
    kfree(info.traced_ips);
    return ret;
}

static int ftrace_ops_populate(struct ftrace_ops_info *info,
                               struct ftrace_ops *ops)
{
    struct ftrace_ops_hash *func_hash;
    struct ftrace_hash *filter_hash;
    struct ftrace_hash *notrace_hash;

    if (!info || !ops)
        return -EINVAL;

    info->callback = (unsigned long)ops->func;
    info->flags = READ_ONCE(ops->flags);

    info->trampoline = (unsigned long)ops->trampoline;
    info->trampoline_size = READ_ONCE(ops->trampoline_size);

    info->direct_call = 0;

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS
#ifndef CONFIG_HAVE_SINGLE_FTRACE_DIRECT_OPS
    info->direct_call = READ_ONCE(ops->direct_call);
#endif
#endif

    func_hash = READ_ONCE(ops->func_hash);
    
    if (!func_hash)
        return -EINVAL;

    filter_hash = READ_ONCE(func_hash->filter_hash);
    notrace_hash = READ_ONCE(func_hash->notrace_hash);

    info->traces_all = false;
    if (filter_hash && notrace_hash) {
	info->traces_all =
	    (info->flags & FTRACE_OPS_FL_ENABLED) &&
    	    !filter_hash->count;
    }

    return 0;
}

static struct traced_function_info *
traced_function_find(struct traced_function_info_array *result,
                     unsigned long ip)
{
    unsigned int i;

    for (i = 0; i < result->count; i++) {
        if (result->functions[i].ip == ip)
            return &result->functions[i];
    }

    return NULL;
}

static int traced_function_add(
    struct traced_function_info_array *result,
    unsigned long ip,
    struct traced_function_info **entry)
{
    struct traced_function_info *tmp;
    struct traced_function_info *function;

    function = traced_function_find(result, ip);

    if (function) {
        *entry = function;
        return 0;
    }

    tmp = krealloc_array(result->functions,
                         result->count + 1,
                         sizeof(*result->functions),
                         GFP_KERNEL);

    if (!tmp)
        return -ENOMEM;

    result->functions = tmp;

    function = &result->functions[result->count];
    memset(function, 0, sizeof(*function));

    function->ip = ip;
    function->name = ftrace_symbol_name(ip);

    result->count++;

    *entry = function;

    return 0;
}

static int traced_function_add_callback(
    struct traced_function_info *function,
    unsigned long callback)
{
    unsigned long *tmp;
    unsigned int i;

    if (!function || !callback)
        return -EINVAL;

    for (i = 0; i < function->callbacks_count; i++) {
        if (function->callbacks[i] == callback)
            return 0;
    }

    tmp = krealloc_array(function->callbacks,
                         function->callbacks_count + 1,
                         sizeof(*function->callbacks),
                         GFP_KERNEL);

    if (!tmp)
        return -ENOMEM;

    function->callbacks = tmp;
    function->callbacks[function->callbacks_count++] = callback;

    return 0;
}

static int ftrace_ops_add_ip(struct ftrace_ops_info *ops,
                             unsigned long ip)
{
    unsigned long *tmp;
    unsigned int i;

    for (i = 0; i < ops->traced_count; i++) {
        if (ops->traced_ips[i] == ip)
            return 0;
    }

    tmp = krealloc_array(ops->traced_ips,
                         ops->traced_count + 1,
                         sizeof(*ops->traced_ips),
                         GFP_KERNEL);

    if (!tmp)
        return -ENOMEM;

    ops->traced_ips = tmp;
    ops->traced_ips[ops->traced_count++] = ip;

    return 0;
}

static int ftrace_hash_enum(
    struct ftrace_ops_info *ops_info,
    struct ftrace_hash *filter_hash,
    struct traced_function_info_array *functions_result)
{
    struct ftrace_func_entry *entry;
    struct hlist_head *head;
    struct traced_function_info *function;
    unsigned int i;
    unsigned long ip;
    int ret;

    if (!ops_info || !filter_hash || !functions_result)
        return -EINVAL;

    /*
     * An empty filter hash means this ops does not have
     * individually enumerated filter entries.
     */
    if (!filter_hash->buckets || !filter_hash->count)
        return 0;

    for (i = 0; i < (1UL << filter_hash->size_bits); i++) {
        head = &filter_hash->buckets[i];

        hlist_for_each_entry(entry, head, hlist) {
            ip = entry->ip;

            ret = ftrace_ops_add_ip(ops_info, ip);
            if (ret)
                return ret;

            ret = traced_function_add(
                functions_result, ip, &function);
            if (ret)
                return ret;

            ret = traced_function_add_callback(
                function, ops_info->callback);
            if (ret)
                return ret;
        }
    }

    return 0;
}

static int traced_functions_populate(
    struct ftrace_ops_info_array *ops_result,
    struct traced_function_info_array *functions_result)
{
    struct ftrace_ops_info *ops_info;
    struct ftrace_ops *ops;
    struct ftrace_ops_hash *func_hash;
    unsigned int i;
    int ret = 0;

    if (!ops_result || !functions_result)
        return -EINVAL;

    for (i = 0; i < ops_result->count; i++) {
        ops_info = &ops_result->ops[i];

        /*
         * All-functions ops are represented by traces_all.
         * Their IPs are intentionally not expanded.
         */
        if (ops_info->traces_all)
            continue;

        ops = (struct ftrace_ops *)ops_info->address;

        func_hash = READ_ONCE(ops->func_hash);
        if (!func_hash) {
            ret = -EINVAL;
            break;
        }

        ret = ftrace_hash_enum(ops_info,
                               READ_ONCE(func_hash->filter_hash),
                               functions_result);
        if (ret)
            break;
    }

    return ret;
}

static int ftrace_ops_list_enum(struct ftrace_ops_info_array *result)
{
    struct ftrace_ops *ops;
    struct ftrace_ops **ops_list;
    struct ftrace_ops *ftrace_list_end_ptr;
    int ret = 0;

    ops_list = (struct ftrace_ops **)resolve_symbol("ftrace_ops_list");
    ftrace_list_end_ptr =
        (struct ftrace_ops *)resolve_symbol("ftrace_list_end");

    if (!ops_list || !ftrace_list_end_ptr)
        return -ENOENT;

    rcu_read_lock();

    ops = rcu_dereference(*ops_list);

    while (ops && ops != ftrace_list_end_ptr) {
        ret = ftrace_ops_add(result, ops);

        if (ret)
            break;

        ops = rcu_dereference(ops->next);
    }

    rcu_read_unlock();

    return ret;
}

static int ftrace_ops_trampoline_list_enum(
    struct ftrace_ops_info_array *result)
{
    struct list_head *head;
    struct ftrace_ops *ops;

    head = (struct list_head *)
        resolve_symbol("ftrace_ops_trampoline_list");

    if (!head)
        return -ENOENT;

    rcu_read_lock();

    list_for_each_entry_rcu(ops, head, list) {
        int ret;

        ret = ftrace_ops_add(result, ops);

        if (ret) {
            rcu_read_unlock();
            return ret;
        }
    }

    rcu_read_unlock();

    return 0;
}

int ftrace_enum(struct ftrace_ops_info_array *ops_result,
                struct traced_function_info_array *functions_result)
{
    int ret;

    if (!ops_result || !functions_result)
        return -EINVAL;

    memset(ops_result, 0, sizeof(*ops_result));
    memset(functions_result, 0, sizeof(*functions_result));

    ret = ftrace_ops_list_enum(ops_result);
    if (ret)
        goto error;

    ret = ftrace_ops_trampoline_list_enum(ops_result);
    if (ret)
        goto error;

    ret = traced_functions_populate(ops_result, functions_result);
    if (ret)
        goto error;

    return 0;

error:
    free_ftrace_info(ops_result, functions_result);
    return ret;
}

void free_ftrace_info(
    struct ftrace_ops_info_array *ops_result,
    struct traced_function_info_array *functions_result)
{
    unsigned int i;

    if (ops_result) {
        for (i = 0; i < ops_result->count; i++)
            kfree(ops_result->ops[i].traced_ips);

        kfree(ops_result->ops);

        memset(ops_result, 0, sizeof(*ops_result));
    }

    if (functions_result) {
        for (i = 0; i < functions_result->count; i++) {
            kfree(functions_result->functions[i].name);
            kfree(functions_result->functions[i].callbacks);
	    kfree(functions_result->functions[i].name);
        }

        kfree(functions_result->functions);

        memset(functions_result, 0, sizeof(*functions_result));
    }
}
