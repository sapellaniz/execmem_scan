#include "es_reporter.h"

static int report_write(struct file *file, loff_t *pos,
                        const char *fmt, ...)
{
    char buf[REPORT_BUF_SIZE];
    va_list args;
    int len;
    int written = 0;
    ssize_t ret;

    va_start(args, fmt);
    len = vscnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    while (written < len) {
        ret = kernel_write(file, buf + written,
                           len - written, pos);

        if (ret < 0)
            return ret;

        if (ret == 0)
            return -EIO;

        written += ret;
    }

    return 0;
}

static const char *suspicious_page_type_name(enum suspicious_type type)
{
    switch (type) {
    case SUSPICIOUS_TEXT:
        return "TEXT";

    case SUSPICIOUS_BPF:
        return "BPF";

    case SUSPICIOUS_MOD_DATA:
        return "MOD_DATA";

    case SUSPICIOUS_MOD_RODATA:
        return "MOD_RODATA";

    default:
        return "UNKNOWN";
    }
}

static int report_modules(struct file *file, loff_t *pos,
                          const struct module_info_array *module_info)
{
    unsigned int i;
    int err;

    err = report_write(file, pos, "=== LOADED MODULES ===\n");
    if (err)
        return err;

    for (i = 0; i < module_info->count; i++) {
        err = report_write(file, pos, "%s, ",
                           module_info->modules[i].name);
        if (err)
            return err;
    }

    return report_write(file, pos, "\n");
}

static int report_ftrace(struct file *file, loff_t *pos,
                        const struct ftrace_ops_info_array *ftrace_info,
                        const struct traced_function_info_array *functions_result)
{
    unsigned int i, j, k;
    int ret;

    if (!file || !pos || !ftrace_info || !functions_result)
        return -EINVAL;

    ret = report_write(file, pos, "\n=== TRACED FUNCTIONS ===\n");
    if (ret)
        return ret;

    for (i = 0; i < functions_result->count; i++) {
        const struct traced_function_info *function =
            &functions_result->functions[i];

        ret = report_write(file, pos,
            "%s ip=0x%016lx\n",
            function->name ? function->name : "UNKNOWN",
            function->ip);
        if (ret)
            return ret;

        /* Report callbacks associated with this function */
        for (j = 0; j < function->callbacks_count; j++) {
            ret = report_write(file, pos,
                "  callback[%u]=0x%016lx\n",
                j, function->callbacks[j]);
            if (ret)
                return ret;
        }

        /* Find ftrace_ops entries tracing this function */
        for (j = 0; j < ftrace_info->count; j++) {
            const struct ftrace_ops_info *ops =
                &ftrace_info->ops[j];
            bool traces_function = false;

            for (k = 0; k < ops->traced_count; k++) {
                if (ops->traced_ips[k] == function->ip) {
                    traces_function = true;
                    break;
                }
            }

            if (!traces_function)
                continue;

            if (ops->direct_call) {
                ret = report_write(file, pos,
                    "  direct_call=0x%016lx\n",
                    ops->direct_call);
                if (ret)
                    return ret;
            }

            if (ops->trampoline) {
                ret = report_write(file, pos,
                    "  trampoline=0x%016lx size=%lx\n",
                    ops->trampoline,
                    ops->trampoline_size);
                if (ret)
                    return ret;
            }
        }
    }

    return 0;
}

static int report_suspicious_pages(struct file *file, loff_t *pos,
                             const struct suspicious_page_array *result)
{
    unsigned int i;
    int err;

    err = report_write(file, pos, "\n=== SUSPICIOUS PAGES ===\n");
    if (err)
        return err;

    for (i = 0; i < result->count; i++) {
        err = report_write(file, pos,
                           "%-12s 0x%016lx\n",
                           suspicious_page_type_name(result->pages[i].type),
                           result->pages[i].base_address);
        if (err)
            return err;
    }

    return report_write(file, pos, "\n");
}

static void report_summary(
        const struct module_info_array *module_info,
        const struct traced_function_info_array *ftrace_functions_info,
        const struct suspicious_page_array *suspicious_pages)
{
    unsigned int text = 0;
    unsigned int bpf = 0;
    unsigned int mod_data = 0;
    unsigned int mod_rodata = 0;
    unsigned int i;

    for (i = 0; i < suspicious_pages->count; i++) {
        switch (suspicious_pages->pages[i].type) {
        case SUSPICIOUS_TEXT:
            text++;
            break;

        case SUSPICIOUS_BPF:
            bpf++;
            break;

        case SUSPICIOUS_MOD_DATA:
            mod_data++;
            break;

        case SUSPICIOUS_MOD_RODATA:
            mod_rodata++;
            break;

        default:
            break;
        }
    }

    pr_info("=== [execmem_scan] ===\n"
	    "- %u modules loaded\n"
	    "- %u traced functions\n"
	    "- %u suspicious pages\n"
	    "  - TEXT pages %u\n"
	    "  - BPF pages %u\n"
	    "  - MOD_DATA pages %u\n"
	    "  - MOD_RODATA pages %u\n"
	    "===================\n",
	    module_info->count,
	    ftrace_functions_info->count,
	    suspicious_pages->count,
	    text,
	    bpf,
	    mod_data,
	    mod_rodata);
}

int execmem_scan_report(
        const struct module_info_array *module_info,
        const struct ftrace_ops_info_array *ftrace_ops_info,
	const struct traced_function_info_array *ftrace_functions_info,
        const struct suspicious_page_array *suspicious_pages)
{
    struct file *file;
    loff_t pos = 0;
    int err;

    if (!module_info || !ftrace_ops_info || !ftrace_functions_info || !suspicious_pages)
        return -EINVAL;

    if ((module_info->count && !module_info->modules) ||
        (ftrace_functions_info->count && !ftrace_functions_info->functions) ||
        (suspicious_pages->count && !suspicious_pages->pages))
        return -EINVAL;

    /* Print summary to dmesg. */
    report_summary(module_info, ftrace_functions_info, suspicious_pages);

    /* Create/truncate report file. */
    file = filp_open(REPORT_PATH,
                     O_WRONLY | O_CREAT | O_TRUNC,
                     0600);

    if (IS_ERR(file)) {
        err = PTR_ERR(file);
        pr_err("[execmem_scan] Failed to open report file: %d\n",
               err);
        return err;
    }

    /* Write detailed report. */
    err = report_modules(file, &pos, module_info);
    if (err)
        goto out;

    err = report_ftrace(file, &pos, ftrace_ops_info, ftrace_functions_info);
    if (err)
        goto out;

    err = report_suspicious_pages(file, &pos, suspicious_pages);

out:
    filp_close(file, NULL);

    if (err)
        pr_err("[execmem_scan] Failed to write report: %d\n", err);
    else
        pr_info("[execmem_scan] Report written to %s\n", REPORT_PATH);

    return err;
}

