#include "vmap_enum.h"
#include "module_enum.h"
#include "ftrace_enum.h"
#include "es_classifier.h"
#include "es_reporter.h"

struct areas execmem_areas;
struct module_info_array module_info;
struct ftrace_ops_info_array ftrace_ops_info;
struct traced_function_info_array ftrace_functions_info;
struct suspicious_page_array suspicious_pages;

static int __init execmem_scan_init(void)
{
    int err;

    pr_info("[execmem_scan] starting scan\n");

    err = vmap_enum(&execmem_areas);
    if (err != 0)
	return err;
    
    pr_info("[execmem_scan] vmap enum completed\n");

    err = module_enum(&module_info);
    if (err != 0)
	return err;
    
    pr_info("[execmem_scan] module enum completed\n");

    err = ftrace_enum(&ftrace_ops_info, &ftrace_functions_info);
    if (err != 0)
	return err;
    
    pr_info("[execmem_scan] ftrace enum completed\n");

    err = es_classify(&execmem_areas, &module_info, &ftrace_ops_info, &suspicious_pages);
    if (err != 0)
	return err;
    
    pr_info("[execmem_scan] es_classify completed\n");
    
    err = execmem_scan_report(&module_info, &ftrace_ops_info, &ftrace_functions_info, &suspicious_pages);
    if (err != 0)
	return err;
    
    pr_info("[execmem_scan] es_report completed\n");
    
    pr_info("[execmem_scan] scan completed\n");

    return 0;
}

static void __exit execmem_scan_exit(void)
{
    free_execmem_areas(&execmem_areas);
    free_module_info(&module_info);
    free_ftrace_info(&ftrace_ops_info, &ftrace_functions_info);
    free_suspicious_pages(&suspicious_pages);
    pr_info("[execmem_scan] unloaded\n");
}

module_init(execmem_scan_init);
module_exit(execmem_scan_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sergio Apellaniz");
MODULE_DESCRIPTION("Linux Rootkits Detection Tool for Linux 6.10+");
