#ifndef EXECMEM_ES_REPORTER_H
#define EXECMEM_ES_REPORTER_H

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/stdarg.h>

#include "module_enum.h"
#include "ftrace_enum.h"
#include "es_classifier.h"

#define REPORT_PATH "/tmp/execmem_scan_report.txt"
#define REPORT_BUF_SIZE 960

int execmem_scan_report(
        const struct module_info_array *module_info,
        const struct ftrace_ops_info_array *ftrace_info,
	const struct traced_function_info_array *ftrace_functions_info,
        const struct suspicious_page_array *suspicious_pages
);

#endif
