# es_reporter

`es_reporter` generates a summary and a detailed report of the analysis. By default, the detailed report is saved to `/tmp/execmem_scan_report.txt`.

The detailed report is written to a file to make `execmem_scan` results easier to parse, share, and analyze. This is particularly important for the kernel module implementation, as some rootkits manipulate or filter messages written to the kernel ring buffer, making `pr_info()` and `dmesg` potentially unreliable sources of information.

## Summary

The summary displays the total number of:

- Loaded modules.
- Traced functions.
- Suspicious executable memory pages, broken down by classification:
    - Suspicious `TEXT` pages.
    - Suspicious `BPF` pages.
    - Suspicious `MOD_DATA` pages.
    - Suspicious `MOD_RODATA` pages.

Suspicious page types are defined in [VMAP Area Classification](vmap_enum.md#vmap-area-classification).

## Detailed Report

### Modules

Lists the loaded kernel modules identified by `execmem_scan`.

**Recommendations:**

- Check for unexpected or unknown modules.
- Compare the results against `lsmod`. Discrepancies, such as modules reported by `execmem_scan` but missing from `lsmod`, may indicate module hiding or kernel tampering.

### Ftrace

Lists traced functions. For each traced function, `execmem_scan` reports:

- **Function name:** The name of the kernel function being traced.
- **Callbacks:** The callback functions associated with tracing the function.
- **Direct calls:** Direct-call targets associated with the function.
- **Trampolines:** Trampoline addresses associated with the tracing operation.

**Recommendations:**

- Review which kernel functions are being traced and identify the Ftrace operations and execution mechanisms associated with each one. This information can help investigate potentially malicious hooks, unexpected tracing operations, and suspicious executable memory associated with Ftrace.
- Compare the results against `/sys/kernel/tracing/enabled_functions`. Functions reported by `execmem_scan` but missing from this interface may indicate Ftrace hooks hidden from user-space enumeration and warrant further investigation.

### Kprobes

TBD

### BPF

TBD

### Suspicious Pages

For each suspicious page, the detailed report includes its classification and the starting address (`page_start`) of the page.

These pages are not associated with any known executable memory object enumerated by `execmem_scan` and therefore require further investigation.

**Recommendation:**

- It is mandatory to inspect every suspicious page to determine whether it contains legitimate code/data or potentially malicious content. The pages can be examined by dumping their contents using memory-dump tools, `gdb` with `/proc/kcore`, or other kernel-memory analysis tools. The inspection should focus on identifying executable code, unexpected data, hooks, or other indicators of kernel compromise.
