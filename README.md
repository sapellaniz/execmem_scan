# execmem scan
Traditional Linux rootkit detection techniques rely on signatures and the identification of previously known Indicators of Compromise (IOCs). Although these approaches can detect documented threats, they present significant limitations when facing rootkits that implement stealth techniques or modify their behavior to evade existing detection mechanisms.

*execmem scan* introduces an alternative approach based on anomaly analysis within the memory space managed by execmem, the kernel subsystem responsible for managing executable memory allocations. Based on this approach, a Volatility plugin has been developed to analyze memory dumps, along with a Linux kernel module to analyze live systems. Both are designed to identify and extract kernel memory regions containing malicious Linux Kernel Modules (LKMs), kprobes, and ftrace hooks, facilitating subsequent forensic analysis.

The techniques implemented in *execmem scan* enable rootkit detection through an approach focused on analyzing kernel memory structures and integrity, rather than relying exclusively on signatures or known Indicators of Compromise.

For now, eBPF-based rootkits are outside the scope of *execmem scan*. Although execmem is involved in managing executable memory used by BPF, these programs rely on specific allocation mechanisms through the BPF JIT memory allocator, which require a separate analysis approach.

Rootkits that rely exclusively on function hooking, rather than DKOM techniques, cannot be detected solely through memory analysis with *execmem scan*. However, its findings can be cross-referenced with those obtained through enumeration tools running on the system under investigation to identify potential discrepancies. For example, a system may have X kernel modules loaded, while a rootkit uses function hooking to manipulate the output of lsmod and conceal itself, yet remains present in the kernel's internal module list. In this scenario, *execmem scan* would not identify the module as malicious and would report X loaded modules. However, if lsmod reports only X-1 modules, the discrepancy between the two results could indicate the possible presence of a hidden module.

> **Disclaimer:** At this stage, the Volatility plugin offers more features than the Linux kernel module. Both implementations are under active development, and their functionalities will gradually be brought into parity over time.

## Screenshots

### Volatility Plugin

![execmem scan Volatility plugin](docs/images/volatility_plugin.png)

### Linux Kernel Module

![execmem scan Linux kernel module](docs/images/linux_module.png)
