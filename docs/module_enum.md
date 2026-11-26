# module_enum

## Loadable Kernel Modules (LKMs)

LKMs are components that can be dynamically loaded into the Linux kernel to extend its functionality without requiring a kernel rebuild or system reboot. They are commonly used for device drivers and other kernel extensions.

Rootkits can abuse LKMs to execute code with kernel privileges, modify internal kernel structures, alter kernel functionality, intercept system calls, and manipulate enumeration mechanisms to hide processes, files, network connections, or other system entities.

Because kernel modules operate in kernel space, they can also interfere with security tools and undermine conventional detection mechanisms.

## Module Memory Layout

Module memory layout is defined in module.h:

```c
enum mod_mem_type {
	MOD_TEXT = 0,
	MOD_DATA,
	MOD_RODATA,
	MOD_RO_AFTER_INIT,
	MOD_INIT_TEXT,
	MOD_INIT_DATA,
	MOD_INIT_RODATA,

	MOD_MEM_NUM_TYPES,
	MOD_INVALID = -1,
};
```

- **`MOD_TEXT`** — Contains the module's executable code, including its functions.
- **`MOD_DATA`** — Contains writable data used by the module, such as global and static variables.
- **`MOD_RODATA`** — Contains read-only data, such as constants and static read-only variables.
- **`MOD_RO_AFTER_INIT`** — Contains data that is writable during module initialization but becomes read-only after initialization completes.
- **`MOD_INIT_TEXT`** — Contains executable code used exclusively during module initialization. It is freed after initialization completes.
- **`MOD_INIT_DATA`** — Contains writable data used exclusively during module initialization. It is freed after initialization completes.
- **`MOD_INIT_RODATA`** — Contains read-only data used exclusively during module initialization. It is freed after initialization completes.

## Module List (`modules`)

The Linux kernel maintains a doubly linked list of loaded kernel modules, commonly referred to as the **module list** and anchored by the `modules` list head (`struct list_head`). Each loaded module is linked into this list through its `struct module` structure.

User-space tools such as `lsmod` rely on information exposed through `/proc/modules`, which is populated from this module list, to enumerate loaded modules.

One of the well-known stealth techniques used by kernel-space rootkits is **module list unlinking** (also known as module hiding). By removing their `struct module` entry from the kernel's module list, rootkits can hide themselves from the normal enumeration mechanisms, causing them to disappear from tools such as `lsmod`, despite remaining loaded and potentially executing in kernel space.

`execmem_scan` uses this list to enumerate visible (non-hidden) loaded modules and collect the memory ranges associated with each module section.
