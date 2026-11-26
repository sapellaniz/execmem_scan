# vmap_enum

## Memory Management Structures

The memory regions managed by execmem are represented by `vmap_area` structures. These regions are grouped into `vmap_node` structures, which are organized in an array referenced by the `vmap_nodes` symbol.

The number of entries in this array, corresponding to the number of `vmap_node` structures, is defined by the `nr_vmap_nodes` symbol.

```
vmap_nodes
    |
    +->+---------------+
       |               |   vmap_nodes
       |   vmap_node   |      [0]
       |               |
       +---------------+
       |               |   vmap_nodes
       |   vmap_node   |      [1]
       |               |
       +---------------+
              ...
       +---------------+
       |               |   vmap_nodes
       |   vmap_node   | [nr_vmap_nodes]
       |               |
       +---------------+
```

Each `vmap_node` maintains active and free memory regions. Active regions can be traversed through the linked list referenced by `vmap_node->busy->head`.

execmem_scan enumerates these structures and selects active `vmap_area` regions, focusing the analysis on memory allocated through execmem. 

## Memory Allocation Types

The memory allocation types handled by execmem are defined in `enum execmem_type`, declared in `execmem.h`:

```c
enum execmem_type {
    EXECMEM_DEFAULT,
    EXECMEM_MODULE_TEXT = EXECMEM_DEFAULT,
    EXECMEM_KPROBES,
    EXECMEM_FTRACE,
    EXECMEM_BPF,
    EXECMEM_MODULE_DATA,
    EXECMEM_TYPE_MAX,
};
```

These allocation types correspond to different kernel subsystems and memory usage patterns. Understanding these distinctions is essential for classifying memory regions and identifying allocations that do not match expected behavior.

## Memory Allocation Patterns

The memory layout depends on the subsystem requesting the allocation:

- **Modules, kprobes, and ftrace:** Executable code is allocated within memory regions consisting of 512 pages. When an allocation cannot be accommodated within an existing region, a new region is allocated.
- **BPF:** BPF programs are allocated within dedicated 512-page regions. Memory within these regions is managed by the BPF JIT memory allocator.
- **Module data:** Module data is allocated separately in regions sized according to the module's requirements. Each module has its own data allocation.

On x86, pages that are free or have been released may be filled with `0xCC` (`INT3`) as a protective measure against unintended execution of stale memory. execmem_scan also takes this memory pattern into account during its analysis.

## VMAP Area Classification

`vmap_enum` classifies each enumerated `vmap_area` according to its allocation size and memory permissions. 

The following classifications are used:

| Classification | Allocation type | Description |
|---|---|---|
| `TEXT` | `EXECMEM_MODULE_TEXT` | Module text and init text (`MOD_TEXT`, `MOD_INIT_TEXT`), Kprobes (`EXECMEM_KPROBES`), and Ftrace (`EXECMEM_FTRACE`). |
| `BPF` | `EXECMEM_BPF` | Executable memory allocated for BPF programs. |
| `MOD_DATA` | `EXECMEM_MODULE_DATA` | Writable module data (`MOD_DATA`, `MOD_INIT_DATA`). |
| `MOD_RODATA` | `EXECMEM_MODULE_DATA` | Read-only module data (`MOD_RODATA`, `MOD_RO_AFTER_INIT`, `MOD_INIT_RODATA`). |

| Classification | Identification criteria |
|---|---|
| `TEXT` | size == 512 pages && flags == 0x402 && !writable |
| `BPF` | size == 512 pages && flags == 0x102 && !writable |
| `MOD_DATA` | size != 512 pages && flags == 0x102 && writable |
| `MOD_RODATA` | size != 512 pages && flags == 0x102 && !writable |

> **Note:** VMAP areas with flags `0x102` and `0x402` both include `VM_ALLOC`, but differ in their additional flags. `0x102` includes `VM_FLUSH_RESET_PERMS` (allocations that require permission changes to be synchronized with the CPU's TLB and direct-map state), while `0x402` includes `VM_ALLOW_HUGE_VMAP` (permits huge-page mappings where supported).
