#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/mm.h>
#include <linux/mm.h>
#include <asm/pgtable.h>

#define VMAP_NODE_SIZE 6272
#define MAX_VMAP_NODES 128
#define VMAP_POOL_SIZE 256

typedef unsigned long (*kallsyms_lookup_name_t)(const char *);
static struct list_head *mod_list_head = NULL;

static kallsyms_lookup_name_t lookup_name;

struct vmap_pool_layout {
    struct list_head head;
    unsigned long len;
};

struct rb_list_layout {
    struct rb_root root;
    struct list_head head;
    spinlock_t lock;
};

struct vmap_node_layout {
    struct vmap_pool_layout pool[VMAP_POOL_SIZE];
    spinlock_t pool_lock;
    bool skip_populate;

    struct rb_list_layout busy;
    struct rb_list_layout lazy;
};

static unsigned long resolve_symbol(const char *name)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };

    unsigned long addr;

    if (!lookup_name) {
        if (register_kprobe(&kp))
            return 0;

        lookup_name = (kallsyms_lookup_name_t)kp.addr;
        unregister_kprobe(&kp);
    }

    addr = lookup_name(name);

    return addr;
}

static bool addr_in_module(unsigned long addr, struct module *mod)
{
    int i;
    for (i = 0; i < MOD_MEM_NUM_TYPES; i++) {
        unsigned long base = (unsigned long)mod->mem[i].base;
        unsigned long size = mod->mem[i].size;
        if (base && addr >= base && addr < base + size)
            return true;
    }
    return false;
}
static bool manual_is_module_address(unsigned long addr)
{
    struct module *mod;
    bool found = false;

    if (!mod_list_head) {
        mod_list_head = (struct list_head *)resolve_symbol("modules");
        if (!mod_list_head) {
            pr_err("[execmem_scan] Failed to resolve 'modules' list head\n");
            return false;
        }
    }

    rcu_read_lock();
    list_for_each_entry_rcu(mod, mod_list_head, list) {
        if (mod->state == MODULE_STATE_UNFORMED)
            continue;

        if (addr_in_module(addr, mod)) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();

    return found;
}

static bool is_page_writable(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    if (!pte)
        return false;

    /* Handles huge pages (2MB/1GB) as well as standard 4KB PTEs */
    if (level == PG_LEVEL_2M)
        return pmd_write(*(pmd_t *)pte);
    if (level == PG_LEVEL_1G)
        return pud_write(*(pud_t *)pte);

    return pte_write(*pte);
}



static void print_vmap_areas(struct list_head *head,
                             const char *list_name)
{
    struct vmap_area *va;
    unsigned long flags;
    bool writable;
    bool is_module;
    struct vm_struct *vm;
    int size;

    list_for_each_entry(va, head, list) {
	
	if (va->va_start < MODULES_VADDR || va->va_start > MODULES_END)
	    continue;
	
        vm = READ_ONCE(va->vm);
        if (vm)
	    flags = READ_ONCE(vm->flags);
	else
	    flags = 0;
	writable = is_page_writable(va->va_start);
	size = va->va_end - va->va_start;

	// skip EXECMEM_BPF
	if (size == 0x201000 && flags == 0x102 && !writable)
	{
	    pr_info("[execmem_scan] %#lx-%#lx: EXECMEM_BPF\n", va->va_start, va->va_end);
	    continue;
	}

	is_module = manual_is_module_address(va->va_start);

	// EXECMEM_MODULE_TEXT | EXECMEM_KPROBES | EXECMEM_FTRACE
	if (size == 0x201000 && flags == 0x402 && !writable)
	{
	    pr_info("[execmem_scan] %#lx-%#lx: TEXT | KPROBES | FTRACE\n", va->va_start, va->va_end);
	    /*
	    for (unsigned long addr = va->va_start ; addr < va->va_end ; addr += 0x1000) {
		if (!manual_is_module_address(addr))
		    pr_info("[execmem_scan] hidden page: %#lx\n", addr);
	    }
	    */
	}
	else if (flags == 0x102 && writable && !is_module)
	    pr_info("[execmem_scan] %#lx-%#lx: hidden EXECMEM_MODULE_DATA (MOD_DATA | MOD_INIT_DATA)\n", va->va_start, va->va_end);
	else if (flags == 0x102 && !writable && !is_module)
	    pr_info("[execmem_scan] %#lx-%#lx: hidden EXECMEM_MODULE_DATA (MOD_RODATA | MOD_RO_AFTER_INIT | MOD_INIT_RODATA)\n", va->va_start, va->va_end);

    }
}

static int __init vmap_inspector_init(void)
{
    unsigned long nodes_addr;
    unsigned long nr_addr;
    void **vmap_nodes;
    unsigned int *nr_vmap_nodes;
    unsigned int nr;
    unsigned int i;

    pr_info("[execmem_scan] starting scan\n");

    nodes_addr = resolve_symbol("vmap_nodes");
    nr_addr = resolve_symbol("nr_vmap_nodes");

    if (!nodes_addr || !nr_addr) {
        pr_err("[execmem_scan] Unable to resolve symbols\n");
        return -ENOENT;
    }

    vmap_nodes = (void **)nodes_addr;
    nr_vmap_nodes = (unsigned int *)nr_addr;

    nr = READ_ONCE(*nr_vmap_nodes);

    if (!nr || nr > MAX_VMAP_NODES) {
        pr_err("[execmem_scan] Invalid node count: %u\n", nr);
        return -EINVAL;
    }

    for (i = 0; i < nr; i++) {
        struct vmap_node_layout *vn =
            (struct vmap_node_layout *)(
                (char *)READ_ONCE(*vmap_nodes)
                + i * VMAP_NODE_SIZE
            );

        spin_lock(&vn->busy.lock);
        print_vmap_areas(&vn->busy.head, "BUSY");
        spin_unlock(&vn->busy.lock);
    }

    pr_info("[execmem_scan] scan completed\n");

    return 0;
}

static void __exit vmap_inspector_exit(void)
{
    pr_info("[execmem_scan] scan unloaded\n");
}

module_init(vmap_inspector_init);
module_exit(vmap_inspector_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sergio Apellaniz");
MODULE_DESCRIPTION("Scan execmem-managed memory for suspicious kernel code");

