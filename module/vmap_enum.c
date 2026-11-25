#include "vmap_enum.h"

static int add_memory_range(struct range_array *arr, struct memory_range r, gfp_t gfp)
{
	struct memory_range *tmp;

	tmp = krealloc_array(arr->ranges, arr->count + 1, sizeof(*arr->ranges), gfp);
	if (!tmp)
		return -ENOMEM;

	arr->ranges = tmp;
	arr->ranges[arr->count++] = r;
	return 0;
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

int vmap_enum(struct areas *result)
{

    unsigned long nodes_addr;
    unsigned long nr_addr;
    void **vmap_nodes;
    unsigned int *nr_vmap_nodes;
    unsigned int nr;
    struct vmap_area *va;
    unsigned long flags;
    bool writable;
    struct vm_struct *vm;
    int size;

    nodes_addr = resolve_symbol("vmap_nodes");
    nr_addr = resolve_symbol("nr_vmap_nodes");

    if (!nodes_addr || !nr_addr) {
        pr_err("[execmem_scan] Unable to resolve symbols\n");
        return -1;
    }

    vmap_nodes = (void **)nodes_addr;
    nr_vmap_nodes = (unsigned int *)nr_addr;

    nr = READ_ONCE(*nr_vmap_nodes);

    if (!nr || nr > MAX_VMAP_NODES) {
        pr_err("[execmem_scan] Invalid node count: %u\n", nr);
        return -1;
    }

    for (int i = 0; i < nr; i++) {
        struct vmap_node_layout *vn =
            (struct vmap_node_layout *)(
                (char *)READ_ONCE(*vmap_nodes)
                + i * VMAP_NODE_SIZE
            );

        spin_lock(&vn->busy.lock);
	list_for_each_entry(va, &vn->busy.head, list) {
	    
	    unsigned long end;

	    if (va->va_start < MODULES_VADDR || va->va_start > MODULES_END)
		continue;

	    vm = READ_ONCE(va->vm);
	    if (!vm)
	        continue;

	    flags = READ_ONCE(vm->flags);
	    size = va->va_end - va->va_start;
	    end = (flags & VM_NO_GUARD) ? va->va_end : (va->va_end - PAGE_SIZE);
	    if (end <= va->va_start)
	        continue;
        
	    writable = is_page_writable(va->va_start);
    
	    if (size == 0x201000 && flags == 0x102 && !writable)
		add_memory_range(&result->bpf,
				(struct memory_range){ va->va_start, end },
				GFP_ATOMIC);
	    else if (size == 0x201000 && flags == 0x402 && !writable)
		add_memory_range(&result->text,
				(struct memory_range){ va->va_start, end },
				GFP_ATOMIC);
	    else if (size != 0x201000 && flags == 0x102 && writable)
		add_memory_range(&result->mod_data,
				(struct memory_range){ va->va_start, end },
				GFP_ATOMIC);
	    else if (size != 0x201000 && flags == 0x102 && !writable)
		add_memory_range(&result->mod_rodata,
				(struct memory_range){ va->va_start, end },
				GFP_ATOMIC);
	}
        spin_unlock(&vn->busy.lock);
    }

    return 0;
}

void free_execmem_areas(struct areas *areas)
{
    if (!areas)
        return;

    kfree(areas->text.ranges);
    kfree(areas->bpf.ranges);
    kfree(areas->mod_data.ranges);
    kfree(areas->mod_rodata.ranges);

    memset(areas, 0, sizeof(*areas));
}
