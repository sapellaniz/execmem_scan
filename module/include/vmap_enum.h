#ifndef EXECMEM_VMAP_ENUM_H
#define EXECMEM_VMAP_ENUM_H

#include "common.h"

#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/highmem.h>

#define VMAP_NODE_SIZE 6272
#define MAX_VMAP_NODES 128
#define VMAP_POOL_SIZE 256

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

struct memory_range {
    unsigned long start;
    unsigned long end;
};

struct range_array {
    struct memory_range *ranges;
    size_t count;
};

struct areas {
    struct range_array text;
    struct range_array bpf;
    struct range_array mod_data;
    struct range_array mod_rodata;
};

/* Function declarations */
int vmap_enum(struct areas *areas);
void free_execmem_areas(struct areas *areas);

#endif
