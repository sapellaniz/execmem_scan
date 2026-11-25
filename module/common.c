#include "common.h"

static kallsyms_lookup_name_t lookup_name;

unsigned long resolve_symbol(const char *name)
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
