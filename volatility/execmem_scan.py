from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.linux.utilities import modules as linux_utilities_modules

from volatility3.framework.objects import utility
import struct

MOD_MEM_TYPE = [
	"MOD_TEXT",
	"MOD_DATA",
	"MOD_RODATA",
	"MOD_RO_AFTER_INIT",
	"MOD_INIT_TEXT",
	"MOD_INIT_DATA",
	"MOD_INIT_RODATA"
]

class ModulesVmalloc(interfaces.plugins.PluginInterface):

    _required_framework_version = (2, 28, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel64"]
            ),
            requirements.StringRequirement(
            name="dump-dir",
            description="Directory to dump suspicious memory pages",
            optional=True
            )
        ]

    def dump_page(self, layer, page_addr, dump_dir, page_size=0x1000):
        data = layer.read(page_addr, page_size)
        with open(f"{dump_dir}/page_{page_addr:x}.bin", "wb") as f:
            f.write(data)

    def get_execmem_areas(self, kernel, layer, symtab):
        """
        Retrieves the virtual memory areas (vmap_va) allocated through
        execmem_alloc by traversing the kernel's execmem allocation structures.
    
        Returns:
        List of vmap_va ranges corresponding to execmem_alloc allocations.
        """
        
        # Get execmem_alloc() memory range
        execmem_sym = kernel.get_symbol("execmem_alloc")
        execmem_start = kernel.offset + execmem_sym.address
        execmem_end = execmem_start
        matching_symbols = False
        while not matching_symbols:
            execmem_end += 1
            matching_symbols = list(kernel.get_symbols_by_absolute_location(execmem_end))

        # Get vmap_nodes details
        vmap_nodes_sym = kernel.object_from_symbol("vmap_nodes")
        vmap_nodes_base = layer.canonicalize(vmap_nodes_sym.dereference().vol.offset)
        nr_vmap_nodes = int(kernel.object_from_symbol("nr_vmap_nodes"))
        vmap_node_size = kernel.get_type("vmap_node").size

        # Iterate over vmap_nodes array
        for i in range(nr_vmap_nodes):

            current_node_addr = vmap_nodes_base + (vmap_node_size*i)
            current_node = self.context.object(
                f"{symtab}{constants.BANG}vmap_node",
                layer_name=kernel.layer_name,
                offset=current_node_addr
            )

            areas_head = current_node.busy.head.cast("list_head")
            symbol_type = f"{symtab}{constants.BANG}vmap_area"
            for va in areas_head.to_list(symbol_type=symbol_type, member="list"):
                if va.vm and (execmem_start <= va.vm.caller <= execmem_end):
                    yield (va.va_start,va.va_end)


    def analyze_modules(self, kernel, layer):
        """
        Retrieves the virtual memory ranges of all sections belonging to
        currently loaded kernel modules, along with the total number of loaded modules.
        
        Returns:
            - List of memory ranges for all module sections.
            - Total number of loaded modules.
        """

        module_ranges = []
        module_count  = 0

        # Retrieve the modules iterator
        modules_list = linux_utilities_modules.Modules.list_modules(
            self.context,
            self.config["kernel"]
        )

        for module in modules_list:
            module_count += 1
            try:
                mod_mem_dict = dict.fromkeys(MOD_MEM_TYPE, (0, 0))
                # Iterate over module sections
                for i in range(len(MOD_MEM_TYPE)): 
                    mod_mem_entry = module.mem[i]
                    mem_type = MOD_MEM_TYPE[i]
                    mem_base = layer.canonicalize(int(mod_mem_entry.base))
                    mem_size = mod_mem_entry.size

                    if mem_base == 0 or mem_size == 0:
                        continue

                    mod_mem_dict[mem_type] = (mem_base, mem_base + mem_size)
                module_ranges += [mod_mem_dict]

            except (AttributeError, ValueError):
                continue

        return module_ranges, module_count

    def analyze_kprobe(self, kernel, layer, symtab):
        """
        Retrieves the base addresses of memory pages allocated for kprobes
        and the total number of active kprobes.

        Returns:
            - List of base addresses of kprobe memory pages.
            - Total number of active kprobes.
        """

        kprobe_pages = []
        kprobe_count = 0

        kprobe_insn_cache = kernel.object_from_symbol("kprobe_insn_slots")
        kprobe_optinsn_cache = kernel.object_from_symbol("kprobe_optinsn_slots")

        for cache in [kprobe_insn_cache, kprobe_optinsn_cache]:
            pages_head = cache.pages.cast("list_head")
            symbol_type = f"{symtab}{constants.BANG}kprobe_insn_page"
            for page in pages_head.to_list(symbol_type=symbol_type, member="list"):
                kprobe_pages += [layer.canonicalize(int(page.insns))]
                print(f"{hex(layer.canonicalize(int(page.insns)))=}")
                kprobe_count += 1

        kprobe_ftrace_ops = kernel.object_from_symbol("kprobe_ftrace_ops")
        kprobe_ipmodify_ops = kernel.object_from_symbol("kprobe_ipmodify_ops")

        for ops in [kprobe_ftrace_ops, kprobe_ipmodify_ops]:
            current_ops = ops
            while current_ops != 0:
                if current_ops.trampoline_size > 0:
                    kprobe_pages += [current_ops.trampoline]
                    kprobe_count += 1

                current_ops = current_ops.next

        return kprobe_pages, kprobe_count

    def analyze_ftrace(self, kernel, layer):
        """
        Analyzes ftrace structures to identify memory ranges used by ftrace
        trampolines, count the functions currently being traced, and identify
        hidden traced functions.
        
        Returns:
            - List of memory ranges used by ftrace trampolines.
            - Total number of traced functions.
            - Total number of hidden traced functions.
        """

        ftrace_ranges   = []
        ftrace_count    = 0
        traced_funcs    = []
        extra_artifacts = []

        current_ftrace_ops = kernel.object_from_symbol("ftrace_ops_list")
        ftrace_list_end = kernel.object_from_symbol("ftrace_list_end")

        if current_ftrace_ops.next != ftrace_list_end.vol.offset:
            while current_ftrace_ops != 0:

                tramp_addr = current_ftrace_ops.trampoline
                tramp_size = current_ftrace_ops.trampoline_size

                if tramp_size > 0:
                    filter_hash_addr = layer.canonicalize(int(current_ftrace_ops.func_hash.filter_hash))
                    ftrace_hash = kernel.object(
                        "ftrace_hash",
                        offset=filter_hash_addr,
                        absolute=True
                    )
                    num_buckets = 1 << int(ftrace_hash.size_bits)
                    buckets_addr = layer.canonicalize(int(ftrace_hash.buckets))
                    bucket_size = kernel.get_type("hlist_head").size
                    hlist_offset = kernel.get_type("ftrace_func_entry").relative_child_offset("hlist")
                    for i in range(num_buckets):
                        head = kernel.object(
                            "hlist_head",
                            offset=buckets_addr + (bucket_size * i),
                            absolute=True
                        )
                        node_ptr = int(head.first)
                        while node_ptr != 0:
                            node_addr = layer.canonicalize(node_ptr)
                            entry = kernel.object(
                                "ftrace_func_entry",
                                offset=node_addr - hlist_offset,
                                absolute=True
                            )
                            traced_funcs += [entry.ip]

                            node = kernel.object("hlist_node", offset=node_addr, absolute=True)
                            node_ptr = int(node.next)


                    ftrace_ranges += [(tramp_addr, tramp_addr + tramp_size)]
                    ftrace_count += 1

                current_ftrace_ops = current_ftrace_ops.next

        if len(traced_funcs) > 0:
            current_ftrace_page = kernel.object_from_symbol("ftrace_pages_start")
            dyn_ftrace_size = kernel.get_type("dyn_ftrace").size
            while current_ftrace_page != 0:
                for dyn_ftrace_base in range(current_ftrace_page.records, current_ftrace_page.records + (current_ftrace_page.index * dyn_ftrace_size), dyn_ftrace_size):
                    data = layer.read(dyn_ftrace_base, 0x10)
                    ip, flags = struct.unpack("<QQ", data)
                    if ip in traced_funcs and (flags & 1) == 0:
                        extra_artifacts += [("hidden ftrace on function", hex(ip))]

                current_ftrace_page = current_ftrace_page.next

        return ftrace_ranges, ftrace_count, extra_artifacts

    def analyze_bpf(self, kernel, layer):
        """
        Analyzes BPF structures to identify memory ranges occupied by BPF
        programs and count the currently loaded BPF programs.

        Returns:
            - List of memory ranges used by BPF programs.
            - Total number of BPF programs.
        """

        bpf_prog_addresses = []
        bpf_prog_count     = 0
        
        prog_idr = kernel.object_from_symbol("prog_idr")
        for prog_addr in prog_idr.get_entries():
            prog_addr = layer.canonicalize(prog_addr)
            bpf_prog = kernel.object(
                    "bpf_prog",
                    offset=prog_addr,
                    absolute=True
            )
            bpf_func_start = layer.canonicalize(int(bpf_prog.bpf_func))
            """
            bpf_func_end   = bpf_func_start + bpf_prog.jited_len
            aux = bpf_prog.aux

            name = bpf_prog.aux.ksym.name
            name = name.cast(
                    "string",
                    max_length=512
                    )
            """

            bpf_prog_addresses += [bpf_func_start]
            bpf_prog_count += 1

        return bpf_prog_addresses, bpf_prog_count
    
    def execmem_scan(self, kernel, layer, symtab):
        """
        Scans memory areas allocated through execmem_alloc to identify pages
        belonging to legitimate kernel components.

        Enumerates busy execmem areas and iterates over their memory pages,
        classifying each page into one of the following categories:
            - Module: Pages belonging to loaded kernel modules.
            - Ftrace: Pages used by ftrace trampolines.
            - Kprobe: Pages allocated for kprobes.
            - BPF: Pages containing BPF programs.
            - Suspicious: Pages that cannot be associated with any of the
              previously identified categories.
        
        Pages classified as suspicious are dumped to disk for further
        forensic analysis.
        """
        
        suspicious_areas = {}
        extra_artifacts  = {}
        suspicious_page_count = 0
        
        mod_ranges, mod_count = self.analyze_modules(kernel, layer)
        kprobe_pages, kprobe_count = self.analyze_kprobe(kernel, layer, symtab)
        ftrace_ranges, ftrace_count, extra_artifacts["ftrace"] = self.analyze_ftrace(kernel, layer)
        bpf_prog_addresses, bpf_prog_count = self.analyze_bpf(kernel, layer)

        execmem_areas = self.get_execmem_areas(kernel, layer, symtab)

        # Remove bpf areas
        execmem_areas = [
                area for area in execmem_areas
                if not any(area[0] <= addr < area[1] for addr in set(bpf_prog_addresses))
        ]

        for area in execmem_areas:
            for addr in range(area[0], area[1] - 0x1000, 0x1000):
                if b'\xcc' * 0x1000 == layer.read(addr, 0x1000):
                    continue
                elif any(addr == kprobe_page for kprobe_page in kprobe_pages):
                    continue
                elif any(ftrace_range[0] <= addr <= ftrace_range[1] for ftrace_range in ftrace_ranges):
                    continue
                else:
                    matched_t = None
                    for mod_range in mod_ranges:
                        matched_t = next(
                            (t for t in MOD_MEM_TYPE if mod_range[t][0] <= addr < mod_range[t][1]),
                            None
                        )
                        if matched_t is not None:
                            break
                    if matched_t is not None:
                        continue

                if area not in suspicious_areas:
                    suspicious_areas[area] = []
                suspicious_areas[area] += [addr]

        suspicious_page_count = sum(len(v) for v in suspicious_areas.values())

        objects = ["module", "bpf_prog", "kprobe", "ftrace", "suspicious pages"]
        counts  = [mod_count, bpf_prog_count, kprobe_count, ftrace_count, suspicious_page_count]

        for count, obj in zip(counts, objects,):
            yield [0, str(count), obj]

        if len(suspicious_areas) > 0:
            dump_dir = self.config.get("dump-dir", None)
            for area, addresses in suspicious_areas.items():
                yield [1, "area", f"{hex(area[0])}-{hex(area[1])}"]
                for addr in addresses:
                    yield [2, "suspicious page", hex(addr)]
                    if dump_dir:
                        self.dump_page(layer, addr, dump_dir)

        if len(extra_artifacts) > 0:
            for key in extra_artifacts:
                for artifact in extra_artifacts[key]:
                    yield [1, artifact[0], artifact[1]]


    def _generator(self):

        kernel = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[kernel.layer_name]
        symtab = kernel.symbol_table_name

        yield from ((level, (obj, count)) for level, obj, count in self.execmem_scan(kernel, layer, symtab))

    def run(self):
        return renderers.TreeGrid(
        [
            ("Count", str),
            ("Object", str)
        ],
        self._generator()
    )
