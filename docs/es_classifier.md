# es_classifier

VMAP area classification is described in [VMAP Area Classification](vmap_enum.md#vmap-area-classification).

For each enumerated `vmap_area`, `es_classifier` iterates over its pages individually and checks whether each page belongs to a known executable memory object: a loaded module, an Ftrace callback or trampoline, a Kprobe handler, or a BPF program. Pages that cannot be associated with any of these objects are flagged as **suspicious page** and require further investigation.
