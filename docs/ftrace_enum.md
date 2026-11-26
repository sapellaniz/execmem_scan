# ftrace_enum

Ftrace is the Linux kernel tracing framework used to trace function execution and monitor kernel activity. It supports function tracing and mechanisms that allow tracing infrastructure to redirect or instrument function execution.

Rootkits may abuse ftrace-related functionality to hook kernel functions, modify execution flow, intercept operations, or evade security monitoring.

`execmem_scan` analyzes memory associated with ftrace to identify potentially suspicious executable regions and provides information about the functions currently being traced and the tracing mechanisms associated with them.

## Ftrace Operations (`ftrace_ops`)

Ftrace uses the `struct ftrace_ops` structure to define tracing operations. Each registered operation specifies how tracing is performed, including the callback responsible for handling traced function events, the functions to be traced, and additional tracing configuration.

An `ftrace_ops` structure can contain different execution-related pointers, including a callback (`func`), a direct-call target (`direct_call`), and a trampoline (`trampoline`). These fields represent different tracing mechanisms and may be used depending on how the operation is configured.

## Ftrace Operation Lists

The kernel maintains lists of registered Ftrace operations, including `ftrace_ops_list` and `ftrace_ops_trampoline_list`.

`execmem_scan` walks these lists to enumerate the registered tracing operations and identify the functions associated with them. It analyzes their tracing filters and configuration to determine which kernel functions are being traced and which callbacks, direct-call targets, or trampolines are associated with each function.

These lists contain tracing operations rather than the traced functions themselves. The association between an operation and a traced function is determined by its tracing configuration, including its filter hashes and tracing flags.

## Callbacks, Direct Calls, and Trampolines

Ftrace can handle traced function execution through different mechanisms depending on the registered operations and their configuration. These mechanisms determine how execution is redirected when a traced function is reached and how the associated tracing code is invoked.

- **Callback (`ops->func`):** The tracing handler registered through `ftrace_ops`. It is the function that performs the tracing-related work, such as inspecting function execution, collecting information, or performing other actions. In the standard tracing path, Ftrace invokes this callback when a traced function is reached. Multiple tracing operations may use different callbacks for the same function.

- **Direct call (`ops->direct_call`):** An alternative execution mechanism that allows a traced function to redirect execution directly to a specified target instead of going through the regular callback dispatch mechanism. This is intended to reduce tracing overhead by avoiding the normal Ftrace callback-dispatch path. The direct-call target is associated with the tracing operation and is used when the operation is configured to use Ftrace direct calls and the tracing configuration permits it.

- **Trampoline (`ops->trampoline`):** An executable code region that provides a specialized entry point for handling traced function execution. A trampoline can be used to invoke the associated tracing callback through a customized execution path, avoiding some of the overhead of the generic Ftrace dispatch mechanism. Ftrace may use an operation-specific trampoline when the traced function is associated with a single compatible tracing operation. Trampolines may be dynamically allocated or provided by the tracing operation itself, depending on the configuration.

In practical terms, the callback is the tracing handler, the direct call is an alternative redirection to a target function, and the trampoline is executable code used to implement a specialized tracing path.

These mechanisms are not mutually exclusive across the entire tracing subsystem. Their use depends on the kernel version, architecture, registered operations, and tracing configuration. The presence of a callback, direct-call target, or trampoline in an `ftrace_ops` structure does not necessarily mean that each mechanism is actively used for every function associated with that operation.
