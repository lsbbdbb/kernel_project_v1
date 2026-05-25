type: general
id: livepatch_consistency_model
tags: livepatch, consistency model, per-task, ftrace, safe patching
title: Livepatch consistency model
Livepatch has a consistency model that is a hybrid of kGraft and kpatch: per-task consistency and syscall barrier switching combined with kpatch's stack trace switching. Patches are applied on a per-task basis when the task is deemed safe to switch over. When a patch is enabled, livepatch enters a transition state where tasks converge to the patched state (usually completes in seconds). An interrupt handler inherits the patched state of the task it interrupts. Forked tasks inherit the patched state of the parent. Approaches for determining when it's safe to patch: (1) Stack checking of sleeping tasks — if no affected functions on stack, patch the task. (2) Kernel exit switching — task is switched when it returns to user space from a syscall, IRQ, or signal. (3) For idle "swapper" tasks, klp_update_patch_state() in the idle loop.

---
type: general
id: livepatch_lifecycle
tags: livepatch, lifecycle, loading, enabling, disabling, removing
title: Livepatch lifecycle
Five basic operations:
1. LOADING: Enable the patch when the module is being loaded. Call klp_enable_patch() in module_init().
2. ENABLING: The system starts using new implementations. Addresses of patched functions are found via kallsyms. A ftrace handler is registered for each patched function. Tasks converge to patched state.
3. REPLACING: Cumulative patches (with .replace flag) can replace all existing patches. After transition finishes, old functions are removed from ftrace handlers.
4. DISABLING: Write '0' to /sys/kernel/livepatch/<name>/enabled. Tasks converge to unpatched state. Ftrace handlers are unregistered.
5. REMOVING: Module removal is only safe when no tasks use the old code. Force-disabled patches permanently block removal.

---
type: general
id: livepatch_limitations
tags: livepatch, limitations, ftrace, notrace, fentry
title: Livepatch kernel limitations
1. Only functions that can be traced can be patched. Functions implementing ftrace or the livepatch ftrace handler cannot be patched (marked "notrace").
2. Livepatch works reliably only when dynamic ftrace is at the very beginning of the function (requires -fentry gcc option on x86_64).
3. Kretprobes using ftrace conflict with patched functions — both modify the return address, first user wins.
4. Kprobes in the original function are ignored when code is redirected to the new implementation.

---
type: general
id: livepatch_klp_structs
tags: livepatch, klp_func, klp_object, klp_patch, struct
title: Livepatch metadata structures
Three-level structure:
- struct klp_func: describes relation between original and new implementation of each patched function. Includes name (string, looked up via kallsyms), address of new function, and optional symbol position.
- struct klp_object: array of patched functions in the same object (vmlinux or module).
- struct klp_patch: array of patched objects. The whole patch is applied only when all patched symbols are found, except symbols from modules not yet loaded.

---
type: general
id: livepatch_elf_format
tags: livepatch, ELF, relocation, .klp.arch, .klp.rela
title: Livepatch module ELF format
Livepatch modules use special ELF sections to handle relocations for functions that need to access non-exported symbols from the original kernel. These special relocation sections (.klp.arch and .klp.rela) contain information about symbols that are resolved at module load time against the running kernel, rather than at build time. This allows livepatch code to reference static (non-exported) functions and variables from the original kernel source file.
