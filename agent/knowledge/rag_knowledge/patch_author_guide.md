type: general
id: patch_analysis_overview
tags: kpatch, safety, analysis
title: Patch analysis — kpatch safety
kpatch provides some guarantees, but it does not guarantee that all patches are safe to apply. Every patch must also be analyzed in-depth by a human. There is no substitute for human analysis and reasoning on a per-patch basis. All patches must be thoroughly analyzed by a human kernel expert who completely understands the patch and the affected code and how they relate to the live patching environment.

---
type: general
id: kpatch_vs_livepatch_vs_kgraft
tags: kpatch, livepatch, kgraft, consistency model
title: kpatch vs livepatch vs kGraft
This document assumes that the kpatch-build tool is being used to create livepatch kernel modules. Other live patching systems may have different consistency models, their own guarantees, and other subtle differences. The guidance in this document applies only to kpatch-build generated livepatches.

---
type: kpatch_limit
id: patch_upgrades_cumulative
tags: kpatch, cumulative, replace flag
title: Patch upgrades — cumulative patches recommended
Due to potential unexpected interactions between patches, it's highly recommended that when patching a system which has already been patched, the second patch should be a cumulative upgrade which is a superset of the first patch. Since upstream kernel 5.1, livepatch supports a "replace" flag to help the management of cumulative patches. With the flag set, the kernel will load the cumulative patch and unload all existing patches in one transition. kpatch-build enables the replace flag by default. If replace behavior is not desired, the user can disable it with -R|--non-replace.

---
type: kpatch_limit
id: data_structure_changes
tags: kpatch, data structure, struct, limitation, patch functions not data
title: Data structure changes — kpatch patches functions, not data
kpatch patches functions, not data. If the original patch involves a change to a data structure, the patch will require some rework, as changes to data structures are not allowed by default.

Workarounds:
1. CHANGE THE CODE WHICH USES THE DATA STRUCTURE: Instead of changing the data structure itself, change the code which uses it. For example, if a patch adds a function pointer to a static array, you can add an explicit check before accessing the array.
2. USE A KPATCH CALLBACK MACRO: Use KPATCH_PRE_PATCH_CALLBACK / KPATCH_POST_PATCH_CALLBACK / KPATCH_PRE_UNPATCH_CALLBACK / KPATCH_POST_UNPATCH_CALLBACK to execute code before/after patching.
3. USE A SHADOW VARIABLE: Use klp_shadow_alloc / klp_shadow_get / klp_shadow_free to add fields to existing data structures.

---
type: rewrite_strategy
id: data_structure_code_change
tags: kpatch, data structure, rewrite, workaround, code change
title: Data structure workaround — change code instead of data
Sometimes, instead of changing the data structure itself, you can change the code which uses it. For example, consider a patch that adds a function pointer to a static array of function pointers (svm_exit_handlers[]). Instead of modifying the array, add an explicit check before the array access: if (exit_code == SVM_EXIT_EXCP_BASE + AC_VECTOR) return ac_interception(svm); This is safer than touching data since the array may be in use by tasks that haven't been patched yet.

---
type: rewrite_strategy
id: kpatch_callback_macros
tags: kpatch, callback, KPATCH_PRE_PATCH_CALLBACK, KPATCH_POST_PATCH_CALLBACK
title: Using kpatch callback macros for data changes
Kpatch supports the kernel's livepatch (Un)patching callbacks via kpatch-macros.h:
- KPATCH_PRE_PATCH_CALLBACK(callback) — executed before patching, returns int (0 = success)
- KPATCH_POST_PATCH_CALLBACK(callback) — executed after patching
- KPATCH_PRE_UNPATCH_CALLBACK(callback) — executed before unpatching
- KPATCH_POST_UNPATCH_CALLBACK(callback) — executed after unpatching

Pre-patch callback signature: static int callback(patch_object *obj) { }
Post/pre-unpatch/post-unpatch signature: static void callback(patch_object *obj) { }

If pre-patch callback returns non-zero, the patch is rejected, completely reverted, and unloaded. Generally pre-patch callbacks are paired with post-unpatch callbacks, meaning anything the former allocates or sets up should be torn down by the latter.

Example: CVE-2016-5696 fix modifying sysctl_tcp_challenge_ack_limit:
  static bool kpatch_write = false;
  static int kpatch_pre_patch(...) {
    if (sysctl_tcp_challenge_ack_limit == 100) {
      sysctl_tcp_challenge_ack_limit = 1000; kpatch_write = true;
    } return 0;
  }
  static void kpatch_post_unpatch(...) {
    if (kpatch_write && sysctl_tcp_challenge_ack_limit == 1000)
      sysctl_tcp_challenge_ack_limit = 100;
  }
  KPATCH_PRE_PATCH_CALLBACK(kpatch_pre_patch);
  KPATCH_POST_UNPATCH_CALLBACK(kpatch_post_unpatch);

---
type: rewrite_strategy
id: shadow_variables
tags: kpatch, shadow variable, klp_shadow_alloc, klp_shadow_get, klp_shadow_free
title: Using shadow variables to add fields to data structures
If you need to add a field to an existing data structure (or many), use the kernel's Shadow Variable API:
- klp_shadow_alloc(obj, id, size, gfp, ctor, ctor_data): allocate a shadow variable
- klp_shadow_get(obj, id): get pointer to existing shadow variable
- klp_shadow_get_or_alloc(obj, id, size, gfp, ctor, ctor_data): get or allocate
- klp_shadow_free(obj, id, dtor): free a shadow variable
- klp_shadow_free_all(id, dtor): free all shadow variables with given id

The shadow variable <obj, id> association is global — provide unique ID enumerations per kpatch. klp_shadow_alloc() and klp_shadow_get_or_alloc() initialize only shadow variable metadata. They allocate storage via kmalloc with the gfp_t flags given, but leave the area untouched. Initialization is the caller's responsibility.

Care should be taken to avoid race conditions between a kernel thread that allocates and concurrent threads that may attempt to use it. Patches may need to call klp_shadow_free_all() from a post-unpatch handler.

---
type: kpatch_limit
id: init_code_changes
tags: kpatch, __init, init function, limitation
title: Init code changes — __init functions cannot be patched
Any code which runs in an __init function or during module or device initialization is problematic, as it may have already run before the patch was applied. The patch may require a pre-patch callback which detects whether such init code has run, and which rewrites or changes the original initialization to force it into the desired state. Some changes involving hardware init are inherently incompatible with live patching.

---
type: kpatch_limit
id: header_file_changes
tags: kpatch, header file, .h, export, limitation
title: Header file changes — be extra careful
When changing header files, be extra careful. If data is being changed, you probably need to modify the patch (see data structure changes). If a function prototype is being changed, make sure it's not an exported function, or it could break out-of-tree modules. Workaround: define an entirely new copy of the function (with updated code) and patch in-tree callers to invoke it rather than the deprecated version.

Many header file changes result in a complete rebuild of the kernel tree, which makes kpatch-build compare every .o file. It slows the build down a lot and can even fail. If it's a trivial header change (like adding a macro), move that macro into the .c file where it's needed.

---
type: general
id: unexpected_changed_functions
tags: kpatch, unexpected changes, inlining, constprop, isra, __LINE__
title: Dealing with unexpected changed functions
Patch as minimally as possible. If kpatch-build reports unexpected function changes:
1. If a changed function was inlined, callers that inlined it will also change — unavoidable.
2. If a function was originally inlined but becomes callable after patching, add __always_inline. Likewise, use noinline if a function becomes inlined only after patching.
3. If your patch adds a call to a function with .constprop or .isra suffix in the original but not in the patched version, the patch caused gcc to stop an interprocedural optimization. Copy/paste the function with a new name and call it instead.
4. Moving source code lines can introduce unique instructions from __LINE__ macros. Mitigate by adding new functions to the bottom of source files, using newline whitespace to maintain original line counts, or hard-coding the original line number.

---
type: kpatch_limit
id: static_local_variables
tags: kpatch, static local, static variable, limitation
title: Removing references to static local variables
Removing references to static locals will fail to patch unless extra steps are taken. Static locals are basically global variables because they outlive the function's scope. They need to be correlated so that the new function will use the old static local — otherwise patching would reset the variable to zero. Workaround: retain the reference to the static local by adding the variable back in the patched function in a non-functional way and ensuring the compiler doesn't optimize it away.

---
type: kpatch_limit
id: code_removal
tags: kpatch, function removal, dead code
title: Code removal — removed functions remain as dead code
kpatch modules can only add new functions and redirect existing functions. "Removed" functions continue to exist in kernel address space as effectively dead code. When removing a function and replacing it with a new version, keep the old function body in the patch (leave it as dead code) to avoid compiler warnings about defined-but-unused functions.

---
type: kpatch_limit
id: once_macros
tags: kpatch, printk_once, pr_warn_once, once, static local, unreconcilable difference
title: "Once" macros cause unreconcilable difference
When adding a call to printk_once(), pr_warn_once(), or any other "once" variation of printk(), you'll get: "ERROR: unable to correlate static local variable __print_once.XXXXX". This is because each "once" macro creates a static local variable (__print_once) that cannot be correlated. To fix, replace printk_once/pr_warn_once with a simple printk/pr_warn, or restructure the code to avoid using "once" macros.

---
type: kpatch_limit
id: inline_implies_notrace
tags: kpatch, inline, notrace, fentry, ftrace
title: inline implies notrace
Functions that are compiled with -function-sections and that are only called once are often inlined by gcc. Once inlined, the function no longer exists as a separate entity — it gets folded into the caller and loses its fentry call. This means inlined functions are not individually patchable. If you need to patch a function that is only called once, ensure it is not inlined by adding __always_inline or noinline as appropriate.

---
type: kpatch_limit
id: jump_labels
tags: kpatch, jump label, static_branch, static_key, module, limitation
title: Jump labels and static calls
Jump labels (static_branch_likely, static_branch_unlikely, static_key_true, static_key_false) are not supported when the corresponding key was originally defined in a module. If such a jump label is part of a tracepoint, kpatch-build will silently remove the tracepoint. Otherwise there will be an error: "Found a jump label at ... using key ..., which is defined in a module. Use static_key_enabled() instead." Fix: replace static_branch_likely/unlikely/static_key_true/false with static_key_enabled() in the patch file.

Similarly, static calls are not supported when the corresponding static call key was originally defined in a module.

---
type: kpatch_limit
id: sibling_calls
tags: kpatch, sibling call, tail call, stack frame
title: Sibling calls
A sibling call (also known as a tail call) occurs when a function ends by calling another function and the compiler reuses the stack frame of the caller for the callee. This optimization can cause issues with livepatch because the stack trace may not show the expected caller. This is generally handled by architecture-specific objtool support.

---
type: kpatch_limit
id: exported_symbol_versioning
tags: kpatch, symbol versioning, CRC, genksyms, modversion
title: Exported symbol versioning (CRC checksums)
If CONFIG_MODVERSIONS is enabled, exported symbols have CRC checksums that must match between the original and patched code. kpatch-build should handle this, but if you see CRC-related errors, the issue is typically a struct ABI change (adding/removing/changing fields in a struct that is passed to an exported function). The fix is to avoid changing the struct ABI — use shadow variables instead of adding fields directly.

---
type: kpatch_limit
id: system_calls
tags: kpatch, syscall, system call
title: System calls
System calls can be patched like any other function. However, because syscalls are called from userspace via a syscall instruction, the ftrace hook needs to be at the function entry point. Ensure the function contains a fentry call. Some architectures define syscalls with __SYSCALL_DEFINEx macros, which generate the appropriate entry point.
