type: failure_pattern
id: env_syncconfig
tags: syncconfig, Kconfig, environment, make olddefconfig, config
title: syncconfig error during kpatch-build
Error: "*** Error during sync of the configuration." / "make[3]: *** [scripts/kconfig/Makefile:77: syncconfig] Error 1"
This is an environment issue, not a patch problem. Do not automatically regenerate or touch configuration files inside a selected target baseline. Stop automatic acceptance and require an operator to prepare a separate baseline with the exact VM `.config`, release metadata, and matching build inputs before retrying.

---
type: failure_pattern
id: apply_hunk_failed
tags: hunk FAILED, patch apply, context drift, git apply --check
title: Hunk failed — patch context doesn't match target source
Error messages: "hunk FAILED", "patch does not apply", "error: patch failed", "fuzz", "file failed to apply"
The source line context in the patch doesn't match the target kernel source tree. This commonly happens when backporting patches to different kernel versions. The fix is to adjust the hunk context lines to match the target source. Strategies:
1. Re-contextualize: update the context lines (the lines around the changed code) to match the target source.
2. If a function was moved/renamed, find where it exists in the target source and update the file path and line numbers.
3. If the change already partially exists (reversed patch), this may indicate the fix was already backported.
This failure is retryable — attempt to rewrite the patch with corrected context.

---
type: failure_pattern
id: apply_file_missing
tags: No such file or directory, cannot find file
title: File missing in target source tree
Error messages: "No such file or directory", "cannot find file"
The patched file doesn't exist in the target kernel source tree. This means the file was removed, renamed, or never existed in this kernel version. Action: manual_required — a human needs to find the equivalent file or determine if the patch is not applicable.

---
type: failure_pattern
id: compile_api_args
tags: too many arguments, too few arguments, passing argument, function signature
title: API mismatch — function argument count or type changed
Error messages: "too many arguments to function", "too few arguments to function", "error: passing argument"
The function signature in the patch doesn't match the target kernel's API. This is common when backporting patches across kernel versions where APIs changed. Fixes:
1. Adjust the function call to match the target kernel signature.
2. If a parameter was added (e.g., struct net *net was added to sock_create), pass the appropriate value (&init_net or derive from context).
3. If a function was removed, find its replacement (e.g., __register_chrdev removed, use register_chrdev_region + cdev_init + cdev_add).
This failure is retryable — attempt to adapt the API call.

---
type: failure_pattern
id: compile_implicit_decl
tags: implicit declaration of function, missing header, missing include, macro
title: Missing function declaration or header
Error messages: "implicit declaration of function", "error: implicit declaration"
The patch calls a function that isn't declared in the target kernel. This could mean: (1) A header file is missing — add the appropriate #include. (2) The function doesn't exist in this kernel version — need to find an alternative or remove the call. (3) A macro or constant is undefined — define it locally in the .c file. This failure is retryable.

---
type: failure_pattern
id: compile_unknown_field
tags: error: unknown field, struct member, field mismatch
title: Struct field doesn't exist
Error messages: "error: unknown field 'foo' specified in initializer", "error: 'struct foo' has no member named 'bar'"
The patch references a struct field that doesn't exist in the target kernel version. The field was added in a newer version. Fixes:
1. Remove the field access if the logic can work without it.
2. Use a shadow variable to attach the field to the struct dynamically.
3. Add a compatibility #ifdef to handle both versions. This failure is retryable.

---
type: failure_pattern
id: kpatch_no_fentry
tags: no fentry call, not traceable, ftrace, fentry
title: Function has no fentry call — cannot be patched
Error messages: "ERROR: no fentry call", "function is not traceable"
The function does not have an ftrace entry point (fentry), so livepatch cannot hook it. This commonly affects: (1) Functions marked __always_inline. (2) Functions in lib-y targets (archived into lib.a, e.g., lib/string.o). (3) Functions that are only called once and got inlined by the compiler. Fixes:
1. Check if the function is inlined — add noinline to ensure it has its own entry point.
2. Move the fix to a caller function that does have fentry (may require modifying the patch to call the fix logic from a higher-level hookable function).
3. This may require manual rewrite (manual_required).

---
type: failure_pattern
id: kpatch_struct_or_data_change
tags: unreconcilable difference, static variable, section change, data section, struct layout
title: kpatch unreconcilable data difference
Error messages: "unreconcilable difference", "WARNING: unable to correlate static local variable", "static variable changed", "section change", "data structure layout change"
The patch modifies static data (global variables, static locals, data sections) which kpatch cannot handle directly. Fixes:
1. Change the code that uses the data structure instead of the structure itself.
2. Use kpatch callback macros (KPATCH_PRE_PATCH_CALLBACK) to modify the data at patch load time.
3. Use shadow variables (klp_shadow_alloc/klp_shadow_get) to add new fields dynamically.
4. For "once" macros (printk_once), replace with plain printk.
This often requires human review (manual_required) to implement the correct workaround.

---
type: failure_pattern
id: kpatch_symbol_section_offset
tags: create-diff-object, kpatch_bundle_symbols, section offset, patchability
title: create-diff-object symbol is not at section start
Error messages: "kpatch_bundle_symbols: ... symbol ... at offset ... within section ... expected 0"
The patch compiles, but `create-diff-object` cannot safely correlate one or more changed function sections into a livepatch object. Treat this as a kpatch limitation and require human review; do not attempt an automatic semantic rewrite or load a partial module.

---
type: failure_pattern
id: kpatch_jump_label
tags: jump label, static_branch, static_key, module key
title: Jump label with module-defined key
Error: "Found a jump label at ... using key ..., which is defined in a module. Use static_key_enabled() instead."
Jump labels are not supported when the key is defined in a module. Fix: replace static_branch_likely()/static_branch_unlikely()/static_key_true()/static_key_false() with static_key_enabled() in the patch file. If the jump label is part of a tracepoint, kpatch-build silently removes the tracepoint.

---
type: failure_pattern
id: env_compiler_version
tags: compiler version, gcc mismatch, build error
title: Compiler version mismatch
Error: "gcc/kernel version mismatch" / warning: "Skipping compiler version matching check (not recommended)"
kpatch-build compares the active compiler to the compiler recorded in the target kernel. Different compiler builds can introduce unrelated object differences. Do not use `--skip-compiler-check` for a module intended for runtime loading. Install the exact compiler package recorded by the target kernel or stop for manual environment remediation.

---
type: failure_pattern
id: env_module_disabled
tags: CONFIG, module disabled, config not set, kernel config
title: Patch target is disabled by kernel configuration
The patch modifies code in a module (e.g., Bluetooth, UBLK) that is not enabled in the target kernel's `.config` (`CONFIG_*=not_set`). Only a pre-build mapping from every patched target object to disabled CONFIG symbols can justify automatic skipping. A later `no changed objects found` message without that evidence is ambiguous and requires human review.
