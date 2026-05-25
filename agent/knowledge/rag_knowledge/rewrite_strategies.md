type: rewrite_strategy
id: strategy_context_drift_detailed
tags: context_drift, hunk, offset, git apply, re-contextualize
title: Context drift rewrite strategy
When a patch fails because the context lines don't match the target source (hunk FAILED), the fix is to re-contextualize the hunks. Steps:
1. Identify the target function in the source tree — locate the exact function and line range that the patch intended to modify.
2. Compare the original context (the lines around the patch's changes) with the actual target source.
3. Adjust the hunk header (@@ -line,count +line,count @@) if the line numbers changed.
4. Update the context lines that surround the change to match the exact target source.
5. Keep the actual changes (+ lines and - lines) identical — only change the context.
6. Run "git apply --check" to verify the rewritten patch applies cleanly.
The security semantics are preserved because only non-functional context lines are modified.

---
type: rewrite_strategy
id: strategy_api_mismatch_detailed
tags: api_mismatch, function signature, parameter, rewrite
title: API mismatch rewrite strategy
When a build fails because a function call doesn't match the target kernel's API:
1. Identify the function signature in the target kernel (check include/ headers or kernel source).
2. Determine the nature of the difference:
   a. Added parameter: Add the argument (e.g., pass &init_net for sock_create's new struct net* parameter).
   b. Removed parameter: Remove the extra argument from the call.
   c. Changed type: Cast or adjust the variable type (e.g., int to size_t for get_random_bytes).
   d. Renamed function: Call the new name (e.g., PDE_DATA -> pde_data, pr_warning -> pr_warn).
   e. Removed function: Find the replacement API (e.g., __register_chrdev -> cdev_init + cdev_add).
3. Apply the fix to ALL call sites in the patch, not just one.
4. Verify with "git apply --check" then kpatch-build.
Security semantics must be preserved — do not remove error checking or security boundary checks during API adaptation.

---
type: rewrite_strategy
id: strategy_missing_include_detailed
tags: missing_include, header, macro, declaration, rewrite
title: Missing include or declaration rewrite strategy
When a compile fails because a function/macro/type is undeclared:
1. Check what header provides the symbol in the target kernel (grep the symbol in include/).
2. Add the missing #include directive to the patched .c file.
3. If the header doesn't exist in the target kernel, the symbol may not exist — find an alternative API.
4. If it's a macro that was added in a newer version, define it locally in the .c file:
   #ifndef NEW_MACRO
   #define NEW_MACRO (old_value)
   #endif
5. Verify with kpatch-build. Do NOT add headers that change data structures or function prototypes from other subsystems — this can trigger massive rebuilds and break kpatch-build.

---
type: rewrite_strategy
id: strategy_no_fentry_hoist_detailed
tags: no_fentry, hoist, wrapper, caller, traceable
title: no fentry hoist — move fix to a hookable caller
When a function cannot be patched because it lacks fentry (not traceable):
1. Identify which callers of the function ARE traceable (have fentry calls).
2. Create a new wrapper function that does the fix logic AND calls the original function.
3. Patch the hookable caller to call your wrapper instead of the original function.
4. Ensure the wrapper matches the original function's signature and semantics.
Example: If the fix is "add NULL check before dereference in static_inline_helper()", and static_inline_helper is called by traced_function(), then patch traced_function() to check for NULL before calling, rather than trying to patch the inlined helper.
This strategy requires human review — ensure the fix still covers all vulnerability paths.

---
type: rewrite_strategy
id: strategy_struct_abi_detailed
tags: struct_abi, struct, wrapper, member, shadow variable
title: Struct ABI workaround strategy
When a patch changes a struct layout (adds/removes/reorders fields), kpatch cannot handle it directly. Options:
1. SHADOW VARIABLE: Use klp_shadow_alloc to attach the new field to existing struct instances. This works when the struct is dynamically allocated and you control allocation points.
2. WRAPPER + CONTAINER: If the struct is embedded, create a new wrapper struct that contains both the original struct and the new fields. Change the code to use the wrapper instead.
3. CODE RESTRUCTURE: Instead of changing the struct, change the code that uses it. For example, if a patch adds a spinlock to struct sta_info, allocate the spinlock as a shadow variable and modify the code that accesses it.
4. For statically allocated structs (like file_operations), the struct layout change is unavoidable — consider using a pre-patch callback to modify the static instance at patching time.

---
type: rewrite_strategy
id: strategy_data_change_detailed
tags: data_change, static variable, dynamic allocation, memory leak
title: Static variable to dynamic allocation rewrite
When a patch modifies a static variable that kpatch cannot handle:
1. Change the static variable to a dynamically allocated one (kmalloc/kzalloc).
2. Allocate in a pre-patch callback (KPATCH_PRE_PATCH_CALLBACK) and store the pointer globally.
3. Free in a post-unpatch callback (KPATCH_POST_UNPATCH_CALLBACK) to avoid memory leaks.
4. In the patched functions, use the dynamically allocated variable instead of the static one.
5. Protect access with appropriate locks if the variable is accessed from multiple contexts.
Memory leak protection is critical — every allocation must have a corresponding free in the unpatch callback.

---
type: rewrite_strategy
id: strategy_semantic_guards
tags: semantic guard, safety, security, rewrite validation
title: Semantic guards for safe rewriting
When rewriting patches, these rules must NEVER be violated:
1. must_preserve_all_added_checks — All security boundary checks (NULL pointer, size, permissions) added by the original patch must be preserved.
2. must_preserve_error_return_paths — Error returns must match the original patch. Changing a -EINVAL to 0 (success) would silently bypass the security fix.
3. must_not_change_fix_logic — The core fix logic (what the patch actually does) must remain identical to the upstream fix.
4. must_not_broaden_fix_scope — Don't apply the fix to code paths it wasn't intended for.
5. must_not_leak_allocated_memory — Every allocation needs a matching free/deallocation.
6. must_keep_original_struct_layout — Don't change struct field layout (use shadow variables instead).
7. must_initialize_before_first_use — All new variables must be initialized before use.
