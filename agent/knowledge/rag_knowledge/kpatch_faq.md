type: general
id: kpatch_overview
tags: kpatch, overview, dynamic patching, livepatch
title: kpatch overview
kpatch is a Linux dynamic kernel patching infrastructure which allows you to patch a running kernel without rebooting or restarting any processes. It enables sysadmins to apply critical security patches to the kernel immediately. kpatch works at a function granularity: old functions are replaced with new ones using ftrace. The kpatch-build tool converts a source diff patch to a livepatch kernel module by compiling the kernel with and without the patch, comparing binaries, and generating a .ko module. After building, load with: kpatch load livepatch-foo.ko

---
type: general
id: kpatch_build_steps
tags: kpatch-build, build steps, create-diff-object
title: kpatch-build steps
kpatch-build primary steps:
1. Build the unstripped vmlinux for the kernel
2. Patch the source tree
3. Rebuild vmlinux and monitor which objects are rebuilt (the "changed objects")
4. Recompile each changed object with -ffunction-sections -fdata-sections (patched version)
5. Unpatch the source tree
6. Recompile each changed object with -ffunction-sections -fdata-sections (original version)
7. For every changed object, use create-diff-object to analyze patchability, add .kpatch.funcs and .kpatch.dynrelas sections
8. Link all output objects into a cumulative object
9. Generate the patch module (.ko)

---
type: kpatch_limit
id: kpatch_limitations
tags: kpatch, limitations, summary
title: kpatch limitations summary
1. Patches modifying __init functions are not supported.
2. Patches modifying statically allocated data are not directly supported (use callbacks or shadow variables).
3. Patches changing how a function interacts with dynamically allocated data may or may not be safe — kpatch-build cannot verify safety.
4. Patches modifying functions in vdso are not supported (user-space, ftrace can't hook them).
5. Patches modifying functions missing a fentry call are not supported (includes lib-y targets archived into lib.a).
6. Some incompatibilities with ftrace and kprobes exist.

---
type: general
id: kpatch_detection
tags: kpatch, detect, taint, /sys/kernel/livepatch
title: Detecting if the kernel is patched
If a patch is currently applied, see /sys/kernel/livepatch. If a patch has been previously applied, TAINT_LIVEPATCH flag (32768) is set — check /proc/sys/kernel/tainted. TAINT_OOT_MODULE (4096) is also set since the patch module is external. TAINT_UNSIGNED_MODULE (8192) is set if the module is unsigned.

---
type: general
id: kpatch_out_of_tree_modules
tags: kpatch, out-of-tree module, oot, external module
title: Patching out-of-tree modules
kpatch supports patching out-of-tree modules:
1. Use --oot-module flag to specify the version running on the machine
2. Use --oot-module-src with directory containing same version code, ready to build with make
3. If Module.symvers isn't in the source root, create a symlink pointing to its actual location
4. Usually need --target flag for proper make target names
5. Tested for single out-of-tree module per patch only

---
type: general
id: kpatch_faq
tags: kpatch, FAQ, safety, removal, multiple patches
title: kpatch frequently asked questions
Q: Is this just a virus/rootkit injection framework?
A: kpatch requires CAP_SYS_MODULE. If you already have that, you already can arbitrarily modify the kernel.

Q: Will it destabilize my system?
A: No, as long as the patch is created carefully following the Patch Author Guide.

Q: What kernels are supported?
A: kpatch needs gcc >= 4.8 and Linux >= 4.0.

Q: Is it possible to remove a patch?
A: Yes — run "kpatch unload" to disable and unload the patch module.

Q: Can you apply multiple patches?
A: Yes, but cumulative patches are recommended (use combinediff, then kpatch-build). Use livepatch atomic "replace" mode (default).

Q: Why did kpatch-build detect a changed function not touched by the source patch?
A: Possible reasons: (1) The patch changed an inline function. (2) The compiler inlined a changed function, causing the outer function to recompile. (3) A bug in kpatch-build's __LINE__ macro detection.

Q: Are kernel modules supported?
A: Yes — both in-tree and out-of-tree modules are supported.

Q: What is needed to support a new architecture?
A: Three phases: (1) CONFIG_HAVE_LIVEPATCH in kernel. (2) kpatch-build (create-diff-object) support. (3) CONFIG_HAVE_RELIABLE_STACKTRACE and objtool.
