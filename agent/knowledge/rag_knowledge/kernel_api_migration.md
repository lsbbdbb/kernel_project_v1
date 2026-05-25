type: kernel_api
id: api_sock_create
tags: sock_create, struct net, networking, function_signature
title: sock_create added struct net* parameter
In kernel 6.6, sock_create() gained a 'struct net *net' first parameter: int sock_create(struct net *net, int family, int type, int protocol, struct socket **res). Patches using the old signature must pass the network namespace. Use &init_net for the global namespace, or derive from context (e.g., sock_net(sk) for socket contexts).

---
type: kernel_api
id: api_register_chrdev
tags: __register_chrdev, removed, char device, register_chrdev_region, cdev_init
title: __register_chrdev removed in 6.6
__register_chrdev() was removed in kernel 6.6. Use the modern sequence: (1) alloc_chrdev_region() or register_chrdev_region(), (2) cdev_init(), (3) cdev_add(). Patches calling __register_chrdev must be rewritten to use this three-step process.

---
type: kernel_api
id: api_timer_setup
tags: init_timer, setup_timer, timer_setup, timer_list
title: init_timer/setup_timer removed — use timer_setup
init_timer() and setup_timer() were removed. Use timer_setup(timer, callback, flags) instead. The callback signature changes from void (*func)(unsigned long) to void (*callback)(struct timer_list *). The data field (unsigned long) that was passed to setup_timer is now typically stored in a container struct and accessed via from_timer().

---
type: kernel_api
id: api_pde_data
tags: PDE_DATA, pde_data, rename, procfs
title: PDE_DATA renamed to pde_data
PDE_DATA() (PDE_DATA macro to get procfs private data) was renamed to lowercase pde_data() in kernel 6.x. Update all call sites.

---
type: kernel_api
id: api_get_random_bytes
tags: get_random_bytes, random, int to size_t
title: get_random_bytes parameter changed to size_t
get_random_bytes() second parameter changed from int to size_t. Most callers compile fine, but -Wconversion may trigger warnings.

---
type: kernel_api
id: api_nla_parse
tags: nla_parse, netlink, const qualifier, nlattr
title: nla_parse lost const on head parameter
nla_parse() third parameter (struct nlattr *head) lost the const qualifier in 6.x. Patches with const may get -Wdiscarded-qualifiers warnings. Remove const from local variables if needed.

---
type: kernel_api
id: api_pr_warn
tags: pr_warn, pr_warning, deprecated, printk
title: pr_warning() deprecated — use pr_warn()
pr_warning() is deprecated since kernel 5.x. All patches should use pr_warn() instead.

---
type: kernel_api
id: api_sk_data_ready
tags: sk_data_ready, sock, len parameter, function_signature
title: sk_data_ready callback added len parameter
sk_data_ready callback signature changed from void (*)(struct sock *sk) to void (*)(struct sock *sk, int len). Patches defining this callback must accept the second parameter.

---
type: kernel_api
id: api_kasprintf_fix
tags: kasprintf, format string, memory leak, GFP_KERNEL
title: kasprintf usage patterns
kasprintf(GFP_KERNEL, fmt, ...) allocates memory and formats a string. Must be freed with kfree() when no longer needed. In livepatches, be careful with memory allocation in atomic contexts — use GFP_ATOMIC if in spinlock/RCU context.

---
type: kernel_api
id: api_static_key_enabled
tags: static_key_enabled, static_branch, jump_label, module
title: static_key_enabled for module-defined keys
When a jump label key is defined in a module, use static_key_enabled(&key) instead of static_branch_likely(&key) or static_branch_unlikely(&key). static_key_enabled returns bool (true if the key is enabled). This avoids the kpatch-build error about module-defined keys.

---
type: kernel_api
id: api_kfree_sensitive
tags: kfree_sensitive, kfree, crypto, security, sensitive data
title: kfree_sensitive for security-sensitive data
For crypto keys, passwords, or any security-sensitive data, use kfree_sensitive() instead of kfree(). kfree_sensitive() zeros the memory before freeing, preventing information leaks. Available in kernel 6.x.

---
type: kernel_api
id: api_kmalloc_array
tags: kmalloc_array, overflow, size multiplication
title: kmalloc_array for multiplicative allocations
When allocating memory with a size that involves multiplication (e.g., kmalloc(n * sizeof(struct foo), GFP_KERNEL)), use kmalloc_array(n, sizeof(struct foo), GFP_KERNEL) instead. kmalloc_array() checks for integer overflow and returns NULL if the product overflows.

---
type: kernel_api
id: api_container_of
tags: container_of, from_timer, struct, pointer
title: from_timer vs container_of
When using timer_setup(), the callback receives struct timer_list*. Use from_timer(var, timer, member) to get the containing struct instead of container_of(). This is the recommended pattern for modern kernel timer handlers.

---
type: kernel_api
id: api_guard_lock
tags: guard, scoped_guard, cleanup, lock, mutex, spinlock
title: guard() and scoped_guard() for automatic lock management
Kernel 6.x introduced guard(mutex)(&lock) and scoped_guard(mutex, &lock) for automatic lock/unlock. These use C compiler __attribute__((__cleanup__)). guard() locks immediately, scoped_guard() locks for the block scope. Use in livepatches when adding locking to existing functions to avoid missing unlock paths.

---
type: kernel_api
id: api_kstrtox
tags: kstrtoint, kstrtoul, simple_strtol, deprecated
title: kstrto* functions vs simple_strtol
simple_strtol(), simple_strtoul(), etc. are deprecated. Use kstrtoint(), kstrtoul(), etc. which provide proper error checking (-EINVAL on invalid input, -ERANGE on overflow). The new functions take (const char *s, unsigned int base, T *res) and return int.
