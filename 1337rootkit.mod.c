#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x9c3f02a1, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x20b8eb7e, __VMLINUX_SYMBOL_STR(d_path) },
	{ 0x43a69ab4, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x12da5bb2, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0xd0d8621b, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x2d24b7a0, __VMLINUX_SYMBOL_STR(commit_creds) },
	{ 0x2306e22c, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0x4c2ae700, __VMLINUX_SYMBOL_STR(strnstr) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0xcb17f51f, __VMLINUX_SYMBOL_STR(kernel_read) },
	{ 0x11089ac7, __VMLINUX_SYMBOL_STR(_ctype) },
	{ 0x8e91e17f, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x50eedeb8, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x2f287f0d, __VMLINUX_SYMBOL_STR(copy_to_user) },
	{ 0xb4390f9a, __VMLINUX_SYMBOL_STR(mcount) },
	{ 0x1e6d26a8, __VMLINUX_SYMBOL_STR(strstr) },
	{ 0x61de5813, __VMLINUX_SYMBOL_STR(prepare_creds) },
	{ 0x61651be, __VMLINUX_SYMBOL_STR(strcat) },
	{ 0xba966047, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x15568631, __VMLINUX_SYMBOL_STR(lookup_address) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xa49e9cbe, __VMLINUX_SYMBOL_STR(fget) },
	{ 0x8235805b, __VMLINUX_SYMBOL_STR(memmove) },
	{ 0x362ef408, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0xe914e41e, __VMLINUX_SYMBOL_STR(strcpy) },
	{ 0xed7a4348, __VMLINUX_SYMBOL_STR(filp_open) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "105ACF10DA0BB81C88B7160");
