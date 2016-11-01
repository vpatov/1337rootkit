#include <linux/kernel.h>
#include <linux/module.h>

int init_module(void){
	printk(KERN_INFO "Rootkit added.\n");
	return 0;
}

void cleanup_module(void){
	printk(KERN_INFO "Rootkit removed.\n");
}
