obj-m += rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	cc test.c -o test
	cc setuid_proc.c -o setuid_proc

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm -f test
	rm -f setuid_proc
