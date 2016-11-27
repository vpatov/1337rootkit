obj-m += 1337rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	cc 1337test.c -o 1337test
	cc 1337setuid_proc.c -o 1337setuid_proc

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm -f 1337test
	rm -f 1337setuid_proc
