obj-m += rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	cc test.c -o test

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm -f test
