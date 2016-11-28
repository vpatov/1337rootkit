***********************************************************/
	Last Updated: Nov 27, 2016
	CSE509 System Security Fall 2016 
	Written By:
		Edwin Y
		Rashmi Makheja(rmakheja@cs.stonybrook.edu)
		Sagar Shah (schshah@cs.stonybrook.edu)
		Vasia
	Project: Rootkit
***********************************************************/

Steps to install rootkit:

	1) build the kernel, install modules and reboot the system
	2) cd /home/iambate/sys_sec/1337rootkit
		go to the rootkit folder(assuming the rootkit source is in this folder)
	3) sudo make 
		build the module
	4) sudo insmod 1337Rootkit.ko 
		installs the rootkit module


Steps to test the functionalities:
	1) Hide specific files and directories from showing up when a user does "ls" and similar commands
		i)ls
		ii)lsmod
		
	2) Modify the /etc/passwd and /etc/shadow file to add a backdoor account while returning the original contents of the files (pre-attack) when a normal user requests to see the file
		i) sudo cat /etc/passwd
		ii) sudo cat /etc/shadow
			the above two files should not show content related to user 'rtry'(the backdoor account)
		iii) sudo useradd testrootkit509
		iv) sudo passwd testrootkit509
		v) sudo login (login with the newly added user and passwd created in previous step)
		vi) id
		vii)exit
	3) Hides processes from the process table when a user does a "ps"
		i) ps
	4) Give the ability to a malicious process to elevate its uid to 0 (root) upon demand
		i)setuid 







	This project is built and tested on ubuntu 12.04 having kernel version 3.2.0-115-generic-pae.The rootkit once installed in the victim's system will have following functionailty :

	1) The system will still work as it was working before rootkit installation.
	2) No delay in the reponse time of commands like 'cat', 'ls', etc 
	3) Rootkit and all its files(containing '1337' in their name) will NOT be visible to the victim through any command
	4) A backdoor account, which is inaccessible by any other user, is added for attacker to login
	5) Attacker can login using backdoor account via SSH also and the rootkit module can only be removed if one secret command is used before rmmod



Platform
Tested at ubuntu linux 12.04 LTS kernel 3.2.0-29-generic
Should be working 3.x kernel version with an appropriate syscall table addr
Module name
kcr.ko
Koo-Chen-Rootkit
Kernel Cracking Rootkit
Directory structure
src/kcr.c :
Define main function
Does device registration
Hijack linux system call table
src/dev.c :
Misc device operations
read, write, open, etc
src/helpers.c:
Define helper functions
src/HJ_x.c:
Functions related to hijacking a ¡°x¡± system call
All hijackings follow the same patterns
i.e HJ_ls.c, HJ_ps.c, HJ_read.c, etc.
src/backdoor.c
Allows a backdoor when having a specific seteuid
headers/dev.h
headers/helpers.h
headers/HJ_ls.h
Describe headers to the corresponding source code
headers/all.h:
Describe common <linux/*> or <asm/*> headers
Include all src/*.c files just for convenience :)
headers/config.h:
Include all.h, and global variables and macros
B. Features (http://securitee.org/teaching/cse509/files/projects/project1.html)
Required implementation
Hide specific files and directories from showing up when a user does "ls" and similar commands
Hide defined prefixes (i.e hide_, bad_, )
Support dynamically changed prefixes
Modify the /etc/passwd and /etc/shadow file to add a backdoor account
while returning the original contents of the files (pre-attack)
when a normal user requests to see the file (sys_read)
Hides processes from the process table when a user does a "ps"
Additional implementation
Key logging (Not yet)
Either saving keystrokes to local file or sending it out to remote site
Backdoor
Allowing a normal program to have a root privilege
Hide the connections (Not yet)
Opening/listening ports
i.e netstat
Hide the rootkit module itself
i.e lsmod
C. Usage
$ make && sudo insmod kcr.ko
ootkit for CSE509 semester project at Stony Brook University, Fall 2016.
