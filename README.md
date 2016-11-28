/**********************************************************************************
 *	Last Updated: Nov 27, 2016
 *	CSE509 System Security Fall 2016
 *	Written By:
 *		Edwin Y
 *		Rashmi Makheja(rmakheja@cs.stonybrook.edu)
 *		Sagar Shah (schshah@cs.stonybrook.edu)
 *		Vasia Patov () 
 *	Project: Rootkit
 **********************************************************************************/
System Specification:
	
		This project is built and tested on ubuntu 12.04 having kernel version 3.2.0-115-generic-pae
		
Steps to install rootkit:

	1) build the kernel, install modules and reboot the system
	2) cd /home/iambate/sys_sec/1337rootkit
		go to the rootkit folder(assuming the rootkit source is in this folder)
	3) sudo make 
		build the module
	4) sudo insmod 1337Rootkit.ko 
		installs the rootkit module


Steps to test the basic requirements:

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

Steps To remove rootkit:
	i)
	ii)
Additional considerations:

	1) No difference in response time of any operation
	2) Ways to 
