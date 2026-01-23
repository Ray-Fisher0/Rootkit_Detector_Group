TODO:
1. decide if we think that this is a viable path forward and what we need to change.
2. decide on what we want to have done by mid term report.

SET UP LAB ENVIRONMENT
	• One Linux VM for attacks
	• One snapshot you can always roll back to
	• Install Ubuntu or Debian in a VM
	• Enable kernel headers + build tools
	•  compile a “hello world” kernel module
  
CREATE UNDERSTANDING OF KERNAL DATA STRUCTURES
Focus on three kernel objects:
	• sys_call_table
	• task struct list
	• module list
	• Write a kernel module that prints:
		○ the address of init_task
		○ the address of sys_call_table
		○ the address of the module list

need to understand what these structures look like in memory
and how they can be reached and manipulated.

BUILD FIRST HONEYPOT
use one of the previous data structures to create a fake version of it
that a rootkit would mistakenly look at.
Example for fake syscall table.
	1. Allocate kernel memory
	2. Fill it with pointers to real syscalls
	4. Put it somewhere rootkits will find when scanning

ADD USER SPACE ALARM SYSTEM
make sure the honey structure is in no access or can be alerted if read.
Build out a way to signal a user process to alert the user that something malicous
might be happening.

INSTALL REAL ROOTKITS TO THE VM
we need to find root kits that target data structures that we are trying to build fake
versions of. I found some for older linux kernels, building for the most current kernel
is hard obviously because it has the most recent security updates.

TESTING
Test multiple rootkits and look for timing results or if a root kit was not able to be
detected.

FINAL REPORT
not sure yet.
