# tfd
Compiling TFD
=============

0. Make sure you have correctly installed DECAF under some directory that 
   I will refer as DECAF_PATH
    For this, follow the instructions in DECAF_PATH/INSTALL 
    More help is available at:
      https://github.com/sycurelab/DECAF

1. Compiling TFD
     cd TFD_PATH
     ./configure --decaf-path=DECAF_PATH
     make

    This step should create a library called tfd.so under TFD_PATH
    The resulting TFD plugin supports v50 traces and v20 state files, 
    which are compatible with the ones in the Bitblaze Vine 1.0 release.
    If you want the latest v60 traces and v40 state files, use instead:
      ./configure --decaf-path=DECAF_PATH --latest 
    or 
      ./configure --decaf-path=DECAF_PATH --trace60 --state40

2. Compiling the hooks
     make hooks

    This step should create a number of hooks libraries (.so files) under
      TFD_PATH/hooks

3. Make sure that TFD_PATH and TFD_PATH/hooks are 
   both included in your LD_LIBRARY_PATH environment variable. 
   These are needed because the plugin and hooks are dynamically loaded 
   using the 'load_plugin' or 'load_hooks' commands in the monitor, and 
   the will look only in the standard directories such as 
   /usr/lib and maybe /usr/local/lib


Configuring QEMU's network (tap) interface
==========================================
Create a script /etc/qemu-ifup, including the following lines:
#!/bin/sh
sudo /sbin/ifconfig $1 <ip_address> up

where <ip_address> is the address used by the host machine

This should allow you to run the tap interface as *root*

Start DECAF
===========
1. $sudo chmod 666 /dev/net/tun
2. $DECAF_PATH/i386-softmmu/qemu-system-i386 -m 512 -net nic,vlan=0 -net tap,vlan=0,script=/etc/qemu-ifup -monitor stdio -snapshot <image_file>

where <image_file> is an absolute path to the guest image

Using TFD
=========
This instructions assume both DECAF and TFD are properly installed, 
otherwise check above.

How to (quickly) collect a trace using TFD: 

  0. Start DECAF

  1. Load TFD plugin
  (qemu) load_plugin TFD_PATH/tfd.so

  2. Identify the PID of the process to trace. 
     To list all running processes:
       a) in a Windows image: (qemu) guest_ps
       b) in a Linux image: (qemu) linux_ps

     If you are not able to list the running processes it means you have
     a problem with DECAF's OS introspection module 
     (i.e., VMI or the guest kernel module).
     This is a DECAF (rather than TFD) issue, so check the 
     DECAF forum for information.

  3. Start tracing the victim process.
  (qemu) trace <pid_of_victim_process> <trace_filename>

  4. After the experiment, stop tracing and collect the trace.
  (qemu) trace_stop
  (In addition to the trace file I recommend keeping the guest.log file that 
   DECAF places in the startup directory)


Tracing a process from the start
================================
If you want to trace a process from the start, then the PID is unknown. 
To trace, then replace steps 2. and 3. above with:

  2. (qemu) tc_modname <process_name>
     This is an optional command to prevent writing to the trace until 
     the first instruction in the main module of the process executes, 
     i.e., the trace does not contain the process creation. 
     You can skip this step if you want to include process creation in
     the trace.

  3. (qemu) tracebyname <process_name> <trace_filename>
     This instructs TFD to start tracing when the given process starts

For example: 
  (qemu) tc_modname named.exe
  (qemu) tracebyname named.exe "/tmp/tmp.trace"

Then, start the process

