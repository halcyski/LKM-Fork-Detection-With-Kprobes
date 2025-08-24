## In order to compile and run this kernel:

1. First, install Windows subsystem for Linux (WSL):
```Powershell
wsl --install
```

2. Then, follow this guide to install the correct WSL2 kernel headers:
https://learn.microsoft.com/en-us/community/content/wsl-user-msft-kernel-v6

3. Clone this repo into a new project folder.

4. Edit the ``Makefile`` to redirect the kernel to your WSL2 compiled kernel

5. Compile the kernel module:
```Bash
make clean && make
```

6. Load the kernel module:
```Bash
sudo insmod my_module.ko
```
7. Confirm the module is loaded:
```Bash
lsmod | grep my_module
```

8. Write any PID to the kernel file (for example, $$ for your shell's PID, 262):
```Bash
echo $$ > /proc/my_proc
```

9. Finally, read from the file and confirm the tracked PID is correct:
```Bash
cat /proc/my_proc
```
