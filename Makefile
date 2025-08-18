KERNEL_DIR = /home/hdski/WSL2-Linux-Kernel

obj-m += my_module.o

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
