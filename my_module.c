#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

MODULE_LICENSE("GPL");

#define PROC_NAME "my_proc"

// PID to track
static long PID = 0;

static int kprobe_pre_handler(struct kprobe* p, struct pt_regs* regs) {

	if (current->pid == PID) {
		printk(KERN_INFO "LKM: Process %ld is forking a new process\n", PID);
	}
	printk(KERN_INFO "LKM: durr durr: %ld \n", PID);
	return 0; // continue execution
}

struct kprobe kp_fork = {
	.symbol_name = "__x64_sys_fork", // monitor the fork syscall
	.pre_handler = kprobe_pre_handler, // set the pre-handler function
};

struct kprobe kp_clone = {
	.symbol_name = "__x64_sys_clone",
	.pre_handler = kprobe_pre_handler,
};

// This function will be called when the /proc/my_proc file is read
static ssize_t proc_read(struct file *file, char __user *usr_buf, size_t count, loff_t *ppos) {
	char buffer[128]; // generous buffer for output string + PID
	long len = 0; // length of the string to be written to the user buffer

	// if this isnt the first read, return 0 to indicate EOF
	if (*ppos != 0) {
		return 0; // EOF
	}

	// len = numbre of characters written to buffer
	len = sprintf(buffer, "Currently monitoring PID: %ld\n", PID);

	// copy kernel buffer to users buffer 
	if (copy_to_user(usr_buf, buffer, len)) { // send the buffer created with sprintf to the user
		return -EFAULT; // error in copying
	}

	*ppos = len; // update the position for next read with the length of the buffer
	return len; // return the number of bytes read
}

static ssize_t proc_write(struct file* file, const char __user* usr_buf, size_t count, loff_t* ppos) {
	char buffer[32];
	long long pid = 0;

	// ensure we dont overflow kernel buffer
	if (count > sizeof(buffer) - 1) {
		return -EINVAL; // invalid argument
	}

	if (copy_from_user(buffer, usr_buf, count)) {
		return -EFAULT; // error in copying
	}
	buffer[count] = '\0'; // null terminate the string

	if (kstrtoll(buffer, 10, &pid) == 0) {
		PID = pid;
		printk(KERN_INFO "LKM: Now monitoring PID %ld\n", PID);
	}
	else {
		return -EINVAL; // invalid input (pid is 0)
	}

	return count;
}

static const struct proc_ops proc_ops = {
	.proc_read = proc_read,
	.proc_write = proc_write,
};

// This function is called when the module is loaded
static int __init my_module_init(void) {
	int ret;
	proc_create(PROC_NAME, 0666, NULL, &proc_ops);
	printk(KERN_INFO "LKM: /proc/%s created\n", PROC_NAME);

	ret = register_kprobe(&kp_fork);
	if (ret < 0) {
		printk(KERN_ERR "LKM: Failed to register kprobe: %d\n", ret);
		return ret; // return error code
	}
	printk(KERN_INFO "LKM: Fork Kprobe registered to %s\n", kp_fork.symbol_name);

	ret = register_kprobe(&kp_clone);
	if (ret < 0) {
		printk(KERN_ERR "LKM: Failed to register kprobe: %d\n", ret);
		return ret;
	}
	printk(KERN_INFO "LKM: Clone Kprobe register to %s\n", kp_clone.symbol_name);
	return 0; // yay
}

static void __exit my_module_exit(void) {
	remove_proc_entry(PROC_NAME, NULL);
	unregister_kprobe(&kp_fork);
	unregister_kprobe(&kp_clone);
	printk(KERN_INFO "LKM: /proc/%s removed and Kprobes unregistered\n", PROC_NAME);
}

module_init(my_module_init);
module_exit(my_module_exit);
// gulp
