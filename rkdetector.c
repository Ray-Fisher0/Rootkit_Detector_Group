// Rootkit detector using kprobes to monitor syscall table modifications
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rootkit Detector");
MODULE_DESCRIPTION("Kprobe-based syscall table modification detector");

#define PROC_NAME "rootkit_scan"
#define SCAN_INTERVAL (30 * HZ)

static unsigned long **syscall_table;
static unsigned long original_syscalls[NR_syscalls];
static struct timer_list scan_timer;
static struct proc_dir_entry *proc_entry;
static unsigned long last_scan_jiffies;
static int last_changes_found;

// Helper: check if an address is within kernel text (optional, can be omitted)
static bool addr_in_kernel_text(unsigned long addr) {
    // ...existing code...
    return true; // Placeholder, as we don't use kallsyms
}

// Scanning function: compares syscall table to original snapshot
static void scan_syscalls(void) {
    int i, changes = 0;
    for (i = 0; i < NR_syscalls; i++) {
        unsigned long current_addr = (unsigned long)syscall_table[i];
        if (current_addr != original_syscalls[i]) {
            changes++;
            printk(KERN_ALERT "[rkdetector] SYSCALL TABLE MODIFIED! syscall %d: original=0x%lx current=0x%lx\n", i, original_syscalls[i], current_addr);
        }
    }
    last_changes_found = changes;
    last_scan_jiffies = jiffies;
    if (changes > 0) {
        printk(KERN_ALERT "[rkdetector] ALERT: %d syscall table entries have changed!\n", changes);
    }
}

// Timer callback for periodic scan
static void timer_callback(struct timer_list *t) {
    scan_syscalls();
    mod_timer(&scan_timer, jiffies + SCAN_INTERVAL);
}

// /proc interface for manual scan and status
static ssize_t proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    char msg[256];
    int len;
    if (*ppos > 0) return 0;
    len = snprintf(msg, sizeof(msg), "Rootkit detector status\nLast scan: %lu seconds ago\nChanges detected: %d\nWrite 'scan' to trigger\n", (jiffies - last_scan_jiffies) / HZ, last_changes_found);
    if (copy_to_user(buf, msg, len)) return -EFAULT;
    *ppos = len;
    return len;
}
static ssize_t proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    char kbuf[16];
    if (count > sizeof(kbuf)-1) return -EINVAL;
    if (copy_from_user(kbuf, buf, count)) return -EFAULT;
    kbuf[count] = '\0';
    if (strncmp(kbuf, "scan", 4) == 0) {
        printk(KERN_INFO "[rkdetector] manual scan requested\n");
        scan_syscalls();
    }
    return count;
}
static const struct proc_ops proc_fops = {
    .proc_read  = proc_read,
    .proc_write = proc_write,
};

// Module initialization and cleanup
static int __init module_start(void) {
    int i;
    printk(KERN_INFO "[rkdetector] loading...\n");
    // Use kprobe to find sys_call_table address
    struct kprobe kp = {
        .symbol_name = "sys_call_table"
    };
    if (register_kprobe(&kp) < 0) {
        printk(KERN_ERR "[rkdetector] kprobe registration failed\n");
        return -EINVAL;
    }
    syscall_table = (unsigned long **)kp.addr;
    unregister_kprobe(&kp);
    if (!syscall_table) {
        printk(KERN_ERR "[rkdetector] cannot resolve sys_call_table\n");
        return -EINVAL;
    }
    for (i = 0; i < NR_syscalls; i++) {
        original_syscalls[i] = (unsigned long)syscall_table[i];
    }
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &proc_fops);
    timer_setup(&scan_timer, timer_callback, 0);
    mod_timer(&scan_timer, jiffies + SCAN_INTERVAL);
    scan_syscalls();
    printk(KERN_INFO "[rkdetector] loaded successfully\n");
    return 0;
}
static void __exit module_end(void) {
    del_timer_sync(&scan_timer);
    if (proc_entry) proc_remove(proc_entry);
    printk(KERN_INFO "[rkdetector] unloaded\n");
}
module_init(module_start);
module_exit(module_end);
