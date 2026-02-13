#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rootkit Detector");
MODULE_DESCRIPTION("Periodic syscall hook rootkit detector");

// Kernel text section boundaries (defined by linker script)
extern char _stext[];
extern char _etext[];

#define PROC_NAME "rootkit_scan"
#define SCAN_INTERVAL (30 * HZ)   // HZ is the number of jiffies per second

static unsigned long **syscall_table;
static struct timer_list scan_timer;
static struct proc_dir_entry *proc_entry;

static unsigned long last_scan_jiffies;
static int last_hooks_found;


// Helper function to check if an address is within the kernel text section
static bool addr_in_kernel_text(unsigned long addr)
{
    return (addr >= (unsigned long)_stext &&
            addr <  (unsigned long)_etext);
}

// Scanning Function that checks syscall table entries for hooks
static void scan_syscalls(void)
{
    int i;
    unsigned long addr;
    int suspicious = 0;

    printk(KERN_INFO "[rkdetector] scanning syscalls...\n");

    for (i = 0; i < NR_syscalls; i++) {
        addr = (unsigned long)syscall_table[i];

        if (!addr_in_kernel_text(addr)) {
            suspicious++;
            printk(KERN_WARNING
                   "[rkdetector] HOOK? syscall %d -> %px\n",
                   i, (void *)addr);
        }
    }

    last_hooks_found = suspicious;
    last_scan_jiffies = jiffies;

    printk(KERN_INFO
           "[rkdetector] scan finished, # of suspicious=%d\n",
           suspicious);
}


// Timer
static void timer_callback(struct timer_list *t)
{
    scan_syscalls();

    // reschedule 
    mod_timer(&scan_timer, jiffies + SCAN_INTERVAL);
}


// /proc interface for manual scan trigger and status reporting

static ssize_t proc_read(struct file *file,
                         char __user *buf,
                         size_t count,
                         loff_t *ppos)
{
    char msg[256];
    int len;

    if (*ppos > 0)
        return 0;

    len = snprintf(msg, sizeof(msg),
                   "Rootkit detector status\n"
                   "Last scan: %lu seconds ago\n"
                   "Suspicious hooks: %d\n"
                   "Write 'scan' to trigger\n",
                   (jiffies - last_scan_jiffies) / HZ,
                   last_hooks_found);

    if (copy_to_user(buf, msg, len))
        return -EFAULT;

    *ppos = len;
    return len;
}


static ssize_t proc_write(struct file *file,
                          const char __user *buf,
                          size_t count,
                          loff_t *ppos)
{
    char kbuf[16];

    if (count > sizeof(kbuf)-1)
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

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
static int __init module_start(void)
{
    printk(KERN_INFO "[rkdetector] loading...\n");

    syscall_table = (unsigned long **)kallsyms_lookup_name("sys_call_table");

    if (!syscall_table) {
        printk(KERN_ERR "cannot find sys_call_table\n");
        return -EINVAL;
    }

    // create /proc entry
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &proc_fops);

    // setup timer
    timer_setup(&scan_timer, timer_callback, 0);
    mod_timer(&scan_timer, jiffies + SCAN_INTERVAL);

    scan_syscalls();

    printk(KERN_INFO "[rkdetector] loaded successfully\n");
    return 0;
}


static void __exit module_end(void)
{
    del_timer_sync(&scan_timer);

    if (proc_entry)
        proc_remove(proc_entry);

    printk(KERN_INFO "[rkdetector] unloaded\n");
}

module_init(module_start);

module_exit(module_end);