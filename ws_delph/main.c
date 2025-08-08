#include <linux/module.h>


static int __init ws_init(void)
{
    printk(KERN_INFO "ws module init\n");
    return 0;
}

static void __exit ws_exit(void)
{
    printk(KERN_INFO "ws module exit\n");
}

module_init(ws_init);
module_exit(ws_exit);

MODULE_DESCRIPTION("Ws learning module");
MODULE_AUTHOR("wangs");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");