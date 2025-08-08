#include <linux/module.h>

#include <ws_init.h>

int ws_init2(struct ws_pci *ws_pdrv)
{
    int ret;
    pr_info("Driver %s Init\n", THIS_MODULE->name);

}

