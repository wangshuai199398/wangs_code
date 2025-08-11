#include <linux/module.h>

#include "ws_init.h"
#include "ws_debugfs.h"
#include "../ver.h"

int ws_init2(struct ws_pci_driver *ws_pdrv)
{
    int ret;
    pr_info("Driver %s Init\n", THIS_MODULE->name);

    ws_debugfs_init();


    
    return ret;
}

void ws_exit2(struct ws_pci_driver *ws_pdrv)
{
    pr_info("Driver %s exit\n", THIS_MODULE->name);

    ws_debugfs_exit();
}