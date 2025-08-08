#include <linux/module.h>

#include <ws_init.h>

int ws_init2(struct ws_pci_driver *ws_pdrv)
{
    int ret;
    ret = 0;
    ws_pdrv->pdrv.name = THIS_MODULE->name;
    pr_info("Driver %s Init\n", THIS_MODULE->name);
    return ret;
}

void ws_exit2(struct ws_pci_driver *ws_pdrv)
{
    ws_pdrv->pdrv.name = THIS_MODULE->name;
    pr_info("Driver %s exit\n", THIS_MODULE->name);
}