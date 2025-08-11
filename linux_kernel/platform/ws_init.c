#include <linux/module.h>

#include "ws_init.h"
#include "ws_debugfs.h"
#include "ws_auxiliary.h"

int ws_init2(struct ws_pci_driver *ws_pdrv)
{
    int ret;
    pr_info("Driver %s Init\n", THIS_MODULE->name);

    ws_debugfs_init();

    ws_pdev_manager_init();

    ret = ws_aux_init(ws_pdrv->aux_drv_support);
    if (ret)
        goto err_aux_init;
    
    ret = ws_pdev_init(&ws_pdrv->pdrv);
    if (ret)
        goto err_pdev_init;

err_pdev_init:
    ws_pdev_uninit(&ws_pdrv->pdrv);

err_aux_init:
    ws_aux_uninit(ws_pdev->aux_drv_support);
    
    return ret;
}

void ws_exit2(struct ws_pci_driver *ws_pdrv)
{
    pr_info("Driver %s exit\n", THIS_MODULE->name);

    ws_debugfs_exit();
}