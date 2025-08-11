#include <linux/pci.h>

#include "ws_pdev.h"
#include "ws_log.h"

struct ws_pdev_manager g_ws_pdev_manager;

int ws_pdev_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    pr_info("Probing device %s with ID %04x:%04x\n", pci_name(pdev), pdev->vendor, pdev->device);
    return 0;
}
void ws_pdev_remove(struct pci_dev *pdev)
{
    pr_info("Removing device %s with ID %04x:%04x\n", pci_name(pdev), pdev->vendor, pdev->device);
}

void ws_pdev_manager_init(void)
{
    static bool init;
    if (init)
        return;
    
    bitmap_zero(g_ws_pdev_manager.eth_dev_id, WS_DEV_MAX);

    INIT_LIST_HEAD(&g_ws_pdev_manager.pdev_list);



    init = true;
}

int ws_pdev_init(struct pci_driver *pdrv)
{
    int ret;
    ret = pci_register_driver(pdrv);
    if (ret) {
        ws_err("Failed to register PCI driver %s\n", pdrv->name);
        return ret;
    }
    return ret;
}

void ws_pdev_uninit(struct pci_driver *pdrv)
{
    pci_unregister_driver(pdrv);
    pr_info("PCI driver %s unregistered\n", pdrv->name);
}
