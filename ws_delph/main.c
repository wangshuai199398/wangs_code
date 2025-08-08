#include <linux/module.h>

#include "../include/ws_platform.h"

static struct ws_pdev_hw pf_type = {
    .irq_flag = PCI_IRQ_MSIX | PCI_IRQ_MSI,
    
};

static const struct pci_device_id ws_pdev_ids[] = {
    { PCI_DEVICE(PCI_VENDOR_ID_WANGS, 0x1001), .driver_data = (unsigned long)&pf_type },
    { 0 }
};

static struct ws_pci_driver ws_driver = {
    .aux_drv_support = AUX_TYPE_ETH,
    .pdrv = {
        .name = "ws_unic3",
        .id_table = ws_pdev_ids,
        .probe = ws_pdev_probe,
        .remove = ws_pdev_remove,
        .sriov_configure = NULL,
    },
};

static int __init ws_init(void)
{
    return ws_init2(&ws_driver);
}

static void __exit ws_exit(void)
{
    ws_exit2(&ws_driver);
}

module_init(ws_init);
module_exit(ws_exit);

MODULE_DESCRIPTION("Ws learning module");
MODULE_AUTHOR("wangs");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
