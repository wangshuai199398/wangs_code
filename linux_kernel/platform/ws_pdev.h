#ifndef __WS_PDEV_H_
#define __WS_PDEV_H_

#include <linux/pci.h>

#include "ws_utils.h"

#define WS_DEV_NAME(name) WS_HW_STRING("ws_", name)

#define PCI_VENDOR_ID_WANGS 0x1f47

#define WS_DEV_MAX 8192

struct ws_pdev_manager {
    struct list_head pdev_list;

    unsigned long eth_dev_id[BITS_TO_LONGS(WS_DEV_MAX)];
};

struct ws_pdev_hw {
    unsigned long irq_flag;
};

void ws_pdev_manager_init(void);

int ws_pdev_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void ws_pdev_remove(struct pci_dev *pdev);

int ws_pdev_init(struct pci_driver *pdrv);
void ws_pdev_uninit(struct pci_driver *pdrv);

#endif
