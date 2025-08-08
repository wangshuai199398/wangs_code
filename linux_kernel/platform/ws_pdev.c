#include <linux/pci.h>

#include "ws_pdev.h"

int ws_pdev_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    pr_info("Probing device %s with ID %04x:%04x\n", pci_name(pdev), pdev->vendor, pdev->device);
    return 0;
}
void ws_pdev_remove(struct pci_dev *pdev)
{
    pr_info("Removing device %s with ID %04x:%04x\n", pci_name(pdev), pdev->vendor, pdev->device);
}