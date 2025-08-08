#ifndef __WS_PDEV_H_
#define __WS_PDEV_H_

#define PCI_VENDOR_ID_WANGS 0x1f47

struct ws_pdev_hw {
    unsigned long irq_flag;
};

int ws_pdev_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void ws_pdev_remove(struct pci_dev *pdev);

#endif