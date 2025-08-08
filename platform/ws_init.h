#ifndef _WS_INIT_H_
#define _WS_INIT_H_

#include <linux/pci.h>
#include <linux/auxiliary_bus.h>

struct ws_pci_driver {
    u32 aux_drv_support;
    struct pci_driver pdrv;
};

int ws_init2(void);
void ws_exit2(void);

#endif