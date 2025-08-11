#ifndef __WS_AUXILIARY_H_
#define __WS_AUXILIARY_H_

#include <linux/auxiliary_bus.h>

#include "ws_pdev.h"

#define AUX_NAME_ETH "eth"

enum {
    AUX_TYPE_ETH = (1 << 0),
};

struct ws_auxiliary_driver {
    struct auxiliary_driver drv;
    u32 aux_drv_support;
    u8 is_registered;
};

#define WS_AUX_DRV(_name, _probe, _remove, _id_table, _aux_drv_support) \
    {   \
        .drv = {   \
            .name = _name,   \
            .probe = _probe,   \
            .remove = _remove,   \
            .id_table = _id_table,   \
        },   \
        .aux_drv_support = _aux_drv_support,   \
    }

#define WS_AUX_MODULE_NAME WS_DEV_NAME(name)

int ws_aux_init(u32 pci_support_type);
int ws_aux_uninit(u32 pci_support_type);

#endif
