#include "ws_auxiliary.h"
#include "ws_ndev.h"

static const struct auxiliary_device_id ws_eth_id_table[] = {
    { .name =  WS_AUX_MODULE_NAME "." AUX_NAME_ETH },
    { },
};

static struct ws_auxiliary_driver ws_adrvs[] = {
    WS_AUX_DRV(AUX_NAME_ETH, ws_aux_eth_probe, ws_aux_eth_remove, ws_eth_id_table, AUX_TYPE_ETH),
    WS_AUX_DRV(NULL, NULL, NULL, NULL, 0)
};

int ws_aux_init(u32 pci_support_type)
{
    int ret;
    int i = 0;

    for(; !IS_ERR_OR_NULL(ws_adrvs[i].drv.name); i++) {
        if (pci_support_type & ws_adrvs[i].aux_drv_support) {
            if (!ws_adrvs[i].is_registered) {
                ret = auxiliary_driver_register(&ws_adrvs[i].drv);
                if (ret)
                    return ret;
                ws_adrvs[i].is_registered = true;
            }
        }
    }
    return ret;
}

void ws_aux_uninit(u32 pci_support_type)
{
    int ret;
    int i = 0;

    for(; !IS_ERR_OR_NULL(ws_adrvs[i].drv.name); i++) {
        if (pci_support_type & ws_adrvs[i].aux_drv_support) {
            if (ws_adrvs[i].is_registered) {
                auxiliary_driver_unregister(&ws_adrvs[i].drv);
                ws_adrvs[i].is_registered = false;
            }
        }
    }
}