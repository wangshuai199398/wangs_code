#ifndef __YS_NDEV_H_
#define __YS_NDEV_H_

#include <linux/auxiliary_bus.h>

int ws_aux_eth_probe(struct auxiliary_device *adev, const struct auxiliary_device_id *id);
void ws_aux_eth_remove(struct auxiliary_device *adev);

#endif
