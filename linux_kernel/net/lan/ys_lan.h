/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_LAN_H_
#define __YS_LAN_H_

#include "./k2ulan/ys_k2ulan.h"

#define LAN_SOC_UPLINK_VFNUM 65535

int ys_aux_lan_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id);
void ys_aux_lan_remove(struct auxiliary_device *auxdev);

#endif /* __YS_LAN_H_ */
