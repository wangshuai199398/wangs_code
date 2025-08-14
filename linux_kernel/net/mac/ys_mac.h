/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_MAC_H_
#define __YS_MAC_H_

#include "./umac/ys_umac.h"
#include "./xmac/ys_xmac.h"

struct ys_mac_ndev {
	struct net_device *ndev;
	struct list_head list;
};

struct ys_mac {
	struct ys_adev *adev;
	struct list_head ndev_list;
	/* list lock, when add/del net_device */
	spinlock_t list_lock;

	/* mac interrupt event notifier */
	int irq_vector;
	struct notifier_block irq_nb;
};

bool ys_k2u_ndev_has_mac_link_status(struct net_device *ndev);
int ys_aux_mac_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id);
void ys_aux_mac_remove(struct auxiliary_device *auxdev);

#endif /* __YS_MAC_H_ */
