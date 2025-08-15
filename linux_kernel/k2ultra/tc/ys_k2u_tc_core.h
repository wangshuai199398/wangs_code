/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_TC_CORE_H_
#define __YS_TC_CORE_H_

#include "../net/tc/ys_tc.h"

extern const struct ys_tc_adapter_ops ys_tc_ops;

int ys_tc_init(struct net_device *ndev, int switchdev_id, __u8 pf_id,
	       __u16 vf_id);
void ys_tc_exit(struct net_device *ndev);

#endif
