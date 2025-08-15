/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_PLATFORM_H_
#define __YS_PLATFORM_H_

#include "../platform/ys_auxiliary.h"
#include "../platform/ys_init.h"
#include "../platform/ys_ndev.h"
#include "../platform/ys_pdev.h"
#include "../platform/ys_queue.h"
#include "../platform/ys_sriov.h"
#include "../platform/ys_sysfs.h"
#include "../platform/ys_i2c.h"
#include "../platform/ys_ptp.h"
#include "../platform/ys_mbox.h"
#include "../platform/ys_vdpa.h"
#include "../platform/ys_plat_doe.h"

#include "../net/lan/ys_lan.h"
#include "../net/mac/ys_mac.h"
#include "../net/ys_ndev_ops.h"

#ifdef CONFIG_YSMOD_CDEV
#include "../platform/ys_cdev.h"
#endif /* CONFIG_YSMOD_CDEV */

#include "../platform/ys_devlink.h"
#include "../net/ys_devlink_ops.h"

#endif /* __YS_PLATFORM_H_ */
