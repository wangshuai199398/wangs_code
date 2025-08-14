/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_DEVLINK_H_
#define __YS_DEVLINK_H_

#include "ys_utils.h"

#ifdef YS_HAVE_DEVLINK_PARAM_DRIVER
#include <net/devlink.h>

struct ys_devlink_hw_ops {
	void (*set_switch_mode)(struct pci_dev *pdev, u8 switch_mode);
	int (*get_switch_mode)(struct pci_dev *pdev);
};

enum ys_devlink_param_id {
	YS_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	YS_DEVLINK_PARAM_ID_SWITCH_MODE,
};

struct ys_devlink {
	struct pci_dev *pdev;
	u8 devlink_registered;
	u8 switch_mode;
	struct ys_devlink_hw_ops *devlink_hw_ops;
};

struct devlink *ys_devlink_alloc(struct device *dev);
void ys_devlink_release(struct devlink *devlink);
int ys_devlink_init(struct pci_dev *pdev);
void ys_devlink_uninit(struct pci_dev *pdev);

#endif /* YS_HAVE_DEVLINK_PARAM_DRIVER */
#endif /* __YS_DEVLINK_H_ */
