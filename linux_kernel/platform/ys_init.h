/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_INIT_H_
#define __YS_INIT_H_

#include <linux/pci.h>
#include <linux/auxiliary_bus.h>

struct ys_pci_driver {
	u32 aux_drv_support;
	struct pci_driver pdrv;
};

int ys_init(struct ys_pci_driver *ys_pdrv);
void ys_exit(struct ys_pci_driver *ys_pdrv);

#endif /* __YS_INIT_H_ */
