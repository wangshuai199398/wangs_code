/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _YS_DEBUG_H_
#define _YS_DEBUG_H_

#include <linux/bitmap.h>
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include "ysnic.h"

struct ys_debug_type {
	u8 gen;
	u32 cursor;
	void *cfg_data;
	void *runtime_data;
	/* resoure spinlock */
	spinlock_t lock;
};

int ys_debug_init(struct pci_dev *pdev);
void ys_debug_uninit(struct pci_dev *pdev);
void ys_debug_back_unit(char *data, u8 gen);
u8 ys_debug_get_unit(struct net_device *ndev, char **data);

#endif
