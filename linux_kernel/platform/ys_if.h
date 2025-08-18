/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __YS_IF_H_
#define __YS_IF_H_

#include <linux/device.h>
#include <linux/pci.h>
#include <linux/debugfs.h>

extern struct dentry *ys_debugfs_root;

void ys_debugfs_init(void);
void ys_debugfs_uninit(void);

struct devlink *ys_devlink_alloc(struct device *dev);

#endif

