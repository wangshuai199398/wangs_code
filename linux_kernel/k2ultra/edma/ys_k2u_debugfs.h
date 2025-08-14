/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __YS_K2U_DEBUGFS_H__
#define __YS_K2U_DEBUGFS_H__

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/list.h>

#include <linux/netdevice.h>
#include <linux/rhashtable.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include <linux/pci.h>

#include "ys_platform.h"

int ys_k2u_debugfs_init(struct ys_pdev_priv *pdev_priv, struct dentry **root);
void ys_k2u_debugfs_exit(struct dentry *root);

#endif /* __YS_K2U_DEBUGFS_H__ */
