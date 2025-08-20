// SPDX-License-Identifier: GPL-2.0

#include <linux/debugfs.h>
#include "ys_platform.h"
#include "ys_debug.h"
#include "ys_debugfs.h"
#include "ysif_linux.h"

struct dentry *ys_debugfs_root;
EXPORT_SYMBOL(ys_debugfs_root);

void ys_debugfs_init(void)
{
	const struct ysif_ops *ops = ysif_get_ops();
	ys_debugfs_root = ops->debugfs_create_dir("yusur", NULL);
	if (IS_ERR(ys_debugfs_root))
		ys_err("Failed to create debugfs root directory");
}

void ys_debugfs_uninit(void)
{
	const struct ysif_ops *ops = ysif_get_ops();
	ops->debugfs_remove(ys_debugfs_root);
}
