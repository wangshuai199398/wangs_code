// SPDX-License-Identifier: GPL-2.0

#include <linux/debugfs.h>
#include "ys_platform.h"
#include "ys_debug.h"
#include "ys_debugfs.h"

struct dentry *ys_debugfs_root;
EXPORT_SYMBOL(ys_debugfs_root);

void ys_debugfs_init(void)
{
	ys_debugfs_root = debugfs_create_dir("yusur", NULL);
	if (IS_ERR(ys_debugfs_root))
		ys_err("Failed to create debugfs root directory");
}

void ys_debugfs_uninit(void)
{
	debugfs_remove(ys_debugfs_root);
}
