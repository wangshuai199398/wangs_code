#include <linux/debugfs.h>

#include "ws_debugfs.h"
#include "ws_log.h"

struct dentry *ws_debug_root;

void ws_debugfs_init(void)
{
    ws_debug_root = debugfs_create_dir("ws", NULL);
    if (IS_ERR(ws_debug_root)) {
        ws_err("Failed to create ws debugfs directory\n");
    }
}

void ws_debugfs_exit(void)
{
    debugfs_remove(ws_debug_root);
}