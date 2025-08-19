#ifndef __YSIF_LINUX_H_
#define __YSIF_LINUX_H_

struct auxiliary_driver;
struct dentry;

struct ysif_ops {
    struct dentry *(*debugfs_create_dir)(const char *name, struct dentry *parent);
    int (*auxiliary_driver_register)(struct auxiliary_driver *drv);
    void (*auxiliary_driver_unregister)(struct auxiliary_driver *drv);
};

const struct ysif_ops *ysif_get_ops(void);
void ysif_ops_init(void);

//extern const struct ysif_ops ysif_linux_ops;

#endif
