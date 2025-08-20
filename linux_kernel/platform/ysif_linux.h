#ifndef __YSIF_LINUX_H_
#define __YSIF_LINUX_H_

struct auxiliary_driver;
struct dentry;
struct list_head;
struct spinlock_t;

struct ysif_ops {
    struct dentry *(*debugfs_create_dir)(const char *name, struct dentry *parent);
    void (*debugfs_remove)(struct dentry *dentry);

    void (*bitmap_zero)(unsigned long *dst, unsigned int nbits);
    void (*bitmap_set)(unsigned long *map, unsigned int start, unsigned int nbits);

    void (*INIT_LIST_HEAD)(struct list_head *list);

    void (*yspin_lock_init)(spinlock_t *spin);
    void (*yrwlock_init)(rwlock_t *rwlock);

    int (*yauxiliary_driver_register)(struct auxiliary_driver *drv);
    void (*auxiliary_driver_unregister)(struct auxiliary_driver *drv);

    int (*ypci_register_driver)(struct pci_driver *pdrv);

    int (*misc_register)(struct miscdevice *misc);

    struct devlink *(*devlink_alloc)(const struct devlink_ops *ops, size_t priv_size, struct device *dev);
    void *(*devlink_priv)(struct devlink *devlink);

    void (*pci_set_drvdata)(struct pci_dev *pdev, void *data);
    int (*pci_enable_device)(struct pci_dev *dev);
    void (*pci_set_master)(struct pci_dev *dev);
    int (*pci_request_regions)(struct pci_dev *dev, const char *name);

    void *(*yioremap)(phys_addr_t offset, size_t size);
};

const struct ysif_ops *ysif_get_ops(void);
void ysif_ops_init(void);

//extern const struct ysif_ops ysif_linux_ops;

#endif
