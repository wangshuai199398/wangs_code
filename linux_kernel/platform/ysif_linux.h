#ifndef __YSIF_LINUX_H_
#define __YSIF_LINUX_H_

struct auxiliary_driver;
struct dentry;
struct list_head;
struct spinlock_t;
struct mutex;

struct ysif_ops {
    struct dentry *(*debugfs_create_dir)(const char *name, struct dentry *parent);
    struct dentry * (*debugfs_create_file)(const char *name, umode_t mode, struct dentry *parent, void *data, const struct file_operations *fops);
    void (*debugfs_remove)(struct dentry *dentry);

    int (*sysfs_create_group)(struct kobject *kobj, const struct attribute_group *grp);

    void (*bitmap_zero)(unsigned long *dst, unsigned int nbits);
    void (*bitmap_set)(unsigned long *map, unsigned int start, unsigned int nbits);
    

    void (*INIT_LIST_HEAD)(struct list_head *list);
    void (*list_add)(struct list_head *new, struct list_head *head);
    void (*list_add_rcu)(struct list_head *new, struct list_head *head);

    unsigned long (*yfind_first_zero_bit)(const unsigned long *addr, unsigned long size);
    void (*set_bit)(unsigned long nr, volatile unsigned long *addr);

    void (*idr_init)(struct idr *idr);
    void *(*idr_find)(const struct idr *, unsigned long id);
    int (*idr_alloc)(struct idr *idr, void *ptr, int start, int end, gfp_t gfp);
    

    void (*refcount_inc)(refcount_t *r);
    void (*refcount_set)(refcount_t *r, int n);

    void (*yspin_lock_init)(spinlock_t *spin);
    void (*spin_lock)(spinlock_t *lock);
    void (*spin_unlock)(spinlock_t *lock);

    void (*yrwlock_init)(rwlock_t *rwlock);
    void (*ywrite_lock_irqsave)(rwlock_t *rwlock, unsigned long flags);
    void (*ywrite_unlock_irqrestore)(rwlock_t *rwlock, unsigned long flags);

    void (*ymutex_init)(struct mutex *mutex);

    void (*YBLOCKING_INIT_NOTIFIER_HEAD)(struct blocking_notifier_head *nh);
    int (*blocking_notifier_chain_register)(struct blocking_notifier_head *nh, struct notifier_block *n);

    void (*YATOMIC_INIT_NOTIFIER_HEAD)(struct atomic_notifier_head *nh);

    void (*init_completion)(struct completion *x);

    int (*yauxiliary_driver_register)(struct auxiliary_driver *drv);
    void (*auxiliary_driver_unregister)(struct auxiliary_driver *drv);
    int (*auxiliary_device_init)(struct auxiliary_device *auxdev);
    int (*yauxiliary_device_add)(struct auxiliary_device *auxdev);
    void (*auxiliary_device_uninit)(struct auxiliary_device *auxdev);

    int (*ypci_register_driver)(struct pci_driver *pdrv);

    int (*misc_register)(struct miscdevice *misc);

    struct devlink *(*devlink_alloc)(const struct devlink_ops *ops, size_t priv_size, struct device *dev);
    void *(*devlink_priv)(struct devlink *devlink);
    struct devlink *(*priv_to_devlink)(void *priv);
    int (*devlink_register)(struct devlink *devlink);
    int (*devlink_params_register)(struct devlink *devlink, const struct devlink_param *params, size_t params_count);
    int (*devlink_param_driverinit_value_set)(struct devlink *devlink, u32 param_id, union devlink_param_value init_val);

    void (*pci_set_drvdata)(struct pci_dev *pdev, void *data);
    int (*pci_enable_device)(struct pci_dev *dev);
    void (*pci_set_master)(struct pci_dev *dev);
    int (*pci_request_regions)(struct pci_dev *dev, const char *name);
    void *(*pci_get_drvdata)(struct pci_dev *pdev);
    int (*pci_msix_vec_count)(struct pci_dev *dev);
    int (*pci_alloc_irq_vectors)(struct pci_dev *dev, unsigned int min_vecs, unsigned int max_vecs, unsigned int flags);
    int (*pci_irq_vector)(struct pci_dev *dev, unsigned int nr);

    void *(*yioremap)(phys_addr_t offset, size_t size);

    int (*dma_set_mask)(struct device *dev, u64 mask);
    int (*dma_set_coherent_mask)(struct device *dev, u64 mask);
    int (*dma_set_max_seg_size)(struct device *dev, unsigned int size);
};

const struct ysif_ops *ysif_get_ops(void);
void ysif_ops_init(void);

//extern const struct ysif_ops ysif_linux_ops;

#endif
