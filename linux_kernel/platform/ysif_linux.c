#include <linux/auxiliary_bus.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include <linux/compiler.h>
#include <linux/debugfs.h>
#include <linux/spinlock.h>
#include <linux/pci.h>
#include <linux/miscdevice.h>
#include <net/devlink.h>
#include <linux/rwlock.h>


#include "ysif_linux.h"

static const struct ysif_ops *g_ys_ops;
static DEFINE_MUTEX(g_ys_ops_lock);

static int ysif_ops_set(const struct ysif_ops *ops)
{
    int ret = 0;

    if (!ops)
        return -EINVAL;

    mutex_lock(&g_ys_ops_lock);
    if (READ_ONCE(g_ys_ops)) {
        ret = -EBUSY;
        goto out;
    }
    WRITE_ONCE(g_ys_ops, ops);
out:
    mutex_unlock(&g_ys_ops_lock);
    return ret;
}

const struct ysif_ops *ysif_get_ops(void)
{
    return READ_ONCE(g_ys_ops);
}

static int ys_auxiliary_driver_register(struct auxiliary_driver *drv)
{
    return auxiliary_driver_register(drv);
}

static void ys_spin_lock_init(spinlock_t *spin)
{
    spin_lock_init(spin);
}

static void ys_rwlock_init(rwlock_t *rwlock)
{
    rwlock_init(rwlock);
}

static int ys_pci_register_driver(struct pci_driver *pdrv)
{
    return pci_register_driver(pdrv);
}

static void *ys_ioremap(phys_addr_t offset, size_t size)
{
    return ioremap(offset, size);
}


static const struct ysif_ops ysif_linux_ops = {
    .debugfs_create_dir = debugfs_create_dir,
    .debugfs_remove = debugfs_remove,

    .bitmap_zero = bitmap_zero,
    .bitmap_set = bitmap_set,

    .INIT_LIST_HEAD = INIT_LIST_HEAD,

    .yspin_lock_init = ys_spin_lock_init,
    .yrwlock_init = ys_rwlock_init,

    .yauxiliary_driver_register   = ys_auxiliary_driver_register,
    .auxiliary_driver_unregister = auxiliary_driver_unregister,

    .ypci_register_driver = ys_pci_register_driver,

    .misc_register = misc_register,

    .devlink_alloc = devlink_alloc,
    .devlink_priv = devlink_priv,

    .pci_set_drvdata = pci_set_drvdata,
    .pci_enable_device = pci_enable_device,
    .pci_set_master = pci_set_master,
    .pci_request_regions = pci_request_regions,

    .yioremap = ys_ioremap,
};

void ysif_ops_init(void)
{
    int ret;
    ret = ysif_ops_set(&ysif_linux_ops);
    if (ret < 0) {
        pr_err("YS if ops init err\n");
    }
}

