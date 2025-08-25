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
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/etherdevice.h>
#include <linux/dma-mapping.h>
#include <linux/if_vlan.h>


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

static const struct ysif_ops *ysif_get_ops(void)
{
    return READ_ONCE(g_ys_ops);
}

static struct dentry *ys_debugfs_create_dir(const char *name, struct dentry *parent)
{
    return debugfs_create_dir(name, parent);
}

static struct dentry *ys_debugfs_create_file(const char *name, umode_t mode, struct dentry *parent, void *data, const struct file_operations *fops)
{
    return debugfs_create_file(name, mode, parent, data, fops);
}

static void ys_debugfs_remove(struct dentry *dentry)
{
    debugfs_remove(dentry);
}

int ys_sysfs_create_group(struct kobject *kobj, const struct attribute_group *grp)
{
    return sysfs_create_group(kobj, grp);
}

void ys_bitmap_zero(unsigned long *dst, unsigned int nbits)
{
    bitmap_zero(dst, nbits);
}

void ys_bitmap_set(unsigned long *map, unsigned int start, unsigned int nbits)
{
    bitmap_set(map, start, nbits);
}

void ys_set_bit(long int a, volatile unsigned long *addr)
{
    set_bit(a, addr);
}

void ys_idr_init(struct idr *idr)
{
    return idr_init(idr);
}

void *ys_idr_find(const struct idr *i, unsigned long id)
{
    return idr_find(i, id);
}

int ys_idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp)
{
    return ys_idr_alloc(idr, ptr, start, end, gfp);
}

void *ys_idr_remove(struct idr *i, unsigned long id)
{
    return idr_remove(i, id);
}

void ys_refcount_inc(refcount_t *r)
{
    refcount_inc(r);
}

void ys_refcount_set(refcount_t *r, unsigned int n)
{
    refcount_set(r, n);
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

unsigned long ys_find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
    return find_first_zero_bit(addr, size);
}


void ys_mutex_init(struct mutex *mutex)
{
    mutex_init(mutex);
}

void ys_blocking_init_notifier_head(struct blocking_notifier_head *nh)
{
    BLOCKING_INIT_NOTIFIER_HEAD(nh);
}

void ys_atomic_init_notifier_head(struct atomic_notifier_head *nh)
{
    ATOMIC_INIT_NOTIFIER_HEAD(nh);
}

void ys_write_lock_irqsave(rwlock_t * rwlock, unsigned long flags)
{
    write_lock_irqsave(rwlock, flags);
}

void ys_write_unlock_irqrestore(rwlock_t * rwlock, unsigned long flags)
{
    write_unlock_irqrestore(rwlock, flags);
}

int ys_auxiliary_device_add(struct auxiliary_device *auxdev)
{
    return auxiliary_device_add(auxdev);
}

static void ys_init_completion(struct completion *comp)
{
    init_completion(comp);
}

static struct net_device *ys_alloc_etherdev_mq(int sizeof_priv, unsigned int count)
{
    return alloc_etherdev_mq(sizeof_priv, count);
}

static dma_addr_t ys_dma_map_single(struct device *dev, void *ptr, size_t size, enum dma_data_direction dir)
{
    return dma_map_single(dev, ptr, size, dir);
}

void ys_dma_unmap_single(struct device *dev, dma_addr_t addr, size_t size, enum dma_data_direction dir)
{
    dma_unmap_single(dev, addr, size, dir);
}

void ys_timer_setup(struct timer_list *timer, void (*func)(struct timer_list *), unsigned int flags)
{
    timer_setup(timer, func, flags);
}

static void ys_netif_napi_add(struct net_device *dev, struct napi_struct *napi, int (*poll)(struct napi_struct *, int))
{
    netif_napi_add(dev, napi, poll);
}

dma_addr_t ys_dma_map_page(struct device *dev, struct page *page, size_t offset, size_t size, enum dma_data_direction dir)
{
    return dma_map_page(dev, page, offset, size, dir);
}

void ys_dma_upmap_page(struct device *dev, dma_addr_t addr, size_t size, enum dma_data_direction dir)
{
    dma_unmap_page(dev, addr, size, dir);
}

static const struct ysif_ops ysif_linux_ops = {
    .debugfs_create_dir = ys_debugfs_create_dir,
    .debugfs_create_file = ys_debugfs_create_file,
    .debugfs_remove = ys_debugfs_remove,

    .sysfs_create_group = ys_sysfs_create_group,

    .bitmap_zero = ys_bitmap_zero,
    .bitmap_set = ys_bitmap_set,
    .yfind_first_zero_bit = ys_find_first_zero_bit,
    .set_bit = ys_set_bit,

    .idr_init = ys_idr_init,
    .idr_find = ys_idr_find,
    .idr_alloc = ys_idr_alloc,
    .idr_remove = ys_idr_remove,

    .refcount_inc = ys_refcount_inc,
    .refcount_set = ys_refcount_set,

    .INIT_LIST_HEAD = INIT_LIST_HEAD,
    .list_add = list_add,
    .list_add_rcu = list_add_rcu,

    .yspin_lock_init = ys_spin_lock_init,
    .spin_lock = spin_lock,
    .spin_unlock = spin_unlock,

    .yrwlock_init = ys_rwlock_init,
    .ywrite_lock_irqsave = ys_write_lock_irqsave,
    .ywrite_unlock_irqrestore = ys_write_unlock_irqrestore,

    .ymutex_init = ys_mutex_init,

    .YBLOCKING_INIT_NOTIFIER_HEAD = ys_blocking_init_notifier_head,
    .blocking_notifier_chain_register = blocking_notifier_chain_register,
    .blocking_notifier_call_chain = blocking_notifier_call_chain,

    .YATOMIC_INIT_NOTIFIER_HEAD = ys_atomic_init_notifier_head,

    .yinit_completion = ys_init_completion,

    .ytimer_setup = ys_timer_setup,
    .mod_timer = mod_timer,

    .yauxiliary_driver_register   = ys_auxiliary_driver_register,
    .auxiliary_driver_unregister = auxiliary_driver_unregister,
    .auxiliary_device_init = auxiliary_device_init,
    .yauxiliary_device_add = ys_auxiliary_device_add,
    .auxiliary_device_uninit = auxiliary_device_uninit,

    .ypci_register_driver = ys_pci_register_driver,

    .misc_register = misc_register,

    .devlink_alloc = devlink_alloc,
    .devlink_priv = devlink_priv,
    .priv_to_devlink = priv_to_devlink,
    .devlink_register = devlink_register,
    .devlink_params_register = devlink_params_register,
    .devlink_param_driverinit_value_set = devlink_param_driverinit_value_set,
    .dev_alloc_pages = dev_alloc_pages,
    .dev_consume_skb_any = dev_consume_skb_any,
    .dev_kfree_skb_any = dev_kfree_skb_any,

    .pci_set_drvdata = pci_set_drvdata,
    .pci_enable_device = pci_enable_device,
    .pci_set_master = pci_set_master,
    .pci_request_regions = pci_request_regions,
    .pci_get_drvdata = pci_get_drvdata,
    .pci_msix_vec_count = pci_msix_vec_count,
    .pci_alloc_irq_vectors = pci_alloc_irq_vectors,
    .pci_irq_vector = pci_irq_vector,

    .yioremap = ys_ioremap,

    .dma_set_mask = dma_set_mask,
    .dma_set_coherent_mask = dma_set_coherent_mask,
    .dma_set_max_seg_size = dma_set_max_seg_size,
    .dma_alloc_coherent = dma_alloc_coherent,
    .ydma_map_single = ys_dma_map_single,
    .dma_mapping_error = dma_mapping_error,
    .ydma_unmap_single = ys_dma_unmap_single,
    .dma_free_coherent = dma_free_coherent,
    .ydma_map_page = ys_dma_map_page,
    .ydma_unmap_page = ys_dma_upmap_page,

    .yalloc_etherdev_mq = ys_alloc_etherdev_mq,

    .netif_set_real_num_tx_queues = netif_set_real_num_tx_queues,
    .netif_set_real_num_rx_queues = netif_set_real_num_rx_queues,
    .netif_device_attach = netif_device_attach,
    .netif_tx_schedule_all = netif_tx_schedule_all,
    .netif_carrier_off = netif_carrier_off,
    .netif_carrier_on = netif_carrier_on,
    .netif_tx_disable = netif_tx_disable,
    .ynetif_napi_add = ys_netif_napi_add,
    .netif_napi_del = netif_napi_del,
    .netif_tx_wake_queue = netif_tx_wake_queue,
    .netdev_xmit_more = netdev_xmit_more,

    
    .napi_schedule = napi_schedule,
    .napi_schedule_prep = napi_schedule_prep,
    .__napi_schedule_irqoff = __napi_schedule_irqoff,
    .napi_enable = napi_enable,
    .napi_disable = napi_disable,
    .napi_alloc_skb = napi_alloc_skb,
    .napi_gro_receive = napi_gro_receive,
    .napi_complete_done = napi_complete_done,
    .netif_tx_queue_stopped = netif_tx_queue_stopped,
    .netif_tx_stop_queue = netif_tx_stop_queue,

    .eth_hw_addr_random = eth_hw_addr_random,

    .register_netdev = register_netdev,
    .netif_tx_start_all_queues = netif_tx_start_all_queues,

    .netdev_get_tx_queue = netdev_get_tx_queue,

    .__vlan_hwaccel_put_tag = __vlan_hwaccel_put_tag,

    .skb_set_hash = skb_set_hash,
    .skb_add_rx_frag = skb_add_rx_frag,
    .skb_record_rx_queue = skb_record_rx_queue,
    .skb_is_gso = skb_is_gso,
    .skb_tx_timestamp = skb_tx_timestamp,

    .copy_from_user = copy_from_user,
};

void ysif_ops_init(void)
{
    int ret;
    ret = ysif_ops_set(&ysif_linux_ops);
    if (ret < 0) {
        pr_err("YS if ops init err\n");
    }
}

