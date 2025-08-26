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

const struct ysif_ops *ysif_get_ops(void)
{
    return READ_ONCE(g_ys_ops);
}

static struct dentry *ys_debugfs_create_dir(const char *name, struct dentry *parent)
{
    pr_info("debugfs_create_dir: name=%s\n", name);
    return debugfs_create_dir(name, parent);
}

static struct dentry *ys_debugfs_create_file(const char *name, umode_t mode, struct dentry *parent, void *data, const struct file_operations *fops)
{
    pr_info("debugfs_create_file: name=%s\n", name);
    return debugfs_create_file(name, mode, parent, data, fops);
}

static void ys_debugfs_remove(struct dentry *dentry)
{
    pr_info("debugfs_remove: name=%s\n", dentry->d_name.name);
    debugfs_remove(dentry);
}

int ysw_sysfs_create_group(struct kobject *kobj, const struct attribute_group *grp)
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

unsigned long ys_find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
    return find_first_zero_bit(addr, size);
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
    return idr_alloc(idr, ptr, start, end, gfp);
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

static void ys_spin_lock_init(spinlock_t *spin)
{
    spin_lock_init(spin);
}

void ys_spin_lock(spinlock_t *lock)
{
    spin_lock(lock);
}

void ys_spin_unlock(spinlock_t *lock)
{
    spin_unlock(lock);
}

void ys_mutex_init(struct mutex *mutex)
{
    mutex_init(mutex);
}

static void ys_rwlock_init(rwlock_t *rwlock)
{
    rwlock_init(rwlock);
}

void ys_write_lock_irqsave(rwlock_t * rwlock, unsigned long flags)
{
    write_lock_irqsave(rwlock, flags);
}

void ys_write_unlock_irqrestore(rwlock_t * rwlock, unsigned long flags)
{
    write_unlock_irqrestore(rwlock, flags);
}

void ys_blocking_init_notifier_head(struct blocking_notifier_head *nh)
{
    BLOCKING_INIT_NOTIFIER_HEAD(nh);
}

void ys_atomic_init_notifier_head(struct atomic_notifier_head *nh)
{
    ATOMIC_INIT_NOTIFIER_HEAD(nh);
}

static void ys_init_completion(struct completion *comp)
{
    init_completion(comp);
}

void ys_timer_setup(struct timer_list *timer, void (*func)(struct timer_list *), unsigned int flags)
{
    timer_setup(timer, func, flags);
}

int ys_mod_timer(struct timer_list *timer, unsigned long expires)
{
    return mod_timer(timer, expires);
}

static int ys_auxiliary_driver_register(struct auxiliary_driver *drv)
{
    pr_info("auxiliary_driver_register: name=%s\n", drv->name);
    return auxiliary_driver_register(drv);
}

void ys_auxiliary_driver_unregister(struct auxiliary_driver *drv)
{
    auxiliary_driver_unregister(drv);
}
int ys_auxiliary_device_init(struct auxiliary_device *auxdev)
{
    return auxiliary_device_init(auxdev);
}

int ys_auxiliary_device_add(struct auxiliary_device *auxdev)
{
    return auxiliary_device_add(auxdev);
}

void ys_auxiliary_device_uninit(struct auxiliary_device *auxdev)
{
    auxiliary_device_uninit(auxdev);
}

int ys_misc_register(struct miscdevice *misc)
{
    pr_info("misc_register: name=%s\n", misc->name);
    return misc_register(misc);
}

struct devlink *ysw_devlink_alloc(const struct devlink_ops *ops, size_t priv_size, struct device *dev)
{
    pr_info("devlink_alloc: dev name=%s dev_driver name: %s \n", dev_name(dev), dev->driver->name);
    return devlink_alloc(ops, priv_size, dev);
}

void *ys_devlink_priv(struct devlink *devlink)
{
    return devlink_priv(devlink);
}

struct devlink *ys_priv_to_devlink(void *priv)
{
    return priv_to_devlink(priv);
}

void ys_devlink_register(struct devlink *devlink)
{
    devlink_register(devlink);
}

int ys_devlink_params_register(struct devlink *devlink, const struct devlink_param *params, size_t params_count)
{
    return devlink_params_register(devlink, params, params_count);
}

int ys_devlink_param_driverinit_value_set(struct devlink *devlink, u32 param_id, union devlink_param_value init_val)
{
    return devlink_param_driverinit_value_set(devlink, param_id, init_val);
}

struct page *ys_dev_alloc_pages(unsigned int order)
{
    return dev_alloc_pages(order);
}

void ys_dev_consume_skb_any(struct sk_buff *skb)
{
    dev_consume_skb_any(skb);
}

void ys_dev_kfree_skb_any(struct sk_buff *skb)
{
    dev_kfree_skb_any(skb);
}

static int ys_pci_register_driver(struct pci_driver *pdrv)
{
    pr_info("pci_register_driver: name=%s\n", pdrv->name);
    return pci_register_driver(pdrv);
}

void ys_pci_set_drvdata(struct pci_dev *pdev, void *data)
{
    pci_set_drvdata(pdev, data);
}

int ys_pci_enable_device(struct pci_dev *dev)
{
    pr_info("pci_enable_device: name=%s\n", dev->driver->name);
    return pci_enable_device(dev);
}

void ys_pci_set_master(struct pci_dev *dev)
{
    pr_info("pci_set_master: name=%s\n", dev->driver->name);
    pci_set_master(dev);
}

int ys_pci_request_regions(struct pci_dev *dev, const char *name)
{
    pr_info("pci_request_regions: name=%s\n", name);
    return pci_request_regions(dev, name);
}

void *ys_pci_get_drvdata(struct pci_dev *pdev)
{
    return pci_get_drvdata(pdev);
}

int ys_pci_msix_vec_count(struct pci_dev *dev)
{
    pr_info("pci_msix_vec_count: name=%s\n", dev->driver->name);
    return pci_msix_vec_count(dev);
}

int ys_pci_msi_vec_count(struct pci_dev *dev)
{
    pr_info("pci_msi_vec_count: name=%s\n", dev->driver->name);
    return pci_msi_vec_count(dev);
}

int ys_pci_alloc_irq_vectors(struct pci_dev *dev, unsigned int min_vecs, unsigned int max_vecs, unsigned int flags)
{
    pr_info("pci_alloc_irq_vectors: name=%s min_vecs=%u max_vecs=%u\n", dev->driver->name, min_vecs, max_vecs);
    return pci_alloc_irq_vectors(dev, min_vecs, max_vecs, flags);
}

int ys_pci_irq_vector(struct pci_dev *dev, unsigned int nr)
{
    pr_info("pci_irq_vector: name=%s nr=%u pci_irq_vector: %d\n", dev->driver->name, nr, pci_irq_vector(dev, nr));
    return pci_irq_vector(dev, nr);
}

static void *ys_ioremap(phys_addr_t offset, size_t size)
{
    return ioremap(offset, size);
}

int ys_dma_set_mask(struct device *dev, u64 mask)
{
    pr_info("dma_set_mask: dev name=%s mask: %llu\n", dev_name(dev), mask);
    return dma_set_mask(dev, mask);
}

int ys_dma_set_coherent_mask(struct device *dev, u64 mask)
{
    pr_info("dma_set_coherent_mask: dev name=%s mask: %llu\n", dev_name(dev), mask);
    return dma_set_coherent_mask(dev, mask);
}

int ys_dma_set_max_seg_size(struct device *dev, unsigned int size)
{
    pr_info("dma_set_max_seg_size: dev name=%s mask: %u\n", dev_name(dev), size);
    return dma_set_max_seg_size(dev, size);
}
    
void *ys_dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle, gfp_t gfp)
{
    return dma_alloc_coherent(dev, size, dma_handle, gfp);
}

static dma_addr_t ys_dma_map_single(struct device *dev, void *ptr, size_t size, enum dma_data_direction dir)
{
    return dma_map_single(dev, ptr, size, dir);
}

int ys_dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
{
    return dma_mapping_error(dev, dma_addr);
}

void ys_dma_unmap_single(struct device *dev, dma_addr_t addr, size_t size, enum dma_data_direction dir)
{
    dma_unmap_single(dev, addr, size, dir);
}

void ys_dma_free_coherent(struct device *dev, size_t size, void *cpu_addr, dma_addr_t dma_handle)
{
    dma_free_coherent(dev, size, cpu_addr, dma_handle);
}

dma_addr_t ys_dma_map_page(struct device *dev, struct page *page, size_t offset, size_t size, enum dma_data_direction dir)
{
    return dma_map_page(dev, page, offset, size, dir);
}

void ys_dma_upmap_page(struct device *dev, dma_addr_t addr, size_t size, enum dma_data_direction dir)
{
    dma_unmap_page(dev, addr, size, dir);
}


static struct net_device *ys_alloc_etherdev_mq(int sizeof_priv, unsigned int count)
{
    return alloc_etherdev_mq(sizeof_priv, count);
}


int ys_netif_set_real_num_tx_queues(struct net_device *dev, unsigned int txq)
{
    return netif_set_real_num_tx_queues(dev, txq);
}

int ys_netif_set_real_num_rx_queues(struct net_device *dev, unsigned int rxq)
{
    return netif_set_real_num_rx_queues(dev, rxq);
}

void ys_netif_device_attach(struct net_device *dev)
{
    netif_device_attach(dev);
}

void ys_netif_tx_schedule_all(struct net_device *dev)
{
    netif_tx_schedule_all(dev);
}

void ys_netif_carrier_on(struct net_device *dev)
{
    netif_carrier_on(dev);
}

void ys_netif_carrier_off(struct net_device *dev)
{
    netif_carrier_off(dev);
}

void ys_netif_tx_disable(struct net_device *dev)
{
    netif_tx_disable(dev);
}

static void ys_netif_napi_add(struct net_device *dev, struct napi_struct *napi, int (*poll)(struct napi_struct *, int))
{
    netif_napi_add(dev, napi, poll);
}


void ys_netif_tx_start_all_queues(struct net_device *dev)
{
    netif_tx_start_all_queues(dev);
}

void ys_netif_napi_del(struct napi_struct *napi)
{
    netif_napi_del(napi);
}

bool ys_netif_tx_queue_stopped(const struct netdev_queue *dev_queue)
{
    return netif_tx_queue_stopped(dev_queue);
}

void ys_netif_tx_wake_queue(struct netdev_queue *dev_queue)
{
    netif_tx_wake_queue(dev_queue);
}

void ys_netif_tx_stop_queue(struct netdev_queue *dev_queue)
{
    netif_tx_stop_queue(dev_queue);
}


struct netdev_queue *ys_netdev_get_tx_queue(const struct net_device *dev, unsigned int index)
{
    return netdev_get_tx_queue(dev, index);
}

bool ys_netdev_xmit_more(void)
{
    return netdev_xmit_more();
}


bool ys_napi_schedule_prep(struct napi_struct *n)
{
    return napi_schedule_prep(n);
}

void ys__napi_schedule_irqoff(struct napi_struct *n)
{
    __napi_schedule_irqoff(n);
}

bool ys_napi_schedule(struct napi_struct *n)
{
    return napi_schedule(n);
}

void ys_napi_enable(struct napi_struct *n)
{
    napi_enable(n);
}

void ys_napi_disable(struct napi_struct *n)
{
    napi_disable(n);
}

struct sk_buff *ys_napi_alloc_skb(struct napi_struct *napi, unsigned int length)
{
    return napi_alloc_skb(napi, length);
}

gro_result_t ys_napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
    return napi_gro_receive(napi, skb);
}

bool ys_napi_complete_done(struct napi_struct *n, int work_done)
{
    return napi_complete_done(n, work_done);
}
    

void ys_eth_hw_addr_random(struct net_device *dev)
{
    eth_hw_addr_random(dev);
}

int ys_register_netdev(struct net_device *dev)
{
    return register_netdev(dev);
}
    
void ys__vlan_hwaccel_put_tag(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci)
{
    __vlan_hwaccel_put_tag(skb, vlan_proto, vlan_tci);
}

void ys_skb_set_hash(struct sk_buff *skb, __u32 hash, enum pkt_hash_types type)
{
    skb_set_hash(skb, hash, type);
}

void ys_skb_add_rx_frag(struct sk_buff *skb, int i, struct page *page, int off, int size, unsigned int truesize)
{
    skb_add_rx_frag(skb, i, page, off, size, truesize);    
}

void ys_skb_record_rx_queue(struct sk_buff *skb, u16 rx_queue)
{
    skb_record_rx_queue(skb, rx_queue);
}

bool ys_skb_is_gso(const struct sk_buff *skb)
{
    return skb_is_gso(skb);
}

void ys_skb_tx_timestamp(struct sk_buff *skb)
{
    skb_tx_timestamp(skb);
}
    
unsigned long ys_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    return copy_from_user(to, from, n);
}

static const struct ysif_ops ysif_linux_ops = {
    .debugfs_create_dir = ys_debugfs_create_dir,
    .debugfs_create_file = ys_debugfs_create_file,
    .debugfs_remove = ys_debugfs_remove,

    .sysfs_create_group = ysw_sysfs_create_group,

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
    .spin_lock = ys_spin_lock,
    .spin_unlock = ys_spin_unlock,

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
    .mod_timer = ys_mod_timer,

    .yauxiliary_driver_register   = ys_auxiliary_driver_register,
    .auxiliary_driver_unregister = ys_auxiliary_driver_unregister,
    .auxiliary_device_init = ys_auxiliary_device_init,
    .yauxiliary_device_add = ys_auxiliary_device_add,
    .auxiliary_device_uninit = ys_auxiliary_device_uninit,

    .ypci_register_driver = ys_pci_register_driver,

    .misc_register = ys_misc_register,

    .devlink_alloc = ysw_devlink_alloc,
    .devlink_priv = ys_devlink_priv,
    .priv_to_devlink = ys_priv_to_devlink,
    .devlink_register = ys_devlink_register,
    .devlink_params_register = ys_devlink_params_register,
    .devlink_param_driverinit_value_set = ys_devlink_param_driverinit_value_set,
    .dev_alloc_pages = ys_dev_alloc_pages,
    .dev_consume_skb_any = ys_dev_consume_skb_any,
    .dev_kfree_skb_any = ys_dev_kfree_skb_any,

    .pci_set_drvdata = ys_pci_set_drvdata,
    .pci_enable_device = ys_pci_enable_device,
    .pci_set_master = ys_pci_set_master,
    .pci_request_regions = ys_pci_request_regions,
    .pci_get_drvdata = ys_pci_get_drvdata,
    .pci_msix_vec_count = ys_pci_msix_vec_count,
    .pci_msi_vec_count = ys_pci_msi_vec_count,
    .pci_alloc_irq_vectors = ys_pci_alloc_irq_vectors,
    .pci_irq_vector = ys_pci_irq_vector,

    .yioremap = ys_ioremap,

    .dma_set_mask = ys_dma_set_mask,
    .dma_set_coherent_mask = ys_dma_set_coherent_mask,
    .dma_set_max_seg_size = ys_dma_set_max_seg_size,
    .dma_alloc_coherent = ys_dma_alloc_coherent,
    .ydma_map_single = ys_dma_map_single,
    .dma_mapping_error = ys_dma_mapping_error,
    .ydma_unmap_single = ys_dma_unmap_single,
    .dma_free_coherent = ys_dma_free_coherent,
    .ydma_map_page = ys_dma_map_page,
    .ydma_unmap_page = ys_dma_upmap_page,

    .yalloc_etherdev_mq = ys_alloc_etherdev_mq,

    .netif_set_real_num_tx_queues = ys_netif_set_real_num_tx_queues,
    .netif_set_real_num_rx_queues = ys_netif_set_real_num_rx_queues,
    .netif_device_attach = ys_netif_device_attach,
    .netif_tx_schedule_all = ys_netif_tx_schedule_all,
    .netif_carrier_off = ys_netif_carrier_off,
    .netif_carrier_on = ys_netif_carrier_on,
    .netif_tx_disable = ys_netif_tx_disable,
    .ynetif_napi_add = ys_netif_napi_add,
    .netif_napi_del = ys_netif_napi_del,
    .netif_tx_wake_queue = ys_netif_tx_wake_queue,
    .netdev_xmit_more = ys_netdev_xmit_more,

    
    .napi_schedule = ys_napi_schedule,
    .napi_schedule_prep = ys_napi_schedule_prep,
    .__napi_schedule_irqoff = ys__napi_schedule_irqoff,
    .napi_enable = ys_napi_enable,
    .napi_disable = ys_napi_disable,
    .napi_alloc_skb = ys_napi_alloc_skb,
    .napi_gro_receive = ys_napi_gro_receive,
    .napi_complete_done = ys_napi_complete_done,
    .netif_tx_queue_stopped = ys_netif_tx_queue_stopped,
    .netif_tx_stop_queue = ys_netif_tx_stop_queue,

    .eth_hw_addr_random = ys_eth_hw_addr_random,

    .register_netdev = ys_register_netdev,
    .netif_tx_start_all_queues = ys_netif_tx_start_all_queues,

    .netdev_get_tx_queue = ys_netdev_get_tx_queue,

    .__vlan_hwaccel_put_tag = ys__vlan_hwaccel_put_tag,

    .skb_set_hash = ys_skb_set_hash,
    .skb_add_rx_frag = ys_skb_add_rx_frag,
    .skb_record_rx_queue = ys_skb_record_rx_queue,
    .skb_is_gso = ys_skb_is_gso,
    .skb_tx_timestamp = ys_skb_tx_timestamp,

    .copy_from_user = ys_copy_from_user,
};

void ysif_ops_init(void)
{
    int ret;
    ret = ysif_ops_set(&ysif_linux_ops);
    if (ret < 0) {
        pr_err("YS if ops init err\n");
    }
}

