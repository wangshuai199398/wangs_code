/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_TC_H_
#define __YS_TC_H_

#ifndef YS_TC_DISABLE

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/rhashtable.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include <net/flow_offload.h>
#include <net/geneve.h>
#include <net/vxlan.h>

#include "ys_debug.h"
#include "ys_platform.h"
#include "ys_doe.h"

#define YS_TC_TABLES_NUM 256

enum ys_tc_tun_type {
	YS_TC_TUNNEL_NONE,
	YS_TC_TUNNEL_VXLAN,
	YS_TC_TUNNEL_GENEVE,
	YS_TC_TUNNEL_MAX,
};

struct ys_tc_priv;

struct ys_tc_adapter_ops {
	int (*setup_tc_cls_flower)(struct ys_tc_priv *tc_priv, struct flow_cls_offload *cls_flower);
#ifdef YS_HAVE_FLOW_ACTION_OFFLOAD
	int (*setup_tc_act)(struct ys_tc_priv *tc_priv, struct flow_offload_action *fl_act);
#endif
};

struct ys_tc_priv {
	/* info */
	struct net_device *ndev;
	__u8 pf_index;
	__u8 pf_id;
	__u16 vf_id;
	__u16 qset;
	bool is_uplink;
	bool is_pfrep;
	bool is_vfrep;
	bool is_run;

	/* switchdev */
	void *switchdev;
	struct list_head switchdev_node;
	struct rcu_head rcu;

	/* table */
	struct list_head table_entry_head[YS_TC_TABLES_NUM];
	spinlock_t table_entry_slock[YS_TC_TABLES_NUM]; /* spin for table add and del*/

	/* flow */
	struct rhashtable tc_ht;
	struct rhashtable_params *tc_ht_params;

	/* block */
	struct list_head tc_indr_block_list;

	/* work */
	struct workqueue_struct *wq;
	struct delayed_work work;
	unsigned long work_interval;

	/* doe */
	struct ys_doe_ops *doe_ops;

	/* tun */
	struct notifier_block tun_nb;
	struct netdev_net_notifier tun_nn;
	struct list_head tun_list;
	spinlock_t tun_slock;	/* spin for tun_list add, del, query */

	/* hw specific tc ops */
	struct ys_tc_adapter_ops ops;
};

extern bool ys_tc_flow_enable;

static inline struct ys_tc_priv *ys_tc_get_priv(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	return (struct ys_tc_priv *)ndev_priv->tc_priv;
}

static inline void ys_tc_set_priv(struct net_device *ndev,
				  struct ys_tc_priv *tc_priv)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	ndev_priv->tc_priv = (void *)tc_priv;
}

static inline bool ys_tc_is_netdev_to_offload(struct net_device *ndev)
{
	if (netif_is_vxlan(ndev))
		return true;
	if (netif_is_geneve(ndev))
		return true;

	return false;
}

int ys_tc_setup_tc(struct net_device *ndev, enum tc_setup_type type,
		   void *type_data);

int ys_tc_tunnel_cb_init(struct ys_tc_priv *tc_priv);
void ys_tc_tunnel_cb_exit(struct ys_tc_priv *tc_priv);

int ys_tc_debug_init(int switchdev_id, bool first, struct dentry **debugfs_root);
void ys_tc_debug_exit(struct dentry *debugfs_root, bool last);

#endif

#endif
