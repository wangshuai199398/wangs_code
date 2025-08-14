/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _YS_K2U_NEW_NDEV_H_
#define _YS_K2U_NEW_NDEV_H_

#include "ys_k2u_new_base.h"

#include "ys_k2u_new_tx.h"
#include "ys_k2u_new_rx.h"

#include "ys_k2u_new_qset.h"

struct ys_k2u_queuepair {
	struct ys_k2u_txq *txq;
	struct ys_k2u_txcq *txcq;
	struct ys_k2u_rxq *rxq;
	struct ys_k2u_rxcq *rxcq;
};

struct ys_k2u_ndev {
	struct ys_pdev_priv *pdev_priv;
	struct net_device *ndev;
	struct device *dev;

	struct ys_k2u_qset *qset;

	struct ys_k2u_queuebase l_qbase;
	struct ys_k2u_queuebase f_qbase;
	struct ys_k2u_queuebase p_qbase;
	struct ys_k2u_queuebase g_qbase;
	u16 real_qnum;
	u16 txq_depth;
	u16 rxq_depth;
	int dst_qset_id;

	bool is_rep;
	bool is_pfrep;
	bool is_uplink;
	bool is_sf;

	struct ys_k2u_queuepair *qps;

	struct dentry *debugfs_dir;
	struct dentry *debugfs_info_file;
	u8 rss_redirect_en;
};

static inline bool ys_k2u_ndev_is_rep(struct ys_ndev_priv *ndev_priv)
{
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	return k2u_ndev->is_rep;
}

static inline bool ys_k2u_ndev_is_pfrep(struct ys_ndev_priv *ndev_priv)
{
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	return k2u_ndev->is_pfrep;
}

static inline bool ys_k2u_ndev_is_uplink(struct ys_ndev_priv *ndev_priv)
{
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	return k2u_ndev->is_uplink;
}

static inline int ys_k2u_ndev_get_dstqsetid(struct ys_ndev_priv *ndev_priv)
{
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	return k2u_ndev->dst_qset_id;
}

static inline struct ys_k2u_queuebase
ys_k2u_ndev_get_qbase(struct ys_ndev_priv *ndev_priv, enum ys_k2u_queue_type type)
{
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	switch (type) {
	case YS_K2U_QUEUE_LOCAL:
		return k2u_ndev->l_qbase;
	case YS_K2U_QUEUE_FUNC:
		return k2u_ndev->f_qbase;
	case YS_K2U_QUEUE_PF:
		return k2u_ndev->p_qbase;
	case YS_K2U_QUEUE_GLOBAL:
		return k2u_ndev->g_qbase;
	default:
		ys_net_err("Invalid queue type %d, return local queue\n", type);
		return k2u_ndev->l_qbase;
	}
}

int ys_k2u_ndev_init(struct net_device *ndev);
void ys_k2u_ndev_uninit(struct net_device *ndev);
int ys_k2u_ndev_start(struct net_device *ndev);
void ys_k2u_ndev_stop(struct net_device *ndev);
void ys_k2u_ndev_update_stat(struct net_device *ndev);

int ys_k2u_ndev_cdev_start(struct net_device *ndev, bool start, u16 txqnum, u16 rxqnum);
int ys_k2u_ndev_cdev_qgroup_get(struct net_device *ndev, u16 qid);
int ys_k2u_ndev_cdev_qgroup_set(struct net_device *ndev, u16 qid, u16 qgroup);
int ys_k2u_ndev_cdev_qos_sync(struct net_device *ndev, u16 qid);
int ys_k2u_ndev_cdev_link_gqbase_get(struct net_device *ndev, u16 *qstart, u16 *qnum);
u16 ys_k2u_ndev_cdev_peer_qset_get(struct net_device *ndev);

int ys_k2u_ndev_create_queues(struct ys_k2u_ndev *k2u_ndev);
void ys_k2u_ndev_destroy_queues(struct ys_k2u_ndev *k2u_ndev);

#endif /* _YS_K2U_NEW_NDEV_H_ */
