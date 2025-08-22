// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_new_core.h"
#include "ys_k2u_new_hw.h"
#include "ys_k2u_new_func.h"
#include "ys_k2u_debugfs.h"
#include "ys_k2u_new_qset.h"
#include "ys_k2u_new_ndev.h"
#include "ys_k2u_new_ethtool.h"
#include "ys_k2u_hqos.h"
#include "ys_k2u_rss_redirect.h"
#include "ys_k2u_message.h"

#include "../tc/ys_k2u_tc_core.h"
#include "../../platform/ysif_linux.h"

/* debug */
static void *ndev_debugfs_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;
	return NULL;
}

static void *ndev_debugfs_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void ndev_debugfs_stop(struct seq_file *seq, void *v)
{
}

static int ndev_debugfs_show(struct seq_file *seq, void *v)
{
	struct ys_k2u_ndev *k2u_ndev = seq->private;

	if (v != SEQ_START_TOKEN)
		return 0;

	seq_printf(seq, "\t%-16s : %-16s\n", "netdev", k2u_ndev->ndev->name);
	seq_printf(seq, "\t%-16s : %-16d\n", "qset id", k2u_ndev->qset->id);
	seq_printf(seq, "\t%-16s : %-16d\n", "dst qset id", k2u_ndev->dst_qset_id);
	seq_printf(seq, "\t%-16s : %-16d\n", "l queue start", k2u_ndev->l_qbase.start);
	seq_printf(seq, "\t%-16s : %-16d\n", "l queue num", k2u_ndev->l_qbase.num);
	seq_printf(seq, "\t%-16s : %-16d\n", "f queue start", k2u_ndev->f_qbase.start);
	seq_printf(seq, "\t%-16s : %-16d\n", "f queue num", k2u_ndev->f_qbase.num);
	seq_printf(seq, "\t%-16s : %-16d\n", "p queue start", k2u_ndev->p_qbase.start);
	seq_printf(seq, "\t%-16s : %-16d\n", "p queue num", k2u_ndev->p_qbase.num);
	seq_printf(seq, "\t%-16s : %-16d\n", "g queue start", k2u_ndev->g_qbase.start);
	seq_printf(seq, "\t%-16s : %-16d\n", "g queue num", k2u_ndev->g_qbase.num);
	seq_printf(seq, "\t%-16s : %-16d\n", "real_qnum", k2u_ndev->real_qnum);
	seq_printf(seq, "\t%-16s : %-16d\n", "txq_depth", k2u_ndev->txq_depth);
	seq_printf(seq, "\t%-16s : %-16d\n", "rxq_depth", k2u_ndev->rxq_depth);
	seq_printf(seq, "\t%-16s : %-16d\n", "is_rep", k2u_ndev->is_rep);
	seq_printf(seq, "\t%-16s : %-16d\n", "is_pfrep", k2u_ndev->is_pfrep);
	seq_printf(seq, "\t%-16s : %-16d\n", "is_uplink", k2u_ndev->is_uplink);
	seq_printf(seq, "\t%-16s : %-16d\n", "is_sf", k2u_ndev->is_sf);
	seq_printf(seq, "\t%-16s : %-16d\n", "gso_max_segs", k2u_ndev->ndev->gso_max_segs);
	seq_printf(seq, "\t%-16s : %-16d\n", "gso_max_size", k2u_ndev->ndev->gso_max_size);

	return 0;
}

static const struct seq_operations ndev_debugfs_sops = {
	.start = ndev_debugfs_start,
	.next = ndev_debugfs_next,
	.stop = ndev_debugfs_stop,
	.show = ndev_debugfs_show,
};

DEFINE_SEQ_ATTRIBUTE(ndev_debugfs);

int ys_k2u_ndev_create_queues(struct ys_k2u_ndev *k2u_ndev)
{
	u16 tx_qnum = k2u_ndev->ndev->real_num_tx_queues;
	u16 rx_qnum = k2u_ndev->ndev->real_num_rx_queues;
	u16 total_qnum = max_t(u16, tx_qnum, rx_qnum);
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);
	int ret, i;
	u32 depth;

	k2u_ndev->qps = kcalloc(total_qnum, sizeof(*k2u_ndev->qps), GFP_KERNEL | __GFP_ZERO);
	if (!k2u_ndev->qps)
		return -ENOMEM;

	for (i = 0; i < total_qnum; i++) {
		if (i < tx_qnum) {
			depth = k2u_ndev->txq_depth;
			depth = roundup_pow_of_two(depth);
			ret = ys_k2u_create_txq(k2u_ndev, i, depth);
			if (ret) {
				ys_net_err("k2u_ndev create txq %d failed", i);
				goto failed;
			}
		}

		if (i < rx_qnum) {
			depth = k2u_ndev->rxq_depth;
			depth = roundup_pow_of_two(depth);
			ret = ys_k2u_create_rxq(k2u_ndev, i, depth);
			if (ret) {
				ys_net_err("k2u_ndev create rxq %d failed", i);
				goto failed;
			}
		}
	}

	return 0;

failed:
	ys_k2u_ndev_destroy_queues(k2u_ndev);
	return ret;
}

void ys_k2u_ndev_destroy_queues(struct ys_k2u_ndev *k2u_ndev)
{
	u16 tx_qnum = k2u_ndev->ndev->real_num_tx_queues;
	u16 rx_qnum = k2u_ndev->ndev->real_num_rx_queues;
	u16 total_qnum = max_t(u16, tx_qnum, rx_qnum);
	struct ys_k2u_queuepair *qp;
	int i;

	if (!k2u_ndev->qps)
		return;

	for (i = 0; i < total_qnum; i++) {
		qp = &k2u_ndev->qps[i];
		if (qp->txq)
			ys_k2u_destroy_txq(qp->txq);
		if (qp->rxq)
			ys_k2u_destroy_rxq(qp->rxq);
	}

	kfree(k2u_ndev->qps);
	k2u_ndev->qps = NULL;
}

static netdev_features_t ys_k2u_features_fix(struct net_device *ndev, netdev_features_t features)
{
	if (features & NETIF_F_GSO_PARTIAL) {
		ndev->gso_partial_features = NETIF_F_GSO_ENCAP_ALL;
		ndev->gso_partial_features |= NETIF_F_GSO_UDP_L4;
	}

	if (!(features & NETIF_F_GSO_PARTIAL))
		ndev->gso_partial_features = 0;

	if ((features & NETIF_F_GSO_UDP_L4) && !(features & NETIF_F_HW_CSUM))
		features &= ~NETIF_F_GSO_UDP_L4;

	return features;
}

static int k2u_ndev_get_dstqsetid(struct ys_k2u_ndev *k2u_ndev, struct ys_adev *adev)
{
	struct net_device *dst_ndev;
	struct ys_ndev_priv *dst_ndev_priv;
	u16 vfid;
	struct ys_vf_info *vf_info;

	if (adev->adev_type != AUX_TYPE_REP)
		return -1;

	if (adev->idx == YS_K2U_ID_NDEV_UPLINK)
		return YS_K2U_ID_MAC_QSETID(k2u_ndev->pdev_priv->pf_id);

	if (adev->idx == YS_K2U_ID_NDEV_PFREP) {
		dst_ndev = ys_aux_match_eth(k2u_ndev->pdev_priv->pdev, 0);
		if (!dst_ndev)
			return -1;
		dst_ndev_priv = netdev_priv(dst_ndev);
		return dst_ndev_priv->qi.qset;
	}

	vfid = YS_K2U_ID_NDEV_VFREP_TO_ID(adev->idx);
	vf_info = &k2u_ndev->pdev_priv->sriov_info.vfinfo[vfid];

	return vf_info->qset;
}

static void
k2u_ndev_get_name(struct ys_pdev_priv *pdev_priv, struct ys_adev *adev, char *name, size_t size)
{
	if (adev->adev_type == AUX_TYPE_ETH) {
		if (pdev_priv->vf_id)
			snprintf(name, size, "pf%dvf%d", pdev_priv->pf_id, (pdev_priv->vf_id - 1));
		else
			snprintf(name, size, "pf%d", pdev_priv->pf_id);
	} else if (adev->adev_type == AUX_TYPE_REP) {
		if (adev->idx == YS_K2U_ID_NDEV_UPLINK)
			snprintf(name, size, "pf%duplink", pdev_priv->pf_id);
		else if (adev->idx == YS_K2U_ID_NDEV_PFREP)
			snprintf(name, size, "pf%drep", pdev_priv->pf_id);
		else
			snprintf(name, size, "pf%dvf%drep",
				 pdev_priv->pf_id, YS_K2U_ID_NDEV_VFREP_TO_ID(adev->idx));
	} else if (adev->adev_type == AUX_TYPE_SF) {
		snprintf(name, size, "sf%d", adev->idx);
	} else {
		snprintf(name, size, "unknown%d", adev->idx);
	}
}

int ys_k2u_ndev_init(struct net_device *ndev)
{
	const struct ysif_ops *ops = ysif_get_ops();
	int ret = 0;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_k2u_ndev *k2u_ndev;
	struct ys_adev *adev;
	struct ys_k2u_new_func *func;
	char name[32];
	struct dentry *entry;
	struct ys_k2u_queuebase qbase;

	k2u_ndev = kzalloc(sizeof(*k2u_ndev), GFP_KERNEL);
	if (!k2u_ndev)
		return -ENOMEM;

	ndev_priv->adp_priv = k2u_ndev;
	k2u_ndev->pdev_priv = pdev_priv;
	k2u_ndev->ndev = ndev;
	k2u_ndev->dev = &pdev_priv->pdev->dev;

	k2u_ndev->qset = ys_k2u_qset_alloc(pdev_priv, ndev_priv);
	if (!k2u_ndev->qset) {
		ys_net_err("k2u_ndev qset alloc failed");
		ret = -ENOMEM;
		goto qset_failed;
	}
	ndev_priv->qi.qset = k2u_ndev->qset->id;

	adev = ys_aux_get_adev(ndev_priv->pdev, ndev_priv->adev_type, ndev);
	if (IS_ERR_OR_NULL(adev)) {
		ys_net_err("k2u_ndev adev get failed");
		ret = -ENODEV;
		goto get_adev_failed;
	}

	/* ethtool -k offload default value */
	ndev->features |= NETIF_F_HIGHDMA;
	ndev->features |= NETIF_F_SG;
	ndev->features |= NETIF_F_GSO;
	ndev->features |= NETIF_F_GRO;
	ndev->features |= NETIF_F_GSO_ENCAP_ALL;
	ndev->features |= NETIF_F_HW_CSUM;
	ndev->features |= NETIF_F_RXCSUM;
	ndev->features |= NETIF_F_TSO;
	ndev->features |= NETIF_F_TSO6;
	ndev->features |= NETIF_F_RXHASH;
	ndev->features |= NETIF_F_GSO_UDP_L4;

	/* ethtool -k offload option */
	ndev->hw_features |= NETIF_F_SG;
	ndev->hw_features |= NETIF_F_HW_CSUM;
	ndev->hw_features |= NETIF_F_RXCSUM;
	ndev->hw_features |= NETIF_F_GSO;
	ndev->hw_features |= NETIF_F_GRO;
	ndev->hw_features |= NETIF_F_RXALL;
	ndev->hw_features |= NETIF_F_RXHASH;
	ndev->hw_features |= NETIF_F_TSO;
	ndev->hw_features |= NETIF_F_TSO6;
	ndev->hw_features |= NETIF_F_GSO_ENCAP_ALL;
	ndev->hw_features |= NETIF_F_TSO_MANGLEID;
	ndev->hw_features |= NETIF_F_GSO_UDP_L4;
	ndev->hw_features |= NETIF_F_GSO_PARTIAL;

	/* vlan features */
	ndev->vlan_features = ndev->hw_features;

	/* enc features */
	ndev->hw_enc_features |= NETIF_F_GSO_ENCAP_ALL;
	ndev->hw_enc_features |= NETIF_F_TSO_MANGLEID;
	ndev->hw_enc_features |= NETIF_F_SG;
	ndev->hw_enc_features |= NETIF_F_HW_CSUM;
	ndev->hw_enc_features |= NETIF_F_TSO;
	ndev->hw_enc_features |= NETIF_F_TSO6;
	ndev->hw_enc_features |= NETIF_F_GSO_UDP_L4;

	if (!pdev_priv->nic_type->is_vf && (ndev_priv->adev_type & AUX_TYPE_ETH))
		ndev_priv->ys_ndev_hw->ys_set_port_vf_rate = ys_k2u_set_vf_rate;

	ndev_priv->ys_ndev_hw->ys_features_fix = ys_k2u_features_fix;

	if (!IS_ERR_OR_NULL(ndev_priv->ys_eth_hw))
		YS_K2U_ETHTOOL_FUNC(ndev_priv->ys_eth_hw);

	adev->state_statistics.flag = ndev->dev_port;
	adev->state_statistics.et_get_stats = ys_k2u_et_get_stats;
	adev->state_statistics.et_get_stats_count = ys_k2u_et_get_stats_count;
	adev->state_statistics.et_get_stats_strings = ys_k2u_et_get_stats_strings;

	if (adev->adev_type == AUX_TYPE_REP) {
		k2u_ndev->is_rep = true;
		if (adev->idx == YS_K2U_ID_NDEV_PFREP)
			k2u_ndev->is_pfrep = true;
		else if (adev->idx == YS_K2U_ID_NDEV_UPLINK)
			k2u_ndev->is_uplink = true;
	} else if (adev->adev_type == AUX_TYPE_SF) {
		k2u_ndev->is_sf = true;
	}

	k2u_ndev->dst_qset_id = k2u_ndev_get_dstqsetid(k2u_ndev, adev);

	/* vf rate limit */
	/* .... */

	/* debugfs */
	func = ys_k2u_func_get_priv(pdev_priv);
	if (func->debugfs_root) {
		k2u_ndev_get_name(pdev_priv, adev, name, sizeof(name));

		k2u_ndev->debugfs_dir = ops->debugfs_create_dir(name, func->debugfs_root);
		if (!k2u_ndev->debugfs_dir) {
			ys_net_err("k2u_ndev debugfs create dir failed");
			ret = -ENOMEM;
			goto debugfs_failed;
		}

		entry = ops->debugfs_create_file("info", 0400, k2u_ndev->debugfs_dir, k2u_ndev,
					    &ndev_debugfs_fops);
		if (!entry) {
			ys_net_err("k2u_ndev info debugfs create file failed");
			ret = -ENOMEM;
			goto debugfs_file_failed;
		}
		k2u_ndev->debugfs_info_file = entry;
	}

	k2u_ndev->l_qbase.start = 0;
	k2u_ndev->l_qbase.num = ndev_priv->qi.ndev_qnum;
	if (k2u_ndev->is_rep)
		k2u_ndev->f_qbase.start = ndev_priv->qi.qbase;
	else
		k2u_ndev->f_qbase.start = 0;
	k2u_ndev->f_qbase.num = ndev_priv->qi.ndev_qnum;
	k2u_ndev->p_qbase.start = ndev_priv->qi.qbase;
	k2u_ndev->p_qbase.num = ndev_priv->qi.ndev_qnum;

	qbase = ys_k2u_func_get_qbase(pdev_priv, YS_K2U_QUEUE_GLOBAL);

	k2u_ndev->g_qbase.start = qbase.start;
	k2u_ndev->g_qbase.num = k2u_ndev->l_qbase.num;
	if (k2u_ndev->is_rep)
		k2u_ndev->g_qbase.start += k2u_ndev->f_qbase.start;

	k2u_ndev->real_qnum = k2u_ndev->l_qbase.num;
	k2u_ndev->txq_depth = YS_K2U_N_NDEV_DEFAULT_DEPTH;
	k2u_ndev->rxq_depth = YS_K2U_N_NDEV_DEFAULT_DEPTH;

	ops->netif_set_real_num_tx_queues(ndev, k2u_ndev->real_qnum);
	ops->netif_set_real_num_rx_queues(ndev, k2u_ndev->real_qnum);

	ndev->gso_max_size = YS_K2U_N_TSO_MAXSIZE;
	ndev->gso_max_segs = min_t(u16, YS_K2U_N_TSO_MAXSEGS, (k2u_ndev->txq_depth >> 2));

	ret = ys_k2u_ndev_create_queues(k2u_ndev);
	if (ret) {
		ys_net_err("k2u_ndev create queues failed");
		goto queues_failed;
	}

	adev->qi.qbase = k2u_ndev->f_qbase.start;
	adev->qi.ndev_qnum = k2u_ndev->f_qbase.num;
	adev->qi.qset = ndev_priv->qi.qset;

	/* mbox */
	ret = ys_k2u_message_init(ndev_priv);
	if (ret) {
		ys_net_err("ys_k2u_message_init failed\n");
		goto message_failed;
	}

	/* tc */
	if (ndev_priv->adev_type == AUX_TYPE_REP) {
		ret = ys_tc_init(ndev, pdev_priv->pdev->bus->number, pdev_priv->pf_id, 0);
		if (ret)
			ys_dev_err("ystc init fail");
	}
	ys_k2u_rss_init(ndev);

	return 0;

message_failed:
	ys_k2u_ndev_destroy_queues(k2u_ndev);
queues_failed:
	debugfs_remove(k2u_ndev->debugfs_info_file);
debugfs_file_failed:
	debugfs_remove(k2u_ndev->debugfs_dir);
debugfs_failed:
get_adev_failed:
	ys_k2u_qset_free(k2u_ndev->qset);
qset_failed:
	kfree(k2u_ndev);
	return ret;
}

void ys_k2u_ndev_uninit(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	ys_tc_exit(ndev);
	ys_k2u_message_uninit(ndev_priv);
	ys_k2u_ndev_destroy_queues(k2u_ndev);
	debugfs_remove(k2u_ndev->debugfs_info_file);
	debugfs_remove(k2u_ndev->debugfs_dir);
	ys_k2u_qset_free(k2u_ndev->qset);
	ndev_priv->adp_priv = NULL;
	kfree(k2u_ndev);
}

int ys_k2u_ndev_start(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_k2u_queuepair *qp;
	u16 tx_qnum = k2u_ndev->ndev->real_num_tx_queues;
	u16 rx_qnum = k2u_ndev->ndev->real_num_rx_queues;
	u16 total_qnum = max_t(u16, tx_qnum, rx_qnum);
	int i;
	int ret;

	if (!k2u_ndev->qps)
		return -ENODEV;

	ret = ys_k2u_qset_start(k2u_ndev->qset, tx_qnum, rx_qnum);
	if (ret) {
		ys_net_err("k2u_ndev qset start failed");
		return ret;
	}

	for (i = 0; i < total_qnum; i++) {
		qp = &k2u_ndev->qps[i];

		if (i < rx_qnum)
			ys_k2u_activate_rxq(qp->rxq);

		if (i < tx_qnum)
			ys_k2u_activate_txq(qp->txq);
	}

	return ret;
}

void ys_k2u_ndev_stop(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_k2u_queuepair *qp;
	u16 tx_qnum = k2u_ndev->ndev->real_num_tx_queues;
	u16 rx_qnum = k2u_ndev->ndev->real_num_rx_queues;
	u16 total_qnum = max_t(u16, tx_qnum, rx_qnum);
	int i;

	for (i = 0; i < total_qnum; i++) {
		qp = &k2u_ndev->qps[i];

		if (i < tx_qnum)
			ys_k2u_deactivate_txq(qp->txq);

		if (i < rx_qnum)
			ys_k2u_deactivate_rxq(qp->rxq);
	}

	for (i = 0; i < total_qnum; i++) {
		qp = &k2u_ndev->qps[i];

		if (i < tx_qnum)
			ys_k2u_clean_txq(qp->txq);

		if (i < rx_qnum)
			ys_k2u_clean_rxq(qp->rxq);
	}

	ys_k2u_qset_stop(k2u_ndev->qset);
}

void ys_k2u_ndev_update_stat(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	struct ys_k2u_txq *txq;
	struct ys_k2u_rxcq *rxcq;

	u64 packets, bytes, errors, drops;
	int i;

	packets = 0;
	bytes = 0;
	errors = 0;
	drops = 0;
	for (i = 0; i < ndev->real_num_tx_queues; i++) {
		txq = k2u_ndev->qps[i].txq;

		if (txq) {
			packets += READ_ONCE(txq->stats_base.packets);
			bytes += READ_ONCE(txq->stats_base.bytes);
			errors += READ_ONCE(txq->stats_base.errors);
			drops += READ_ONCE(txq->stats_base.drops);
		}
	}
	ndev->stats.tx_packets = packets;
	ndev->stats.tx_bytes = bytes;
	ndev->stats.tx_errors = errors;
	ndev->stats.tx_dropped = drops;

	packets = 0;
	bytes = 0;
	errors = 0;
	drops = 0;
	for (i = 0; i < ndev->real_num_rx_queues; i++) {
		rxcq = k2u_ndev->qps[i].rxcq;

		if (rxcq) {
			packets += READ_ONCE(rxcq->stats_base.packets);
			bytes += READ_ONCE(rxcq->stats_base.bytes);
			errors += READ_ONCE(rxcq->stats_base.errors);
			drops += READ_ONCE(rxcq->stats_base.drops);
		}
	}

	ndev->stats.rx_packets = packets;
	ndev->stats.rx_bytes = bytes;
	ndev->stats.rx_errors = errors;
	ndev->stats.rx_dropped = drops;
}

int ys_k2u_ndev_cdev_start(struct net_device *ndev, bool start, u16 txqnum, u16 rxqnum)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	if (start) {
		ys_k2u_rss_redirect_table_init(ndev, rxqnum);
		return ys_k2u_qset_start(k2u_ndev->qset, txqnum, rxqnum);
	}

	ys_k2u_qset_stop(k2u_ndev->qset);
	/* restore rss to default */
	ys_k2u_rss_redirect_table_init(ndev, (u16)ndev->real_num_rx_queues);
	return 0;
}

int ys_k2u_ndev_cdev_qgroup_get(struct net_device *ndev, u16 qid)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_k2u_txq *txq;

	if (qid >= ndev->real_num_tx_queues)
		return -EINVAL;

	if (!k2u_ndev->qps || !k2u_ndev->qps[qid].txq)
		return -ENODEV;

	txq = k2u_ndev->qps[qid].txq;
	return txq->qgroup;
}

int ys_k2u_ndev_cdev_qgroup_set(struct net_device *ndev, u16 qid, u16 qgroup)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_k2u_txq *txq;

	if (qid >= ndev->real_num_tx_queues)
		return -EINVAL;

	if (qgroup >= YS_K2U_N_MAX_QGROUP)
		return -EINVAL;

	if (!k2u_ndev->qps || !k2u_ndev->qps[qid].txq)
		return -ENODEV;

	txq = k2u_ndev->qps[qid].txq;

	txq->qgroup_request = qgroup;

	return 0;
}

int ys_k2u_ndev_cdev_qos_sync(struct net_device *ndev, u16 qid)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
//	void *hw_addr = ys_k2u_func_get_hwaddr(k2u_ndev->pdev_priv);
	struct ys_k2u_txq *txq;
//	u32 data;

	if (qid >= ndev->real_num_tx_queues)
		return -EINVAL;

	if (!k2u_ndev->qps || !k2u_ndev->qps[qid].txq)
		return -ENODEV;

	txq = k2u_ndev->qps[qid].txq;

	/* 1. set qgroup */
	txq->qgroup = txq->qgroup_request;

	/* 2. set hqos */
	/*
	 * data = FIELD_PREP(GENMASK(26, 22), txq->qgroup);
	 * ys_wr32(hw_addr, YS_K2U_RQ_TBDATA(0), data);
	 * ys_wr32(hw_addr, YS_K2U_RQ_TBMASK(0), 0xffffffff);
	 * data = FIELD_PREP(GENMASK(15, 0), txq->qid.f_id);
	 * ys_wr32(hw_addr, YS_K2U_RQ_TBADDR, data);
	 * ys_wr32(hw_addr, YS_K2U_RQ_TBVALID, 1);
	 */

	return 0;
}

int ys_k2u_ndev_cdev_link_gqbase_get(struct net_device *ndev, u16 *qstart, u16 *qnum)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	*qstart = k2u_ndev->g_qbase.start;
	*qnum = k2u_ndev->g_qbase.num;

	return 0;
}

u16 ys_k2u_ndev_cdev_peer_qset_get(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	return ys_k2u_ndev_get_dstqsetid(ndev_priv);
}
