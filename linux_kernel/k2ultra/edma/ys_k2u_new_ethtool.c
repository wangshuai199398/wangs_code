// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_new_core.h"
#include "ys_k2u_new_hw.h"
#include "ys_k2u_new_func.h"
#include "ys_k2u_debugfs.h"
#include "ys_k2u_new_ethtool.h"
#include "ys_k2u_new_ndev.h"
#include "ys_k2u_rss_redirect.h"

#include "../../platform/ysif_linux.h"

int ys_k2u_et_set_channels(struct net_device *ndev, struct ethtool_channels *ch)
{
	const struct ysif_ops *ops = ysif_get_ops();
	int ret = 0;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	if (k2u_ndev->rss_redirect_dynamic_adjust)
		ys_k2u_rss_redir_timer_delete(ndev);

	ys_k2u_ndev_destroy_queues(k2u_ndev);

	ops->netif_set_real_num_tx_queues(ndev, ch->combined_count);
	ops->netif_set_real_num_rx_queues(ndev, ch->combined_count);
	ret = ys_k2u_ndev_create_queues(k2u_ndev);
	if (!ret) {
		ys_k2u_rss_redirect_table_init(ndev, (u16)ndev->real_num_rx_queues);

		if (k2u_ndev->rss_redirect_dynamic_adjust) {
			if (ch->combined_count > 1)
				ys_k2u_rss_redir_timer_setup(k2u_ndev);
			else
				k2u_ndev->rss_redirect_dynamic_adjust = 0;
		}
	}
	return ret;
}

void ys_k2u_et_get_ringparam(struct net_device *ndev, struct ethtool_ringparam *param)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	param->rx_max_pending = YS_K2U_N_MAX_QDEPTH;
	param->tx_max_pending = YS_K2U_N_MAX_QDEPTH;

	param->rx_pending = k2u_ndev->rxq_depth;
	param->tx_pending = k2u_ndev->txq_depth;

	ndev->gso_max_segs = min_t(u16, YS_K2U_N_TSO_MAXSEGS, (k2u_ndev->txq_depth >> 2));
	if ((ndev->features & (NETIF_F_TSO | NETIF_F_TSO6)) != (NETIF_F_TSO | NETIF_F_TSO6)) {
		if (k2u_ndev->txq_depth <= 128)
			ndev->gso_max_segs >>= 2;
	}
}

int ys_k2u_et_ringparam_check(struct net_device *ndev, struct ethtool_ringparam *param)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (param->rx_jumbo_pending) {
		ys_net_info("rx_jumbo_pending not supported");
		return -EINVAL;
	}

	if (param->rx_mini_pending) {
		ys_net_info("rx_mini_pending not supported");
		return -EINVAL;
	}

	if (param->rx_pending < YS_K2U_N_MIN_QDEPTH) {
		ys_net_info("rx_pending (%d) < min (%d)", param->rx_pending,
			    YS_K2U_N_MIN_QDEPTH);
		return -EINVAL;
	}
	if (param->rx_pending > YS_K2U_N_MAX_QDEPTH) {
		ys_net_info("rx_pending (%d) > max (%d)", param->rx_pending,
			    YS_K2U_N_MAX_QDEPTH);
		return -EINVAL;
	}

	if (param->tx_pending < YS_K2U_N_MIN_QDEPTH) {
		ys_net_info("tx_pending (%d) < min (%d)", param->tx_pending,
			    YS_K2U_N_MIN_QDEPTH);
		return -EINVAL;
	}
	if (param->tx_pending > YS_K2U_N_MAX_QDEPTH) {
		ys_net_info("tx_pending (%d) < max (%d)", param->tx_pending,
			    YS_K2U_N_MAX_QDEPTH);
		return -EINVAL;
	}

	return 0;
}

int ys_k2u_et_set_ringparam(struct net_device *ndev, struct ethtool_ringparam *param)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	u8 log_tx_size;
	u8 log_rx_size;

	log_tx_size = order_base_2(param->tx_pending);
	log_rx_size = order_base_2(param->rx_pending);

	k2u_ndev->rxq_depth = (1 << log_rx_size);
	k2u_ndev->txq_depth = (1 << log_tx_size);

	ys_k2u_ndev_destroy_queues(k2u_ndev);

	return ys_k2u_ndev_create_queues(k2u_ndev);
}

#define YS_K2U_READ_CTR64(ptr, dsc, i) \
	READ_ONCE(*(u64 *)((char *)(ptr) + (dsc)[(i)].stats_offset))

#define YS_K2U_RXQ_STATS_NUM ARRAY_SIZE(ys_k2u_rxq_stats)
#define YS_K2U_TXQ_STATS_NUM ARRAY_SIZE(ys_k2u_txq_stats)

#define YS_K2U_RXQ_STATS_BASE_OFFSET(q_relative_index) \
	((1 + (q_relative_index)) * YS_K2U_RXQ_STATS_NUM)
#define YS_K2U_TXQ_STATS_BASE_OFFSET(q_relative_index) \
	((1 + (q_relative_index)) * YS_K2U_TXQ_STATS_NUM)

static const struct ys_priv_stats ys_k2u_rxq_stats[] = {
	_STAT("packets", 0, offsetof(struct ys_k2u_stats_base, packets)),
	_STAT("bytes", 0, offsetof(struct ys_k2u_stats_base, bytes)),
	_STAT("errors", 0, offsetof(struct ys_k2u_stats_base, errors)),
	_STAT("drops", 0, offsetof(struct ys_k2u_stats_base, drops)),
	_STAT("vlanremove", 1, offsetof(struct ys_k2u_rxc_stats_sw, num_vlan_remove)),
	_STAT("lro_packets", 1, offsetof(struct ys_k2u_rxc_stats_sw, num_lro_pkt)),
};

static const struct ys_priv_stats ys_k2u_txq_stats[] = {
	_STAT("packets", 0, offsetof(struct ys_k2u_stats_base, packets)),
	_STAT("bytes", 0, offsetof(struct ys_k2u_stats_base, bytes)),
	_STAT("errors", 0, offsetof(struct ys_k2u_stats_base, errors)),
	_STAT("drops", 0, offsetof(struct ys_k2u_stats_base, drops)),
	_STAT("vlaninsert", 1, offsetof(struct ys_k2u_tx_stats_sw, num_vlaninsert)),
};

static int ys_k2u_ethtool_get_rxq_stats(struct net_device *ndev, u64 *data)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	u64 val, sum;
	int offset;
	int i;
	int j;
	u32 idx;
	u32 rss_direct_offset;

	for (i = 0; i < YS_K2U_RXQ_STATS_NUM; i++) {
		sum = 0;
		for (j = 0; j < ndev->real_num_rx_queues; j++) {
			if (!ys_k2u_rxq_stats[i].sizeof_stat)
				val = YS_K2U_READ_CTR64(&k2u_ndev->qps[j].rxcq->stats_base,
							ys_k2u_rxq_stats, i);
			else
				val = YS_K2U_READ_CTR64(&k2u_ndev->qps[j].rxcq->stats_sw,
							ys_k2u_rxq_stats, i);
			offset = YS_K2U_RXQ_STATS_BASE_OFFSET(j) + i;
			data[offset] = val;
			sum += val;
		}
		/* -1 for the sum value of all rx queues */
		offset = YS_K2U_RXQ_STATS_BASE_OFFSET(-1) + i;
		data[offset] = sum;
	}

	rss_direct_offset = YS_K2U_RXQ_STATS_NUM * (ndev->real_num_rx_queues + 1);
	for (idx = 0; idx < 4 * ndev->real_num_rx_queues; idx++) {
		sum = 0;
		for (j = 0; j < ndev->real_num_rx_queues; j++)
			sum += READ_ONCE(k2u_ndev->qps[j].rxcq->stats_rss_redir
							.num_rss_redir_idx[idx]);
		offset = rss_direct_offset + idx;
		data[offset] = sum;
	}
	return YS_K2U_RXQ_STATS_NUM * (ndev->real_num_rx_queues + 1)
		   + 4 * ndev->real_num_rx_queues;
}

static int ys_k2u_ethtool_get_txq_stats(struct net_device *ndev, u64 *data)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	u64 val, sum;
	int offset;
	int i;
	int j;

	for (i = 0; i < YS_K2U_TXQ_STATS_NUM; i++) {
		sum = 0;
		for (j = 0; j < ndev->real_num_tx_queues; j++) {
			if (!ys_k2u_txq_stats[i].sizeof_stat)
				val = YS_K2U_READ_CTR64(&k2u_ndev->qps[j].txq->stats_base,
							ys_k2u_txq_stats, i);
			else
				val = YS_K2U_READ_CTR64(&k2u_ndev->qps[j].txq->stats_sw,
							ys_k2u_txq_stats, i);
			offset = YS_K2U_TXQ_STATS_BASE_OFFSET(j) + i;
			data[offset] = val;
			sum += val;
		}
		/* -1 for the sum value of all tx queues */
		offset = YS_K2U_TXQ_STATS_BASE_OFFSET(-1) + i;
		data[offset] = sum;
	}

	return YS_K2U_TXQ_STATS_NUM * (ndev->real_num_tx_queues + 1);
}

static int ys_k2u_ethtool_get_rxq_stats_strings(struct net_device *ndev, u8 *data)
{
	char stat_string[ETH_GSTRING_LEN];
	u8 *p = data;
	int offset;
	int i;
	int j;
	u32 idx;
	u32 rss_direct_offset;

	for (i = 0; i < YS_K2U_RXQ_STATS_NUM; i++) {
		for (j = 0; j < ndev->real_num_rx_queues; j++) {
			offset = YS_K2U_RXQ_STATS_BASE_OFFSET(j) + i;
			sprintf(stat_string, "rx%d_", j);
			strcat(stat_string, ys_k2u_rxq_stats[i].stat_string);
			memcpy(p + offset * ETH_GSTRING_LEN,
			       stat_string, ETH_GSTRING_LEN);
		}
		/* -1 for the sum value of all rx queues */
		offset = YS_K2U_RXQ_STATS_BASE_OFFSET(-1) + i;
		strscpy(stat_string, "rx_", sizeof(stat_string));
		strcat(stat_string, ys_k2u_rxq_stats[i].stat_string);
		memcpy(p + offset * ETH_GSTRING_LEN,
		       stat_string, ETH_GSTRING_LEN);
	}

	rss_direct_offset = YS_K2U_RXQ_STATS_NUM * (ndev->real_num_rx_queues + 1);
	for (idx = 0; idx < 4 * ndev->real_num_rx_queues; idx++) {
		offset = rss_direct_offset + idx;
		sprintf(stat_string, "rx_rss_redir_%d", idx);
		memcpy(p + offset * ETH_GSTRING_LEN,
		       stat_string, ETH_GSTRING_LEN);
	}

	return YS_K2U_RXQ_STATS_NUM * (ndev->real_num_rx_queues + 1)
		   + 4 * ndev->real_num_rx_queues;
}

static int ys_k2u_ethtool_get_txq_stats_strings(struct net_device *ndev, u8 *data)
{
	char stat_string[ETH_GSTRING_LEN];
	u8 *p = data;
	int offset;
	int i;
	int j;

	for (i = 0; i < YS_K2U_TXQ_STATS_NUM; i++) {
		for (j = 0; j < ndev->real_num_tx_queues; j++) {
			offset = YS_K2U_TXQ_STATS_BASE_OFFSET(j) + i;
			sprintf(stat_string, "tx%d_", j);
			strcat(stat_string, ys_k2u_txq_stats[i].stat_string);
			memcpy(p + offset * ETH_GSTRING_LEN,
			       stat_string, ETH_GSTRING_LEN);
		}
		/* -1 for the sum value of all tx queues */
		offset = YS_K2U_TXQ_STATS_BASE_OFFSET(-1) + i;
		strscpy(stat_string, "tx_", sizeof(stat_string));
		strcat(stat_string, ys_k2u_txq_stats[i].stat_string);
		memcpy(p + offset * ETH_GSTRING_LEN,
		       stat_string, ETH_GSTRING_LEN);
	}

	return YS_K2U_TXQ_STATS_NUM * (ndev->real_num_tx_queues + 1);
}

void ys_k2u_et_get_stats(struct net_device *ndev, u64 *data)
{
	int offset;

	offset = ys_k2u_ethtool_get_rxq_stats(ndev, data);
	ys_k2u_ethtool_get_txq_stats(ndev, data + offset);
}

void ys_k2u_et_get_stats_strings(struct net_device *ndev, u8 *data)
{
	int offset;
	int len;

	len = ys_k2u_ethtool_get_rxq_stats_strings(ndev, data);
	offset = len * ETH_GSTRING_LEN;
	ys_k2u_ethtool_get_txq_stats_strings(ndev, data + offset);
}

int ys_k2u_et_get_stats_count(struct net_device *ndev)
{
	int rxq_stats_count;
	int txq_stats_count;

	rxq_stats_count = (ndev->real_num_rx_queues + 1) *
			  YS_K2U_RXQ_STATS_NUM + 4 * ndev->real_num_rx_queues;

	txq_stats_count = (ndev->real_num_tx_queues + 1) *
			  YS_K2U_TXQ_STATS_NUM;

	return rxq_stats_count + txq_stats_count;
}

u32 ys_k2u_get_rxfh_key_size(struct net_device *ndev)
{
	return YS_K2U_RSS_HASH_KEY_SIZE;
}

u32 ys_k2u_get_rxfh_indir_size(struct net_device *ndev)
{
	u32 qcount;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	qcount = ndev->real_num_rx_queues;
	if (k2u_ndev->rss_redirect_en)
		return 4 * qcount;

	return qcount;
}

int ys_k2u_get_rxfh(struct net_device *ndev, u32 *indir, u8 *key, u8 *hfunc)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	u32 i = 0;
	u32 qcount = ndev->real_num_rx_queues;

	if (indir) {
		if (k2u_ndev->rss_redirect_en) {
			ys_k2u_rss_redirect_table_get(ndev, indir);
		} else {
			for (i = 0; i < qcount; i++)
				indir[i] = i;
		}
	}

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;

	if (key)
		ys_k2u_rss_key_get(ndev, key);

	return 0;
}

int ys_k2u_set_rxfh(struct net_device *ndev, const u32 *indir, const u8 *key, const u8 hfunc)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;

	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	if (key)
		ys_k2u_rss_key_set(ndev, key);

	if (indir && k2u_ndev->rss_redirect_en && !k2u_ndev->rss_redirect_dynamic_adjust)
		ys_k2u_rss_redirect_table_set(ndev, indir);

	return 0;
}
