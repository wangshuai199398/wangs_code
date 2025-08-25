// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_new_rx.h"
#include "ys_k2u_new_func.h"
#include "ys_k2u_new_ndev.h"

#include "../../platform/ysif_linux.h"

struct ys_k2u_rxcb {
	u16 lro_valid:1;
	u16 lro_id;
};

static int ys_k2u_rxcq_handler(struct napi_struct *napi, int napi_budget);
static int ys_k2u_rxq_fill_rxd(struct ys_k2u_rxq *rxq);

/* debug */
static void *rxq_debugfs_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;
	return NULL;
}

static void *rxq_debugfs_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void rxq_debugfs_stop(struct seq_file *seq, void *v)
{
}

static int rxq_debugfs_show(struct seq_file *seq, void *v)
{
	u16 i;

	struct ys_k2u_rxq *rxq = seq->private;
	struct ys_k2u_ndev *k2u_ndev = rxq->k2u_ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);

	if (v != SEQ_START_TOKEN)
		return 0;
	/* 1. rxq */
	/* 1.1. name */
	seq_printf(seq, "%-16s :\n", "rx queue");
	seq_printf(seq, "\t%-16s : %-16s\n", "netdev", k2u_ndev->ndev->name);
	seq_printf(seq, "\t%-16s : %-4d\n", "l_id", rxq->qid.l_id);
	seq_printf(seq, "\t%-16s : %-4d\n", "f_id", rxq->qid.f_id);
	seq_printf(seq, "\t%-16s : %-4d\n", "p_id", rxq->qid.p_id);
	seq_printf(seq, "\t%-16s : %-4d\n", "g_id", rxq->qid.g_id);
	seq_printf(seq, "\t%-16s : %-4d\n", "qset", ndev_priv->qi.qset);
	seq_printf(seq, "\t%-16s : %-4d\n", "active", rxq->active);
	/* 1.2. config param */
	seq_printf(seq, "\t%-16s : %-4d\n", "qdepth", rxq->qdepth);
	seq_printf(seq, "\t%-16s : %-4d\n", "qfragsize", rxq->qfragsize);
	/* 1.3. property */
	seq_printf(seq, "\t%-16s : %-4u\n", "qdepth_max", rxq->qdepth_max);
	seq_printf(seq, "\t%-16s : %-4u\n", "qfragsize_max", rxq->qfragsize_max);
	/* 1.4. stats */
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_alloc_page", rxq->stats_sw.err_alloc_page);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_map_page", rxq->stats_sw.err_map_page);
	/* 1.5. hw */
	/* 1.6 ring */
	seq_printf(seq, "\t%-16s : %-6d\n", "head", ys_ringb_head_orig(&rxq->rxdrb));
	seq_printf(seq, "\t%-16s : %-6d\n", "tail", ys_ringb_tail_orig(&rxq->rxdrb));

	/* 2. rxcq */
	/* 2.1. name */
	seq_printf(seq, "\n%-16s :\n", "rx cpl queue");
	/* 1.2. config param */
	seq_printf(seq, "\t%-16s : %-6d\n", "irq_vector", rxq->rxcq->irq_vector);
	seq_printf(seq, "\t%-16s : %-6d\n", "irq_period", rxq->rxcq->irq_period);
	seq_printf(seq, "\t%-16s : %-6d\n", "irq_coal", rxq->rxcq->irq_coal);
	seq_printf(seq, "\t%-16s : %-6d\n", "period", rxq->rxcq->period);
	seq_printf(seq, "\t%-16s : %-6d\n", "coal", rxq->rxcq->coal);
	seq_printf(seq, "\t%-16s : %-6d\n", "irq_disable", rxq->rxcq->irq_disable);
	/* 1.3 stats */
	seq_printf(seq, "\t%-16s : %-16llu\n", "packets", rxq->rxcq->stats_base.packets);
	seq_printf(seq, "\t%-16s : %-16llu\n", "bytes", rxq->rxcq->stats_base.bytes);
	seq_printf(seq, "\t%-16s : %-16llu\n", "errors", rxq->rxcq->stats_base.errors);
	seq_printf(seq, "\t%-16s : %-16llu\n", "drops", rxq->rxcq->stats_base.drops);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_interrupt",
		   rxq->rxcq->stats_sw.num_interrupt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_schedule",
		   rxq->rxcq->stats_sw.num_schedule);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_handler",
		   rxq->rxcq->stats_sw.num_handler);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_unicast_desc",
		   rxq->rxcq->stats_sw.num_unicast_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_unicast_pkt",
		   rxq->rxcq->stats_sw.num_unicast_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_multicast_desc",
		   rxq->rxcq->stats_sw.num_multicast_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_multicast_pkt",
		   rxq->rxcq->stats_sw.num_multicast_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_broadcast_desc",
		   rxq->rxcq->stats_sw.num_broadcast_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_broadcast_pkt",
		   rxq->rxcq->stats_sw.num_broadcast_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_vlan_8021ad",
		   rxq->rxcq->stats_sw.num_vlan_8021ad);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_vlan_8021q",
		   rxq->rxcq->stats_sw.num_vlan_8021q);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_vlan_remove",
		   rxq->rxcq->stats_sw.num_vlan_remove);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_lro_desc",
		   rxq->rxcq->stats_sw.num_lro_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_lro_pkt",
		   rxq->rxcq->stats_sw.num_lro_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_chkcpl_desc",
		   rxq->rxcq->stats_sw.num_chkcpl_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_chkcpl_pkt",
		   rxq->rxcq->stats_sw.num_chkcpl_pkt);
	for (i = 0; i < ARRAY_SIZE(rxq->rxcq->stats_sw.num_csum_unchk); i++) {
		if (rxq->rxcq->stats_sw.num_csum_unchk[i] == 0)
			continue;

		seq_printf(seq, "\t%sO%c%cI%c%c%-6s : %-16llu\n", "num_",
			   (i & 1) ? '3' : '.', (i & 2) ? '4' : '.',
			   (i & 4) ? '3' : '.', (i & 8) ? '4' : '.',
			   "unchk", rxq->rxcq->stats_sw.num_csum_unchk[i]);
	}
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_nopage",
		   rxq->rxcq->stats_sw.err_nopage);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_rcvsize",
		   rxq->rxcq->stats_sw.err_rcvsize);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_fcs_desc",
		   rxq->rxcq->stats_sw.err_fcs_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_fcs_pkt",
		   rxq->rxcq->stats_sw.err_fcs_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_mtu_desc",
		   rxq->rxcq->stats_sw.err_mtu_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_mtu_pkt",
		   rxq->rxcq->stats_sw.err_mtu_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_edma_desc",
		   rxq->rxcq->stats_sw.err_edma_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_edma_pkt",
		   rxq->rxcq->stats_sw.err_edma_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_ol3_csum_desc",
		   rxq->rxcq->stats_sw.err_ol3_csum_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_ol3_csum_pkt",
		   rxq->rxcq->stats_sw.err_ol3_csum_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_ol4_csum_desc",
		   rxq->rxcq->stats_sw.err_ol4_csum_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_ol4_csum_pkt",
		   rxq->rxcq->stats_sw.err_ol4_csum_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_il3_csum_desc",
		   rxq->rxcq->stats_sw.err_il3_csum_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_il3_csum_pkt",
		   rxq->rxcq->stats_sw.err_il3_csum_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_il4_csum_desc",
		   rxq->rxcq->stats_sw.err_il4_csum_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_il4_csum_pkt",
		   rxq->rxcq->stats_sw.err_il4_csum_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_pktcutoff_desc",
		   rxq->rxcq->stats_sw.err_pktcutoff_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_pktcutoff_pkt",
		   rxq->rxcq->stats_sw.err_pktcutoff_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_pkttimeo_desc",
		   rxq->rxcq->stats_sw.err_pkttimeo_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_pkttimeo_pkt",
		   rxq->rxcq->stats_sw.err_pkttimeo_pkt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_unknown_desc",
		   rxq->rxcq->stats_sw.err_unknown_desc);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_alloc_skb",
		   rxq->rxcq->stats_sw.err_alloc_skb);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_gather",
		   rxq->rxcq->stats_sw.err_gather);
	/* 1.4. ring */
	seq_printf(seq, "\t%-16s : %-6d\n", "head", ys_ringb_head_orig(&rxq->rxcq->rxcdrb));
	seq_printf(seq, "\t%-16s : %-6d\n", "tail", ys_ringb_tail_orig(&rxq->rxcq->rxcdrb));

	return 0;
}

static const struct seq_operations rxq_debugfs_sops = {
	.start = rxq_debugfs_start,
	.next = rxq_debugfs_next,
	.stop = rxq_debugfs_stop,
	.show = rxq_debugfs_show,
};

DEFINE_SEQ_ATTRIBUTE(rxq_debugfs);

/* debug */
static void *rxd_debugfs_start(struct seq_file *seq, loff_t *pos)
{
	struct ys_k2u_rxq *rxq = seq->private;

	if (*pos >= rxq->qdepth)
		return NULL;

	return (*pos >= rxq->qdepth) ? NULL : (rxq->rxd + (*pos));
}

static void *rxd_debugfs_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;
	return rxd_debugfs_start(seq, pos);
}

static void rxd_debugfs_stop(struct seq_file *seq, void *v)
{
}

static int rxd_debugfs_show(struct seq_file *seq, void *v)
{
	struct ys_k2u_rxq *rxq = seq->private;
	struct ys_k2u_rxd *rxd = v;
	long rxd_idx;

	if (!v)
		return 0;

	rxd_idx = rxd - rxq->rxd;
	seq_printf(seq, "%-6ld : %-16.16llx\n", rxd_idx, rxd->addr);

	return 0;
}

static const struct seq_operations rxd_debugfs_sops = {
	.start = rxd_debugfs_start,
	.next = rxd_debugfs_next,
	.stop = rxd_debugfs_stop,
	.show = rxd_debugfs_show,
};

DEFINE_SEQ_ATTRIBUTE(rxd_debugfs);

/* debug */
static void *rxcd_debugfs_start(struct seq_file *seq, loff_t *pos)
{
	struct ys_k2u_rxq *rxq = seq->private;

	if (*pos >= rxq->qdepth)
		return NULL;

	return (*pos >= rxq->qdepth) ? NULL : (rxq->rxcq->rxcd + (*pos));
}

static void *rxcd_debugfs_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;
	return rxcd_debugfs_start(seq, pos);
}

static void rxcd_debugfs_stop(struct seq_file *seq, void *v)
{
}

static int rxcd_debugfs_show(struct seq_file *seq, void *v)
{
	struct ys_k2u_rxq *rxq = seq->private;
	struct ys_k2u_rxcd *rxcd = v;
	long rxcd_idx;

	if (!v)
		return 0;

	rxcd_idx = rxcd - rxq->rxcq->rxcd;
	seq_printf(seq, "%-6ld : %-16.16llx, %-16.16llx\n",
		   rxcd_idx, rxcd->value1, rxcd->value2);

	return 0;
}

static const struct seq_operations rxcd_debugfs_sops = {
	.start = rxcd_debugfs_start,
	.next = rxcd_debugfs_next,
	.stop = rxcd_debugfs_stop,
	.show = rxcd_debugfs_show,
};

DEFINE_SEQ_ATTRIBUTE(rxcd_debugfs);

static int ys_k2u_rxcq_int(struct notifier_block *nb, unsigned long action, void *data)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_k2u_rxcq *rxcq = container_of(nb, struct ys_k2u_rxcq, irq_nb);

	rxcq->stats_sw.num_interrupt++;

	if (unlikely(!(rxcq->rxq->active)))
		return NOTIFY_DONE;

	if (likely(ops->napi_schedule_prep(rxcq->napi))) {
		rxcq->stats_sw.num_schedule++;
		ys_k2u_rxcq_irq_disable(rxcq);
		ops->__napi_schedule_irqoff(rxcq->napi);
	}

	return NOTIFY_DONE;
}

static int ys_k2u_create_rxcq(struct ys_k2u_rxq *rxq)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_k2u_ndev *k2u_ndev = rxq->k2u_ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_k2u_rxcq *rxcq;
	u64 size;
	int ret = 0;

	rxcq = kzalloc(sizeof(*rxcq), GFP_KERNEL);
	if (!rxcq)
		return -ENOMEM;

	ys_ringb_init(&rxcq->rxcdrb, rxq->qdepth);

	/* hw addr */
	rxcq->hw_addr = rxq->hw_addr;

	size = sizeof(struct ys_k2u_rxcd) * rxq->qdepth;
	rxcq->rxcd = ops->dma_alloc_coherent(rxq->dev, size, &rxcq->rxcd_dma_addr, GFP_KERNEL);
	if (!rxcq->rxcd) {
		ys_net_err("rxcq %d rxcdma dma alloc failed", rxq->qid.l_id);
		ret = -ENOMEM;
		goto rxcd_dma_failed;
	}

	rxcq->rxq = rxq;

	/* dma */
	rxcq->rxc_head_dma_addr = ops->ydma_map_single(rxq->dev, &rxcq->rxcdrb.head, sizeof(rxcq->rxcdrb.head), DMA_FROM_DEVICE);

	if (ops->dma_mapping_error(rxq->dev, rxcq->rxc_head_dma_addr)) {
		ys_net_err("rxcq %d dma map failed", rxq->qid.l_id);
		ret = -ENOMEM;
		goto rxc_head_dma_failed;
	}

	/* config params */
	ys_k2u_rxcq_irq_disable(rxcq);

	rxcq->irq_nb.notifier_call = ys_k2u_rxcq_int;

	/* YS_REGISTER_NOTIFIER_IRQ */
	ret = ({
		int ret;
		do {
			struct ys_irq_nb irq_nb = YS_IRQ_NB_INIT(0, pdev_priv->pdev, YS_IRQ_TYPE_QUEUE, ndev_priv->ndev, NULL, NULL);
			irq_nb.sub.bh_type = YS_IRQ_BH_NOTIFIER;
			irq_nb.sub.bh.nb = &rxcq->irq_nb;
			ret = ops->blocking_notifier_call_chain(&pdev_priv->irq_table.nh, YS_IRQ_NB_REGISTER_ANY, &irq_nb);
		} while (0);
		ret;
	});
	
	if (ret < 0) {
		ys_net_err("rxcq %d register irq failed", rxq->qid.l_id);
		goto config_failed;
	}
	rxcq->irq_vector = ret;
	rxcq->irq_period = YS_K2U_N_RX_IRQ_PERIOD;
	rxcq->irq_coal = YS_K2U_N_RX_IRQ_COAL;
	rxcq->period = YS_K2U_N_RX_PERIOD;
	rxcq->coal = YS_K2U_N_RX_COAL;
	rxcq->irq_disable = 0;

	rxq->rxcq = rxcq;
	k2u_ndev->qps[rxq->qid.l_id].rxcq = rxcq;

	return 0;

config_failed:
	ops->ydma_unmap_single(rxq->dev, rxcq->rxc_head_dma_addr,
			 sizeof(rxcq->rxcdrb.head), DMA_FROM_DEVICE);
rxc_head_dma_failed:
	size = sizeof(struct ys_k2u_rxcd) * rxq->qdepth;
	ops->dma_free_coherent(rxq->dev, size, rxcq->rxcd, rxcq->rxcd_dma_addr);
rxcd_dma_failed:
	kfree(rxcq);
	return ret;
}

static void ys_k2u_destroy_rxcq(struct ys_k2u_rxq *rxq)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_k2u_rxcq *rxcq = rxq->rxcq;
	struct ys_k2u_ndev *k2u_ndev = rxq->k2u_ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	u64 size;

	k2u_ndev->qps[rxq->qid.l_id].rxcq = NULL;

	/* YS_UNREGISTER_IRQ */
	({
		int ret;
		do {
			struct ys_irq_nb irq_nb = YS_IRQ_NB_INIT(rxcq->irq_vector, pdev_priv->pdev, 0, NULL, NULL, NULL);
			irq_nb.sub.bh.nb = &rxcq->irq_nb;
			ret = blocking_notifier_call_chain(&irq_table->nh, YS_IRQ_NB_UNREGISTER, &irq_nb);
		} while (0);
		ret;
	});

	ops->ydma_unmap_single(rxq->dev, rxcq->rxc_head_dma_addr,
			 sizeof(rxcq->rxcdrb.head), DMA_FROM_DEVICE);

	size = sizeof(struct ys_k2u_rxcd) * rxq->qdepth;
	ops->dma_free_coherent(rxq->dev, size, rxcq->rxcd, rxcq->rxcd_dma_addr);
}

int ys_k2u_create_rxq(struct ys_k2u_ndev *k2u_ndev, u16 idx, u32 depth)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);
	struct ys_k2u_rxq *rxq;
	size_t size;
	int ret;
	char name[32];

	if (!is_power_of_2(depth)) {
		ys_net_err("rxq %d depth %d not power of 2", idx, depth);
		return -EINVAL;
	}

	size = sizeof(struct ys_k2u_rxq) + sizeof(struct ys_k2u_rxi) * depth;
	rxq = kzalloc(size, GFP_KERNEL);
	if (!rxq) {
		ys_net_err("rxq alloc mem failed, size = %ld", size);
		return -ENOMEM;
	}

	ys_ringb_init(&rxq->rxdrb, depth);

	size = sizeof(struct ys_k2u_rxd) * depth;
	rxq->rxd = ops->dma_alloc_coherent(&ndev_priv->pdev->dev, size, &rxq->rxd_dma_addr, GFP_KERNEL);
	if (!rxq->rxd) {
		ys_net_err("rxq %d rxd dma alloc failed", idx);
		ret = -ENOMEM;
		goto rxd_dma_failed;
	}

	rxq->rxi = (struct ys_k2u_rxi *)(rxq + 1);

	rxq->dev = &ndev_priv->pdev->dev;

	rxq->qid.l_id = k2u_ndev->l_qbase.start + idx;
	rxq->qid.f_id = k2u_ndev->f_qbase.start + idx;
	rxq->qid.p_id = k2u_ndev->p_qbase.start + idx;
	rxq->qid.g_id = k2u_ndev->g_qbase.start + idx;

	/* hw addr */
	rxq->hw_addr = ys_k2u_func_get_hwaddr(k2u_ndev->pdev_priv) +
		       YS_K2U_RE_QX_BASE(rxq->qid.f_id);

	/* config params */
	rxq->qdepth = depth;
	rxq->qfragsize = PAGE_SIZE;

	rxq->active = 0;
	rxq->qdepth_max_power = ys_rd32(rxq->hw_addr, YS_K2U_RE_RXQ_DEPTH_MAX);
	/* should be this */
	//rxq->qdepth_max = 1 << rxq->qdepth_max_power;
	rxq->qdepth_max = YS_K2U_N_MAX_QDEPTH;
	if (rxq->qdepth > rxq->qdepth_max) {
		ys_net_err("rxq %d depth %d > max %d", idx, rxq->qdepth, rxq->qdepth_max);
		ret = -EINVAL;
		goto property_failed;
	}

	rxq->qfragsize_max = ys_rd32(rxq->hw_addr, YS_K2U_RE_RXQ_FRAGSIZE_MAX);
	if (rxq->qfragsize > rxq->qfragsize_max) {
		ys_net_err("rxq %d fragsize %d > max %d", idx, rxq->qfragsize, rxq->qfragsize_max);
		ret = -EINVAL;
		goto property_failed;
	}

	rxq->k2u_ndev = k2u_ndev;

	ret = ys_k2u_create_rxcq(rxq);
	if (ret) {
		ys_net_err("rxq %d create rxcq failed", idx);
		goto rxcq_failed;
	}

	if (k2u_ndev->debugfs_dir) {
		snprintf(name, sizeof(name), "rxq_%d_info", rxq->qid.l_id);
		rxq->debugfs_info_file = ops->debugfs_create_file(name, 0400, k2u_ndev->debugfs_dir, rxq,
							     &rxq_debugfs_fops);
		if (IS_ERR(rxq->debugfs_info_file))
			ys_net_err("rxq %d create debugfs info file failed", idx);

		snprintf(name, sizeof(name), "rxq_%d_rxd", rxq->qid.l_id);
		rxq->debugfs_rxd_file = ops->debugfs_create_file(name, 0400, k2u_ndev->debugfs_dir, rxq,
							    &rxd_debugfs_fops);
		if (IS_ERR(rxq->debugfs_rxd_file))
			ys_net_err("rxq %d create debugfs rxd file failed", idx);

		snprintf(name, sizeof(name), "rxq_%d_rxcd", rxq->qid.l_id);
		rxq->debugfs_rxcd_file = ops->debugfs_create_file(name, 0400, k2u_ndev->debugfs_dir, rxq,
							     &rxcd_debugfs_fops);
		if (IS_ERR(rxq->debugfs_rxcd_file))
			ys_net_err("rxq %d create debugfs rxcd file failed", idx);
	}

	k2u_ndev->qps[idx].rxq = rxq;

	return 0;

rxcq_failed:
property_failed:
	size = sizeof(struct ys_k2u_rxd) * depth;
	dma_free_coherent(rxq->dev, size, rxq->rxd, rxq->rxd_dma_addr);
rxd_dma_failed:
	kfree(rxq);
	return ret;
}

void ys_k2u_destroy_rxq(struct ys_k2u_rxq *rxq)
{
	const struct ysif_ops *ops = ysif_get_ops();
	u64 size;

	rxq->k2u_ndev->qps[rxq->qid.l_id].rxq = NULL;

	ops->debugfs_remove(rxq->debugfs_rxcd_file);
	ops->debugfs_remove(rxq->debugfs_rxd_file);
	ops->debugfs_remove(rxq->debugfs_info_file);

	ys_k2u_destroy_rxcq(rxq);

	size = sizeof(struct ys_k2u_rxd) * rxq->qdepth;
	ops->dma_free_coherent(rxq->dev, size, rxq->rxd, rxq->rxd_dma_addr);

	kfree(rxq);
}

int ys_k2u_activate_rxq(struct ys_k2u_rxq *rxq)
{
	struct ys_k2u_rxcq *rxcq = rxq->rxcq;
	struct ys_k2u_ndev *k2u_ndev = rxq->k2u_ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);
	struct napi_struct *napi = &ndev_priv->rx_napi_list[rxq->qid.l_id].napi;
	const struct ysif_ops *ops = ysif_get_ops();

	ys_ringb_init(&rxq->rxdrb, rxq->qdepth);
	ys_ringb_init(&rxq->rxcq->rxcdrb, rxq->qdepth);

	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXQ_CTRL, YS_K2U_V_RXQ_RXCLR);

	ys_wr32(rxcq->hw_addr, YS_K2U_RE_RXCQ_ADDR_L, rxcq->rxcd_dma_addr);
	ys_wr32(rxcq->hw_addr, YS_K2U_RE_RXCQ_ADDR_H, rxcq->rxcd_dma_addr >> 32);

	ys_wr32(rxcq->hw_addr, YS_K2U_RE_RXCQ_HEAD_ADDR_L, rxcq->rxc_head_dma_addr);
	ys_wr32(rxcq->hw_addr, YS_K2U_RE_RXCQ_HEAD_ADDR_H, rxcq->rxc_head_dma_addr >> 32);

	ys_wr32(rxcq->hw_addr, YS_K2U_RE_RXCQ_IRQ_VECTOR, rxcq->irq_vector);

	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXCQ_IRQ_COAL, rxcq->irq_coal);
	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXCQ_IRQ_PERIOD, rxcq->irq_period);
	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXCQ_PERIOD, rxcq->period);
	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXCQ_COAL, rxcq->coal);

	ys_k2u_rxcq_irq_enable(rxcq);

	ndev_priv->rx_napi_list[rxq->qid.l_id].priv_data = rxcq;
	ops->ynetif_napi_add(ndev_priv->ndev, napi, ys_k2u_rxcq_handler);
	ops->napi_enable(napi);
	/* txcq */
	rxcq->napi = napi;

	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXQ_CTRL, 0);

	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXQ_ADDR_L, rxq->rxd_dma_addr);
	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXQ_ADDR_H, rxq->rxd_dma_addr >> 32);

	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXQ_TAIL, ys_ringb_tail_orig(&rxq->rxdrb));
	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXQ_HEAD, ys_ringb_head_orig(&rxq->rxdrb));

	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXQ_DEPTH, ilog2(rxq->qdepth));

	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXQ_FRAGSIZE, rxq->qfragsize);

	/* fill rxd & txi */
	ys_k2u_rxq_fill_rxd(rxq);

	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXQ_CTRL, 1);
	rxq->active = 1;

	return 0;
}

void ys_k2u_deactivate_rxq(struct ys_k2u_rxq *rxq)
{
	rxq->active = 0;

	/* clear rxd */
	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXQ_CTRL, YS_K2U_V_RXQ_RXCLR);

	ys_k2u_rxcq_irq_disable(rxq->rxcq);
	napi_disable(rxq->rxcq->napi);
	netif_napi_del(rxq->rxcq->napi);
}

void ys_k2u_clean_rxq(struct ys_k2u_rxq *rxq)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(rxq->k2u_ndev->ndev);
	struct ys_k2u_rxi *rxi;
	int count = 0;
	u32 val;

	count = 10;
	while (count--) {
		val = ys_rd32(rxq->hw_addr, YS_K2U_RE_RXQ_CTRL);
		if (val & YS_K2U_V_RXQ_RXEMPTY)
			break;
		usleep_range(1000, 2000);
	}
	if (!(val & YS_K2U_V_RXQ_RXEMPTY))
		ys_net_err("rxq %d clear rxd timeout", rxq->qid.l_id);

	/* clean rxi */
	count = 0;
	while (!ys_ringb_empty(&rxq->rxdrb)) {
		rxi = rxq->rxi + ys_ringb_tail(&rxq->rxdrb);

		if (rxi->page) {
			dma_unmap_page(rxq->dev, rxi->dma_addr, rxq->qfragsize, DMA_FROM_DEVICE);
			__free_pages(rxi->page, rxq->fragorder);
			rxi->page = NULL;
		}

		if (rxi->skb) {
			dev_kfree_skb_any(rxi->skb);
			rxi->skb = NULL;
		}

		ys_ringb_pop(&rxq->rxdrb);
		ys_ringb_pop(&rxq->rxcq->rxcdrb);

		if (count++ > rxq->qdepth) {
			ys_net_err("rxq clean rxi error, count %d > qdepth %d\n",
				   count, rxq->qdepth);
			break;
		}
	}
}

/* rx_limit will delete on future */
static int rx_limit = 32768;
module_param(rx_limit, int, 0644);

static int ys_k2u_rxq_fill_rxd(struct ys_k2u_rxq *rxq)
{
	int ret = 0;
	struct ys_k2u_rxd *rxd;
	struct ys_k2u_rxi *rxi;
	int count = 0;
	const struct ysif_ops *ops = ysif_get_ops();

	if (ys_ringb_left(&rxq->rxdrb) < 16)
		return 0;

	while (ys_ringb_left(&rxq->rxdrb) && count < rx_limit) {
		rxd = rxq->rxd + ys_ringb_head(&rxq->rxdrb);
		rxi = rxq->rxi + ys_ringb_head(&rxq->rxdrb);

		if (rxi->page)
			goto next;

		rxi->page = ops->dev_alloc_pages(rxq->fragorder);
		if (unlikely(!rxi->page)) {
			rxq->stats_sw.err_alloc_page++;
			ret = -ENOMEM;
			break;
		}

		rxi->dma_addr = ops->ydma_map_page(rxq->dev, rxi->page, 0, rxq->qfragsize,
					     DMA_FROM_DEVICE);
		if (unlikely(ops->dma_mapping_error(rxq->dev, rxi->dma_addr))) {
			__free_pages(rxi->page, rxq->fragorder);
			rxi->page = NULL;
			rxq->stats_sw.err_map_page++;
			ret = -ENOMEM;
			break;
		}
		rxd->addr = cpu_to_le64(rxi->dma_addr);
next:
		count++;
		ys_ringb_push(&rxq->rxdrb);
	}

	if (count)
		ys_k2u_rxq_doorbell(rxq);

	return ret;
}

static inline bool
ys_k2u_rxcd_err(struct ys_k2u_rxcq *rxcq, struct ys_k2u_rxcd *rxcd,
		struct ys_k2u_rxi *rxi)
{
	u16 rcvsize;

	if (unlikely(!rxi->page)) {
		rxcq->stats_sw.err_nopage++;
		goto err_must;
	}

	rcvsize = le16_to_cpu(rxcd->size);
	if (unlikely(!rcvsize || rcvsize > rxcq->rxq->qfragsize)) {
		rxcq->stats_sw.err_rcvsize++;
		goto err_must;
	}

	if (unlikely(rxcd->edma_error)) {
		rxcq->stats_sw.err_edma_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.err_edma_pkt++;
		goto err_out;
	}

	if (unlikely(rxcd->fcs_error)) {
		rxcq->stats_sw.err_fcs_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.err_fcs_pkt++;
		goto err_out;
	}

	if (unlikely(rxcd->mtu_error && !rxcd->lro_valid)) {
		rxcq->stats_sw.err_mtu_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.err_mtu_pkt++;
		goto err_out;
	}

	if (unlikely(rxcd->outer_l3_csum_error)) {
		rxcq->stats_sw.err_ol3_csum_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.err_ol3_csum_pkt++;
		goto csum_err;
	}

	if (unlikely(rxcd->inner_l3_csum_error)) {
		rxcq->stats_sw.err_il3_csum_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.err_il3_csum_pkt++;
		goto csum_err;
	}

	if (unlikely(rxcd->outer_l4_csum_error && !rxcd->lro_valid)) {
		rxcq->stats_sw.err_ol4_csum_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.err_ol4_csum_pkt++;
		goto csum_err;
	}

	if (unlikely(rxcd->inner_l4_csum_error && !rxcd->inner_l4_csum_unchk)) {
		rxcq->stats_sw.err_il4_csum_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.err_il4_csum_pkt++;
		goto csum_err;
	}

	if (unlikely(rxcd->pkt_cutoff)) {
		rxcq->stats_sw.err_pktcutoff_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.err_pktcutoff_pkt++;
		goto err_out;
	}

	if (unlikely(rxcd->pkt_timeout)) {
		rxcq->stats_sw.err_pkttimeo_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.err_pkttimeo_pkt++;
		goto err_out;
	}

	return false;

csum_err:
	if (!(rxcq->rxq->k2u_ndev->ndev->features & NETIF_F_RXCSUM))
		return false;
err_out:
	if (rxcq->rxq->k2u_ndev->ndev->features & NETIF_F_RXALL)
		return false;
err_must:
	if (rxcd->fd)
		rxcq->stats_base.errors++;
	return true;
}

static inline bool
ys_k2u_rxcd_casttype(struct ys_k2u_rxcq *rxcq, struct ys_k2u_rxcd *rxcd)
{
	if (rxcd->cast_type == 0) {
		rxcq->stats_sw.num_unicast_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.num_unicast_pkt++;
	} else if (rxcd->cast_type == 1) {
		rxcq->stats_sw.num_multicast_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.num_multicast_pkt++;
	} else if (rxcd->cast_type == 2) {
		rxcq->stats_sw.num_broadcast_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.num_broadcast_pkt++;
	} else {
		rxcq->stats_sw.err_unknown_desc++;
		return true;
	}

	return false;
}

static inline void ys_k2u_rxcd_other(struct ys_k2u_rxcq *rxcq, struct ys_k2u_rxcd *rxcd)
{
	u16 unchk_idx;

	if (rxcd->csum_complete_valid) {
		rxcq->stats_sw.num_chkcpl_desc++;
		if (rxcd->fd)
			rxcq->stats_sw.num_chkcpl_pkt++;
	}

	unchk_idx = rxcd->outer_l3_csum_unchk | (rxcd->outer_l4_csum_unchk << 1) |
		    (rxcd->inner_l3_csum_unchk << 2) | (rxcd->inner_l4_csum_unchk << 3);

	rxcq->stats_sw.num_csum_unchk[unchk_idx]++;
}

static inline void ys_k2u_fixup_csum(struct sk_buff *skb)
{
	__be16 proto = ((struct ethhdr *)skb->data)->h_proto;
	int depth = 0;

	proto = __vlan_get_protocol(skb, proto, &depth);
	if (depth > ETH_HLEN)
		skb->csum = csum_partial(skb->data + ETH_HLEN, depth - ETH_HLEN, skb->csum);
}

static struct sk_buff *ys_k2u_lro_build(struct ys_k2u_rxcq *rxcq, struct sk_buff *skb)
{
	struct ys_k2u_rxcb *rxcb = (struct ys_k2u_rxcb *)(skb->cb);

	if (rxcb->lro_valid)
		rxcq->stats_sw.num_lro_pkt++;

	return skb;
}

static __used noinline __attribute__((optimize("O0"))) void
ys_k2u_rx_tracepoint(struct ys_k2u_rxq *rxq, struct sk_buff *skb,
		     u16 rxcd_head_start, u16 rxcd_head_end)
{
}

static int ys_k2u_rxcq_handler(struct napi_struct *napi, int napi_budget)
{
	struct ys_napi *ys_napi = container_of(napi, struct ys_napi, napi);
	struct ys_k2u_rxcq *rxcq = ys_napi->priv_data;
	struct ys_ndev_priv *ndev_priv = netdev_priv(rxcq->rxq->k2u_ndev->ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct net_device *ndev = ndev_priv->ndev;
	struct ys_k2u_rxq *rxq = rxcq->rxq;
	struct ys_k2u_rxi *rxi;
	struct ys_k2u_rxcd *rxcd;
	struct sk_buff *skb;
	int done = 0;
	u16 rcvsize;
	u16 vlan_id;
	u32 headlen;
	struct ys_k2u_rxcb *rxcb;
	u16 rxcd_head_start = 0;
	u16 rxcd_head_end = 0;
	u32 rss_redir_qcount = 4 * ndev->real_num_rx_queues;
	u32 rss_redir_idx = 0;
	const struct ysif_ops *ops = ysif_get_ops();

	rxcq->stats_sw.num_handler++;
	if (unlikely(!(rxcq->rxq->active) || !(ndev->flags & IFF_UP)))
		goto out;

	while (!ys_ringb_empty(&rxcq->rxcdrb) && done < napi_budget) {
		rxcd = rxcq->rxcd + ys_ringb_tail(&rxcq->rxcdrb);
		rxi = rxcq->rxq->rxi + ys_ringb_tail(&rxcq->rxcdrb);

		if (ys_k2u_rxcd_err(rxcq, rxcd, rxi) ||
		    ys_k2u_rxcd_casttype(rxcq, rxcd)) {
			ys_ringb_pop(&rxq->rxdrb);
			ys_ringb_pop(&rxcq->rxcdrb);
			if (rxi->skb)
				dev_kfree_skb_any(rxi->skb);
			rxi->skb = NULL;
			continue;
		}

		ys_k2u_rxcd_other(rxcq, rxcd);

		rcvsize = le16_to_cpu(rxcd->size);

		skb = rxi->skb;
		if (rxcd->fd && !skb) {
			rxcd_head_start = ys_ringb_head_orig(&rxcq->rxcdrb);

			skb = ops->napi_alloc_skb(napi, YS_K2U_N_RX_MINDATA);
			if (unlikely(!skb)) {
				rxcq->stats_sw.err_alloc_skb++;
				break;
			}

			if (rxcd->vlan_valid) {
				if (rxcd->vlan_protocol_type)
					rxcq->stats_sw.num_vlan_8021ad++;
				else
					rxcq->stats_sw.num_vlan_8021q++;

				vlan_id = le16_to_cpu(ys_k2u_rxcd_get_vlanid(rxcd));
				if (rxcd->vlan_protocol_type)
					ops->__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), vlan_id);
				else
					ops->__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_id);
			}

			/* notice : it need lan configure hash elements */
			/* todo : hashtype should be PKT_HASH_TYPE_L4 or PKT_HASH_TYPE_L3
			 *        according to lan configuration(ethtool ?)
			 */
			if (rxcd->hash_result && (ndev->features & NETIF_F_RXHASH))
				ops->skb_set_hash(skb, be16_to_cpu(rxcd->hash_result), PKT_HASH_TYPE_L4);

			if (rxcd->vlan_tag_remove && rxcd->fd)
				rxcq->stats_sw.num_vlan_remove++;

			if (rxcd->lro_valid) {
				rxcq->stats_sw.num_lro_desc++;
				rxcb = (struct ys_k2u_rxcb *)(skb->cb);
				rxcb->lro_valid = 1;
				rxcb->lro_id = le16_to_cpu(rxcd->lro_id);
			}

			headlen = min_t(u32, rcvsize, YS_K2U_N_RX_MINDATA);
			memcpy(__skb_put(skb, headlen), page_address(rxi->page), headlen);

			if (rcvsize - headlen) {
				ops->skb_add_rx_frag(skb, 0, rxi->page, headlen, rcvsize - headlen, rxq->qfragsize);
				rxi->page = NULL;
				dma_unmap_page(rxq->dev, rxi->dma_addr, rxq->qfragsize,
					       DMA_FROM_DEVICE);
			}

			if (rxcd->csum_complete_valid && (ndev->features & NETIF_F_RXCSUM)) {
				skb->ip_summed = CHECKSUM_COMPLETE;
				skb->csum = csum_unfold(le16_to_cpu(rxcd->csum_complete));
				ys_k2u_fixup_csum(skb);
			}
		} else if (likely(skb) && !rxcd->fd) {
			ops->skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rxi->page, 0, rcvsize, rxq->qfragsize);
			rxi->page = NULL;
			dma_unmap_page(rxq->dev, rxi->dma_addr, rxq->qfragsize, DMA_FROM_DEVICE);
		} else {
			/* it should not be there */
			rxcq->stats_sw.err_gather++;
			ys_ringb_pop(&rxq->rxdrb);
			ys_ringb_pop(&rxcq->rxcdrb);
			if (rxi->skb)
				dev_kfree_skb_any(rxi->skb);
			rxi->skb = NULL;
			continue;
		}

		rxi->skb = NULL;
		ys_ringb_pop(&rxq->rxdrb);
		ys_ringb_pop(&rxcq->rxcdrb);
		done++;

		if (!rxcd->ld) {
			rxi = rxq->rxi + ys_ringb_tail(&rxcq->rxcdrb);
			rxi->skb = skb;
			continue;
		}

		rxcd_head_end = ys_ringb_head_orig(&rxcq->rxcdrb);

		ys_k2u_rx_tracepoint(rxq, skb, rxcd_head_start, rxcd_head_end);

		skb = ys_k2u_lro_build(rxcq, skb);
		if (unlikely(!skb))
			continue;

		ops->skb_record_rx_queue(skb, rxq->qid.l_id);

		rxcq->stats_base.packets++;
		rxcq->stats_base.bytes += skb->len;
		if (k2u_ndev->rss_redirect_en) {
			if (is_power_of_2(rss_redir_qcount))
				rss_redir_idx = skb->hash & (rss_redir_qcount - 1);
			else
				rss_redir_idx = skb->hash - (skb->hash / rss_redir_qcount)
								 * rss_redir_qcount;
			rxcq->stats_rss_redir.num_rss_redir_idx[rss_redir_idx]++;
		}
		skb->protocol = eth_type_trans(skb, ndev_priv->ndev);
		ops->napi_gro_receive(napi, skb);
	}

	/* fill rxd */
	ys_k2u_rxq_fill_rxd(rxq);

	if (done == napi_budget) {
		ops->napi_schedule(napi);
		return done;
	}
out:
	if (ops->napi_complete_done(napi, done))
		ys_k2u_rxcq_irq_enable(rxcq);

	return done;
}
