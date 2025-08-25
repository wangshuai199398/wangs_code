// SPDX-License-Identifier: GPL-2.0
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/netdevice.h>

#include "ys_k2u_new_tx.h"
#include "ys_k2u_new_hw.h"
#include "ys_k2u_scatter.h"

#include "ys_k2u_new_func.h"
#include "ys_k2u_new_ndev.h"

#include "../../platform/ysif_linux.h"

/* function declare */
static int ys_k2u_txcq_handler(struct napi_struct *napi, int napi_budget);

/* debug */
static void *txq_debugfs_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;
	return NULL;
}

static void *txq_debugfs_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void txq_debugfs_stop(struct seq_file *seq, void *v)
{
}

static int txq_debugfs_show(struct seq_file *seq, void *v)
{
	struct ys_k2u_txq *txq = seq->private;
	struct ys_k2u_ndev *k2u_ndev = txq->k2u_ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);

	if (v != SEQ_START_TOKEN)
		return 0;
	/* 1. txq */
	/* 1.1. name */
	seq_printf(seq, "%-16s :\n", "tx queue");
	seq_printf(seq, "\t%-16s : %-16s\n", "netdev", k2u_ndev->ndev->name);
	seq_printf(seq, "\t%-16s : %-4d\n", "l_id", txq->qid.l_id);
	seq_printf(seq, "\t%-16s : %-4d\n", "f_id", txq->qid.f_id);
	seq_printf(seq, "\t%-16s : %-4d\n", "p_id", txq->qid.p_id);
	seq_printf(seq, "\t%-16s : %-4d\n", "g_id", txq->qid.g_id);
	seq_printf(seq, "\t%-16s : %-4d\n", "qset", ndev_priv->qi.qset);
	seq_printf(seq, "\t%-16s : %-4d\n", "active", txq->active);
	/* 1.2. config param */
	seq_printf(seq, "\t%-16s : %-4d\n", "qgroup", txq->qgroup);
	seq_printf(seq, "\t%-16s : %-4d\n", "qdepth", txq->qdepth);
	seq_printf(seq, "\t%-16s : %-4d\n", "qfragsize", txq->qfragsize);
	/* 1.3. property */
	seq_printf(seq, "\t%-16s : %-4u\n", "qdepth_max", txq->qdepth_max);
	seq_printf(seq, "\t%-16s : %-4u\n", "qfragsize_max", txq->qfragsize_max);
	seq_printf(seq, "\t%-16s : %-4u\n", "qpktsize_max", txq->qpktsize_max);
	/* 1.4. stats */
	seq_printf(seq, "\t%-16s : %-16llu\n", "packets", txq->stats_base.packets);
	seq_printf(seq, "\t%-16s : %-16llu\n", "bytes", txq->stats_base.bytes);
	seq_printf(seq, "\t%-16s : %-16llu\n", "errors", txq->stats_base.errors);
	seq_printf(seq, "\t%-16s : %-16llu\n", "drops", txq->stats_base.drops);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_smalltso", txq->stats_sw.num_smalltso);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_bigtso", txq->stats_sw.num_bigtso);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_txd", txq->stats_sw.num_txd);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_txdfd", txq->stats_sw.num_txdfd);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_txdld", txq->stats_sw.num_txdld);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_txdummy", txq->stats_sw.num_txdummy);
	seq_printf(seq, "\t%-16s : %-16llu\n", "over_fragsize", txq->stats_sw.over_fragsize);
	seq_printf(seq, "\t%-16s : %-16llu\n", "over_pktsize", txq->stats_sw.over_pktsize);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_dmasg", txq->stats_sw.err_dmasg);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_linearize", txq->stats_sw.err_linearize);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_scatter", txq->stats_sw.err_scatter);
	seq_printf(seq, "\t%-16s : %-16llu\n", "err_notxd", txq->stats_sw.err_notxd);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_qstop", txq->stats_sw.num_qstop);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_qwakeup", txq->stats_sw.num_qwakeup);
	/* 1.5. hw */
	/* 1.6 ring */
	seq_printf(seq, "\t%-16s : %-6d\n", "head", ys_ringb_head_orig(&txq->txdrb));
	seq_printf(seq, "\t%-16s : %-6d\n", "tail", ys_ringb_tail_orig(&txq->txdrb));

	/* 2. txcq */
	/* 2.1. name */
	seq_printf(seq, "\n%-16s :\n", "tx cpl queue");
	/* 1.2. config param */
	seq_printf(seq, "\t%-16s : %-6d\n", "irq_vector", txq->txcq->irq_vector);
	seq_printf(seq, "\t%-16s : %-6d\n", "coal", txq->txcq->coal);
	seq_printf(seq, "\t%-16s : %-6d\n", "period", txq->txcq->period);
	seq_printf(seq, "\t%-16s : %-6d\n", "irq_disable", txq->txcq->irq_disable);
	seq_printf(seq, "\t%-16s : %-6d\n", "cpllen", txq->txcq->qcpllen);
	/* 1.3 stats sw */
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_freeskb", txq->txcq->stats_sw.num_freeskb);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_interrupt", txq->txcq->stats_sw.num_interrupt);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_schedule", txq->txcq->stats_sw.num_schedule);
	seq_printf(seq, "\t%-16s : %-16llu\n", "num_handler", txq->txcq->stats_sw.num_handler);
	/* 1.4. ring */
	seq_printf(seq, "\t%-16s : %-6d\n", "head", ys_ringb_head_orig(&txq->txcq->txcdrb));
	seq_printf(seq, "\t%-16s : %-6d\n", "tail", ys_ringb_tail_orig(&txq->txcq->txcdrb));

	return 0;
}

static const struct seq_operations txq_debugfs_sops = {
	.start = txq_debugfs_start,
	.next = txq_debugfs_next,
	.stop = txq_debugfs_stop,
	.show = txq_debugfs_show,
};

DEFINE_SEQ_ATTRIBUTE(txq_debugfs);

/* debug */
static void *txd_debugfs_start(struct seq_file *seq, loff_t *pos)
{
	struct ys_k2u_txq *txq = seq->private;

	if (*pos >= txq->qdepth)
		return NULL;

	return (*pos >= txq->qdepth) ? NULL : (txq->txd + (*pos));
}

static void *txd_debugfs_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;
	return txd_debugfs_start(seq, pos);
}

static void txd_debugfs_stop(struct seq_file *seq, void *v)
{
}

static int txd_debugfs_show(struct seq_file *seq, void *v)
{
	struct ys_k2u_txq *txq = seq->private;
	struct ys_k2u_txd *txd = v;
	long txd_idx;

	if (!v)
		return 0;

	txd_idx = txd - txq->txd;
	seq_printf(seq, "%-6ld : %-16.16llx, %-16.16llx\n", txd_idx, txd->addr, txd->value);

	return 0;
}

static const struct seq_operations txd_debugfs_sops = {
	.start = txd_debugfs_start,
	.next = txd_debugfs_next,
	.stop = txd_debugfs_stop,
	.show = txd_debugfs_show,
};

DEFINE_SEQ_ATTRIBUTE(txd_debugfs);

static int ys_k2u_txcq_int(struct notifier_block *nb, unsigned long action, void *data)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_k2u_txcq *txcq = container_of(nb, struct ys_k2u_txcq, irq_nb);

	txcq->stats_sw.num_interrupt++;

	if (unlikely(!(txcq->txq->active)))
		return NOTIFY_DONE;

	if (likely(ops->napi_schedule_prep(txcq->napi))) {
		txcq->stats_sw.num_schedule++;
		ys_k2u_txcq_irq_disable(txcq);
		ops->__napi_schedule_irqoff(txcq->napi);
	}

	return NOTIFY_DONE;
}

static int ys_k2u_create_txcq(struct ys_k2u_txq *txq)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_k2u_ndev *k2u_ndev = txq->k2u_ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_k2u_txcq *txcq;
	int ret = 0;

	txcq = kzalloc(sizeof(*txcq), GFP_KERNEL);
	if (!txcq)
		return -ENOMEM;

	ys_ringb_init(&txcq->txcdrb, txq->qdepth);
	txcq->txq = txq;

	/* hw addr */
	txcq->hw_addr = txq->hw_addr;

	/* dma */
	txcq->txc_head_dma_addr = ops->ydma_map_single(txq->dev, &txcq->txcdrb.head,
						 sizeof(txcq->txcdrb.head), DMA_FROM_DEVICE);
	if (ops->dma_mapping_error(txq->dev, txcq->txc_head_dma_addr)) {
		ys_net_err("txcq %d dma map failed", txq->qid.l_id);
		ret = -ENOMEM;
		goto txcq_failed;
	}
	/* config param */
	txcq->coal = YS_K2U_N_TXCQ_COAL;
	txcq->period = YS_K2U_N_TXCQ_PERIOD;
	txcq->irq_disable = 0;
	txcq->qcpllen = CPLLEN_64K;
	txcq->irq_nb.notifier_call = ys_k2u_txcq_int;

	ys_k2u_txcq_irq_disable(txcq);
	/* YS_REGISTER_NOTIFIER_IRQ */
	ret = ({
		int ret;
		do {
			struct ys_irq_nb irq_nb = YS_IRQ_NB_INIT(0, pdev_priv->pdev, YS_IRQ_TYPE_QUEUE, ndev_priv->ndev, NULL, NULL);
			irq_nb.sub.bh_type = YS_IRQ_BH_NOTIFIER;
			irq_nb.sub.bh.nb = &txcq->irq_nb;
			ret = ops->blocking_notifier_call_chain(&pdev_priv->irq_table.nh, YS_IRQ_NB_REGISTER_ANY, &irq_nb);/* -> irqs_change_nb */
		} while (0);
		ret;
	});

	if (ret < 0) {
		ys_net_err("txcq %d register irq failed", txq->qid.l_id);
		goto config_failed;
	}
	txcq->irq_vector = ret;

	txq->txcq = txcq;
	k2u_ndev->qps[txq->qid.l_id].txcq = txcq;

	return 0;

config_failed:
	ops->ydma_unmap_single(txq->dev, txcq->txc_head_dma_addr,
			 sizeof(txcq->txcdrb.head), DMA_FROM_DEVICE);
txcq_failed:
	kfree(txcq);
	return ret;
}

static void ys_k2u_destroy_txcq(struct ys_k2u_txq *txq)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_k2u_txcq *txcq = txq->txcq;
	struct ys_k2u_ndev *k2u_ndev = txq->k2u_ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;

	k2u_ndev->qps[txq->qid.l_id].txcq = NULL;

	/* YS_UNREGISTER_IRQ */
	({
		int ret;
		do {
			struct ys_irq_nb irq_nb = YS_IRQ_NB_INIT(txcq->irq_vector,pdev_priv->pdev, 0, NULL, NULL, NULL);
			irq_nb.sub.bh.nb = &txcq->irq_nb;
			ret = blocking_notifier_call_chain(&irq_table->nh, YS_IRQ_NB_UNREGISTER, &irq_nb);
		} while (0);
		ret;
	});

	ops->ydma_unmap_single(&pdev_priv->pdev->dev, txcq->txc_head_dma_addr,
			 sizeof(txcq->txcdrb.head), DMA_FROM_DEVICE);
	kfree(txcq);
}

int ys_k2u_create_txq(struct ys_k2u_ndev *k2u_ndev, u16 idx, u32 depth)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);
	struct ys_k2u_txq *txq;
	size_t size;
	int ret;
	char name[32];

	if (!is_power_of_2(depth)) {
		ys_net_err("txq %d depth %d not power of 2", idx, depth);
		return -EINVAL;
	}

	size = sizeof(*txq) + sizeof(struct ys_k2u_txi) * depth;
	txq = kzalloc(size, GFP_KERNEL);
	if (!txq) {
		ys_net_err("txq alloc failed, siza %lu, depth %u, struct size %lu",
			   size, depth, sizeof(struct ys_k2u_txi));
		return -ENOMEM;
	}

	/* txd & txi */
	ys_ringb_init(&txq->txdrb, depth);
	size = sizeof(struct ys_k2u_txd) * depth;
	txq->txd = ops->dma_alloc_coherent(&ndev_priv->pdev->dev, size,
				      &txq->txd_dma_addr, GFP_KERNEL);
	if (!txq->txd) {
		ret = -ENOMEM;
		goto txq_failed;
	}

	txq->txi = (struct ys_k2u_txi *)(txq + 1);

	txq->dev = &ndev_priv->pdev->dev;
	txq->qid.l_id = k2u_ndev->l_qbase.start + idx;
	txq->qid.f_id = k2u_ndev->f_qbase.start + idx;
	txq->qid.p_id = k2u_ndev->p_qbase.start + idx;
	txq->qid.g_id = k2u_ndev->g_qbase.start + idx;

	/* hw addr */
	txq->hw_addr = ys_k2u_func_get_hwaddr(k2u_ndev->pdev_priv) +
		       YS_K2U_RE_QX_BASE(txq->qid.f_id);

	/* config params */
	txq->qdepth = depth;
	txq->qfragsize = YS_K2U_N_MAX_TXFRAGSIZE;

	/* property */
	txq->active = 0;
	txq->qdepth_max_power = ys_rd32(txq->hw_addr, YS_K2U_RE_TXQ_DEPTH_MAX);
	/* should be this */
	//txq->qdepth_max = 1 << txq->qdepth_max_power;
	txq->qdepth_max = YS_K2U_N_MAX_QDEPTH;
	if (txq->qdepth > txq->qdepth_max) {
		ys_net_err("txq %d depth %d > max %d", idx, txq->qdepth, txq->qdepth_max);
		ret = -EINVAL;
		goto property_failed;
	}

	txq->qfragsize_max = ys_rd32(txq->hw_addr, YS_K2U_RE_TXQ_FRAGSIZE_MAX);
	if (txq->qfragsize > txq->qfragsize_max) {
		ys_net_err("txq %d fragsize %d > max %d", idx, txq->qfragsize, txq->qfragsize_max);
		ret = -EINVAL;
		goto property_failed;
	}
	txq->qpktsize_max = YS_K2U_N_MAX_TXPKTLEN;

	txq->k2u_ndev = k2u_ndev;

	ret = ys_k2u_create_txcq(txq);
	if (ret) {
		ys_net_err("txq %d create txcq failed", idx);
		goto txcq_failed;
	}

	if (k2u_ndev->debugfs_dir) {
		snprintf(name, sizeof(name), "txq_%d_info", txq->qid.l_id);
		txq->debugfs_info_file = ops->debugfs_create_file(name, 0400, k2u_ndev->debugfs_dir, txq,
							     &txq_debugfs_fops);
		if (IS_ERR(txq->debugfs_info_file))
			ys_net_err("txq %d create debugfs info file failed", idx);

		snprintf(name, sizeof(name), "txq_%d_txd", txq->qid.l_id);
		txq->debugfs_txd_file = ops->debugfs_create_file(name, 0400, k2u_ndev->debugfs_dir, txq,
							    &txd_debugfs_fops);
		if (IS_ERR(txq->debugfs_txd_file))
			ys_net_err("txq %d create debugfs txd file failed", idx);
	}

	k2u_ndev->qps[idx].txq = txq;

	return 0;

txcq_failed:
property_failed:
	size = sizeof(struct ys_k2u_txd) * depth;
	ops->dma_free_coherent(&ndev_priv->pdev->dev, size, txq->txd, txq->txd_dma_addr);
txq_failed:
	kfree(txq);
	return ret;
}

void ys_k2u_destroy_txq(struct ys_k2u_txq *txq)
{
	const struct ysif_ops *ops = ysif_get_ops();
	struct ys_k2u_ndev *k2u_ndev = txq->k2u_ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);
	size_t size;

	k2u_ndev->qps[txq->qid.l_id].txq = NULL;

	ops->debugfs_remove(txq->debugfs_info_file);
	ops->debugfs_remove(txq->debugfs_txd_file);

	ys_k2u_destroy_txcq(txq);

	size = sizeof(struct ys_k2u_txd) * txq->qdepth;
	ops->dma_free_coherent(&ndev_priv->pdev->dev, size, txq->txd, txq->txd_dma_addr);

	kfree(txq);
}

int ys_k2u_activate_txq(struct ys_k2u_txq *txq)
{
	struct ys_k2u_txcq *txcq = txq->txcq;
	struct ys_k2u_ndev *k2u_ndev = txq->k2u_ndev;
	struct ys_ndev_priv *ndev_priv = netdev_priv(k2u_ndev->ndev);
	struct napi_struct *napi = &ndev_priv->tx_napi_list[txq->qid.l_id].napi;
	const struct ysif_ops *ops = ysif_get_ops();

	ys_ringb_init(&txq->txdrb, txq->qdepth);
	ys_ringb_init(&txcq->txcdrb, txq->qdepth);

	/* txcq */
	txcq->napi = napi;

	ys_wr32(txcq->hw_addr, YS_K2U_RE_TXCQ_HEAD_ADDR_L, (u32)(txcq->txc_head_dma_addr));
	ys_wr32(txcq->hw_addr, YS_K2U_RE_TXCQ_HEAD_ADDR_H, (u32)(txcq->txc_head_dma_addr >> 32));

	ys_wr32(txcq->hw_addr, YS_K2U_RE_TXCQ_IRQ_VECTOR, txcq->irq_vector);

	ys_wr32(txcq->hw_addr, YS_K2U_RE_TXCQ_COAL, txcq->coal);
	ys_wr32(txcq->hw_addr, YS_K2U_RE_TXCQ_PERIOD, txcq->period);

	ys_k2u_txcq_irq_enable(txcq);
	ys_wr32(txcq->hw_addr, YS_K2U_RE_TXCQ_CPLLEN, txcq->qcpllen);

	/* napi */
	ops->ynetif_napi_add(ndev_priv->ndev, napi, ys_k2u_txcq_handler);
	ops->napi_enable(napi);
	txq->tx_queue = ops->netdev_get_tx_queue(k2u_ndev->ndev, txq->qid.l_id);
	ndev_priv->tx_napi_list[txq->qid.l_id].priv_data = txcq;

	/* txq */
	ys_wr32(txq->hw_addr, YS_K2U_RE_TXQ_CTRL, 0);

	ys_wr32(txq->hw_addr, YS_K2U_RE_TXQ_ADDR_L, (u32)(txq->txd_dma_addr));
	ys_wr32(txq->hw_addr, YS_K2U_RE_TXQ_ADDR_H, (u32)(txq->txd_dma_addr >> 32));

	ys_wr32(txq->hw_addr, YS_K2U_RE_TXQ_TAIL, ys_ringb_tail_orig(&txq->txdrb));
	ys_wr32(txq->hw_addr, YS_K2U_RE_TXQ_HEAD, ys_ringb_head_orig(&txq->txdrb));

	ys_wr32(txq->hw_addr, YS_K2U_RE_TXQ_DEPTH, ilog2(txq->qdepth));

	ys_wr32(txq->hw_addr, YS_K2U_RE_TXQ_FRAGSIZE, txq->qfragsize);

	ys_wr32(txq->hw_addr, YS_K2U_RE_TXQ_CTRL, 1);

	txq->active = 1;

	return 0;
}

void ys_k2u_deactivate_txq(struct ys_k2u_txq *txq)
{
	int i;
	u32 txq_head, txq_tail;
	struct ys_ndev_priv *ndev_priv = netdev_priv(txq->k2u_ndev->ndev);
	const struct ysif_ops *ops = ysif_get_ops();

	txq->active = 0;
	for (i = 0; i < 10; i++) {
		txq_head = ys_rd32(txq->hw_addr, YS_K2U_RE_TXQ_HEAD);
		txq_tail = ys_rd32(txq->hw_addr, YS_K2U_RE_TXQ_TAIL);

		if (txq_head == txq_tail)
			break;

		msleep(20);
	}

	if (i >= 10)
		ys_net_err("txq %d clean txq timeout", txq->qid.l_id);

	ys_wr32(txq->hw_addr, YS_K2U_RE_TXQ_CTRL, 0);

	usleep_range(100, 200);

	ys_k2u_txcq_irq_disable(txq->txcq);

	ops->napi_disable(txq->txcq->napi);
	ops->netif_napi_del(txq->txcq->napi);
}

void ys_k2u_clean_txq(struct ys_k2u_txq *txq)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(txq->k2u_ndev->ndev);
	struct ys_k2u_txi *txi;
	u32 count = 0;
	u16 head = ys_ringb_head_orig(&txq->txdrb);
	u16 tail = ys_ringb_tail_orig(&txq->txdrb);
	const struct ysif_ops *ops = ysif_get_ops();

	/* clean txi */
	while (!ys_ringb_empty(&txq->txdrb)) {
		txi = txq->txi + ys_ringb_tail(&txq->txdrb);

		if (txi->addr) {
			ops->ydma_unmap_single(txq->dev, dma_unmap_addr(txi, addr), dma_unmap_len(txi, len), DMA_TO_DEVICE);
			txi->addr = 0;
			txi->len = 0;
		}
		if (txi->skb) {
			ops->dev_kfree_skb_any(txi->skb);
			txi->skb = NULL;
		}

		ys_ringb_pop(&txq->txdrb);
		ys_ringb_pop(&txq->txcq->txcdrb);

		if (count++ > txq->qdepth) {
			ys_net_err("txq %d(head %d tail %d)clean txi error, count %d > qdepth %d\n", txq->qid.l_id, head, tail, count, txq->qdepth);
			break;
		}
	}
}

/****** xmit ******/

static int
ys_k2u_tx_check_scatter(struct ys_k2u_txq *txq, struct ys_k2u_scatter *scatter)
{
	int i;
	struct ys_k2u_sctfrag *frag;
	u16 will_size;
	bool rollback = false;
	u16 ctrld_num;
	struct ys_ringbase txdrb = txq->txdrb;
	bool in_bottom = ys_ringb_in_bottom(&txdrb);
	u16 bottom_left = ys_ringb_bottom_left(&txdrb);

	for (i = 0, will_size = 0; i < ARRAY_SIZE(scatter->frags); i++) {
		frag = &scatter->frags[i];

		if (!frag->seg_num)
			break;
		ctrld_num = frag->tso_valid ? 1 : 0;
		if ((will_size + frag->seg_num + ctrld_num) > bottom_left &&
		    in_bottom && !rollback) {
			will_size = bottom_left;
			rollback = true;
		}
		will_size += frag->seg_num + ctrld_num;
	}

	if (will_size > ys_ringb_left(&txdrb)) {
		txq->stats_sw.err_notxd++;
		return -ENOMEM;
	}

	return 0;
}

static void ys_k2u_txq_bottom_fill_dummy(struct ys_k2u_txq *txq)
{
	u16 i;
	u16 bottom = ys_ringb_bottom_left(&txq->txdrb);
	struct ys_k2u_txd *txd;
	struct ys_k2u_txi *txi;

	for (i = 0; i < bottom; i++) {
		txd = txq->txd + ys_ringb_head(&txq->txdrb);
		txi = txq->txi + ys_ringb_head(&txq->txdrb);

		txd->value = 0;
		txd->fd = 1;
		txd->ld = 1;
		txi->skb = NULL;
		ys_ringb_push(&txq->txdrb);
	}

	txq->stats_sw.num_txdummy += bottom;
}

static int ys_k2u_txcq_handler(struct napi_struct *napi, int napi_budget)
{
	struct ys_napi *ys_napi = container_of(napi, struct ys_napi, napi);
	struct ys_k2u_txcq *txcq = ys_napi->priv_data;
	struct ys_ndev_priv *ndev_priv = netdev_priv(txcq->txq->k2u_ndev->ndev);
	struct ys_k2u_txq *txq = txcq->txq;
	int done = 0;
	struct ys_k2u_txi *txi;
	const struct ysif_ops *ops = ysif_get_ops();

	txcq->stats_sw.num_handler++;
	if (ys_ringb_used(&txcq->txcdrb) > ys_ringb_size(&txcq->txcdrb)) {
		ys_net_err("txcq %d (head %d tail %d) hardware push write back ptr error!!",
			   txq->qid.l_id, txcq->txcdrb.head, txcq->txcdrb.tail);
		goto out;
	}

	while (!ys_ringb_empty(&txcq->txcdrb) && done < napi_budget) {
		txi = txq->txi + ys_ringb_tail(&txcq->txcdrb);

		if (txi->addr) {
			dma_unmap_single(txq->dev, dma_unmap_addr(txi, addr),
					 dma_unmap_len(txi, len), DMA_TO_DEVICE);
			txi->addr = 0;
			txi->len = 0;
		}
		if (txi->skb) {
			txcq->stats_sw.num_freeskb++;
			ops->dev_consume_skb_any(txi->skb);
			txi->skb = NULL;
		}

		ys_ringb_pop(&txcq->txcdrb);
		ys_ringb_pop(&txq->txdrb);
		done++;
	}

	/* wake queue if it is stopped */
	if (ops->netif_tx_queue_stopped(txq->tx_queue) && !ys_k2u_txq_is_full(txq)) {
		txq->stats_sw.num_qwakeup++;
		ops->netif_tx_wake_queue(txq->tx_queue);
	}

	if (done == napi_budget) {
		ops->napi_schedule(napi);
		return done;
	}
out:
	if (ops->napi_complete_done(napi, done))
		ys_k2u_txcq_irq_enable(txq->txcq);

	return done;
}

static noinline __used __attribute__((optimize("O0"))) void
ys_k2u_xmit_tracepoint(struct ys_k2u_txq *txq, struct ys_k2u_scatter *scatter,
		       struct sk_buff *skb, u16 txd_head_start, u16 txd_head_end)
{
}

static inline bool ys_k2u_check_size(struct ys_k2u_txq *txq, struct sk_buff *skb)
{
	int hdrlen = 0;

	if (!skb_is_gso(skb))
		goto not_gso_check;
	else
		goto gso_check;

gso_check:
	if (skb->len <= txq->qpktsize_max) {
		txq->stats_sw.num_smalltso++;
	} else {
		txq->stats_sw.num_bigtso++;
		if (skb_shinfo(skb)->gso_type & (SKB_GSO_TCPV6 | SKB_GSO_TCPV4))
			hdrlen = skb->encapsulation ? (skb_inner_transport_offset(skb) +
				inner_tcp_hdrlen(skb)) : (skb_transport_offset(skb) +
				tcp_hdrlen(skb));
		else if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4)
			hdrlen = skb->encapsulation ? (skb_inner_transport_offset(skb) +
				 sizeof(struct udphdr)) : (skb_transport_offset(skb) +
				 sizeof(struct udphdr));
		if ((skb_headlen(skb) < hdrlen) && (skb_linearize(skb) < 0)) {
			txq->stats_sw.err_linearize++;
			return false;
		}
	}

	return true;

not_gso_check:
	if (unlikely(skb_headlen(skb) > txq->qfragsize || skb->data_len > txq->qfragsize)) {
		txq->stats_sw.over_fragsize++;
		return false;
	}

	if (unlikely(skb->len > txq->qpktsize_max)) {
		txq->stats_sw.over_pktsize++;
		return false;
	}

	return true;
}

netdev_tx_t ys_k2u_new_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	int ret;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_k2u_txq *txq = NULL;
	struct ys_k2u_scatter *scatter = NULL;
	struct ys_k2u_scatter_iter iter_value;
	struct ys_k2u_scatter_iter *iter = &iter_value;
	struct ys_k2u_ctld *ctld;
	struct ys_k2u_txd *txd = NULL;
	struct ys_k2u_txi *txi = NULL;
	bool xmit_more;
	u16 vlan_pri;
	bool is_8021ad;
	u16 txd_head_start;
	u16 txd_head_end;
	bool mangleid;
	const struct ysif_ops *ops = ysif_get_ops();

	/* 1. check */
	if (unlikely(!(ndev->flags & IFF_UP)))
		goto tx_drop;

	txq = k2u_ndev->qps[skb_get_queue_mapping(skb)].txq;
	if (!txq->active)
		goto tx_drop;

	/* 2. check */
	if (unlikely(ys_k2u_txq_is_full(txq))) {
		if (!ops->netif_tx_queue_stopped(txq->tx_queue)) {
			txq->stats_sw.num_qstop++;
			ops->netif_tx_stop_queue(txq->tx_queue);
		}
		goto tx_busy;
	}

	if (unlikely(!ys_k2u_check_size(txq, skb)))
		goto tx_drop;

	/* 3. scatter skb */
	scatter = &txq->scatter;
	ret = ys_k2u_scatter_construct(scatter, txq->dev, skb, txq->qpktsize_max);
	if (ret < 0) {
		if (ret == -ENOMEM)
			txq->stats_sw.err_dmasg++;
		else
			txq->stats_sw.err_scatter++;
		goto tx_drop;
	}

	/* 4. can send ? */
	ret = ys_k2u_tx_check_scatter(txq, scatter);
	if (ret < 0) {
		ys_k2u_scatter_destruct(scatter, txq->dev);
		goto tx_busy;
	}

	txd_head_start = ys_ringb_head_orig(&txq->txdrb);
	mangleid = !!(ndev->features & NETIF_F_TSO_MANGLEID);
	/* 5. for each scatter */
	for (ys_k2u_scatter_iter_start(scatter, iter);
	     ys_k2u_scatter_iter_cond(scatter, iter);
	     ys_k2u_scatter_iter_next(scatter, iter)) {
	/* 6. fill tx desc */
		/* 6.0 fill dummy ? */
		if (iter->seg->fp &&
		    (ys_ringb_bottom_left(&txq->txdrb) <
		    (iter->frag->seg_num + (iter->frag->tso_valid ? 1 : 0))) &&
		    ys_ringb_in_bottom(&txq->txdrb))
			ys_k2u_txq_bottom_fill_dummy(txq);

		/* 6.1 tso and seg fp, so add ctrld*/
		if (iter->frag->tso_valid && iter->seg->fp) {
			ctld = txq->ctld + ys_ringb_head(&txq->txdrb);
			txi = txq->txi + ys_ringb_head(&txq->txdrb);

			ctld->value1 = 0;
			ctld->value2 = 0;

			ctld->tso_en = 1;
			ctld->tso_first = iter->frag->tso_fp;
			ctld->tso_last = iter->frag->tso_lp;
			ctld->mss_num = iter->frag->mss_num;

			ys_k2u_ctld_set_mss(ctld, cpu_to_le16(skb_shinfo(skb)->gso_size));

			ctld->control = 1;
			ctld->fd = 1;
			txi->skb = NULL;
			ys_ringb_push(&txq->txdrb);
			txq->stats_sw.num_txd++;
			txq->stats_sw.num_txdfd++;
		}

		/* 6.2 fill txd */
		txd = txq->txd + ys_ringb_head(&txq->txdrb);
		txi = txq->txi + ys_ringb_head(&txq->txdrb);

		txd->value = 0;
		txd->addr = cpu_to_le64(iter->seg->addr);
		txd->size = cpu_to_le16(iter->seg->len);
		txd->ppp_sysm_disable = 1;
		txd->tso_fixed_id = (iter->frag->tso_valid && mangleid) ? 0 : 1;
		ys_k2u_txd_set_qgroup(txd, txq->qgroup);
		txd->local_priority = txq->qgroup & 0x7;

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			if (skb->encapsulation) {
				txd->outer_l3_csum_en = 1;
				if (ops->skb_is_gso(skb) && (skb_shinfo(skb)->gso_type & (SKB_GSO_UDP_TUNNEL_CSUM | SKB_GSO_GRE_CSUM)))
					txd->outer_l4_csum_en = 1;
				txd->inner_l3_csum_en = 1;
				txd->inner_l4_csum_en = 1;
			} else {
				txd->outer_l3_csum_en = 1;
				txd->outer_l4_csum_en = 1;
			}
		}

		if (skb_vlan_tag_present(skb)) {
			if ((iter->frag->tso_valid && iter->frag->tso_fp && iter->seg->fp) ||
			    (!iter->frag->tso_valid && iter->seg->fp))
				txq->stats_sw.num_vlaninsert++;

			vlan_pri = (skb_vlan_tag_get(skb) & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
			is_8021ad =  (skb->vlan_proto == htons(ETH_P_8021AD)) ? true : false;
			ys_k2u_txd_set_vlan(txd, skb_vlan_tag_get(skb), vlan_pri, is_8021ad);
		}

		txd->fd = (iter->seg->fp && (!iter->frag->tso_valid)) ? 1 : 0;
		txd->ld = iter->seg->lp;

		if (txd->fd)
			txq->stats_sw.num_txdfd++;
		if (txd->ld)
			txq->stats_sw.num_txdld++;

		if (iter->unmap && iter->sctl) {
			dma_unmap_addr_set(txi, addr, dma_unmap_addr(iter->sctl, addr));
			dma_unmap_len_set(txi, len, dma_unmap_len(iter->sctl, len));
		}

		ys_ringb_push(&txq->txdrb);
		txq->stats_sw.num_txd++;
	}

	txd->interrupt = 1;
	if (txi)
		txi->skb = skb;

	txd_head_end = ys_ringb_head_orig(&txq->txdrb) - 1;
	ys_k2u_xmit_tracepoint(txq, scatter, skb, txd_head_start, txd_head_end);

	/* 7. other */
	txq->stats_base.packets++;
	txq->stats_base.bytes += skb->len;
	ops->skb_tx_timestamp(skb);

	/* 8. doorbell */
	xmit_more = ops->netdev_xmit_more();
	if (!xmit_more)
		ys_k2u_txq_doorbell(txq);

	return NETDEV_TX_OK;

tx_drop:
	if (txq)
		txq->stats_base.drops++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
tx_busy:
	return NETDEV_TX_BUSY;
}
