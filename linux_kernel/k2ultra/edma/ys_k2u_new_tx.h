/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_NEW_TX_H__
#define __YS_K2U_NEW_TX_H__

#include "ys_k2u_new_base.h"
#include "ys_k2u_new_hw.h"
#include "ys_k2u_scatter.h"

#define YS_K2U_N_TXCQ_COAL		16
#define YS_K2U_N_TXCQ_PERIOD		2000

#define YS_K2U_N_TSO_MAXSIZE		65535
#define YS_K2U_N_TSO_MAXSEGS		720

struct ys_k2u_tx_stats_sw {
	u64 num_smalltso;
	u64 num_bigtso;
	u64 num_txd;
	u64 num_txdummy;
	u64 num_txdfd;
	u64 num_txdld;
	u64 num_vlaninsert;
	u64 over_fragsize;
	u64 over_pktsize;
	u64 err_dmasg;
	u64 err_linearize;
	u64 err_scatter;
	u64 err_notxd;
	u64 num_qstop;
	u64 num_qwakeup;
};

struct ys_k2u_txc_stats_sw {
	u64 num_freeskb;
	u64 num_interrupt;
	u64 num_schedule;
	u64 num_handler;
};

/* tx info */
/* todo : too big, need to optimize */
struct ys_k2u_txi {
	struct sk_buff *skb;
	dma_addr_t addr;
	u32 len;
} ____cacheline_aligned;

struct ys_k2u_port;

struct ys_k2u_txq {
	/* tx & txc & txi */
	struct ys_ringbase txdrb;
	union {
		struct ys_k2u_txd *txd;
		struct ys_k2u_ctld *ctld;
	};
	struct ys_k2u_txi *txi;

	struct device *dev;
	struct ys_k2u_stats_base stats_base;

	/* hw addr */
	void __iomem *hw_addr;

	/* more stats */
	struct ys_k2u_tx_stats_sw stats_sw;

	/* config params */
	u16 qgroup;
	u16 qgroup_request;
	u32 qdepth;
	u32 qfragsize;

	/* property */
	struct ys_k2u_queueid qid;
	u16 active:1;
	u16 qdepth_max_power;
	u32 qdepth_max;
	u32 qfragsize_max;
	u32 qpktsize_max;
	u32 reserve;	/* for future use */

	/* pointer */
	struct ys_k2u_ndev *k2u_ndev;
	struct ys_k2u_txcq *txcq;
	struct netdev_queue *tx_queue;

	dma_addr_t txd_dma_addr;
	/* debug */
	struct dentry *debugfs_info_file;
	struct dentry *debugfs_txd_file;

	/* scatter */
	struct ys_k2u_scatter scatter;
} ____cacheline_aligned;

struct ys_k2u_txcq {
	/* txcd, txq */
	struct ys_ringbase txcdrb;
	struct ys_k2u_txq *txq;
	struct notifier_block irq_nb;
	struct napi_struct *napi;

	struct ys_k2u_txc_stats_sw stats_sw;

	/* config params */
	enum ys_k2u_txcq_cpllen qcpllen;
	u32 irq_vector;
	u32 coal;
	u32 period;
	u32 irq_disable;

	/* head dma */
	dma_addr_t txc_head_dma_addr;

	void __iomem *hw_addr;
} ____cacheline_aligned;

static inline void ys_k2u_txcq_irq_enable(struct ys_k2u_txcq *txcq)
{
	wmb();	/* guarantee sequence */
	txcq->irq_disable = 0;
	ys_wr32(txcq->hw_addr, YS_K2U_RE_TXCQ_IRQ_DISABLE, 0);
}

static inline void ys_k2u_txcq_irq_disable(struct ys_k2u_txcq *txcq)
{
	wmb();	/* guarantee sequence */
	txcq->irq_disable = 1;
	ys_wr32(txcq->hw_addr, YS_K2U_RE_TXCQ_IRQ_DISABLE, 1);
}

static inline void ys_k2u_txq_doorbell(struct ys_k2u_txq *txq)
{
	ys_wr32(txq->hw_addr, YS_K2U_RE_TXQ_HEAD, ys_ringb_head_orig(&txq->txdrb));
}

static inline bool ys_k2u_txq_is_full(struct ys_k2u_txq *txq)
{
	return (ys_ringb_left(&txq->txdrb) < 8);
}

int ys_k2u_create_txq(struct ys_k2u_ndev *k2u_ndev, u16 idx, u32 depth);
void ys_k2u_destroy_txq(struct ys_k2u_txq *txq);
int ys_k2u_activate_txq(struct ys_k2u_txq *txq);
void ys_k2u_deactivate_txq(struct ys_k2u_txq *txq);
void ys_k2u_clean_txq(struct ys_k2u_txq *txq);
netdev_tx_t ys_k2u_new_start_xmit(struct sk_buff *skb, struct net_device *ndev);

#endif /* __YS_K2U_NEW_TX_H__ */
