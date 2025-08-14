/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_NEW_RX_H__
#define __YS_K2U_NEW_RX_H__

#include "ys_k2u_new_base.h"
#include "ys_k2u_new_hw.h"

#define YS_K2U_N_RX_IRQ_PERIOD		16
#define YS_K2U_N_RX_IRQ_COAL		16
#define YS_K2U_N_RX_PERIOD		16
#define YS_K2U_N_RX_COAL		16

#define YS_K2U_N_RX_MINDATA		256

struct ys_k2u_rxc_stats_sw {
	u64 num_interrupt;
	u64 num_schedule;
	u64 num_handler;
	u64 num_unicast_desc;
	u64 num_unicast_pkt;
	u64 num_multicast_desc;
	u64 num_multicast_pkt;
	u64 num_broadcast_desc;
	u64 num_broadcast_pkt;
	u64 num_vlan_8021ad;
	u64 num_vlan_8021q;
	u64 num_vlan_remove;
	u64 num_lro_desc;
	u64 num_lro_pkt;
	u64 num_chkcpl_desc;
	u64 num_chkcpl_pkt;
	u64 num_csum_unchk[16];
	u64 err_nopage;
	u64 err_rcvsize;
	u64 err_fcs_desc;
	u64 err_fcs_pkt;
	u64 err_mtu_desc;
	u64 err_mtu_pkt;
	u64 err_edma_desc;
	u64 err_edma_pkt;
	u64 err_ol3_csum_desc;
	u64 err_ol3_csum_pkt;
	u64 err_ol4_csum_desc;
	u64 err_ol4_csum_pkt;
	u64 err_il3_csum_desc;
	u64 err_il3_csum_pkt;
	u64 err_il4_csum_desc;
	u64 err_il4_csum_pkt;
	u64 err_pktcutoff_desc;
	u64 err_pktcutoff_pkt;
	u64 err_pkttimeo_desc;
	u64 err_pkttimeo_pkt;
	u64 err_unknown_desc;
	u64 err_alloc_skb;
	u64 err_gather;
};

struct ys_k2u_rxc_stats_rss_redir {
	u64 num_rss_redir_idx[64];
};

struct ys_k2u_rx_stats_sw {
	u64 err_alloc_page;
	u64 err_map_page;
};

struct ys_k2u_rxi {
	struct page *page;
	dma_addr_t dma_addr;
	struct sk_buff *skb;
};

struct ys_k2u_rxcq {
	struct ys_ringbase rxcdrb;
	struct ys_k2u_rxcd *rxcd;
	struct ys_k2u_rxq *rxq;
	struct ys_k2u_stats_base stats_base;

	/* more stats */
	struct ys_k2u_rxc_stats_sw stats_sw;
	struct ys_k2u_rxc_stats_rss_redir stats_rss_redir;

	struct notifier_block irq_nb;
	struct napi_struct *napi;

	/* config params */
	u32 irq_vector;
	u32 irq_period;
	u32 irq_coal;
	u32 period;
	u32 coal;
	u32 irq_disable;

	/* head dma */
	dma_addr_t rxcd_dma_addr;
	dma_addr_t rxc_head_dma_addr;

	void __iomem *hw_addr;
};

struct ys_k2u_rxq {
	/* rx rxc rxi */
	struct ys_ringbase rxdrb;
	struct ys_k2u_rxd *rxd;
	struct ys_k2u_rxi *rxi;

	struct device *dev;
	struct ys_k2u_rxcq *rxcq;

	struct ys_k2u_rx_stats_sw stats_sw;

	/* hw addr */
	void __iomem *hw_addr;

	/* config params */
	u32 qdepth;
	u32 qfragsize;
	u32 fragorder;

	/* property */
	struct ys_k2u_queueid qid;
	u16 active:1;
	u16 qdepth_max_power;
	u32 qdepth_max;
	u32 qfragsize_max;

	/* pointer */
	struct ys_k2u_ndev *k2u_ndev;

	dma_addr_t rxd_dma_addr;

	/* debug */
	struct dentry *debugfs_info_file;
	struct dentry *debugfs_rxd_file;
	struct dentry *debugfs_rxcd_file;
};

static inline void ys_k2u_rxcq_irq_enable(struct ys_k2u_rxcq *rxcq)
{
	wmb();	/* guarantee sequence */
	rxcq->irq_disable = 0;
	ys_wr32(rxcq->hw_addr, YS_K2U_RE_RXCQ_IRQ_DISABLE, 0);
}

static inline void ys_k2u_rxcq_irq_disable(struct ys_k2u_rxcq *rxcq)
{
	wmb();	/* guarantee sequence */
	rxcq->irq_disable = 1;
	ys_wr32(rxcq->hw_addr, YS_K2U_RE_RXCQ_IRQ_DISABLE, 1);
}

static inline void ys_k2u_rxq_doorbell(struct ys_k2u_rxq *rxq)
{
	ys_wr32(rxq->hw_addr, YS_K2U_RE_RXQ_HEAD, ys_ringb_head_orig(&rxq->rxdrb));
}

int ys_k2u_create_rxq(struct ys_k2u_ndev *k2u_ndev, u16 idx, u32 depth);
void ys_k2u_destroy_rxq(struct ys_k2u_rxq *rxq);
int ys_k2u_activate_rxq(struct ys_k2u_rxq *rxq);
void ys_k2u_deactivate_rxq(struct ys_k2u_rxq *rxq);
void ys_k2u_clean_rxq(struct ys_k2u_rxq *rxq);

#endif /* __YS_K2U_NEW_RX_H__ */
