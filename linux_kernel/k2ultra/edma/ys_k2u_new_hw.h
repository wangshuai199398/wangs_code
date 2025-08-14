/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _YS_K2U_NEW_HW_H_
#define _YS_K2U_NEW_HW_H_

#include "ys_k2u_new_base.h"

/* k2u register errno */
#define YS_K2U_N_REG_EPERM		(0xdeaddecd)
#define YS_K2U_N_REG_UNUSED		(0xdeadc0d9)
static inline bool ys_k2u_reg_err(u32 val)
{
	return (val == YS_K2U_N_REG_EPERM) || (val == YS_K2U_N_REG_UNUSED);
}

/******* k2u register edma *******/
#define YS_K2U_RE_BASE                  0x00000000

#define YS_K2U_RE_DMA_BASE		(YS_K2U_RE_BASE + 0x00000)

#define YS_K2U_RE_DMA_ID		(0x0000)
#define YS_K2U_RE_DMA_INST		(0x0004)
#define YS_K2U_RE_DMA_QNUM		(0x0008)
#define YS_K2U_RE_DMA_QSETNUM		(0x000c)

#define YS_K2U_RE_DMA_PFX_FNUM(i)	(0x0010 + ((i) * 0x4))
#define YS_K2U_RE_DMA_PF_FTOP_GMASK	GENMASK(31, 16)
#define YS_K2U_RE_DMA_PF_FBASE_GMASK	GENMASK(15, 0)

#define YS_K2U_RE_DMA_QSET_OFFSET	(0x0034)
#define YS_K2U_RE_DMA_QSET_OFFSET_GMASK		GENMASK(10, 0)
#define YS_K2U_RE_DMA_QSET_QMAXNUM_GMASK	GENMASK(19, 16)

#define YS_K2U_RE_DMA_PFX_QBASE(i)	(0x0040 + ((i) * 0x4))
#define YS_K2U_RE_DMA_PF_QSTART_GMASK	GENMASK(9, 0)
#define YS_K2U_RE_DMA_PF_QNUM_GMASK	GENMASK(25, 16)

#define YS_K2U_RE_DMA_FUNC_QBASE	(0x2000)
#define YS_K2U_RE_DMA_FUNCX_QBASE(i)	(0x2000 + ((i) * 0x4))
#define YS_K2U_RE_DMA_FUNC_QSTART_GMASK	GENMASK(9, 0)
#define YS_K2U_RE_DMA_FUNC_QNUM_GMASK	GENMASK(25, 16)

/* queue */
#define YS_K2U_RE_QUEUE_BASE            (YS_K2U_RE_BASE + 0x40000)
#define YS_K2U_RE_QX_BASE(i)            (YS_K2U_RE_QUEUE_BASE + ((i) * 0x100))

#define YS_K2U_RE_TXQ_ADDR_L		0x00
#define YS_K2U_RE_TXQ_ADDR_H		0x04
#define YS_K2U_RE_TXQ_HEAD		0x08
#define YS_K2U_RE_TXQ_TAIL		0x0c
#define YS_K2U_RE_TXQ_DEPTH		0x10
#define YS_K2U_RE_TXQ_DEPTH_MAX		0x14
#define YS_K2U_RE_TXQ_FRAGSIZE		0x18
#define YS_K2U_RE_TXQ_FRAGSIZE_MAX	0x1c
#define YS_K2U_RE_TXQ_CTRL		0x20

#define YS_K2U_RE_TXCQ_HEAD_ADDR_L	0x48
#define YS_K2U_RE_TXCQ_HEAD_ADDR_H	0x4c
#define YS_K2U_RE_TXCQ_HEAD		0x50
#define YS_K2U_RE_TXCQ_IRQ_VECTOR	0x54
#define YS_K2U_RE_TXCQ_COAL		0x58
#define YS_K2U_RE_TXCQ_PERIOD		0x5c
#define YS_K2U_RE_TXCQ_IRQ_DISABLE	0x60
#define YS_K2U_RE_TXCQ_CPLLEN		0x64

enum ys_k2u_txcq_cpllen {
	CPLLEN_2K = 0,
	CPLLEN_4K,
	CPLLEN_8K,
	CPLLEN_16K,
	CPLLEN_32K,
	CPLLEN_64K,
	CPLLEN_128K,
	CPLLEN_NOLIMIT,
};

#define YS_K2U_RE_RXQ_ADDR_L		0x80
#define YS_K2U_RE_RXQ_ADDR_H		0x84
#define YS_K2U_RE_RXQ_HEAD		0x88
#define YS_K2U_RE_RXQ_TAIL		0x8c
#define YS_K2U_RE_RXQ_DEPTH		0x90
#define YS_K2U_RE_RXQ_DEPTH_MAX		0x94
#define YS_K2U_RE_RXQ_FRAGSIZE		0x98
#define YS_K2U_RE_RXQ_FRAGSIZE_MAX	0x9c
#define YS_K2U_RE_RXQ_CTRL		0xa0

#define YS_K2U_RE_RXCQ_ADDR_L		0xc0
#define YS_K2U_RE_RXCQ_ADDR_H		0xc4
#define YS_K2U_RE_RXCQ_HEAD_ADDR_L	0xc8
#define YS_K2U_RE_RXCQ_HEAD_ADDR_H	0xcc
#define YS_K2U_RE_RXCQ_HEAD		0xd0
#define YS_K2U_RE_RXCQ_IRQ_VECTOR	0xd4
#define YS_K2U_RE_RXCQ_IRQ_PERIOD	0xd8
#define YS_K2U_RE_RXCQ_IRQ_COAL		0xdc
#define YS_K2U_RE_RXCQ_PERIOD		0xe0
#define YS_K2U_RE_RXCQ_COAL		0xe4
#define YS_K2U_RE_RXCQ_IRQ_DISABLE	0xe8

#define YS_K2U_V_RXQ_RXCLR		BIT(1)
#define YS_K2U_V_RXQ_RXEMPTY		BIT(4)

#define YS_K2U_RE_QSET2Q_BASE		(YS_K2U_RE_BASE + 0x4000)
#define YS_K2U_RE_QSET2Q(i)		(YS_K2U_RE_QSET2Q_BASE + ((i) * 0x4))

#define YS_K2U_RE_QSET2Q_QSTART_GMASK	GENMASK(9, 0)
#define YS_K2U_RE_QSET2Q_RSS_REDIRECT_EN	BIT(10)
#define YS_K2U_RE_QSET2Q_QNUM_GMASK	GENMASK(18, 11)
#define YS_K2U_RE_QSET2Q_VALID_GMASK	GENMASK(19, 19)
#define YS_K2U_RE_QSET2Q_PRITYPE_GMASK	GENMASK(25, 20)
#define YS_K2U_RE_QSET2Q_CBSBASE_GMASK	GENMASK(31, 26)

#define YS_K2U_RE_Q2QSET_BASE		(YS_K2U_RE_BASE + 0x8000)
#define YS_K2U_RE_Q2QSET(i)		(YS_K2U_RE_Q2QSET_BASE + ((i) * 0x4))
#define YS_K2U_RE_Q2QSET_QSETID_GMASK	GENMASK(9, 0)

/* function */
#define YS_K2U_RE_FUNC_BASE		(YS_K2U_RE_BASE + 0x2000)
#define YS_K2U_RE_FUNCX_QUEUE(i)	(0x04 * (i))

/* pcie */
#define YS_K2U_RP_PFVFID		(0x220014)
#define YS_K2U_RP_PFID_GMASK		GENMASK(31, 16)
#define YS_K2U_RP_VFID_GMASK		GENMASK(15, 0)

#define YS_K2U_RP_VFX_IRQNUM(i)		(0x120000 + ((i) * 0x4))
#define YS_K2U_RP_VFX_IRQNUM_GMASK	GENMASK(11, 0)

/* hqos */
#define YS_K2U_RQ_BASE			0x800000
#define YS_K2U_RQ_TBDATA(i)		(YS_K2U_RQ_BASE + ((i) << 2))
#define YS_K2U_RQ_TBMASK(i)		(YS_K2U_RQ_BASE + 0x20 + ((i) << 2))
#define YS_K2U_RQ_TBADDR		(YS_K2U_RQ_BASE + 0x40)
#define YS_K2U_RQ_TBVALID		(YS_K2U_RQ_BASE + 0x44)

#define YS_K2U_N_HQOS_MCLK		(100)	/* 100M */

/* rss redirect sacle & bias & sw_fr */
#define YS_K2U_RSS_REDIRECT_SCALE_BIAS_ADDR	0x80
#define YS_K2U_RSS_REDIRECT_SCALE		GENMASK(7, 6)
#define YS_K2U_RSS_REDIRECT_BIAS		GENMASK(11, 8)
#define YS_K2U_RSS_REDIRECT_SW_FR		BIT(12)
/* default value */
#define YS_K2U_RSS_REDIRECT_SCALE_POWER_VALUE	2
#define YS_K2U_RSS_REDIRECT_BIAS_VALUE	0
#define YS_K2U_RSS_REDIRECT_SW_FR_VALUE	0

/* rss redirect table */
#define YS_K2U_RSS_REDIRECT_BASE	0x9000
/* rss key */
#define YS_K2U_RSS_KEY_ADDR		0xd00140
#define YS_K2U_RSS_HASH_KEY_SIZE	40

struct ys_k2u_txd {
	u64 addr;
	union {
		u64 value;
		struct {
#ifndef __BIG_ENDIAN_BITFIELD
			u64 size:16;

			u64 reserved1:1;
			u64 lan_pars_disable:1;		/* turn off lan parser */
			u64 ppp_sysm_disable:1;		/* ppp can not modify sysmeta */
			u64 ppp_bypass:1;		/* ??? */
			u64 local_priority:3;
			u64 q_group:5;
			u64 pass_through:1;
			u64 outer_l3_csum_en:1;		/* support ipv4 & ipv6 */
			u64 outer_l4_csum_en:1;		/* support tcp & udp */
			u64 inner_l3_csum_en:1;		/* support ipv4 & ipv6 */

			u64 inner_l4_csum_en:1;		/* support tcp & udp */
			u64 tso_fixed_id:1;
			u64 vlan_protocol_type:1;	/* 0: 802.1q, 1: 802.1ad used with vlan */
			u64 ptp_sync:1;
			u64 soft_def:8;			/* used with np */
			u64 vlan_id_h:4;

			u64 vlan_valid:1;
			u64 vlan_pri:3;
			u64 vlan_id_l:8;
			u64 control:1;
			u64 interrupt:1;
			u64 fd:1;
			u64 ld:1;
#else
			u64 size:16;

			u64 q_group_1:1;		/* q_group least significant bit */
			u64 local_priority:3;
			u64 ppp_bypass:1;		/* ??? */
			u64 ppp_sysm_disable:1;		/* ppp can not modify sysmeta */
			u64 lan_pars_disable:1;		/* turn off lan parser */
			u64 reserved1:1;
			u64 inner_l3_csum_en:1;		/* support ipv4 & ipv6 */
			u64 outer_l4_csum_en:1;		/* support tcp & udp */
			u64 outer_l3_csum_en:1;		/* support ipv4 & ipv6 */
			u64 pass_through:1;
			u64 q_group_2:4;		/* q_group most significant bit */

			u64 soft_def_1:4		/* used with np, least significant bit */
			u64 ptp_sync:1;
			u64 vlan_protocol_type:1;	/* 0: 802.1q, 1: 802.1ad used with vlan */
			u64 tso_fixed_id:1;
			u64 inner_l4_csum_en:1;		/* support tcp & udp */
			u64 vlan_id_h:4;
			u64 soft_def_2:4		/* used with np, most significant bit */

			u64 vlan_id_l_1:4;		/* vlan_id_l least significant bit */
			u64 vlan_pri:3;
			u64 vlan_valid:1;
			u64 ld:1;
			u64 fd:1;
			u64 interrupt:1;
			u64 control:1;
			u64 vlan_id_l_2:4;		/* vlan_id_l most significant bit */
#endif
		};
	};
};

static inline void ys_k2u_txd_set_qgroup(struct ys_k2u_txd *txd, u16 qg)
{
#ifndef __BIG_ENDIAN_BITFIELD
	txd->q_group = qg & 0x1f;
#else
	txd->q_group_1 = qg & 0x1;
	txd->q_group_2 = (qg >> 1) & 0xf;
#endif
}

static inline void ys_k2u_txd_set_softdef(struct ys_k2u_txd *txd, u8 softdef)
{
#ifndef __BIG_ENDIAN_BITFIELD
	txd->soft_def = softdef;
#else
	txd->soft_def_1 = softdef & 0xf;
	txd->soft_def_2 = (softdef >> 4) & 0xf;
#endif
}

static inline void
ys_k2u_txd_set_vlan(struct ys_k2u_txd *txd, u16 vlan_id, u8 vlan_pri, bool is_8021ad)
{
	txd->vlan_valid = 1;
#ifndef __BIG_ENDIAN_BITFIELD
	txd->vlan_id_l = vlan_id & 0xff;
#else
	txd->vlan_id_l_1 = vlan_id & 0xf;
	txd->vlan_id_l_2 = (vlan_id >> 4) & 0xf;
#endif
	txd->vlan_id_h = (vlan_id >> 8) & 0xf;
	txd->vlan_pri = vlan_pri & 0x7;

	txd->vlan_protocol_type = is_8021ad ? 1 : 0;
}

struct ys_k2u_ctld {
	union {
		u64 value1;
		struct {
#ifndef __BIG_ENDIAN_BITFIELD
			u64 reserved1:8;
			u64 mss_num:7;
			u64 tso_en:1;
			u64 mss_h:6;
			u64 tso_first:1;
			u64 tso_last:1;
			u64 mss_l:8;
#else
			u64 reserved1:8;
			u64 tso_en:1;
			u64 mss_num:7;
			u64 tso_last:1;
			u64 tso_first:1;
			u64 mss_h:6;
			u64 mss_l:8;
#endif
			u64 desc_ctrl:16;
			u64 parser_hash_l:8;
			u64 last_offset:8;
		};
	};

	union {
		u64 value2;
		struct {
			u64 bit_flag:32;
			u64 parser_hash_h:16;
			u64 reserved3:8;
#ifndef __BIG_ENDIAN_BITFIELD
			u64 reserved4:4;
			u64 control:1;
			u64 interrupt:1;
			u64 fd:1;
			u64 ld:1;
#else
			u64 ld:1;
			u64 fd:1;
			u64 interrupt:1;
			u64 control:1;
			u64 reserved4:4;
#endif
		};
	};
};

static inline void ys_k2u_ctld_set_mss(struct ys_k2u_ctld *ctld, u16 mss)
{
	ctld->mss_l = mss & 0xff;
	ctld->mss_h = (mss >> 8) & 0x3f;
}

struct ys_k2u_rxd {
	u64 addr;
};

struct ys_k2u_rxcd {
	union {
		u64 value1;
		struct {
			u64 size:16;
			u64 desc_id:16;
#ifndef __BIG_ENDIAN_BITFIELD
			u64 fcs_error:1;		/* used by mac, stats and drop it */
			u64 vlan_tag_remove:1;
			u64 mtu_error:1;  /* used by lan, exceed mtu setting, stats and drop it */
			u64 vlan_protocol_type:1;	/* 0: 802.1q, 1: 802.1ad used with vlan */
			u64 ptp_rec:1;
			u64 soft_def:8;
			u64 vlan_id_h:4;
			u64 vlan_valid:1;
			u64 vlan_pri:3;
			u64 vlan_id_l:8;
			u64 edma_error:1;		/* used by edma, stats and drop it */
			u64 fd:1;
			u64 ld:1;
#else
			u64 soft_def_1:3		/* least significant bit */
			u64 ptp_rec:1;
			u64 vlan_protocol_type:1;	/* 0: 802.1q, 1: 802.1ad used with vlan */
			u64 mtu_error:1;  /* used by lan, exceed mtu setting, stats and drop it */
			u64 vlan_tag_remove:1;
			u64 fcs_error:1;		/* used by mac, drop it */

			u64 vlan_id_h_1:3;
			u64 soft_def_2:5;

			u64 vlan_id_l_1:3;
			u64 vlan_pri:3;
			u64 vlan_valid:1;
			u64 vlan_id_h_2:1;

			u64 ld:1;
			u64 fd:1;
			u64 edma_error:1;		/* used by edma, stats and drop it */
			u64 vlan_id_l_2:5;
#endif
		};
	};
	union {
		u64 value2;
		struct {
#ifndef __BIG_ENDIAN_BITFIELD
			u64 hash_result:16;		/* used by lan for RXHASH */

			u64 inner_l4_csum_unchk:1;
			u64 inner_l4_csum_error:1;	/* used by lan or np, stats and drop it */
			u64 inner_l3_csum_unchk:1;
			u64 inner_l3_csum_error:1;	/* used by lan or np, stats and drop it */
			u64 outer_l4_csum_unchk:1;
			u64 outer_l4_csum_error:1;	/* used by lan or np, stats and drop it */
			u64 outer_l3_csum_unchk:1;
			u64 outer_l3_csum_error:1;	/* used by lan or np, stats and drop it */

			u64 cast_type:2;		/* 00b : unicast, 01b : multicast */
			u64 pkt_timeout:1;		/* used by lan, stats and drop it */
			u64 pkt_cutoff:1;		/* used by lan, stats and drop it */
			u64 csum_complete_valid:1;	/* used by np for checksum complete */
			u64 lro_valid:1;		/* used by np for lro */
			u64 reserved2:2;

			u64 csum_complete:16;		/* csum complete value from ip */
			u64 lro_id:16;			/* used by np for lro */
#else
			u64 hash_result:16;		/* used by lan for RXHASH */

			u64 outer_l3_csum_error:1;	/* used by lan or np, stats and drop it */
			u64 outer_l3_csum_unchk:1;
			u64 outer_l4_csum_error:1;	/* used by lan or np, stats and drop it */
			u64 outer_l4_csum_unchk:1;
			u64 inner_l3_csum_error:1;	/* used by lan or np, stats and drop it */
			u64 inner_l3_csum_unchk:1;
			u64 inner_l4_csum_error:1;	/* used by lan or np, stats and drop it */
			u64 inner_l4_csum_unchk:1;

			u64 reserved2:2;
			u64 lro_valid:1;		/* used by np for lro */
			u64 csum_complete_valid:1;	/* used by np for checksum complete */
			u64 pkt_cutoff:1;		/* used by lan, stats and drop it */
			u64 pkt_timeout:1;		/* used by lan, stats and drop it */
			u64 cast_type:2;		/* 00b : unicast, 01b : multicast */

			u64 csum_complete:16;		/* csum complete value from ip */
			u64 lro_id:16;			/* used by np for lro */
#endif
		};
	};
};

static inline u16 ys_k2u_rxcd_get_vlanid(struct ys_k2u_rxcd *rxcd)
{
#ifndef __BIG_ENDIAN_BITFIELD
	return (rxcd->vlan_id_h << 8) | rxcd->vlan_id_l;
#else
	return (rxcd->vlan_id_h_2 << (8 + 3)) | (rxcd->vlan_id_h_1 << 8) |
	       (rxcd->vlan_id_l_2 << 3) | (rxcd->vlan_id_l_1);
#endif
}

#endif /* _YS_K2U_NEW_HW_H_ */
