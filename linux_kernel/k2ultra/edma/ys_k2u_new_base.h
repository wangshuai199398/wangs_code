/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_NEW_BASE_H__
#define __YS_K2U_NEW_BASE_H__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/skbuff.h>

#include <linux/device.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>

#include <linux/debugfs.h>
#include <linux/scatterlist.h>

#include <linux/tcp.h>
#include <uapi/linux/udp.h>

#include <linux/moduleparam.h>
#include <linux/refcount.h>

#include "ys_platform.h"
#include "ys_adapter.h"
#include "ys_debug.h"
#include "ys_reg_ops.h"

struct ys_k2u_queueid {
	u16 g_id;	/* global id */
	u16 p_id;	/* pf queue id */
	u16 f_id;	/* function queue id */
	u16 l_id;	/* local queue id */
};

struct ys_k2u_queuebase {
	u16 start;
	u16 num;
};

struct ys_k2u_stats_base {
	u64 packets;
	u64 bytes;
	u64 errors;
	u64 drops;
};

#include "ys_ringbase.h"

#define YS_K2U_N_MAX_QDEPTH		(32768U)
#define YS_K2U_N_MIN_QDEPTH		(64U)
#define YS_K2U_N_MAX_TXPKTLEN		(9696)
#define YS_K2U_N_MAX_TXFRAGSIZE		(12288)

#ifndef CONFIG_MAX_SKB_FRAGS
#define CONFIG_MAX_SKB_FRAGS		(17)
#endif

#define YS_K2U_N_MAX_SCTLIST		(CONFIG_MAX_SKB_FRAGS + 1)
#define YS_K2U_N_MAX_SCTFRAGS		(16)
#define YS_K2U_N_MAX_SCTSEGS		(128)
#define YS_K2U_N_MAX_TXD		(16)

#define YS_K2U_N_MIN_QGROUP		(0)
#define YS_K2U_N_MAX_QGROUP		((1 << 5) - 1)

#define YS_K2U_N_MAX_PF			(8)
#define YS_K2U_N_PF_MAX_FUNC		(512)
#define YS_K2U_N_MAX_VF			(YS_K2U_N_PF_MAX_FUNC - 1)

#define YS_K2U_N_PF_MAXQNUM		(16)
#define YS_K2U_N_VF_MAXQNUM		(16)
#define YS_K2U_N_UPLINK_MAXQNUM		(8)
#define YS_K2U_N_REP_MAXQNUM		(4)

#define YS_K2U_ID_NDEV_UPLINK		(0x200)
#define YS_K2U_ID_NDEV_PFREP		(0)
#define YS_K2U_ID_NDEV_VFREP(id)	((id) + 1)
#define YS_K2U_ID_NDEV_VFREP_TO_ID(rep_id)	((rep_id) - 1)

#define YS_K2U_ID_MAC_QSETID(i)		(0x800 + (i))

#define YS_K2U_N_NDEV_DEFAULT_DEPTH	(1024U)

enum ys_k2u_ndev_type {
	YS_K2U_NDEV_UPLINK,
	YS_K2U_NDEV_REP,
	YS_K2U_NDEV_PF,
	YS_K2U_NDEV_VF,
	YS_K2U_NDEV_SF,
};

enum ys_k2u_queue_type {
	YS_K2U_QUEUE_LOCAL,
	YS_K2U_QUEUE_FUNC,
	YS_K2U_QUEUE_PF,
	YS_K2U_QUEUE_GLOBAL,
};

#endif /* __YS_K2U_NEW_BASE_H__ */
