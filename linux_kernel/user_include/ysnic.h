/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YSNIC_H_
#define __YSNIC_H_

enum ys_dpu_mode {
	MODE_LEGACY = 1,
	MODE_DPU_HOST = 2,
	MODE_SMART_NIC = 3,
	MODE_DPU_SOC = 4
};

enum ys_doe_ctrl_cmd {
	ADD_MAC_FILTER = 0,
	DEL_MAC_FILTER = 1,
	FIND_MAC_FILTER = 2,
	ADD_MULTICAST = 3,
	DEL_MULTICAST = 4,
	FIND_MULTICAST = 5
};

#define YSIOCTL_TYPE 'x'

#define YS_IOCTL_OP_READ 0
#define YS_IOCTL_OP_WRITE 1

enum {
	YS_SET_MTU = (1ULL << 0),
	YS_SET_MAC = (1ULL << 1),
	YS_SET_RX_QSET_HASH = (1ULL << 2),
	YS_SET_RX_PROMISC = (1ULL << 3),
};

struct ysioctl_info {
	size_t tx_buffer_size; /* output */
	size_t filters_size; /* output */
	int if_index[4]; /* output */
};

struct ysioctl_rw_reg_arg {
	int op; /* 0: read, 1: write */
	unsigned long bar; /* BAR number */
	unsigned long reg; /* register address */
	unsigned long val; /* value to write */
};

struct ysioctl_i2c_arg {
	int op; /* 0: read, 1: write */
	unsigned char i2c_num;
	unsigned char regaddr;
	unsigned char *buffer;
	size_t size;
};

struct ysioctl_umd_cfg {
	char start;
	char is_virtual;
	char is_virtual_sf;
	char dpu_mode;
	bool is_pt; /* iommu passthrough */
	unsigned short vfsf_id;
	unsigned short sf_id; /* The sf in the vf/pf*/
	unsigned short is_pf_sf; /* 1 pf sf; 2 vf sf */
	bool is_rep;
	unsigned short rep_id;
	unsigned short qbase;
	unsigned short qnum;
	unsigned char dev_addr[6];
	/*
	 * At smartnic/dpu_soc mode, the number of rep must be less than or
	 * equal to the number of vf.
	 */
	unsigned short sum_vf;
};

struct ysioctl_umd_hw {
	/* for ldma3 set/get hw parameter */
	char is_virtual;
	char is_virtual_sf;
	char action;
	unsigned short vfsf_id;
	unsigned short sf_id; /* The sf in the vf/pf*/
	unsigned short is_pf_sf; /* 1 pf sf; 2 vf sf */
	unsigned long long cfg;
	unsigned long long mtu;
	unsigned long long mac;
	unsigned long long qnum;
	unsigned long long data;
	unsigned long long promisc;
};

enum action {
	YS_SET = 0,
	YS_EGT,
	YS_RESTORE
};

struct ysioctl_dma_map {
	unsigned short vf_num;
	unsigned long vaddr;
	unsigned long size;
	unsigned long iova;
};

struct ys_mac_tbl {
	unsigned char mac[6];
	unsigned short vlan;
	unsigned short ingress_id;
	unsigned short vf;
};

struct ysioctl_doe_ctrl {
	unsigned char mac[6];
	unsigned short ingress_id;
	unsigned short cmd;
	unsigned short vlan;
	unsigned short vf;
	unsigned short rxq;
	unsigned char action;
	unsigned char action_mask;
	unsigned int vlan_tag;
	unsigned short vf_num;
	unsigned short mac_tbl_num;
};

#define YS_ETH_LINK_DUPLEX_FULL 1
#define YS_ETH_LINK_HALF_DUPLEX 0
#define YS_ETH_LINK_AUTONEG 1
#define YS_ETH_LINK_AUTONEG_FIXED 0
#define YS_ETH_LINK_DOWN 0
#define YS_ETH_LINK_UP 1

struct ysioctl_eth_link {
	unsigned int link_speed;
	unsigned int link_duplex : 1;
	unsigned int link_autoneg : 1;
	unsigned int link_status : 1;
};

#define YS_DEBUG_MAX_DEVICE 128
#define YS_DEBUG_CFG_PAGE_OFFSET 65536
#define YS_DEBUG_RUNTIME_PAGE_OFFSET 65535

#define YS_DEBUG_MAX_PAYLOAD_SIZE 64
#define YS_DEBUG_BUFFER_LEN 512

enum ys_debug_action {
	YS_DEBUG_OFF,
	YS_DEBUG_ON,
	YS_DEBUG_EGT_INFO
};

struct ys_debug_cfg {
	unsigned int ifindex;
	unsigned int function_id; /* 0 for pf , 1 2 3 ... for vf */
	unsigned char action; /* YS_DEBUG_OFF YS_DEBUG_ON YS_DEBUG_EGT_INFO ...*/
	unsigned int qtypeid;
	unsigned int gen:8;
	unsigned int cursor;
};

struct ys_debug_meta {
	unsigned int gen:8;
	unsigned int ifindex;
};

struct ys_debug_unit {
	char payload[YS_DEBUG_MAX_PAYLOAD_SIZE];
	struct ys_debug_meta mt;
};

#define YS_DEBUG_BUFFER_SIZE (sizeof(struct ys_debug_unit) * YS_DEBUG_BUFFER_LEN)

#define YS_IOCR_GET_BAR_SIZE _IOR(YSIOCTL_TYPE, 0xa1, unsigned long[BAR_MAX])
#define YS_IOCX_RW_REG _IOWR(YSIOCTL_TYPE, 0xa2, struct ysioctl_rw_reg_arg)
#define YS_IOCX_RW_I2C _IOWR(YSIOCTL_TYPE, 0xa3, struct ysioctl_i2c_arg)
#define YS_IOCW_SET_MMAP_FLAG _IOW(YSIOCTL_TYPE, 0xa4, u32)
#define YS_IOCX_UMD_CFG _IOWR(YSIOCTL_TYPE, 0xa5, struct ysioctl_umd_cfg)
#define YS_IOCX_DMA_MAP _IOWR(YSIOCTL_TYPE, 0xa6, struct ysioctl_dma_map)
#define YS_IOCX_DMA_UNMAP _IOW(YSIOCTL_TYPE, 0xa6, struct ysioctl_dma_map)
#define YS_IOCX_GET_ETH_LINK _IOR(YSIOCTL_TYPE, 0xa7, struct ysioctl_eth_link)
#define YS_IOCX_DOE_CTRL _IOWR(YSIOCTL_TYPE, 0xa8, struct ysioctl_doe_ctrl)
#define YS_IOCX_UMD_HW _IOWR(YSIOCTL_TYPE, 0xa9, struct ysioctl_umd_hw)
#define YS_IOCX_DEBUG_SET _IOWR(YSIOCTL_TYPE, 0xaa, struct ys_debug_cfg)

/****** ysc support start ******/

#ifndef __KERNEL__
#include <stdint.h>
#include <stdbool.h>
#endif

#define YSC_IOCTL_COMM_TYPE	'c'
#define YSC_IOCTL_NET_TYPE	'n'
#define YSC_IOCTL_DOE_TYPE	'd'
#define YSC_IOCTL_QOS_TYPE	'q'
#define YSC_IOCTL_LINK_TYPE	'l'
#define YSC_IOCTL_NP_TYPE	'p'
#define YSC_IOCTL_LAN_TYPE	'a'

/****** common ******/
enum ysc_comm_devtype {
	YSC_COMM_DEVTYPE_PCI = 1,
	YSC_COMM_DEVTYPE_REP,
	YSC_COMM_DEVTYPE_NDEV,
};

struct ysc_comm_devid {
	enum ysc_comm_devtype type;
	union {
		struct ysc_pci_addr {
			s32 domain;
			u8 bus;
			u8 devid;
			u8 function;
		} pci;
		struct ysc_rep_devid {
			s32 domain;
			u8 bus;
			u8 devid;
			u8 function;
			u16 rep_id;
		} rep;
		struct ysc_ndev_devid {
			u32 ifindex;
		} ndev;
	};
} __packed;

enum {
	YSC_COMM_DEVBIND,
	YSC_COMM_MAX,
};

#define YSC_COMM_DEV_BIND	_IOW(YSC_IOCTL_COMM_TYPE, YSC_COMM_DEVBIND, struct ysc_comm_devid)

/****** net ******/
struct ysc_net_devinfo {
	enum ys_dpu_mode mode;
	bool is_pt; /* iommu passthrough */
	u16 pf_id;
	u16 vf_id;
	u16 vf_num;
	u32 ifindex;
	u32 min_mtu;
	u32 max_mtu;
} __packed;

struct ysc_net_qinfo {
	u16 qnum;
	u16 qbase;
	u16 real_qnum;
	union {
		u16 qset_id;	/* for k2u */
	};
	u32 min_qdepth;
	u32 max_qdepth;
} __packed;

struct ysc_net_macaddr {
	u8 addr[6];
} __packed;

struct ysc_net_mtu {
	u16 size;
} __packed;

struct ysc_net_linkinfo {
	u32 link_speed;
	u16 link_duplex:1;
	u16 link_autoneg:1;
} __packed;

#define YSC_BIT64(nr)			(1UL << (nr))

#define YSC_RXOLCAP_VLAN_STRIP       YSC_BIT64(0)
#define YSC_RXOLCAP_IPV4_CKSUM       YSC_BIT64(1)
#define YSC_RXOLCAP_UDP_CKSUM        YSC_BIT64(2)
#define YSC_RXOLCAP_TCP_CKSUM        YSC_BIT64(3)
#define YSC_RXOLCAP_TCP_LRO          YSC_BIT64(4)
#define YSC_RXOLCAP_QINQ_STRIP       YSC_BIT64(5)
#define YSC_RXOLCAP_OUTER_IPV4_CKSUM YSC_BIT64(6)
#define YSC_RXOLCAP_MACSEC_STRIP     YSC_BIT64(7)
#define YSC_RXOLCAP_HEADER_SPLIT     YSC_BIT64(8)
#define YSC_RXOLCAP_VLAN_FILTER      YSC_BIT64(9)
#define YSC_RXOLCAP_VLAN_EXTEND      YSC_BIT64(10)
#define YSC_RXOLCAP_SCATTER          YSC_BIT64(13)
#define YSC_RXOLCAP_TIMESTAMP        YSC_BIT64(14)
#define YSC_RXOLCAP_SECURITY         YSC_BIT64(15)
#define YSC_RXOLCAP_KEEP_CRC         YSC_BIT64(16)
#define YSC_RXOLCAP_SCTP_CKSUM       YSC_BIT64(17)
#define YSC_RXOLCAP_OUTER_UDP_CKSUM  YSC_BIT64(18)
#define YSC_RXOLCAP_RSS_HASH         YSC_BIT64(19)
#define YSC_RXOLCAP_BUFFER_SPLIT     YSC_BIT64(20)

#define YSC_TXOLCAP_VLAN_INSERT      YSC_BIT64(0)
#define YSC_TXOLCAP_IPV4_CKSUM       YSC_BIT64(1)
#define YSC_TXOLCAP_UDP_CKSUM        YSC_BIT64(2)
#define YSC_TXOLCAP_TCP_CKSUM        YSC_BIT64(3)
#define YSC_TXOLCAP_SCTP_CKSUM       YSC_BIT64(4)
#define YSC_TXOLCAP_TCP_TSO          YSC_BIT64(5)
#define YSC_TXOLCAP_UDP_TSO          YSC_BIT64(6)
#define YSC_TXOLCAP_OUTER_IPV4_CKSUM YSC_BIT64(7)  /**< Used for tunneling packet. */
#define YSC_TXOLCAP_QINQ_INSERT      YSC_BIT64(8)
#define YSC_TXOLCAP_VXLAN_TNL_TSO    YSC_BIT64(9)  /**< Used for tunneling packet. */
#define YSC_TXOLCAP_GRE_TNL_TSO      YSC_BIT64(10) /**< Used for tunneling packet. */
#define YSC_TXOLCAP_IPIP_TNL_TSO     YSC_BIT64(11) /**< Used for tunneling packet. */
#define YSC_TXOLCAP_GENEVE_TNL_TSO   YSC_BIT64(12) /**< Used for tunneling packet. */
#define YSC_TXOLCAP_MACSEC_INSERT    YSC_BIT64(13)
#define YSC_TXOLCAP_MT_LOCKFREE      YSC_BIT64(14)
#define YSC_TXOLCAP_MULTI_SEGS       YSC_BIT64(15)
#define YSC_TXOLCAP_MBUF_FAST_FREE   YSC_BIT64(16)
#define YSC_TXOLCAP_SECURITY         YSC_BIT64(17)
#define YSC_TXOLCAP_UDP_TNL_TSO      YSC_BIT64(18)
#define YSC_TXOLCAP_IP_TNL_TSO       YSC_BIT64(19)
#define YSC_TXOLCAP_OUTER_UDP_CKSUM  YSC_BIT64(20)
#define YSC_TXOLCAP_SEND_ON_TIMESTAMP YSC_BIT64(21)

struct ysc_net_offloadcap {
	u64 rxsupport;
	u64 txsupport;
	u64 rxconfig;
	u64 txconfig;
} __packed;

struct ysc_net_promisc {
	bool enable;
} __packed;

struct ysc_net_dmamap {
	u64 vaddr;
	u64 len;
	u64 iova;
} __packed;

struct ysc_net_umd {
	bool enable;
} __packed;

struct ysc_net_pcibar {
	struct {
		u16 bar_idx;
	} req;
	struct {
		u64 bar_addr;
		u64 bar_size;
		u64 bar_offset;
	} rsp;
} __packed;

struct ysc_net_start {
	bool enable;
	u16 txqnum;
	u16 rxqnum;
} __packed;

struct ysc_net_peer_qset {
	u16 qset_id;
} __packed;

enum {
	YSC_NET_DEVINFO,
	YSC_NET_QINFO,
	YSC_NET_MACADDR,
	YSC_NET_MTU,
	YSC_NET_LINKINFO,
	YSC_NET_OFFLOADCAP,
	YSC_NET_PROMISC,
	YSC_NET_DMAMAP,
	YSC_NET_DMAUNMAP,
	YSC_NET_UMD,
	YSC_NET_PCIBAR,
	YSC_NET_START,
	YSC_NET_PEER_QSET,
	YSC_NET_MAX,
};

#define YSC_NET_DEVINFO_GET	_IOR(YSC_IOCTL_NET_TYPE, YSC_NET_DEVINFO, struct ysc_net_devinfo)
#define YSC_NET_QINFO_GET	_IOR(YSC_IOCTL_NET_TYPE, YSC_NET_QINFO, struct ysc_net_qinfo)
#define YSC_NET_MACADDR_GET	_IOR(YSC_IOCTL_NET_TYPE, YSC_NET_MACADDR, struct ysc_net_macaddr)
#define YSC_NET_MACADDR_SET	_IOW(YSC_IOCTL_NET_TYPE, YSC_NET_MACADDR, struct ysc_net_macaddr)
#define YSC_NET_MTU_GET		_IOR(YSC_IOCTL_NET_TYPE, YSC_NET_MTU, struct ysc_net_mtu)
#define YSC_NET_MTU_SET		_IOW(YSC_IOCTL_NET_TYPE, YSC_NET_MTU, struct ysc_net_mtu)
#define YSC_NET_LINKINFO_GET	_IOR(YSC_IOCTL_NET_TYPE, YSC_NET_LINKINFO, struct ysc_net_linkinfo)
#define YSC_NET_OFFLOADCAP_GET	\
	_IOR(YSC_IOCTL_NET_TYPE, YSC_NET_OFFLOADCAP, struct ysc_net_offloadcap)
#define YSC_NET_OFFLOADCAP_SET	\
	_IOW(YSC_IOCTL_NET_TYPE, YSC_NET_OFFLOADCAP, struct ysc_net_offloadcap)
#define YSC_NET_PROMISC_SET	_IOW(YSC_IOCTL_NET_TYPE, YSC_NET_PROMISC, struct ysc_net_promisc)
#define YSC_NET_DMA_MAP		_IOW(YSC_IOCTL_NET_TYPE, YSC_NET_DMAMAP, struct ysc_net_dmamap)
#define YSC_NET_DMA_UNMAP	_IOW(YSC_IOCTL_NET_TYPE, YSC_NET_DMAUNMAP, struct ysc_net_dmamap)
#define YSC_NET_UMD_SET		_IOW(YSC_IOCTL_NET_TYPE, YSC_NET_UMD, struct ysc_net_umd)
#define YSC_NET_PCIBAR_GET	_IOWR(YSC_IOCTL_NET_TYPE, YSC_NET_PCIBAR, struct ysc_net_pcibar)
#define YSC_NET_START_SET	_IOW(YSC_IOCTL_NET_TYPE, YSC_NET_START, struct ysc_net_start)
#define YSC_NET_PEER_QSET_GET	\
	_IOR(YSC_IOCTL_NET_TYPE, YSC_NET_PEER_QSET, struct ysc_net_peer_qset)

/****** QOS ******/

struct ysc_qos_qgroup {
	u16 qid;
	u16 qgroup;
} __packed;

struct ysc_qos_queue {
	u16 qnum;
	u16 real_qnum;
};

struct ysc_qos_sync {
	u16 qid;
} __packed;

enum {
	YSC_QOS_QGROUP,
	YSC_QOS_QUEUE,
	YSC_QOS_SYNC,
	YSC_QOS_MAX,
};

#define YSC_QOS_QGROUP_GET	_IOR(YSC_IOCTL_QOS_TYPE, YSC_QOS_QGROUP, struct ysc_qos_qgroup)
#define YSC_QOS_QGROUP_SET	_IOW(YSC_IOCTL_QOS_TYPE, YSC_QOS_QGROUP, struct ysc_qos_qgroup)
#define YSC_QOS_QUEUE_GET	_IOR(YSC_IOCTL_QOS_TYPE, YSC_QOS_QUEUE, struct ysc_qos_queue)
#define YSC_QOS_SYNC_SET	_IOW(YSC_IOCTL_QOS_TYPE, YSC_QOS_SYNC, struct ysc_qos_sync)

/****** LINK ******/
struct ysc_link_gqbase {
	u16 qstart;
	u16 qnum;
};

enum {
	YSC_LINK_GQBASE,
	YSC_LINK_MAX,
};

#define YSC_LINK_GQBASE_GET	_IOR(YSC_IOCTL_LINK_TYPE, YSC_LINK_GQBASE, struct ysc_link_gqbase)

/****** NP ******/
struct ysc_np_cfg_arg {
	u16 type;
	u16 value;
};

enum {
	YSC_NP_CFG,
	YSC_NP_BOND_CFG,
	YSC_NP_BOND_LINKSTATUS_CFG,
};

enum ysc_np_cfg_type {
	YS_NP_CFG_DOE_TBL_READY      = 0,
	YS_NP_CFG_FCS_ERR_DROP       = 1,
	YS_NP_CFG_TM_TRUST_PRI       = 2,
	YS_NP_CFG_LRO                = 3,
	YS_NP_CFG_IGN_PPP            = 14,
	YS_NP_CFG_TRUST_PPP          = 15,
	YS_NP_CFG_BYPASS_OFFLOAD     = 16,
	YS_NP_CFG_IGN_TNL_V4_ID      = 17,
	YS_NP_CFG_IGN_FRAG_L4_PORT   = 18,
	YS_NP_CFG_TBL_CACHE_MISS     = 19,
	YS_NP_CFG_MA_DISPATCH_POLICY = 20,
	YS_NP_CFG_MAX,
};

struct ysc_np_bond_cfg_arg {
	u8 bond_id;
	bool enable;
	u32 value;
} __packed;

struct ysc_np_bond_linkstatus_cfg_arg {
	u16 port_id;
	bool enable;
} __packed;

#define YSC_NP_CFG_SET		_IOW(YSC_IOCTL_NP_TYPE, YSC_NP_CFG, struct ysc_np_cfg_arg)
#define YSC_NP_BOND_CFG_SET	_IOW(YSC_IOCTL_NP_TYPE, YSC_NP_BOND_CFG, struct ysc_np_bond_cfg_arg)
#define YSC_NP_BOND_LINKSTATUS_CFG_SET	\
	_IOW(YSC_IOCTL_NP_TYPE, YSC_NP_BOND_LINKSTATUS_CFG, struct ysc_np_bond_linkstatus_cfg_arg)

#define YSC_K2ULAN_MC_GROUP_QBMP_NUM 1024
struct ysc_lan_cfg_arg {
	u32 group_id;
	u32 bitmap[YSC_K2ULAN_MC_GROUP_QBMP_NUM / 32];
};

enum {
	YSC_LAN_CFG,
};

#define YSC_LAN_CFG_SET		_IOW(YSC_IOCTL_LAN_TYPE, YSC_LAN_CFG, struct ysc_lan_cfg_arg)

/******* ysc support end *******/

#endif /* __YSNIC_H_ */
