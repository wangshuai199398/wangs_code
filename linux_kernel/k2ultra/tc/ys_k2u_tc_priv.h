/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_TC_PRIV_H__
#define __YS_TC_PRIV_H__

#include "ys_debug.h"
#include "ys_platform.h"

#ifndef YS_TC_DISABLE

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/list.h>

#include <linux/netdevice.h>
#include <linux/rhashtable.h>
#include <linux/workqueue.h>
#include <linux/debugfs.h>

#include <net/pkt_cls.h>

#include <net/tc_act/tc_pedit.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_vlan.h>
#include <net/tc_act/tc_tunnel_key.h>

#include <net/flow_offload.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>

#include "ys_doe.h"
#include "ys_doe_kapi.h"
#include "../net/tc/ys_tc.h"
#include "../net/lan/k2ulan/ys_k2ulan.h"
#include "../np/ys_k2u_np.h"
#include "../np/ys_k2u_np_lag.h"
#include "../edma/ys_k2u_new_ndev.h"

/* ystc basic start */
struct ys_tc_addr {
	bool is_ipv6;
	union {
		__be32 ipv4;
		struct in6_addr ipv6;
	};
};

/* ystc basic end */
/* ystc table start */

enum ys_tc_table_id {
	YS_TC_TABLE_ID_L3PROTO = 0,
	YS_TC_TABLE_ID_IPV4_FLOW = 1,
	YS_TC_TABLE_ID_IPV6_FLOW = 2,
	YS_TC_TABLE_ID_MISS = 99,
	YS_TC_TABLE_ID_COMMCNT = 100,
	YS_TC_TABLE_ID_VXLANENCAP = 105,
	YS_TC_TABLE_ID_MIRROR = 107,
	YS_TC_TABLE_ID_GNVENCAP = 130,
	YS_TC_TABLE_ID_METER = 122,
	YS_TC_TABLE_ID_MAX = 255,
};

enum { YS_TC_CNT_TBL_VAL_LEN = (sizeof(__u64) * 2) };
struct ys_tc_table_commcnt_data {
	__be64        be_pkts; /* hw data cache */
	__be64        be_bytes;	/* hw data cache */
	u64           used;
	u64           last_pkts;
	u64           last_bytes;
	spinlock_t    cache_slock; /* To protect data */
};

enum { YS_TC_CNT_LOAD_BATCH = 128 };

enum {
	YS_TC_DOE_PROTECT_OFF = 0,
	YS_TC_DOE_PROTECT_ON = 1,
};

/* ystc table end */
/* ystc priv start */

struct ys_tc_tun_info {
	__u16 port_min;
	__u16 port_max;
};

struct ys_tc_tun_dev {
	struct list_head node;
	struct ys_tc_tun_info info;
};

/* ystc priv end  */
/* ystc switchdev start */

struct ys_tc_table;

#define YS_TC_NP_CLUSTER_NUM	16
struct ys_pdev_priv;

// u32 bitmap[64] stand for 2048 bits qset bitmap
#define YS_K2ULAN_TC_MC_GROUP_NUM	2048
#define YS_K2ULAN_TC_MC_GROUP_QBMP_NUM	1024

enum { YS_TC_DOE_CHANNEL_NUM = 2 };
struct ys_tc_doe_channel_info {
	int location[YS_TC_DOE_CHANNEL_NUM];
};

enum {
	YS_TC_METRICS_ARRAY_STORE_TOTAL       = 0,
	YS_TC_METRICS_ARRAY_LOAD_TOTAL        = 1,
	YS_TC_METRICS_METER_STORE_TOTAL       = 2,
	YS_TC_METRICS_COUNTER_ENABLE_TOTAL    = 3,
	YS_TC_METRICS_COUNTER_DISABLE_TOTAL   = 4,
	YS_TC_METRICS_COUNTER_LOAD_TOTAL      = 5,
	YS_TC_METRICS_COUNTER_DOWNGRADE_TOTAL = 6,
	YS_TC_METRICS_HASH_INSERT_TOTAL       = 7,
	YS_TC_METRICS_HASH_DEL_TOTAL          = 8,
	YS_TC_METRICS_HIGH_PRI_SET_TOTAL      = 9,
	YS_TC_METRICS_HIGH_PRI_UNSET_TOTAL    = 10,

	YS_TC_METRICS_FLOW_ADD_TOTAL          = 11,
	YS_TC_METRICS_FLOW_DEL_TOTAL          = 12,

	YS_TC_METRICS_WORK_RETRY_TOTAL        = 13,
	YS_TC_METRICS_DUMP_SKIP_TOTAL         = 14,
	YS_TC_METRICS_MAX,
};

enum {
	YS_TC_STATES_ARRAY_STORE_FAIL         = 0,
	YS_TC_STATES_ARRAY_LOAD_FAIL          = 1,
	YS_TC_STATES_METER_STORE_FAIL         = 2,
	YS_TC_STATES_COUNTER_ENABLE_FAIL      = 3,
	YS_TC_STATES_COUNTER_DISABLE_FAIL     = 4,
	YS_TC_STATES_COUNTER_LOAD_FAIL        = 5,
	YS_TC_STATES_COUNTER_DOWNGRADE_FAIL   = 6,
	YS_TC_STATES_HASH_INSERT_FAIL         = 7,
	YS_TC_STATES_HASH_DEL_FAIL            = 8,
	YS_TC_STATES_MAX,
};

struct ys_tc_switchdev {
	int id;
	refcount_t refcnt;
	struct dentry *debugfs_root;

	struct list_head priv_head;
	struct mutex priv_mlock;	/* for priv add and del */

	struct ys_tc_table *ys_tc_tables[YS_TC_TABLES_NUM];

	atomic64_t doe_errors[100 + 256]; /* Unknown errors are logged by index 0 */
	atomic64_t stats[YS_TC_STATES_MAX];
	atomic64_t metrics[YS_TC_METRICS_MAX];

	atomic_t priority_flow_nb;
	const struct ys_doe_ops *doe_ops;
	struct ys_tc_doe_channel_info doe_chl_info;
	u16 array_tbl_value_len_max;
	u16 hash_tbl_key_len_max;
	u16 hash_tbl_value_len_max;
	bool hash_tbl_cache_high;

	/* work */
	struct workqueue_struct *wq;

#ifdef YS_HAVE_FLOW_ACTION_OFFLOAD
	/* meter */
	struct rhashtable meter_ht;
	struct rhashtable_params *meter_ht_params;
#endif
	/* multicast group */
	atomic_t group_id_used;
	DECLARE_BITMAP(group_id_bitmap, YS_K2ULAN_TC_MC_GROUP_NUM);
	struct rhashtable multicast_ht;
	struct rhashtable_params *multicast_ht_params;
};

/* ystc switchdev end */
/* ystc table start */

enum ys_tc_table_type {
	YS_TC_TABLE_ARRAY = (1 << 0),
	YS_TC_TABLE_HASH  = (1 << 1),
	YS_TC_TABLE_CNT   = (1 << 2),
	YS_TC_TABLE_METER = (1 << 3),
	YS_TC_TABLE_REF   = (1 << 4),
};

struct ys_tc_table {
	enum ys_tc_table_type type;
	char name[32];
	const struct ys_tc_table_ops *ops;
	struct dentry *debugfs_file;
	atomic_t used;

	enum ys_tc_table_id id;
	unsigned int size;
	const struct hw_advance_cfg *extra;

	struct idr idr;
	spinlock_t idr_slock; /* for idr alloc and remove */
	int start_idx; /* for meter */

	__u16 key_len; /* for hash table */
	__u16 value_len;

	struct ys_tc_switchdev *switchdev;
	struct delayed_work tc_work;
	unsigned long work_interval;
	unsigned long flags;

	struct llist_head addlist;
	struct llist_head dellist;
	unsigned long *bitmask; /* for counter update loop */
	u8 *buf; /* for counter update */
	struct rhashtable ref_ht; /* for referenece table */
	struct rhashtable_params ref_ht_params; /* for referenece table */
	struct ys_tc_table_entry *entry_list[];
};

#define YS_TC_FLAG_REALDECAP BIT(2)
#define YS_TC_FLAG_HIGHPRI BIT(3)
enum { YS_TC_FLOW_HIGHPRI_MAX_NUM = 64 };

enum {
	YS_TC_FLOW_FLAG_HIGHPRI	      = 3,
	YS_TC_FLOW_FLAG_DELETED	      = 6,
};

enum {
	YS_TC_TABLE_ENTRY_VALID       = 7,
	YS_TC_TABLE_ENTRY_HIGHPRI     = 8,
};

enum {
	YS_TC_TABLE_FLAG_DUMP         = 0,
	YS_TC_TABLE_FLAG_WORK_CANCEL  = 1,
	YS_TC_TABLE_FLAG_WORK_PROCESS = 2,
};

struct ys_tc_table_entry_node {
	struct list_head flow_node;
	struct ys_tc_table_entry *tbl_entry;
};

struct ys_tc_table_entry {
	struct rhash_head node;
	refcount_t refcnt;
	struct ys_tc_table *table;
	struct llist_node addlist;
	struct llist_node dellist;
	int idx;
	unsigned long flags;
	char data[];
};

struct ys_tc_table_create_param {
	char *name;
	enum ys_tc_table_id id;
	unsigned int size;
	unsigned int size_on_ram;
	__u16 key_len;
	__u16 value_len;
	__u16 value_min_len;
	int start_idx;
	unsigned long work_interval; /* Time interval for counter table update work in mesc */
	struct hw_advance_cfg extra;
};

struct ys_tc_table_ops {
	int (*create)(struct ys_tc_priv *tc_priv, struct ys_tc_table *table);
	void (*destroy)(struct ys_tc_priv *tc_priv, struct ys_tc_table *table);
	struct ys_tc_table_entry *(*alloc)(struct ys_tc_priv *tc_priv,
					   struct ys_tc_table *table, const int *idx,
					   const void *data);
	int (*add)(struct ys_tc_priv *tc_priv, struct ys_tc_table_entry *entry);
	void (*del)(struct ys_tc_priv *tc_priv, struct ys_tc_table_entry *entry);
	void (*work)(struct work_struct *work);
};

static inline __u16 ys_tc_table_get_keylen(struct ys_tc_table *table)
{
	return (table->type == YS_TC_TABLE_HASH) ? table->key_len : 0;
}

static inline __u16 ys_tc_table_get_valuelen(struct ys_tc_table *table)
{
	return table->value_len;
}

/* ystc table end */
/* ystc flow start */

enum ys_tc_frag_type {
	YS_TC_FRAG_NONE = 0,
	YS_TC_FRAG_FIRST = 1,
	YS_TC_FRAG_LATER = 2,
};

struct ys_tc_key_ipv4 {
	__be16 src_qset;
	__u8 tun_type;
	__u8 protocol;
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__be32 tenant_id;
	__u8 dst_eth[ETH_ALEN];
	__u8 src_eth[ETH_ALEN];
	__be16 vlan_id;
	__u8 fragment;
	__u8 reserved;
} __packed;

#define YS_TC_KEY_IPV6_ADDR_LEN 16
struct ys_tc_key_ipv6 {
	__be16 src_qset;
	__u8 tun_type;
	__u8 protocol;
	__u8 src_ip[YS_TC_KEY_IPV6_ADDR_LEN];
	__u8 dst_ip[YS_TC_KEY_IPV6_ADDR_LEN];
	__be16 src_port;
	__be16 dst_port;
	__be32 tenant_id;
	__u8 dst_eth[ETH_ALEN];
	__u8 src_eth[ETH_ALEN];
	__be16 vlan_id;
	__u8 fragment;
	__u8 reserved;
} __packed;

struct ys_tc_action_port {
	__u8 resv;
	__u8 pf_id;
	__be16 vf_id;
} __packed;

struct ys_tc_action_meter {
	__be32 meter_id;
	__be32 green_cnt_idx;
	__be32 red_cnt_idx;
} __packed;

union ys_tc_action_entry_data {
	__be32 count_id;
	__be16 table_id;
	struct ys_tc_action_port port;
	__be32 tun_tbl_id;	/* for vxlan and geneve */
	__be32 vlan_tag;
	__be16 vlan_id;
	__be16 ttl;
	__be16 ipv4_dscp;
	__be32 src_ipv4;
	__be32 dst_ipv4;
	__be16 src_port;
	__be16 dst_port;
	__u8 src_eth[ETH_ALEN];
	__u8 dst_eth[ETH_ALEN];
	__be16 vlan_pcp;
	struct ys_tc_action_meter meter_action;
	__be16 qid;
	__be32 mirror_id;
	__be16 ipv6_dscp;
	__be16 jump_id;
	__u8 src_ipv6[YS_TC_KEY_IPV6_ADDR_LEN];
	__u8 dst_ipv6[YS_TC_KEY_IPV6_ADDR_LEN];
	__u8 vxlan_encap[74];
	__u8 vxlan_ipv4[50];
	__be16 group_id;
};

struct ys_tc_action_tunencap_data {
	__u8 type;
	__u8 len;
	__u8 data[];
};

enum ys_tc_action_vxlanencap_data_type {
	YS_TC_ACTION_VXLANENCAP_IPV4 = 1,
	YS_TC_ACTION_VXLANENCAP_VLANIPV4,
	YS_TC_ACTION_VXLANENCAP_IPV6,
	YS_TC_ACTION_VXLANENCAP_VLANIPV6,
};

enum ys_tc_action_gnvencap_data_type {
	YS_TC_ACTION_GNVENCAP_IPV4 = 1,
	YS_TC_ACTION_GNVENCAP_VLANIPV4,
	YS_TC_ACTION_GNVENCAP_IPV6,
	YS_TC_ACTION_GNVENCAP_VLANIPV6,
	YS_TC_ACTION_GNVENCAP_IPV4OPT,
	YS_TC_ACTION_GNVENCAP_VLANIPV4OPT,
	YS_TC_ACTION_GNVENCAP_IPV6OPT,
	YS_TC_ACTION_GNVENCAP_VLANIPV6OPT,
};

struct ys_tc_action_entry {
	__u8 type;
	__u8 len;
	union ys_tc_action_entry_data data;
} __packed;

enum ys_tc_action_type {
	YS_TC_ACTION_END = 0,
	YS_TC_ACTION_COUNT = 1,
	YS_TC_ACTION_DEC_TTL = 2,
	YS_TC_ACTION_JUMP = 3,
	YS_TC_ACTION_OUTPUT_PORT = 4,
	YS_TC_ACTION_VXLAN_DECAP = 5,
	YS_TC_ACTION_VXLAN_ENCAP = 6,
	YS_TC_ACTION_POP_VLAN = 7,
	YS_TC_ACTION_PUSH_VLAN = 8,
	YS_TC_ACTION_DROP = 9,
	YS_TC_ACTION_SET_VLANID = 10,
	YS_TC_ACTION_SET_TTL = 11,
	YS_TC_ACTION_SET_DSCP = 12,
	YS_TC_ACTION_SET_IP_SRC = 13,
	YS_TC_ACTION_SET_IP_DST = 14,
	YS_TC_ACTION_SET_TP_SRC = 15,
	YS_TC_ACTION_SET_TP_DST = 16,
	YS_TC_ACTION_SET_MAC_SRC = 17,
	YS_TC_ACTION_SET_MAC_DST = 18,
	YS_TC_ACTION_SET_VLAN_PCP = 19,
	YS_TC_ACTION_QUEUE = 21,
	YS_TC_ACTION_FLOW_MIRROR = 22,
	YS_TC_ACTION_SET_IPV6_DSCP = 23,
	YS_TC_ACTION_SET_IPV6_SRC = 24,
	YS_TC_ACTION_SET_IPV6_DST = 25,
	YS_TC_ACTION_GENEVE_DECAP = 26,
	YS_TC_ACTION_GENEVE_ENCAP = 27,
	YS_TC_ACTION_ENCAP_VXLAN_IPV4 = 28,
	YS_TC_ACTION_METER = 29,
	YS_TC_ACTION_GROUP = 30,
	YS_TC_ACTION_MAX,
};

struct ys_tc_action_buf {
	void *data; /* Pointer of memory to store on doe */
	size_t size; /* Total length of data */
	size_t offset; /* Length data already used*/
};

struct ys_tc_flow {
	struct rhash_head node;
	struct ys_tc_priv *tc_priv;
	unsigned long cookie;
	refcount_t refcnt;
	struct rcu_head rcu_head;
	unsigned long flags;
	struct ys_tc_table_entry *table_entry;
	struct ys_tc_table_entry *cnt_entry;
	struct list_head tbl_entry_head;
	struct ys_tc_group_entry *group_entry;
};

struct ys_tc_flow_metadata {
	struct net_device *in_ndev;

	enum ys_tc_tun_type tun_type;
	struct ys_tc_addr tun_src_addr;
	struct ys_tc_addr tun_dst_addr;
	__be16 tun_src_port;
	__be16 tun_dst_port;
	__be32 tun_id;
	__u8 tun_opt[8];

	__u8 src_eth[ETH_ALEN];
	__u8 dst_eth[ETH_ALEN];
	__u16 vlan_id;
	__u16 cvlan_id;
	struct ys_tc_addr src_addr;
	struct ys_tc_addr dst_addr;
	__u8 proto;
	enum ys_tc_frag_type frag_type;

	__be16 src_port;
	__be16 dst_port;
};

/* ystc flow end */
/* ystc flow cache start */

struct ys_tc_action_meta {
	int pos;
	int action_pos_list[YS_TC_ACTION_MAX]; // value 0 is invalid, [1, ..]
	unsigned long action_bits[BITS_TO_LONGS(YS_TC_ACTION_MAX)];
	__u32 flags;
	struct net_device *pre_out_ndev;
	struct net_device *out_ndev;
	struct net_device *mirror_ndev;
	union {
		__be32 vlan_tag;
		struct {
			__be16 vlan_tpid;
			__be16 vlan_vid;
		};
	};
	__be16 vlan_id;
	__be16 vlan_pcp;
	struct ethhdr eth;
	__u16 jump_id;
	struct iphdr ipv4;
	struct ipv6hdr ipv6;
	struct tcphdr tcp;
	struct ethhdr tunnel_eth;
	struct ip_tunnel_info tunnel_info;
	__u8 tunnel_opt[8];
	__u32 meter_id;
	__u32 meter_green_cnt_idx;
	__u32 meter_red_cnt_idx;
	bool encap_in_mirror;
	bool has_tnl_encap;
	DECLARE_BITMAP(bitmap, YS_K2ULAN_TC_MC_GROUP_QBMP_NUM);
};

struct ys_tc_action_ctx {
	const struct ys_tc_flow_metadata *flow_meta;
	struct ys_tc_action_meta action_meta;
	struct ys_tc_flow *flow;
	struct ys_tc_action_buf action_buf;
	struct ys_tc_table_entry *mirror_tbl_entry;
	struct ys_tc_action_buf mirror_buf;
	struct ys_tc_action_buf *encap_buf;
};

struct ys_tc_ops_action {
	enum ys_tc_action_type type;
	__u8 datalen;
	int (*parse)(struct ys_tc_priv *tc_priv,
		     const struct ys_tc_ops_action *ops,
		     struct ys_tc_action_ctx *ctx);
};

/* ystc flow cache end */
/* ystc meter start */

enum ys_tc_meter_algo_type {
	YS_TC_METER_ALGO_INVALID = 0,
	YS_TC_METER_ALGO_SRTWOCM, //single rate two color marker
	YS_TC_METER_ALGO_BSRTCM,  //blind single rate three color marker
	YS_TC_METER_ALGO_SRTCM,
	YS_TC_METER_ALGO_BTRTCM,
	YS_TC_METER_ALGO_TRTCM,
};

enum ys_tc_meter_action_type {
	YS_TC_METER_PASS,
	YS_TC_METER_DROP,
	YS_TC_METER_REMARK_DSCP,
};

struct ys_tc_meter {
	struct rhash_head node;
	refcount_t refcnt;
	struct rcu_head rcu_head;
	__u32 index;
	__u32 burst;
	__u64 rate_bytes_ps;
	struct ys_tc_priv *tc_priv;
	struct ys_tc_table_entry *meter_tbl_entry;
	struct ys_tc_table_entry *green_cnt_entry;
	struct ys_tc_table_entry *red_cnt_entry;
};

/* ystc meter end */

/* ystc multicast */

struct ys_tc_group_entry {
	struct rhash_head node;
	refcount_t refcnt;
	struct rcu_head rcu_head;
	__u16 group_id;
	DECLARE_BITMAP(bitmap, YS_K2ULAN_TC_MC_GROUP_QBMP_NUM);
};

int ys_tc_setup_tc(struct net_device *dev, enum tc_setup_type type,
		   void *type_data);

static inline bool ys_tc_dev_valid(struct net_device *ndev)
{
	return ndev->netdev_ops && ndev->netdev_ops->ndo_setup_tc &&
	       (ndev->netdev_ops->ndo_setup_tc == ys_tc_setup_tc) &&
	       ys_tc_get_priv(ndev);
}

static inline bool ys_tc_same_switchdev(struct net_device *ndev1,
					struct net_device *ndev2)
{
	if (ys_tc_dev_valid(ndev1) && ys_tc_dev_valid(ndev2)) {
		struct ys_tc_priv *tc_priv1 = ys_tc_get_priv(ndev1);
		struct ys_tc_priv *tc_priv2 = ys_tc_get_priv(ndev2);

		return tc_priv1->switchdev == tc_priv2->switchdev;
	}
	return false;
}

int ys_tc_table_init(struct ys_tc_priv *tc_priv);
void ys_tc_table_exit(struct ys_tc_priv *tc_priv);

struct ys_tc_table_entry *ys_tc_table_alloc(struct ys_tc_priv *tc_priv,
					    enum ys_tc_table_id id,
					    const int *idx, const void *data);
void ys_tc_table_free(struct ys_tc_priv *tc_priv,
		      struct ys_tc_table_entry *entry);
int ys_tc_table_add(struct ys_tc_priv *tc_priv,
		    struct ys_tc_table_entry *entry);
void ys_tc_table_del_and_free(struct ys_tc_priv *tc_priv,
			      struct ys_tc_table_entry *entry);
int ys_tc_table_update(struct ys_tc_priv *tc_priv,
		       struct ys_tc_table_entry *entry);
struct ys_tc_table *ys_tc_table_find(struct ys_tc_priv *tc_priv,
				     enum ys_tc_table_id id);

int ys_tc_add_flower(struct ys_tc_priv *tc_priv,
		     struct flow_cls_offload *cls_flower);
int ys_tc_del_flower(struct ys_tc_priv *tc_priv,
		     struct flow_cls_offload *cls_flower);
int ys_tc_stat_flower(struct ys_tc_priv *tc_priv,
		      struct flow_cls_offload *cls_flower);
int ys_tc_flow_init(struct ys_tc_priv *tc_priv);
void ys_tc_flow_exit(struct ys_tc_priv *tc_priv);
int ys_tc_flow_once_init(struct ys_tc_priv *tc_priv);

int ys_tc_multicast_init(struct ys_tc_priv *tc_priv);
void ys_tc_multicast_exit(struct ys_tc_priv *tc_priv);

#ifdef YS_HAVE_FLOW_ACTION_OFFLOAD
int ys_tc_add_act(struct ys_tc_priv *tc_priv,
		  struct flow_offload_action *fl_act);
int ys_tc_del_act(struct ys_tc_priv *tc_priv,
		  struct flow_offload_action *fl_act);
int ys_tc_stat_act(struct ys_tc_priv *tc_priv,
		   struct flow_offload_action *fl_act);
int ys_tc_meter_init(struct ys_tc_priv *tc_priv);
void ys_tc_meter_exit(struct ys_tc_priv *tc_priv);
struct ys_tc_meter *
ys_tc_meter_lookup(struct ys_tc_priv *tc_priv, __u32 index);
void ys_tc_meter_put(struct ys_tc_priv *tc_priv,
		     struct ys_tc_meter *meter);
#endif

#endif

#endif
