/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _YS_LAG_H_
#define _YS_LAG_H_

#ifndef YS_TC_DISABLE

#include <linux/netdevice.h>
#include "ys_k2u_np_priv.h"

#define YS_K2U_NP_QOS_BASE                      0x13a3000
#define YS_K2U_NP_QOS(id)                       (YS_K2U_NP_QOS_BASE + 0x0004 * (id))
#define YS_K2U_NP_QOS_AGG_PHY_PORT_CONFIG(id)   (YS_K2U_NP_QOS(id) + 0x0a00)
#define YS_K2U_NP_QOS_AGG_PORT_CONFIG(id)       (YS_K2U_NP_QOS(id) + 0x0a20)
#define YS_K2U_NP_QOS_AGG_PORT_BITMAP(id)       (YS_K2U_NP_QOS(id) + 0x0a40)
#define YS_K2U_NP_QOS_AGG_PORT_LINKSTATUS_CHK   (YS_K2U_NP_QOS_BASE + 0x0a6c)

#define YS_K2U_NP_LAG_QSET_BASE                  0xc00
#define YS_K2U_NP_LAG_QSET(id)                   (YS_K2U_NP_LAG_QSET_BASE + (id))

#define YS_K2U_LAG_MAX_GROUP        8
#define YS_K2U_PHY_PORT_NUM         8

/* np hardware bond mode*/
enum {
	YS_k2U_NP_MODE_HASH_BALANCE = 0,
	YS_k2U_NP_MODE_ROUND_ROBIN,
	YS_k2U_NP_MODE_ACTIVE_BACKUP,
	YS_k2U_NP_MODE_BOND_SINGLE_MAC,
	YS_k2U_NP_MODE_MAX,
};

/* np share memory bond mode*/
enum {
	YS_k2U_NP_SHM_MODE_NONE = 0,
	YS_k2U_NP_SHM_MODE_ROUND_ROBIN,
	YS_k2U_NP_SHM_MODE_ACTIVE_BACKUP,
	YS_k2U_NP_SHM_MODE_HASH,
	YS_k2U_NP_SHM_MODE_8023AD_HASH = 5,
};

/* np bond hash policy*/
enum {
	YS_k2U_NP_POLICY_NONE = 0,
	YS_k2U_NP_POLICY_L2 = 0,
	YS_k2U_NP_POLICY_L23,
	YS_k2U_NP_POLICY_L34,
};

struct ys_k2u_lag_group {
	struct net_device *upper_dev;
	int bond_mode;
	u8 bond_status;
	u8 primary_pf_id;
	size_t num_slaves;
	enum netdev_lag_tx_type tx_type;
#ifdef YS_HAVE_NETDEV_LAG_HASH
	enum netdev_lag_hash hash_type;
#endif /* YS_HAVE_NETDEV_LAG_HASH */
};

#define ys_np_debug(f, arg...) \
	dev_dbg(pdev_priv->dev, "%s: [NP]: " f, YS_HW_NAME, ##arg)

/* LAG info struct */
struct ys_k2u_lag {
	struct ys_np_sw *np_sw;
	struct notifier_block notif_block;
	struct ys_k2u_lag_group lag_group[YS_K2U_LAG_MAX_GROUP];
	size_t active_groups;
};

int ys_k2u_init_lag(struct ys_np *np);
void ys_k2u_deinit_lag(struct ys_np *np);
int ys_k2u_get_lag_group_id_by_master(int bus_id, struct net_device *netdev);

#endif

#endif /* _YS_LAG_H_ */
