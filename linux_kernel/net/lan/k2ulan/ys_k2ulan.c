// SPDX-License-Identifier: GPL-2.0

#include <linux/iopoll.h>
#include "../../../platform/ys_auxiliary.h"
#include "../../../platform/ys_intr.h"
#include "../../../platform/ys_ndev.h"
#include "../../../platform/ys_pdev.h"
#include "../../../platform/ys_mbox.h"
#include "../../../platform/ys_debugfs.h"

#include "ys_adapter.h"
#include "ys_debug.h"

#include "ys_k2ulan.h"
#include "ys_k2ulan_register.h"
#include "../../ys_ndev_ops.h"
#include "ys_cuckoo_hash.h"

struct ys_k2ulan_mbox_ctx {
	u16 func_id : 10;
	u16 type : 6;
};

static const char ys_k2ulan_priv_strings[][ETH_GSTRING_LEN] = {
	"veb_enable",
	"rss_sel_udp_tunnel_info",
	"pvid_miss_upload"
};

static void ys_k2ulan_enable_qset(struct net_device *ndev, u16 vf_id, u8 enable);
static void ys_k2ulan_enable_smart_card_qset(struct net_device *ndev, u16 adev_id, bool open);
static void ys_k2ulan_qset_init_hash(void __iomem *bar_addr, u16 qset);
static void ys_k2ulan_qset_init_flags(void __iomem *bar_addr, u16 qset);
static void ys_k2ulan_rep_qset_init_flags(void __iomem *hw_addr, u16 qset);
static int ys_k2ulan_cmd_exec(struct ys_mbox *mbox, u32 op_code, u32 ctx, void *in,
			      u32 in_len, struct ys_mbox_msg *ack);
static int ys_k2ulan_cmd_exec_async(struct ys_mbox *mbox, u32 op_code, u32 ctx,
				    void *in, u32 in_len);
static void ys_k2ulan_qset_init_drops(void __iomem *bar_addr, u16 qset);
static void ys_k2ulan_qset_init_vlan(void __iomem *bar_addr, u16 qset);
static void ys_k2ulan_rep_qset_init_vlan(void __iomem *hw_addr, u16 qset);
static void ys_k2ulan_mbox_req_set_inner_vlan(struct ys_mbox *mbox, struct ys_queue_params *qi,
					      u32 vlan_id, __be16 proto, u8 enable);
static void ys_k2ulan_clear_inner_vlan(struct ys_pdev_priv *pdev_priv,
				       struct ys_queue_params *qi, u32 vlan_id,
				       __be16 proto);
static void ys_k2ulan_clear_port_vf_vlan(void __iomem *hw_addr, u16 qset);
static void ys_k2ulan_reset_vf_regs(void __iomem *hw_addr, u16 qset);
static void ys_k2ulan_mbox_req_set_mc_mac(struct ys_mbox *mbox, u8 *mac,
					  struct ys_queue_params *qi,
					  enum ys_k2ulan_filter_action action);
static void ys_k2ulan_mbox_req_remove_vf_port(struct ys_pdev_priv *pdev_priv);

static int ys_k2ulan_bmp_set_bit(u32 *bitmap, u32 bmp_size, u32 qset, bool set)
{
	int j, k;

	j = qset / 32;
	k = qset % 32;

	if (j >= bmp_size / 32)
		return -1;

	if (set)
		bitmap[j] |= 1 << k;
	else
		bitmap[j] &= ~(1 << k);

	return 0;
}

static int ys_k2ulan_bmp_clear_bit(u32 *bitmap, u32 bmp_size, u32 qset)
{
	int j, k;

	j = qset / 32;
	k = qset % 32;

	if (j >= bmp_size / 32)
		return -1;

	if ((bitmap[j] | ~(1 << k)) == 0)
		return -1;
	bitmap[j] &= ~(1 << k);

	return 0;
}

static int ys_k2ulan_bmp_find_first_zero_bit(u32 *bitmap, u32 bmp_size, bool zero)
{
	u32 i, j, k;

	j = bmp_size / 32;

	for (i = 0; i < j; i++) {
		for (k = 0; k < 32; k++) {
			if (zero) {
				if ((bitmap[i] & (1 << k)) == 0)
					return i * 32 + k;
			} else {
				if ((bitmap[i] & (1 << k)) > 0)
					return i * 32 + k;
			}
		}
	}

	return bmp_size;
}

static int ys_k2ulan_compare_qset_bmp(u32 *target_qbmp, u32 *qbmp, u32 len)
{
	if (len < 1 || len >= 4096)
		return -1;

	return memcmp(target_qbmp, qbmp, len * 4);
}

static void ys_k2ulan_set_mc_qbmp(struct ys_k2ulan *k2ulan,
				  struct ys_k2ulan_mc_qset_bitmap *l2mc_qbmp)
{
	u32 i;
	void __iomem *entry_addr;

	entry_addr = k2ulan->lan_mac_table->hw.bar_addr;
	entry_addr += YS_K2ULAN_STEERING_RX_MAC_RULE_ENTRY_ADDR(l2mc_qbmp->index);
	if (k2ulan->lan_mac_table->type == YS_CUCKOO_TYPE_K2U_LAN_MAC)
		for (i = 0; i < YS_K2ULAN_STEERING_RX_IPV4_L2MC_RULE_ENTRY_LEN / 4; i++)
			ys_wr32(entry_addr, i * sizeof(l2mc_qbmp->bitmap[0]),
				l2mc_qbmp->bitmap[i]);
	else if (k2ulan->lan_mac_table->type == YS_CUCKOO_TYPE_K2U_BNIC_LAN_MAC)
		for (i = 0; i < YS_K2ULAN_STEERING_RX_IPV4_L2MC_RULE_ENTRY_LEN / 2 / 4; i++)
			ys_wr32(entry_addr, i * sizeof(l2mc_qbmp->bitmap[0]),
				l2mc_qbmp->bitmap[i]);
	else
		ys_err("k2u lan set mc qset bitmap with unknown table type %d!",
		       k2ulan->lan_mac_table->type);
}

static void ys_k2ulan_set_uc_qbmp(struct ys_k2ulan *k2ulan,
				  struct ys_k2ulan_uc_qset_bitmap *l2uc_qbmp)
{
	u32 i;
	void __iomem *entry_addr;

	entry_addr = k2ulan->lan_mac_table->hw.bar_addr;
	entry_addr += YS_K2ULAN_STEERING_RX_MAC_RULE_ENTRY_ADDR(l2uc_qbmp->index);
	if (k2ulan->lan_mac_table->type == YS_CUCKOO_TYPE_K2U_LAN_MAC)
		for (i = 0; i < YS_K2ULAN_STEERING_RX_MAC_RULE_ENTRY_LEN / 4; i++)
			ys_wr32(entry_addr, i * sizeof(u32), l2uc_qbmp->bitmap[i]);
	else if (k2ulan->lan_mac_table->type == YS_CUCKOO_TYPE_K2U_BNIC_LAN_MAC)
		for (i = 0; i < YS_K2ULAN_STEERING_RX_MAC_RULE_ENTRY_LEN / 2 / 4; i++)
			ys_wr32(entry_addr, i * sizeof(u32), l2uc_qbmp->bitmap[i]);
	else
		ys_err("k2u lan set uc qset bitmap with unknown table type %d!",
		       k2ulan->lan_mac_table->type);
}

static int ys_k2ulan_alloc_l2uc_qset_bmp(struct ys_k2ulan *k2ulan,
					 int old_qbmp_index, u32 *bitmap)
{
	struct ys_k2ulan_uc_qset_bitmap *l2uc_qbmp = NULL;
	struct ys_k2ulan_uc_qset_bitmap *temp;
	struct ys_k2ulan_uc_qset_bitmap *l2uc_qbmp_exist = NULL;
	struct ys_k2ulan_steering *steering;
	bool new_qbmp_match = false;
	bool old_qbmp_match = false;

	steering = &k2ulan->lan_steering;
	list_for_each_entry_safe(l2uc_qbmp, temp, &steering->l2uc_qbmp_list,
				 uc_qbmp_node) {
		ys_debug("compare %p to %p", bitmap, l2uc_qbmp->bitmap);
		if (ys_k2ulan_compare_qset_bmp(l2uc_qbmp->bitmap, bitmap,
					       YS_K2ULAN_QSET_BITMAP) == 0) {
			if (new_qbmp_match)
				ys_err("ys k2u panic add ref uc qbmp list has duplicate entry!");
			l2uc_qbmp->ref_cnt++;
			l2uc_qbmp_exist = l2uc_qbmp;
			new_qbmp_match = true;
		}

		if (old_qbmp_index != -1 && l2uc_qbmp->index == old_qbmp_index) {
			if (old_qbmp_match)
				ys_err("ys k2u panic del ref uc qbmp list has duplicate entry!");
			/* dereference old qset bitmap */
			if (0 == --l2uc_qbmp->ref_cnt) {
				if (ys_k2ulan_bmp_clear_bit(steering->uc_qbmp_index,
							    YS_K2ULAN_QSET_BITMAP_BITS,
							    old_qbmp_index) != 0) {
					ys_err("ys k2u panic remove no exist qset bitmap!");
				}
				list_del(&l2uc_qbmp->uc_qbmp_node);
				steering->uc_qbmp_used--;
				kfree(l2uc_qbmp);
			}
			old_qbmp_match = true;
		}
	}

	if (l2uc_qbmp_exist)
		return l2uc_qbmp_exist->index;

	if (&l2uc_qbmp->uc_qbmp_node == &steering->l2uc_qbmp_list)
		l2uc_qbmp = NULL;

	/* alloc new l2uc qset bitmap */
	if (!l2uc_qbmp) {
		l2uc_qbmp = kzalloc(sizeof(*l2uc_qbmp), GFP_ATOMIC);
		if (IS_ERR_OR_NULL(l2uc_qbmp)) {
			ys_err("ys k2u can not alloc unicast qset bitmap memory!");
			return -ENOMEM;
		}
		l2uc_qbmp->index =
			ys_k2ulan_bmp_find_first_zero_bit(steering->uc_qbmp_index,
							  YS_K2ULAN_RX_MAC_RULE_NUMB,
							  true);
		if (l2uc_qbmp->index == YS_K2ULAN_RX_MAC_RULE_NUMB) {
			ys_err("ys k2u no more unicast qset bitmap resource!");
			kfree(l2uc_qbmp);
			return -EAGAIN;
		}
		ys_k2ulan_bmp_set_bit(steering->uc_qbmp_index, YS_K2ULAN_QSET_BITMAP_BITS,
				      l2uc_qbmp->index, true);
		memcpy(l2uc_qbmp->bitmap, bitmap, sizeof(l2uc_qbmp->bitmap));
		l2uc_qbmp->ref_cnt = 1;
		ys_k2ulan_set_uc_qbmp(k2ulan, l2uc_qbmp);
		list_add(&l2uc_qbmp->uc_qbmp_node, &steering->l2uc_qbmp_list);
		steering->uc_qbmp_used++;
	}

	return l2uc_qbmp->index;
}

static int ys_k2ulan_free_l2uc_qset_bmp(struct ys_k2ulan *k2ulan, u16 qset,
					struct ys_k2ulan_mac_uc_filter *l2uc_key)
{
	struct ys_k2ulan_uc_qset_bitmap *l2uc_qbmp = NULL;
	struct ys_k2ulan_uc_qset_bitmap *temp;
	struct ys_k2ulan_uc_qset_bitmap *l2uc_qbmp_exist = NULL;
	struct ys_k2ulan_steering *steering;
	bool empty_qbmp = false;
	u32 ret;

	steering = &k2ulan->lan_steering;
	ys_k2ulan_bmp_set_bit(l2uc_key->bitmap, YS_K2ULAN_QSET_BITMAP_BITS,
			      qset, false);
	ret = ys_k2ulan_bmp_find_first_zero_bit(l2uc_key->bitmap,
						YS_K2ULAN_QSET_BITMAP_BITS,
						false);
	if (ret == YS_K2ULAN_QSET_BITMAP_BITS)
		empty_qbmp = true;

	list_for_each_entry_safe(l2uc_qbmp, temp, &steering->l2uc_qbmp_list,
				 uc_qbmp_node) {
		if (l2uc_qbmp->index == l2uc_key->qset_bmp_idx) {
			/* dereference old qset bitmap */
			if (0 == --l2uc_qbmp->ref_cnt) {
				if (ys_k2ulan_bmp_clear_bit(steering->uc_qbmp_index,
							    YS_K2ULAN_QSET_BITMAP_BITS,
							    l2uc_qbmp->index) != 0) {
					ys_err("ys k2u panic %s remove no exist qset bitmap!",
					       __func__);
				}
				list_del(&l2uc_qbmp->uc_qbmp_node);
				steering->uc_qbmp_used--;
				kfree(l2uc_qbmp);
			}
		} else if (!empty_qbmp &&
			   ys_k2ulan_compare_qset_bmp(l2uc_qbmp->bitmap,
						      l2uc_key->bitmap,
						      YS_K2ULAN_QSET_BITMAP) == 0) {
			l2uc_qbmp->ref_cnt++;
			l2uc_qbmp_exist = l2uc_qbmp;
		}
	}

	if (empty_qbmp)
		return -1;

	if (l2uc_qbmp_exist)
		return l2uc_qbmp_exist->index;

	l2uc_qbmp = kzalloc(sizeof(*l2uc_qbmp), GFP_ATOMIC);
	if (IS_ERR_OR_NULL(l2uc_qbmp)) {
		ys_err("ys k2u can not alloc unicast qset bitmap memory!");
		return -ENOMEM;
	}
	l2uc_qbmp->index =
		ys_k2ulan_bmp_find_first_zero_bit(steering->uc_qbmp_index,
						  YS_K2ULAN_RX_MAC_RULE_NUMB,
						  true);
	if (l2uc_qbmp->index == YS_K2ULAN_RX_MAC_RULE_NUMB) {
		ys_err("ys k2u no more unicast qset bitmap resource!");
		kfree(l2uc_qbmp);
		return -EAGAIN;
	}
	ys_k2ulan_bmp_set_bit(steering->uc_qbmp_index,
			      YS_K2ULAN_QSET_BITMAP_BITS,
			      l2uc_qbmp->index, true);
	memcpy(l2uc_qbmp->bitmap, l2uc_key->bitmap, sizeof(l2uc_qbmp->bitmap));
	l2uc_qbmp->ref_cnt = 1;
	ys_k2ulan_set_uc_qbmp(k2ulan, l2uc_qbmp);
	list_add(&l2uc_qbmp->uc_qbmp_node, &steering->l2uc_qbmp_list);
	steering->uc_qbmp_used++;

	return l2uc_qbmp->index;
}

static void ys_k2ulan_init_qset(void __iomem *bar_addr)
{
	u16 qset;

	for (qset = 0; qset < YS_K2ULAN_RX_MAC_RULE_NUMB; qset++) {
		ys_k2ulan_qset_init_hash(bar_addr, qset);
		ys_k2ulan_qset_init_flags(bar_addr, qset);
		ys_k2ulan_qset_init_drops(bar_addr, qset);
		ys_k2ulan_qset_init_vlan(bar_addr, qset);
	}
}

static int ys_k2ulan_add_l2uc_entry(struct ys_k2ulan *k2ulan, u8 *new_mac,
				    struct ys_queue_params *qi)
{
	struct ys_k2ulan_mac_uc_filter *l2uc_key = NULL;
	struct ys_k2ulan_steering *steering;
	struct ys_k2ulan_mac_filter_hw uc_value = {{0}};
	u8 mac_key[6];
	int uc_qbmp_index = -1;
	int ret = 0;

	steering = &k2ulan->lan_steering;
	/* search l2uc key list */
	list_for_each_entry(l2uc_key, &steering->l2uc_key_list,
			    uc_key_node) {
		if (memcmp(l2uc_key->mac, new_mac, ETH_ALEN) == 0) {
			ys_info("%s new mac %02x:%02x:%02x:%02x:%02x:%02x match exist entry",
				__func__, new_mac[0], new_mac[1], new_mac[2], new_mac[3],
				new_mac[4], new_mac[5]);
			break;
		}
	}

	if (&l2uc_key->uc_key_node == &steering->l2uc_key_list)
		l2uc_key = NULL;

	mac_key[5] = new_mac[0];
	mac_key[4] = new_mac[1];
	mac_key[3] = new_mac[2];
	mac_key[2] = new_mac[3];
	mac_key[1] = new_mac[4];
	mac_key[0] = new_mac[5];

	if (l2uc_key) {
		ys_k2ulan_bmp_set_bit(l2uc_key->bitmap, YS_K2ULAN_QSET_BITMAP_BITS,
				      qi->qset, true);
		uc_qbmp_index = ys_k2ulan_alloc_l2uc_qset_bmp(k2ulan,
							      l2uc_key->qset_bmp_idx,
							      l2uc_key->bitmap);
		if (uc_qbmp_index >= YS_K2ULAN_RX_MAC_RULE_NUMB ||
		    uc_qbmp_index < 0) {
			return -EFAULT;
		}
		l2uc_key->qset_bmp_idx = uc_qbmp_index;
		l2uc_key->ref_cnt++;
		memcpy(uc_value.mac, mac_key, ETH_ALEN);
		uc_value.qset_bmp_idx = l2uc_key->qset_bmp_idx;
		uc_value.enable = 1;
		ret = ys_cuckoo_change(k2ulan->lan_mac_table, mac_key, (u8 *)&uc_value);
		if (ret != 0) {
			ys_k2ulan_free_l2uc_qset_bmp(k2ulan, qi->qset, l2uc_key);
			ys_err("uc mac entry insert failed!");
		}
	} else {
		l2uc_key = kzalloc(sizeof(*l2uc_key), GFP_ATOMIC);
		if (IS_ERR_OR_NULL(l2uc_key))
			return -ENOMEM;

		memcpy(l2uc_key->mac, new_mac, ETH_ALEN);
		l2uc_key->qset_bmp_idx = -1;
		ys_k2ulan_bmp_set_bit(l2uc_key->bitmap, YS_K2ULAN_QSET_BITMAP_BITS,
				      qi->qset, true);
		uc_qbmp_index = ys_k2ulan_alloc_l2uc_qset_bmp(k2ulan,
							      l2uc_key->qset_bmp_idx,
							      l2uc_key->bitmap);
		if (uc_qbmp_index >= YS_K2ULAN_RX_MAC_RULE_NUMB ||
		    uc_qbmp_index < 0) {
			kfree(l2uc_key);
			return -EFAULT;
		}
		l2uc_key->qset_bmp_idx = uc_qbmp_index;
		memcpy(uc_value.mac, mac_key, ETH_ALEN);
		uc_value.qset_bmp_idx = uc_qbmp_index;
		uc_value.enable = 1;
		ret = ys_cuckoo_insert(k2ulan->lan_mac_table, mac_key, (u8 *)&uc_value);
		if (ret != 0) {
			ys_err("uc mac entry insert failed!");
			if (ys_k2ulan_bmp_clear_bit(steering->uc_qbmp_index,
						    YS_K2ULAN_QSET_BITMAP_BITS,
						    l2uc_key->qset_bmp_idx) != 0) {
				ys_err("ys k2u panic %s remove no exist qset bitmap!",
				       __func__);
			}
			ys_k2ulan_free_l2uc_qset_bmp(k2ulan, qi->qset, l2uc_key);
			kfree(l2uc_key);
		} else {
			l2uc_key->ref_cnt = 1;
			list_add(&l2uc_key->uc_key_node, &steering->l2uc_key_list);
			steering->uc_used++;
			ys_debug("uc mac entry insert %d success!", steering->uc_used);
		}
	}

	return ret;
}

static int ys_k2ulan_del_l2uc_entry(struct ys_k2ulan *k2ulan, u8 *old_mac,
				    struct ys_queue_params *qi)
{
	struct ys_k2ulan_mac_uc_filter *l2uc_key = NULL;
	struct ys_k2ulan_steering *steering;
	struct ys_k2ulan_mac_filter_hw uc_value = {{0}};
	int uc_qbmp_index = -1;
	u8 mac_key[6];
	int ret = 0;

	steering = &k2ulan->lan_steering;
	/* search l2uc key list */
	list_for_each_entry(l2uc_key, &steering->l2uc_key_list,
			    uc_key_node) {
		if (memcmp(l2uc_key->mac, old_mac, ETH_ALEN) == 0) {
			ys_debug("%s old mac %02x:%02x:%02x:%02x:%02x:%02x match exist entry",
				__func__, old_mac[0], old_mac[1], old_mac[2], old_mac[3],
				old_mac[4], old_mac[5]);
			break;
		}
	}

	if (&l2uc_key->uc_key_node == &steering->l2uc_key_list) {
		ys_debug("%s panic delete old mac %02x:%02x:%02x:%02x:%02x:%02x no exist!",
			__func__, old_mac[0], old_mac[1], old_mac[2], old_mac[3], old_mac[4],
			old_mac[5]);
		return ret;
	}

	mac_key[5] = old_mac[0];
	mac_key[4] = old_mac[1];
	mac_key[3] = old_mac[2];
	mac_key[2] = old_mac[3];
	mac_key[1] = old_mac[4];
	mac_key[0] = old_mac[5];

	uc_qbmp_index = ys_k2ulan_free_l2uc_qset_bmp(k2ulan, qi->qset, l2uc_key);
	if (--l2uc_key->ref_cnt == 0) {
		ret = ys_cuckoo_delete(k2ulan->lan_mac_table, mac_key);
		if (ret == -EINVAL)
			ys_err("ys k2u %s delete mac %02x:%02x:%02x:%02x:%02x:%02x failed!",
			       __func__, old_mac[0], old_mac[1], old_mac[2], old_mac[3],
			       old_mac[4], old_mac[5]);
		list_del(&l2uc_key->uc_key_node);
		kfree(l2uc_key);
		steering->uc_used--;
	} else {
		if (uc_qbmp_index >= YS_K2ULAN_RX_MAC_RULE_NUMB ||
		    uc_qbmp_index < 0) {
			ys_debug("%s panic update old mac %02x:%02x:%02x:%02x:%02x:%02x qbmp!",
				__func__, old_mac[0], old_mac[1], old_mac[2], old_mac[3],
				old_mac[4], old_mac[5]);
			return -EFAULT;
		}
		l2uc_key->qset_bmp_idx = uc_qbmp_index;
		memcpy(uc_value.mac, mac_key, ETH_ALEN);
		uc_value.qset_bmp_idx = l2uc_key->qset_bmp_idx;
		uc_value.enable = 1;
		ret = ys_cuckoo_change(k2ulan->lan_mac_table, mac_key, (u8 *)&uc_value);
		if (ret != 0) {
			ys_err("%s panic change old mac %02x:%02x:%02x:%02x:%02x:%02x qbmp!",
			       __func__, old_mac[0], old_mac[1], old_mac[2], old_mac[3],
			       old_mac[4], old_mac[5]);
		}
	}

	return ret;
}

static int ys_k2ulan_alloc_ipv4_l2mc_qset_bmp(struct ys_k2ulan *k2ulan,
					      int old_qbmp_index, u32 *bitmap)
{
	struct ys_k2ulan_mc_qset_bitmap *l2mc_qbmp = NULL;
	struct ys_k2ulan_mc_qset_bitmap *temp;
	struct ys_k2ulan_mc_qset_bitmap *l2mc_qbmp_exist = NULL;
	struct ys_k2ulan_steering *steering;
	bool new_qbmp_match = false;
	bool old_qbmp_match = false;

	steering = &k2ulan->lan_steering;
	list_for_each_entry_safe(l2mc_qbmp, temp, &steering->ipv4_l2mc_qbmp_list,
				 mc_qbmp_node) {
		ys_debug("compare %p to %p", bitmap, l2mc_qbmp->bitmap);
		if (ys_k2ulan_compare_qset_bmp(l2mc_qbmp->bitmap, bitmap,
					       YS_K2ULAN_QSET_BITMAP) == 0) {
			if (new_qbmp_match)
				ys_err("ys k2u panic add ref mc qbmp list has duplicate entry!");
			l2mc_qbmp->ref_cnt++;
			l2mc_qbmp_exist = l2mc_qbmp;
			new_qbmp_match = true;
			ys_info("ys k2u %s add ref %d for mc qbmp %p",
				__func__, l2mc_qbmp->ref_cnt, l2mc_qbmp);
		}

		if (old_qbmp_index != -1 && l2mc_qbmp->index == old_qbmp_index) {
			if (old_qbmp_match)
				ys_err("ys k2u panic del ref mc qbmp list has duplicate entry!");
			/* dereference old qset bitmap */
			if (0 == --l2mc_qbmp->ref_cnt) {
				l2mc_qbmp->index -= YS_K2ULAN_STEERING_RX_MAC_RULE_ENTRY_NUMB;
				if (ys_k2ulan_bmp_clear_bit(steering->mc_qbmp_index,
							    YS_K2ULAN_QSET_BITMAP_BITS,
							    l2mc_qbmp->index) != 0) {
					ys_err("ys k2u panic remove no exist qset bitmap!");
				}
				list_del(&l2mc_qbmp->mc_qbmp_node);
				steering->mc_qbmp_used--;
				ys_debug("ys k2u %s remove mc qbmp %p", __func__, l2mc_qbmp);
				kfree(l2mc_qbmp);
			} else {
				ys_info("ys k2u %s dec ref %d for mc qbmp %p",
					__func__, l2mc_qbmp->ref_cnt, l2mc_qbmp);
			}
			old_qbmp_match = true;
		}
	}

	if (l2mc_qbmp_exist)
		return l2mc_qbmp_exist->index;

	if (&l2mc_qbmp->mc_qbmp_node == &steering->ipv4_l2mc_qbmp_list)
		l2mc_qbmp = NULL;
	else
		ys_err("ys k2u panic can not match exsit qbmp and l2mc_qbmp not empty!");

	/* alloc new l2mc qset bitmap */
	if (!l2mc_qbmp) {
		l2mc_qbmp = kzalloc(sizeof(*l2mc_qbmp), GFP_ATOMIC);
		if (IS_ERR_OR_NULL(l2mc_qbmp)) {
			ys_err("ys k2u can not alloc multicast qset bitmap memory!");
			return -ENOMEM;
		}
		l2mc_qbmp->index =
			ys_k2ulan_bmp_find_first_zero_bit(steering->mc_qbmp_index,
							  YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB,
							  true);
		if (l2mc_qbmp->index == YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB) {
			ys_err("ys k2u no more multicast qset bitmap resource!");
			kfree(l2mc_qbmp);
			return -EAGAIN;
		}
		ys_k2ulan_bmp_set_bit(steering->mc_qbmp_index, YS_K2ULAN_QSET_BITMAP_BITS,
				      l2mc_qbmp->index, true);
		//mc mac use last YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB MAC FILTER BITMAP
		l2mc_qbmp->index += YS_K2ULAN_STEERING_RX_MAC_RULE_ENTRY_NUMB;
		memcpy(l2mc_qbmp->bitmap, bitmap, sizeof(l2mc_qbmp->bitmap));
		l2mc_qbmp->ref_cnt = 1;
		ys_k2ulan_set_mc_qbmp(k2ulan, l2mc_qbmp);
		list_add(&l2mc_qbmp->mc_qbmp_node, &steering->ipv4_l2mc_qbmp_list);
		steering->mc_qbmp_used++;
		ys_info("ys k2u new mc qbmp %p", l2mc_qbmp);
	}

	return l2mc_qbmp->index;
}

static int ys_k2ulan_free_ipv4_l2mc_qset_bmp(struct ys_k2ulan *k2ulan, u16 qset,
					     struct ys_k2ulan_mac_ipv4_mc_filter *ipv4_l2mc_key)
{
	struct ys_k2ulan_mc_qset_bitmap *l2mc_qbmp = NULL;
	struct ys_k2ulan_mc_qset_bitmap *temp;
	struct ys_k2ulan_mc_qset_bitmap *l2mc_qbmp_exist = NULL;
	struct ys_k2ulan_steering *steering;
	bool empty_qbmp = false;
	u32 ret;

	steering = &k2ulan->lan_steering;
	ys_k2ulan_bmp_set_bit(ipv4_l2mc_key->bitmap, YS_K2ULAN_QSET_BITMAP_BITS,
			      qset, false);
	ret = ys_k2ulan_bmp_find_first_zero_bit(ipv4_l2mc_key->bitmap,
						YS_K2ULAN_QSET_BITMAP_BITS,
						false);
	if (ret == YS_K2ULAN_QSET_BITMAP_BITS)
		empty_qbmp = true;

	list_for_each_entry_safe(l2mc_qbmp, temp, &steering->ipv4_l2mc_qbmp_list,
				 mc_qbmp_node) {
		if (l2mc_qbmp->index == ipv4_l2mc_key->qset_bmp_idx) {
			/* dereference old qset bitmap */
			if (0 == --l2mc_qbmp->ref_cnt) {
				l2mc_qbmp->index -= YS_K2ULAN_STEERING_RX_MAC_RULE_ENTRY_NUMB;
				if (ys_k2ulan_bmp_clear_bit(steering->mc_qbmp_index,
							    YS_K2ULAN_QSET_BITMAP_BITS,
							    l2mc_qbmp->index) != 0) {
					ys_err("ys k2u panic %s remove no exist qset bitmap!",
					       __func__);
				}
				list_del(&l2mc_qbmp->mc_qbmp_node);
				steering->mc_qbmp_used--;
				ys_info("ys k2u %s remove mc qbmp %p", __func__, l2mc_qbmp);
				kfree(l2mc_qbmp);
			} else {
				ys_info("ys k2u %s dec ref %d for mc qbmp %p",
					__func__, l2mc_qbmp->ref_cnt, l2mc_qbmp);
			}
		} else if (!empty_qbmp &&
			   ys_k2ulan_compare_qset_bmp(l2mc_qbmp->bitmap,
						      ipv4_l2mc_key->bitmap,
						      YS_K2ULAN_QSET_BITMAP) == 0) {
			l2mc_qbmp->ref_cnt++;
			if (l2mc_qbmp_exist)
				ys_err("ys k2u panic match new mc qbmp more than 1!");
			l2mc_qbmp_exist = l2mc_qbmp;
		}
	}

	if (empty_qbmp)
		return -1;

	if (l2mc_qbmp_exist)
		return l2mc_qbmp_exist->index;

	l2mc_qbmp = kzalloc(sizeof(*l2mc_qbmp), GFP_ATOMIC);
	if (IS_ERR_OR_NULL(l2mc_qbmp)) {
		ys_err("ys k2u can not alloc multicast qset bitmap memory!");
		return -ENOMEM;
	}
	l2mc_qbmp->index =
		ys_k2ulan_bmp_find_first_zero_bit(steering->mc_qbmp_index,
						  YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB,
						  true);
	if (l2mc_qbmp->index == YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB) {
		ys_err("ys k2u no more multicast qset bitmap resource!");
		kfree(l2mc_qbmp);
		return -EAGAIN;
	}
	ys_k2ulan_bmp_set_bit(steering->mc_qbmp_index,
			      YS_K2ULAN_QSET_BITMAP_BITS,
			      l2mc_qbmp->index, true);
	//mc mac use last YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB MAC FILTER BITMAP
	l2mc_qbmp->index += YS_K2ULAN_STEERING_RX_MAC_RULE_ENTRY_NUMB;
	memcpy(l2mc_qbmp->bitmap, ipv4_l2mc_key->bitmap, sizeof(l2mc_qbmp->bitmap));
	l2mc_qbmp->ref_cnt = 1;
	ys_k2ulan_set_mc_qbmp(k2ulan, l2mc_qbmp);
	list_add(&l2mc_qbmp->mc_qbmp_node, &steering->ipv4_l2mc_qbmp_list);
	steering->mc_qbmp_used++;
	ys_info("ys k2u %s new mc qbmp %p", __func__, l2mc_qbmp);

	return l2mc_qbmp->index;
}

static int ys_k2ulan_add_ipv4_l2mc_entry(struct ys_k2ulan *k2ulan, u8 *mac,
					 struct ys_queue_params *qi)
{
	struct ys_k2ulan_mac_ipv4_mc_filter *ipv4_l2mc_key = NULL, *entry = NULL;
	struct ys_k2ulan_mac_filter_hw mc_value = {{0}};
	struct ys_k2ulan_steering *steering;
	u8 mac_key[6];
	int mc_qbmp_index = -1;
	int ret = 0;

	steering = &k2ulan->lan_steering;
	/* search ipv4 l2mc key list */
	list_for_each_entry(entry, &steering->ipv4_l2mc_key_list,
			    mc_key_node) {
		if (memcmp(entry->mac, mac, ETH_ALEN) == 0) {
			ys_info("%s match exist entry", __func__);
			ipv4_l2mc_key = entry;
			break;
		}
	}

	/* init mac key & entry value */
	mac_key[0] = mac[5];
	mac_key[1] = mac[4];
	mac_key[2] = mac[3];
	mac_key[3] = mac[2];
	mac_key[4] = mac[1];
	mac_key[5] = mac[0];
	mc_value.enable = 1;
	memcpy(mc_value.mac, mac_key, sizeof(mac_key));

	if (ipv4_l2mc_key) {
		/* update l2mc entry qset bitmap index */
		ys_k2ulan_bmp_set_bit(ipv4_l2mc_key->bitmap, YS_K2ULAN_QSET_BITMAP_BITS,
				      qi->qset, true);
		mc_qbmp_index = ys_k2ulan_alloc_ipv4_l2mc_qset_bmp(k2ulan,
								   ipv4_l2mc_key->qset_bmp_idx,
								   ipv4_l2mc_key->bitmap);
		if (mc_qbmp_index >= YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB * 2 ||
		    mc_qbmp_index < YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB) {
			return -EFAULT;
		}
		mc_value.qset_bmp_idx = mc_qbmp_index;
		ret = ys_cuckoo_change(k2ulan->lan_mac_table, mac_key, (u8 *)&mc_value);
		if (ret != 0) {
			ys_k2ulan_free_ipv4_l2mc_qset_bmp(k2ulan, mc_qbmp_index,
							  ipv4_l2mc_key);
			ys_err("mc mac entry insert failed!");
		} else {
			ipv4_l2mc_key->qset_bmp_idx = mc_qbmp_index;
		}
	} else {
		/* add new l2mc entry */
		ipv4_l2mc_key = kzalloc(sizeof(*ipv4_l2mc_key), GFP_ATOMIC);
		if (IS_ERR_OR_NULL(ipv4_l2mc_key))
			return -ENOMEM;
		memcpy(ipv4_l2mc_key->mac, mac, sizeof(mc_value.mac));
		ys_k2ulan_bmp_set_bit(ipv4_l2mc_key->bitmap, YS_K2ULAN_QSET_BITMAP_BITS,
				      qi->qset, true);
		mc_qbmp_index = ys_k2ulan_alloc_ipv4_l2mc_qset_bmp(k2ulan, -1,
								   ipv4_l2mc_key->bitmap);
		if (mc_qbmp_index >= YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB * 2 ||
		    mc_qbmp_index < YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB) {
			kfree(ipv4_l2mc_key);
			ys_info("%s get mc_qbmp_index error %d", __func__, mc_qbmp_index);
			return -EFAULT;
		}

		mc_value.qset_bmp_idx = mc_qbmp_index;
		ret = ys_cuckoo_insert(k2ulan->lan_mac_table, mac_key, (u8 *)&mc_value);
		if (ret != 0) {
			ys_k2ulan_free_ipv4_l2mc_qset_bmp(k2ulan, mc_qbmp_index,
							  ipv4_l2mc_key);
			kfree(ipv4_l2mc_key);
			ys_err("mc mac entry insert failed!");
		} else {
			ipv4_l2mc_key->qset_bmp_idx = mc_qbmp_index;
			steering->mc_key_used++;
			list_add(&ipv4_l2mc_key->mc_key_node,
				 &steering->ipv4_l2mc_key_list);
		}
	}

	return 0;
}

static int ys_k2ulan_del_ipv4_l2mc_entry(struct ys_k2ulan *k2ulan, u8 *mac,
					 struct ys_queue_params *qi)
{
	struct ys_k2ulan_mac_ipv4_mc_filter *ipv4_l2mc_key = NULL, *entry = NULL;
	struct ys_k2ulan_mac_filter_hw mc_value = {{0}};
	struct ys_k2ulan_steering *steering;
	u8 mac_key[6];
	int mc_qbmp_index = -1;
	int ret = 0;

	steering = &k2ulan->lan_steering;
	/* search ipv4 l2mc key list */
	list_for_each_entry(entry, &steering->ipv4_l2mc_key_list, mc_key_node) {
		if (memcmp(entry->mac, mac, ETH_ALEN) == 0) {
			ipv4_l2mc_key = entry;
			break;
		}
	}

	/* init mac key & entry value */
	mac_key[0] = mac[5];
	mac_key[1] = mac[4];
	mac_key[2] = mac[3];
	mac_key[3] = mac[2];
	mac_key[4] = mac[1];
	mac_key[5] = mac[0];
	mc_value.enable = 1;
	memcpy(mc_value.mac, mac_key, sizeof(mac_key));

	if (ipv4_l2mc_key) {
		/* l2mc entry qset bitmap remove this qset */
		mc_qbmp_index = ys_k2ulan_free_ipv4_l2mc_qset_bmp(k2ulan, qi->qset,
								  ipv4_l2mc_key);
		if (mc_qbmp_index >= YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB * 2 ||
		    (mc_qbmp_index < YS_K2ULAN_RX_IPV4_L2MC_RULE_NUMB &&
		     mc_qbmp_index != -1)) {
			return -EFAULT;
		}
		if (mc_qbmp_index == -1) {
			/* l2mc entry need remove */
			ret = ys_cuckoo_delete(k2ulan->lan_mac_table, mac_key);
			if (ret != 0)
				ys_err("mc mac entry delete failed!");
			list_del(&ipv4_l2mc_key->mc_key_node);
			kfree(ipv4_l2mc_key);
			steering->mc_key_used--;
		} else {
			mc_value.qset_bmp_idx = mc_qbmp_index;
			ret = ys_cuckoo_change(k2ulan->lan_mac_table, mac_key,
					       (u8 *)&mc_value);
			if (ret != 0)
				ys_err("mc mac entry insert failed!");
			else
				ipv4_l2mc_key->qset_bmp_idx = mc_qbmp_index;
		}
	} else {
		ys_err("k2u delete no exist mc entry!");
	}

	return 0;
}

static int ys_k2ulan_update_l2(struct ys_pdev_priv *pdev_priv,
			       struct ys_ndev_priv *ndev_priv,
			       enum ys_k2ulan_l2_filter_type type,
			       enum ys_k2ulan_filter_action action,
			       union ys_k2ulan_l2_data *data)
{
	struct ys_k2ulan *k2ulan = NULL;
	struct ys_k2ulan_steering *steering;
	struct ys_queue_params *qi;
	u8 mac_empty[6] = {0};
	int ret = 0;
	unsigned long flags;

	k2ulan = ys_aux_match_k2ulan_dev(pdev_priv->pdev);
	steering = &k2ulan->lan_steering;
	qi = &ndev_priv->qi;
	spin_lock_irqsave(&steering->lock, flags);
	switch (type) {
	case YS_K2ULAN_L2UC_FILTER:
		ys_dev_debug("uc addr :%.2x:%.2x:%.2x:%.2x:%.2x:%.2x, action : %s",
			    data->uc.mac[0], data->uc.mac[1], data->uc.mac[2],
			    data->uc.mac[3], data->uc.mac[4], data->uc.mac[5],
			    action == YS_K2ULAN_FILTER_ADD ?
			    "add" : (action == YS_K2ULAN_FILTER_DEL ? "del" : "update"));
		ys_dev_debug("before action current uc addr number : %d, as follows:",
			    steering->uc_used);
		ys_dev_debug("qi.qset: %d", qi->qset);
		switch (action) {
		case YS_K2ULAN_FILTER_ADD:
			ret = ys_k2ulan_add_l2uc_entry(k2ulan, data->uc.mac, qi);
			if (ret != 0)
				ys_dev_err("ys k2u %s uc mac entry insert failed!",
					   __func__);
			break;
		case YS_K2ULAN_FILTER_UPDATE:
			if (memcmp(mac_empty, ndev_priv->old_mac, ETH_ALEN) != 0) {
				ys_dev_debug("pf %d old mac: %02x:%02x:%02x:%02x:%02x:%02x",
					    pdev_priv->pf_id, ndev_priv->old_mac[0],
					    ndev_priv->old_mac[1], ndev_priv->old_mac[2],
					    ndev_priv->old_mac[3], ndev_priv->old_mac[4],
					    ndev_priv->old_mac[5]);
				ret = ys_k2ulan_del_l2uc_entry(k2ulan, ndev_priv->old_mac, qi);
				if (ret != 0)
					ys_dev_err("ys k2u %s delete old mac failed!", __func__);
			}
			/* add new mac value */
			ret = ys_k2ulan_add_l2uc_entry(k2ulan, data->uc.mac, qi);
			if (ret != 0) {
				ys_dev_err("uc mac entry update failed!");
			} else {
				memcpy(ndev_priv->old_mac, data->uc.mac, ETH_ALEN);
				ys_dev_debug("pf %d update new mac: %02x:%02x:%02x:%02x:%02x:%02x",
					    pdev_priv->pf_id, ndev_priv->old_mac[0],
					    ndev_priv->old_mac[1], ndev_priv->old_mac[2],
					    ndev_priv->old_mac[3], ndev_priv->old_mac[4],
					    ndev_priv->old_mac[5]);
			}
			break;
		case YS_K2ULAN_FILTER_DEL:
			ret = ys_k2ulan_del_l2uc_entry(k2ulan, data->uc.mac, qi);
			if (ret != 0)
				ys_dev_err("ys k2u %s uc mac entry delete failed!",
					   __func__);
			break;
		default:
			break;
		}
		ys_dev_debug("after action uc addr number : %d, as follows:",
			     steering->uc_used);
		break;
	case YS_K2ULAN_L2MC_IPV4_FILTER:
		ys_dev_debug("mc addr : %02x:%02x:%02x:%02x:%02x:%02x, action : %s",
			    data->mc.mac[0], data->mc.mac[1], data->mc.mac[2],
			    data->mc.mac[3], data->mc.mac[4], data->mc.mac[5],
			    action == YS_K2ULAN_FILTER_ADD ?
			    "add" : (action == YS_K2ULAN_FILTER_DEL ? "del" : "update"));
		ys_dev_debug("before action current mc addr number : %d, as follows:",
			    steering->mc_key_used);
		ys_dev_debug("qi.qset: %d", qi->qset);
		switch (action) {
		case YS_K2ULAN_FILTER_ADD:
			ret = ys_k2ulan_add_ipv4_l2mc_entry(k2ulan, data->mc.mac, qi);
			break;
		case YS_K2ULAN_FILTER_DEL:
			ret = ys_k2ulan_del_ipv4_l2mc_entry(k2ulan, data->mc.mac, qi);
			break;
		default:
			ys_dev_debug("l2 not support action");
			break;
		}
		ys_dev_debug("after action mc addr number : %d, as follows:",
			     steering->mc_key_used);
		break;
	case YS_K2ULAN_VLAN_FILTER:
		break;
	default:
		ret = -1;
	}
	spin_unlock_irqrestore(&steering->lock, flags);
	return ret;
}

static int ys_k2ulan_update_l2_filter_wrapper(struct ys_pdev_priv *pdev_priv,
					      struct ys_ndev_priv *ndev_priv,
					      enum ys_k2ulan_l2_filter_type type,
					      enum ys_k2ulan_filter_action action,
					      u8 *mac)
{
	union ys_k2ulan_l2_data data;

	if (type == YS_K2ULAN_L2UC_FILTER)
		memcpy(data.uc.mac, mac, ETH_ALEN);
	else if (type == YS_K2ULAN_L2MC_IPV4_FILTER)
		memcpy(data.mc.mac, mac, ETH_ALEN);

	return ys_k2ulan_update_l2(pdev_priv, ndev_priv, type, action, &data);
}

static void ys_k2ulan_set_vlan_qbmp(struct ys_k2ulan_steering *steering,
				    void __iomem *hw_addr,
				    u16 qbmp_idx,
				    u32 *vlan_qbmp)
{
	u32 i;
	void __iomem *entry_addr;
	struct ys_k2ulan_steering_bitmap empty_qbmp = {{0}};

	if (!vlan_qbmp)
		vlan_qbmp = empty_qbmp.bitmap;

	entry_addr = hw_addr + YS_K2ULAN_STEERING_RX_VLAN_RULE_ENTRY_ADDR(qbmp_idx);
	if (steering->lan_hw_type == YS_K2ULAN_HW_TYPE_NORMAL)
		for (i = 0; i < YS_K2ULAN_STEERING_RX_VLAN_RULE_ENTRY_LEN / 4; i++)
			ys_wr32(entry_addr, i * sizeof(u32), vlan_qbmp[i]);
	else if (steering->lan_hw_type == YS_K2ULAN_HW_TYPE_BNIC)
		for (i = 0; i < YS_K2ULAN_STEERING_RX_VLAN_RULE_ENTRY_LEN / 2 / 4; i++)
			ys_wr32(entry_addr, i * sizeof(u32), vlan_qbmp[i]);
	else
		ys_err("k2u lan set vlan qset bitmap with unknown lan hw type %d!",
		       steering->lan_hw_type);
}

static void ys_k2ulan_get_vlan_qbmp(struct ys_k2ulan_steering *steering,
				    void __iomem *hw_addr,
				    u16 qbmp_idx,
				    u32 *vlan_qbmp)
{
	u32 i;
	void __iomem *entry_addr;

	entry_addr = hw_addr + YS_K2ULAN_STEERING_RX_VLAN_RULE_ENTRY_ADDR(qbmp_idx);
	if (steering->lan_hw_type == YS_K2ULAN_HW_TYPE_NORMAL)
		for (i = 0; i < YS_K2ULAN_STEERING_RX_VLAN_RULE_ENTRY_LEN / 4; i++)
			vlan_qbmp[i] = ys_rd32(entry_addr, i * sizeof(u32));
	else if (steering->lan_hw_type == YS_K2ULAN_HW_TYPE_BNIC)
		for (i = 0; i < YS_K2ULAN_STEERING_RX_VLAN_RULE_ENTRY_LEN / 2 / 4; i++)
			vlan_qbmp[i] = ys_rd32(entry_addr, i * sizeof(u32));
	else
		ys_err("k2u lan get vlan qset bitmap with unknown lan hw type %d!",
		       steering->lan_hw_type);
}

static int ys_k2ulan_update_vlan_qset_bmp(struct ys_k2ulan_steering *steering,
					  void __iomem *hw_addr, int old_qbmp_index,
					  u32 *bitmap)
{
	struct ys_k2ulan_vlan_qbmp *vlan_qbmp = NULL;
	struct ys_k2ulan_vlan_qbmp *temp;
	struct ys_k2ulan_vlan_qbmp *vlan_qbmp_exist = NULL;
	bool new_qbmp_match = false;
	bool old_qbmp_match = false;

	list_for_each_entry_safe(vlan_qbmp, temp, &steering->vlan_qset_bmp_list,
				 vlan_qbmp_node) {
		ys_debug("compare %p to %p", bitmap, vlan_qbmp->bitmap);
		if (ys_k2ulan_compare_qset_bmp(vlan_qbmp->bitmap, bitmap,
					       YS_K2ULAN_QSET_BITMAP) == 0) {
			if (new_qbmp_match)
				ys_err("ys k2u panic add ref vlan qbmp list has duplicate entry!");
			vlan_qbmp->ref_cnt++;
			vlan_qbmp_exist = vlan_qbmp;
			new_qbmp_match = true;
			ys_info("vlan qset bmp %p add ref cnt %d!", vlan_qbmp, vlan_qbmp->ref_cnt);
		}

		if (old_qbmp_index != -1 && vlan_qbmp->index == old_qbmp_index) {
			if (old_qbmp_match)
				ys_err("ys k2u panic del ref vlan qbmp list has duplicate entry!");
			/* dereference old qset bitmap */
			if (0 == --vlan_qbmp->ref_cnt) {
				// non-bnic mode kernel vlan use first half vlan qbmp resource
				if (steering->dpu_mode != MODE_LEGACY)
					old_qbmp_index -= steering->vlan_qbmp_num;
				if (ys_k2ulan_bmp_clear_bit(steering->vlan_qbmp_index,
							    YS_K2ULAN_QSET_BITMAP_BITS,
							    old_qbmp_index) != 0) {
					ys_err("ys k2u panic remove no exist vlan qset bitmap!");
				}
				list_del(&vlan_qbmp->vlan_qbmp_node);
				steering->vlan_qbmp_used--;
				ys_info("vlan qset bmp %p qbmp index %d ref cnt 0!",
					vlan_qbmp, old_qbmp_index);
				kfree(vlan_qbmp);
			} else {
				ys_info("vlan qset bmp %p dec ref cnt %d!",
					vlan_qbmp, vlan_qbmp->ref_cnt);
			}
			old_qbmp_match = true;
		}
	}

	if (vlan_qbmp_exist)
		return vlan_qbmp_exist->index;

	if (ys_k2ulan_bmp_find_first_zero_bit(bitmap,
					      YS_K2ULAN_QSET_BITMAP_BITS,
					      false) == YS_K2ULAN_QSET_BITMAP_BITS) {
		ys_info("empty vlan qset bitmap return -1!");
		return -1;
	}

	if (&vlan_qbmp->vlan_qbmp_node == &steering->vlan_qset_bmp_list)
		vlan_qbmp = NULL;

	/* alloc new vlan qset bitmap */
	if (!vlan_qbmp) {
		vlan_qbmp = kzalloc(sizeof(*vlan_qbmp), GFP_ATOMIC);
		if (IS_ERR_OR_NULL(vlan_qbmp)) {
			ys_err("ys k2u can not alloc vlan qset bitmap memory!");
			return -ENOMEM;
		}
		vlan_qbmp->index =
			ys_k2ulan_bmp_find_first_zero_bit(steering->vlan_qbmp_index,
							  steering->vlan_qbmp_num,
							  true);
		if (vlan_qbmp->index == steering->vlan_qbmp_num) {
			ys_err("ys k2u no more vlan qset bitmap resource!");
			kfree(vlan_qbmp);
			return -EAGAIN;
		}
		ys_k2ulan_bmp_set_bit(steering->vlan_qbmp_index, YS_K2ULAN_QSET_BITMAP_BITS,
				      vlan_qbmp->index, true);
		// non-bnic mode kernel vlan use first half vlan qbmp resource
		if (steering->dpu_mode != MODE_LEGACY)
			vlan_qbmp->index += steering->vlan_qbmp_num;
		memcpy(vlan_qbmp->bitmap, bitmap, sizeof(vlan_qbmp->bitmap));
		vlan_qbmp->ref_cnt = 1;
		ys_k2ulan_set_vlan_qbmp(steering, hw_addr,
					vlan_qbmp->index, vlan_qbmp->bitmap);
		list_add(&vlan_qbmp->vlan_qbmp_node, &steering->vlan_qset_bmp_list);
		steering->vlan_qbmp_used++;
		ys_info("new vlan qset bmp %p ref cnt 1!", vlan_qbmp);
	}

	return vlan_qbmp->index;
}

static void ys_k2ulan_mbox_req_set_mtu(struct ys_mbox *mbox, u16 mtu)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0}, ack_msg;
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("vf req_set_mtu get mbox failed!");
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role != MB_VF) {
		ys_dev_err("req_set_mtu mbox role is invalid, role:%x", mbox->role);
		return;
	}
	ctx->type = MB_PF;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	cmd->cmd_type = YS_K2ULAN_CMD_VF_MTU_SET;
	memcpy(cmd->cmd_data, &mtu, sizeof(mtu));
	cmd->data_len = sizeof(mtu);
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg.data;

	if (ys_k2ulan_cmd_exec(mbox, YS_MBOX_OPCODE_SET_MTU, send_id,
			       cmd, sizeof(*cmd) + cmd->data_len, &ack_msg)) {
		ys_dev_err("vf set qset mtu failed. status:%x", cmd_ack->cmd_status);
	}
}

static void ys_k2ulan_lib_set_mtu(struct ys_pdev_priv *pdev_priv,
				  struct ys_queue_params qi,
				  u16 mtu)
{
	void __iomem *hw_addr;
	struct k2ulan_qset_mtu *qset_mtu;
	u32 reg;

	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_MTU(qi.qset));
	qset_mtu = (struct k2ulan_qset_mtu *)&reg;
	qset_mtu->q_mtu = mtu;
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_MTU(qi.qset), reg);
}

static int ys_k2ulan_mbox_set_mtu(struct ys_mbox *mbox, struct ys_k2ulan_cmd *cmd, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_vf_info *vf_info;
	struct ys_queue_params qi = {0};
	u16 mtu;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	qi.qset = vf_info->qset;

	memcpy(&mtu, cmd->cmd_data, sizeof(mtu));
	ys_k2ulan_lib_set_mtu(pdev_priv, qi, mtu);

	return 0;
}

static int ys_k2ulan_set_qset_mtu(struct net_device *ndev, int mtu)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf mtu*/
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("mbox not support!\n");
			return -1;
		}
		ys_k2ulan_mbox_req_set_mtu(mbox, mtu);
	} else {
		ys_k2ulan_lib_set_mtu(pdev_priv, ndev_priv->qi, mtu);
	}

	return 0;
}

static void ys_k2ulan_mbox_req_set_hash_mode(struct ys_mbox *mbox, struct ys_hash_field hash_field,
					     struct ys_queue_params qi)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0}, ack_msg;
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("vf req_set_hash_mode get mbox failed!");
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role != MB_VF) {
		ys_dev_err("req_set_hash_mode mbox role is invalid, role:%x", mbox->role);
		return;
	}
	ctx->type = MB_PF;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	cmd->cmd_type = YS_K2ULAN_CMD_VF_HASH_SET;
	cmd->data_len = sizeof(hash_field);
	memcpy(cmd->cmd_data, &hash_field, cmd->data_len);
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg.data;

	if (ys_k2ulan_cmd_exec(mbox, YS_MBOX_OPCODE_SET_HASH, send_id,
			       cmd, sizeof(*cmd) + cmd->data_len, &ack_msg)) {
		ys_dev_err("vf set hash mode failed. status:%x", cmd_ack->cmd_status);
	}
}

static int ys_k2ulan_mbox_set_hash_mode(struct ys_mbox *mbox, struct ys_k2ulan_cmd *cmd, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_vf_info *vf_info;
	struct k2ulan_qset_hash *qset_hash;
	void __iomem *hw_addr;
	u16 qset;
	u32 temp = 0;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	qset = vf_info->qset;

	temp = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_HASH(qset));
	qset_hash = (struct k2ulan_qset_hash *)&temp;
	qset_hash->q_ipv4_tcp_hash_mode = cmd->cmd_data[0];
	qset_hash->q_ipv6_tcp_hash_mode = cmd->cmd_data[1];
	qset_hash->q_ipv4_udp_hash_mode = cmd->cmd_data[2];
	qset_hash->q_ipv6_udp_hash_mode = cmd->cmd_data[3];
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_HASH(qset), temp);

	return 0;
}

static void ys_k2ulan_set_qset_hash(struct net_device *ndev)
{
	struct k2ulan_qset_hash *qset_hash;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;
	void __iomem *hw_addr;
	u16 qset;
	u32 temp = 0;

	ndev_priv = netdev_priv(ndev);
	qset = ndev_priv->qi.qset;

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf hash*/
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("mbox not support!\n");
			return;
		}
		ys_dev_debug("vf %d set hash ip4: tcp %02x, udp %02x ip6: tcp %02x, udp %02x",
			     pdev_priv->vf_id, ndev_priv->hash_field.ipv4_tcp_hash_mode,
			     ndev_priv->hash_field.ipv4_udp_hash_mode,
			     ndev_priv->hash_field.ipv6_tcp_hash_mode,
			     ndev_priv->hash_field.ipv6_udp_hash_mode);
		ys_k2ulan_mbox_req_set_hash_mode(mbox, ndev_priv->hash_field,
						 ndev_priv->qi);
	} else {
		temp = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_HASH(qset));
		qset_hash = (struct k2ulan_qset_hash *)&temp;
		qset_hash->q_ipv4_tcp_hash_mode = ndev_priv->hash_field.ipv4_tcp_hash_mode;
		qset_hash->q_ipv4_udp_hash_mode = ndev_priv->hash_field.ipv4_udp_hash_mode;
		qset_hash->q_ipv6_tcp_hash_mode = ndev_priv->hash_field.ipv6_tcp_hash_mode;
		qset_hash->q_ipv6_udp_hash_mode = ndev_priv->hash_field.ipv6_udp_hash_mode;
		ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_HASH(qset), temp);
	}
}

static void ys_k2ulan_mbox_req_set_mac(struct ys_mbox *mbox, u8 *mac,
				       u8 *old_mac, struct ys_queue_params qi,
				       enum ys_k2ulan_filter_action action)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0};
	struct ys_k2ulan_cmd *cmd;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("req_set_mac get mbox failed!");
		return;
	}

	if (mbox->role != MB_VF && mbox->role != MB_PF) {
		ys_err("req_set_mac mbox role is invalid, role:%x", mbox->role);
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role == MB_VF)
		ctx->type = MB_PF;
	else
		ctx->type = MB_MASTER;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	memcpy(cmd->cmd_data, mac, ETH_ALEN); //new mac
	cmd->data_len = ETH_ALEN;
	memcpy(cmd->cmd_data + ETH_ALEN, &qi, sizeof(qi)); //qset info
	cmd->data_len += sizeof(qi);

	if (action == YS_K2ULAN_FILTER_UPDATE && IS_ERR_OR_NULL(old_mac)) {
		ys_err("send uc mac update mailbox msg but old mac is NULL!");
		return;
	}

	if (old_mac) {
		memcpy(cmd->cmd_data + cmd->data_len, old_mac, ETH_ALEN); //old mac
		cmd->data_len += ETH_ALEN;
	}

	switch (action) {
	case YS_K2ULAN_FILTER_ADD:
		cmd->cmd_type = YS_K2ULAN_CMD_VF_UC_ADD;
		break;
	case YS_K2ULAN_FILTER_UPDATE:
		cmd->cmd_type = YS_K2ULAN_CMD_VF_UC_UPD;
		break;
	case YS_K2ULAN_FILTER_DEL:
		cmd->cmd_type = YS_K2ULAN_CMD_VF_UC_DEL;
		break;
	default:
		ys_err("uc mac mailbox msg action type %d invalid!", action);
		return;
	}

	if (ys_k2ulan_cmd_exec_async(mbox, YS_MBOX_OPCODE_SET_MAC, send_id, cmd,
				     sizeof(*cmd) + cmd->data_len)) {
		if (mbox->role == MB_PF)
			ys_dev_err("salve pf set mac failed!");
		else
			ys_dev_err("vf set mac failed!");
	}
}

static int ys_k2ulan_mbox_req_set_vf_mac(struct ys_mbox *mbox, u8 *mac,
					 u8 *old_mac, struct ys_queue_params *qi,
					 u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg *msg, *ack_msg;
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;
	int ret = 0;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("req_set_vf_mac get mbox failed!");
		ret = -EFAULT;
		goto ret_nofree;
	}

	if (mbox->role != MB_PF && mbox->role != MB_MASTER) {
		ys_err("req_set_vf_mac mbox role is invalid, role:%x", mbox->role);
		ret = -EFAULT;
		goto ret_nofree;
	}
	msg = kzalloc(sizeof(*msg), GFP_ATOMIC);
	if (IS_ERR_OR_NULL(msg)) {
		ys_err("req_set_vf_mac alloc mailbox request message failed!");
		ret = -ENOMEM;
		goto ret_nofree;
	}
	ack_msg = kzalloc(sizeof(*ack_msg), GFP_ATOMIC);
	if (IS_ERR_OR_NULL(ack_msg)) {
		ys_err("req_set_vf_mac alloc mailbox ack message failed!");
		ret = -ENOMEM;
		goto ret_free_1;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	ctx->type = MB_VF;
	ctx->func_id = vf_id - 1;

	cmd = (struct ys_k2ulan_cmd *)msg->data;
	cmd->cmd_type = YS_K2ULAN_CMD_PF_SET_VF_UC;
	memcpy(cmd->cmd_data, mac, ETH_ALEN); //new mac
	cmd->data_len = ETH_ALEN;
	memcpy(cmd->cmd_data + ETH_ALEN, qi, sizeof(struct ys_queue_params)); //vf qset info
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg->data;
	cmd->data_len += sizeof(struct ys_queue_params);

	if (ys_k2ulan_cmd_exec(mbox, YS_MBOX_OPCODE_SET_VF_MAC, send_id,
			       cmd, sizeof(*cmd) + cmd->data_len, ack_msg)) {
		ys_dev_err("pf set vf mac failed. status:%x", cmd_ack->cmd_status);
		ret = -EFAULT;
		goto ret_free_2;
	}
	memcpy(old_mac, cmd_ack->cmd_data, ETH_ALEN);

ret_free_2:
	kfree(ack_msg);
ret_free_1:
	kfree(msg);
ret_nofree:
	return ret;
}

static void ys_k2ulan_set_mac(struct net_device *ndev, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_ndev_priv *ndev_priv;
	struct ys_mbox *mbox;
	u8 *mac;
	u8 *old_mac;
	struct ys_vf_info *vf_info;
	struct ys_queue_params qi;
	int ret;

	ndev_priv = netdev_priv(ndev);
	mac = (u8 *)ndev->dev_addr;
	old_mac = (u8 *)ndev_priv->old_mac;
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf mac*/
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("mbox not support!\n");
			return;
		}
		ys_k2ulan_mbox_req_set_mac(mbox, mac, old_mac, ndev_priv->qi,
					   YS_K2ULAN_FILTER_UPDATE);
		memcpy(old_mac, mac, ETH_ALEN);
	} else {
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("mbox not support!\n");
			return;
		}
		/*pf set vf mac*/
		if (vf_id > 0) {
			struct ys_ndev_priv *fake_ndev_priv;

			fake_ndev_priv = kzalloc(sizeof(*fake_ndev_priv), GFP_ATOMIC);
			if (IS_ERR_OR_NULL(fake_ndev_priv)) {
				ys_err("%s alloc fake ndev private info no memory!", __func__);
				return;
			}
			/*request pf set vf mac*/
			vf_info = &pdev_priv->sriov_info.vfinfo[vf_id - 1];
			qi.qset = vf_info->qset;
			mac = vf_info->vf_mac_addresses;
			ret = ys_k2ulan_mbox_req_set_vf_mac(mbox, mac, fake_ndev_priv->old_mac,
							    &qi, vf_id);
			if (ret != 0) {
				ys_dev_err("pf update vf mac update failed!\n");
				kfree(fake_ndev_priv);
				return;
			}
			/* make a fake ndev */
			fake_ndev_priv->qi = qi;
			if (mbox->role == MB_MASTER)
				ys_k2ulan_update_l2_filter_wrapper(pdev_priv,
								   fake_ndev_priv,
								   YS_K2ULAN_L2UC_FILTER,
								   YS_K2ULAN_FILTER_UPDATE,
								   mac);
			else
				ys_k2ulan_mbox_req_set_mac(mbox, mac, old_mac, qi,
							   YS_K2ULAN_FILTER_UPDATE);
			kfree(fake_ndev_priv);
		} else {
			if (mbox->role == MB_MASTER) {
				ys_k2ulan_update_l2_filter_wrapper(pdev_priv, ndev_priv,
								   YS_K2ULAN_L2UC_FILTER,
								   YS_K2ULAN_FILTER_UPDATE,
								   mac);
			} else {
				ys_k2ulan_mbox_req_set_mac(mbox, mac, old_mac, ndev_priv->qi,
							   YS_K2ULAN_FILTER_UPDATE);
				memcpy(old_mac, mac, ETH_ALEN);
			}
		}
	}
}

static void ys_k2ulan_clear_mac(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;
	u8 *mac;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	mac = (u8 *)ndev->dev_addr;
	mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
	if (!mbox) {
		ys_dev_err("mbox not support!\n");
		return;
	}
	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf mac*/
		ys_k2ulan_mbox_req_set_mac(mbox, mac, NULL, ndev_priv->qi,
					   YS_K2ULAN_FILTER_DEL);
	} else {
		if (mbox->role == MB_MASTER) {
			ys_k2ulan_update_l2_filter_wrapper(pdev_priv, ndev_priv,
							   YS_K2ULAN_L2UC_FILTER,
							   YS_K2ULAN_FILTER_DEL, mac);
		} else {
			ys_k2ulan_mbox_req_set_mac(mbox, mac, NULL, ndev_priv->qi,
						   YS_K2ULAN_FILTER_DEL);
		}
	}
}

static int ys_k2ulan_mbox_set_mac(struct ys_mbox *mbox, struct ys_k2ulan_cmd *cmd, u16 msg_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_ndev_priv *ndev_priv;
	struct ys_queue_params qi;
	u8 mac[ETH_ALEN];
	enum ys_k2ulan_filter_action action;
	struct ys_vf_info *vf_info;
	struct ys_k2ulan_mbox_ctx *ctx = NULL;
	int ret;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	memcpy(mac, cmd->cmd_data, sizeof(mac));
	memcpy(&qi, cmd->cmd_data + ETH_ALEN, sizeof(qi));
	ctx = (struct ys_k2ulan_mbox_ctx *)&msg_id;
	/* make a fake ndev */
	ndev_priv = kzalloc(sizeof(*ndev_priv), GFP_ATOMIC);
	if (IS_ERR_OR_NULL(ndev_priv)) {
		ys_err("%s alloc fake ndev private info no memory!", __func__);
		return -ENOMEM;
	}
	ndev_priv->qi = qi;

	switch (cmd->cmd_type) {
	case YS_K2ULAN_CMD_VF_UC_ADD:
		action = YS_K2ULAN_FILTER_ADD;
		break;
	case YS_K2ULAN_CMD_VF_UC_UPD:
		memcpy(ndev_priv->old_mac, cmd->cmd_data + ETH_ALEN + sizeof(qi), ETH_ALEN);
		action = YS_K2ULAN_FILTER_UPDATE;
		break;
	case YS_K2ULAN_CMD_VF_UC_DEL:
		action = YS_K2ULAN_FILTER_DEL;
		break;
	default:
		ys_dev_err("pf set vf mac get invalid cmd type %d\n", cmd->cmd_type);
		return -1;
	}

	if (mbox->role == MB_PF) {
		ys_k2ulan_mbox_req_set_mac(mbox, mac, ndev_priv->old_mac,
					   ndev_priv->qi, action);
		kfree(ndev_priv);
		if (cmd->cmd_type == YS_K2ULAN_CMD_VF_UC_UPD) {
			vf_info = &pdev_priv->sriov_info.vfinfo[ctx->func_id];
			memcpy(vf_info->vf_mac_addresses, mac, ETH_ALEN);
		}
		return 0;
	}

	ret = ys_k2ulan_update_l2_filter_wrapper(pdev_priv, ndev_priv,
						 YS_K2ULAN_L2UC_FILTER,
						 action, mac);
	if (ctx->type == MB_VF && cmd->cmd_type == YS_K2ULAN_CMD_VF_UC_UPD) {
		vf_info = &pdev_priv->sriov_info.vfinfo[ctx->func_id];
		memcpy(vf_info->vf_mac_addresses, mac, ETH_ALEN);
	}
	kfree(ndev_priv);
	return ret;
}

static int ys_k2ulan_mbox_pf_set_vf_mac(struct ys_mbox *mbox, struct ys_k2ulan_cmd *cmd,
					struct ys_k2ulan_cmd *cmd_ack, u16 vf_id)
{
	struct ys_ndev_priv *ndev_priv;
	struct net_device *ndev;
	struct ys_queue_params qi;
	u8 *ndev_mac;
	u8 mac[ETH_ALEN];

	memcpy(mac, cmd->cmd_data, ETH_ALEN);
	memcpy(&qi, cmd->cmd_data + ETH_ALEN, sizeof(struct ys_queue_params));

	ndev = ys_aux_match_ndev_by_qset(mbox->pdev, qi.qset);
	if (IS_ERR_OR_NULL(ndev)) {
		ys_err("vf handle pf set vf mac message get ndev failed!");
		return -1;
	}
	ndev_priv = netdev_priv(ndev);
	ndev_mac = (u8 *)ndev->dev_addr;

	memcpy(cmd_ack->cmd_data, ndev_priv->old_mac, ETH_ALEN);
	memcpy(ndev_priv->old_mac, mac, ETH_ALEN);
	memcpy(ndev_mac, mac, ETH_ALEN);

	return 0;
}

static int ys_k2ulan_update_uc_mac_addr(struct net_device *ndev, u16 vf_id,
					u8 *old_eth_addr, u8 *new_eth_addr)
{
	ys_k2ulan_set_mac(ndev, vf_id);

	return 0;
}

static void ys_k2ulan_mbox_req_clear_hash(struct ys_mbox *mbox)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0}, ack_msg;
	struct ys_hash_field hash_field = {0};
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("vf req_clear_hash get mbox failed!");
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role != MB_VF) {
		ys_dev_err("req_clear_hash mbox role is invalid, role:%x", mbox->role);
		return;
	}
	ctx->type = MB_PF;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	cmd->cmd_type = YS_K2ULAN_CMD_VF_HASH_CLEAR;
	cmd->data_len = sizeof(hash_field);
	memcpy(cmd->cmd_data, &hash_field, cmd->data_len);
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg.data;

	if (ys_k2ulan_cmd_exec(mbox, YS_MBOX_OPCODE_CLEAR_HASH, send_id,
			       cmd, sizeof(*cmd) + cmd->data_len, &ack_msg)) {
		ys_dev_err("vf clear hash mode failed. status:%x", cmd_ack->cmd_status);
	}
}

static int ys_k2ulan_mbox_clear_hash(struct ys_mbox *mbox, struct ys_k2ulan_cmd *cmd, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_vf_info *vf_info;
	struct k2ulan_qset_hash *qset_hash;
	void __iomem *hw_addr;
	u16 qset;
	u32 temp;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	qset = vf_info->qset;

	temp = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_HASH(qset));
	qset_hash = (struct k2ulan_qset_hash *)&temp;
	qset_hash->q_ipv4_tcp_hash_mode = 0;
	qset_hash->q_ipv4_udp_hash_mode = 0;
	qset_hash->q_ipv6_tcp_hash_mode = 0;
	qset_hash->q_ipv6_udp_hash_mode = 0;
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_HASH(qset), temp);

	return 0;
}

static void ys_k2ulan_clear_qset_hash(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *hw_addr;
	struct ys_mbox *mbox;
	u16 qset;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	qset = ndev_priv->qi.qset;
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];

	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf hash*/
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("mbox not support!\n");
			return;
		}
		ys_k2ulan_mbox_req_clear_hash(mbox);
	} else {
		ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_HASH(qset), 0);
	}
}

static void ys_k2ulan_clear_qset_vlan(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_vlan *ys_vlan;
	struct ys_mbox *mbox = NULL;
	struct list_head *vlan_list;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	/* request master pf unset pf/vf vlan */
	mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
	if (!mbox) {
		ys_dev_err("mbox not support!\n");
		return;
	}

	vlan_list = &ndev_priv->cvlan_list;
	list_for_each_entry(ys_vlan, vlan_list, list) {
		if (pdev_priv->nic_type->is_vf || mbox->role == MB_PF) {
			// TODO get vlan proto form ys_vlan list
			ys_k2ulan_mbox_req_set_inner_vlan(mbox, &ndev_priv->qi,
							  ys_vlan->vlan_id,
							  htons(ETH_P_8021Q), 0);
		} else {
			ys_k2ulan_clear_inner_vlan(pdev_priv, &ndev_priv->qi,
						   ys_vlan->vlan_id,
						   htons(ETH_P_8021Q));
		}
	}

	vlan_list = &ndev_priv->svlan_list;
	list_for_each_entry(ys_vlan, vlan_list, list) {
		if (pdev_priv->nic_type->is_vf || mbox->role == MB_PF) {
			// TODO get vlan proto form ys_vlan list
			ys_k2ulan_mbox_req_set_inner_vlan(mbox, &ndev_priv->qi,
							  ys_vlan->vlan_id,
							  htons(ETH_P_8021AD), 0);
		} else {
			ys_k2ulan_clear_inner_vlan(pdev_priv, &ndev_priv->qi,
						   ys_vlan->vlan_id,
						   htons(ETH_P_8021AD));
		}
	}
}

static void ys_k2ulan_set_rxvlan_features(struct ys_pdev_priv *pdev_priv,
					  struct ys_queue_params qi,
					  netdev_features_t changed,
					  netdev_features_t features)
{
	void __iomem *hw_addr;
	struct k2ulan_qset_mtu *qset_vlan_offload;
	struct k2ulan_qset_qinq *qset_vlanfilter_offload;
	u32 reg;

	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_MTU(qi.qset));
	qset_vlan_offload = (struct k2ulan_qset_mtu *)&reg;

	if (changed & NETIF_F_HW_VLAN_CTAG_RX) {
		if (features & NETIF_F_HW_VLAN_CTAG_RX)
			qset_vlan_offload->q_vlan_offload_mode |=
				YS_K2ULAN_RX_VLAN_OFFLOAD_MODE_CTAG_OFFLOAD;
		else
			qset_vlan_offload->q_vlan_offload_mode &=
				YS_K2ULAN_RX_VLAN_OFFLOAD_MODE_STAG_OFFLOAD;
	}

	if (changed & NETIF_F_HW_VLAN_STAG_RX) {
		if (features & NETIF_F_HW_VLAN_STAG_RX)
			qset_vlan_offload->q_vlan_offload_mode |=
				YS_K2ULAN_RX_VLAN_OFFLOAD_MODE_STAG_OFFLOAD;
		else
			qset_vlan_offload->q_vlan_offload_mode &=
				YS_K2ULAN_RX_VLAN_OFFLOAD_MODE_CTAG_OFFLOAD;
	}
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_MTU(qi.qset), reg);

	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qi.qset));
	qset_vlanfilter_offload = (struct k2ulan_qset_qinq *)&reg;

	if (changed & NETIF_F_HW_VLAN_CTAG_FILTER) {
		if (features & NETIF_F_HW_VLAN_CTAG_FILTER)
			qset_vlanfilter_offload->ctag_vlan_valid = 1;
		else
			qset_vlanfilter_offload->ctag_vlan_valid = 0;
	}

	if (changed & NETIF_F_HW_VLAN_STAG_FILTER) {
		if (features & NETIF_F_HW_VLAN_STAG_FILTER)
			qset_vlanfilter_offload->stag_vlan_valid = 1;
		else
			qset_vlanfilter_offload->stag_vlan_valid = 0;
	}
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qi.qset), reg);
}

int ys_k2ulan_switch_update_cfg(struct net_device *ndev, u16 vf_id)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	switch (pdev_priv->dpu_mode) {
	case MODE_LEGACY:
		ys_k2ulan_enable_qset(ndev, vf_id, true);
		break;
	case MODE_SMART_NIC:
	case MODE_DPU_HOST:
		ys_k2ulan_enable_smart_card_qset(ndev, vf_id, true);
		break;
	case MODE_DPU_SOC:
		//ys_k2ulan_enable_dpu_soc_qset(ndev, vf_id, true);
		break;
	default:
		break;
	}

	ys_k2ulan_set_qset_mtu(ndev, ndev->mtu);
	ys_k2ulan_set_qset_hash(ndev);
	if (vf_id < YS_K2U_SMARTNIC_REP_ID_UPLINK_ID && ndev_priv->adev_type != AUX_TYPE_REP)
		ys_k2ulan_set_mac(ndev, vf_id);

	return 0;
}

int ys_k2ulan_switch_del_cfg(struct net_device *ndev, u16 vf_id)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (pdev_priv->dpu_mode == MODE_LEGACY)
		ys_k2ulan_enable_qset(ndev, vf_id, 0);
	else if (pdev_priv->dpu_mode == MODE_SMART_NIC)
		ys_k2ulan_enable_smart_card_qset(ndev, vf_id, false);
	mbox = ys_aux_match_mbox_dev(pdev_priv->pdev);
	if (!IS_ERR_OR_NULL(mbox)) {
		if (mbox->role == MB_VF) {
			ys_k2ulan_clear_mac(ndev);
			ys_k2ulan_mbox_req_remove_vf_port(pdev_priv);
		}
	}
	ys_k2ulan_clear_qset_hash(ndev);
	ys_k2ulan_clear_qset_vlan(ndev);
	return 0;
}

static void ys_k2ulan_mbox_req_set_vlan_features(struct ys_mbox *mbox,
						 netdev_features_t changed,
						 netdev_features_t features)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0}, ack_msg;
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("req_set_vlan_features get mbox failed!");
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role != MB_VF) {
		ys_dev_err("req_set_vlan_feature mbox role is invalid, role:%x", mbox->role);
		return;
	}
	ctx->type = MB_PF;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	cmd->cmd_type = YS_K2ULAN_CMD_VF_RX_FEATURE_SET;
	memcpy(cmd->cmd_data, &changed, sizeof(netdev_features_t));
	memcpy(cmd->cmd_data + sizeof(netdev_features_t), &features,
	       sizeof(netdev_features_t));
	cmd->data_len = sizeof(netdev_features_t) * 2;
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg.data;

	if (ys_k2ulan_cmd_exec(mbox, YS_MBOX_OPCODE_SET_VLAN_FEATURES, send_id,
			       cmd, sizeof(*cmd) + cmd->data_len, &ack_msg)) {
		ys_dev_err("vf set vlan feature failed. status:%x", cmd_ack->cmd_status);
	}
}

static int ys_k2ulan_mbox_set_vlan_feature(struct ys_mbox *mbox,
					   struct ys_k2ulan_cmd *cmd, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_vf_info *vf_info;
	struct ys_queue_params qi = {0};
	netdev_features_t changed;
	netdev_features_t features;
	u16 qset;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	qset = vf_info->qset;
	qi.qset = qset;

	memcpy(&changed, cmd->cmd_data, sizeof(netdev_features_t));
	memcpy(&features, cmd->cmd_data + sizeof(netdev_features_t),
	       sizeof(netdev_features_t));

	ys_k2ulan_set_rxvlan_features(pdev_priv, qi, changed, features);

	return 0;
}

int ys_k2ulan_set_features(struct net_device *ndev, netdev_features_t features)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	netdev_features_t changed;
	struct ys_mbox *mbox;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	changed = features ^ ndev->features;

	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf hash*/
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("mbox not support!\n");
			return -EOPNOTSUPP;
		}
		ys_k2ulan_mbox_req_set_vlan_features(mbox, changed, features);
	} else {
		ys_k2ulan_set_rxvlan_features(pdev_priv, ndev_priv->qi, changed, features);
	}

	return 0;
}

static void ys_k2ulan_set_tx_features(struct ys_pdev_priv *pdev_priv,
				      struct ys_queue_params qi,
				      netdev_features_t changed,
				      netdev_features_t features)
{
	void __iomem *hw_addr;
	u32 reg;

	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qi.qset));
	/* tx vlan offload */
	if (changed & NETIF_F_HW_VLAN_CTAG_TX || changed & NETIF_F_HW_VLAN_STAG_TX) {
		/*set inner vlan trust*/
		reg &= ~YS_K2ULAN_TX_QSET_OFFLOAD_VEB_INNER_VLAN_TRUST;
		if (features & NETIF_F_HW_VLAN_CTAG_TX || features & NETIF_F_HW_VLAN_STAG_TX)
			reg |= FIELD_PREP(YS_K2ULAN_TX_QSET_OFFLOAD_VEB_INNER_VLAN_TRUST, 1);
	}

	ys_wr32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qi.qset), reg);
}

static void ys_k2ulan_mbox_req_set_tx_features(struct ys_mbox *mbox,
					       netdev_features_t changed,
					       netdev_features_t features)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0}, ack_msg;
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("req_set_tx_features get mbox failed!");
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role != MB_VF) {
		ys_dev_err("req_set_tx_feature mbox role is invalid, role:%x", mbox->role);
		return;
	}
	ctx->type = MB_PF;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	cmd->cmd_type = YS_K2ULAN_CMD_VF_TX_FEATURE_SET;
	memcpy(cmd->cmd_data, &changed, sizeof(netdev_features_t));
	memcpy(cmd->cmd_data + sizeof(netdev_features_t), &features,
	       sizeof(netdev_features_t));
	cmd->data_len = sizeof(netdev_features_t) * 2;
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg.data;

	if (ys_k2ulan_cmd_exec(mbox, YS_MBOX_OPCODE_SET_TX_FEATURES, send_id,
			       cmd, sizeof(*cmd) + cmd->data_len, &ack_msg)) {
		ys_dev_err("vf set tx feature failed. status:%x", cmd_ack->cmd_status);
	}
}

static int ys_k2ulan_mbox_set_tx_feature(struct ys_mbox *mbox,
					 struct ys_k2ulan_cmd *cmd, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_vf_info *vf_info;
	struct ys_queue_params qi = {0};
	netdev_features_t changed;
	netdev_features_t features;
	u16 qset;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	qset = vf_info->qset;
	qi.qset = qset;

	memcpy(&changed, cmd->cmd_data, sizeof(netdev_features_t));
	memcpy(&features, cmd->cmd_data + sizeof(netdev_features_t),
	       sizeof(netdev_features_t));

	ys_k2ulan_set_tx_features(pdev_priv, qi, changed, features);

	return 0;
}

int ys_k2ulan_tx_features_set(struct net_device *ndev, netdev_features_t features)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	netdev_features_t changed;
	struct ys_mbox *mbox;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	changed = features ^ ndev->features;

	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf hash*/
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("mbox not support!\n");
			return -EOPNOTSUPP;
		}
		ys_k2ulan_mbox_req_set_tx_features(mbox, changed, features);
	} else {
		ys_k2ulan_set_tx_features(pdev_priv, ndev_priv->qi, changed, features);
	}

	return 0;
}

int ys_k2ulan_set_vf_spoofchk(struct net_device *ndev, u16 vf_id, bool enable)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_vf_info *vf_info;
	void __iomem *hw_addr;
	u16 qset;
	u32 reg = 0;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	/* this func vf id start with 0 */
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id - 1];
	vf_info->spoofchk = 0;
	qset = vf_info->qset;
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];

	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qset));
	reg &= ~YS_K2ULAN_TX_QSET_OFFLOAD_VEB_SRC_MAC_FILTER_EN;
	if (enable) {
		reg |= FIELD_PREP(YS_K2ULAN_TX_QSET_OFFLOAD_VEB_SRC_MAC_FILTER_EN, enable);
		vf_info->spoofchk = 1;
	}
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qset), reg);

	return 0;
}

int ys_k2ulan_set_rss_hash_opt(struct net_device *ndev,
			       struct ethtool_rxnfc *rxnfc)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_hash_field *hash_field;
	u8 temp = 0;

	ndev_priv = netdev_priv(ndev);
	hash_field = &ndev_priv->hash_field;

	if (rxnfc->data & RXH_IP_SRC)
		temp |= YS_HASH_FIELD_SEL_SRC_IP;
	if (rxnfc->data & RXH_IP_DST)
		temp |= YS_HASH_FIELD_SEL_DST_IP;
	if (rxnfc->data & RXH_L4_B_0_1)
		temp |= YS_HASH_FIELD_SEL_L4_SPORT;
	if (rxnfc->data & RXH_L4_B_2_3)
		temp |= YS_HASH_FIELD_SEL_L4_DPORT;
	if (rxnfc->data & RXH_L3_PROTO)
		temp |= YS_HASH_FIELD_SEL_L3_PROTO;

	switch (rxnfc->flow_type) {
	case TCP_V4_FLOW:
		/* For tcp/udp n-tupple hash is supported */
		hash_field->ipv4_tcp_hash_mode = temp;
		ys_k2ulan_set_qset_hash(ndev);
		return 0;
	case TCP_V6_FLOW:
		hash_field->ipv6_tcp_hash_mode = temp;
		ys_k2ulan_set_qset_hash(ndev);
		return 0;
	case UDP_V4_FLOW:
		hash_field->ipv4_udp_hash_mode = temp;
		ys_k2ulan_set_qset_hash(ndev);
		return 0;
	case UDP_V6_FLOW:
		/* For tcp/udp n-tupple hash is supported */
		hash_field->ipv6_udp_hash_mode = temp;
		ys_k2ulan_set_qset_hash(ndev);
		return 0;
	case IPV4_FLOW:
	case IPV6_FLOW:
	case SCTP_V4_FLOW:
	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case SCTP_V6_FLOW:
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case IP_USER_FLOW:
	case ETHER_FLOW:
		/* RSS is not supported for these protocols */
		if (rxnfc->data) {
			ys_net_info("Command parameters not supported\n");
			return -EINVAL;
		}
		return 0;

	default:
		return -EINVAL;
	}
}

u32 ys_k2ulan_get_link_speed(struct net_device *ndev)
{
	return SPEED_10G;
}

u32 ys_k2ulan_get_link_duplex(struct net_device *ndev)
{
	return DUPLEX_FULL;
}

static void ys_k2ulan_mbox_req_get_hash_mode(struct ys_mbox *mbox, struct ys_ndev_priv *ndev_priv)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0}, ack_msg;
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;
	struct ys_hash_field *hash_field;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("vf req_get_hash_mode get mbox failed!");
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role != MB_VF) {
		ys_dev_err("req_get_hash_mode mbox role is invalid, role:%x", mbox->role);
		return;
	}
	ctx->type = MB_PF;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	cmd->cmd_type = YS_K2ULAN_CMD_VF_HASH_GET;
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg.data;

	if (ys_k2ulan_cmd_exec(mbox, YS_MBOX_OPCODE_GET_HASH_MODE, send_id,
			       cmd, sizeof(*cmd), &ack_msg)) {
		ys_dev_err("vf get hash mode failed. status:%x", cmd_ack->cmd_status);
		return;
	}

	if (cmd_ack->cmd_status == 0) {
		hash_field = &ndev_priv->hash_field;
		hash_field->ipv4_tcp_hash_mode |= cmd_ack->cmd_data[0] &
						  (YS_HASH_FIELD_SEL_SRC_IP |
						   YS_HASH_FIELD_SEL_DST_IP |
						   YS_HASH_FIELD_SEL_L4_SPORT |
						   YS_HASH_FIELD_SEL_L4_DPORT |
						   YS_HASH_FIELD_SEL_L3_PROTO);
		hash_field->ipv6_tcp_hash_mode |= cmd_ack->cmd_data[1] &
						  (YS_HASH_FIELD_SEL_SRC_IP |
						   YS_HASH_FIELD_SEL_DST_IP |
						   YS_HASH_FIELD_SEL_L4_SPORT |
						   YS_HASH_FIELD_SEL_L4_DPORT |
						   YS_HASH_FIELD_SEL_L3_PROTO);
		hash_field->ipv4_udp_hash_mode |= cmd_ack->cmd_data[2] &
						  (YS_HASH_FIELD_SEL_SRC_IP |
						   YS_HASH_FIELD_SEL_DST_IP |
						   YS_HASH_FIELD_SEL_L4_SPORT |
						   YS_HASH_FIELD_SEL_L4_DPORT |
						   YS_HASH_FIELD_SEL_L3_PROTO);
		hash_field->ipv6_udp_hash_mode |= cmd_ack->cmd_data[3] &
						  (YS_HASH_FIELD_SEL_SRC_IP |
						   YS_HASH_FIELD_SEL_DST_IP |
						   YS_HASH_FIELD_SEL_L4_SPORT |
						   YS_HASH_FIELD_SEL_L4_DPORT |
						   YS_HASH_FIELD_SEL_L3_PROTO);
	}
}

static int ys_k2ulan_mbox_get_hash_mode(struct ys_mbox *mbox, struct ys_k2ulan_cmd *cmd,
					struct ys_k2ulan_cmd *cmd_ack, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_vf_info *vf_info;
	struct ys_hash_field hash_field = {0};
	void __iomem *hw_addr;
	struct k2ulan_qset_hash *qset_hash;
	u16 qset;
	u32 temp;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	qset = vf_info->qset;

	temp = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_HASH(qset));
	qset_hash = (struct k2ulan_qset_hash *)&temp;
	hash_field.ipv4_tcp_hash_mode |= qset_hash->q_ipv4_tcp_hash_mode &
						(YS_HASH_FIELD_SEL_SRC_IP |
						 YS_HASH_FIELD_SEL_DST_IP |
						 YS_HASH_FIELD_SEL_L4_SPORT |
						 YS_HASH_FIELD_SEL_L4_DPORT |
						 YS_HASH_FIELD_SEL_L3_PROTO);
	hash_field.ipv6_tcp_hash_mode |= qset_hash->q_ipv6_tcp_hash_mode &
						(YS_HASH_FIELD_SEL_SRC_IP |
						 YS_HASH_FIELD_SEL_DST_IP |
						 YS_HASH_FIELD_SEL_L4_SPORT |
						 YS_HASH_FIELD_SEL_L4_DPORT |
						 YS_HASH_FIELD_SEL_L3_PROTO);
	hash_field.ipv4_udp_hash_mode |= qset_hash->q_ipv4_udp_hash_mode &
						(YS_HASH_FIELD_SEL_SRC_IP |
						 YS_HASH_FIELD_SEL_DST_IP |
						 YS_HASH_FIELD_SEL_L4_SPORT |
						 YS_HASH_FIELD_SEL_L4_DPORT |
						 YS_HASH_FIELD_SEL_L3_PROTO);
	hash_field.ipv6_udp_hash_mode |= qset_hash->q_ipv6_udp_hash_mode &
						(YS_HASH_FIELD_SEL_SRC_IP |
						 YS_HASH_FIELD_SEL_DST_IP |
						 YS_HASH_FIELD_SEL_L4_SPORT |
						 YS_HASH_FIELD_SEL_L4_DPORT |
						 YS_HASH_FIELD_SEL_L3_PROTO);

	cmd_ack->cmd_data[0] = hash_field.ipv4_tcp_hash_mode;
	cmd_ack->cmd_data[1] = hash_field.ipv6_tcp_hash_mode;
	cmd_ack->cmd_data[2] = hash_field.ipv4_udp_hash_mode;
	cmd_ack->cmd_data[3] = hash_field.ipv6_udp_hash_mode;

	return 0;
}

void ys_k2ulan_get_hash_mode(struct net_device *ndev)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_ndev_priv *ndev_priv;
	void __iomem *hw_addr;
	struct k2ulan_qset_hash *qset_hash;
	struct ys_hash_field *hash_field;
	struct ys_mbox *mbox;
	u16 qset;
	u32 temp = 0;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	hash_field = &ndev_priv->hash_field;
	qset = ndev_priv->qi.qset;
	if (pdev_priv->nic_type->is_vf) {
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("mbox not support!\n");
			return;
		}
		ys_k2ulan_mbox_req_get_hash_mode(mbox, ndev_priv);
	} else {
		hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
		temp = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_HASH(qset));
		qset_hash = (struct k2ulan_qset_hash *)&temp;
		hash_field->ipv4_tcp_hash_mode |= qset_hash->q_ipv4_tcp_hash_mode &
						  (YS_HASH_FIELD_SEL_SRC_IP |
						   YS_HASH_FIELD_SEL_DST_IP |
						   YS_HASH_FIELD_SEL_L4_SPORT |
						   YS_HASH_FIELD_SEL_L4_DPORT |
						   YS_HASH_FIELD_SEL_L3_PROTO);
		hash_field->ipv6_tcp_hash_mode |= qset_hash->q_ipv6_tcp_hash_mode &
						  (YS_HASH_FIELD_SEL_SRC_IP |
						   YS_HASH_FIELD_SEL_DST_IP |
						   YS_HASH_FIELD_SEL_L4_SPORT |
						   YS_HASH_FIELD_SEL_L4_DPORT |
						   YS_HASH_FIELD_SEL_L3_PROTO);
		hash_field->ipv4_udp_hash_mode |= qset_hash->q_ipv4_udp_hash_mode &
						  (YS_HASH_FIELD_SEL_SRC_IP |
						   YS_HASH_FIELD_SEL_DST_IP |
						   YS_HASH_FIELD_SEL_L4_SPORT |
						   YS_HASH_FIELD_SEL_L4_DPORT |
						   YS_HASH_FIELD_SEL_L3_PROTO);
		hash_field->ipv6_udp_hash_mode |= qset_hash->q_ipv6_udp_hash_mode &
						  (YS_HASH_FIELD_SEL_SRC_IP |
						   YS_HASH_FIELD_SEL_DST_IP |
						   YS_HASH_FIELD_SEL_L4_SPORT |
						   YS_HASH_FIELD_SEL_L4_DPORT |
						   YS_HASH_FIELD_SEL_L3_PROTO);
	}
}

void ys_k2ulan_init_hw_features(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;

	ndev_priv = netdev_priv(ndev);
	if (ndev_priv->adev_type & AUX_TYPE_ETH ||
	    ndev_priv->adev_type & AUX_TYPE_SF) {
		/* ndev hw features enable */
		ndev->hw_features |= NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX;
		ndev->hw_features |= NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX;
		ndev->hw_features |= NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER;

		/* ndev default features */
		ndev->features |= NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX;
		ndev->features |= NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX;
		ndev->features |= NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER;
	}
}

static void ys_k2ulan_get_priv_strings(struct net_device *ndev, u8 *data)
{
	memcpy(data, ys_k2ulan_priv_strings, sizeof(ys_k2ulan_priv_strings));
}

static int ys_k2ulan_get_priv_count(struct net_device *ndev)
{
	return YS_K2ULAN_PFLAG_LEN;
}

static void ys_k2ulan_set_veb(struct ys_pdev_priv *pdev_priv,
			      struct ys_queue_params *qi, bool enable)
{
	void __iomem *hw_addr;
	u32 reg = 0;

	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qi->qset));
	reg &= ~YS_K2ULAN_TX_QSET_OFFLOAD_VEB_VEB_EN;
	reg |= FIELD_PREP(YS_K2ULAN_TX_QSET_OFFLOAD_VEB_VEB_EN, enable);
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qi->qset), reg);
}

static void ys_k2ulan_set_rss_sel_udp_tunnel_info(struct ys_pdev_priv *pdev_priv,
						  struct ys_queue_params *qi, bool enable)
{
	void __iomem *hw_addr;
	u32 reg = 0;

	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_HASH(qi->qset));
	reg &= ~YS_K2ULAN_QSET_TUNNEL_PKT_HASH_SEL;
	reg |= FIELD_PREP(YS_K2ULAN_QSET_TUNNEL_PKT_HASH_SEL, enable);
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_HASH(qi->qset), reg);
}

static void ys_k2ulan_set_pvid_miss(struct ys_pdev_priv *pdev_priv,
				    struct ys_queue_params *qi, bool enable)
{
	void __iomem *hw_addr;
	struct k2ulan_qset_qinq *qset_qinq;
	u32 reg;

	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qi->qset));
	qset_qinq = (struct k2ulan_qset_qinq *)&reg;
	// enable : 0; disable : 1;
	if (enable)
		qset_qinq->pvid_bypass = 0;
	else
		qset_qinq->pvid_bypass = 1;
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qi->qset), reg);
}

static int ys_k2ulan_mbox_set_priv(struct ys_mbox *mbox, struct ys_k2ulan_cmd *cmd, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_vf_info *vf_info;
	struct ys_queue_params qi = {0};
	bool enable = false;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	qi.qset = vf_info->qset;

	if (cmd->cmd_data[YS_K2ULAN_PFLAG_VEB_ENABLE])
		enable = true;
	ys_k2ulan_set_veb(pdev_priv, &qi, enable);

	enable = false;
	if (cmd->cmd_data[YS_K2ULAN_PFLAG_RSS_SEL_UDP_TUN_INFO])
		enable = true;
	ys_k2ulan_set_rss_sel_udp_tunnel_info(pdev_priv, &qi, enable);

	return 0;
}

static void ys_k2ulan_mbox_req_set_priv(struct ys_mbox *mbox, u32 flag)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0}, ack_msg;
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("vf req_set_priv get mbox failed!");
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role != MB_VF) {
		ys_dev_err("req_set_priv mbox role is invalid, role:%x", mbox->role);
		return;
	}
	ctx->type = MB_PF;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	cmd->cmd_type = YS_K2ULAN_CMD_VF_SET_PRIV_FLAG;
	cmd->cmd_data[YS_K2ULAN_PFLAG_VEB_ENABLE] =
		flag & (1 << YS_K2ULAN_PFLAG_VEB_ENABLE);
	cmd->cmd_data[YS_K2ULAN_PFLAG_RSS_SEL_UDP_TUN_INFO] =
		flag & (1 << YS_K2ULAN_PFLAG_RSS_SEL_UDP_TUN_INFO);
	cmd->data_len = YS_K2ULAN_PFLAG_LEN;
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg.data;

	if (ys_k2ulan_cmd_exec(mbox, YS_MBOX_OPCODE_SET_PRIV, send_id,
			       cmd, sizeof(*cmd) + cmd->data_len, &ack_msg)) {
		ys_dev_err("vf set priv failed status:%x", cmd_ack->cmd_status);
	}
}

static u32 ys_k2ulan_get_priv_flags(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	u32 flag = 0;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (ndev_priv->veb_enable)
		flag |= (1 << YS_K2ULAN_PFLAG_VEB_ENABLE);

	if (ndev_priv->rss_sel_udp_tun_info)
		flag |= (1 << YS_K2ULAN_PFLAG_RSS_SEL_UDP_TUN_INFO);

	if (ndev_priv->pvid_miss_upload && !pdev_priv->nic_type->is_vf)
		flag |= (1 << YS_K2ULAN_PFLAG_PVID_MISS_UPLOAD);

	ys_net_debug("\n%s : %s\n",
		     ys_k2ulan_priv_strings[YS_K2ULAN_PFLAG_VEB_ENABLE],
		     ndev_priv->veb_enable ? "on" : "off");
	ys_net_debug("\n%s : %s\n",
		     ys_k2ulan_priv_strings[YS_K2ULAN_PFLAG_RSS_SEL_UDP_TUN_INFO],
		     ndev_priv->rss_sel_udp_tun_info ? "on" : "off");
	ys_net_debug("\n%s : %s\n",
		     ys_k2ulan_priv_strings[YS_K2ULAN_PFLAG_RSS_SEL_UDP_TUN_INFO],
		     pdev_priv->nic_type->is_vf ? "na" :
		     ndev_priv->rss_sel_udp_tun_info ? "on" : "off");

	return flag;
}

static u32 ys_k2ulan_set_priv_flags(struct net_device *ndev, u32 flag)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_mbox *mbox;
	u32 err = 0;

	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf priv flag*/
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("mbox not support!\n");
			return -1;
		}
		ys_k2ulan_mbox_req_set_priv(mbox, flag);
		ndev_priv->veb_enable =
			((flag & (1 << YS_K2ULAN_PFLAG_VEB_ENABLE)) != 0);
		ndev_priv->rss_sel_udp_tun_info =
			((flag & (1 << YS_K2ULAN_PFLAG_RSS_SEL_UDP_TUN_INFO)) != 0);
	} else {
		/* pf set veb enable */
		ndev_priv->veb_enable =
			((flag & (1 << YS_K2ULAN_PFLAG_VEB_ENABLE)) != 0);
		ys_k2ulan_set_veb(pdev_priv, &ndev_priv->qi, ndev_priv->veb_enable);
		/* pf set select udp tunnel info for rss calculate */
		ndev_priv->rss_sel_udp_tun_info =
			((flag & (1 << YS_K2ULAN_PFLAG_RSS_SEL_UDP_TUN_INFO)) != 0);
		ys_k2ulan_set_rss_sel_udp_tunnel_info(pdev_priv, &ndev_priv->qi,
						      ndev_priv->rss_sel_udp_tun_info);
		/* pvid miss upload to pf */
		ndev_priv->pvid_miss_upload =
			((flag & (1 << YS_K2ULAN_PFLAG_PVID_MISS_UPLOAD)) != 0);
		ys_k2ulan_set_pvid_miss(pdev_priv, &ndev_priv->qi,
					ndev_priv->pvid_miss_upload);
	}

	return (u32)err;
}

static void ys_k2ulan_lib_set_promisc(struct ys_pdev_priv *pdev_priv,
				      u16 qset,
				      u8 enable)
{
	void __iomem *hw_addr;
	struct k2ulan_qset_qinq *qset_qinq;
	u32 reg = 0;

	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset));
	qset_qinq = (struct k2ulan_qset_qinq *)&reg;
	if (enable) {
		qset_qinq->promiscuous_enable = 1;
		if (pdev_priv->dpu_mode == MODE_SMART_NIC)
			qset_qinq->smartnic_promiscuous = 1;
	} else {
		qset_qinq->promiscuous_enable = 0;
		if (pdev_priv->dpu_mode == MODE_SMART_NIC)
			qset_qinq->smartnic_promiscuous = 0;
	}
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset), reg);
}

static int ys_k2ulan_mbox_switch_set_promisc(struct ys_mbox *mbox,
					     struct ys_k2ulan_cmd *cmd, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_vf_info *vf_info;
	u16 qset;
	u8 enable;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	qset = vf_info->qset;
	enable = cmd->cmd_data[0];

	ys_k2ulan_lib_set_promisc(pdev_priv, qset, enable);

	return 0;
}

static void ys_k2ulan_mbox_req_set_promisc(struct ys_mbox *mbox, u8 enable)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0}, ack_msg;
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("vf req_set_promisc get mbox failed!");
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role != MB_VF) {
		ys_dev_err("req_set_promisc mbox role is invalid, role:%x", mbox->role);
		return;
	}
	ctx->type = MB_PF;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	cmd->cmd_type = YS_K2ULAN_CMD_VF_PROMISC_SET;
	cmd->cmd_data[0] = enable;
	cmd->data_len = 1;
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg.data;

	if (ys_k2ulan_cmd_exec(mbox, YS_MBOX_OPCODE_SET_PROMISC, send_id,
			       cmd, sizeof(*cmd) + cmd->data_len, &ack_msg)) {
		ys_dev_err("vf set promisc failed status:%x", cmd_ack->cmd_status);
	}
}

int ys_k2ulan_switch_set_promisc(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;
	u8 enable = 0;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (ndev->flags & IFF_PROMISC)
		enable = 1;
	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf promisc*/
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("mbox not support!\n");
			return -1;
		}
		ys_k2ulan_mbox_req_set_promisc(mbox, enable);
	} else {
		ys_k2ulan_lib_set_promisc(pdev_priv, ndev_priv->qi.qset, enable);
	}
	return 0;
}

static void ys_k2ulan_qset_init_dst(void __iomem *bar_addr, u32 qset,
				    u8 pf_id, u8 enable)
{
	u32 reg;
	u16 dst_qset;

	reg = ys_rd32(bar_addr, YS_K2ULAN_STEERING_TX_DST_QSET(qset));
	reg &= ~YS_K2ULAN_STEERING_TX_DST_QSET_VALUE;
	if (enable) {
		dst_qset = YS_K2ULAN_STEERING_TX_DST_QSET_PF_BASE + pf_id;
		reg |= FIELD_PREP(YS_K2ULAN_STEERING_TX_DST_QSET_VALUE, dst_qset);
	}
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_TX_DST_QSET(qset), reg);
}

static void ys_k2ulan_set_dst_qset(void __iomem *bar_addr, u32 src_qset, bool enable,
				   bool pass_through, bool qset_trust, u16 dst_qset)
{
	u32 value = 0;

	if (enable) {
		value |= FIELD_PREP(YS_K2ULAN_STEERING_TX_DST_QSET_PASSTHROUGH_VALID, 1);
		value |= FIELD_PREP(YS_K2ULAN_STEERING_TX_DST_QSET_PASSTHROUGH, pass_through);
		value |= FIELD_PREP(YS_K2ULAN_STEERING_TX_DST_QSET_TRUST, qset_trust);
		value |= FIELD_PREP(YS_K2ULAN_STEERING_TX_DST_QSET_VALUE, dst_qset);
		ys_wr32(bar_addr, YS_K2ULAN_STEERING_TX_DST_QSET(src_qset), value);
	} else {
		value |= FIELD_PREP(YS_K2ULAN_STEERING_TX_DST_QSET_PASSTHROUGH_VALID, 0);
		value |= FIELD_PREP(YS_K2ULAN_STEERING_TX_DST_QSET_PASSTHROUGH, 0);
		value |= FIELD_PREP(YS_K2ULAN_STEERING_TX_DST_QSET_TRUST, 0);
		value |= FIELD_PREP(YS_K2ULAN_STEERING_TX_DST_QSET_VALUE, 0);
		ys_wr32(bar_addr, YS_K2ULAN_STEERING_TX_DST_QSET(src_qset), value);
	}
}

static void ys_k2ulan_qset_enable_port(void __iomem *bar_addr, u32 qset,
				       u8 port, u8 enable)
{
	u32 reg;
	u8 val;

	/* enable rx port */
	reg = ys_rd32(bar_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset));
	val = FIELD_GET(YS_K2ULAN_QSET_VID_MISC_PORT_ENABLE, reg);
	reg &= ~FIELD_PREP(YS_K2ULAN_QSET_VID_MISC_PORT_ENABLE, 0xff);
	if (enable)
		val |= 1 << port;
	else
		val &= ~(1 << port);
	reg |= FIELD_PREP(YS_K2ULAN_QSET_VID_MISC_PORT_ENABLE, val);
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset), reg);
}

static void ys_k2ulan_qset_init_drops(void __iomem *bar_addr, u16 qset)
{
	u32 reg;

	reg = ys_rd32(bar_addr, YS_K2ULAN_STEERING_QSET_MTU(qset));
	reg &= ~FIELD_PREP(YS_K2ULAN_QSET_MTU_MISC_OVER_MTU_DROP, 0);
	reg &= ~FIELD_PREP(YS_K2ULAN_QSET_MTU_MISC_FCS_ERR_DROP, 0);
	reg &= ~FIELD_PREP(YS_K2ULAN_QSET_MTU_MISC_CHKSUM_ERR_DROP, 0);
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_QSET_MTU(qset), reg);
}

static void ys_k2ulan_qset_init_flags(void __iomem *bar_addr, u16 qset)
{
	struct k2ulan_qset_qinq *qset_qinq;
	u32 reg;

	reg = ys_rd32(bar_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset));
	qset_qinq = (struct k2ulan_qset_qinq *)&reg;
	qset_qinq->umc_flood_enable = 0;
	qset_qinq->pvid_bypass = 1; // enable : 0; disable : 1;
	qset_qinq->bc_disable = 0; // enable : 0; disable : 1;
	qset_qinq->promiscuous_enable = 0;
	qset_qinq->smartnic_promiscuous = 1; // enable smartnic promiscuous for mirror
	qset_qinq->src_dst_qset_filter = 0; // drop : 0; bypass: 1;
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset), reg);

	reg = ys_rd32(bar_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qset));
	reg |= FIELD_PREP(YS_K2ULAN_TX_QSET_OFFLOAD_VEB_VEB_EN, 1);
	reg &= ~YS_K2ULAN_TX_QSET_OFFLOAD_VEB_SRC_MAC_FILTER_EN;
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qset), reg);
}

static void ys_k2ulan_reset_vf_qset_flags(void __iomem *bar_addr, u16 qset)
{
	struct k2ulan_qset_qinq *qset_qinq;
	u32 reg;

	reg = ys_rd32(bar_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset));
	qset_qinq = (struct k2ulan_qset_qinq *)&reg;
	qset_qinq->umc_flood_enable = 0;
	qset_qinq->bc_disable = 0; // enable : 0; disable : 1;
	qset_qinq->promiscuous_enable = 0;
	qset_qinq->smartnic_promiscuous = 1; // enable smartnic promiscuous for mirror
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset), reg);
}

static void ys_k2ulan_rep_qset_init_flags(void __iomem *hw_addr, u16 qset)
{
	struct k2ulan_qset_qinq *qset_qinq;
	u32 reg = 0;

	qset_qinq = (struct k2ulan_qset_qinq *)&reg;
	qset_qinq->bc_disable = 1; // enable : 0; disable : 1;
	/* rep port enable promiscuous by default */
	qset_qinq->smartnic_promiscuous = 1;
	qset_qinq->promiscuous_enable = 1;
	qset_qinq->src_dst_qset_filter = 1; // drop : 0; bypass: 1;
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset), reg);

	reg = 0;
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qset), reg);
}

static void ys_k2ulan_smart_card_qset_init_flags(void __iomem *hw_addr, u16 qset)
{
	struct k2ulan_qset_qinq *qset_qinq;
	u32 reg;

	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset));
	qset_qinq = (struct k2ulan_qset_qinq *)&reg;
	qset_qinq->smartnic_promiscuous = 0;
	qset_qinq->src_dst_qset_filter = 1; // drop : 0; bypass: 1;
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset), reg);
}

static void ys_k2ulan_qset_init_hash(void __iomem *bar_addr, u16 qset)
{
	struct k2ulan_qset_hash *qset_hash;
	struct ys_hash_field hash_field;
	u32 temp = 0;
	u8 hash_mode = 0;

	/* init qset hash */
	hash_mode = YS_HASH_FIELD_SEL_SRC_IP |
		    YS_HASH_FIELD_SEL_DST_IP |
		    YS_HASH_FIELD_SEL_L4_SPORT |
		    YS_HASH_FIELD_SEL_L4_DPORT |
		    YS_HASH_FIELD_SEL_L3_PROTO,
	hash_field.ipv4_tcp_hash_mode = hash_mode;
	hash_field.ipv6_tcp_hash_mode = hash_mode;
	hash_field.ipv4_udp_hash_mode = hash_mode;
	hash_field.ipv6_udp_hash_mode = hash_mode;

	/* init pf qset hash */
	temp = ys_rd32(bar_addr, YS_K2ULAN_STEERING_QSET_HASH(qset));
	qset_hash = (struct k2ulan_qset_hash *)&temp;
	qset_hash->q_ipv4_tcp_hash_mode = hash_field.ipv4_tcp_hash_mode;
	qset_hash->q_ipv6_tcp_hash_mode = hash_field.ipv6_tcp_hash_mode;
	qset_hash->q_ipv4_udp_hash_mode = hash_field.ipv4_udp_hash_mode;
	qset_hash->q_ipv6_udp_hash_mode = hash_field.ipv6_udp_hash_mode;
	qset_hash->q_tunnel_pkt_hash_sel = YS_K2ULAN_HASH_TUNNEL_PKT_SEL_OUTER;
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_QSET_HASH(qset), temp);
}

static void ys_k2ulan_qset_init_vlan(void __iomem *bar_addr, u16 qset)
{
	u32 reg = 0;

	/* netdev tx vlan offload on by default */
	reg = ys_rd32(bar_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qset));
	reg |= FIELD_PREP(YS_K2ULAN_TX_QSET_OFFLOAD_VEB_INNER_VLAN_TRUST, 1);
	reg &= ~YS_K2ULAN_TX_QSET_OFFLOAD_VEB_VLAN_TYPE;
	reg |= FIELD_PREP(YS_K2ULAN_TX_QSET_OFFLOAD_VEB_VLAN_TYPE, 0x88a8);
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qset), reg);
	/* netdev rx vlan offload on by default */
	reg = ys_rd32(bar_addr, YS_K2ULAN_STEERING_QSET_MTU(qset));
	reg |= FIELD_PREP(YS_K2ULAN_QSET_MTU_MISC_VLAN_OFFLOAD_MODE, 0x3);
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_QSET_MTU(qset), reg);
	/* netdev rx vlan filter on by default */
	reg = ys_rd32(bar_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset));
	reg |= FIELD_PREP(YS_K2ULAN_QSET_VID_MISC_STAG_VLAN_VALID, 1) |
	       FIELD_PREP(YS_K2ULAN_QSET_VID_MISC_CTAG_VLAN_VALID, 1);
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset), reg);
}

static void ys_k2ulan_rep_qset_init_vlan(void __iomem *hw_addr, u16 qset)
{
	u32 reg = 0;

	/* rep netdev rx vlan offload disable fixed */
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_MTU(qset));
	reg &= ~YS_K2ULAN_QSET_MTU_MISC_VLAN_OFFLOAD_MODE;
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_MTU(qset), reg);
}

static int ys_k2ulan_set_uc_mac(struct net_device *ndev, u8 *mac, bool enable)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;
	enum ys_k2ulan_filter_action action;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	ys_net_info("uc mac addr %s %02x:%02x:%02x:%02x:%02x:%02x\n",
		    enable ? "add" : "del", mac[0], mac[1], mac[2], mac[3],
		    mac[4], mac[5]);

	action = enable ? YS_K2ULAN_FILTER_ADD : YS_K2ULAN_FILTER_DEL;
	mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
	if (!mbox) {
		ys_dev_err("mbox not support!\n");
		return -1;
	}

	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf mac*/
		ys_k2ulan_mbox_req_set_mac(mbox, mac, NULL, ndev_priv->qi,
					   action);
	} else {
		if (mbox->role == MB_MASTER)
			ys_k2ulan_update_l2_filter_wrapper(pdev_priv, ndev_priv,
							   YS_K2ULAN_L2UC_FILTER,
							   action,
							   mac);
		else
			ys_k2ulan_mbox_req_set_mac(mbox, mac, NULL, ndev_priv->qi, action);
	}

	return 0;
}

static int ys_k2ulan_mbox_set_mc_mac(struct ys_mbox *mbox, struct ys_k2ulan_cmd *cmd, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_ndev_priv *ndev_priv;
	enum ys_k2ulan_filter_action action;
	u8 mac[ETH_ALEN];
	int ret;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	memcpy(mac, cmd->cmd_data, ETH_ALEN);
	/* make a fake ndev */
	ndev_priv = kzalloc(sizeof(*ndev_priv), GFP_ATOMIC);
	if (IS_ERR_OR_NULL(ndev_priv)) {
		ys_err("%s alloc fake ndev private info no memory!", __func__);
		return -ENOMEM;
	}
	memcpy(&ndev_priv->qi, cmd->cmd_data + ETH_ALEN, sizeof(ndev_priv->qi));

	switch (cmd->cmd_type) {
	case YS_K2ULAN_CMD_VF_MC_ADD:
		action = YS_K2ULAN_FILTER_ADD;
		break;
	case YS_K2ULAN_CMD_VF_MC_DEL:
		action = YS_K2ULAN_FILTER_DEL;
		break;
	default:
		ys_dev_err("pf set vf mc mac get invalid cmd type %d\n", cmd->cmd_type);
		kfree(ndev_priv);
		return -1;
	}

	if (mbox->role == MB_PF) {
		ys_k2ulan_mbox_req_set_mc_mac(mbox, mac, &ndev_priv->qi, action);
		kfree(ndev_priv);
		return 0;
	}

	ret = ys_k2ulan_update_l2_filter_wrapper(pdev_priv, ndev_priv,
						 YS_K2ULAN_L2MC_IPV4_FILTER,
						 action, mac);
	kfree(ndev_priv);
	return ret;
}

static void ys_k2ulan_mbox_req_set_mc_mac(struct ys_mbox *mbox, u8 *mac,
					  struct ys_queue_params *qi,
					  enum ys_k2ulan_filter_action action)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0};
	struct ys_k2ulan_cmd *cmd;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("req_set_mc_mac get mbox failed!");
		return;
	}

	if (mbox->role != MB_VF && mbox->role != MB_PF) {
		ys_err("req_set_mc_mac mbox role is invalid, role:%x", mbox->role);
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role == MB_VF)
		ctx->type = MB_PF;
	else
		ctx->type = MB_MASTER;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	switch (action) {
	case YS_K2ULAN_FILTER_ADD:
		cmd->cmd_type = YS_K2ULAN_CMD_VF_MC_ADD;
		break;
	case YS_K2ULAN_FILTER_DEL:
		cmd->cmd_type = YS_K2ULAN_CMD_VF_MC_DEL;
		break;
	default:
		ys_dev_err("mc mac mailbox msg action type %d invalid!", action);
		return;
	}
	memcpy(cmd->cmd_data, mac, ETH_ALEN); //new mac
	cmd->data_len = ETH_ALEN;
	memcpy(cmd->cmd_data + ETH_ALEN, qi, sizeof(*qi)); //qset info
	cmd->data_len += sizeof(*qi);

	if (ys_k2ulan_cmd_exec_async(mbox, YS_MBOX_OPCODE_SET_MC_MAC, send_id,
				     cmd, sizeof(*cmd) + cmd->data_len)) {
		if (mbox->role == MB_PF)
			ys_dev_err("slave pf set mc mac failed!");
		else
			ys_dev_err("vf set mc mac failed!");
	}
}

static int ys_k2ulan_set_mc_mac(struct net_device *ndev, u8 *mac, bool enable)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox *mbox;
	enum ys_k2ulan_filter_action action;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	ys_net_info("mc mac addr %s %02x:%02x:%02x:%02x:%02x:%02x\n",
		    enable ? "add" : "del", mac[0], mac[1], mac[2], mac[3],
		    mac[4], mac[5]);

	action = enable ? YS_K2ULAN_FILTER_ADD : YS_K2ULAN_FILTER_DEL;

	mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
	if (!mbox) {
		ys_dev_err("mbox not support!\n");
		return -1;
	}

	if (pdev_priv->nic_type->is_vf) {
		/*request pf set vf mc mac*/
		ys_k2ulan_mbox_req_set_mc_mac(mbox, mac, &ndev_priv->qi, action);
	} else {
		if (mbox->role == MB_MASTER)
			ys_k2ulan_update_l2_filter_wrapper(pdev_priv, ndev_priv,
							   YS_K2ULAN_L2MC_IPV4_FILTER,
							   action, mac);
		else
			ys_k2ulan_mbox_req_set_mc_mac(mbox, mac, &ndev_priv->qi, action);
	}

	return 0;
}

static void ys_k2ulan_mbox_req_enable_qset(struct ys_mbox *mbox, u8 enable)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0}, ack_msg;
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("vf req_enable_qset get mbox failed!");
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);

	if (mbox->role != MB_VF) {
		ys_dev_err("req_enable_qset mbox role is invalid, role:%x", mbox->role);
		return;
	}
	ctx->type = MB_PF;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	cmd->cmd_type = YS_K2ULAN_CMD_VF_PORT_EN;
	cmd->cmd_data[0] = enable;
	cmd->data_len = 1;
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg.data;

	if (ys_k2ulan_cmd_exec(mbox, YS_MBOX_OPCODE_SET_PORT_ENABLE, send_id, cmd,
			       sizeof(*cmd) + cmd->data_len, &ack_msg)) {
		ys_dev_err("vf set qset %sable failed. status:%x", enable ? "en" : "dis",
			   cmd_ack->cmd_status);
	}
}

static void ys_k2ulan_mbox_req_remove_vf_port(struct ys_pdev_priv *pdev_priv)
{
	struct ys_mbox_msg msg = {0}, ack_msg;
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	struct ys_mbox *mbox;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	mbox = ys_aux_match_mbox_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(mbox)) {
		ys_dev_err("vf remove port get mbox failed!");
		return;
	}

	if (mbox->role != MB_VF) {
		ys_dev_err("vf remove port mbox role is invalid, role:%x", mbox->role);
		return;
	}
	ctx->type = MB_PF;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	cmd->cmd_type = YS_K2ULAN_CMD_VF_PORT_REMOVE;
	cmd->cmd_data[0] = 0;
	cmd->data_len = 1;
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg.data;

	if (ys_k2ulan_cmd_exec(mbox, YS_MBOX_OPCODE_SET_PORT_ENABLE, send_id, cmd,
			       sizeof(*cmd) + cmd->data_len, &ack_msg)) {
		ys_dev_err("vf remove port failed. status:%x", cmd_ack->cmd_status);
	}
}

static int ys_k2ulan_mbox_switch_enable_qset(struct ys_mbox *mbox,
					     struct ys_k2ulan_cmd *cmd, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_vf_info *vf_info;
	void __iomem *hw_addr;
	u16 qset;
	u8 enable;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	qset = vf_info->qset;
	enable = cmd->cmd_data[0];

	if (pdev_priv->dpu_mode == MODE_DPU_HOST ||
	    pdev_priv->dpu_mode == MODE_SMART_NIC) {
		ys_k2ulan_smart_card_qset_init_flags(hw_addr, qset);
	} else {
		ys_k2ulan_qset_enable_port(hw_addr, qset, pdev_priv->pf_id, enable);
		ys_k2ulan_qset_init_dst(hw_addr, qset, pdev_priv->pf_id, enable);
	}

	return 0;
}

static int ys_k2ulan_mbox_remove_vf(struct ys_mbox *mbox,
				    struct ys_k2ulan_cmd *cmd, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_vf_info *vf_info;
	void __iomem *hw_addr;
	u16 qset;

	pdev_priv = pci_get_drvdata(mbox->pdev);
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	qset = vf_info->qset;

	ys_k2ulan_reset_vf_qset_flags(hw_addr, qset);

	return 0;
}

static void ys_k2ulan_enable_smart_card_qset(struct net_device *ndev, u16 adev_id, bool enable)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_ndev_priv *ndev_priv;
	struct net_device *dst_ndev;
	struct ys_ndev_priv *dst_ndev_priv;
	struct ys_mbox *mbox;
	void __iomem *hw_addr;
	u16 rep_qset;
	u16 dst_qset;
	struct ys_vf_info *vf_info;

	ndev_priv = netdev_priv(ndev);
	rep_qset = ndev_priv->qi.qset;
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];

	if (ndev_priv->adev_type != AUX_TYPE_REP) {
		if (enable) {
			if (pdev_priv->nic_type->is_vf) {
				mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
				if (!mbox) {
					ys_dev_err("mbox not support!\n");
					return;
				}
				ys_k2ulan_mbox_req_enable_qset(mbox, enable);
			} else {
				ys_k2ulan_smart_card_qset_init_flags(hw_addr, rep_qset);
			}
		}
		return;
	}

	/* init rep qset config */
	if (enable) {
		ys_k2ulan_rep_qset_init_flags(hw_addr, rep_qset);
		ys_k2ulan_rep_qset_init_vlan(hw_addr, rep_qset);
	} else {
		ys_k2ulan_qset_init_flags(hw_addr, rep_qset);
		ys_k2ulan_qset_init_vlan(hw_addr, rep_qset);
	}

	if (adev_id == YS_K2U_SMARTNIC_REP_ID_UPLINK_ID) {
		dst_qset = YS_K2ULAN_STEERING_TX_DST_QSET_PF_BASE + pdev_priv->pf_id;
		ys_k2ulan_set_dst_qset(hw_addr, rep_qset, enable, 1, 1, dst_qset);
		return;
	}

	/* mapping pf/vf...uplink/rep dst qset */
	if (adev_id > 0) {
		vf_info = &pdev_priv->sriov_info.vfinfo[YS_K2U_SMARTNIC_ADEV_ID_TO_VF(adev_id)];
		dst_qset = vf_info->qset;
		ys_info("%s vf rep %d set dst qset src qset %d dst qset %d", ndev->name,
			adev_id, rep_qset, dst_qset);
		ys_k2ulan_set_dst_qset(hw_addr, rep_qset, enable, 1, 1, dst_qset);
		ys_k2ulan_set_dst_qset(hw_addr, dst_qset, enable, 0, 1, rep_qset);
	} else {
		/* only set pf rep dst qset */
		if (ndev_priv->rep_type != YS_REP_TYPE_PF)
			return;

		dst_ndev = ys_aux_match_eth(ndev_priv->pdev, 0);
		if (IS_ERR_OR_NULL(dst_ndev)) {
			ys_err("representor's vf ndev get failed!");
			return;
		}
		dst_ndev_priv = netdev_priv(dst_ndev);
		if (IS_ERR_OR_NULL(dst_ndev_priv)) {
			ys_err("representor's vf ndev private get failed!");
			return;
		}
		dst_qset = dst_ndev_priv->qi.qset;
		ys_info("%s pf rep set dst qset src qset %d dst qset %d", ndev->name,
			rep_qset, dst_qset);
		ys_k2ulan_set_dst_qset(hw_addr, rep_qset, enable, 1, 1, dst_qset);
		ys_k2ulan_set_dst_qset(hw_addr, dst_qset, enable, 0, 1, rep_qset);
	}
}

static void ys_k2ulan_enable_qset(struct net_device *ndev, u16 vf_id, u8 enable)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_ndev_priv *ndev_priv;
	struct ys_mbox *mbox;
	void __iomem *hw_addr;
	u16 qset;

	ndev_priv = netdev_priv(ndev);
	qset = ndev_priv->qi.qset;
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];

	if (pdev_priv->nic_type->is_vf) {
		mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
		if (!mbox) {
			ys_dev_err("mbox not support!\n");
			return;
		}
		ys_k2ulan_mbox_req_enable_qset(mbox, enable);
	} else if (vf_id == 0) {
		ys_k2ulan_qset_enable_port(hw_addr, qset, pdev_priv->pf_id, enable);
		ys_k2ulan_qset_init_dst(hw_addr, qset, pdev_priv->pf_id, enable);
	}
}

static int ys_k2ulan_set_mc_mac_call_fn(struct notifier_block *nb, unsigned long action, void *data)
{
	struct ys_mc_mac *mc_mac = (struct ys_mc_mac *)data;

	return ys_k2ulan_set_mc_mac(mc_mac->ndev, (u8 *)mc_mac->eth_addr, mc_mac->enable);
}

static int ys_k2ulan_set_uc_mac_call_fn(struct notifier_block *nb, unsigned long action, void *data)
{
	struct ys_uc_mac *uc_mac = (struct ys_uc_mac *)data;

	return ys_k2ulan_set_uc_mac(uc_mac->ndev, (u8 *)uc_mac->eth_addr, uc_mac->enable);
}

static struct notifier_block k2ulan_set_mc_mac_block = {
	.notifier_call = ys_k2ulan_set_mc_mac_call_fn,
};

static struct notifier_block k2ulan_set_uc_mac_block = {
	.notifier_call = ys_k2ulan_set_uc_mac_call_fn,
};

static void ys_k2ulan_add_inner_vlan(struct ys_pdev_priv *pdev_priv,
				     struct ys_queue_params *qi,
				     u32 vlan_id, __be16 proto)
{
	void __iomem *hw_addr;
	u32 reg;
	struct ys_k2ulan *k2ulan = NULL;
	struct ys_k2ulan_steering *steering;
	struct ys_k2ulan_vlan_entry *vlan_entry;
	u32 vlan_entry_idx;
	u32 offset;

	k2ulan = ys_aux_match_k2ulan_dev(pdev_priv->pdev);
	steering = &k2ulan->lan_steering;

	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	vlan_entry_idx = vlan_id;
	if (proto == htons(ETH_P_8021AD)) {
		vlan_entry_idx += 4096;
		offset = YS_K2ULAN_STEERING_RX_VLAN_FILTER_TYPE1_BASE +
			 YS_K2ULAN_STEERING_RX_VLAN_FILTER_VLAN_BMP_FIELD(vlan_id);
	} else {
		offset = YS_K2ULAN_STEERING_RX_VLAN_FILTER_TYPE0_BASE +
			 YS_K2ULAN_STEERING_RX_VLAN_FILTER_VLAN_BMP_FIELD(vlan_id);
	}

	vlan_entry = &steering->vlan_entrys[vlan_entry_idx];
	ys_info("%s vlan entry id %d vlan_entry %p!", __func__, vlan_entry_idx, vlan_entry);

	ys_k2ulan_bmp_set_bit(vlan_entry->bitmap, YS_K2ULAN_QSET_BITMAP_BITS,
			      qi->qset, true);
	vlan_entry->qbmp_idx = ys_k2ulan_update_vlan_qset_bmp(steering, hw_addr,
							      vlan_entry->qbmp_idx,
							      vlan_entry->bitmap);
	if (vlan_entry->qbmp_idx < 0) {
		ys_err("k2u lan alloc vlan qset bitmap failed!");
		return;
	}
	vlan_entry->member_cnt++;
	ys_info("%s vlan id %d vlan_entry %p member %d qbmp %d!",
		__func__, vlan_entry_idx, vlan_entry, vlan_entry->member_cnt,
		vlan_entry->qbmp_idx);

	reg = FIELD_PREP(YS_K2ULAN_VLAN_FILTER_ENABLE, 1) |
	      FIELD_PREP(YS_K2ULAN_VLAN_FILTER_QSET_BMP_INDEX, vlan_entry->qbmp_idx & 0xfff);
	ys_wr32(hw_addr, offset, reg);
}

static void ys_k2ulan_clear_inner_vlan(struct ys_pdev_priv *pdev_priv,
				       struct ys_queue_params *qi,
				       u32 vlan_id, __be16 proto)
{
	void __iomem *hw_addr;
	u32 reg;
	struct ys_k2ulan *k2ulan;
	struct ys_k2ulan_steering *steering;
	struct ys_k2ulan_vlan_entry *vlan_entry;
	u32 vlan_entry_idx;
	u32 offset;

	k2ulan = ys_aux_match_k2ulan_dev(pdev_priv->pdev);
	steering = &k2ulan->lan_steering;

	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	vlan_entry_idx = vlan_id;
	if (proto == htons(ETH_P_8021AD)) {
		vlan_entry_idx += 4096;
		offset = YS_K2ULAN_STEERING_RX_VLAN_FILTER_TYPE1_BASE +
			 YS_K2ULAN_STEERING_RX_VLAN_FILTER_VLAN_BMP_FIELD(vlan_id);
	} else {
		offset = YS_K2ULAN_STEERING_RX_VLAN_FILTER_TYPE0_BASE +
			 YS_K2ULAN_STEERING_RX_VLAN_FILTER_VLAN_BMP_FIELD(vlan_id);
	}

	vlan_entry = &steering->vlan_entrys[vlan_entry_idx];
	ys_info("%s vlan entry id %d vlan_entry %p!", __func__, vlan_entry_idx, vlan_entry);
	ys_k2ulan_bmp_set_bit(vlan_entry->bitmap, YS_K2ULAN_QSET_BITMAP_BITS,
			      qi->qset, false);
	if (0 == --vlan_entry->member_cnt) {
		if (YS_K2ULAN_QSET_BITMAP_BITS !=
		    ys_k2ulan_bmp_find_first_zero_bit(vlan_entry->bitmap,
						      YS_K2ULAN_QSET_BITMAP_BITS,
						      false)) {
			ys_err("k2u panic vlan qset bitmap not empty but member count is zero!");
		}
		ys_k2ulan_update_vlan_qset_bmp(steering, hw_addr, vlan_entry->qbmp_idx,
					       vlan_entry->bitmap);
		reg = FIELD_PREP(YS_K2ULAN_VLAN_FILTER_ENABLE, 0) |
		      FIELD_PREP(YS_K2ULAN_VLAN_FILTER_QSET_BMP_INDEX, 0);
		ys_wr32(hw_addr, offset, reg);
		memset(vlan_entry, 0, sizeof(*vlan_entry));
		vlan_entry->qbmp_idx = -1;
	} else {
		vlan_entry->qbmp_idx = ys_k2ulan_update_vlan_qset_bmp(steering, hw_addr,
								      vlan_entry->qbmp_idx,
								      vlan_entry->bitmap);
		if (vlan_entry->qbmp_idx < 0) {
			ys_err("k2u lan alloc vlan qset bitmap failed!");
			return;
		}
		reg = FIELD_PREP(YS_K2ULAN_VLAN_FILTER_ENABLE, 1) |
		      FIELD_PREP(YS_K2ULAN_VLAN_FILTER_QSET_BMP_INDEX,
				 vlan_entry->qbmp_idx & 0xfff);
		ys_wr32(hw_addr, offset, reg);
	}
}

static void ys_k2ulan_mbox_req_set_inner_vlan(struct ys_mbox *mbox, struct ys_queue_params *qi,
					      u32 vlan_id, __be16 proto, u8 enable)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_mbox_msg msg = {0};
	struct ys_k2ulan_cmd *cmd;
	u32 send_id = 0;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&send_id;

	if (IS_ERR_OR_NULL(mbox)) {
		ys_err("vf req_set_inner_vlan get mbox failed!");
		return;
	}
	if (mbox->role != MB_VF && mbox->role != MB_PF) {
		ys_err("req_set_inner_vlan mbox role is invalid, role:%x", mbox->role);
		return;
	}
	pdev_priv = pci_get_drvdata(mbox->pdev);
	if (mbox->role == MB_VF)
		ctx->type = MB_PF;
	else
		ctx->type = MB_MASTER;

	cmd = (struct ys_k2ulan_cmd *)msg.data;
	cmd->cmd_type = YS_K2ULAN_CMD_VF_INNER_VLAN_SET;
	cmd->cmd_data[0] = enable;
	cmd->cmd_data[1] = (vlan_id >> 8) & 0x0f;
	cmd->cmd_data[2] = vlan_id & 0xff;
	if (proto == htons(ETH_P_8021AD))
		cmd->cmd_data[3] = 1; // ETH_P_8021Q : 0, ETH_P_8021AD : 1
	cmd->data_len = 4;
	memcpy(cmd->cmd_data + cmd->data_len, qi, sizeof(*qi)); //qset info
	cmd->data_len += sizeof(*qi);

	if (ys_k2ulan_cmd_exec_async(mbox, YS_MBOX_OPCODE_SET_INNER_VLAN, send_id,
				     cmd, sizeof(*cmd) + cmd->data_len)) {
		if (mbox->role == MB_PF)
			ys_dev_err("salve pf set inner vlan failed!");
		else
			ys_dev_err("vf set inner vlan failed!");
	}
}

static int ys_k2ulan_mbox_set_inner_vlan(struct ys_mbox *mbox,
					 struct ys_k2ulan_cmd *cmd, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_queue_params *qi;
	__be16 proto;
	u16 vlan_id = 0;
	u8 enable;

	pdev_priv = pci_get_drvdata(mbox->pdev);

	enable = cmd->cmd_data[0];
	vlan_id = ((cmd->cmd_data[1] << 8) | cmd->cmd_data[2]) & 0xfff;
	if (cmd->cmd_data[3] == 0)
		proto = htons(ETH_P_8021Q);
	else
		proto = htons(ETH_P_8021AD);
	qi = (struct ys_queue_params *)(cmd->cmd_data + 4);
	ys_info("pf %d set vf %d qset %d set %s inner vlan id %d, proto %s",
		pdev_priv->pf_id, vf_id, qi->qset, enable ? "enable" : "disable", vlan_id,
		cmd->cmd_data[3] ? "ETH_P_8021AD" : "ETH_P_8021Q");

	if (mbox->role == MB_PF) {
		ys_k2ulan_mbox_req_set_inner_vlan(mbox, qi, vlan_id, proto, enable);
		return 0;
	}

	if (enable)
		ys_k2ulan_add_inner_vlan(pdev_priv, qi, vlan_id, proto);
	else
		ys_k2ulan_clear_inner_vlan(pdev_priv, qi, vlan_id, proto);

	return 0;
}

void ys_k2ulan_set_inner_vlan(struct net_device *ndev, u16 vlan_id,
			      __be16 proto, u8 enable)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct list_head *vlan_list;
	struct ys_vlan *ys_vlan, *temp;
	struct ys_mbox *mbox;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	if (proto == htons(ETH_P_8021Q)) {
		vlan_list = &ndev_priv->cvlan_list;
	} else if (proto == htons(ETH_P_8021AD)) {
		vlan_list = &ndev_priv->svlan_list;
	} else {
		ys_dev_warn("proto only support ETH_P_8021Q or ETH_P_8021AD\n");
		return;
	}

	if (enable) {
		list_for_each_entry_safe(ys_vlan, temp, vlan_list, list) {
			if (ys_vlan->vlan_id == vlan_id)
				return;
		}
		ys_vlan = kzalloc(sizeof(*ys_vlan), GFP_ATOMIC);
		if (!ys_vlan)
			return;
		/* No error print as WARNING: Possible unnecessary 'out of memory' message */
		ys_vlan->vlan_id = vlan_id;
		list_add(&ys_vlan->list, vlan_list);
	} else {
		if (list_empty(vlan_list)) {
			ys_dev_info("%s remove vlan id %d but vlan list empty return directly!",
				    __func__, vlan_id);
			return;
		}
		list_for_each_entry_safe(ys_vlan, temp, vlan_list, list) {
			if (ys_vlan->vlan_id == vlan_id) {
				list_del(&ys_vlan->list);
				kfree(ys_vlan);
				ys_vlan = NULL;
			}
		}
	}
	mbox = ys_aux_match_mbox_dev(ndev_priv->pdev);
	if (!mbox) {
		ys_dev_err("mbox not support!\n");
		return;
	}

	if (pdev_priv->nic_type->is_vf || mbox->role == MB_PF) {
		ys_k2ulan_mbox_req_set_inner_vlan(mbox, &ndev_priv->qi, vlan_id, proto, enable);
	} else {
		if (enable)
			ys_k2ulan_add_inner_vlan(pdev_priv, &ndev_priv->qi, vlan_id, proto);
		else
			ys_k2ulan_clear_inner_vlan(pdev_priv, &ndev_priv->qi, vlan_id, proto);
	}
}

static void ys_k2ulan_clear_port_vf_vlan(void __iomem *hw_addr, u16 qset)
{
	u32 reg;

	/* tx pvid config reset */
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qset));
	reg &= ~YS_K2ULAN_TX_QSET_OFFLOAD_VEB_QINQ_VLAN_MODE;
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qset), reg);

	reg = FIELD_PREP(YS_K2ULAN_TX_QSET_QINQ_CFG_QINQ_TYPE, 0) |
	      FIELD_PREP(YS_K2ULAN_TX_QSET_QINQ_CFG_QINQ_PVID, 0);
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_QINQ_CFG(qset), reg);

	/* rx pvid config reset */
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset));
	reg &= ~YS_K2ULAN_QSET_VID_MISC_PVID;
	reg &= ~YS_K2ULAN_QSET_VID_MISC_PVID_TYPE;
	reg &= ~YS_K2ULAN_QSET_VID_MISC_PVID_VALID;
	reg &= ~YS_K2ULAN_QSET_VID_MISC_PVID_BYPASS;
	reg |= FIELD_PREP(YS_K2ULAN_QSET_VID_MISC_PVID_BYPASS, 1);
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset), reg);
}

static void ys_k2ulan_reset_vf_regs(void __iomem *hw_addr, u16 qset)
{
	ys_k2ulan_qset_init_hash(hw_addr, qset);
	ys_k2ulan_qset_init_flags(hw_addr, qset);
	ys_k2ulan_qset_init_drops(hw_addr, qset);
	ys_k2ulan_qset_init_vlan(hw_addr, qset);
}

static int ys_k2ulan_set_port_vf_vlan(struct net_device *ndev,
				      u16 vf_id, u16 vlan_id,
				      u8 qos, __be16 proto, bool enable)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	void __iomem *hw_addr;
	u32 reg;
	u16 qset;
	struct ys_vf_info *vf_info;

	if (proto != htons(ETH_P_8021Q) &&
	    proto != htons(ETH_P_8021AD))
		return -EPROTONOSUPPORT;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	/* this func vf id start with 0 */
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	qset = vf_info->qset;
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	vf_info->vf_vlan = vlan_id;
	/* lan tx */
	if (vlan_id) {
		reg = FIELD_PREP(YS_K2ULAN_TX_QSET_QINQ_CFG_QINQ_TYPE, ntohs(proto)) |
		      FIELD_PREP(YS_K2ULAN_TX_QSET_QINQ_CFG_QINQ_PVID, vlan_id);
		ys_wr32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_QINQ_CFG(qset), reg);
	}
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qset));
	reg &= ~YS_K2ULAN_TX_QSET_OFFLOAD_VEB_QINQ_VLAN_MODE;
	reg |= FIELD_PREP(YS_K2ULAN_TX_QSET_OFFLOAD_VEB_QINQ_VLAN_MODE, vlan_id ? 1 : 0);
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB(qset), reg);
	/* lan rx */
	reg = ys_rd32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset));
	reg &= ~YS_K2ULAN_QSET_VID_MISC_PVID;
	reg |= FIELD_PREP(YS_K2ULAN_QSET_VID_MISC_PVID, vlan_id);
	if (vlan_id) {
		reg &= ~YS_K2ULAN_QSET_VID_MISC_PVID_VALID;
		reg |= FIELD_PREP(YS_K2ULAN_QSET_VID_MISC_PVID_VALID, 1);
		reg &= ~YS_K2ULAN_QSET_VID_MISC_PVID_TYPE;
		if (proto == htons(ETH_P_8021AD))
			reg |= FIELD_PREP(YS_K2ULAN_QSET_VID_MISC_PVID_TYPE, 1);
	} else {
		reg &= ~YS_K2ULAN_QSET_VID_MISC_PVID_TYPE;
		reg &= ~YS_K2ULAN_QSET_VID_MISC_PVID_VALID;
	}
	ys_wr32(hw_addr, YS_K2ULAN_STEERING_QSET_QINQ(qset), reg);
	return 0;
}

int ys_k2ulan_set_tc_mc_group(struct net_device *ndev, u32 group_id, u32 *bitmap)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_k2ulan *k2ulan = NULL;
	void __iomem *hw_addr;

	// sanity check
	if (IS_ERR_OR_NULL(ndev) || IS_ERR_OR_NULL(bitmap)) {
		ys_err("k2u set tc mc group parameter has NULL pointer!");
		return -EINVAL;
	}

	if (group_id >= YS_K2ULAN_TC_MC_GROUP_NUM) {
		ys_err("k2u set tc mc group id %d too big!", group_id);
		return -EINVAL;
	}

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];

	k2ulan = ys_aux_match_k2ulan_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(k2ulan))
		return -EFAULT;
	ys_k2ulan_set_vlan_qbmp(&k2ulan->lan_steering, hw_addr, group_id, bitmap);

	return 0;
}

int ys_k2ulan_get_tc_mc_group(struct net_device *ndev, u32 group_id, u32 *bitmap)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct ys_k2ulan *k2ulan = NULL;
	void __iomem *hw_addr;

	// sanity check
	if (IS_ERR_OR_NULL(ndev) || IS_ERR_OR_NULL(bitmap)) {
		ys_err("k2u get tc mc group parameter has NULL pointer!");
		return -EINVAL;
	}

	if (group_id >= YS_K2ULAN_TC_MC_GROUP_NUM) {
		ys_err("k2u get tc mc group id %d too big!", group_id);
		return -EINVAL;
	}

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];

	k2ulan = ys_aux_match_k2ulan_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(k2ulan))
		return -EFAULT;
	ys_k2ulan_get_vlan_qbmp(&k2ulan->lan_steering, hw_addr, group_id, bitmap);

	return 0;
}

static void ys_k2ulan_reset_vf_cfg(struct net_device *ndev, u16 vf_id)
{
	struct ys_pdev_priv *pdev_priv;
	void __iomem *hw_addr;
	struct ys_vf_info *vf_info;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	if (pdev_priv->nic_type->is_vf) {
		ys_dev_err("Only PF can do it!\n");
		return;
	}
	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	vf_info = &pdev_priv->sriov_info.vfinfo[vf_id];
	ys_k2ulan_reset_vf_regs(hw_addr, vf_info->qset);
	ys_k2ulan_clear_port_vf_vlan(hw_addr, vf_info->qset);
}

static int ys_k2ulan_ndev_init(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	int ret;

	if (ndev_priv->adev_type & AUX_TYPE_REP) {
		if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw))
			K2ULAN_REP_NDEV_FUNC(ndev_priv->ys_ndev_hw);
		return 0;
	}

	ndev->priv_flags |= IFF_UNICAST_FLT;

	memset(ndev_priv->hw_default_hash_indir, 0xffffffff,
	       sizeof(ndev_priv->hw_default_hash_indir));

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw))
		K2ULAN_NDEV_FUNC(ndev_priv->ys_ndev_hw);

	ret = atomic_notifier_chain_register(&ndev_priv->ys_ndev_hw->ys_set_mc_mac_list,
					     &k2ulan_set_mc_mac_block);
	if (ret < 0) {
		ys_net_err("ys k2u lan notifier chain register fail: multicast error");
		goto mc_mac_list_register_fail;
	}
	ret = atomic_notifier_chain_register(&ndev_priv->ys_ndev_hw->ys_set_uc_mac_list,
					     &k2ulan_set_uc_mac_block);
	if (ret < 0) {
		ys_net_err("ys k2ulan notifier chain register fail: unicast error");
		goto mc_mac_list_register_fail;
	}

	return 0;

mc_mac_list_register_fail:
	return ret;
}

static void ys_k2ulan_ndev_uninit(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv;

	ndev_priv = netdev_priv(ndev);

	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw))
		atomic_notifier_chain_unregister(&ndev_priv->ys_ndev_hw->ys_set_mc_mac_list,
						 &k2ulan_set_mc_mac_block);
	if (!IS_ERR_OR_NULL(ndev_priv->ys_ndev_hw))
		atomic_notifier_chain_unregister(&ndev_priv->ys_ndev_hw->ys_set_uc_mac_list,
						 &k2ulan_set_uc_mac_block);
}

static void ys_k2ulan_reset_hw_regs(void __iomem *buf, u64 offset, u32 buf_len)
{
	u32 i = 0;

	for (i = 0; i < (buf_len / sizeof(u32)); i++)
		ys_wr32(buf, offset + i * 0x4, 0);
}

static int ys_k2ulan_devlink_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);

	if (!IS_ERR_OR_NULL(pdev_priv->devlink_info.devlink_hw_ops)) {
		K2ULAN_DEVLINK_FUNC(pdev_priv->devlink_info.devlink_hw_ops);
		(void)pdev_priv;
	}

	return 0;
}

static void ys_k2ulan_init_h2c_global_en(void __iomem *bar_addr)
{
	u32 reg = 0;

	reg = FIELD_PREP(YS_K2ULAN_TX_GLOBAL_SWITCH_SUB_EN, 1) |
	      FIELD_PREP(YS_K2ULAN_TX_GLOBAL_OFFLOAD_SUB_EN, 1) |
	      FIELD_PREP(YS_K2ULAN_TX_GLOBAL_VLANTAG_OFFLOAD_SUB_EN, 1) |
	      FIELD_PREP(YS_K2ULAN_TX_GLOBAL_LAN_PRE_SUB_EN, 1) |
	      FIELD_PREP(YS_K2ULAN_TX_GLOBAL_LAN_PARSER_EN, 1);
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_TX_GLOBAL_SUBSYSTEM_EN, reg);

	reg = FIELD_PREP(YS_K2ULAN_TX_GLOBAL_LOOP_ENABLE, 1) |
	      FIELD_PREP(YS_K2ULAN_TX_GLOBAL_VLAN_BITFLAG_EN, 1);
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_TX_GLOBAL_GLOBAL_MODE, reg);
}

static void ys_k2ulan_init_c2h_global_en(void __iomem *bar_addr)
{
	u32 reg = 0;

	reg = FIELD_PREP(YS_K2ULAN_RX_PARSER_ENABLE, 1);
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_RX_PARSER_EN, reg);

	// init rx reserved l2 multicast address
	// IEEE standard mac group address 01:80:C2:00:00:00 ~ 01:80:C2:FF:FF:FF
	reg = FIELD_PREP(YS_K2ULAN_RX_RSVD_MC_MAC_LO32BITS, 0xc2000000);
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_RX_RSVD_MC_MATCH_KEY0, reg);
	reg = FIELD_PREP(YS_K2ULAN_RX_RSVD_MC_MAC_HI16BITS, 0x0180) |
	      FIELD_PREP(YS_K2ULAN_RX_RSVD_MC_KEY_MASK_LEN, 24) |
	      FIELD_PREP(YS_K2ULAN_RX_RSVD_MC_MAC_VALID, 1);
	ys_wr32(bar_addr, YS_K2ULAN_STEERING_RX_RSVD_MC_MATCH_KEY0 + 4, reg);
}

static int ys_k2ulan_cmd_exec(struct ys_mbox *mbox, u32 op_code, u32 ctx, void *in,
			      u32 in_len, struct ys_mbox_msg *ack)
{
	struct ys_mbox_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.opcode = op_code;
	memcpy(msg.data, in, in_len);

	return ys_mbox_send_msg(mbox, &msg, ctx, MB_WAIT_REPLY, 1000, ack);
}

static int ys_k2ulan_cmd_exec_async(struct ys_mbox *mbox, u32 op_code, u32 ctx,
				    void *in, u32 in_len)
{
	struct ys_mbox_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.opcode = op_code;
	memcpy(msg.data, in, in_len);

	return ys_mbox_send_msg(mbox, &msg, ctx, MB_NO_REPLY, 0, NULL);
}

static void ys_mbox_k2ulan_cmd_handler(struct ys_mbox *mbox, struct ys_mbox_msg *msg, u32 msg_id)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(mbox->pdev);
	struct ys_k2ulan_cmd *cmd, *cmd_ack;
	struct ys_k2ulan_mbox_ctx *ctx = (struct ys_k2ulan_mbox_ctx *)&msg_id;
	struct ys_mbox_msg ack_msg;
	u16 vf_id;

	memset(&ack_msg, 0, sizeof(ack_msg));
	cmd = (struct ys_k2ulan_cmd *)msg->data;
	cmd_ack = (struct ys_k2ulan_cmd *)ack_msg.data;
	cmd_ack->cmd_type = cmd->cmd_type; // is it neccessery ?
	vf_id = ctx->func_id;
	ys_dev_debug("ys_mbox k2ulan cmd handler:%x, cmd type:%d", msg_id, cmd->cmd_type);

	switch (cmd->cmd_type) {
	case YS_K2ULAN_CMD_VF_UC_ADD:
	case YS_K2ULAN_CMD_VF_UC_UPD:
	case YS_K2ULAN_CMD_VF_UC_DEL:
		ys_k2ulan_mbox_set_mac(mbox, cmd, (u16)msg_id);
		return;
	case YS_K2ULAN_CMD_VF_MC_ADD:
	case YS_K2ULAN_CMD_VF_MC_DEL:
		ys_k2ulan_mbox_set_mc_mac(mbox, cmd, vf_id);
		return;
	case YS_K2ULAN_CMD_PF_SET_VF_UC:
		cmd_ack->cmd_status = ys_k2ulan_mbox_pf_set_vf_mac(mbox, cmd, cmd_ack, vf_id);
		break;
	case YS_K2ULAN_CMD_VF_HASH_SET:
		cmd_ack->cmd_status = ys_k2ulan_mbox_set_hash_mode(mbox, cmd, vf_id);
		break;
	case YS_K2ULAN_CMD_VF_HASH_GET:
		cmd_ack->cmd_status = ys_k2ulan_mbox_get_hash_mode(mbox, cmd, cmd_ack, vf_id);
		break;
	case YS_K2ULAN_CMD_VF_HASH_CLEAR:
		cmd_ack->cmd_status = ys_k2ulan_mbox_clear_hash(mbox, cmd, vf_id);
		break;
	case YS_K2ULAN_CMD_VF_PROMISC_SET:
		cmd_ack->cmd_status = ys_k2ulan_mbox_switch_set_promisc(mbox, cmd, vf_id);
		break;
	case YS_K2ULAN_CMD_VF_PORT_EN:
		cmd_ack->cmd_status = ys_k2ulan_mbox_switch_enable_qset(mbox, cmd, vf_id);
		break;
	case YS_K2ULAN_CMD_VF_PORT_REMOVE:
		cmd_ack->cmd_status = ys_k2ulan_mbox_remove_vf(mbox, cmd, vf_id);
		break;
	case YS_K2ULAN_CMD_VF_INNER_VLAN_SET:
		ys_k2ulan_mbox_set_inner_vlan(mbox, cmd, vf_id);
		return;
	case YS_K2ULAN_CMD_VF_RX_FEATURE_SET:
		cmd_ack->cmd_status = ys_k2ulan_mbox_set_vlan_feature(mbox, cmd, vf_id);
		break;
	case YS_K2ULAN_CMD_VF_TX_FEATURE_SET:
		cmd_ack->cmd_status = ys_k2ulan_mbox_set_tx_feature(mbox, cmd, vf_id);
		break;
	case YS_K2ULAN_CMD_VF_MTU_SET:
		cmd_ack->cmd_status = ys_k2ulan_mbox_set_mtu(mbox, cmd, vf_id);
		break;
	case YS_K2ULAN_CMD_VF_SET_PRIV_FLAG:
		cmd_ack->cmd_status = ys_k2ulan_mbox_set_priv(mbox, cmd, vf_id);
		break;
	default:
		ys_dev_info("cmd type unknown, cmd type:0x%x", cmd->cmd_type);
		cmd_ack->cmd_status = -2;
		break;
	}

	ack_msg.opcode = msg->opcode | (1 << YS_MBOX_OPCODE_MASK_ACK);
	ack_msg.seqno = msg->seqno;
	/* response message */
	ys_mbox_send_msg(mbox, &ack_msg, msg_id, MB_NO_REPLY, 0, NULL);
}

static int ys_k2ulan_eth_init(struct net_device *ndev)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);

	if (ndev_priv->adev_type & AUX_TYPE_REP) {
		if (!IS_ERR_OR_NULL(ndev_priv->ys_eth_hw))
			K2ULAN_REP_ETH_FUNC(ndev_priv->ys_eth_hw);
		/* init private flag all disable */
		ndev_priv->veb_enable = false;
		ndev_priv->umc_flood = false;
		ndev_priv->rss_sel_udp_tun_info = false;
		return 0;
	}

	if (!IS_ERR_OR_NULL(ndev_priv->ys_eth_hw))
		K2ULAN_ETH_FUNC(ndev_priv->ys_eth_hw);

	/* init private flag default value */
	ndev_priv->veb_enable = true;
	ndev_priv->umc_flood = false;
	ndev_priv->rss_sel_udp_tun_info = false;
	ndev_priv->pvid_miss_upload = false; /* only for pf */

	return 0;
}

static int ys_k2ulan_debugfs_show(struct seq_file *seq, void *data)
{
	struct ys_pdev_priv *pdev_priv = seq->private;
	void __iomem *hw_addr;
	u64 cnt = 0;

	seq_puts(seq, "yusur lan switch counter:\n");

	seq_printf(seq, "pf%d lan\n", pdev_priv->pf_id);

	hw_addr = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_SW_DROP_CNT_CH0);
	seq_printf(seq, "switch_drop_cnt_ch0: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_SW_HIT_CNT_CH0);
	seq_printf(seq, "switch_hit_cnt_ch0: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_SW_DROP_CNT_CH1);
	seq_printf(seq, "switch_drop_cnt_ch1: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_SW_HIT_CNT_CH1);
	seq_printf(seq, "switch_hit_cnt_ch1: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_SW_DROP_CNT_CH2);
	seq_printf(seq, "switch_drop_cnt_ch2: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_SW_HIT_CNT_CH2);
	seq_printf(seq, "switch_hit_cnt_ch2: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_SW_DROP_CNT_CH3);
	seq_printf(seq, "switch_drop_cnt_ch3: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_SW_HIT_CNT_CH3);
	seq_printf(seq, "switch_hit_cnt_ch3: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_MAC_MISS_CNT);
	seq_printf(seq, "switch_mac_miss_cnt: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_FIRST_VLAN_MISS_CNT);
	seq_printf(seq, "switch_first_vlan_miss_cnt: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_SECOND_VLAN_MISS_CNT);
	seq_printf(seq, "switch_vlan_miss_cnt: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_PVID_MISS_CNT);
	seq_printf(seq, "switch_pvid_miss_cnt: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_VEB_DROP_CNT);
	seq_printf(seq, "switch_veb_drop_cnt: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_FCS_DROP_CNT);
	seq_printf(seq, "switch_fsc_drop_cnt: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_CHKSUM_DROP_CNT);
	seq_printf(seq, "switch_checksum_drop_cnt: %lld\n", cnt);

	cnt = ys_big_rd64(hw_addr, YS_K2ULAN_RX_DEBUG_STATS_MTU_DROP_CNT);
	seq_printf(seq, "switch_over_mtu_drop_cnt: %lld\n", cnt);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ys_k2ulan_debugfs);

static void ys_k2ulan_init_hw_res(void __iomem *hw_addr)
{
	int i;

	/* lan init qset & filter regs */
	ys_k2ulan_reset_hw_regs(hw_addr,
				YS_K2ULAN_STEERING_TX_DST_QSET_BASE,
				YS_K2ULAN_STEERING_TX_DST_QSET_TOTAL_LEN);

	ys_k2ulan_reset_hw_regs(hw_addr,
				YS_K2ULAN_STEERING_TX_QSET_QINQ_CFG_BASE,
				YS_K2ULAN_STEERING_TX_QSET_QINQ_CFG_TOTAL_LEN);

	ys_k2ulan_reset_hw_regs(hw_addr,
				YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB_BASE,
				YS_K2ULAN_STEERING_TX_QSET_OFFLOAD_VEB_TOTAL_LEN);

	ys_k2ulan_reset_hw_regs(hw_addr,
				YS_K2ULAN_STEERING_TX_VPORT_BASE,
				YS_K2ULAN_STEERING_TX_VPORT_TOTAL_LEN);

	ys_k2ulan_reset_hw_regs(hw_addr,
				YS_K2ULAN_STEERING_RX_QEST_BASE,
				YS_K2ULAN_STEERING_RX_QEST_TOTAL_LEN);

	ys_k2ulan_reset_hw_regs(hw_addr,
				YS_K2ULAN_STEERING_RX_MAC_FILTER_BASE,
				YS_K2ULAN_STEERING_RX_MAC_FILTER_TOTAL_LEN);

	ys_k2ulan_reset_hw_regs(hw_addr,
				YS_K2ULAN_STEERING_RX_VLAN_FILTER_TYPE0_BASE,
				YS_K2ULAN_STEERING_RX_VLAN_FILTER_TOTAL_LEN);

	ys_k2ulan_reset_hw_regs(hw_addr,
				YS_K2ULAN_STEERING_RX_VLAN_FILTER_TYPE1_BASE,
				YS_K2ULAN_STEERING_RX_VLAN_FILTER_TOTAL_LEN);

	ys_k2ulan_reset_hw_regs(hw_addr,
				YS_K2ULAN_STEERING_RX_VLAN_RULE_BASE,
				YS_K2ULAN_STEERING_RX_VLAN_RULE_TOTAL_LEN);

	ys_k2ulan_reset_hw_regs(hw_addr,
				YS_K2ULAN_STEERING_RX_IPV4_L2MC_FILTER_BASE,
				YS_K2ULAN_STEERING_RX_IPV4_L2MC_FILTER_TOTAL_LEN);

	for (i = 0; i < YS_K2ULAN_STEERING_RX_IPV4_L2MC_FILTER_REG_NUMB; i++) {
		ys_k2ulan_reset_hw_regs(hw_addr,
					YS_K2ULAN_STEERING_RX_IPV4_L2MC_FILTER_REG(i),
					0x8);
	}

	ys_k2ulan_init_h2c_global_en(hw_addr);
	ys_k2ulan_init_c2h_global_en(hw_addr);
	ys_k2ulan_init_qset(hw_addr);
}

int ys_k2ulan_probe(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(adev->pdev);
	struct ys_k2ulan *k2ulan;
	struct ys_mbox *mbox;
	void __iomem *hw_base;
	struct ys_k2ulan_steering *steering;
	char debugfs_file_name[16];
	int i;

	k2ulan = kzalloc(sizeof(*k2ulan), GFP_KERNEL);
	if (IS_ERR_OR_NULL(k2ulan))
		return -ENOMEM;

	mbox = ys_aux_match_mbox_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(mbox))
		return -EFAULT;

	hw_base = pdev_priv->bar_addr[YS_K2ULAN_REGS_BAR];
	if (!pdev_priv->nic_type->is_vf && mbox->role == MB_MASTER) {
		steering = &k2ulan->lan_steering;
		spin_lock_init(&steering->lock);
		INIT_LIST_HEAD(&steering->l2uc_key_list);
		INIT_LIST_HEAD(&steering->l2uc_qbmp_list);
		INIT_LIST_HEAD(&steering->ipv4_l2mc_key_list);
		INIT_LIST_HEAD(&steering->ipv4_l2mc_qbmp_list);
		/* init k2u lan shared cuckoo table */
		if (pdev_priv->dpu_mode == MODE_LEGACY ||
		    pdev_priv->dpu_mode == MODE_SMART_NIC) {
		// TODO init bnic version by device id
		//if (pdev_priv->pdev->device == K2U_BNIC_DEVID)
			steering->lan_hw_type = YS_K2ULAN_HW_TYPE_BNIC;
			k2ulan->lan_mac_table = ys_cuckoo_create(YS_CUCKOO_TYPE_K2U_BNIC_LAN_MAC,
								 0, pdev_priv->pf_id, hw_base);
		} else {
			steering->lan_hw_type = YS_K2ULAN_HW_TYPE_NORMAL;
			k2ulan->lan_mac_table = ys_cuckoo_create(YS_CUCKOO_TYPE_K2U_LAN_MAC,
								 0, pdev_priv->pf_id, hw_base);
		}
		if (IS_ERR_OR_NULL(k2ulan->lan_mac_table)) {
			ys_dev_err("k2u lan create cuckoo hash table failed!\n");
			return -EFAULT;
		}

		steering->vlan_qbmp_num = YS_K2ULAN_STEERING_RX_VLAN_RULE_NUMS;
		steering->dpu_mode = pdev_priv->dpu_mode;
		// non-bnic mode kernel vlan use first half vlan qbmp resource
		if (pdev_priv->dpu_mode == MODE_SMART_NIC)
			steering->vlan_qbmp_num = YS_K2ULAN_STEERING_RX_VLAN_RULE_NUMS / 2;
		// 8K vlan entry = 802.1Q 4K + 802.1ad 4K
		steering->vlan_entrys = kzalloc(sizeof(*steering->vlan_entrys) * 8192,
						GFP_KERNEL);
		if (IS_ERR_OR_NULL(steering->vlan_entrys)) {
			ys_dev_err("k2u lan create vlan entries failed!\n");
			return -EFAULT;
		}
		for (i = 0; i < 8192; i++)
			steering->vlan_entrys[i].qbmp_idx = -1;
		INIT_LIST_HEAD(&steering->vlan_qset_bmp_list);

		/* lan init qset & filter regs */
		ys_k2ulan_init_hw_res(hw_base);
	}

	if (!pdev_priv->nic_type->is_vf) {
		snprintf(debugfs_file_name, sizeof(debugfs_file_name),
			 "lan_stats_%02d", pdev_priv->pf_id);
		k2ulan->debugfs_file = debugfs_create_file(debugfs_file_name, 0400,
							   ys_debugfs_root, pdev_priv,
							   &ys_k2ulan_debugfs_fops);
		if (IS_ERR(k2ulan->debugfs_file)) {
			ys_dev_err("Failed to create debugfs file %s\n", debugfs_file_name);
			k2ulan->debugfs_file = NULL;
		}
	}

	adev->adev_priv = (void *)k2ulan;

	pdev_priv->ops->lan_adp_eth_init = ys_k2ulan_eth_init;
	pdev_priv->ops->lan_adp_ndev_init = ys_k2ulan_ndev_init;
	pdev_priv->ops->lan_adp_ndev_uninit = ys_k2ulan_ndev_uninit;
	pdev_priv->ops->lan_adp_devlink_init = ys_k2ulan_devlink_init;

	mbox = ys_aux_match_mbox_dev(pdev_priv->pdev);
	if (IS_ERR_OR_NULL(mbox))
		return -EFAULT;

	mbox->mbox_vf_to_pf_set_inner_vlan = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_vf_to_pf_set_mac = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_vf_to_pf_set_mc_mac = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_vf_to_pf_set_mtu = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_vf_to_pf_set_hash = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_vf_to_pf_clear_hash = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_vf_to_pf_set_port_enable = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_vf_to_pf_get_hash_mode = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_vf_to_pf_set_vlan_features = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_vf_to_pf_set_tx_features = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_pf_to_vf_set_mac = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_vf_to_pf_set_promisc = ys_mbox_k2ulan_cmd_handler;
	mbox->mbox_vf_to_pf_set_priv = ys_mbox_k2ulan_cmd_handler;

	return 0;
}

void ys_k2ulan_remove(struct auxiliary_device *auxdev)
{
	struct ys_adev *adev = container_of(auxdev, struct ys_adev, auxdev);
	struct ys_k2ulan *k2ulan = (struct ys_k2ulan *)adev->adev_priv;

	if (!IS_ERR_OR_NULL(k2ulan)) {
		if (k2ulan->lan_mac_table)
			ys_cuckoo_destroy(k2ulan->lan_mac_table);
		debugfs_remove(k2ulan->debugfs_file);
		kfree(k2ulan);
		adev->adev_priv = NULL;
	}
}
