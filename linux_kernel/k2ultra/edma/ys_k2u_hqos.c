// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_new_core.h"
#include "ys_k2u_new_hw.h"
#include "ys_k2u_new_func.h"
#include "ys_k2u_debugfs.h"
#include "ys_k2u_new_qset.h"
#include "ys_k2u_new_ndev.h"
#include "ys_k2u_new_vfsf.h"
#include "ys_k2u_new_ethtool.h"
#include "ys_k2u_hqos.h"

struct ys_k2u_hqos_data {
	union {
		u32 data[8];
		struct {
			u64 bucket_en:1;
			u64 cir_factor:28;
			u64 cbs:28;
			u64 next_route_id:3;
			u64 next_class_id_l:4;

			u64 next_class_id_h:12;
			u64 cc:29;
			u64 b_time_l:23;

			u64 b_time_h:25;
			u64 borrow_en:1;
			u64 share_en:1;
			u64 share_ctrl:1;
			u64 src_tag_qid:16;
			u64 next_1v1_id:3;
			u64 reserved1:17;

			u64 reserved2;
		};
	};
} __packed;

#define YS_K2U_V_HQOS_MASK_DEFAULT \
{ \
	.data = {0xffffffff, 0xffffffff, 0x00000fff, 0x00000000, 0x06000000, \
		0x00007000, 0x00000000, 0x00000000}, \
}

static inline void
ys_k2u_hqos_data_init(struct ys_k2u_hqos_data *hqos_data)
{
	memset(hqos_data, 0, sizeof(*hqos_data));
}

static inline void
ys_k2u_hqos_data_set_bucket_en(struct ys_k2u_hqos_data *hqos_data, bool en)
{
	hqos_data->bucket_en = en ? 1 : 0;
}

static inline void
ys_k2u_hqos_data_set_cir_factor(struct ys_k2u_hqos_data *hqos_data, u32 cir_factor)
{
	hqos_data->cir_factor = cir_factor & 0x0fffffff;
}

static inline void
ys_k2u_hqos_data_set_cbs(struct ys_k2u_hqos_data *hqos_data, u32 cbs)
{
	hqos_data->cbs = cbs & 0x0fffffff;
}

static inline void
ys_k2u_hqos_data_set_next_class_id(struct ys_k2u_hqos_data *hqos_data, u32 class_id)
{
	hqos_data->next_class_id_l = class_id & 0xf;
	hqos_data->next_class_id_h = (class_id >> 4) & 0xfff;
}

static void ys_k2u_hqos_params_calc(int rate, u32 *cir_factor, u32 *cbs)
{
	/* cir_factor use B */
	*cir_factor = (rate << (20 - 3)) / YS_K2U_N_HQOS_MCLK;
	/* cbs use b */
	if (rate <= 100)
		*cbs = (rate * 1000 * 1500) >> 3;
	else
		*cbs = (100000 * 1500) >> 3;
}

static void ys_k2u_hqos_data_debug(struct ys_k2u_ndev *k2u_ndev,
				   struct ys_k2u_hqos_data *data, u16 qset)
{
	struct ys_pdev_priv *pdev_priv = k2u_ndev->pdev_priv;

	ys_dev_info("hqos qset %d bucket_en : 0x%x, cir_factor : 0x%x, cbs : 0x%x",
		    qset, data->bucket_en, data->cir_factor, data->cbs);

	ys_dev_info("next_class_id_l : 0x%x, next_class_id_h : 0x%x",
		    data->next_class_id_l, data->next_class_id_h);
}

static inline void
ys_k2u_hqos_set_data(struct ys_k2u_ndev *k2u_ndev, struct ys_k2u_hqos_data *hqos_data)
{
	int i;
	struct ys_pdev_priv *pdev_priv = k2u_ndev->pdev_priv;

	for (i = 0; i < 8; i++) {
		ys_dev_debug("hqos register 0x%8x : value 0x%8x",
			     YS_K2U_RQ_TBDATA(i), hqos_data->data[i]);
		ys_wr32(ys_k2u_func_get_hwaddr(pdev_priv), YS_K2U_RQ_TBDATA(i), hqos_data->data[i]);
	}
}

static inline void
ys_k2u_hqos_set_mask(struct ys_k2u_ndev *k2u_ndev, struct ys_k2u_hqos_data *hqos_data)
{
	int i;
	struct ys_pdev_priv *pdev_priv = k2u_ndev->pdev_priv;

	for (i = 0; i < 8; i++) {
		ys_dev_debug("hqos register 0x%8x : value 0x%8x",
			     YS_K2U_RQ_TBMASK(i), hqos_data->data[i]);
		ys_wr32(ys_k2u_func_get_hwaddr(pdev_priv), YS_K2U_RQ_TBMASK(i), hqos_data->data[i]);
	}
}

static inline void
ys_k2u_hqos_set_addr(struct ys_k2u_ndev *k2u_ndev, u16 ram_addr, u8 ram_id, u8 ifce_id)
{
	u32 value = (ifce_id << 24) | (ram_id << 16) | ram_addr;
	struct ys_pdev_priv *pdev_priv = k2u_ndev->pdev_priv;

	ys_dev_debug("hqos register 0x%8x : value 0x%8x",
		     YS_K2U_RQ_TBADDR, value);
	ys_wr32(ys_k2u_func_get_hwaddr(pdev_priv), YS_K2U_RQ_TBADDR, value);
}

static inline void
ys_k2u_hqos_set_valid(struct ys_k2u_ndev *k2u_ndev, bool valid)
{
	struct ys_pdev_priv *pdev_priv = k2u_ndev->pdev_priv;

	ys_dev_debug("hqos register 0x%8x : value 0x%8x",
		     YS_K2U_RQ_TBVALID, valid ? 1 : 0);
	ys_wr32(ys_k2u_func_get_hwaddr(pdev_priv), YS_K2U_RQ_TBVALID, valid ? 1 : 0);
}

static void ys_k2u_hqos_queue_set(struct ys_k2u_ndev *k2u_ndev, u16 qset, u16 qid)
{
	struct ys_k2u_hqos_data data;
	struct ys_k2u_hqos_data mask = YS_K2U_V_HQOS_MASK_DEFAULT;

	ys_k2u_hqos_data_init(&data);
	ys_k2u_hqos_data_set_next_class_id(&data, qset);
	ys_k2u_hqos_data_debug(k2u_ndev, &data, qset);
	wmb();		/* wmb */

	ys_k2u_hqos_set_data(k2u_ndev, &data);

	ys_k2u_hqos_set_mask(k2u_ndev, &mask);

	ys_k2u_hqos_set_addr(k2u_ndev, qid, 0, 0x07);

	ys_k2u_hqos_set_valid(k2u_ndev, true);
}

static void ys_k2u_hqos_qset_set(struct ys_k2u_ndev *k2u_ndev, u16 qset, int rate, bool en)
{
	u32 cir_factor;
	u32 cbs;
	struct ys_k2u_hqos_data data;
	struct ys_k2u_hqos_data mask = YS_K2U_V_HQOS_MASK_DEFAULT;

	ys_k2u_hqos_params_calc(rate, &cir_factor, &cbs);

	ys_k2u_hqos_data_init(&data);
	ys_k2u_hqos_data_set_cir_factor(&data, cir_factor);
	ys_k2u_hqos_data_set_cbs(&data, cbs);
	ys_k2u_hqos_data_set_bucket_en(&data, en);
	ys_k2u_hqos_data_debug(k2u_ndev, &data, qset);
	wmb();		/* wmb */

	ys_k2u_hqos_set_data(k2u_ndev, &data);

	ys_k2u_hqos_set_mask(k2u_ndev, &mask);

	ys_k2u_hqos_set_addr(k2u_ndev, qset, 0, 0x08);

	ys_k2u_hqos_set_valid(k2u_ndev, true);
}

int ys_k2u_set_vf_rate(struct net_device *ndev, int vf, int min_tx_rate, int max_tx_rate)
{
	int rate = max_tx_rate;
	struct ys_vf_info *vfinfo;
	struct ys_ndev_priv *ndev_priv = netdev_priv(ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	struct ys_k2u_ndev *k2u_ndev = ndev_priv->adp_priv;
	struct ys_k2u_queuebase qbase;
	u16 qset;
	u16 i;

	if (pdev_priv->sriov_info.num_vfs <= vf || rate < 0)
		return -EINVAL;

	vfinfo = &pdev_priv->sriov_info.vfinfo[vf];

	qset = vfinfo->qset;

	qbase = ys_k2u_func_get_funcx_qbase(pdev_priv, vf + 1, YS_K2U_QUEUE_GLOBAL);

	if (rate > 0) {
		for (i = 0; i < qbase.num; i++)
			ys_k2u_hqos_queue_set(k2u_ndev, qset, qbase.start + i);
	}

	ys_k2u_hqos_qset_set(k2u_ndev, qset, rate, !!rate);

	vfinfo->vf_tx_rate = rate;

	return 0;
}
