// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_new_core.h"
#include "ys_k2u_new_hw.h"
#include "ys_k2u_new_func.h"
#include "ys_k2u_new_vfsf.h"
#include "ys_k2u_new_qset.h"
#include "ys_k2u_new_ndev.h"
#include "ys_k2u_message.h"

#include "ys_k2u_new_tx.h"

#include "../mbox/ys_k2u_mbox.h"
#include "../doe/ys_k2u_doe_core.h"
#include "../np/ys_k2u_np.h"
#include "../../net/mac/ys_mac.h"

static struct hw_adapter_ops ys_k2u_ops = {
	.hw_adp_mbox_init = ys_k2u_mbox_init,
	.hw_adp_init = ys_k2u_ndev_init,
	.hw_adp_uninit = ys_k2u_ndev_uninit,
	.hw_adp_start = ys_k2u_ndev_start,
	.hw_adp_stop = ys_k2u_ndev_stop,
	.hw_adp_update_stat = ys_k2u_ndev_update_stat,
	.hw_adp_send = ys_k2u_new_start_xmit,
	.hw_adp_get_init_qbase = ys_k2u_pdev_get_init_qbase,
	.hw_adp_get_init_qnum = ys_k2u_pdev_get_init_qnum,
	.hw_adp_sriov_enable = ys_k2u_sriov_enable,
	.hw_adp_sriov_config_change = ys_k2u_sriov_config_change,
	.hw_adp_sriov_disable = ys_k2u_sriov_disable,
	.hw_adp_doe_init = ys_k2u_doe_aux_probe,
	.hw_adp_doe_uninit = ys_k2u_doe_aux_remove,
#ifdef CONFIG_YSMOD_NP
	.hw_adp_np_init = ys_k2u_np_aux_probe,
	.hw_adp_np_uninit = ys_k2u_np_aux_remove,
#endif /* CONFIG_YSMOD_NP */
	.hw_adp_add_cdev = ys_k2u_doe_module_add_cdev,
	.hw_adp_cdev_start = ys_k2u_ndev_cdev_start,
	.hw_adp_cdev_qgroup_get = ys_k2u_ndev_cdev_qgroup_get,
	.hw_adp_cdev_qgroup_set = ys_k2u_ndev_cdev_qgroup_set,
	.hw_adp_cdev_qos_sync = ys_k2u_ndev_cdev_qos_sync,
	.hw_adp_cdev_link_gqbase_get = ys_k2u_ndev_cdev_link_gqbase_get,
	.hw_adp_cdev_peer_qset_get = ys_k2u_ndev_cdev_peer_qset_get,
	.ndev_has_mac_link_status = ys_k2u_ndev_has_mac_link_status,
};

int ys_k2u_pdev_init(struct ys_pdev_priv *pdev_priv)
{
	void __iomem *hw_addr;
	int ret;
	u32 val;

	/* 1. fill pdev_priv */
	pdev_priv->dpu_mode = MODE_LEGACY;
	if (smart_nic)
		pdev_priv->dpu_mode = MODE_SMART_NIC;
	if (dpu_host)
		pdev_priv->dpu_mode = MODE_DPU_HOST;
	if (dpu_soc)
		pdev_priv->dpu_mode = MODE_DPU_SOC;

#ifdef CONFIG_YSHW_K2ULTRA
	pdev_priv->hw_type = YS_HW_TYPE_K2ULTRA;
#elif defined(CONFIG_YSHW_K2ULTRA_CS)
	pdev_priv->hw_type = YS_HW_TYPE_K2ULTRA_CS;
#endif /* CONFIG_YSHW_K2ULTRA */

	hw_addr = pdev_priv->bar_addr[0];
	val = ys_rd32(hw_addr, YS_K2U_RP_PFVFID);
	pdev_priv->pf_id = FIELD_GET(YS_K2U_RP_PFID_GMASK, val);
	pdev_priv->vf_id = FIELD_GET(YS_K2U_RP_VFID_GMASK, val);

	/* 2. func */
	ret = ys_k2u_pdev_func_init(pdev_priv);
	if (ret) {
		ys_err("ys_k2u_pdev_func_init failed\n");
		return ret;
	}

	ret = ys_k2u_pdev_vfsf_init(pdev_priv);
	if (ret) {
		ys_err("ys_k2u_pdev_vfsf_init failed\n");
		goto vfsf_failed;
	}

	/* 3. qset */
	ret = ys_k2u_pdev_qset_init(pdev_priv);
	if (ret) {
		ys_err("ys_k2u_pdev_qset_init failed\n");
		goto qset_failed;
	}

	/* 4. mbox */
	/* ... */

	/* 5. ops */
	pdev_priv->ops = &ys_k2u_ops;

	return 0;

qset_failed:
	ys_k2u_pdev_vfsf_uninit(pdev_priv);
vfsf_failed:
	ys_k2u_pdev_func_uninit(pdev_priv);
	return ret;
}

void ys_k2u_pdev_uninit(struct ys_pdev_priv *pdev_priv)
{
	pdev_priv->ops = NULL;
	ys_k2u_pdev_qset_uninit(pdev_priv);
	ys_k2u_pdev_vfsf_uninit(pdev_priv);
	ys_k2u_pdev_func_uninit(pdev_priv);
}

int ys_k2u_pdev_fix_mode(struct ys_pdev_priv *pdev_priv)
{
	/**
	 * smartnic mode: mapping between uplink&pf&vf id and rep id
	 * | ------------ | ------ |
	 * | pf&vf&uplink | rep id |
	 * | ------------ | ------ |
	 * | uplink       | 0x200  |
	 * | pf           | 0x0    |
	 * | vf 0         | 0x1    |
	 * | vf 1         | 0x2    |
	 * | ...          | ...    |
	 * | vf n         | n + 1  |
	 * | ------------ | ------ |
	 */
	struct ys_queue_params qi;
	u16 qnum;

	if (pdev_priv->nic_type->is_vf)
		return 0;

	switch (pdev_priv->dpu_mode) {
	case MODE_SMART_NIC:
		qnum = ys_k2u_vfsf_get_minqnum(pdev_priv, YS_K2U_NDEV_PF);

		/* uplink */
		qi.qbase = qnum;
		qi.ndev_qnum = ys_k2u_vfsf_get_minqnum(pdev_priv, YS_K2U_NDEV_UPLINK);
		qi.qset = 0xffff;
		ys_aux_add_adev(pdev_priv->pdev, YS_K2U_ID_NDEV_UPLINK, AUX_NAME_REP, &qi);

		/* pf rep */
		qi.qbase = qnum + ys_k2u_vfsf_get_minqnum(pdev_priv, YS_K2U_NDEV_UPLINK);
		qi.ndev_qnum = ys_k2u_vfsf_get_minqnum(pdev_priv, YS_K2U_NDEV_REP);
		qi.qset = 0xffff;
		ys_aux_add_adev(pdev_priv->pdev, YS_K2U_ID_NDEV_PFREP, AUX_NAME_REP, &qi);

		break;
	case MODE_DPU_SOC:
		qnum = ys_k2u_vfsf_get_minqnum(pdev_priv, YS_K2U_NDEV_PF);

		/* pf rep */
		qi.qbase = qnum;
		qi.ndev_qnum = ys_k2u_vfsf_get_minqnum(pdev_priv, YS_K2U_NDEV_REP);
		qi.qset = 0xffff;
		ys_aux_add_adev(pdev_priv->pdev, YS_K2U_ID_NDEV_PFREP, AUX_NAME_REP, &qi);

		break;
	default:
		break;
	}

	return 0;
}

void ys_k2u_pdev_unfix_mode(struct ys_pdev_priv *pdev_priv)
{
	switch (pdev_priv->dpu_mode) {
	case MODE_SMART_NIC:
		ys_aux_del_match_adev(pdev_priv->pdev, YS_K2U_ID_NDEV_UPLINK, AUX_NAME_REP);
		ys_aux_del_match_adev(pdev_priv->pdev, YS_K2U_ID_NDEV_PFREP, AUX_NAME_REP);
		break;
	case MODE_DPU_SOC:
		ys_aux_del_match_adev(pdev_priv->pdev, YS_K2U_ID_NDEV_PFREP, AUX_NAME_REP);
		break;
	default:
		break;
	}
}
