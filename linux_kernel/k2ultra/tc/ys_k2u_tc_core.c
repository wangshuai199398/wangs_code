// SPDX-License-Identifier: GPL-2.0

#include "ys_k2u_tc_core.h"
#include "ys_k2u_tc_priv.h"
#include "../np/ys_k2u_np.h"

static DEFINE_IDR(ys_tc_switchdev_idr);
static DEFINE_MUTEX(ys_tc_switchdev_lock);

static bool ys_tc_doe_array_cache_max;
static bool ys_tc_doe_hash_cache_max;

static int ys_tc_setup_tc_cls_flower(struct ys_tc_priv *tc_priv,
				     struct flow_cls_offload *cls_flower)
{
	if (cls_flower->common.chain_index)
		return -EOPNOTSUPP;

	if (cls_flower->command == FLOW_CLS_REPLACE &&
	    !tc_can_offload_extack(tc_priv->ndev, cls_flower->common.extack))
		return -EOPNOTSUPP;

	switch (cls_flower->command) {
	case FLOW_CLS_REPLACE:
		return ys_tc_add_flower(tc_priv, cls_flower);
	case FLOW_CLS_DESTROY:
		return ys_tc_del_flower(tc_priv, cls_flower);
	case FLOW_CLS_STATS:
		return ys_tc_stat_flower(tc_priv, cls_flower);
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
ys_tc_indr_setup_tc_act(struct ys_tc_priv *tc_priv,
			struct flow_offload_action *fl_act)
{
	switch (fl_act->command) {
	case FLOW_ACT_REPLACE:
		return ys_tc_add_act(tc_priv, fl_act);
	case FLOW_ACT_DESTROY:
		return ys_tc_del_act(tc_priv, fl_act);
	case FLOW_ACT_STATS:
		return ys_tc_stat_act(tc_priv, fl_act);
	default:
		return -EOPNOTSUPP;
	}
}

const struct ys_tc_adapter_ops ys_tc_ops = {
	.setup_tc_cls_flower = ys_tc_setup_tc_cls_flower,
	.setup_tc_act = ys_tc_indr_setup_tc_act,
};

static void ys_tc_metrcs_init(struct ys_tc_switchdev *switchdev)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(switchdev->doe_errors); i++)
		atomic64_set(&switchdev->doe_errors[i], 0);

	for (i = 0; i < ARRAY_SIZE(switchdev->stats); i++)
		atomic64_set(&switchdev->stats[i], 0);

	for (i = 0; i < ARRAY_SIZE(switchdev->metrics); i++)
		atomic64_set(&switchdev->metrics[i], 0);
}

static int ys_tc_debug_qset_show(struct seq_file *seq, void *data)
{
	struct ys_tc_switchdev *switchdev = seq->private;
	struct ys_tc_priv *tc_priv = NULL;
	struct ys_ndev_priv *ndev_priv = NULL;

	mutex_lock(&switchdev->priv_mlock);
	list_for_each_entry(tc_priv, &switchdev->priv_head, switchdev_node) {
		ndev_priv = netdev_priv(tc_priv->ndev);
		seq_printf(seq, "%-16s qset: %u, peer qset: %u\n",
			   tc_priv->ndev->name, ndev_priv->qi.qset, tc_priv->qset);
	}
	mutex_unlock(&switchdev->priv_mlock);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ys_tc_debug_qset);

static int ys_tc_set_doe_array_cache(struct ys_tc_priv *tc_priv, bool use_max)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(tc_priv->ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	const int bus_id = pdev_priv->pdev->bus->number;
	const u32 data_len = use_max ? 64 : 128;
	const u32 nb_cache = use_max ? 2000 : 1000;

	hados_doe_set_table_cache_entry_limit(bus_id, DOE_TABLE_NORMAL_ARRAY, data_len);
	if (nb_cache != hados_doe_get_table_cache_entry_limit(bus_id, DOE_TABLE_NORMAL_ARRAY))
		return -EINVAL;

	return 0;
}

static int ys_tc_set_doe_hash_cache(struct ys_tc_priv *tc_priv, bool use_max)
{
	struct ys_ndev_priv *ndev_priv = netdev_priv(tc_priv->ndev);
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	const int bus_id = pdev_priv->pdev->bus->number;
	const u32 data_len = use_max ? 64 : 128;
	const u32 nb_cache = use_max ? 2000 : 1000;

	hados_doe_set_table_cache_entry_limit(bus_id, DOE_TABLE_BIG_HASH, data_len);
	if (nb_cache != hados_doe_get_table_cache_entry_limit(bus_id, DOE_TABLE_BIG_HASH))
		return -EINVAL;

	return 0;
}

static int ys_tc_switchdev_init(struct ys_tc_priv *tc_priv,
				int switchdev_id,
				const struct ys_doe_ops *doe_ops)
{
	int ret = 0;
	struct ys_tc_switchdev *switchdev = NULL;
	char work_q_name[32] = {0};
	int i = 0;

	mutex_lock(&ys_tc_switchdev_lock);
	switchdev = idr_find(&ys_tc_switchdev_idr, switchdev_id);
	if (switchdev) {
		tc_priv->switchdev = switchdev;
		if (refcount_inc_not_zero(&switchdev->refcnt))
			goto out;
		else
			ret = -EINVAL;
		goto fail;
	}

	ret = ys_tc_set_doe_array_cache(tc_priv, ys_tc_doe_array_cache_max);
	if (ret) {
		ys_tc_err("Failed to set use array cache max %d for switchdev %d\n",
			  ys_tc_doe_array_cache_max, switchdev_id);
		ret = -EINVAL;
		goto fail;
	}

	ret = ys_tc_set_doe_hash_cache(tc_priv, ys_tc_doe_hash_cache_max);
	if (ret) {
		ys_tc_err("Failed to set use hash cache max %d for switchdev %d\n",
			  ys_tc_doe_hash_cache_max, switchdev_id);
		ret = -EINVAL;
		goto fail;
	}

	switchdev = kzalloc(sizeof(*switchdev), GFP_KERNEL);
	if (!switchdev) {
		ret = -ENOMEM;
		goto fail;
	}

	switchdev->id = switchdev_id;
	ret = idr_alloc(&ys_tc_switchdev_idr, switchdev, switchdev_id,
			switchdev_id + 1, GFP_ATOMIC);
	if (ret != switchdev_id) {
		ys_tc_err("failed to allocate switchdev id %d\n",
			  switchdev_id);
		ret = -EINVAL;
		goto fail_with_alloc;
	}

	snprintf(work_q_name, sizeof(work_q_name), "ys_tc_sw_work_%d", switchdev_id);
	switchdev->wq = create_singlethread_workqueue(work_q_name);
	if (!switchdev->wq) {
		ret = -ENOMEM;
		goto fail_with_idr;
	}
	switchdev->doe_ops = doe_ops;

	INIT_LIST_HEAD(&switchdev->priv_head);
	mutex_init(&switchdev->priv_mlock);

	refcount_set(&switchdev->refcnt, 1);
	tc_priv->switchdev = switchdev;
	ys_tc_metrcs_init(switchdev);
	atomic_set(&switchdev->priority_flow_nb, 0);
	switchdev->array_tbl_value_len_max = ys_tc_doe_array_cache_max ? 64 : 128;
	switchdev->hash_tbl_key_len_max = ys_tc_doe_hash_cache_max ? 64 : 128;
	switchdev->hash_tbl_value_len_max = ys_tc_doe_hash_cache_max ? 64 : 128;
	switchdev->hash_tbl_cache_high = ys_tc_doe_hash_cache_max;

	for (i = 0; i < YS_TC_DOE_CHANNEL_NUM; i++) {
		switchdev->doe_chl_info.location[i] = hados_doe_get_channel_type(switchdev->id, i);
		ys_tc_info("Doe channel %d location type is %d.\n",
			   i, switchdev->doe_chl_info.location[i]);
	}

	ret = ys_tc_debug_init(switchdev->id, true, &switchdev->debugfs_root);
	if (ret) {
		ys_tc_err("failed to init debug, ret %d.\n", ret);
		goto fail_with_wq;
	}

	// Create qset debugfs
	debugfs_create_file("qset", 0400, switchdev->debugfs_root, switchdev,
			    &ys_tc_debug_qset_fops);

	ret = ys_tc_table_init(tc_priv);
	if (ret) {
		ys_tc_err("failed to init table\n");
		goto fail_with_fs;
	}

	ret = ys_tc_meter_init(tc_priv);
	if (ret) {
		ys_tc_err("failed to init meter\n");
		goto fail_with_table;
	}
	ret = ys_tc_multicast_init(tc_priv);
	if (ret) {
		ys_tc_err("failed to init multicast\n");
		goto fail_with_meter;
	}

out:
	mutex_unlock(&ys_tc_switchdev_lock);
	return 0;

fail_with_meter:
	ys_tc_meter_exit(tc_priv);
fail_with_table:
	ys_tc_table_exit(tc_priv);
fail_with_fs:
	ys_tc_debug_exit(switchdev->debugfs_root, true);
fail_with_wq:
	destroy_workqueue(switchdev->wq);
fail_with_idr:
	idr_remove(&ys_tc_switchdev_idr, switchdev->id);
fail_with_alloc:
	kfree(switchdev);
fail:
	mutex_unlock(&ys_tc_switchdev_lock);
	tc_priv->switchdev = NULL;
	return ret;
}

static void ys_tc_switchdev_exit(struct ys_tc_priv *tc_priv)
{
	struct ys_tc_switchdev *switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);

	if (!switchdev)
		return;

	mutex_lock(&ys_tc_switchdev_lock);
	if (refcount_dec_and_test(&switchdev->refcnt)) {
		ys_tc_multicast_exit(tc_priv);
		ys_tc_meter_exit(tc_priv);
		ys_tc_table_exit(tc_priv);
		ys_tc_debug_exit(switchdev->debugfs_root, true);

		destroy_workqueue(switchdev->wq);
		switchdev->wq = NULL;
		idr_remove(&ys_tc_switchdev_idr, switchdev->id);
		kfree(switchdev);
	}
	tc_priv->switchdev = NULL;
	mutex_unlock(&ys_tc_switchdev_lock);
}

static bool ys_tc_doe_valid(struct ys_doe_ops *doe_ops)
{
	if (!doe_ops ||
	    !doe_ops->tbl_valid ||
	    !doe_ops->hw_init ||
	    !doe_ops->protect_status ||
	    !doe_ops->set_protect_status ||
	    !doe_ops->create_arraytbl ||
	    !doe_ops->delete_arraytbl ||
	    !doe_ops->create_hashtbl ||
	    !doe_ops->delete_hashtbl ||
	    !doe_ops->array_store ||
	    !doe_ops->array_store_batch ||
	    !doe_ops->array_load ||
	    !doe_ops->array_load_batch ||
	    !doe_ops->counter_enable ||
	    !doe_ops->counter_enable_batch ||
	    !doe_ops->counter_load ||
	    !doe_ops->hash_insert ||
	    !doe_ops->hash_insert_batch ||
	    !doe_ops->hash_query ||
	    !doe_ops->hash_query_batch ||
	    !doe_ops->hash_delete ||
	    !doe_ops->hash_delete_batch ||
	    !doe_ops->meter_store)
		return false;
	return true;
}

int ys_tc_init(struct net_device *ndev, int switchdev_id, __u8 pf_id,
	       __u16 vf_id)
{
	struct ys_tc_priv *tc_priv = NULL;
	struct ys_ndev_priv *ndev_priv = NULL;
	struct ys_pdev_priv *pdev_priv = NULL;
	int ret = 0;
	int peer_qset = 0;
	struct ys_tc_switchdev *switchdev = NULL;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (pdev_priv->dpu_mode != MODE_SMART_NIC && pdev_priv->dpu_mode != MODE_DPU_SOC)
		return 0;

	if (!ys_tc_flow_enable)
		return 0;

	if (!ys_tc_doe_valid(pdev_priv->pdev_manager->doe_ops)) {
		ys_net_err("doe_ops doesn't exist\n");
		return -EOPNOTSUPP;
	}

	peer_qset = ys_k2u_ndev_get_dstqsetid(ndev_priv);
	if (peer_qset < 0 || peer_qset > U16_MAX) {
		ys_net_err("Got unsupported qset %d for tc.\n", peer_qset);
		return -EOPNOTSUPP;
	}

	tc_priv = kzalloc(sizeof(*tc_priv), GFP_KERNEL);
	if (!tc_priv)
		return -ENOMEM;

	tc_priv->ndev = ndev;
	tc_priv->qset = peer_qset;
	tc_priv->is_uplink = ys_k2u_ndev_is_uplink(ndev_priv);

	INIT_LIST_HEAD(&tc_priv->tc_indr_block_list);
	tc_priv->ops = ys_tc_ops;
	rcu_head_init(&tc_priv->rcu);

	ret = ys_tc_switchdev_init(tc_priv, switchdev_id, pdev_priv->pdev_manager->doe_ops);
	if (ret) {
		ys_tc_err("failed to init switchdev\n");
		goto fail;
	}

	ret = ys_tc_flow_init(tc_priv);
	if (ret) {
		ys_tc_err("failed to init flow\n");
		goto fail_switchdev;
	}

	ret = ys_tc_tunnel_cb_init(tc_priv);
	if (ret) {
		ys_tc_err("tc tunnel cb init failed\n");
		goto fail_flow;
	}

	ys_tc_set_priv(ndev, tc_priv);

	tc_priv->is_run = true;
	ndev->features |= NETIF_F_HW_TC;
	ndev->hw_features |= NETIF_F_HW_TC;

	switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);
	mutex_lock(&switchdev->priv_mlock);
	list_add(&tc_priv->switchdev_node, &switchdev->priv_head);
	mutex_unlock(&switchdev->priv_mlock);
	ys_tc_info("%s success\n", __func__);

	return 0;

fail_flow:
	ys_tc_flow_exit(tc_priv);

fail_switchdev:
	ys_tc_switchdev_exit(tc_priv);
	ys_tc_err("%s failed\n", __func__);

fail:
	kfree(tc_priv);
	return ret;
}

void ys_tc_exit(struct net_device *ndev)
{
	struct ys_tc_priv *tc_priv = ys_tc_get_priv(ndev);
	struct ys_tc_switchdev *switchdev = NULL;

	if (!tc_priv)
		return;

	switchdev = (struct ys_tc_switchdev *)(tc_priv->switchdev);
	mutex_lock(&switchdev->priv_mlock);
	list_del(&tc_priv->switchdev_node);
	mutex_unlock(&switchdev->priv_mlock);

	tc_priv->is_run = false;

	ys_tc_tunnel_cb_exit(tc_priv);
	ys_tc_flow_exit(tc_priv);
	ys_tc_switchdev_exit(tc_priv);

	ys_tc_set_priv(ndev, NULL);

	ys_tc_info("%s success\n", __func__);

	kfree_rcu(tc_priv, rcu);
}

module_param_named(doe_array_cache_max, ys_tc_doe_array_cache_max, bool, 0444);
MODULE_PARM_DESC(flow_en, "doe_array_cache_max: true or false. Default = false");

module_param_named(doe_hash_cache_max, ys_tc_doe_hash_cache_max, bool, 0444);
MODULE_PARM_DESC(flow_en, "doe_hash_cache_max: true or false. Default = false");
