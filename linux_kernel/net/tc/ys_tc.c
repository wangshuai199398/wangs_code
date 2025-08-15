// SPDX-License-Identifier: GPL-2.0

#include "ys_tc.h"
#include "../../platform/ys_debugfs.h"


bool ys_tc_flow_enable;

struct ys_tc_indr_block_priv {
	struct net_device *tunnel_ndev;
	struct ys_tc_priv *tc_priv;
	struct list_head node;
};

static int ys_tc_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
				   void *cb_priv)
{
	struct ys_tc_priv *tc_priv = cb_priv;
	struct flow_cls_offload *cls_flower = type_data;

	if (!tc_priv->is_run || !tc_priv->switchdev)
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		if (!IS_ERR_OR_NULL(tc_priv->ops.setup_tc_cls_flower))
			return tc_priv->ops.setup_tc_cls_flower(tc_priv, cls_flower);
		else
			return -EOPNOTSUPP;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static LIST_HEAD(ys_tc_block_list);
int ys_tc_setup_tc(struct net_device *ndev, enum tc_setup_type type,
		   void *type_data)
{
	struct ys_tc_priv *tc_priv;
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;

	ndev_priv = netdev_priv(ndev);
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);

	if (pdev_priv->dpu_mode != MODE_SMART_NIC && pdev_priv->dpu_mode != MODE_DPU_SOC)
		return 0;

	if (!ys_tc_flow_enable)
		return 0;

	tc_priv = ys_tc_get_priv(ndev);
	if (!tc_priv || !tc_priv->switchdev)
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_BLOCK:
		return flow_block_cb_setup_simple(type_data, &ys_tc_block_list,
						  ys_tc_setup_tc_block_cb,
						  tc_priv, tc_priv, true);
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static struct ys_tc_indr_block_priv *
ys_tc_indr_block_priv_lookup(struct ys_tc_priv *tc_priv,
			     struct net_device *ndev)
{
	struct ys_tc_indr_block_priv *indr_priv;

	list_for_each_entry(indr_priv, &tc_priv->tc_indr_block_list, node)
		if (indr_priv->tunnel_ndev == ndev)
			return indr_priv;

	return NULL;
}

static void ys_tc_indr_block_release(void *cb_priv)
{
	struct ys_tc_indr_block_priv *indr_priv = cb_priv;

	list_del(&indr_priv->node);
	kfree(indr_priv);
}

static int ys_tc_setup_indr_block_cb(enum tc_setup_type type, void *type_data,
				     void *cb_priv)
{
	struct ys_tc_indr_block_priv *indr_priv = cb_priv;
	struct flow_cls_offload *cls_flower = type_data;

	if (cls_flower->common.chain_index || !indr_priv->tc_priv->is_run)
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		if (!IS_ERR_OR_NULL(indr_priv->tc_priv->ops.setup_tc_cls_flower))
			return indr_priv->tc_priv->ops.setup_tc_cls_flower(indr_priv->tc_priv,
									   cls_flower);
		else
			return -EOPNOTSUPP;
	default:
		return -EOPNOTSUPP;
	}
}

static LIST_HEAD(ys_tc_indr_block_list);

static int
ys_tc_indr_setup_block(struct net_device *ndev, struct Qdisc *sch,
		       struct ys_tc_priv *tc_priv, struct flow_block_offload *f,
		       flow_setup_cb_t *setup_cb, void *data,
		       void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct ys_tc_indr_block_priv *indr_priv;
	struct flow_block_cb *block_cb;

	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	if (!ys_tc_is_netdev_to_offload(ndev))
		return -EOPNOTSUPP;

	f->unlocked_driver_cb = true;
	f->driver_block_list = &ys_tc_indr_block_list;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		indr_priv = ys_tc_indr_block_priv_lookup(tc_priv, ndev);
		if (indr_priv)
			return -EEXIST;

		indr_priv = kmalloc(sizeof(*indr_priv), GFP_KERNEL);
		if (!indr_priv)
			return -ENOMEM;

		indr_priv->tunnel_ndev = ndev;
		indr_priv->tc_priv = tc_priv;
		list_add(&indr_priv->node, &tc_priv->tc_indr_block_list);
		block_cb = flow_indr_block_cb_alloc(setup_cb, indr_priv,
						    indr_priv,
						    ys_tc_indr_block_release, f,
						    ndev, sch, data, tc_priv,
						    cleanup);
		if (IS_ERR(block_cb)) {
			list_del(&indr_priv->node);
			kfree(indr_priv);
			return PTR_ERR(block_cb);
		}
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &ys_tc_indr_block_list);
		return 0;
	case FLOW_BLOCK_UNBIND:
		indr_priv = ys_tc_indr_block_priv_lookup(tc_priv, ndev);
		if (!indr_priv)
			return -ENOENT;

		block_cb = flow_block_cb_lookup(f->block, setup_cb, indr_priv);
		if (!block_cb)
			return -ENOENT;
		flow_indr_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int
ys_tc_indr_setup_nodev(struct ys_tc_priv *tc_priv, enum tc_setup_type type, void *data)
{
	if (!data)
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_ACT:
		if (!IS_ERR_OR_NULL(tc_priv->ops.setup_tc_act))
			return tc_priv->ops.setup_tc_act(tc_priv, data);
		else
			return -EOPNOTSUPP;
	default:
		return -EOPNOTSUPP;
	}
}

static int
ys_tc_indr_block_bind_cb(struct net_device *ndev, struct Qdisc *sch,
			 void *cb_priv, enum tc_setup_type type,
			 void *type_data, void *data,
			 void (*cleanup)(struct flow_block_cb *block_cb))
{
	if (!ndev)
		return ys_tc_indr_setup_nodev(cb_priv, type, data);

	switch (type) {
	case TC_SETUP_BLOCK:
		return ys_tc_indr_setup_block(ndev, sch, cb_priv, type_data,
					      ys_tc_setup_indr_block_cb, data,
					      cleanup);
	default:
		return -EOPNOTSUPP;
	}
}

static int ys_tc_switchdev_event(struct notifier_block *nb, unsigned long event,
				 void *data)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(data);

	if (!netif_is_vxlan(ndev) && !netif_is_geneve(ndev))
		return NOTIFY_DONE;

	/* reserve */
	switch (event) {
	case NETDEV_CHANGENAME:
		break;
	case NETDEV_UNREGISTER:
		break;
	case NETDEV_REGISTER:
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

int ys_tc_tunnel_cb_init(struct ys_tc_priv *tc_priv)
{
	int ret;

	if (!tc_priv->is_uplink)
		return 0;

	tc_priv->tun_nb.notifier_call = ys_tc_switchdev_event;
	ret = register_netdevice_notifier_dev_net(tc_priv->ndev, &tc_priv->tun_nb,
						  &tc_priv->tun_nn);
	if (ret)
		return ret;

	return flow_indr_dev_register(ys_tc_indr_block_bind_cb, tc_priv);
}

void ys_tc_tunnel_cb_exit(struct ys_tc_priv *tc_priv)
{
	if (!tc_priv->is_uplink)
		return;

	unregister_netdevice_notifier_dev_net(tc_priv->ndev, &tc_priv->tun_nb,
					      &tc_priv->tun_nn);
	flow_indr_dev_unregister(ys_tc_indr_block_bind_cb, tc_priv,
				 ys_tc_indr_block_release);
}

int ys_tc_debug_init(int switchdev_id, bool first, struct dentry **debugfs_root)
{
	char name[32];

	if (first) {
		snprintf(name, sizeof(name), "ys_tc_%d", switchdev_id);
		*debugfs_root = debugfs_create_dir(name, ys_debugfs_root);
		if (IS_ERR(*debugfs_root)) {
			*debugfs_root = NULL;
			return -EINVAL;
		} else if (!(*debugfs_root)) {
			return -EEXIST;
		}
	}
	return 0;
}

void ys_tc_debug_exit(struct dentry *debugfs_root, bool last)
{
	if (last)
		debugfs_remove_recursive(debugfs_root);
}


module_param_named(flow_en, ys_tc_flow_enable, bool, 0644);
MODULE_PARM_DESC(flow_en, "flow_en: true or false. Default = false");
