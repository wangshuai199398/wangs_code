// SPDX-License-Identifier: GPL-2.0
#include <linux/rcupdate.h>

#include "ys_intr.h"
#include "ys_ndev.h"

#include "ys_debug.h"
#include "../k2ultra/edma/ys_k2u_new_hw.h"

static int ys_irq_get_max_required_vectors(struct ys_pdev_priv *pdev_priv)
{
	const struct ys_pdev_hw *nic_type = pdev_priv->nic_type;
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	int ret = 0;
	int irq_sum = nic_type->irq_sum;
#ifdef CONFIG_YSHW_K2ULTRA
	u32 val;

	if (nic_type->is_vf) {
		val = ys_rd32(pdev_priv->bar_addr[0], YS_K2U_RP_PFVFID);
		val = ys_rd32(pdev_priv->bar_addr[0],
			      YS_K2U_RP_VFX_IRQNUM(FIELD_GET(YS_K2U_RP_VFID_GMASK, val)));
		irq_sum = FIELD_GET(YS_K2U_RP_VFX_IRQNUM_GMASK, val);
		irq_sum = min(irq_sum, nic_type->irq_sum);
	}
#endif /* CONFIG_YSHW_K2ULTRA */

	/* If the NIC supports MSIX, the maximum MSIX IRQ count should
	 * be checked. If the NIC supports MSI, the maximum MSI IRQ
	 * count should be checked. If both MSIX and MSI are disabled,
	 * an error should be reported.
	 */
	if (nic_type->irq_flag | PCI_IRQ_MSIX)
		ret = pci_msix_vec_count(pdev_priv->pdev);

	if (ret <= 0 && (nic_type->irq_flag | PCI_IRQ_MSI))
		ret = pci_msi_vec_count(pdev_priv->pdev);

	if (irq_sum > 0)
		ret = min(ret, irq_sum);

	if (ret > 0)
		irq_table->max = ret;

	if (irq_table->user_max > 0)
		irq_table->max = min(irq_table->max, irq_table->user_max);

	return ret;
}

static int ys_irq_alloc_vectors(struct ys_pdev_priv *pdev_priv)
{
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	int ret;

	ret = ys_irq_get_max_required_vectors(pdev_priv);
	if (ret <= 0) {
		ys_dev_err("Get MSI or MSI-X max irq count error: %d", ret);
		return ret;
	}

	ret = pci_alloc_irq_vectors(pdev_priv->pdev, 1, irq_table->max,
				    pdev_priv->nic_type->irq_flag);
	if (ret <= 0) {
		ys_dev_err("Failed to allocate irqs");
		irq_table->max = 0;
		return ret;
	} else if (ret < irq_table->max) {
		irq_table->max = ret;
	}

	return ret;
}

static irqreturn_t ys_irq_notifier_handler(int irqn, void *data)
{
	struct ys_irq *irq = data;

	atomic_notifier_call_chain(&irq->nh, 0, NULL);

	return IRQ_HANDLED;
}

static int ys_irq_free(struct ys_pdev_priv *pdev_priv, int index)
{
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq *irq;

	if (index >= irq_table->max)
		return -EINVAL;

	mutex_lock(&irq_table->lock);

	irq = &irq_table->irqs[index];
	if (irq->state != YS_IRQ_STATE_REGISTERED) {
		mutex_unlock(&irq_table->lock);
		return 0;
	}

	if (irq->sub.bh_type == YS_IRQ_BH_NOTIFIER &&
	    rcu_access_pointer(irq->nh.head)) {
		ys_debug("Irq%d bh notifier isnot empty", index);
		mutex_unlock(&irq_table->lock);
		return -EINVAL;
	} else if (irq->sub.bh_type == YS_IRQ_BH_TASKLET) {
		tasklet_kill(&irq->tasklet);
	}
	free_irq(irq->irqn, irq);

	ys_debug("Free irq %d vector %d with name %s", index,
		 irq->irqn, pdev_priv->nic_type->func_name);

	irq->state = YS_IRQ_STATE_UNREGISTERED;
	memset(&irq->sub, 0, sizeof(struct ys_irq_sub));
	irq_table->used--;

	mutex_unlock(&irq_table->lock);

	return 0;
}

static int ys_irq_request(struct ys_pdev_priv *pdev_priv, int index,
			  struct ys_irq_sub *sub)
{
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq *irq;
	int ret;

	if (index < 0 || index >= irq_table->max)
		return -EINVAL;

	if (IS_ERR_OR_NULL(sub))
		return -EINVAL;

	if (sub->irq_type < YS_IRQ_TYPE_QUEUE ||
	    sub->irq_type >= YS_IRQ_TYPE_HW_MAX) {
		ys_dev_err("Invalid sub irq type: %d", sub->irq_type);
		return -EINVAL;
	}

	if (sub->bh_type != YS_IRQ_BH_NOTIFIER &&
	    IS_ERR_OR_NULL(sub->handler)) {
		ys_dev_err("Missing irq handler");
		return -EINVAL;
	}

	mutex_lock(&irq_table->lock);

	irq = &irq_table->irqs[index];
	if (irq->state != YS_IRQ_STATE_UNREGISTERED) {
		mutex_unlock(&irq_table->lock);
		ys_dev_err("Irq %d(%d) has already been registered",
			   index, irq->state);
		return -EINVAL;
	}

	irq->sub = *sub;
	if (irq->sub.bh_type == YS_IRQ_BH_WORK) {
		if (IS_ERR_OR_NULL(irq->sub.bh.work_handler)) {
			memset(&irq->sub, 0, sizeof(struct ys_irq_sub));
			mutex_unlock(&irq_table->lock);
			ys_dev_err("Irq %d(%d) misubssing work_handler",
				   index, irq->sub.bh_type);
			return -EINVAL;
		}
		INIT_WORK(&irq->work, irq->sub.bh.work_handler);
	} else if (irq->sub.bh_type == YS_IRQ_BH_NOTIFIER) {
		irq->sub.handler = ys_irq_notifier_handler;
		ret = atomic_notifier_chain_register(&irq->nh, sub->bh.nb);
		if (ret < 0) {
			memset(&irq->sub, 0, sizeof(struct ys_irq_sub));
			mutex_unlock(&irq_table->lock);
			ys_dev_err("Irq %d(%d) nb register failed",
				   index, irq->sub.bh_type);
			return -EINVAL;
		}
		irq->refcnt = 1;
	} else if (irq->sub.bh_type == YS_IRQ_BH_TASKLET) {
		if (IS_ERR_OR_NULL(irq->sub.bh.tasklet_handler)) {
			memset(&irq->sub, 0, sizeof(struct ys_irq_sub));
			mutex_unlock(&irq_table->lock);
			ys_dev_err("Irq %d(%d) missing tasklet_handler",
				   index, irq->sub.bh_type);
			return -EINVAL;
		}
		tasklet_init(&irq->tasklet, irq->sub.bh.tasklet_handler,
			     (unsigned long)irq);
	}

	if (irq->sub.devname) {
		ret = request_irq(irq->irqn, irq->sub.handler, 0,
				  irq->sub.devname, irq);
	} else {
		irq->sub.devname = kcalloc(YS_MAX_IRQ_NAME,
					   sizeof(char), GFP_KERNEL);
		snprintf(irq->sub.devname, YS_MAX_IRQ_NAME,
			 "%s[%d](%s)",
			 pdev_priv->nic_type->func_name, index,
			 pci_name(pdev_priv->pdev));
		ret = request_irq(irq->irqn, irq->sub.handler, 0,
				  irq->sub.devname, irq);
	}

	if (ret < 0) {
		if (irq->sub.bh_type == YS_IRQ_BH_NOTIFIER) {
			atomic_notifier_chain_unregister(&irq->nh, sub->bh.nb);
			irq->refcnt = 0;
		} else if (irq->sub.bh_type == YS_IRQ_BH_TASKLET) {
			tasklet_kill(&irq->tasklet);
		}
		memset(&irq->sub, 0, sizeof(struct ys_irq_sub));
		mutex_unlock(&irq_table->lock);
		ys_dev_err("Failed to request irq index %d virq %d", index,
			   irq->irqn);
		return ret;
	}

	irq->state = YS_IRQ_STATE_REGISTERED;
	irq_table->used++;

	mutex_unlock(&irq_table->lock);

	ys_debug("Request irq %d vector %d", index, irq->irqn);

	return 0;
}

static int ys_irq_add_notifier(struct ys_pdev_priv *pdev_priv, int index,
			       struct ys_irq_sub *sub)
{
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq *irq;
	int ret;

	if (index < 0 || index >= irq_table->max)
		return -EINVAL;

	if (IS_ERR_OR_NULL(sub))
		return -EINVAL;

	if (sub->bh_type != YS_IRQ_BH_NOTIFIER &&
	    !sub->bh.nb)
		return -EINVAL;

	mutex_lock(&irq_table->lock);

	irq = &irq_table->irqs[index];
	if (irq->state != YS_IRQ_STATE_REGISTERED ||
	    irq->sub.bh_type != YS_IRQ_BH_NOTIFIER ||
	    irq->sub.irq_type != sub->irq_type) {
		mutex_unlock(&irq_table->lock);
		return -EINVAL;
	}

	ret = atomic_notifier_chain_register(&irq->nh, sub->bh.nb);
	if (ret < 0) {
		mutex_unlock(&irq_table->lock);
		return -EINVAL;
	}
	irq->refcnt++;

	mutex_unlock(&irq_table->lock);

	return 0;
}

static int ys_irq_del_notifier(struct ys_pdev_priv *pdev_priv, int index,
			       struct ys_irq_sub *sub)
{
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq *irq;

	if (index < 0 || index >= irq_table->max)
		return -EINVAL;

	if (IS_ERR_OR_NULL(sub))
		return -EINVAL;

	if (!sub->bh.nb)
		return -EINVAL;

	mutex_lock(&irq_table->lock);

	irq = &irq_table->irqs[index];
	if (atomic_notifier_chain_unregister(&irq->nh, sub->bh.nb) < 0) {
		mutex_unlock(&irq_table->lock);
		ys_dev_err("Irq%d bh notifier unregister error", index);
		return -EINVAL;
	}
	irq->refcnt--;

	mutex_unlock(&irq_table->lock);

	return 0;
}

static int ys_irq_find_free_vector(struct ys_irq_table *irq_table)
{
	struct ys_irq *irq;
	int idle = -1;
	int i;

	for (i = 0; i < irq_table->max; i++) {
		irq = &irq_table->irqs[i];
		if (irq->state == YS_IRQ_STATE_UNREGISTERED) {
			idle = i;
			break;
		}
	}

	return idle;
}

static int ys_irq_find_bh_notifier_vector(struct ys_irq_table *irq_table,
					  struct ys_irq_sub *sub)
{
	int min_refcnt = INT_MAX;
	struct ys_irq *irq;
	int match = -1;
	int i;

	if (IS_ERR_OR_NULL(sub))
		return -EINVAL;

	if (sub->bh_type != YS_IRQ_BH_NOTIFIER)
		return -EINVAL;

	for (i = 0; i < irq_table->max; i++) {
		irq = &irq_table->irqs[i];
		if (irq->state != YS_IRQ_STATE_REGISTERED ||
		    irq->sub.bh_type != YS_IRQ_BH_NOTIFIER ||
		    irq->sub.irq_type != sub->irq_type)
			continue;

		if (sub->irq_type == YS_IRQ_TYPE_MISC) {
			match = i;
			break;
		}

		if (irq->refcnt > 0 && irq->refcnt < min_refcnt) {
			min_refcnt = irq->refcnt;
			match = i;
		}
	}

	return match;
}

static int ys_irq_check_misc_irq_registered(struct ys_irq_table *irq_table)
{
	struct ys_irq *irq;
	int ret = -1;
	int i;

	for (i = 0; i < irq_table->max; i++) {
		irq = &irq_table->irqs[i];
		if (irq->state == YS_IRQ_STATE_REGISTERED &&
		    irq->sub.irq_type == YS_IRQ_TYPE_MISC) {
			ret = 0;
			break;
		}
	}

	return ret;
}

static int ys_irq_register_fixed(struct ys_irq_nb *irq_nb)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(irq_nb->pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq_sub *sub = &irq_nb->sub;
	int index = irq_nb->index;
	int ret;

	if (sub->irq_type == YS_IRQ_TYPE_MISC) {
		if (sub->bh_type != YS_IRQ_BH_NOTIFIER) {
			ys_dev_err("Misc irq has wrong bh type.");
			return -EINVAL;
		}
		ret = ys_irq_check_misc_irq_registered(irq_table);
		if (ret == 0) {
			/* misc irq already registered */
			index = ys_irq_find_bh_notifier_vector(irq_table, sub);
			if (index != irq_nb->index)
				return -EINVAL;

			return ys_irq_add_notifier(pdev_priv, index, sub);
		}
	}

	ret = ys_irq_request(pdev_priv, index, sub);
	if (ret == 0)
		return ret;

	/* If the registration process is failed, try to add into the
	 * registered YS_IRQ_BH_NOTIFIER irq.
	 */
	if (sub->bh_type == YS_IRQ_BH_NOTIFIER)
		ret = ys_irq_add_notifier(pdev_priv, index, sub);

	return ret;
}

static int ys_irq_register_any(struct ys_irq_nb *irq_nb)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(irq_nb->pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq_sub *sub = &irq_nb->sub;
	int index = -1;
	int ret;

	if (sub->irq_type == YS_IRQ_TYPE_MISC) {
		if (sub->bh_type != YS_IRQ_BH_NOTIFIER) {
			ys_dev_err("Misc irq has wrong bh type.");
			return -EINVAL;
		}
		ret = ys_irq_check_misc_irq_registered(irq_table);
		if (ret)
			index = ys_irq_find_free_vector(irq_table);
	} else {
		index = ys_irq_find_free_vector(irq_table);
	}

	if (index >= 0) {
		ret = ys_irq_request(pdev_priv, index, sub);
		if (ret == 0)
			return index;
	}

	if (sub->bh_type != YS_IRQ_BH_NOTIFIER)
		return -EINVAL;

	index = ys_irq_find_bh_notifier_vector(irq_table, sub);
	if (index >= 0) {
		ret = ys_irq_add_notifier(pdev_priv, index, sub);
		if (ret == 0)
			return index;
	}

	return -EINVAL;
}

static int ys_irq_unregister_fixed(struct ys_irq_nb *irq_nb)
{
	struct ys_pdev_priv *pdev_priv;
	struct ys_irq_table *irq_table;
	struct ys_irq_sub *sub;
	struct ys_irq *irq;
	int index;
	int ret;

	if (IS_ERR_OR_NULL(irq_nb))
		return -EINVAL;

	pdev_priv = pci_get_drvdata(irq_nb->pdev);
	irq_table = &pdev_priv->irq_table;
	index = irq_nb->index;
	sub = &irq_nb->sub;

	irq = &irq_table->irqs[index];
	if (irq->sub.bh_type != YS_IRQ_BH_NOTIFIER ||
	    !sub->bh.nb)
		return ys_irq_free(pdev_priv, index);

	ret = ys_irq_del_notifier(pdev_priv, index, sub);
	if (ret)
		return ret;

	if (irq->refcnt == 0)
		return ys_irq_free(pdev_priv, index);

	return 0;
}

static int ys_irq_change_notify(struct notifier_block *nb, unsigned long mode,
				void *data)
{
	struct ys_irq_nb *irq_nb = (struct ys_irq_nb *)data;
	int ret;

	switch (mode) {
	case YS_IRQ_NB_REGISTER_FIXED:
		ret = ys_irq_register_fixed(irq_nb);
		break;
	case YS_IRQ_NB_REGISTER_ANY:
		ret = ys_irq_register_any(irq_nb);
		break;
	case YS_IRQ_NB_UNREGISTER:
		ret = ys_irq_unregister_fixed(irq_nb);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static struct notifier_block irqs_change_nb = {
	.notifier_call = ys_irq_change_notify,
};

int ys_irq_register_ndev_irqs(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq_sub sub;
	int init_count = 0;
	int ret;
	int i;

	if (!IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_irq_pre_init))
		pdev_priv->ops->hw_adp_irq_pre_init(pdev_priv->pdev);

	if (IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_get_init_irq_sub))
		return 0;

	for (i = 0; i < irq_table->max; i++) {
		memset(&sub, 0, sizeof(sub));
		ret = pdev_priv->ops->hw_adp_get_init_irq_sub(pdev_priv->pdev,
							      i, &sub);
		if (ret == 0) {
			init_count++;
			ret = YS_REGISTER_IRQ(&irq_table->nh, YS_IRQ_NB_REGISTER_FIXED,
					      i, pdev_priv->pdev, sub);
			if (ret < 0) {
				ys_dev_err("Setup irq %d error: %d", i, ret);
				return ret;
			}
		}
	}

	ys_debug("init irq count %d", init_count);

	return 0;
}

int ys_irq_unregister_ndev_irqs(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq_sub sub;
	int ret;
	int i;

	if (IS_ERR_OR_NULL(pdev_priv->ops->hw_adp_get_init_irq_sub))
		return 0;

	for (i = 0; i < irq_table->max; i++) {
		memset(&sub, 0, sizeof(sub));
		ret = pdev_priv->ops->hw_adp_get_init_irq_sub(pdev_priv->pdev,
							      i, &sub);
		if (ret == 0)
			YS_UNREGISTER_IRQ(&irq_table->nh, i,
					  pdev_priv->pdev, NULL);
	}

	return 0;
}

int ys_irq_init(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	struct ys_irq *irq;
	int ret;
	int i;

	mutex_init(&irq_table->lock);
	BLOCKING_INIT_NOTIFIER_HEAD(&irq_table->nh);

	ret = ys_irq_alloc_vectors(pdev_priv);
	if (ret <= 0) {
		ys_dev_err("Alloc irq vectors error: %d", ret);
		goto irq_fail;
	}

	ys_dev_info("Alloc irq vectors count: %d, hw MSI-X Table Size: %d",
		    irq_table->max, pci_msix_vec_count(pdev));

	irq_table->irqs = kcalloc(irq_table->max, sizeof(*irq), GFP_KERNEL);
	if (!irq_table->irqs) {
		ret = -ENOMEM;
		ys_dev_err("Alloc irqs error");
		goto irq_fail;
	}

	for (i = 0; i < irq_table->max; i++) {
		irq = &irq_table->irqs[i];
		irq->state = YS_IRQ_STATE_UNREGISTERED;
		irq->index = i;
		irq->irqn = pci_irq_vector(pdev_priv->pdev, i);
		irq->pdev = pdev_priv->pdev;
		ATOMIC_INIT_NOTIFIER_HEAD(&irq->nh);
		bitmap_zero(irq->bh_data, YS_MAX_IRQ);
	}

	ret = blocking_notifier_chain_register(&irq_table->nh, &irqs_change_nb);
	if (ret < 0)
		goto irq_fail;

	return 0;
irq_fail:
	return ret;
}

void ys_irq_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv = pci_get_drvdata(pdev);
	struct ys_irq_table *irq_table = &pdev_priv->irq_table;
	int i;

	if (!IS_ERR_OR_NULL(irq_table->irqs)) {
		blocking_notifier_chain_unregister(&irq_table->nh,
						   &irqs_change_nb);
		for (i = 0; i < irq_table->max; i++)
			ys_irq_free(pdev_priv, i);
		kfree(irq_table->irqs);
		pdev_priv->irq_table.irqs = NULL;
	}

	if (irq_table->max > 0) {
		pci_free_irq_vectors(pdev);
		irq_table->max = 0;
		irq_table->used = 0;
	}

	mutex_destroy(&irq_table->lock);
}
