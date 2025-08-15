// SPDX-License-Identifier: GPL-2.0

#include "ys_debug.h"
#include "ys_ndev.h"
#include "ys_pdev.h"
#include "ysnic.h"

int ys_debug_init(struct pci_dev *pdev)
{
	int ret = 0;
	struct ys_pdev_priv *pdev_priv;

	if (pdev->is_virtfn)
		return 0;

	pdev_priv = pci_get_drvdata(pdev);

	pdev_priv->diagnose.gen = 0;
	pdev_priv->diagnose.cursor = 0;
	pdev_priv->diagnose.cfg_data = vmalloc_user(sizeof(struct ys_debug_cfg));
	pdev_priv->diagnose.runtime_data = vmalloc_user(sizeof(struct ys_debug_unit) *
							YS_DEBUG_BUFFER_LEN);
	memset(pdev_priv->diagnose.runtime_data, 0xff, sizeof(struct ys_debug_unit) *
						       YS_DEBUG_BUFFER_LEN);
	if (!pdev_priv->diagnose.runtime_data || !pdev_priv->diagnose.cfg_data) {
		ys_debug_uninit(pdev);
		ret = -1;
	}
	spin_lock_init(&pdev_priv->diagnose.lock);

	return ret;
}

u8 ys_debug_get_unit(struct net_device *ndev, char **data)
{
	struct ys_ndev_priv *ndev_priv;
	struct ys_pdev_priv *pdev_priv;
	struct pci_dev *pdev;
	struct ys_debug_unit *unit;
	unsigned long flags;
	u8 ret = 0;

	ndev_priv = netdev_priv(ndev);
	pdev = ndev_priv->pdev;
	pdev_priv = pci_get_drvdata(ndev_priv->pdev);
	if (unlikely(ndev_priv->debug == YS_DEBUG_OFF)) {
		*data = NULL;
		return 0;
	}

	if (pdev->is_virtfn) {
		pdev = pdev->physfn;
		ys_net_debug("vf pdev:%p", pdev);
		pdev_priv = pci_get_drvdata(pdev);
	}

	unit = (struct ys_debug_unit *)pdev_priv->diagnose.runtime_data;
	spin_lock_irqsave(&pdev_priv->diagnose.lock, flags);
	*data = unit[pdev_priv->diagnose.cursor].payload;
	unit[pdev_priv->diagnose.cursor].mt.ifindex = ndev->ifindex;
	pdev_priv->diagnose.cursor += 1;
	ret = pdev_priv->diagnose.gen;
	if (pdev_priv->diagnose.cursor == YS_DEBUG_BUFFER_LEN) {
		pdev_priv->diagnose.gen += 1;
		pdev_priv->diagnose.cursor = 0;
	}
	ys_net_debug("debug get gen:%d, cursor:%d", pdev_priv->diagnose.gen,
		     pdev_priv->diagnose.cursor);
	spin_unlock_irqrestore(&pdev_priv->diagnose.lock, flags);
	return ret;
}

void ys_debug_back_unit(char *data, u8 gen)
{
	struct ys_debug_unit *unit = container_of((void *)data, struct ys_debug_unit, payload);
	/* Ensure that the data in the payload has been written */
	wmb();
	unit->mt.gen = gen;
	ys_debug("debug back gen:%d", gen);
}

void ys_debug_uninit(struct pci_dev *pdev)
{
	struct ys_pdev_priv *pdev_priv;

	if (pdev->is_virtfn)
		return;

	pdev_priv = pci_get_drvdata(pdev);
	if (pdev_priv->diagnose.cfg_data) {
		vfree(pdev_priv->diagnose.cfg_data);
		pdev_priv->diagnose.cfg_data = NULL;
	}
	if (pdev_priv->diagnose.runtime_data) {
		vfree(pdev_priv->diagnose.runtime_data);
		pdev_priv->diagnose.runtime_data = NULL;
	}
}
