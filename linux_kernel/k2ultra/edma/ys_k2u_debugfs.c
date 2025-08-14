// SPDX-License-Identifier: GPL-2.0

#include "../../platform/ys_debugfs.h"
#include "ys_k2u_debugfs.h"

int ys_k2u_debugfs_init(struct ys_pdev_priv *pdev_priv, struct dentry **root)
{
	char name[128];
	struct pci_dev *pdev = pdev_priv->pdev;

	sprintf(name, "k2u_%04x:%02x:%02x.%d",
		pci_domain_nr(pdev->bus),
		pdev->bus->number,
		PCI_SLOT(pdev->devfn),
		PCI_FUNC(pdev->devfn));
	*root = debugfs_create_dir(name, ys_debugfs_root);
	if (IS_ERR(*root)) {
		ys_dev_err("Failed to create debugfs root directory");
		*root = NULL;
	}

	return 0;
}

void ys_k2u_debugfs_exit(struct dentry *root)
{
	debugfs_remove_recursive(root);
}
