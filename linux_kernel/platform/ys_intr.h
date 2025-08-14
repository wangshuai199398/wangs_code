/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_INTR_H_
#define __YS_INTR_H_

#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/mutex.h>

#include "ys_irq.h"
#include "ys_mbox.h"

#define YS_MAX_IRQ_NAME	(50)
#define YS_MAX_IRQ 2048

struct ys_irq {
	int state;
	int index;
	int irqn;
	struct pci_dev *pdev;
	/* for work irq */
	struct work_struct work;
	/* for notifier irq */
	struct atomic_notifier_head nh;
	int refcnt;
	/* for tasklet irq */
	struct tasklet_struct tasklet;
	/* variable irq information */
	struct ys_irq_sub sub;
	unsigned long bh_data[BITS_TO_LONGS(MBOX_MAX_CHANNAL)];
};

struct ys_irq_table {
	struct ys_irq *irqs;
	int user_max;
	int max;
	int used;
	/* lock */
	struct mutex lock;
	struct blocking_notifier_head nh;
};

int ys_irq_register_ndev_irqs(struct pci_dev *pdev);
int ys_irq_unregister_ndev_irqs(struct pci_dev *pdev);
int ys_irq_init(struct pci_dev *pdev);
void ys_irq_uninit(struct pci_dev *pdev);

#endif /* __YS_INTR_H_ */
