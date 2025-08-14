/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_IRQ_H_
#define __YS_IRQ_H_

#include <linux/interrupt.h>
#include <linux/notifier.h>

enum ys_irq_states {
	YS_IRQ_STATE_UNREGISTERED,
	YS_IRQ_STATE_REGISTERED
};

/* Generally, an interrupt vector corresponds to a type of interrupt.
 *
 * The YS_IRQ_TYPE_MISC is a unique exception in the interrupt vector
 * table, where only a single interrupt vector of this type is permitted.
 * This configuration enables the registration of various interrupt types
 * on the same interrupt vector. Additionally, it is essential to implement
 * the bottom half of interrupts of this type using the YS_IRQ_BH_NOTIFIER,
 * ensuring efficient and organized handling of multiple interrupt signals.
 */
enum ys_irq_types {
	YS_IRQ_TYPE_QUEUE,
	YS_IRQ_TYPE_QUEUE_TX,
	YS_IRQ_TYPE_MBOX,
	YS_IRQ_TYPE_LAN,
	YS_IRQ_TYPE_MAC,
	YS_IRQ_TYPE_NP,
	YS_IRQ_TYPE_HW_PRIVATE,
	YS_IRQ_TYPE_MISC,
	YS_IRQ_TYPE_HW_MAX
};

enum ys_irq_bh_types {
	YS_IRQ_BH_NONE,
	YS_IRQ_BH_THREADED,
	YS_IRQ_BH_WORK,
	YS_IRQ_BH_NOTIFIER,
	YS_IRQ_BH_TASKLET
};

enum ys_irq_nb_types {
	YS_IRQ_NB_REGISTER_FIXED,
	YS_IRQ_NB_REGISTER_ANY,
	YS_IRQ_NB_UNREGISTER
};

/*  struct ys_irq_sub - variable irq information
 *  @irq_type: type define in ys_irq_types
 *  @ndev: which net_device does the irq belongs to
 *  @handler: the irq handler
 *  @bh_type: the irq bottom half processing type
 *  @bh: the irq bottom half information
 *  @devname: an ascii name for the claiming device
 */
struct ys_irq_sub {
	int irq_type;
	struct net_device *ndev;
	irq_handler_t handler;
	int bh_type;
	union {
		irq_handler_t thread_fn;
		work_func_t work_handler;
		struct notifier_block *nb;
		void (*tasklet_handler)(unsigned long data);
	} bh;
	char *devname;
};

struct ys_irq_nb {
	int index;
	struct pci_dev *pdev;
	struct ys_irq_sub sub;
};

#define YS_IRQ_SUB_INIT(_irq_type, _ndev, _handler, _bh_type, _devname) \
	{ \
		.irq_type = (_irq_type), .ndev = (_ndev), \
		.handler = (_handler), .bh_type = (_bh_type), \
		.devname = (_devname), \
	}

#define YS_IRQ_NB_INIT(_index, _pdev, _irq_type, _ndev, _handler, _devname) \
	{ \
		.index = (_index), .pdev = (_pdev), \
		.sub = YS_IRQ_SUB_INIT((_irq_type), (_ndev), (_handler), \
				       YS_IRQ_BH_NONE, _devname) \
	}

#define YS_REGISTER_IRQ(_nh, _mode, _index, _pdev, _sub) ({ \
	int ret; \
	do { \
		struct ys_irq_nb irq_nb; \
		irq_nb.index = (_index); \
		irq_nb.pdev = (_pdev); \
		irq_nb.sub = (_sub); \
		ret = blocking_notifier_call_chain((_nh), (_mode), \
						   &irq_nb); \
	} while (0); \
	ret; \
})

#define YS_REGISTER_NONE_IRQ(_nh, _mode, _index, _pdev, _irq_type, _ndev, \
			     _handler, _devname) ({ \
	int ret; \
	do { \
		struct ys_irq_nb irq_nb = \
			YS_IRQ_NB_INIT((_index), (_pdev), (_irq_type), \
				       (_ndev), (_handler), (_devname)); \
		ret = blocking_notifier_call_chain((_nh), (_mode), \
						   &irq_nb); \
	} while (0); \
	ret; \
})

#define YS_REGISTER_THREADED_IRQ(_nh, _mode, _index, _pdev, _irq_type, _ndev, \
				 _handler, _func, _devname) ({ \
	int ret; \
	do { \
		struct ys_irq_nb irq_nb = \
			YS_IRQ_NB_INIT((_index), (_pdev), (_irq_type), \
				       (_ndev), (_handler), (_devname)); \
		irq_nb.sub.bh_type = YS_IRQ_BH_THREADED; \
		irq_nb.sub.bh.thread_fn = (_func); \
		ret = blocking_notifier_call_chain((_nh), (_mode), \
						   &irq_nb); \
	} while (0); \
	ret; \
})

#define YS_REGISTER_WORK_IRQ(_nh, _mode, _index, _pdev, _irq_type, _ndev, \
			     _handler, _func, _devname) ({ \
	int ret; \
	do { \
		struct ys_irq_nb irq_nb = \
			YS_IRQ_NB_INIT((_index), (_pdev), (_irq_type), \
				       (_ndev), (_handler), (_devname)); \
		irq_nb.sub.bh_type = YS_IRQ_BH_WORK; \
		irq_nb.sub.bh.work_handler = (_func); \
		ret = blocking_notifier_call_chain((_nh), (_mode), \
							&irq_nb); \
	} while (0); \
	ret; \
})

#define YS_REGISTER_NOTIFIER_IRQ(_nh, _mode, _index, _pdev, _irq_type, _ndev, \
			     _bh_nb, _devname) ({ \
	int ret; \
	do { \
		struct ys_irq_nb irq_nb = \
			YS_IRQ_NB_INIT((_index), (_pdev), (_irq_type), \
				       (_ndev), NULL, (_devname)); \
		irq_nb.sub.bh_type = YS_IRQ_BH_NOTIFIER; \
		irq_nb.sub.bh.nb = (_bh_nb); \
		ret = blocking_notifier_call_chain((_nh), (_mode), \
							&irq_nb); \
	} while (0); \
	ret; \
})

#define YS_UNREGISTER_IRQ(_nh, _index, _pdev, _bh_nb) ({ \
	int ret; \
	do { \
		struct ys_irq_nb irq_nb = \
			YS_IRQ_NB_INIT((_index), (_pdev), 0, \
				       NULL, NULL, NULL); \
		irq_nb.sub.bh.nb = (_bh_nb); \
		ret = blocking_notifier_call_chain((_nh), \
						   YS_IRQ_NB_UNREGISTER, \
						   &irq_nb); \
	} while (0); \
	ret; \
})

#endif /* __YS_IRQ_H_ */
