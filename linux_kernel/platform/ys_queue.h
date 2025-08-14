/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_QUEUE_H_
#define __YS_QUEUE_H_

/* in k2 project, pf will use 1024 queue */
#define YS_MAX_QUEUES	1024
/*
 * in ldma3 project, pf will use 256 queue
 * in k2u project, pf will use 768 queue
 */
#define YS_MAX_QSET	1024

struct ys_queue_params {
	u16 qbase;
	u16 ndev_qnum;
	u16 qset;
};

enum ys_queue_type {
	QUEUE_TYPE_TX,
	QUEUE_TYPE_RX
};

struct ys_queue_info {
	bool is_used;
	enum ys_queue_type type;
	int index;
	u16 qset;
	bool is_vf;
	int vf_id;
	int pio_id;
};

struct ys_qset_pool {
	struct idr pool;
	/* spinlock for more ndev/sf in pf alloc qset pool */
	spinlock_t lock;
	u16 qset_start;
	u16 qset_end;
};

void ys_queue_clear(struct pci_dev *pdev);
void ys_queue_update_info(struct net_device *ndev,
			  int is_vf,
			  int vf_id);
void ys_queue_set_info(struct pci_dev *pdev,
		       enum ys_queue_type type,
		       int qbase,
		       int qset,
		       int qcount,
		       int index,
		       int is_vf,
		       int vf_id,
		       int pioid);
void ys_queue_clear_info(struct pci_dev *pdev,
			 enum ys_queue_type type,
			 int qbase,
			 int qcount);
bool ys_queue_check_info(struct pci_dev *pdev,
			 enum ys_queue_type type,
			 int qbase,
			 int qcount);
int ys_queue_cal_vf_max_queue(struct pci_dev *pdev);
int ys_queue_find_available_base(struct pci_dev *pdev,
				 enum ys_queue_type type,
				 int qcount);
int ys_qset_get_id(struct pci_dev *pdev);
void ys_qset_release_id(struct pci_dev *pdev, int id);
void ys_qset_pool_init(struct pci_dev *pdev);
void ys_qset_pool_uninit(struct pci_dev *pdev);

#endif /* __YS_QUEUE_H_ */
