/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_PTP_H_
#define __YS_PTP_H_

#include <linux/ptp_clock_kernel.h>
#include <linux/net_tstamp.h>

enum {
	YS_PTP_CLK_ADJ_INC = 0x01000000, /* Add a tick every n ticks */
	YS_PTP_CLK_ADJ_DEC = 0x00000000, /* Skip a tick every n ticks */
	YS_PTP_CLK_ADJ_MAX = 0x00FFFFFF,
};

struct ys_ptp {
	struct pci_dev *pdev;
	struct ptp_clock *pclock;
	struct ptp_clock_info clock_info;
	u32 tick_hz;

	struct hwtstamp_config hwts_config;
	bool rx_hw_tstamp;
	bool tx_hw_tstamp;
	struct hrtimer phc_pps_hrtimer;
	long last_phc_pps;
	bool phc_pps_enabled;
	spinlock_t ptp_clock_lock; /* clock lock */
};

int ys_aux_ptp_probe(struct auxiliary_device *auxdev,
		     const struct auxiliary_device_id *id);
void ys_aux_ptp_remove(struct auxiliary_device *auxdev);

#endif /* __YS_PTP_H_ */
