/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_UMAC_H_
#define __YS_UMAC_H_

#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/netdevice.h>

#include "ys_platform.h"
#include "ys_adapter.h"
#include "ys_debug.h"
#include "ys_reg_ops.h"

#include "ys_umac_register.h"

enum {
	UMAC_FRAMES_XMIT_ERROR,
	UMAC_FRAMES_XMIT_SIZELT64,
	UMAC_FRAMES_XMIT_SIZEEQ64,
	UMAC_FRAMES_XMIT_SIZE65TO127,
	UMAC_FRAMES_XMIT_SIZE128TO255,
	UMAC_FRAMES_XMIT_SIZE256TO511,
	UMAC_FRAMES_XMIT_SIZE512TO1023,
	UMAC_FRAMES_XMIT_SIZE1024TO1518,
	UMAC_FRAMES_XMIT_SIZE1519TO2047,
	UMAC_FRAMES_XMIT_SIZE2048TO4095,
	UMAC_FRAMES_XMIT_SIZE4096TO8191,
	UMAC_FRAMES_SMIT_SIZE8192TO9215,
	UMAC_FRAMES_XMIT_SIZEGT9216,

	UMAC_FRAMES_RCVD_CRCERROR,
	UMAC_FRAMES_RCVD_SIZELT64,
	UMAC_FRAMES_RCVD_SIZEEQ64,
	UMAC_FRAMES_RCVD_SIZE65TO127,
	UMAC_FRAMES_RCVD_SIZE128TO255,
	UMAC_FRAMES_RCVD_SIZE256TO511,
	UMAC_FRAMES_RCVD_SIZE512TO1023,
	UMAC_FRAMES_RCVD_SIZE1024TO1518,
	UMAC_FRAMES_RCVD_SIZE1419TO2047,
	UMAC_FRAMES_RCVD_SIZE2048TO4095,
	UMAC_FRAMES_RCVD_SIZE4096TO8191,
	UMAC_FRAMES_RCVD_SIZE8192TO9215,
	UMAC_FRAMES_RCVD_SIZEGT9216,

	UMAC_DUMMY_TX_DISCARD_PHY,
	UMAC_DUMMY_RX_DISCARD_PHY,
	UMAC_STATE_STATISTICS_NUM,
};

enum {
	UMAC_MODE_SPEED_DISABLED = 0,
	UMAC_MODE_SPEED_10GBASE = 15,
	UMAC_MODE_SPEED_10GBASE_FC = 16,
	UMAC_MODE_SPEED_25GBASE = 21,
	UMAC_MODE_SPEED_25GBASE_FC = 22,
	UMAC_MODE_SPEED_25GBASE_RS_IEEE = 23,
	UMAC_MODE_SPEED_25GBASE_RS_CONS = 24,
	UMAC_MODE_SPEED_40GBASE = 26,
	UMAC_MODE_SPEED_40GBASE_FC = 27,
	UMAC_MODE_SPEED_50GBASE = 37,
	UMAC_MODE_SPEED_50GBASE_FC = 38,
	UMAC_MODE_SPEED_50GBASE_RS = 39,
	UMAC_MODE_SPEED_100GBASE = 46,
	UMAC_MODE_SPEED_100GBASE_RS = 47,
};

enum {
	UMAC_MODE_SPEEDM_10GBASE = 0,
	UMAC_MODE_SPEEDM_25GBASE,
	UMAC_MODE_SPEEDM_40GBASE,
	UMAC_MODE_SPEEDM_100GBASE,
};

enum {
	UMAC_D2M_SET_SPEED10G = 1,              //Proactively tune to 10G
	UMAC_D2M_SET_SPEED25G,                  //Proactively tune to 25G
	UMAC_D2M_SET_SPEED40G,                  //Proactively tune to 40G
	UMAC_D2M_SET_SPEED50G,                  //Proactively tune to 50G
	UMAC_D2M_SET_SPEED100G,                 //Proactively tune to 100G
	UMAC_D2M_SET_FEC_RS,                    //Set FC-FEC
	UMAC_D2M_SET_FEC_BASER,                 //Set RS_IEEE_FEC
	UMAC_D2M_SET_FEC_NONE,                  //Close FEC
	UMAC_D2M_SET_SPEED_AUTONEGO,            //Enable Auto-Negotiation
	UMAC_D2M_GET_SPEED_AUTONEGO,
	UMAC_D2M_SET_FEC_AUTONEGO,              //Enable FEC Auto-Negotiation
	UMAC_D2M_SET_PF0_FC_PAUSE,              //enable PF0 TX,RX FC
	UMAC_D2M_SET_PFN_FC_PAUSE,              //enable PFN TX,RX FC
	UMAC_D2M_SET_PF0_FC_PAUSE_OFF,          //disable PF0 TX,RX FC
	UMAC_D2M_SET_PFN_FC_PAUSE_OFF,          //disable PFN TX,RX FC
	UMAC_D2M_SET_PORT0_LIGHT_BLINK,         //Port 0 Blinking
	UMAC_D2M_SET_PORT1_LIGHT_BLINK,         //Port 1 Blinking
	UMAC_D2M_SET_PORT0_LIGHT_NORMAL,        //Port 0 Blinking Disabled
	UMAC_D2M_SET_PORT1_LIGHT_NORMAL,        //Port 1 Blinking Disabled
	UMAC_D2M_CMD_MAX,
};

#ifdef YS_HAVE_ETHTOOL_MAC_STATS
#define get_umac_stats(umac) ((umac)->et_get_mac_stats = ys_umac_get_mac_stats)
#else
#define get_umac_stats(umac) \
	do {                \
	} while (0)
#endif

int ys_umac_init(struct auxiliary_device *auxdev);
void ys_umac_uninit(struct auxiliary_device *auxdev);

int ys_umac_get_sfp_data(struct net_device *ndev, u32 pf_id, u8 *data,
			 u32 data_type);
int ys_umac_status_check(struct net_device *ndev);
int ys_umac_enable_25gbase_rs_cons(struct net_device *ndev);
int ys_umac_enable_25gbase(struct net_device *ndev);
int ys_umac_set_link_speed(struct net_device *ndev, u32 speed);
int ys_umac_eth_init(struct net_device *ndev);
int ys_umac_ndev_init(struct net_device *ndev);
void ys_umac_ndev_uninit(struct net_device *ndev);
int ys_umac_enable(struct net_device *ndev);
void ys_umac_get_stats(struct net_device *ndev, u64 *data);
void ys_umac_get_stats_strings(struct net_device *ndev, u8 *data);
int ys_umac_get_stats_count(struct net_device *ndev);
int ys_umac_set_fec_mode(struct net_device *ndev, u32 fec);
int ys_umac_vf_link_state(struct net_device *ndev,
			  int vf, int link_state);
int ys_umac_set_speed_autonego(struct net_device *ndev, bool on);
u8 ys_umac_get_speed_autonego(struct net_device *ndev);
void ysk2_shr0_port_autonego(struct ys_mbox *mbox, u32 pf_id, u32 speed);
void ysk2_shr0_port_speed(struct ys_mbox *mbox, u32 pf_id, u32 speed);
u32 ysk2_get_shr0_port_autonego(struct ys_mbox *mbox);
u32 ysk2_get_shr0_port_speed(struct ys_mbox *mbox);

#define UMAC_ETH_FUNC(umac)					\
	do {							\
		typeof(umac) _umac_temp = (umac);		\
		_umac_temp->enable_mac = NULL;                      \
		_umac_temp->et_get_supported_advertising = ys_umac_get_supported_advertising; \
		_umac_temp->et_get_link_speed = ys_umac_get_link_speed; \
		_umac_temp->et_get_link_duplex = ys_umac_get_link_duplex; \
		_umac_temp->et_get_link_port_type = ys_umac_get_link_port_type;   \
		_umac_temp->et_get_fec_mode = ys_umac_get_fec_mode;           \
		_umac_temp->et_get_module_data = ys_umac_get_sfp_data;     \
		_umac_temp->et_set_link_speed = ys_umac_set_m3_link_speed;     \
		_umac_temp->et_set_link_autoneg = ys_umac_set_speed_autonego; \
		_umac_temp->et_get_link_autoneg = ys_umac_get_speed_autonego; \
		_umac_temp->ys_set_phys_id = ys_umac_set_phys_id;       \
		_umac_temp->et_set_fec_mode = ys_umac_set_fec_mode;   \
		_umac_temp->ys_set_pauseparam  = ys_umac_set_pauseparam;   \
		_umac_temp->ys_get_pauseparam  = ys_umac_get_pauseparam;   \
		get_umac_stats(_umac_temp);                                   \
	} while (0)
#define UMAC_NDEV_FUNC(umac) \
	do {							\
		typeof(umac) _umac_temp = (umac); \
		_umac_temp->ys_set_vf_link_state =  ys_umac_vf_link_state;\
	} while (0)
#endif
