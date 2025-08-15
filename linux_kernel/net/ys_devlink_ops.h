/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_DEVLINK_OPS_H_
#define __YS_DEVLINK_OPS_H_

#include <net/devlink.h>

int ys_devlink_get_switch_mode_init_value(struct devlink *devlink);
int ys_devlink_switch_mode_get(struct devlink *devlink, u32 id,
			       struct devlink_param_gset_ctx *ctx);
int ys_devlink_switch_mode_set(struct devlink *devlink, u32 id,
			       struct devlink_param_gset_ctx *ctx);
#ifdef YS_HAVE_DEVLINK_VALIDATE
int ys_devlink_switch_mode_validate(struct devlink *devlink, u32 id,
				    union devlink_param_value val);
#else
int ys_devlink_switch_mode_validate(struct devlink *devlink, u32 id,
				    union devlink_param_value val,
				    struct netlink_ext_ack *extack);
#endif /* YS_HAVE_DEVLINK_VALIDATE */
#endif /* __YS_DEVLINK_OPS_H_ */
