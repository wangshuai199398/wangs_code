/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_PLAT_NP_H_
#define __YS_PLAT_NP_H_

#include "ys_auxiliary.h"

int ys_aux_np_probe(struct auxiliary_device *auxdev,
		    const struct auxiliary_device_id *id);

void ys_aux_np_remove(struct auxiliary_device *auxdev);

#endif /* __YS_PLAT_NP_H_ */
