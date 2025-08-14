/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_REG_OPS_H_
#define __YS_REG_OPS_H_

#include "ys_debug.h"
#include "ys_utils.h"

#include <linux/bitfield.h>

#define ys_rd32(base, reg) \
	ioread32((void __iomem *)((uintptr_t)(base) + (reg)))
#define ys_wr32(base, reg, value) \
	iowrite32(value, (void __iomem *)((uintptr_t)(base) + (reg)))

static inline u64 ys_rd64(void __iomem *addr, u32 off)
{
	return (u64)ys_rd32(addr, off) | ((u64)ys_rd32(addr, off + 4) << 32);
}

static inline u64 ys_big_rd64(void __iomem *addr, u32 off)
{
	return (u64)ys_rd32(addr, off + 4) | ((u64)ys_rd32(addr, off) << 32);
}

#endif /* __YS_REG_OPS_H_ */
