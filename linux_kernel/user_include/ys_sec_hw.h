/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ys_sec_HW_H
#define ys_sec_HW_H

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/types.h>

#define YS_SEC_PCIE_PFVFID		0x7000120
#define YS_SEC_PFID_MASK		0xff
#define YS_SEC_VFID_MASK		0xffff

#define SYS_CFG_BASE		0x0000UL

#define GLO_CGF_BASE		(SYS_CFG_BASE)
#define GLO_FPGA_DATE		0x00
#define GLO_FPGA_TIME		0x04
#define GLO_FPGA_VER		0x08
#define GLO_CFG_RST		0x0C
#define GLO_HOST_SOC		0x10
#define GLO_RING_NUM		0x14
#define GLO_DESC_CFG		0x18
#define GLO_CFG_REG(reg) (GLO_CGF_BASE + (reg))

#define F_RING_CFG_BASE		(SYS_CFG_BASE + 0x1000)
#define F_RING_CFG_START	0x00
#define F_RING_CFG_STOP		0x04
#define F_RING_CFG_REG(f_id, reg) (F_RING_CFG_BASE + 0x10 * (f_id) + (reg))

#define RV_INT_CFG_BASE		(SYS_CFG_BASE + 0x1300)
#define RV_INT_CTL		0x00
#define RV_INT_STAT		0X04
#define RV_INT_CFG_RET(f_id, reg) (RV_INT_CFG_BASE + 0x8 * (f_id) + (reg))

#define RING_INT_CFG_BASE	(SYS_CFG_BASE + 0x1500)
#define RING_INT_VF		0x00
#define RING_INT_CTL		0x04
#define RING_INT_STAT		0x08
#define RING_INT_RSVD		0x0C
#define RING_INT_CFG_REG(r_id, reg) (RING_INT_CFG_BASE + 0x10 * (r_id) + (reg))

#define RING_CSR_BASE		0x4000UL
#define RING_CSR_INFO		0x00
#define RING_CSR_CFG		0X04
#define RING_CSR_PRODUCER	0x08
#define RING_CSR_CONSUMER	0x0C
#define RING_CSR_DESC_L		0x10
#define RING_CSR_DESC_H		0x14
#define RING_CSR_STAT_L		0x18
#define RING_CSR_STAT_H		0x1C
#define RING_CSR_EXCPTION	0x20
#define RING_CSR_REG(r_id, reg) (RING_CSR_BASE + 0x40 * (r_id) + (reg))

#define INT_TABLE_BASE		0x10000UL
#define RING_INT_NO_REG(r_id) (INT_TABLE_BASE + 0x04 * (r_id))
#define RV_INT_NO_REG(f_id) (INT_TABLE_BASE + 0xC00 + 0x04 * (f_id))

#define ENGINE_BASE		0x12000UL
#define ENGINE_RESET		0x10c
#define ENGINE_HS_LOCK		0x100
#define ENGINE_FINISH		0x110
#define ENGINE_REG(reg) (ENGINE_BASE + (reg))

#define RISCV_SYS_BASE		0x13000UL
#define RISCV_RX_SHMEM0		0x0
#define RISCV_RX_SHMEM1		0x1000
#define RISCV_TX_SHMEM0		0x2000
#define RISCV_TX_SHMEM1		0x3000
#define RISCV_EVENT_Q		0x4000
#define RISCV_EVENT_FULL	0x4004
#define RISCV_EVENT_NUM		0x4008
#define RISCV_WRITE_FLAG	0x400c
#define RISCV_MODULE_CHOOSE	0x4010
#define RISCV_RX_LOCK0		0x4014
#define RISCV_RX_LOCK1		0x4018
#define RISCV_RX_UNLOCK0	0x402c
#define RISCV_RX_UNLOCK1	0x4020
#define RISCV_TX_LOCK0		0x4024
#define RISCV_TX_LOCK1		0x4028
#define RISCV_TX_UNLOCK0	0x402c
#define RISCV_TX_UNLOCK1	0x4030
#define RISCV_REG(reg) (RISCV_SYS_BASE + (reg))

#define KM_RESET		0x2509c
#define SM2_RESET		0x11304

#define BUFF_BASE		0x28000UL
#define BUFF_HSEC_CONFIG1	0x58
#define BUFF_HSEC_CONFIG2	0x5c
#define BUFF_HSEC_OPERATION	0x60
#define BUFF_HSEC_FINISH	0x7c
#define BUFF_REG(reg) (BUFF_BASE + (reg))

#define HADOS_IV_LEN 16

struct ys_sec_ri {
	u32 index;
	struct ys_sec_ri *next;
};

struct ys_sec_rs {
	u16 en : 1;
	u16 host_soc : 1;
	u16 ring_id : 8;
	u16 rsvd2 : 6;

	u16 pf_id : 6;
	u16 rsvd1 : 1;
	u16 vf_id : 9;

	u16 hw_head;
	u16 hw_tail;

	u32 rsvd3;
	u32 rsvd4;
} SEC_PACKED;

struct ys_sec_ring;

struct ys_sec_ring {
	u16 id;

	u16 pfid;
	u16 vfid;

	u32 size;
	u32 size_mask;

	u32 sw_head;
	u32 sw_tail;

	u8 *desc_addr;
	u32 desc_len;
	u32 desc_stride;

	u8 *data_addr;
	u32 data_len;
	u32 data_stride;

	u32 hw_ptr_mask;

	void __iomem *hw_addr;
	void __iomem *hw_head_ptr;
	void __iomem *hw_tail_ptr;

	u8 *state_addr;

	/*
	 * store data with every desc
	 */
	struct ys_sec_ri *ri;

	struct device	*dev;
	dma_addr_t	desc_dma_addr;
	dma_addr_t	data_dma_addr;
	dma_addr_t	state_dma_addr;
};

struct ys_sec_desc {
	u16	src_len;
	u16	rsvd1;
	void		*src_addr;
	void		*dst_addr;
	u8		cmd;
	u8		func0;
	u8		func1;
	u8		func2;
	u32	param;
	u8		rsvd2;
	u16	dst_len;
	u8		flag;
	u8		iv[HADOS_IV_LEN];
	u8		rsvd3[16];
} SEC_PACKED;

#define RING_MOVE_HEAD(ring)  ({				\
	typeof(ring) _r = (ring);				\
	_r->sw_head = (_r->sw_head + 1) & (_r->size - 1);	\
})

#define RING_MOVE_TAIL(ring) ({					\
	typeof(ring) _r = (ring);				\
	(_r->sw_tail = (_r->sw_tail + 1) & (_r->size - 1));	\
})

#define RING_FULL(ring) ({					\
	typeof(ring) _r = (ring);				\
	((_r->sw_head + 1) & (_r->size - 1)) == _r->sw_tail;	\
})

#define RING_EMPTY(ring) ({					\
	typeof(ring) _r = (ring);				\
	_r->sw_head == _r->sw_tail;				\
})

#endif // ys_sec_HW_H
