/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ys_sec_HW_H
#define ys_sec_HW_H

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/types.h>

#ifndef __KERNEL__
#define __iomem
#include <pthread.h>
#include <stdint.h>
#endif

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
#ifndef __KERNEL__
	void *cb;
	void *cb_tag;
	void *rsp;
#else
#endif
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

#ifndef __KERNEL__
struct ys_sec_km_if {
	void (*km_cb)(struct ys_sec_ring *ring, u32 index);

	void *data;
	u32 len;
	void *cb;
	void *cb_tag;

	void *timespec;
};

#endif
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

#if defined(__KERNEL__)
	struct device	*dev;
	dma_addr_t	desc_dma_addr;
	dma_addr_t	data_dma_addr;
	dma_addr_t	state_dma_addr;
#else
	pthread_mutex_t lock_tx;
	pthread_mutex_t lock_rx;

	struct ys_sec_km_if km_if;
#endif
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

#ifdef __KERNEL__
static struct ys_sec_ring *ys_sec_ring_alloc(struct device *dev,
					     void __iomem *hw_addr,
					     u16 ring_id, u16 ring_size,
					     u16 stride)
{
	struct ys_sec_ring *ring;
	struct ys_sec_rs *state;
	struct ys_sec_desc *desc;
	int ret, i;
	u8 *data_addr;

	ring = kmalloc(sizeof(*ring), GFP_KERNEL);
	if (!ring)
		return ERR_PTR(-ENOMEM);

	ring->dev = dev;
	ring->id = ring_id;
	ring->size = ring_size;
	ring->desc_stride = stride;
	ring->size_mask = 0xFFFF;
	ring->sw_head = 0;
	ring->sw_tail = 0;
	ring->desc_len = stride * ring_size;

	ring->desc_addr = dma_alloc_coherent(dev, ring->desc_len,
					     &ring->desc_dma_addr, GFP_KERNEL);
	if (!ring->desc_addr) {
		ret = -ENOMEM;
		goto err_alloc_coherent_desc;
	}

	ring->data_len = 0x1000 * ring_size;
	ring->data_addr = dma_alloc_coherent(dev, ring->data_len,
					     &ring->data_dma_addr, GFP_KERNEL);
	if (!ring->data_addr) {
		ret = -ENOMEM;
		goto err_alloc_coherent_data;
	}

	ring->state_addr = dma_alloc_coherent(dev, sizeof(*state),
					      &ring->state_dma_addr, GFP_KERNEL);
	if (!ring->state_addr) {
		ret = -ENOMEM;
		goto err_alloc_coherent_state;
	}

	ring->hw_head_ptr = hw_addr + RING_CSR_REG(ring_id, RING_CSR_PRODUCER);
	ring->hw_tail_ptr = hw_addr + RING_CSR_REG(ring_id, RING_CSR_CONSUMER);

	iowrite32((u32)ring->desc_dma_addr,
		  hw_addr + RING_CSR_REG(ring_id, RING_CSR_DESC_L));
	iowrite32((u32)(ring->desc_dma_addr >> 32),
		  hw_addr + RING_CSR_REG(ring_id, RING_CSR_DESC_H));

	iowrite32((u32)ring->state_dma_addr,
		  hw_addr + RING_CSR_REG(ring_id, RING_CSR_STAT_L));
	iowrite32((u32)(ring->state_dma_addr >> 32),
		  hw_addr + RING_CSR_REG(ring_id, RING_CSR_STAT_H));

	iowrite32(0, hw_addr + RING_INT_CFG_REG(ring_id, RING_INT_VF));

	iowrite32(0, hw_addr + RING_CSR_REG(ring_id, RING_CSR_CFG));
	iowrite32(0, ring->hw_head_ptr);
	// iowrite32(0, ring->hw_tail_ptr);
	iowrite32((ring_size << 1) + 1,
		  hw_addr + RING_CSR_REG(ring_id, RING_CSR_CFG));

	for (i = 0; i < ring_size; ++i) {
		desc = (struct ys_sec_desc *)(ring->desc_addr + i * stride);
		data_addr = (u8 *)ring->data_dma_addr + i * 0x1000;
		desc->src_addr = data_addr;
		desc->dst_addr = data_addr;
	}

	return ring;

err_alloc_coherent_state:
	dma_free_coherent(dev, ring->data_len, ring->data_addr,
			  ring->data_dma_addr);
err_alloc_coherent_data:
	dma_free_coherent(dev, ring->desc_len, ring->desc_addr,
			  ring->desc_dma_addr);
err_alloc_coherent_desc:
	kfree(ring);

	return ERR_PTR(ret);
}
#else
static struct ys_sec_ring *ys_sec_ring_alloc(void __iomem *hw_addr, u16 ring_id,
					     u32 ring_size, void *desc_addr,
					     u32 desc_stride, u32 desc_len,
					     void *data_addr, u32 data_stride,
					     u32 data_len, void *state_addr)
{
	struct ys_sec_ring *ring;
	int i;

	ring = malloc(sizeof(*ring));
	if (!ring)
		return NULL;

	ring->id = ring_id;
	ring->size = ring_size;
	ring->size_mask = 0xffff;

	ring->hw_addr = hw_addr;

	ring->desc_addr = desc_addr;
	ring->desc_len = desc_len;
	ring->desc_stride = desc_stride;

	ring->data_addr = data_addr;
	ring->data_len = data_len;
	ring->data_stride = data_stride;

	ring->state_addr = state_addr;

	ring->hw_head_ptr = hw_addr + RING_CSR_REG(ring_id, RING_CSR_PRODUCER);
	ring->hw_tail_ptr = hw_addr + RING_CSR_REG(ring_id, RING_CSR_CONSUMER);

	ring->sw_head = *(u32 *)ring->hw_head_ptr;
	ring->sw_tail = *(u32 *)ring->hw_tail_ptr;

	ring->ri = calloc(ring_size, sizeof(*ring->ri));
	for (i = 0; i < ring_size; ++i)
		ring->ri[i].index = i;

	return ring;
}
#endif

static void ys_sec_ring_destroy(struct ys_sec_ring *ring)
{
#ifdef __KERNEL__
	dma_free_coherent(ring->dev, sizeof(struct ys_sec_rs),
			  ring->state_addr, ring->state_dma_addr);
	dma_free_coherent(ring->dev, ring->desc_len, ring->desc_addr,
			  ring->desc_dma_addr);
	dma_free_coherent(ring->dev, ring->data_len, ring->data_addr,
			  ring->data_dma_addr);
	kfree(ring);
#else
	free(ring);
#endif
}

#ifndef __KERNEL__
static s32 ys_sec_ring_check(struct ys_sec_ring *ring,
			     struct ys_sec_desc **desc,
			     struct ys_sec_ri **ri)
{
	u32 ret, hw_tail;
	void *addr;
	struct ys_sec_rs *rs = (struct ys_sec_rs *)ring->state_addr;

	if (RING_EMPTY(ring))
		return 0;

	hw_tail = rs->hw_tail;

	ret = ((hw_tail - ring->sw_tail) & (ring->size - 1));
	if (ret != 0) {
		addr = ring->desc_addr + ring->desc_stride * ring->sw_tail;
		*desc = (struct ys_sec_desc *)addr;

		if (ri)
			*ri = &ring->ri[ring->sw_tail];

		RING_MOVE_TAIL(ring);
		return ret;
	}

	return -1;
}

static s32 ys_sec_ring_check_by_index(struct ys_sec_ring *ring,
				      u32 index,
				      struct ys_sec_desc **desc,
				      struct ys_sec_ri **ri)
{
	u32 ret, hw_tail;
	void *addr;
	struct ys_sec_rs *rs = (struct ys_sec_rs *)ring->state_addr;

	if (RING_EMPTY(ring))
		return 0;

	hw_tail = rs->hw_tail;

	ret = ((hw_tail - ring->sw_tail) & (ring->size - 1));
	if (ret != 0) {
		if (ring->sw_tail != index)
			return 0;

		addr = ring->desc_addr + ring->desc_stride * ring->sw_tail;
		*desc = (struct ys_sec_desc *)addr;

		if (ri)
			*ri = &ring->ri[ring->sw_tail];

		RING_MOVE_TAIL(ring);

		return ret;
	}

	return -1;
}

static s32 ys_sec_ring_get_desc(struct ys_sec_ring *ring,
				struct ys_sec_desc **desc,
				struct ys_sec_ri **ri)
{
	if (RING_FULL(ring))
		return -1;

	*desc = (struct ys_sec_desc *)(ring->desc_addr +
				       ring->desc_stride * ring->sw_head);

	if (ri)
		*ri = &ring->ri[ring->sw_head];

	RING_MOVE_HEAD(ring);

	return 0;
}

static void ys_sec_ring_submit(struct ys_sec_ring *ring)
{
#ifdef __KERNEL__
	iowrite32(ring->sw_head, ring->hw_head_ptr);
#else
	*((u32 *)ring->hw_head_ptr) = ring->sw_head;
#endif
}

static void *ys_sec_ring_addr(struct ys_sec_ring *ring, u32 index)
{
	return ring->data_addr +  (index & (ring->size - 1)) * 0x1000;
}
#endif

#ifndef __KERNEL__
// key manager
struct ys_sec_km_rx_eq {
	u32 source: 2;
	u32 len_opt: 1;
	u32 rsvd1: 5;
	u32 cmd_code: 8;
	u32 pfvf_id: 16;
	u32 data_len: 16;
	u32 rsvd2: 8;
	u32 sh_entry: 1;
	u32 rsvd3: 7;
} SEC_PACKED;

struct ys_sec_km_tx_eq {
	u32 source: 2;
	u32 fail: 1;
	u32 fail_type: 4;
	u32 cmd_type: 4;
	u32 rsvd: 5;
	u32 pfvf_id: 16;
	u32 handler;
	u32 data_len;
	char data[];
} SEC_PACKED;

static s32 ys_sec_km_rx_lock(struct ys_sec_ring *ring)
{
	u32 val;
	void *addr = ring->hw_addr;

	val = *(u32 *)(addr +  RISCV_REG(RISCV_RX_LOCK0));
	if (val & 0x1)
		return 1;

	return 0;
}

static s32 ys_sec_km_tx_unlock(struct ys_sec_ring *ring, u32 index)
{
	void *addr = ring->hw_addr;

	if (index == 1)
		*(u32 *)(addr + RISCV_REG(RISCV_TX_UNLOCK0)) = 1111;
	else if (index == 2)
		*(u32 *)(addr + RISCV_REG(RISCV_TX_UNLOCK1)) = 1111;

	return 0;
}

static s32 ys_sec_km_send_cmd(struct ys_sec_ring *ring,
			      u8 *data, u32 data_len,
			      struct ys_sec_km_rx_eq *event)
{
	void *baddr = ring->hw_addr;
	u64 event_data = 0;

	/* copy data to share memory */
	memcpy(baddr +  RISCV_REG(RISCV_RX_SHMEM0), data, data_len);

	/* convert event struct to u64 */
	event_data |= event->source;
	event_data |= (u64)event->len_opt << 2;
	event_data |= (u64)event->cmd_code << 8;
	event_data |= (u64)event->pfvf_id << 16;
	event_data |= (u64)event->data_len << 32;
	event_data |= (u64)event->sh_entry << 56;

	/* write event data to register */
	*(u32 *)(baddr +  RISCV_REG(RISCV_EVENT_Q)) = event_data;
	__asm__ __volatile__("" ::: "memory");
	*(u32 *)(baddr +  RISCV_REG(RISCV_EVENT_Q)) = event_data >> 32;

	return 0;
}

static u32 ys_sec_km_check_result_index(struct ys_sec_ring *ring)
{
	u32 ret = *(u32 *)(ring->hw_addr + RISCV_REG(RISCV_WRITE_FLAG));

	__asm__ __volatile__("" ::: "memory");

	return ret;
}

static struct ys_sec_km_tx_eq *
ys_sec_km_get_result(struct ys_sec_ring *ring, u32 index)
{
	u32 offset;
	void *addr = ring->hw_addr;

	if (index == 1) {
		offset = RISCV_REG(RISCV_TX_SHMEM0);
	} else if (index == 2) {
		offset = RISCV_REG(RISCV_TX_SHMEM1);
	} else {
		fprintf(stderr, "ERR Write flag: %d\n", index);
		return NULL;
	}

	return (struct ys_sec_km_tx_eq *)(addr + offset);
}
#endif //__KERNEL__

#endif // ys_sec_HW_H
