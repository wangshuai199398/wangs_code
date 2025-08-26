/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_K2U_MBOX_H__
#define __YS_K2U_MBOX_H__

extern bool dpu_soc;
extern u32 ys_k2u_mbox_base; //mbox base offset

#define YS_K2U_MBOX_BAR                     BAR0
#define YS_K2U_MBOX_IRQ                     0
#define YS_K2U_MBOX_BASE                    (ys_k2u_mbox_base)

#define YS_K2U_MBOX_DPU_HOST_BASE	0x300000
#define YS_K2U_MBOX_DPU_SOC_BASE	0x380000

/* hw define pf id */
#define YS_K2U_MBOX_M3_PF_ID                (0x180 + 25)
#define YS_K2U_MBOX_MASTER_PF_ID            0x100

/* vf2pf reg */
#define YS_K2U_MBOX_PF2VF_IRQ_TRIGGER       (YS_K2U_MBOX_BASE + 0x40)
#define YS_K2U_MBOX_PF2VF_IRQ_VECTOR        (YS_K2U_MBOX_BASE + 0x44)
#define YS_K2U_MBOX_PF2VF_IRQ_PENDING       (YS_K2U_MBOX_BASE + 0x48)
#define YS_K2U_MBOX_PF2VF_IRQ_P_STATUS      GENMASK(27, 27)
#define YS_K2U_MBOX_PF2VF_IRQ_P_VF_ID       GENMASK(8, 0)
#define YS_K2U_MBOX_PF2VF_IRQ_P_VECTOR      GENMASK(26, 15)

/* only manage can be config */
#define YS_K2U_MBOX_G_REG                   (YS_K2U_MBOX_BASE + 0x1000)
#define YS_K2U_MBOX_G_BUF_SIZE              (YS_K2U_MBOX_G_REG + 0x00)
#define YS_K2U_MBOX_G_TIMEOUT_ENABLE        (YS_K2U_MBOX_G_REG + 0x20)
#define YS_K2U_MBOX_G_TIMEOUT_CNT           (YS_K2U_MBOX_G_REG + 0x24)
#define YS_K2U_MBOX_G_M3_IRQ_OUT_CNT        (YS_K2U_MBOX_G_REG + 0x28)
#define YS_K2U_MBOX_G_MAILBOX_VERSION       (YS_K2U_MBOX_G_REG + 0x30)
#define YS_K2U_MBOX_G_MAILBOX_INIT_DONE     (YS_K2U_MBOX_G_REG + 0x38)
#define YS_K2U_MBOX_G_PF_IRQ_TIME_OUT_ALARM (YS_K2U_MBOX_G_REG + 0x50)
#define YS_K2U_MBOX_G_VF_IRQ_TIME_OUT_ALARM (YS_K2U_MBOX_G_REG + 0x54)
#define YS_K2U_MBOX_G_M3_IRQ_TIME_OUT_ALARM (YS_K2U_MBOX_G_REG + 0x58)
#define YS_K2U_MBOX_G_TIMEOUT               (5000000)

/* pf&pf master reg */
#define YS_K2U_MBOX_PF_BASE                 (YS_K2U_MBOX_BASE + 0x2000)
#define YS_K2U_MBOX_MASTER_PREEMPT          (YS_K2U_MBOX_PF_BASE + 0x00)
#define YS_K2U_MBOX_MASTER_SEL              BIT(0)
#define YS_K2U_MBOX_MASTER_OPTION           (YS_K2U_MBOX_PF_BASE + 0x04)
#define YS_K2U_MBOX_LF_START                0
#define YS_K2U_MBOX_LF_END                  8
#define YS_K2U_MBOX_LFX_MEM_OFFSET(lf_id) \
	(YS_K2U_MBOX_PF_BASE + 0x8 + (lf_id) * 4)
#define YS_K2U_MBOX_LFX_MEM_PF_ID           GENMASK(21, 16)
#define YS_K2U_MBOX_LFX_MEM_ADDR            GENMASK(15, 0)
#define YS_K2U_MBOX_PF2PF_IRQ_TRIGGER       (YS_K2U_MBOX_PF_BASE + 0x30)
#define YS_K2U_MBOX_PF2PF_IRQ_VECTOR        (YS_K2U_MBOX_PF_BASE + 0x34)
#define YS_K2U_MBOX_PF2PF_IRQ_PENDING       (YS_K2U_MBOX_PF_BASE + 0x38)
#define YS_K2U_MBOX_PF2PF_IRQ_P_PF_ID       GENMASK(8, 0)
#define YS_K2U_MBOX_PF2PF_IRQ_P_STATUS      GENMASK(27, 27)
#define YS_K2U_MBOX_PF2PF_IRQ_P_VECTOR      GENMASK(26, 15)
/* host2soc trigger interrupt */
#define YS_K2U_MBOX_H2S_IRQ_TRIGGER         (YS_K2U_MBOX_PF_BASE + 0x40)
#define YS_K2U_MBOX_S2H_IRQ_VECTOR          (YS_K2U_MBOX_PF_BASE + 0x44)
/* host2m3 trigger interrupt */
#define YS_K2U_MBOX_H2M_IRQ_TRIGGER         (YS_K2U_MBOX_PF_BASE + 0x50)
#define YS_K2U_MBOX_M2H_IRQ_VECTOR          (YS_K2U_MBOX_PF_BASE + 0x54)

/* vf reg */
#define YS_K2U_MBOX_VF_BASE                 (YS_K2U_MBOX_BASE + 0x8000)
#define YS_K2U_MBOX_VF_IRQ_TRIGGER          (YS_K2U_MBOX_VF_BASE + 0x0)
#define YS_K2U_MBOX_VF_IRQ_VECTOR           (YS_K2U_MBOX_VF_BASE + 0x4)
#define YS_K2U_MBOX_VF_IRQ_PENDING          (YS_K2U_MBOX_VF_BASE + 0x8)
#define YS_K2U_MBOX_VF2PF_IRQ_P_STATUS      GENMASK(27, 27)
#define YS_K2U_MBOX_VF2PF_IRQ_P_VF_ID       GENMASK(8, 0)
#define YS_K2U_MBOX_VF2PF_IRQ_P_VECTOR      GENMASK(26, 15)

/* pf&vf buffer*/
#define YS_K2U_MBOX_VF_PF_BUF_BASE          (YS_K2U_MBOX_BASE + 0x10000)
/* vf id from 0 to 511 */
#define YS_K2U_MBOX_VF_PF_BUF_OFFSET(vf_id) \
	(YS_K2U_MBOX_VF_PF_BUF_BASE + 0x100 * (vf_id))

/* pf&pf buffer */
#define YS_K2U_MBOX_PF2PF_BUF_BASE          (YS_K2U_MBOX_BASE + 0x30000)
/* pf id from 0 to 10 */
#define YS_K2U_MBOX_PF2PF_BUF_OFFSET(pf_id) \
	(YS_K2U_MBOX_PF2PF_BUF_BASE + 0x100 * (pf_id))
#define YS_K2U_MBOX_M2M3_CHN                (YS_K2U_MBOX_PF2PF_BUF_BASE + 0x900)
#define YS_K2U_MBOX_M2M_CHN                 (YS_K2U_MBOX_DPU_SOC_BASE + 0x30a00)

#define YS_K2U_MBOX_MAX_PF                  64
#define YS_K2U_MBOX_MAX_VF                  511
#define YS_K2U_MBOX_MSG_LEN                 128

#define YS_K2U_MBOX_SH_BUF_SIZE             0x100
#define YS_K2U_MBOX_SH_BUF_TH               0x0
#define YS_K2U_MBOX_SH_BUF_BH               0x80

#define YS_K2U_MBOX_DEF_VAL                 0x0
#define YS_K2U_MBOX_ERR_VAL                 0xdeaddec2 //0xdeadbed2
#define YS_K2U_MBOX_DEF_VAL_ERR_MSG         "default value error"
#define YS_K2U_MBOX_VFS_NUM                 (64)

#define YS_K2U_MBOX_LF0_LF1_VF_NUM          (YS_K2U_MBOX_BASE + 0x1060)
#define YS_K2U_MBOX_LF2_LF3_VF_NUM          (YS_K2U_MBOX_BASE + 0x1064)
#define YS_K2U_MBOX_LF4_LF5_VF_NUM          (YS_K2U_MBOX_BASE + 0x1068)
#define YS_K2U_MBOX_LF6_LF7_VF_NUM          (YS_K2U_MBOX_BASE + 0x106c)
#define YS_K2U_MBOX_LF0_LF1_REMAP_PF_ID     (YS_K2U_MBOX_BASE + 0x1070)
#define YS_K2U_MBOX_LF2_LF3_REMAP_PF_ID     (YS_K2U_MBOX_BASE + 0x1074)
#define YS_K2U_MBOX_LF4_LF5_REMAP_PF_ID     (YS_K2U_MBOX_BASE + 0x1078)
#define YS_K2U_MBOX_LF6_LF7_REMAP_PF_ID     (YS_K2U_MBOX_BASE + 0x107C)
#define YS_K2U_MBOX_LF8_REMAP_PF_ID         (YS_K2U_MBOX_BASE + 0x1080)
#define YS_K2U_MBOX_HOST_IRQ_CNT            (YS_K2U_MBOX_BASE + 0x1090)
#define YS_K2U_MBOX_M3_MASTER_IRQ_CNT       (YS_K2U_MBOX_BASE + 0x1094)
#define YS_K2U_MBOX_M3_LF_IRQ_CNT           (YS_K2U_MBOX_BASE + 0x1098)
#define YS_K2U_MBOX_TRIG_VF2PF_IRQ_CNT      (YS_K2U_MBOX_BASE + 0x109C)
#define YS_K2U_MBOX_TRIG_PF2VF_IRQ_CNT      (YS_K2U_MBOX_BASE + 0x10A0)
#define YS_K2U_MBOX_TRIG_PF2PF_IRQ_CNT      (YS_K2U_MBOX_BASE + 0x10A4)
#define YS_K2U_MBOX_TRIG_M3_MASTER_IRQ_CNT  (YS_K2U_MBOX_BASE + 0x10A8)
#define YS_K2U_MBOX_TRIG_M3_LF_IRQ_CNT      (YS_K2U_MBOX_BASE + 0x10AC)
#define YS_K2U_MBOX_HOST_SOC_SEL            (YS_K2U_MBOX_BASE + 0x10B0)
#define YS_K2U_MBOX_APB_TRIG_ADDR1          (YS_K2U_MBOX_BASE + 0x10B4)
#define YS_K2U_MBOX_APB_TRIG_ADDR2          (YS_K2U_MBOX_BASE + 0x10B8)
#define YS_K2U_MBOX_APB_WDATA               (YS_K2U_MBOX_BASE + 0x10BC)
#define YS_K2U_MBOX_MAILBOX_FIFO_EMPTY      (YS_K2U_MBOX_BASE + 0x10C0)
#define YS_K2U_MBOX_MAILBOX_FIFO_FULL       (YS_K2U_MBOX_BASE + 0x10C4)
#define YS_K2U_MBOX_IRQ_OUT_DATA            (YS_K2U_MBOX_BASE + 0x10C8)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG0         (YS_K2U_MBOX_BASE + 0x10CC)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG1         (YS_K2U_MBOX_BASE + 0x10D0)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG2         (YS_K2U_MBOX_BASE + 0x10D4)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG3         (YS_K2U_MBOX_BASE + 0x10D8)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG4         (YS_K2U_MBOX_BASE + 0x10DC)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG5         (YS_K2U_MBOX_BASE + 0x10E0)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG6         (YS_K2U_MBOX_BASE + 0x10E4)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG7         (YS_K2U_MBOX_BASE + 0x10E8)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG8         (YS_K2U_MBOX_BASE + 0x10EC)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG9         (YS_K2U_MBOX_BASE + 0x10F0)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG10        (YS_K2U_MBOX_BASE + 0x10F4)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG11        (YS_K2U_MBOX_BASE + 0x10F8)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG12        (YS_K2U_MBOX_BASE + 0x10FC)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG13        (YS_K2U_MBOX_BASE + 0x1100)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG14        (YS_K2U_MBOX_BASE + 0x1104)
#define YS_K2U_MBOX_PF_VF_IRQ_FLAG15        (YS_K2U_MBOX_BASE + 0x1108)

struct ys_k2u_mbox_ctx {
	u16 func_id : 10;
	u16 type : 6;
};

struct ys_k2u_mbox_offset_ctx {
	u32 offset;
	u32 trigger_offset;
	u32 trigger_id;
};

struct ys_k2u_mbox {
	u32 pf2lf_table[YS_K2U_MBOX_MAX_PF];
};

int ys_k2u_mbox_init(struct pci_dev *pdev);

#endif /* __YS_K2U_MBOX_H__ */
