# SPDX-License-Identifier: GPL-2.0

ifeq ($(CONFIG_YSHW_K2ULTRA), m)
	obj-$(CONFIG_YSHW_K2ULTRA) += ysk_unic3.o
else ifeq ($(CONFIG_YSHW_K2ULTRA_U200), m)
	obj-$(CONFIG_YSHW_K2ULTRA_U200) += ysk_unic3.o
else ifeq ($(CONFIG_YSHW_K2ULTRA_CS), m)
	obj-$(CONFIG_YSHW_K2ULTRA_CS) += ysk_unic3.o
endif

ifeq ($(CONFIG_YSHW_K2ULTRA_U200), m)
	ysk_unic3-objs := $(HW_DIR)/doe/ys_k2u_doe_main.o \
		$(HW_DIR)/doe/ys_k2u_doe_addrmap.o \
		$(HW_DIR)/doe/ys_k2u_doe_core.o \
		$(HW_DIR)/doe/ys_k2u_doe_if.o \
		$(HW_DIR)/doe/ys_k2u_doe_kapi.o \
		$(HW_DIR)/doe/ys_k2u_doe_mm.o \
		$(HW_DIR)/doe/ys_k2u_doe_schedule.o \
		$(HW_DIR)/mbox/ys_k2u_mbox.o
else
	ysk_unic3-objs := $(HW_DIR)/ys_k2u_main.o \
		$(HW_DIR)/edma/ys_k2u_new_core.o \
		$(HW_DIR)/edma/ys_k2u_new_func.o \
		$(HW_DIR)/edma/ys_k2u_new_vfsf.o \
		$(HW_DIR)/edma/ys_k2u_new_qset.o \
		$(HW_DIR)/edma/ys_k2u_new_ndev.o \
		$(HW_DIR)/edma/ys_k2u_new_ethtool.o \
		$(HW_DIR)/edma/ys_k2u_new_rx.o \
		$(HW_DIR)/edma/ys_k2u_new_tx.o \
		$(HW_DIR)/edma/ys_k2u_scatter.o \
		$(HW_DIR)/edma/ys_k2u_message.o \
		$(HW_DIR)/edma/ys_k2u_hqos.o \
		$(HW_DIR)/edma/ys_k2u_debugfs.o \
		$(HW_DIR)/mbox/ys_k2u_mbox.o \
		$(HW_DIR)/edma/ys_k2u_rss_redirect.o \
		$(HW_DIR)/doe/ys_k2u_doe_addrmap.o \
		$(HW_DIR)/doe/ys_k2u_doe_core.o \
		$(HW_DIR)/doe/ys_k2u_doe_if.o \
		$(HW_DIR)/doe/ys_k2u_doe_kapi.o \
		$(HW_DIR)/doe/ys_k2u_doe_mm.o \
		$(HW_DIR)/doe/ys_k2u_doe_schedule.o

ifeq ($(CONFIG_YSMOD_NP), k2u)
	ysk_unic3-objs += $(HW_DIR)/np/ys_k2u_np.o \
			$(HW_DIR)/np/ys_k2u_np_doe.o \
			$(HW_DIR)/np/ys_k2u_np_lag.o
endif

ifeq ($(CONFIG_YSMOD_NP), k2u)
	ysk_unic3-objs += $(HW_DIR)/np/ys_k2u_np.o \
			$(HW_DIR)/np/ys_k2u_np_doe.o
endif

ifeq ($(CONFIG_YSHW_K2ULTRA), m)
	ysk_unic3-objs += $(HW_DIR)/tc/ys_k2u_tc_core.o \
			$(HW_DIR)/tc/ys_k2u_tc_table.o \
			$(HW_DIR)/tc/ys_k2u_tc_flow.o \
			$(HW_DIR)/tc/ys_k2u_tc_meter.o
endif
endif

ysk_unic3-objs += $(DRV_OBJS)
ysk_unic3-objs += $(NET_OBJS)

ccflags-y += -DBUILD_IN_KERNELSPACE
