# SPDX-License-Identifier: GPL-2.0

include $(PWD)/mod_config.mk

# basic
DRV_OBJS := 	platform/ys_intr.o \
		platform/ys_init.o \
		platform/ys_pdev.o \
		platform/ys_queue.o \
		platform/ys_ndev.o \
		platform/ys_sysfs.o \
		platform/ys_debugfs.o \
		platform/ys_auxiliary.o \
		platform/ys_i2c.o \
		platform/ys_ptp.o \
		platform/ys_mbox.o \
		platform/ys_sriov.o \
		platform/ys_cdev.o \
		platform/ysc_dev.o \
		platform/ys_dmamap.o \
		platform/ys_devlink.o \
		platform/ys_debug.o \
		platform/ys_plat_doe.o \
		platform/ys_plat_np.o \
		platform/ys_vdpa.o

NET_OBJS := 	net/ys_ethtool_ops.o \
		net/ys_ext_ethtool.o \
		net/ys_ndev_ops.o \
		net/ys_devlink_ops.o \
		net/lan/ys_lan.o \
		net/lan/k2ulan/ys_k2ulan.o \
		net/mac/ys_mac.o \
		net/mac/cmac/ys_cmac.o \
		net/mac/umac/ys_umac.o \
		net/mac/xmac/ys_xmac.o \
		net/tc/ys_tc.o \
		net/ppp/ys_cuckoo_hash.o \
		net/lan/k2ulan/ys_k2ulan_cuckoo.o

ifeq ($(CONFIG_YSMOD_CDEV), y)
	EXTRA_CFLAGS += -DCONFIG_YSMOD_CDEV
endif

ifeq ($(CONFIG_YSMOD_MAC), c)
	EXTRA_CFLAGS += -DCONFIG_YSMOD_MAC
	EXTRA_CFLAGS += -DCONFIG_YSMOD_CMAC
else ifeq ($(CONFIG_YSMOD_MAC), u)
	EXTRA_CFLAGS += -DCONFIG_YSMOD_MAC
	EXTRA_CFLAGS += -DCONFIG_YSMOD_UMAC
else ifeq ($(CONFIG_YSMOD_MAC), x)
	EXTRA_CFLAGS += -DCONFIG_YSMOD_MAC
	EXTRA_CFLAGS += -DCONFIG_YSMOD_XMAC
endif

ifeq ($(CONFIG_YSMOD_LAN), k2u)
	EXTRA_CFLAGS += -DCONFIG_YSMOD_LAN
	EXTRA_CFLAGS += -DCONFIG_YSMOD_LAN_K2U
endif

ifeq ($(CONFIG_YSMOD_NP), k2u)
	EXTRA_CFLAGS += -DCONFIG_YSMOD_NP
	EXTRA_CFLAGS += -DCONFIG_YSMOD_NP_K2U
endif

ifeq ($(CONFIG_YSHW_K2ULTRA), m)
	HW_DIR := k2ultra
	EXTRA_CFLAGS += -DCONFIG_YSHW_K2ULTRA
else ifeq ($(CONFIG_YSHW_K2ULTRA_U200), m)
	HW_DIR := k2ultra
	EXTRA_CFLAGS += -DCONFIG_YSHW_K2ULTRA_U200
else ifeq ($(CONFIG_YSHW_K2ULTRA_CS), m)
	HW_DIR := k2ultra
	EXTRA_CFLAGS += -DCONFIG_YSHW_K2ULTRA_U200
endif

ifeq ($(CONFIG_YSARCH_PLAT), y)
	obj-m += ysk_platform.o
	DRV_OBJS_PLAT := $(DRV_OBJS)
	NET_OBJS_PLAT := $(NET_OBJS)
	ysk_platform-objs += $(DRV_OBJS_PLAT)
	ysk_platform-objs += $(NET_OBJS_PLAT)
	EXTRA_CFLAGS += -DCONFIG_YSARCH_PLAT
	EXTRA_CFLAGS += -DCONFIG_YSMOD_CDEV
	DRV_OBJS :=
	NET_OBJS :=
endif

AUXILIARY_EXISTS:= $(shell grep -c "YS_HAVE_AUXILIARY_BUS yes" $(PWD)/compat_config.h 2>/dev/null)
AUXILIARY_CHECK := $(shell lsmod | grep -c auxiliary)
AUXILIARY_CONFIG := $(shell grep -c 'CONFIG_AUXILIARY_BUS' /boot/config-$(shell uname -r))
ifeq ($(AUXILIARY_EXISTS), 0)
        ifeq ($(AUXILIARY_CHECK), 0)
		AUXILIARY_INSTALL := yes
                AUXILIARY_MOD_NAME := auxiliary
                AUXILIARY_OBJS := lib/auxiliary_bus/auxiliary.o
                obj-m += $(AUXILIARY_MOD_NAME).o
                $(AUXILIARY_MOD_NAME)-objs := $(AUXILIARY_OBJS)
        endif
else
        ifeq ($(AUXILIARY_CONFIG), 0)
		AUXILIARY_INSTALL := yes
                AUXILIARY_MOD_NAME := auxiliary
                AUXILIARY_OBJS := lib/auxiliary_bus/auxiliary.o
                obj-m += $(AUXILIARY_MOD_NAME).o
                $(AUXILIARY_MOD_NAME)-objs := $(AUXILIARY_OBJS)
        endif
endif

ccflags-y += -Wall -Werror
ccflags-y += -I$(src)/include
ccflags-y += -I$(src)/user_include

KDIR ?= /lib/modules/$(shell uname -r)/build

SYMBDIR ?= ./kernel_compat/symbolsfile

# Check if ysarch is passed as an argument to make command
YSARCH := $(filter double,$(MAKECMDGOALS))
# Compile without other hw directory
YSRELEASETEST := $(filter release_test,$(MAKECMDGOALS))


ifneq ($(wildcard $(PWD)/$(HW_DIR)/Makefile),)
include $(PWD)/$(HW_DIR)/Makefile
endif

all:modules

ver:
	@echo "/* SPDX-License-Identifier: GPL-2.0 */" > ver.h
	@echo "#define YS_GIT_VERSION \"1.9.5\"" >> ver.h
	@echo "#define YS_COMPILE_TIME \"$(shell date +"%Y-%m-%d %H:%M:%S")\"" >> ver.h
	@echo "#define YS_COMPILE_PAGE_SIZE $(shell getconf PAGE_SIZE)" >> ver.h
	@echo "#define YS_GCC_VERSION \"$(shell gcc -dumpversion)\"" >> ver.h
	@echo "#define YS_KERNEL_HEADER_VERSION \"$(KDIR)\"" >> ver.h
	@echo "#define YS_K2U_DRV_VERSION \"$(shell cat $(PWD)/$(HW_DIR)/k2u_ver)\"" >> ver.h
	echo "#define YS_HW_NAME \"K2ULTRA\"" >> ver.h
	echo "#define YS_HW_TYPE \"NDEV\"" >> ver.h
	
compat:
	@rm -f compat_config.h
	@bash ./kernel_compat/autocompat.sh $(KDIR) $(SYMBDIR)

modules:ver compat
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

k2ultra:clean
	@./gen_config.sh k2u
	make -j16

