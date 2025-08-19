# SPDX-License-Identifier: GPL-2.0

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
		platform/ys_vdpa.o \
		platform/ysif_linux.o \
		

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

ccflags-y += -Wall -Werror
ccflags-y += -I$(src)/include
ccflags-y += -I$(src)/user_include

ccflags-y += -DCONFIG_YSMOD_CDEV
ccflags-y += -DCONFIG_YSMOD_MAC
ccflags-y += -DCONFIG_YSMOD_XMAC
ccflags-y += -DCONFIG_YSMOD_LAN
ccflags-y += -DCONFIG_YSMOD_LAN_K2U
ccflags-y += -DCONFIG_YSMOD_NP
ccflags-y += -DCONFIG_YSMOD_NP_K2U
ccflags-y += -DCONFIG_YSHW_K2ULTRA

KDIR ?= /lib/modules/$(shell uname -r)/build
SYMBDIR ?= ./kernel_compat/symbolsfile

include $(PWD)/k2ultra/Makefile

all:modules

ver:
	@echo "/* SPDX-License-Identifier: GPL-2.0 */" > ver.h
	@echo "#define YS_GIT_VERSION \"1.9.5\"" >> ver.h
	@echo "#define YS_COMPILE_TIME \"$(shell date +"%Y-%m-%d %H:%M:%S")\"" >> ver.h
	@echo "#define YS_COMPILE_PAGE_SIZE $(shell getconf PAGE_SIZE)" >> ver.h
	@echo "#define YS_GCC_VERSION \"$(shell gcc -dumpversion)\"" >> ver.h
	@echo "#define YS_KERNEL_HEADER_VERSION \"$(KDIR)\"" >> ver.h
	@echo "#define YS_K2U_DRV_VERSION \"$(shell cat $(PWD)/k2ultra/k2u_ver)\"" >> ver.h
	@echo "#define YS_HW_NAME \"K2ULTRA\"" >> ver.h
	@echo "#define YS_HW_TYPE \"NDEV\"" >> ver.h

# bash ./kernel_compat/autocompat.sh /lib/modules/$(uname -r)/build ./kernel_compat/symbolsfile
compat:
	@rm -f compat_config.h
# @bash ./kernel_compat/autocompat.sh $(KDIR) $(SYMBDIR)

modules:ver compat
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

k2ultra:clean
	@./gen_config.sh k2u
	make -j16

