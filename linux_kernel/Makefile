
DRV_OBJS := platform/ws_init.o \
			platform/ws_pdev.o \
			platform/ws_auxiliary.o \

ccflags-y += -Wall -Werror
ccflags-y += -I$(src)/include

KDIR ?= /lib/modules/$(shell uname -r)/build

ifneq ($(wildcard $(PWD)/ws/Makefile),)
include $(PWD)/ws/Makefile
endif

ver:
	@HW_NAME=; \
	HW_TYPE=; \
	HW_NAME="WS"; \
	HW_TYPE="NDEV"; \
	if [ -n "$$HW_NAME" ]; then \
		echo "#define WS_HW_NAME \"$$HW_NAME\"" >> ver.h; \
		echo "#define WS_HW_TYPE \"$$HW_TYPE\"" >> ver.h; \
	fi

all:ver
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
