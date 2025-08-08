
DRV_OBJS := platform/ws_init.o \
			platform/ws_pdev.o \
			platform/ws_auxiliary.o \

ccflags-y += -Wall -Werror
ccflags-y += -I$(src)/include

KDIR ?= /lib/modules/$(shell uname -r)/build

ifneq ($(wildcard $(PWD)/ws/Makefile),)
include $(PWD)/ws/Makefile
endif

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
