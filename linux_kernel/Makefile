
DRV_OBJS := platform/ws_init.o \
			platform/ws_pdev.o \
			platform/ws_auxiliary.o \

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
