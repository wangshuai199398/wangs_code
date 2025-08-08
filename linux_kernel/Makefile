
DRV_OBJS := platform/ws_init.o \
            platform/ws_pdev.o \
			platform/ws_auxiliary.o \


all:clean
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
