ad-objs := main.o send_reset.o
obj-m := ad.o
CFLAGS_ad.o := -DDEBUG

KDIR=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm *.o *.ko *.mod.c modules.order Module.symvers
