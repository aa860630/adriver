ifeq ($(DEBUG),y)
	# CFLAGS_ad.o doesn't work :(
	CFLAGS_main.o += -DDEBUG
	CFLAGS_send_reset.o += -DDEBUG
	CFLAGS_sfilter.o += -DDEBUG
endif

ad-objs := main.o send_reset.o sfilter.o
obj-m := ad.o

KDIR=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.c modules.order Module.symvers .tmp_versions
