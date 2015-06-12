ifeq ($(DEBUG),y)
	# CFLAGS_ad.o doesn't work :(
	CFLAGS_main.o += -DDEBUG
	CFLAGS_send_reset.o += -DDEBUG
	CFLAGS_sfilter.o += -DDEBUG
	CFLAGS_filters.o += -DDEBUG
endif

ifeq ($(ANDROID),y)
	KDIR := ~/android/kernel/android_kernel_samsung_jf
else
	KDIR := /lib/modules/$(shell uname -r)/build
endif

ad-objs := main.o send_reset.o sfilter.o filters.o
obj-m := ad.o

PWD=$(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.c modules.order Module.symvers .tmp_versions
