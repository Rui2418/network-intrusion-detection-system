obj-m += mod_firewall.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(RM) -rf .*.cmd *.mod.c *.o *.ko .tmp*

load:
	sudo insmod mod_firewall.ko
	sudo mknod /dev/firewall c 124 0 2>/dev/null || true

unload:
	sudo rmmod mod_firewall
