KERN_DIR = /lib/modules/$(shell uname -r)/build
fw-objs := firewall.o
obj-m += fw.o

all:
	make -C $(KERN_DIR) M=$(shell pwd) modules   
clean:                                  
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf modules.order
	rm -f *.symvers
load:
	make clean
	make 
	sudo insmod fw.ko
unload:
	make clean
	sudo rmmod fw