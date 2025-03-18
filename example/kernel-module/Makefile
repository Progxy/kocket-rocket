obj-m += kocket.o
kocket-y += kocket_entry.o 

kernel_example: 
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) EXTRA_AFLAGS="-D_DEBUG" modules

disassemble: kocket.ko
	objdump -dS kocket.ko > kocket_d.S

clean: 
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm *.S
