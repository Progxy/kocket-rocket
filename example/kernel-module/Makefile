obj-m += example.o
example-y += example_entry.o 

kernel_example: 
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) EXTRA_AFLAGS="-D_DEBUG" modules

disassemble: example.ko
	objdump -dS example.ko > example_d.S

clean: 
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm *.S
