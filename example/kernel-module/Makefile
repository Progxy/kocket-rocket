obj-m += example.o
example-y += example_entry.o 

kernel_example: 
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

clean: 
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
