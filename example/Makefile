obj-m += kernel_example.o
example-y += example_entry.o 

FLAGS = -std=gnu11 -Wall -Wextra -pedantic -ggdb
DEFINITIONS = -D_DEBUG

example: kernel_example user_example

user_example: user_example.c
	gcc $(FLAGS) $(DEFINITIONS) $< -o $@
	
kernel_example: 
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

