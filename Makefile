all: user_example kernel_example

user_example:
	make -C ./example/userspace

kernel_example:
	make -C ./example/kernel-module

clean:
	make clean -C ./example/userspace
	make clean -C ./example/kernel-module
