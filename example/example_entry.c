#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/semaphore.h>

static s32 __init example_init(void) {
	DEBUG_LOG("Module loaded.");
	return 0;
}

static void __exit example_exit(void) {
	DEBUG_LOG("Module unloaded.");
	return;
}

module_init(example_init);
module_exit(example_exit);

// Module metadata
MODULE_AUTHOR("TheProgxy");
MODULE_DESCRIPTION("OSAS: An example kernel module that uses kocket-rocket.");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
