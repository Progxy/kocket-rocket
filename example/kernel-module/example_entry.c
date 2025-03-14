#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mutex.h> 
#include <linux/kthread.h>
#include <net/sock.h>
#include <net/tcp.h>

#define _KOCKET_CUSTOM_ALLOCATOR_
/// kmalloc wrapper to emulate calloc behaviour
#define kocket_calloc(nmemb, size) kcalloc(nmemb, size, GFP_KERNEL)

/// kmalloc wrapper to emulate realloc behaviour
#define kocket_realloc(ptr, new_size) krealloc(ptr, new_size, GFP_KERNEL)

/// kfree wrapper to emulate free behaviour
#define kocket_free(ptr) kfree(ptr)

#define _KOCKET_PRINTING_UTILS_
#define _KOCKET_UTILS_IMPLEMENTATION_
#include "../../k_kocket.h"

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
