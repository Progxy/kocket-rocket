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

/* -------------------------------------------------------------------------------------------------------- */
// -----------------
//  Macros and Enums
// -----------------
#define HOST_PORT 6969
#define HOST_ADDRESS "127.0.0.1"

typedef enum InfoRequestTypes { LOG_BUFFER_SIZE, IS_LOG_BUFFER_EMPTY } InfoRequestTypes;
typedef enum ClientKocketTypes { KOCKET_LOG_TYPE = 0, KOCKET_INFO_REQUEST } ClientKocketTypes;

/* -------------------------------------------------------------------------------------------------------- */
// ------------------------
//  Functions Declarations
// ------------------------
// TODO: Remove the \n from all the places where it could be printed to kernel ring buffer
int info_request_handler(u32 kocket_client_id, KocketPacket kocket_packet);

/* -------------------------------------------------------------------------------------------------------- */
int info_request_handler(u32 kocket_client_id, KocketPacket kocket_packet) {
	KocketPacket info_req_res = {0};
	info_req_res.type_id = KOCKET_INFO_REQUEST;
	info_req_res.payload_size = sizeof(InfoRequestTypes);
	info_req_res.payload = (u8*) kocket_calloc(sizeof(InfoRequestTypes), sizeof(u8));
	
	if (info_req_res.payload == NULL) {
		int ret = 0;
		if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
			ERROR_LOG("An error occurred while de-initializing the kocket.", kocket_status_str[-ret]);
			return ret;
		}
		WARNING_LOG("Failed to allocate the payload.");
		return -1;
	}
	
	int err = 0;
	InfoRequestTypes info_req = *KOCKET_CAST_PTR(kocket_packet.payload, InfoRequestTypes);
	if (info_req == LOG_BUFFER_SIZE) {
		int val = 512;
		mem_cpy(info_req_res.payload, &val, sizeof(InfoRequestTypes));
		
		if ((err = kocket_write(kocket_client_id, &info_req_res)) < 0) {
			KOCKET_SAFE_FREE(info_req_res.payload);
			int ret = 0;
			if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
				ERROR_LOG("An error occurred while de-initializing the kocket.", kocket_status_str[-ret]);
				return ret;
			}
			ERROR_LOG("An error occurred while writing to the kocket.", kocket_status_str[-err]);
			return err;
		}

		KOCKET_SAFE_FREE(info_req_res.payload);
		
		return KOCKET_NO_ERROR;
	} else if (info_req == IS_LOG_BUFFER_EMPTY) {
		int val = 0;
		mem_cpy(info_req_res.payload, &val, sizeof(InfoRequestTypes));
		
		if ((err = kocket_write(kocket_client_id, &info_req_res)) < 0) {
			KOCKET_SAFE_FREE(info_req_res.payload);
			int ret = 0;
			if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
				ERROR_LOG("An error occurred while de-initializing the kocket.", kocket_status_str[-ret]);
				return ret;
			}
			ERROR_LOG("An error occurred while writing to the kocket.", kocket_status_str[-err]);
			return err;
		}

		KOCKET_SAFE_FREE(info_req_res.payload);
		
		return KOCKET_NO_ERROR;
	}
	
	int val = -1;
	mem_cpy(info_req_res.payload, &val, sizeof(InfoRequestTypes));
	
	if ((err = kocket_write(kocket_client_id, &info_req_res)) < 0) {
		KOCKET_SAFE_FREE(info_req_res.payload);
		int ret = 0;
		if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
			ERROR_LOG("An error occurred while de-initializing the kocket.", kocket_status_str[-ret]);
			return ret;
		}
		ERROR_LOG("An error occurred while writing to the kocket.", kocket_status_str[-err]);
		return err;
	}

	KOCKET_SAFE_FREE(info_req_res.payload);

	return KOCKET_NO_ERROR;
}

static s32 __init example_init(void) {
	KocketType kocket_log_type = {
		.type_name = "LOG",
	   	.has_handler = FALSE,
		.kocket_handler = NULL
   	};

	KocketType kocket_info_request_type = {
		.type_name = "INFO_REQUEST",
		.has_handler = TRUE,
		.kocket_handler = info_request_handler
	};
	
	KocketType kocket_types[] = { kocket_log_type, kocket_info_request_type };
	
	int err = 0;
	ServerKocket kocket = {0};
	kocket.backlog = 5;
	kocket.port = HOST_PORT;
	kocket.address = INADDR_ANY;
	kocket.kocket_types = kocket_types;
	kocket.kocket_types_cnt = KOCKET_ARR_SIZE(kocket_types);
	kocket.use_secure_connection = FALSE;
	
	if ((err = kocket_init(kocket)) < 0) {
		ERROR_LOG("An error occurred while initializing the kocket.", kocket_status_str[-err]);
		return err;
	}

	// Randomly exchange some data with the client
	KocketPacket log_msg = {0};
	log_msg.type_id = KOCKET_LOG_TYPE;
	const char log_payload[] = "Here is some data.\n";
	log_msg.payload_size = KOCKET_ARR_SIZE(log_payload);
	log_msg.payload = (u8*) kocket_calloc(log_msg.payload_size, sizeof(u8));
	if (log_msg.payload == NULL) {
		int ret = 0;
		if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
			ERROR_LOG("An error occurred while de-initializing the kocket.", kocket_status_str[-ret]);
			return ret;
		}
		WARNING_LOG("Failed to allocate buffer for payload.\n");
		return -1;
	}
	mem_cpy(log_msg.payload, log_payload, log_msg.payload_size);
	
	if ((err = kocket_write(0, &log_msg)) < 0) {
		int ret = 0;
		if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
			ERROR_LOG("An error occurred while de-initializing the kocket.", kocket_status_str[-ret]);
			return ret;
		}
		ERROR_LOG("An error occurred while writing to the kocket.", kocket_status_str[-err]);
		return err;
	}

	KocketPacket log_sec_msg = {0};
	log_sec_msg.type_id = KOCKET_LOG_TYPE;
	const char log_sec_payload[] = "Here is some data again.\n";
	log_sec_msg.payload_size = KOCKET_ARR_SIZE(log_sec_payload);
	log_sec_msg.payload = (u8*) kocket_calloc(log_sec_msg.payload_size, sizeof(u8));
	if (log_sec_msg.payload == NULL) {
		int ret = 0;
		if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
			ERROR_LOG("An error occurred while de-initializing the kocket.", kocket_status_str[-ret]);
			return ret;
		}
		WARNING_LOG("Failed to allocate buffer for payload.");
		return -1;
	}
	mem_cpy(log_sec_msg.payload, log_sec_payload, log_sec_msg.payload_size);

	if ((err = kocket_write(0, &log_msg)) < 0) {
		int ret = 0;
		if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
			ERROR_LOG("An error occurred while de-initializing the kocket.", kocket_status_str[-ret]);
			return ret;
		}
		ERROR_LOG("An error occurred while writing to the kocket.", kocket_status_str[-err]);
		return err;
	}
	
	DEBUG_LOG("Module loaded.");
	return 0;
}

static void __exit example_exit(void) {
	int err = 0;
	if ((err = kocket_deinit(KOCKET_NO_ERROR)) < 0) {
		ERROR_LOG("An error occurred while de-initializing the kocket.", kocket_status_str[-err]);
		return;
	}

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
