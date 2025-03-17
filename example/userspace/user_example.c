#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <stdint.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef u8 bool;

#define _KOCKET_PRINTING_UTILS_
#define _KOCKET_UTILS_IMPLEMENTATION_
#include "../../u_kocket.h"

#define HOST_PORT 6969

typedef enum InfoRequestTypes { LOG_BUFFER_SIZE, IS_LOG_BUFFER_EMPTY } InfoRequestTypes;
typedef enum ClientKocketTypes { KOCKET_LOG_TYPE = 0, KOCKET_INFO_REQUEST } ClientKocketTypes;

int log_handler(KocketStruct kocket_struct) {
	DEBUG_LOG("SERVER_INFO: '%s'\n", kocket_struct.payload);
	return KOCKET_NO_ERROR;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		DEBUG_LOG("Usage: user_example <ip address>\n");
		return -1;
	}
	
	KocketType kocket_log_type = {
		.type_name = "LOG",
	   	.has_handler = TRUE,
		.kocket_handler = log_handler
   	};

	KocketType kocket_info_request_type = {
		.type_name = "INFO_REQUEST",
		.has_handler = FALSE,
		.kocket_handler = NULL
	};
	
	KocketType kocket_types[] = { kocket_log_type, kocket_info_request_type };
	
	int err = 0;
	ClientKocket kocket = {0};
	DEBUG_LOG("Connecting to address '%s' on port %u\n", argv[1], HOST_PORT);
	if ((err = kocket_addr_to_bytes(argv[1], &kocket.address)) < 0) {
		WARNING_LOG("An error occurred while converting the address from string to bytes.\n");
		return err;
	}
	
	kocket.port = HOST_PORT;
	kocket.kocket_types = kocket_types;
	kocket.kocket_types_cnt = KOCKET_ARR_SIZE(kocket_types);
	kocket.use_secure_connection = FALSE;
	
	if ((err = kocket_init(kocket)) < 0) {
		ERROR_LOG("An error occurred while initializing the kocket.\n", kocket_status_str[-err]);
		return err;
	}

	// Randomly exchange some data with the server
	KocketStruct info_request = {0};
	info_request.type_id = KOCKET_INFO_REQUEST;
	info_request.payload_size = sizeof(InfoRequestTypes);
	info_request.payload = (u8*) kocket_calloc(sizeof(InfoRequestTypes), sizeof(u8));
	if (info_request.payload == NULL) {
		WARNING_LOG("Failed to allocate the payload.\n");
		int ret = 0;
		if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
			ERROR_LOG("An error occurred while de-initializing the kocket.\n", kocket_status_str[-ret]);
			return ret;
		}
		return -1;
	}
	
	mem_cpy(info_request.payload, LOG_BUFFER_SIZE, sizeof(InfoRequestTypes));
	
	if ((err = kocket_write(&info_request)) < 0) {
		ERROR_LOG("An error occurred while writing to the kocket.\n", kocket_status_str[-err]);
		int ret = 0;
		if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
			ERROR_LOG("An error occurred while de-initializing the kocket.\n", kocket_status_str[-ret]);
			return ret;
		}
		return err;
	}

	KocketStruct info_request_response = {0};
	if ((err = kocket_read(info_request.req_id, &info_request_response, FALSE)) < 0) {
		ERROR_LOG("An error occurred while reading from the kocket.\n", kocket_status_str[-err]);
		int ret = 0;
		if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
			ERROR_LOG("An error occurred while de-initializing the kocket.\n", kocket_status_str[-ret]);
			return ret;
		}
		return err;
	}

	if (info_request_response.payload_size != sizeof(u32)) {
		KOCKET_SAFE_FREE(info_request_response.payload);
		WARNING_LOG("Payload size doesn't match: found %u, but expected: %lu.\n", info_request_response.payload_size, sizeof(u32));
		int ret = 0;
		if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
			ERROR_LOG("An error occurred while de-initializing the kocket.\n", kocket_status_str[-ret]);
			return ret;
		}
		return -KOCKET_INVALID_PAYLOAD_SIZE;
	} else if (*KOCKET_CAST_PTR(info_request_response.payload, int) < 0) {
		KOCKET_SAFE_FREE(info_request_response.payload);
		WARNING_LOG("The server returned an error code: %d.\n", *KOCKET_CAST_PTR(info_request_response.payload, int));
		int ret = 0;
		if ((ret = kocket_deinit(-KOCKET_IO_ERROR)) < 0) {
			ERROR_LOG("An error occurred while de-initializing the kocket.\n", kocket_status_str[-ret]);
			return ret;
		}
		return -KOCKET_INVALID_PAYLOAD_SIZE;
	}

	DEBUG_LOG("Logbuffer size: %lu\n", *KOCKET_CAST_PTR(info_request_response.payload + sizeof(u32), u64));

	KOCKET_SAFE_FREE(info_request_response.payload);
		
	if ((err = kocket_deinit(KOCKET_NO_ERROR)) < 0) {
		ERROR_LOG("An error occurred while de-initializing the kocket.\n", kocket_status_str[-err]);
		return err;
	}
	
	return 0;
}
