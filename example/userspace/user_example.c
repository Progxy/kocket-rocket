#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <fcntl.h>

#include <stdint.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#define _KOCKET_PRINTING_UTILS_
#define _KOCKET_UTILS_IMPLEMENTATION_
#include "../../u_kocket.h"

int log_handler(KocketStruct kocket_struct) {
	printf("SERVER_INFO: '%s'\n", kocket_struct.payload);
	return KOCKET_NO_ERROR;
}

typedef enum ClientKocketTypes { KOCKET_LOG_TYPE = 0, KOCKET_INFO_REQUEST } ClientKocketTypes;
typedef enum InfoRequestTypes { LOG_BUFFER_SIZE, IS_LOG_BUFFER_EMPTY } InfoRequestTypes;

#define HOST_PORT 6969
#define HOST_ADDRESS "127.0.0.1"
int main(void) {
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
	
	ClientKocket kocket = {0};
	kocket.port = HOST_PORT;
	kocket.address = kocket_addr_to_bytes(HOST_ADDRESS);
	kocket.kocket_types = kocket_types;
	kocket.kocket_types_cnt = KOCKET_ARR_SIZE(kocket_types);
	kocket.secure_connection = FALSE;
	pthread_t kocket_thread = 0;
	if ((err = kocket_init(&kocket, &kocket_thread)) < 0) {
		ERROR_LOG("An error occurred while initializing the kocket.\n", kocket_status_str[-err]);
		return err;
	}

	// Randomly exchange some data with the server
	KocketStruct info_request = {0};
	info_request.type_id = KOCKET_LOG_TYPE;
	info_request.payload_size = sizeof(u32) + sizeof(InfoRequestType);
	if ((err = kocket_write(info_request)) < 0) {
		ERROR_LOG("An error occurred while writing to the kocket.\n", kocket_status_str[-err]);
		return err;
	}

	KOCKET_SAFE_FREE(info_request_payload);

	KocketStruct info_request_response = {0};
	if ((err = kocket_read(info_request.req_id, &info_request_response, FALSE)) < 0) {
		ERROR_LOG("An error occurred while reading from the kocket.\n", kocket_status_str[-err]);
		return err;
	}

	if (info_request_response.payload_size != (sizeof(u32) + sizeof(u64))) {
		WARNING_LOG("Payload size doesn't match: found %lu, but expected: %lu.\n", info_request_response.payload_size, sizeof(u32) + sizeof(u64));
		return -KOCKET_INVALID_PAYLOAD_SIZE;
	}

	printf("Logbuffer size: %lu\n", *CAST_PTR(info_request_response.payload + sizeof(u32), u64));

	KOCKET_SAFE_FREE(info_request_response.payload);
		
	if ((err = kocket_deinit(&kocket, KOCKET_NO_ERROR, kocket_thread)) < 0) {
		ERROR_LOG("An error occurred while de-initializing the kocket.\n", kocket_status_str[-err]);
		return err;
	}
	
	return 0;
}
