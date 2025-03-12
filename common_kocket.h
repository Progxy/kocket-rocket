/*
 * Copyright (C) 2025 TheProgxy <theprogxy@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _COMMON_KOCKET_H_
#define _COMMON_KOCKET_H_

#ifdef _KOCKET_PRINTING_UTILS_
// -------------------------------
// Printing Macros
// -------------------------------
#define RED           "\033[31m"
#define GREEN         "\033[32m"
#define PURPLE        "\033[35m"
#define CYAN          "\033[36m"
#define BRIGHT_YELLOW "\033[38;5;214m"    
#define RESET_COLOR   "\033[0m"

#define WARNING_COLOR BRIGHT_YELLOW
#define ERROR_COLOR   RED
#define DEBUG_COLOR   PURPLE
#define TODO_COLOR    CYAN

#define COLOR_STR(str, COLOR) COLOR str RESET_COLOR
#define WARNING_LOG(format, ...) printf(COLOR_STR("WARNING:" __FILE__ ":%u: ", BRIGHT_YELLOW) format, __LINE__, ##__VA_ARGS__)
#define TODO(msg) printf(COLOR_STR("TODO: " __FILE__ ":%u: ", TODO_COLOR) msg "\n", __LINE__), assert(FALSE)

#ifdef _DEBUG
	#define DEBUG_LOG(format, ...) printf(COLOR_STR("DEBUG:" __FILE__ ":%u: ", DEBUG_COLOR) format, __LINE__, ##__VA_ARGS__)
#else 
    #define DEBUG_LOG(...)
#endif //_DEBUG

#include "./str_error.h"
#define PERROR_LOG(format, ...) printf(COLOR_STR("WARNING:" __FILE__ ":%u: ", BRIGHT_YELLOW) format ", because: " COLOR_STR("'%s'", BRIGHT_YELLOW) ".\n", __LINE__, ##__VA_ARGS__, str_error())

#endif //_KOCKET_PRINTING_UTILS_

/* -------------------------------------------------------------------------------------------------------- */
// Types and Structs
typedef enum KocketStatus { KOCKET_NO_ERROR = 0, KOCKET_IO_ERROR, KOCKET_TODO } KocketStatus;
static const char* kocket_status_str[] = { "KOCKET_NO_ERROR", "KOCKET_IO_ERROR", "KOCKET_TODO" };

typedef struct PACKED_STRUCT KocketStruct {
	u32 type_id;
	u64 req_id;
	u32 payload_size;
	u8* payload;	
} KocketStruct;

typedef struct KocketType {
	char* type_name;
	bool has_handler;
	KocketHandler kocket_handler;
} KocketType;

typedef struct sockaddr_in ClientKocket;
typedef int (*KocketHandler)(KocketStruct);
typedef struct ServerKocket {
	int socket;
	int backlog;
	unsigned short int port;
	struct sockaddr_in sock_addr;
	KocketType* kocket_types;
	u32 kocket_types_cnt;
	int* clients;
	struct pollfd* polls;
	u32 clients_cnt;
	bool use_secure_connection
} ServerKocket;

typedef struct ClientKocket {
	int socket;
	unsigned short int port;
	struct sockaddr_in sock_addr;
	KocketType* kocket_types;
	u32 kocket_types_cnt;
	struct pollfd poll_fd;
	bool use_secure_connection
} ClientKocket;

typedef struct KocketQueue {
	KocketStruct* kocket_structs;
	u32* kocket_clients_ids;
	struct semaphore sem; // TODO: add guard to switch between the userspace and kernelspace version
	u32 size;
} KocketQueue;

/* -------------------------------------------------------------------------------------------------------- */
// Constant Values
#define KOCKET_PORT 6969

/* -------------------------------------------------------------------------------------------------------- */
// Static Shared Variables
static KocketQueue kocket_writing_queue = {0};
static KocketQueue kocket_reads_queue = {0};

// TODO: add guard to switch between the userspace and kernelspace version
static struct semaphore kocket_status_sem = {0};
static KocketStatus kocket_status = KOCKET_NO_ERROR;

/* -------------------------------------------------------------------------------------------------------- */
int kocket_init_queue(KocketQueue* kocket_queue) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	kocket_queue -> kocket_structs = NULL;
	kocket_queue -> kocket_clients_ids = NULL;
	kocket_queue -> size = 0;
	sema_init(&(kocket_queue -> sem), 1);

	return KOCKET_NO_ERROR;
}

int kocket_deallocate_queue(KocketQueue* kocket_queue) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	if (down_interruptible(&(kocket_queue -> sem))) {
        WARNING_LOG("Failed to acquire the semaphore.\n");
        return -KOCKET_IO_ERROR;
    }
	
	for (u32 i = 0; i < kocket_queue -> size; ++i) SAFE_FREE((kocket_queue -> kocket_structs)[i].payload);
	SAFE_FREE(kocket_queue -> kocket_structs);
	SAFE_FREE(kocket_queue -> kocket_clients_ids);
	kocket_queue -> size = 0;
	
	up(&(kocket_queue -> sem));

	return KOCKET_NO_ERROR;
}

int kocket_enqueue(KocketQueue* kocket_queue, KocketStruct kocket_struct, u32 kocket_client_id) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	if (down_interruptible(&(kocket_queue -> sem))) {
        WARNING_LOG("Failed to acquire the semaphore.\n");
        return -KOCKET_IO_ERROR;
    }
	
	kocket_queue -> kocket_structs = realloc(kocket_queue -> kocket_structs, sizeof(KocketStruct) * (++(kocket_queue -> size)));
	if (kocket_queue -> kocket_structs == NULL) {
		WARNING_LOG("Failed to reallocate the kocket_structs.\n");
		return -KOCKET_IO_ERROR;
	}
	
	(kocket_queue -> kocket_structs)[kocket_queue -> size - 1] = kocket_struct;
	
	kocket_queue -> kocket_clients_ids = realloc(kocket_queue -> kocket_clients_ids, sizeof(int) * kocket_queue -> size);
	if (kocket_queue -> kocket_clients_ids == NULL) {
		WARNING_LOG("Failed to reallocate the kocket_clients_ids.\n");
		return -KOCKET_IO_ERROR;
	}
	
	(kocket_queue -> kocket_clients_ids)[kocket_queue -> size - 1] = kocket_client_id;
		
	up(&(kocket_queue -> sem));

	return KOCKET_NO_ERROR;
}

int kocket_dequeue(KocketQueue* kocket_queue, KocketStruct* kocket_struct, u32* kocket_client_id) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	if (down_interruptible(&(kocket_queue -> sem))) {
        WARNING_LOG("Failed to acquire the semaphore.\n");
        return -KOCKET_IO_ERROR;
    }
	
   	*kocket_struct = (kocket_queue -> kocket_structs)[kocket_queue -> size - 1];
   	*kocket_client_id = (kocket_queue -> kocket_clients_ids)[kocket_queue -> size - 1];
	
	kocket_queue -> kocket_structs = realloc(kocket_queue -> kocket_structs, sizeof(KocketStruct) * (--(kocket_queue -> size)));
	if (kocket_queue -> kocket_structs == NULL) {
		WARNING_LOG("Failed to reallocate the kocket_structs.\n");
		return -KOCKET_IO_ERROR;
	}
	
	kocket_queue -> kocket_clients_ids = realloc(kocket_queue -> kocket_clients_ids, sizeof(int) * kocket_queue -> size);
	if (kocket_queue -> kocket_clients_ids == NULL) {
		WARNING_LOG("Failed to reallocate the kocket_clients_ids.\n");
		return -KOCKET_IO_ERROR;
	}
		
	up(&(kocket_queue -> sem));
	
	return KOCKET_NO_ERROR;
}

int is_kocket_queue_empty(KocketQueue* kocket_queue) {	
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	if (down_interruptible(&(kocket_queue -> sem))) {
        WARNING_LOG("Failed to acquire the semaphore.\n");
        return -KOCKET_IO_ERROR;
    }
	
	u32 queue_size = kocket_queue -> size;

	up(&(kocket_queue -> sem));
	
	return queue_size;
}

int kocket_dequeue_find(KocketQueue* kocket_queue, u64 req_id, KocketStruct* kocket_struct) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	if (down_interruptible(&(kocket_queue -> sem))) {
        WARNING_LOG("Failed to acquire the semaphore.\n");
        return -KOCKET_IO_ERROR;
    }
	
	for (index = 0; i < kocket_queue -> size; ++i) {
		if ((kocket_queue -> kocket_structs)[i].req_id == req_id) break;
	}

	if (index >= kocket_queue -> size) {
		up(&(kocket_queue -> sem));
		return -KOCKET_REQ_NOT_FOUND;
	}
	
	*kocket_struct = (kocket_queue -> kocket_structs)[index];
	
	mem_move(kocket_queue -> kocket_structs + index, kocket_queue -> kocket_structs + index + 1, (kocket_queue -> size - 1 - index) * sizeof(KocketStruct));
	mem_move(kocket_queue -> kocket_clients_ids + index, kocket_queue -> kocket_clients_ids + index + 1, (kocket_queue -> size - 1 - index) * sizeof(int));

	kocket_queue -> kocket_structs = realloc(kocket_queue -> kocket_structs, sizeof(KocketStruct) * (--(kocket_queue -> size)));
	if (kocket_queue -> kocket_structs == NULL) {
		WARNING_LOG("Failed to reallocate the kocket_structs.\n");
		return -KOCKET_IO_ERROR;
	}
	
	kocket_queue -> kocket_clients_ids = realloc(kocket_queue -> kocket_clients_ids, sizeof(int) * kocket_queue -> size);
	if (kocket_queue -> kocket_clients_ids == NULL) {
		WARNING_LOG("Failed to reallocate the kocket_clients_ids.\n");
		return -KOCKET_IO_ERROR;
	}
		
	up(&(kocket_queue -> sem));

	return KOCKET_NO_ERROR;
}

#endif //_COMMON_KOCKET_H_

