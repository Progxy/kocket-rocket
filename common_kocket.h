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

// ----------------
//  Utility Macros
// ----------------
#ifndef _KOCKET_CUSTOM_ALLOCATOR_
#define kocket_realloc realloc
#define kocket_calloc  calloc
#define kocket_free    free
#endif //_KOCKET_CUSTOM_ALLOCATOR_

#if !defined(kocket_free) || !defined(kocket_calloc) || !defined(kocket_realloc)
	#error "kocket_free, kocket_calloc and kocket_realloc, must be either customly defined, or you should just use the macros already provided."
	#include <stophere>
#endif // CHECK_ALLOCATIONS

#define KOCKET_SAFE_FREE(ptr) do { if ((ptr) != NULL) { kocket_free(ptr); (ptr) = NULL; } } while (0) 
#define KOCKET_ARR_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define KOCKET_IS_NUM(chr) ((48 <= (chr)) && ((chr) <= 57))
#define KOCKET_CAST_PTR(ptr, type) ((type*) (ptr))
#define NO_INLINE __attribute__((__noinline__))
#define PACKED_STRUCT __attribute__((packed))
#define KOCKET_CHAR_TO_NUM(chr) ((chr) - 48)

#ifndef TRUE
#define FALSE 0
#define TRUE  1
#endif //TRUE

#ifdef _U_KOCKET_H_
	#define print printf
#else
	#define print(fmt, ...) printk(KERN_WARNING fmt, ##__VA_ARGS__)
#endif //_U_KOCKET_H_

// -------------------------------
// Printing Macros
// -------------------------------
#ifdef _KOCKET_PRINTING_UTILS_
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
#define WARNING_LOG(format, ...) print(COLOR_STR("WARNING:" __FILE__ ":%u: ", WARNING_COLOR) format, __LINE__, ##__VA_ARGS__)
#define ERROR_LOG(format, error_str, ...) print(COLOR_STR("KOCKET_ERROR:%s:" __FILE__ ":%u: ", ERROR_COLOR) format, error_str, __LINE__, ##__VA_ARGS__)
#define TODO(msg) print(COLOR_STR("TODO: " __FILE__ ":%u: ", TODO_COLOR) msg "\n", __LINE__), assert(FALSE)

#ifdef _DEBUG
	#ifdef _U_KOCKET_H_	
		#define DEBUG_LOG(format, ...) print(COLOR_STR("DEBUG:" __FILE__ ":%u: ", DEBUG_COLOR) format, __LINE__, ##__VA_ARGS__)
	#else
		#define DEBUG_LOG(format, ...) printk(KERN_INFO COLOR_STR("DEBUG:" __FILE__ ":%u: ", DEBUG_COLOR) format, __LINE__, ##__VA_ARGS__)
	#endif //_U_KOCKET_H_
#else 
    #define DEBUG_LOG(...)
#endif //_DEBUG

#include "./str_error.h"
#ifdef _U_KOCKET_H_
#define PERROR_LOG(format, ...) print(COLOR_STR("WARNING:" __FILE__ ":%u: ", WARNING_COLOR) format ", because: " COLOR_STR("'%s'", BRIGHT_YELLOW) ".\n", __LINE__, ##__VA_ARGS__, str_error())
#else
#define PERROR_LOG(format, err, ...) print(COLOR_STR("WARNING:" __FILE__ ":%u: ", WARNING_COLOR) format ", because: " COLOR_STR("'%s'", BRIGHT_YELLOW) ".\n", __LINE__, ##__VA_ARGS__, str_error(err))
#endif //_U_KOCKET_H_

#endif //_KOCKET_PRINTING_UTILS_

/* -------------------------------------------------------------------------------------------------------- */
#ifdef _KOCKET_UTILS_IMPLEMENTATION_

static void mem_move(void* dest, const void* src, size_t size) {
    if (dest == NULL || src == NULL || size == 0) return;
    
	unsigned char* temp = (unsigned char*) kocket_calloc(size, sizeof(unsigned char));
	for (size_t i = 0; i < size; ++i) *KOCKET_CAST_PTR(temp + i, unsigned char) = *KOCKET_CAST_PTR(KOCKET_CAST_PTR(src, unsigned char) + i, unsigned char); 
    for (size_t i = 0; i < size; ++i) *KOCKET_CAST_PTR(KOCKET_CAST_PTR(dest, unsigned char) + i, unsigned char) = *KOCKET_CAST_PTR(temp + i, unsigned char);
    
	KOCKET_SAFE_FREE(temp);
    
    return;
}

static void* mem_cpy(void* dest, const void* src, size_t size) {
	if (dest == NULL || src == NULL) return NULL;
	for (size_t i = 0; i < size; ++i) KOCKET_CAST_PTR(dest, unsigned char)[i] = KOCKET_CAST_PTR(src, unsigned char)[i];
	return dest;
}

#define mem_set(ptr, value, size)    mem_set_var(ptr, value, size, sizeof(u8))
#define mem_set_32(ptr, value, size) mem_set_var(ptr, value, size, sizeof(u32))
#define mem_set_64(ptr, value, size) mem_set_var(ptr, value, size, sizeof(u64))
static void mem_set_var(void* ptr, int value, size_t size, size_t val_size) {
	if (ptr == NULL) return;
	for (size_t i = 0; i < size; ++i) KOCKET_CAST_PTR(ptr, unsigned char)[i] = KOCKET_CAST_PTR(&value, unsigned char)[i % val_size]; 
	return;
}

#endif // _KOCKET_UTILS_IMPLEMENTATION_

/* -------------------------------------------------------------------------------------------------------- */
// Types and Structs
typedef enum KocketStatus { 
	KOCKET_NO_ERROR = 0, 
	KOCKET_IO_ERROR, 
	KOCKET_REQ_NOT_FOUND, 
	KOCKET_THREAD_STOP, 
	KOCKET_INVALID_PAYLOAD_SIZE,
	KOCKET_INVALID_STR_ADDR,
	KOCKET_INVALID_PARAMETERS,
	INVALID_KOCKET_CLIENT_ID,
	KOCKET_TODO 
} KocketStatus;
static const char* kocket_status_str[] = { 
	"KOCKET_NO_ERROR", 
	"KOCKET_IO_ERROR", 
	"KOCKET_REQ_NOT_FOUND", 
	"KOCKET_THREAD_STOP", 
	"KOCKET_INVALID_PAYLOAD_SIZE",
	"KOCKET_INVALID_STR_ADDR",
	"KOCKET_INVALID_PARAMETERS",
	"INVALID_KOCKET_CLIENT_ID",
	"KOCKET_TODO"
};

#ifdef _U_KOCKET_H_
	#include <pthread.h>
	typedef pthread_mutex_t mutex_t;
	#define mutex_init(mutex_lock) pthread_mutex_init((mutex_lock), NULL)
	#define mutex_lock             pthread_mutex_lock
	#define mutex_unlock           pthread_mutex_unlock
	#define mutex_destroy          pthread_mutex_destroy
#else
	typedef struct mutex mutex_t;
	#define mutex_destroy mutex_unlock
#endif //_U_KOCKET_H_

// TODO: Should probably change KocketStruct with KocketPacket or something similar
typedef struct PACKED_STRUCT KocketStruct {
	u32 type_id;
	u64 req_id;
	u32 payload_size;
	u8* payload;	
} KocketStruct;

#ifdef _U_KOCKET_H_
	typedef int (*KocketHandler)(KocketStruct);
#else
	typedef int (*KocketHandler)(u32, KocketStruct);
#endif //_U_KOCKET_H_

typedef struct KocketType {
	char* type_name;
	bool has_handler;
	KocketHandler kocket_handler;
} KocketType;

#ifdef _K_KOCKET_H_
typedef struct PollSocket {
	u32 reg_events;
	struct socket* socket;
} PollSocket;

typedef struct ServerKocket {
	struct socket* socket;
	int backlog;
	unsigned short int port;
	unsigned int address;
	struct sockaddr_in sock_addr;
	KocketType* kocket_types;
	u32 kocket_types_cnt;
	struct socket** clients;
	PollSocket* poll_sockets;
	u32 clients_cnt;
	bool use_secure_connection;
} ServerKocket;

#else

typedef struct ClientKocket {
	int socket;
	unsigned short int port;
	unsigned int address;
	struct sockaddr_in sock_addr;
	KocketType* kocket_types;
	u32 kocket_types_cnt;
	struct pollfd poll_fd;
	bool use_secure_connection;
} ClientKocket;

#endif //_K_KOCKET_H_

typedef struct KocketQueue {
	KocketStruct* kocket_structs;
	u32* kocket_clients_ids;
	mutex_t lock;
	u32 size;
} KocketQueue;

/* -------------------------------------------------------------------------------------------------------- */
// Constant Values
#define KOCKET_TIMEOUT_MS 1000 // NOTE: This value should be changed based on the requirement of the operational environment.
#define KOCKET_PORT       6969

/* -------------------------------------------------------------------------------------------------------- */
// Static Shared Variables
static KocketQueue kocket_writing_queue = {0};
static KocketQueue kocket_reads_queue = {0};

static KocketStatus kocket_status = KOCKET_NO_ERROR;
static mutex_t kocket_status_lock = {0};

/* -------------------------------------------------------------------------------------------------------- */
// ------------------------
//  Functions Declarations
// ------------------------
int kocket_alloc_queue(KocketQueue* kocket_queue);
int kocket_deallocate_queue(KocketQueue* kocket_queue);
int kocket_enqueue(KocketQueue* kocket_queue, KocketStruct kocket_struct, u32 kocket_client_id);
int kocket_dequeue(KocketQueue* kocket_queue, KocketStruct* kocket_struct, u32* kocket_client_id);
int is_kocket_queue_empty(KocketQueue* kocket_queue) ;
int kocket_dequeue_find(KocketQueue* kocket_queue, u64 req_id, KocketStruct* kocket_struct);
int kocket_queue_get_n_client_id(KocketQueue* kocket_queue, u32 index, u32* kocket_client_id);
int kocket_addr_to_bytes(const char* str_addr, u32* bytes_addr);

/* -------------------------------------------------------------------------------------------------------- */
int kocket_alloc_queue(KocketQueue* kocket_queue) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	kocket_queue -> kocket_structs = NULL;
	kocket_queue -> kocket_clients_ids = NULL;
	kocket_queue -> size = 0;

	mutex_init(&(kocket_queue -> lock));

	return KOCKET_NO_ERROR;
}

int kocket_deallocate_queue(KocketQueue* kocket_queue) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	mutex_lock(&(kocket_queue -> lock));
	
	DEBUG_LOG("kocket_queue -> size: %u\n", kocket_queue -> size);
	for (u32 i = 0; i < kocket_queue -> size; ++i) KOCKET_SAFE_FREE((kocket_queue -> kocket_structs)[i].payload);
	KOCKET_SAFE_FREE(kocket_queue -> kocket_structs);
	KOCKET_SAFE_FREE(kocket_queue -> kocket_clients_ids);
	kocket_queue -> size = 0;
	
	mutex_destroy(&(kocket_queue -> lock));

	return KOCKET_NO_ERROR;
}

int kocket_enqueue(KocketQueue* kocket_queue, KocketStruct kocket_struct, u32 kocket_client_id) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	mutex_lock(&(kocket_queue -> lock));
	
	kocket_queue -> kocket_structs = kocket_realloc(kocket_queue -> kocket_structs, sizeof(KocketStruct) * (++(kocket_queue -> size)));
	if (kocket_queue -> kocket_structs == NULL) {
		mutex_unlock(&(kocket_queue -> lock));
		WARNING_LOG("Failed to reallocate the kocket_structs.\n");
		return -KOCKET_IO_ERROR;
	}
	
	(kocket_queue -> kocket_structs)[kocket_queue -> size - 1] = kocket_struct;
	
	kocket_queue -> kocket_clients_ids = kocket_realloc(kocket_queue -> kocket_clients_ids, sizeof(int) * kocket_queue -> size);
	if (kocket_queue -> kocket_clients_ids == NULL) {
		mutex_unlock(&(kocket_queue -> lock));
		WARNING_LOG("Failed to reallocate the kocket_clients_ids.\n");
		return -KOCKET_IO_ERROR;
	}
	
	(kocket_queue -> kocket_clients_ids)[kocket_queue -> size - 1] = kocket_client_id;
		
	mutex_unlock(&(kocket_queue -> lock));

	return KOCKET_NO_ERROR;
}

int kocket_dequeue(KocketQueue* kocket_queue, KocketStruct* kocket_struct, u32* kocket_client_id) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	mutex_lock(&(kocket_queue -> lock));
	
   	*kocket_struct = (kocket_queue -> kocket_structs)[kocket_queue -> size - 1];
   	*kocket_client_id = (kocket_queue -> kocket_clients_ids)[kocket_queue -> size - 1];
	
	kocket_queue -> kocket_structs = kocket_realloc(kocket_queue -> kocket_structs, sizeof(KocketStruct) * (--(kocket_queue -> size)));
	if (kocket_queue -> kocket_structs == NULL) {
		mutex_unlock(&(kocket_queue -> lock));
		WARNING_LOG("Failed to reallocate the kocket_structs.\n");
		return -KOCKET_IO_ERROR;
	}
	
	kocket_queue -> kocket_clients_ids = kocket_realloc(kocket_queue -> kocket_clients_ids, sizeof(int) * kocket_queue -> size);
	if (kocket_queue -> kocket_clients_ids == NULL) {
		mutex_unlock(&(kocket_queue -> lock));
		WARNING_LOG("Failed to reallocate the kocket_clients_ids.\n");
		return -KOCKET_IO_ERROR;
	}
		
	mutex_unlock(&(kocket_queue -> lock));
	
	return KOCKET_NO_ERROR;
}

int is_kocket_queue_empty(KocketQueue* kocket_queue) {	
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	mutex_lock(&(kocket_queue -> lock));
	
	u32 queue_size = kocket_queue -> size;
	
	mutex_unlock(&(kocket_queue -> lock));
	
	return queue_size;
}

int kocket_dequeue_find(KocketQueue* kocket_queue, u64 req_id, KocketStruct* kocket_struct) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	mutex_lock(&(kocket_queue -> lock));
	
	u32 index = 0;
	for (index = 0; index < kocket_queue -> size; ++index) {
		if ((kocket_queue -> kocket_structs)[index].req_id == req_id) break;
	}

	if (index >= kocket_queue -> size) {
		mutex_unlock(&(kocket_queue -> lock));
		return KOCKET_REQ_NOT_FOUND;
	}
	
	*kocket_struct = (kocket_queue -> kocket_structs)[index];
	
	mem_move(kocket_queue -> kocket_structs + index, kocket_queue -> kocket_structs + index + 1, (kocket_queue -> size - 1 - index) * sizeof(KocketStruct));
	mem_move(kocket_queue -> kocket_clients_ids + index, kocket_queue -> kocket_clients_ids + index + 1, (kocket_queue -> size - 1 - index) * sizeof(int));

	kocket_queue -> kocket_structs = kocket_realloc(kocket_queue -> kocket_structs, sizeof(KocketStruct) * (--(kocket_queue -> size)));
	if (kocket_queue -> kocket_structs == NULL) {
		mutex_unlock(&(kocket_queue -> lock));
		WARNING_LOG("Failed to reallocate the kocket_structs.\n");
		return -KOCKET_IO_ERROR;
	}
	
	kocket_queue -> kocket_clients_ids = kocket_realloc(kocket_queue -> kocket_clients_ids, sizeof(int) * kocket_queue -> size);
	if (kocket_queue -> kocket_clients_ids == NULL) {
		mutex_unlock(&(kocket_queue -> lock));
		WARNING_LOG("Failed to reallocate the kocket_clients_ids.\n");
		return -KOCKET_IO_ERROR;
	}
		
	mutex_unlock(&(kocket_queue -> lock));

	return KOCKET_NO_ERROR;
}

int kocket_queue_get_n_client_id(KocketQueue* kocket_queue, u32 index, u32* kocket_client_id) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.\n");
		return -KOCKET_IO_ERROR;
	}

	mutex_lock(&(kocket_queue -> lock));
	
	if (kocket_queue -> size <= index) {
		mutex_unlock(&(kocket_queue -> lock));
		WARNING_LOG("Out of bound index: %u > %u (queue size).\n", index, kocket_queue -> size);
		return -KOCKET_INVALID_PARAMETERS;
	}

	*kocket_client_id = (kocket_queue -> kocket_clients_ids)[index];
	
	mutex_unlock(&(kocket_queue -> lock));
	
	return KOCKET_NO_ERROR;
}

int kocket_addr_to_bytes(const char* str_addr, u32* bytes_addr) {
    if (str_addr == NULL || bytes_addr == NULL) {
        WARNING_LOG("Parameters must be non-NULL.\n");
        return -KOCKET_INVALID_PARAMETERS;
    }
    
    u8 temp = 0;
    *bytes_addr = 0;
    for (u8 i = 0, bytes_cnt = 0; i < 15 && bytes_cnt < 4; ++i, ++str_addr) {
        if (*str_addr == '.' || *str_addr == '\0') {
            *bytes_addr = (*bytes_addr << 4) | temp;
            if (*str_addr == '\0') return KOCKET_NO_ERROR;
            temp = 0;
            bytes_cnt++;
            continue;
        } else if (!KOCKET_IS_NUM(*str_addr)) {
            WARNING_LOG("Expected a number but found: '%c'\n", *str_addr);
            return -KOCKET_INVALID_STR_ADDR;
        }
        temp = temp * 10 + KOCKET_CHAR_TO_NUM(*str_addr);
    }
    
    return KOCKET_NO_ERROR;
}

#endif //_COMMON_KOCKET_H_

