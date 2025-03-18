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

#include "./str_error.h"
#ifdef _U_KOCKET_H_
	#define ERROR_LOG(format, error_str, ...) printf(COLOR_STR("ERROR:%s:" __FILE__ ":%u: ", ERROR_COLOR) format "\n", error_str, __LINE__, ##__VA_ARGS__)
	#define WARNING_LOG(format, ...)          printf(COLOR_STR("WARNING:" __FILE__ ":%u: ", WARNING_COLOR) format "\n", __LINE__, ##__VA_ARGS__)
	#define PERROR_LOG(format, ...)           printf(COLOR_STR("WARNING:" __FILE__ ":%u: ", WARNING_COLOR) format ", because: " COLOR_STR("'%s'", BRIGHT_YELLOW) ".\n", __LINE__, ##__VA_ARGS__, str_error())
	#define DEBUG_LOG(format, ...)            printf(COLOR_STR("DEBUG:" __FILE__ ":%u: ", DEBUG_COLOR) format "\n", __LINE__, ##__VA_ARGS__)
#else 
	#define ERROR_LOG(fmt, error_str, ...) printk(KERN_ERR "ERROR:%s:(" __FILE__ ":%d): " fmt "\n", error_str, __LINE__,  ##__VA_ARGS__)
	#define PERROR_LOG(fmt, err, ...) 	   printk(KERN_WARNING "WARNING:" __FILE__ ":%u: " fmt ", because: " COLOR_STR("'%s'", BRIGHT_YELLOW) ".\n", __LINE__, ##__VA_ARGS__, str_error(err))
	#define WARNING_LOG(fmt, ...)          printk(KERN_WARNING "WARNING(" __FILE__ ":%d): " fmt "\n", __LINE__,  ##__VA_ARGS__)
	#define DEBUG_LOG(fmt, ...)            printk(KERN_INFO "DEBUG: " fmt "\n", ##__VA_ARGS__)
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
	KOCKET_FAILED_LOCK,
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
	"KOCKET_FAILED_LOCK",
	"KOCKET_TODO"
};

#ifdef _U_KOCKET_H_
	#include <pthread.h>
	typedef pthread_mutex_t mutex_t;
	#define kocket_mutex_init(mutex_lock) pthread_mutex_init((mutex_lock), NULL)
	#define kocket_mutex_unlock           pthread_mutex_unlock
	#define kocket_mutex_destroy          pthread_mutex_destroy
	int kocket_mutex_lock(mutex_t* lock, u64 timeout_sec) {
		struct timespec ts = {0};
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += timeout_sec;

		if (pthread_mutex_timedlock(lock, &ts) != 0) {
			WARNING_LOG("Mutex lock timed out, as the %lu secs timeout expired.", timeout_sec);
			return -KOCKET_FAILED_LOCK;
		}

		return KOCKET_NO_ERROR;
	}
#else
	typedef struct mutex mutex_t;
	#define kocket_mutex_destroy mutex_unlock
	#define kocket_mutex_unlock mutex_unlock
	#define kocket_mutex_init mutex_init
	int kocket_mutex_lock(mutex_t* lock, u64 timeout_sec);
	int kocket_mutex_lock(mutex_t* lock, u64 timeout_sec) {
		while (timeout_sec--) {
			if (mutex_trylock(lock)) return KOCKET_NO_ERROR;
			schedule_timeout_interruptible(1); 
		}

		WARNING_LOG("Mutex lock timed out, as the %llu secs timeout expired.", timeout_sec);
		
		return -KOCKET_FAILED_LOCK;
	}
#endif //_U_KOCKET_H_

typedef struct PACKED_STRUCT KocketPacket {
	u32 type_id;
	u64 req_id;
	u32 payload_size;
	u8* payload;	
} KocketPacket;

#ifdef _U_KOCKET_H_

typedef struct KocketPacketEntry {
	KocketPacket kocket_packet;
} KocketPacketEntry;

#else

typedef struct KocketPacketEntry {
	KocketPacket kocket_packet;
	u32 kocket_client_id;
} KocketPacketEntry;

#endif //_U_KOCKET_H_

typedef struct KocketWaitEntry {
	mutex_t lock;
	u64 req_id;
} KocketWaitEntry;

typedef struct KocketQueue {
	void** elements;
	mutex_t lock;
	void (*free_elements)(struct KocketQueue*);
	u8 elements_size;
	u32 size;
} KocketQueue;
typedef void (*FreeElementsHandler)(struct KocketQueue*);

typedef int (*KocketHandler)(KocketPacketEntry);
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

/* -------------------------------------------------------------------------------------------------------- */
// Constant Values
#define DEFAULT_LOCK_TIMEOUT_SEC 60
#define KOCKET_TIMEOUT_MS 1000 // NOTE: This value should be changed based on the requirement of the operational environment.
#define KOCKET_PORT       6969

/* -------------------------------------------------------------------------------------------------------- */
// Static Shared Variables
static KocketQueue kocket_writing_queue = {0};
static KocketQueue kocket_reads_queue = {0};
static KocketQueue kocket_wait_queue = {0};

static KocketStatus kocket_status = KOCKET_NO_ERROR;
static mutex_t kocket_status_lock = {0};

/* -------------------------------------------------------------------------------------------------------- */
// ------------------------
//  Functions Declarations
// ------------------------
int kocket_alloc_queue(KocketQueue* kocket_queue, u8 elements_size, FreeElementsHandler free_elements_handler);
int kocket_deallocate_queue(KocketQueue* kocket_queue);
int kocket_enqueue(KocketQueue* kocket_queue, void* kocket_entry);
int kocket_dequeue(KocketQueue* kocket_queue, void* kocket_entry);
int kocket_dequeue_packet(KocketQueue* kocket_packets_queue, u64 req_id, KocketPacketEntry* kocket_packet, KocketQueue* kocket_waits_queue, KocketWaitEntry* kocket_wait_entry);
int is_kocket_queue_empty(KocketQueue* kocket_queue) ;
int wake_waiting_entry(KocketQueue* kocket_queue, u64 req_id);
int kocket_addr_to_bytes(const char* str_addr, u32* bytes_addr);

/* -------------------------------------------------------------------------------------------------------- */
int kocket_alloc_queue(KocketQueue* kocket_queue, u8 elements_size, FreeElementsHandler free_elements_handler) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.");
		return -KOCKET_IO_ERROR;
	} else if (free_elements_handler == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given free_elements handler is uninitialized.");
		return -KOCKET_IO_ERROR;
	}
	
	kocket_queue -> elements = NULL;
	kocket_queue -> free_elements = free_elements_handler;
	kocket_queue -> elements_size = elements_size;
	kocket_queue -> size = 0;

	kocket_mutex_init(&(kocket_queue -> lock));

	return KOCKET_NO_ERROR;
}

int kocket_deallocate_queue(KocketQueue* kocket_queue) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.");
		return -KOCKET_IO_ERROR;
	}

	kocket_mutex_lock(&(kocket_queue -> lock), DEFAULT_LOCK_TIMEOUT_SEC);
	
	(*kocket_queue -> free_elements)(kocket_queue);
	kocket_queue -> size = 0;
	
	kocket_mutex_destroy(&(kocket_queue -> lock));

	return KOCKET_NO_ERROR;
}

int kocket_enqueue(KocketQueue* kocket_queue, void* kocket_entry) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.");
		return -KOCKET_IO_ERROR;
	}

	kocket_mutex_lock(&(kocket_queue -> lock), DEFAULT_LOCK_TIMEOUT_SEC);
	
	kocket_queue -> elements = (void**) kocket_realloc(kocket_queue -> elements, kocket_queue -> elements_size * (++(kocket_queue -> size)));
	if (kocket_queue -> elements == NULL) {
		kocket_mutex_unlock(&(kocket_queue -> lock));
		WARNING_LOG("Failed to reallocate the elements.");
		return -KOCKET_IO_ERROR;
	}
	
	mem_cpy(KOCKET_CAST_PTR(kocket_queue -> elements, u8) + kocket_queue -> elements_size * (kocket_queue -> size - 1), kocket_entry, kocket_queue -> elements_size);
		
	kocket_mutex_unlock(&(kocket_queue -> lock));

	return KOCKET_NO_ERROR;
}

int kocket_dequeue(KocketQueue* kocket_queue, void* kocket_entry) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.");
		return -KOCKET_IO_ERROR;
	}

	kocket_mutex_lock(&(kocket_queue -> lock), DEFAULT_LOCK_TIMEOUT_SEC);
	
   	mem_cpy(kocket_entry, KOCKET_CAST_PTR(kocket_queue -> elements, u8) + kocket_queue -> elements_size  * (kocket_queue -> size - 1), kocket_queue -> elements_size);
	
	kocket_queue -> elements = (void**) kocket_realloc(kocket_queue -> elements, kocket_queue -> elements_size * (--(kocket_queue -> size)));
	if (kocket_queue -> elements == NULL) {
		kocket_mutex_unlock(&(kocket_queue -> lock));
		WARNING_LOG("Failed to reallocate the elements.");
		return -KOCKET_IO_ERROR;
	}
		
	kocket_mutex_unlock(&(kocket_queue -> lock));
	
	return KOCKET_NO_ERROR;
}

int is_kocket_queue_empty(KocketQueue* kocket_queue) {	
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.");
		return -KOCKET_IO_ERROR;
	}

	kocket_mutex_lock(&(kocket_queue -> lock), DEFAULT_LOCK_TIMEOUT_SEC);
	
	u32 queue_size = kocket_queue -> size;
	
	kocket_mutex_unlock(&(kocket_queue -> lock));
	
	return queue_size;
}

int kocket_dequeue_packet(KocketQueue* kocket_packets_queue, u64 req_id, KocketPacketEntry* kocket_packet, KocketQueue* kocket_waits_queue, KocketWaitEntry* kocket_wait_entry) {
	if (kocket_packets_queue == NULL) {
		WARNING_LOG("Invalid kocket_packets_queue, the given kocket_packets_queue is NULL.");
		return -KOCKET_IO_ERROR;
	}

	kocket_mutex_lock(&(kocket_packets_queue -> lock), DEFAULT_LOCK_TIMEOUT_SEC);
	
	u32 index = 0;
	KocketPacketEntry* kocket_packet_entries = KOCKET_CAST_PTR(kocket_packets_queue -> elements, KocketPacketEntry);
	for (index = 0; index < kocket_packets_queue -> size; ++index) {
		if (kocket_packet_entries[index].kocket_packet.req_id == req_id) break;
	}

	if (index >= kocket_packets_queue -> size) {
		kocket_mutex_unlock(&(kocket_packets_queue -> lock));
		if (kocket_waits_queue != NULL && kocket_wait_entry != NULL) {
			mem_set(kocket_wait_entry, 0, sizeof(KocketWaitEntry));
			kocket_wait_entry -> req_id = kocket_packet -> kocket_packet.req_id;
			kocket_mutex_init(&(kocket_wait_entry -> lock));
			
			int ret = 0;
			if ((ret = kocket_enqueue(kocket_waits_queue, kocket_wait_entry)) < 0) {
				WARNING_LOG("An error occurred while enqueuing the wait_lock.");
				return ret;
			}
			
			kocket_mutex_lock(&(kocket_wait_entry -> lock), DEFAULT_LOCK_TIMEOUT_SEC);
		
		}
		
		return KOCKET_REQ_NOT_FOUND;
	}
	
	*kocket_packet = kocket_packet_entries[index];
	
	mem_move(KOCKET_CAST_PTR(kocket_packets_queue -> elements, KocketPacketEntry) + index, KOCKET_CAST_PTR(kocket_packets_queue -> elements, KocketPacketEntry) + index + 1, (kocket_packets_queue -> size - 1 - index) * sizeof(KocketPacket));

	kocket_packets_queue -> elements = kocket_realloc(kocket_packets_queue -> elements, sizeof(KocketPacket) * (--(kocket_packets_queue -> size)));
	if (kocket_packets_queue -> elements == NULL) {
		kocket_mutex_unlock(&(kocket_packets_queue -> lock));
		WARNING_LOG("Failed to reallocate the elements.");
		return -KOCKET_IO_ERROR;
	}
		
	kocket_mutex_unlock(&(kocket_packets_queue -> lock));

	return KOCKET_NO_ERROR;
}

#ifdef _K_KOCKET_H_
int kocket_queue_get_n_client_id(KocketQueue* kocket_queue, u32 index, u32* kocket_client_id);
int kocket_queue_get_n_client_id(KocketQueue* kocket_queue, u32 index, u32* kocket_client_id) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.");
		return -KOCKET_IO_ERROR;
	}

	kocket_mutex_lock(&(kocket_queue -> lock), DEFAULT_LOCK_TIMEOUT_SEC);
	
	if (kocket_queue -> size <= index) {
		kocket_mutex_unlock(&(kocket_queue -> lock));
		WARNING_LOG("Out of bound index: %u > %u (queue size).", index, kocket_queue -> size);
		return -KOCKET_INVALID_PARAMETERS;
	}

	*kocket_client_id = KOCKET_CAST_PTR(kocket_queue -> elements, KocketPacketEntry)[index].kocket_client_id;
	
	kocket_mutex_unlock(&(kocket_queue -> lock));
	
	return KOCKET_NO_ERROR;
}
#endif //_K_KOCKET_H_

int wake_waiting_entry(KocketQueue* kocket_queue, u64 req_id) {
	if (kocket_queue == NULL) {
		WARNING_LOG("Invalid kocket_queue, the given kocket_queue is NULL.");
		return -KOCKET_IO_ERROR;
	}

	kocket_mutex_lock(&(kocket_queue -> lock), DEFAULT_LOCK_TIMEOUT_SEC);
	
	u32 index = 0;
	KocketWaitEntry* kocket_wait_entries = KOCKET_CAST_PTR(kocket_queue -> elements, KocketWaitEntry);
	for (index = 0; index < kocket_queue -> size; ++index) {
		if (kocket_wait_entries[index].req_id == req_id) {
			kocket_mutex_unlock(&(kocket_wait_entries[index].lock));
			break;
		}
	}

	kocket_mutex_unlock(&(kocket_queue -> lock));

	return KOCKET_NO_ERROR;
}

int kocket_addr_to_bytes(const char* str_addr, u32* bytes_addr) {
    if (str_addr == NULL || bytes_addr == NULL) {
        WARNING_LOG("Parameters must be non-NULL.");
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
            WARNING_LOG("Expected a number but found: '%c'", *str_addr);
            return -KOCKET_INVALID_STR_ADDR;
        }
        temp = temp * 10 + KOCKET_CHAR_TO_NUM(*str_addr);
    }
    
    return KOCKET_NO_ERROR;
}

#endif //_COMMON_KOCKET_H_

