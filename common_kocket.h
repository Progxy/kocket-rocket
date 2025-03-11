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
	u32 req_id;
	u32 payload_size;
	u8* payload;	
} KocketStruct;

typedef struct KocketType {
	u32 id;
	char* type_name;
	bool has_handler;
	KocketHandler kocket_handler;
} KocketType;

typedef struct sockaddr_in ClientKocket;
typedef int (*KocketHandler)(KocketStruct);
typedef struct Kocket {
	int socket;
	int backlog;
	unsigned short int port;
	struct sockaddr_in sock_addr;
	KocketType* kocket_types;
	u32 kocket_types_cnt;
	int* clients;
	struct pollfd* polls;
	u32 clients_cnt;
} Kocket;

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
KocketQueue kocket_writing_queue = {0};
KocketQueue kocket_reads_queue = {0};
KocketStruct kocket_status = KOCKET_NO_ERROR;

/* -------------------------------------------------------------------------------------------------------- */
int kocket_init_queue(KocketQueue* kocket_queue) {
	return KOCKET_NO_ERROR;
}

int kocket_deallocate_queue(KocketQueue* kocket_queue) {
	return KOCKET_NO_ERROR;
}

int kocket_enqueue(KocketQueue* kocket_queue, KocketStruct kocket_struct, u32 kocket_client_id) {
	return KOCKET_NO_ERROR;
}

int kocket_dequeue(KocketQueue* kocket_queue, KocketStruct* kocket_struct, u32* kocket_client_id) {
	return KOCKET_NO_ERROR;
}

int is_kocket_queue_empty(KocketQueue* kocket_queue) {
	return KOCKET_NO_ERROR;
}

int kocket_queue_find(KocketQueue* kocket_queue, u32 req_id, KocketStruct* kocket_struct) {
	return KOCKET_NO_ERROR;
}

#endif //_COMMON_KOCKET_H_

