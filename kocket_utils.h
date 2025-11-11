#ifndef _KOCKET_UTILS_H_
#define _KOCKET_UTILS_H_

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
#define KOCKET_CHAR_TO_NUM(chr) ((chr) - 48)

#ifndef NO_INLINE
	#define NO_INLINE __attribute__((__noinline__))
#endif //NO_INLINE

#ifndef PACKED_STRUCT
	#define PACKED_STRUCT __attribute__((packed))
#endif //PACKED_STRUCT

#ifndef UNUSED_FUNCTION
	#define UNUSED_FUNCTION __attribute__((unused))
#endif //UNUSED_FUNCTION

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
	#define BLUE          "\033[34m"
	#define PURPLE        "\033[35m"
	#define CYAN          "\033[36m"
	#define BRIGHT_YELLOW "\033[38;5;214m"    
	#define RESET_COLOR   "\033[0m"

	#define WARNING_COLOR BRIGHT_YELLOW
	#define ERROR_COLOR   RED
	#define DEBUG_COLOR   PURPLE
	#define TODO_COLOR    CYAN
	#define INFO_COLOR    BLUE

	#define COLOR_STR(str, COLOR) COLOR str RESET_COLOR

	#include "./str_error.h"
	
	#ifdef _K_KOCKET_H_
		#define ERROR_LOG(fmt, error_str, ...) printk(KERN_ERR "ERROR:%s:(" __FILE__ ":%u): " fmt "\n", error_str, __LINE__,  ##__VA_ARGS__)
		#define PERROR_LOG(fmt, err, ...) 	   printk(KERN_WARNING "WARNING:" __FILE__ ":%u: " fmt ", because: " COLOR_STR("'%s'", BRIGHT_YELLOW) ".\n", __LINE__, ##__VA_ARGS__, str_error(err))
		#define WARNING_LOG(fmt, ...)          printk(KERN_WARNING "WARNING:" __FILE__ ":%u: " fmt "\n", __LINE__,  ##__VA_ARGS__)
		#define INFO_LOG(fmt, ...)             printk(KERN_INFO "INFO:" __FILE__ ":%u: " fmt "\n", __LINE__,  ##__VA_ARGS__)
		#ifdef _DEBUG
			#define DEBUG_LOG(fmt, ...)            printk(KERN_INFO "DEBUG: " fmt "\n", ##__VA_ARGS__)
		#else
			#define DEBUG_LOG(fmt, ...)
		#endif //_DEBUG	
	#else
		#define ERROR_LOG(format, error_str, ...) printf(COLOR_STR("ERROR:%s:" __FILE__ ":%u: ", ERROR_COLOR) format "\n", error_str, __LINE__, ##__VA_ARGS__)
		#define WARNING_LOG(format, ...)          printf(COLOR_STR("WARNING:" __FILE__ ":%u: ", WARNING_COLOR) format "\n", __LINE__, ##__VA_ARGS__)
		#define INFO_LOG(format, ...)             printf(COLOR_STR("INFO:" __FILE__ ":%u: ", INFO_COLOR) format "\n", __LINE__, ##__VA_ARGS__)
		#define PERROR_LOG(format, ...)           printf(COLOR_STR("WARNING:" __FILE__ ":%u: ", WARNING_COLOR) format ", because: " COLOR_STR("'%s'", BRIGHT_YELLOW) ".\n", __LINE__, ##__VA_ARGS__, str_error())
		#ifdef _DEBUG
			#define DEBUG_LOG(format, ...)            printf(COLOR_STR("DEBUG:" __FILE__ ":%u: ", DEBUG_COLOR) format "\n", __LINE__, ##__VA_ARGS__)
		#else 
			#define DEBUG_LOG(format, ...)
		#endif //_DEBUG	
	
		#define TODO(format, ...)            printf(COLOR_STR("TODO:" __FILE__ ":%u: ", TODO_COLOR) COLOR_STR("function %s: ", PURPLE) format "\n", __LINE__, __func__, ##__VA_ARGS__)

	#endif //_K_KOCKET_H_

#endif //_KOCKET_PRINTING_UTILS_

/* -------------------------------------------------------------------------------------------------------- */
#ifdef _KOCKET_SPECIAL_TYPE_SUPPORT_

#define STATIC_ASSERT _Static_assert

typedef unsigned char bool;

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

STATIC_ASSERT(sizeof(u8)   == 1,  "u8 must be 1 byte");
STATIC_ASSERT(sizeof(u16)  == 2,  "u16 must be 2 bytes");
STATIC_ASSERT(sizeof(u32)  == 4,  "u32 must be 4 bytes");
STATIC_ASSERT(sizeof(u64)  == 8,  "u64 must be 8 bytes");

typedef char          s8;
typedef short int     s16;
typedef int           s32;
typedef long long int s64;

STATIC_ASSERT(sizeof(s8)   == 1,  "s8 must be 1 byte");
STATIC_ASSERT(sizeof(s16)  == 2,  "s16 must be 2 bytes");
STATIC_ASSERT(sizeof(s32)  == 4,  "s32 must be 4 bytes");
STATIC_ASSERT(sizeof(s64)  == 8,  "s64 must be 8 bytes");

#endif //_KOCKET_SPECIAL_TYPE_SUPPORT_

/* -------------------------------------------------------------------------------------------------------- */
#ifdef _KOCKET_UTILS_IMPLEMENTATION_

#include <stdarg.h>

#define GET_BIT(val, bit_pos) ((val) >> (bit_pos))
#define HEX_TO_CHR_CAP(val) ((val) > 9 ? (val) + 55 : (val) + '0')
#define KOCKET_BE_CONVERT(ptr_val, size) kocket_be_to_le(ptr_val, size)
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
    defined(__LITTLE_ENDIAN__) || \
    defined(__ARMEL__) || \
    defined(__THUMBEL__) || \
    defined(__AARCH64EL__) || \
    defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)

	UNUSED_FUNCTION static void kocket_be_to_le(void* ptr_val, size_t size) {
        for (size_t i = 0; i < size / 2; ++i) {
            unsigned char temp = KOCKET_CAST_PTR(ptr_val, unsigned char)[i];
            KOCKET_CAST_PTR(ptr_val, unsigned char)[i] = KOCKET_CAST_PTR(ptr_val, unsigned char)[size - 1 - i];
            KOCKET_CAST_PTR(ptr_val, unsigned char)[size - 1 - i] = temp;
        }
        return;
    }

#else
    #define kocket_be_to_le(ptr_val, size)
#endif // CHECK_ENDIANNESS

UNUSED_FUNCTION static u64 str_len(const char* str) {
	if (str == NULL) return 0;
	u64 i = 0;
	while (*str++) ++i;
	return i;
}

UNUSED_FUNCTION static u8 bit_size(u8 val) {
	u8 size = 8;
	for (u8 i = 0; i < 8; ++i) {
		if (GET_BIT(val, i)) break;
		size--;
	}
	return size;
}

UNUSED_FUNCTION static void mem_move(void* dest, const void* src, size_t size) {
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

static int mem_cmp(const void* a, const void* b, size_t size) {
	if (a == NULL || b == NULL) return -2;
	for (size_t i = 0; i < size; ++i) {
		if (KOCKET_CAST_PTR(a, unsigned char)[i] != KOCKET_CAST_PTR(b, unsigned char)[i]) return -1;
	}
	return 0;
}

#define mem_set(ptr, value, size)    mem_set_var(ptr, value, size, sizeof(u8))
#define mem_set_32(ptr, value, size) mem_set_var(ptr, value, size, sizeof(u32))
#define mem_set_64(ptr, value, size) mem_set_var(ptr, value, size, sizeof(u64))
static void mem_set_var(void* ptr, int value, size_t size, size_t val_size) {
	if (ptr == NULL) return;
	for (size_t i = 0; i < size; ++i) KOCKET_CAST_PTR(ptr, unsigned char)[i] = KOCKET_CAST_PTR(&value, unsigned char)[i % val_size]; 
	return;
}

static char* to_hex_str(u8* val, unsigned int size, char* str, bool use_space) {
	unsigned int i = 0;
    for (unsigned int j = 0; j < size; i += 2 + use_space, ++j) {
        str[i] = HEX_TO_CHR_CAP((val[j] >> 4) & 0xF);
        str[i + 1] = HEX_TO_CHR_CAP(val[j] & 0xF);
		if (use_space) str[i + 2] = ' ';	
    }
    str[i] = '\0';
    return str;
}

static u8* concat(u64 len, u64* size, ...) {
	va_list args;
    va_start(args, size);
	
	for (u64 i = 0; i < len; i += 2) {
		u8* element = va_arg(args, u8*);	
		(void) element;
		*size += va_arg(args, u64);
	}

	va_end(args);

	u8* concatenation = calloc(*size, 1);
	if (concatenation == NULL) {
		printf("Failed to allocate concatentation buffer.\n");
		return NULL;
	}
    
	va_start(args, size);
	
	u64 current_size = 0;
	for (u64 i = 0; i < len; i += 2) {
		u8* element = va_arg(args, u8*);	
		u64 element_size = va_arg(args, u64);
		mem_cpy(concatenation + current_size, element, element_size);	
		current_size += element_size;
	}

	va_end(args);

	return concatenation;
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
	KOCKET_NO_DATA_RECEIVED,
	KOCKET_CLOSED_CONNECTION,
	KOCKET_INVALID_SIGNATURE,
	KOCKET_INVALID_POINT,
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
	"KOCKET_NO_DATA_RECEIVED",
	"KOCKET_CLOSED_CONNECTION",
	"KOCKET_INVALID_SIGNATURE",
	"KOCKET_INVALID_POINT",
	"KOCKET_TODO"
};

#endif //_KOCKET_UTILS_H_

