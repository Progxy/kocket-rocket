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

#define HOST_PORT 6969
#define HOST_ADDRESS "127.0.0.1"
int main(void) {
	ClientKocket kocket = {0};
	kocket.port = HOST_PORT;
	kocket.address = kocket_haddrn(HOST_ADDRESS);
	kocket_init()
	printf("Hello World.\n");
	return 0;
}
