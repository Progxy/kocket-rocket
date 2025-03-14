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

#ifndef _U_KOCKET_H_
#define _U_KOCKET_H_

#include "common_kocket.h"
#include "./crypto/chacha20.h"

// ------------------------
//  Functions Declarations
// ------------------------
int kocket_init(ClientKocket* kocket, pthread_t* pthread);
int kocket_deinit(ClientKocket* kocket, KocketStatus status, pthread_t thread);
int kocket_write(KocketStruct* kocket_struct);
int kocket_read(u64 req_id, KocketStruct* kocket_struct, bool wait_response);
static int kocket_send(ClientKocket kocket, KocketStruct kocket_struct);
static int kocket_recv(ClientKocket kocket);
static void stop_thread(void);
static bool thread_should_stop(void);
void* kocket_dispatcher(void* kocket_arg);

/* -------------------------------------------------------------------------------------------------------- */
int kocket_init(ClientKocket* kocket, pthread_t* pthread) {
	if ((kocket -> socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		PERROR_LOG("An error occurred while creating the socket");
		return -KOCKET_IO_ERROR;
	}

	struct sockaddr_in server_sock_addr = {0};
	server_sock_addr.sin_family = AF_INET;
	server_sock_addr.sin_port = htons(kocket -> port);
	server_sock_addr.sin_addr.s_addr = htonl(kocket -> address);

	if (connect(kocket -> socket, (struct sockaddr *) &server_sock_addr, sizeof(server_sock_addr)) < 0) {
		close(kocket -> socket);
		PERROR_LOG("An error occurred while connecting to the kocket server");
		return -KOCKET_IO_ERROR;
	}

	if (fcntl(kocket -> socket, F_SETFL, O_NONBLOCK) < 0) {
		close(kocket -> socket);
		PERROR_LOG("An error occurred while setting the socket non-blocking");
		return -KOCKET_IO_ERROR;
    }

	kocket -> poll_fd.fd = kocket -> socket;
	kocket -> poll_fd.events = POLLIN;

	mutex_init(&kocket_status_lock);
	
	// TODO: Implement the algorithms needed for ensuring connection security
	if (kocket -> use_secure_connection) {
		close(kocket -> socket);
		mutex_destroy(&kocket_status_lock);
		WARNING_LOG("The secure connection stack has not been implemented yet.\n");
		return -KOCKET_TODO;
	}
	
	kocket_alloc_queue(&kocket_writing_queue);
	kocket_alloc_queue(&kocket_reads_queue);

	if (pthread_create(pthread, NULL, kocket_dispatcher, (void*) kocket) != 0) {
		close(kocket -> socket);
		mutex_destroy(&kocket_status_lock);
		kocket_deallocate_queue(&kocket_writing_queue);
		kocket_deallocate_queue(&kocket_reads_queue);
		WARNING_LOG("Failed to create the pthread.\n");
		return -KOCKET_IO_ERROR;
	}

	return KOCKET_NO_ERROR;
}

int kocket_deinit(ClientKocket* kocket, KocketStatus status, pthread_t thread) {
	int err = KOCKET_NO_ERROR;
	
	stop_thread();
	if (pthread_join(thread, (void**) &err)) {
		WARNING_LOG("An error occurred while joining the thread.\n");
		err = -KOCKET_IO_ERROR;
	} else if (err < 0) {
		WARNING_LOG("The kocket_thread failed during execution.\n");
	}

	if ((err = kocket_deallocate_queue(&kocket_writing_queue)) < 0) {
		WARNING_LOG("An error occurred while deallocating the queue.\n");
	} else if ((err = kocket_deallocate_queue(&kocket_reads_queue)) < 0) {
		WARNING_LOG("An error occurred while deallocating the queue.\n");
	}
	
	close(kocket -> socket);
	
	mutex_lock(&kocket_status_lock);
	kocket_status = status;
	mutex_destroy(&kocket_status_lock);

	return err;
}

int kocket_write(KocketStruct* kocket_struct) {
	u8 initialization_vector[64] = {0};
	kocket_struct -> req_id = *KOCKET_CAST_PTR(cha_cha20(initialization_vector), u64);
	
	int err = 0;
	if ((err = kocket_enqueue(&kocket_writing_queue, *kocket_struct, 0)) < 0) {
		WARNING_LOG("Failed to enqueue the given kocket_struct.\n");
		return err;
	}
	return KOCKET_NO_ERROR;
}

int kocket_read(u64 req_id, KocketStruct* kocket_struct, bool wait_response) {
	int ret = 0;
	if ((ret = kocket_dequeue_find(&kocket_reads_queue, req_id, kocket_struct)) < 0) {
		WARNING_LOG("An error occurred while finding withing the queue.\n");
		return ret;
	}
	
	if (ret == KOCKET_REQ_NOT_FOUND && wait_response) {
		// TODO: find a way to wait until the response with matching req_id arrives.
		return KOCKET_NO_ERROR;
	} else if (ret == KOCKET_REQ_NOT_FOUND) return KOCKET_NO_ERROR;

	return KOCKET_NO_ERROR;
}

static int kocket_send(ClientKocket kocket, KocketStruct kocket_struct) {
	u32 payload_size = sizeof(KocketStruct) - sizeof(u8*) + kocket_struct.payload_size;
	void* payload = kocket_calloc(payload_size, sizeof(u8));
	if (payload == NULL) {
		WARNING_LOG("Failed to allocate the buffer for the payload.\n");
		return -KOCKET_IO_ERROR;
	}
	
	mem_cpy(payload, &kocket_struct, sizeof(KocketStruct) - sizeof(u8*));
	mem_cpy(KOCKET_CAST_PTR(payload, u8) + sizeof(KocketStruct) - sizeof(u8*), kocket_struct.payload, kocket_struct.payload_size);

	if (send(kocket.socket, payload, payload_size, 0) < (ssize_t) payload_size) {
		KOCKET_SAFE_FREE(payload);
		PERROR_LOG("An error occurred while sending %u bytes", payload_size);
		return -KOCKET_IO_ERROR;
	}
	
	KOCKET_SAFE_FREE(payload);

	return KOCKET_NO_ERROR;
}

static int kocket_recv(ClientKocket kocket) {
	KocketStruct kocket_struct = {0};

	if (recv(kocket.socket, &kocket_struct, sizeof(KocketStruct) - sizeof(u8*), 0) < (ssize_t) (sizeof(KocketStruct) - sizeof(u8*))) {
		PERROR_LOG("An error occurred while reading from the client.\n");
		return -KOCKET_IO_ERROR;
	}

	kocket_struct.payload = (u8*) kocket_calloc(kocket_struct.payload_size, sizeof(u8));
	if (kocket_struct.payload == NULL) {
		WARNING_LOG("An error occurred while allocating the buffer for the payload.\n");
		return -KOCKET_IO_ERROR;
	}
	
	if (recv(kocket.socket, kocket_struct.payload, kocket_struct.payload_size, 0) < kocket_struct.payload_size) {
		KOCKET_SAFE_FREE(kocket_struct.payload);
		PERROR_LOG("An error occurred while reading from the server.\n");
		return -KOCKET_IO_ERROR;
	}
	
	int ret = 0;
	if (kocket_struct.type_id < kocket.kocket_types_cnt && (kocket.kocket_types)[kocket_struct.type_id].has_handler) {
		if ((ret = (*((kocket.kocket_types)[kocket_struct.type_id].kocket_handler)) (kocket_struct)) < 0) {
			WARNING_LOG("An error occurred while executing the handler for the type: '%s'\n", (kocket.kocket_types)[kocket_struct.type_id].type_name);
			return ret;
		}
	} 

	if ((ret = kocket_enqueue(&kocket_writing_queue, kocket_struct, 0)) < 0) {
		WARNING_LOG("Failed to enqueue the given kocket_struct.\n");
		return ret;
	}
	
	return KOCKET_NO_ERROR;
}

static void stop_thread(void) {
	mutex_lock(&kocket_status_lock); 
    kocket_status = KOCKET_THREAD_STOP; 
	mutex_unlock(&kocket_status_lock);
	return;
}

static bool thread_should_stop(void) {
	bool status = TRUE;
	mutex_lock(&kocket_status_lock); 
    status = kocket_status; 
	mutex_unlock(&kocket_status_lock);
	return status;
}

// This will be the function executed by the kocket-thread.
void* kocket_dispatcher(void* kocket_arg) {
	int err = 0;
	ClientKocket* kocket = (ClientKocket*) kocket_arg;
	while (thread_should_stop()) {
		int ret = poll(&(kocket -> poll_fd), 1, KOCKET_TIMEOUT_MS);
		if (ret < 0) {
			PERROR_LOG("Failed to perform the read/accept poll");
			stop_thread();
			return (void*) -KOCKET_IO_ERROR;
		} else if (ret != 0 && (kocket -> poll_fd.revents & POLLIN) && (err = kocket_recv(*kocket)) < 0) {
			WARNING_LOG("An error occurred while receiving.\n");
			stop_thread();
			return (void*)(intptr_t) err; 
		}
		
		// TODO: As the send operations are non-blocking, we should probably also check using polling if we can send data.
		while ((err = is_kocket_queue_empty(&kocket_writing_queue)) > 0) {
			u32 kocket_client_id = 0;
			KocketStruct kocket_struct = {0};
			if ((err = kocket_dequeue(&kocket_writing_queue, &kocket_struct, &kocket_client_id)) < 0) {
				WARNING_LOG("Failed to dequeue from the kocket_writing_queue.\n");
				stop_thread();
				return (void*)(intptr_t) err;
			}
			
			if ((err = kocket_send(*kocket, kocket_struct)) < 0) {
				WARNING_LOG("Failed to send the queued kocket_struct.\n");
				stop_thread();
				return (void*)(intptr_t) err;
			}
		}
		
		if (err < 0) {
			WARNING_LOG("An error occurred while checking if the kocket_writing_queue was empty.\n");
			stop_thread();
			return (void*)(intptr_t) err;
		}
	}
	
	return KOCKET_NO_ERROR;
}

#endif //_U_KOCKET_H_

