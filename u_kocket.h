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

// Macro
#define check_kocket_status thread_should_stop

// Static Variables
static pthread_t kocket_thread = 0;

// ------------------------
//  Functions Declarations
// ------------------------
int kocket_init(ClientKocket kocket);
int kocket_deinit(KocketStatus status);
int kocket_write(KocketPacketEntry* kocket_packet);
int kocket_read(u64 req_id, KocketPacketEntry* kocket_packet, bool wait_response);
static int kocket_send(ClientKocket kocket, KocketPacket kocket_packet);
static int kocket_recv(ClientKocket kocket);
static inline void stop_thread(void);
static inline KocketStatus thread_should_stop(void);
void* kocket_dispatcher(void* kocket_arg);
void wait_queue_free_elements(KocketQueue* kocket_queue);
void packet_queue_free_elements(KocketQueue* kocket_queue);

/* -------------------------------------------------------------------------------------------------------- */
int kocket_init(ClientKocket kocket) {
	if ((kocket.socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		PERROR_LOG("An error occurred while creating the socket");
		return -KOCKET_IO_ERROR;
	}

	struct sockaddr_in server_sock_addr = {0};
	server_sock_addr.sin_family = AF_INET;
	server_sock_addr.sin_port = htons(kocket.port);
	server_sock_addr.sin_addr.s_addr = htonl(kocket.address);

	if (connect(kocket.socket, (struct sockaddr *) &server_sock_addr, sizeof(server_sock_addr)) < 0) {
		close(kocket.socket);
		PERROR_LOG("An error occurred while connecting to the kocket server");
		return -KOCKET_IO_ERROR;
	}

	if (fcntl(kocket.socket, F_SETFL, O_NONBLOCK) < 0) {
		close(kocket.socket);
		PERROR_LOG("An error occurred while setting the socket non-blocking");
		return -KOCKET_IO_ERROR;
    }

	kocket.poll_fd.fd = kocket.socket;
	kocket.poll_fd.events = POLLIN;

	kocket_mutex_init(&kocket_status_lock);
	
	// TODO: Implement the algorithms needed for ensuring connection security
	if (kocket.use_secure_connection) {
		close(kocket.socket);
		kocket_mutex_destroy(&kocket_status_lock);
		WARNING_LOG("The secure connection stack has not been implemented yet.");
		return -KOCKET_TODO;
	}
	
	int err = 0;
	if ((err = kocket_alloc_queue(&kocket_writing_queue, sizeof(KocketPacketEntry), packet_queue_free_elements)) < 0) {
		close(kocket.socket);
		kocket_mutex_destroy(&kocket_status_lock);
		WARNING_LOG("Failed to allocate the queue.");
		return err;
	}
	
	if ((err = kocket_alloc_queue(&kocket_reads_queue, sizeof(KocketPacketEntry), packet_queue_free_elements)) < 0) {
		close(kocket.socket);
		kocket_mutex_destroy(&kocket_status_lock);
		kocket_deallocate_queue(&kocket_writing_queue);
		WARNING_LOG("Failed to allocate the queue.");
		return err;
	}
	
	if ((err = kocket_alloc_queue(&kocket_wait_queue, sizeof(KocketWaitEntry), wait_queue_free_elements)) < 0) {
		close(kocket.socket);
		kocket_mutex_destroy(&kocket_status_lock);
		kocket_deallocate_queue(&kocket_writing_queue);
		kocket_deallocate_queue(&kocket_reads_queue);
		WARNING_LOG("Failed to allocate the queue.");
		return err;
	}

	if (pthread_create(&kocket_thread, NULL, kocket_dispatcher, (void*) &kocket) != 0) {
		close(kocket.socket);
		kocket_mutex_destroy(&kocket_status_lock);
		kocket_deallocate_queue(&kocket_writing_queue);
		kocket_deallocate_queue(&kocket_reads_queue);
		kocket_deallocate_queue(&kocket_wait_queue);
		WARNING_LOG("Failed to create the pthread.");
		return -KOCKET_IO_ERROR;
	}

	return KOCKET_NO_ERROR;
}

int kocket_deinit(KocketStatus status) {
	int err = 0;
	void* pthread_err = NULL;
	
	stop_thread();
	
	if (pthread_join(kocket_thread, &pthread_err)) {
		WARNING_LOG("An error occurred while joining the thread.");
		err = -KOCKET_IO_ERROR;
	} else if (pthread_err != NULL) {
		WARNING_LOG("The kocket_thread failed during execution.");
		err = (int) ((intptr_t) pthread_err);
	}

	if ((err = kocket_deallocate_queue(&kocket_writing_queue)) < 0) {
		WARNING_LOG("An error occurred while deallocating the queue.");
	}
	
	if ((err = kocket_deallocate_queue(&kocket_reads_queue)) < 0) {
		WARNING_LOG("An error occurred while deallocating the queue.");
	}
	
	if ((err = kocket_deallocate_queue(&kocket_wait_queue)) < 0) {
		WARNING_LOG("An error occurred while deallocating the queue.");
	}

	kocket_mutex_lock(&kocket_status_lock, DEFAULT_LOCK_TIMEOUT_SEC);
	kocket_status = status;
	kocket_mutex_destroy(&kocket_status_lock);

	return err;
}

int kocket_write(KocketPacketEntry* kocket_packet) {
	KocketStatus status = KOCKET_NO_ERROR;
	if ((status = check_kocket_status()) < 0) return status;
	
	u8 initialization_vector[64] = {0};
	kocket_packet -> kocket_packet.req_id = *KOCKET_CAST_PTR(cha_cha20(initialization_vector), u64);
	
	int err = 0;
	if ((err = kocket_enqueue(&kocket_writing_queue, kocket_packet)) < 0) {
		WARNING_LOG("Failed to enqueue the given kocket_packet.");
		return err;
	}

	return KOCKET_NO_ERROR;
}

int kocket_read(u64 req_id, KocketPacketEntry* kocket_packet, bool wait_response) {
	KocketStatus status = KOCKET_NO_ERROR;
	if ((status = check_kocket_status()) < 0) return status;
	
	int ret = 0;
	KocketWaitEntry wait_entry = {0};
	if ((ret = kocket_dequeue_packet(&kocket_reads_queue, req_id, kocket_packet, wait_response ? &kocket_wait_queue : NULL, wait_response ? &wait_entry : NULL)) < 0) {
		WARNING_LOG("An error occurred while finding withing the queue.");
		return ret;
	}
	
	if (ret == KOCKET_REQ_NOT_FOUND && wait_response) {
		kocket_mutex_lock(&(wait_entry.lock), DEFAULT_LOCK_TIMEOUT_SEC);
		
		if ((ret = kocket_dequeue_packet(&kocket_reads_queue, req_id, kocket_packet, NULL, NULL)) < 0) {
			WARNING_LOG("An error occurred while finding withing the queue.");
			return ret;
		}
		
		kocket_mutex_unlock(&(wait_entry.lock));

		if (ret == KOCKET_REQ_NOT_FOUND) {
			WARNING_LOG("Something must be wrong as even after waiting the data was still not there, req_id: %lu", req_id);
			return -ret;
		}

		return KOCKET_NO_ERROR;
	} else if (ret == KOCKET_REQ_NOT_FOUND) return ret;

	return KOCKET_NO_ERROR;
}

static int kocket_send(ClientKocket kocket, KocketPacket kocket_packet) {
	u32 payload_size = sizeof(KocketPacket) - sizeof(u8*) + kocket_packet.payload_size;
	void* payload = kocket_calloc(payload_size, sizeof(u8));
	if (payload == NULL) {
		WARNING_LOG("Failed to allocate the buffer for the payload.");
		return -KOCKET_IO_ERROR;
	}
	
	DEBUG_LOG("Sending %u bytes of payload to the server.", payload_size);

	mem_cpy(payload, &kocket_packet, sizeof(KocketPacket) - sizeof(u8*));
	mem_cpy(KOCKET_CAST_PTR(payload, u8) + sizeof(KocketPacket) - sizeof(u8*), kocket_packet.payload, kocket_packet.payload_size);

	if (send(kocket.socket, payload, payload_size, 0) < (ssize_t) payload_size) {
		KOCKET_SAFE_FREE(payload);
		PERROR_LOG("An error occurred while sending %u bytes", payload_size);
		return -KOCKET_IO_ERROR;
	}
	
	DEBUG_LOG("Sent %u bytes to server.", payload_size);	

	KOCKET_SAFE_FREE(payload);

	return KOCKET_NO_ERROR;
}

static int kocket_recv(ClientKocket kocket) {
	KocketPacket kocket_packet = {0};

	if (recv(kocket.socket, &kocket_packet, sizeof(KocketPacket) - sizeof(u8*), 0) < (ssize_t) (sizeof(KocketPacket) - sizeof(u8*))) {
		PERROR_LOG("An error occurred while reading from the client.");
		return -KOCKET_IO_ERROR;
	}

	DEBUG_LOG("Receiving %u bytes from the server.", kocket_packet.payload_size);

	kocket_packet.payload = (u8*) kocket_calloc(kocket_packet.payload_size, sizeof(u8));
	if (kocket_packet.payload == NULL) {
		WARNING_LOG("An error occurred while allocating the buffer for the payload.");
		return -KOCKET_IO_ERROR;
	}
	
	if (recv(kocket.socket, kocket_packet.payload, kocket_packet.payload_size, 0) < kocket_packet.payload_size) {
		KOCKET_SAFE_FREE(kocket_packet.payload);
		PERROR_LOG("An error occurred while reading from the server.");
		return -KOCKET_IO_ERROR;
	}
	
	int ret = 0;
	KocketPacketEntry packet_entry = { .kocket_packet = kocket_packet };
	if (kocket_packet.type_id < kocket.kocket_types_cnt && (kocket.kocket_types)[kocket_packet.type_id].has_handler) {
		if ((ret = (*((kocket.kocket_types)[kocket_packet.type_id].kocket_handler)) (packet_entry)) < 0) {
			WARNING_LOG("An error occurred while executing the handler for the type: '%s'", (kocket.kocket_types)[kocket_packet.type_id].type_name);
			return ret;
		}
		WARNING_LOG("Handled kocket with type_id: %u", kocket_packet.type_id);
		return KOCKET_NO_ERROR;
	} 

	if ((ret = kocket_enqueue(&kocket_reads_queue, &packet_entry)) < 0) {
		WARNING_LOG("Failed to enqueue the given kocket_packet.");
		return ret;
	}
	
	DEBUG_LOG("Kocket with type id %u appended to the queue.", kocket_packet.type_id);

	return KOCKET_NO_ERROR;
}

static inline void stop_thread(void) {
	kocket_mutex_lock(&kocket_status_lock, DEFAULT_LOCK_TIMEOUT_SEC); 
    kocket_status = KOCKET_THREAD_STOP; 
	kocket_mutex_unlock(&kocket_status_lock);
	return;
}

static KocketStatus thread_should_stop(void) {
	KocketStatus status = TRUE;
	kocket_mutex_lock(&kocket_status_lock, DEFAULT_LOCK_TIMEOUT_SEC); 
    status = kocket_status; 
	kocket_mutex_unlock(&kocket_status_lock);
	return status;
}

static int kocket_poll_write(ClientKocket* kocket) {
	int err = 0;
	if ((kocket -> poll_fd.revents & POLLOUT) == 0) return KOCKET_NO_ERROR;
	else if ((err = is_kocket_queue_empty(&kocket_writing_queue)) < 0) {
		WARNING_LOG("An error occurred while checking if the kocket_writing_queue was empty.");
		return err;
	} else if (err == 0) return KOCKET_NO_ERROR;
	
	DEBUG_LOG("kocket queue not empty: %u", err);

	KocketPacketEntry packet_entry = {0};
	if ((err = kocket_dequeue(&kocket_writing_queue, &packet_entry)) < 0) {
		WARNING_LOG("Failed to dequeue from the kocket_writing_queue.");
		return err;
	}
	
	if ((err = kocket_send(*kocket, packet_entry.kocket_packet)) < 0) {
		WARNING_LOG("Failed to send the queued kocket_packet.");
		return err;
	}
	
	KOCKET_SAFE_FREE(packet_entry.kocket_packet.payload);

	return KOCKET_NO_ERROR;
}

// This will be the function executed by the kocket-thread.
void* kocket_dispatcher(void* kocket_arg) {
	ClientKocket kocket = {0};
	mem_cpy(&kocket, (ClientKocket*) kocket_arg, sizeof(ClientKocket));
	
	int err = 0;
	while (!thread_should_stop()) {
		int ret = poll(&(kocket.poll_fd), 1, KOCKET_TIMEOUT_MS);
		if (ret < 0) {
			PERROR_LOG("Failed to perform the read/accept poll");
			err = -KOCKET_IO_ERROR;
			break;
		} else if (ret == 0) continue;
		
		DEBUG_LOG("poll: 0x%X - 0x%X, 0x%X", kocket.poll_fd.revents & POLLIN, kocket.poll_fd.revents & POLLOUT, kocket.poll_fd.revents);

		if ((kocket.poll_fd.revents & POLLIN) && (ret = kocket_recv(kocket)) < 0) {
			WARNING_LOG("An error occurred while receiving.");
			err = ret;
			break;
		}
		
		if ((ret = kocket_poll_write(&kocket)) < 0) {
			WARNING_LOG("An error occurred while performing poll_write.");
			err = ret;
			break;
		}
	}
	
	close(kocket.socket);

	DEBUG_LOG("Closed socket and thread.");

	return (void*)(intptr_t) err;
}

void wait_queue_free_elements(KocketQueue* kocket_queue) {
	KocketWaitEntry* kocket_wait_entries = KOCKET_CAST_PTR(kocket_queue -> elements, KocketWaitEntry);
	for (u32 i = 0; i < kocket_queue -> size; ++i) kocket_mutex_destroy(&(kocket_wait_entries[i].lock));
	KOCKET_SAFE_FREE(kocket_queue -> elements);
	return;
}

void packet_queue_free_elements(KocketQueue* kocket_queue) {
	KocketPacketEntry* kocket_packet_entries = KOCKET_CAST_PTR(kocket_queue -> elements, KocketPacketEntry);
	for (u32 i = 0; i < kocket_queue -> size; ++i) KOCKET_SAFE_FREE(kocket_packet_entries[i].kocket_packet.payload);
	KOCKET_SAFE_FREE(kocket_queue -> elements);
	return;
}

#endif //_U_KOCKET_H_

