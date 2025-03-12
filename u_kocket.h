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

int kocket_write(u32 kocket_client_id, KocketStruct kocket_struct);
int kocket_read(u64 req_id, KocketStruct* kocket_struct, bool wait_response);
int kocket_init(ClientKocket* kocket);
void kocket_deallocate(ClientKocket* kocket);
void kocket_dispatcher(void* kocket_arg);

/* -------------------------------------------------------------------------------------------------------- */
int kocket_init(ClientKocket* kocket, struct task_struct *kthread) {
	if ((kocket -> socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		PERROR_LOG("An error occurred while creating the socket");
		return -KOCKET_IO_ERROR;
	}

	server_sock_addr.sin_family = AF_INET;
	server_sock_addr.sin_port = htons(kocket -> port);
	server_sock_addr.sin_addr.s_addr = htonl(kocket -> kocket_address);

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

	// TODO: Implement the algorithms needed for ensuring connection security
	if (kocket -> use_secure_connection) {
		WARNING_LOG("The secure connection stack has not been implemented yet.\n");
		return -KOCKET_TODO;
	}

	kthread = kthread_run(kocket_dispatcher, (void*) kocket, "kocket_kthread");
	if (kthread == NULL) {
		WARNING_LOG("Failed to create and run the kthread.\n");
		return -KOCKET_IO_ERROR;
	}

	return KOCKET_NO_ERROR;
}

int kocket_deallocate(ClientKocket* kocket, KocketStatus status, struct task_struct* kthread) {
	if (kthread != NULL && kthread -> state != TASK_DEAD) {
		kthread_stop(kthread);
		put_task_struct(kthread);
	}

	kocket_deallocate_queue(&kocket_writing_queue);
	kocket_deallocate_queue(&kocket_reads_queue);
	
	// Close all the clients connections
	// TODO: Probably should be better to introduce a default kocket_type,
	// to close the connection on both ends instead of closing only from this side
	for (u32 i = 0; i < kocket -> clients_cnt; ++i) close((kocket -> clients)[i]);
	
	close(kocket -> socket);
	
	if (down_interruptible(&kocket_status_sem)) {
        WARNING_LOG("Failed to acquire the semaphore.\n");
        return -KOCKET_IO_ERROR;
    }
	
	kocket_status = status;
	
	up(&kocket_status_sem);

	return KOCKET_NO_ERROR;
}

int kocket_write(u32 kocket_client_id, KocketStruct* kocket_struct) {
	u8 initialization_vector[64] = {0};
	kocket_struct -> req_id = *KOCKET_CAST_PTR(cha_cha20(initialization_vector), u64);
	if ((err = kocket_enqueue(&kocket_writing_queue, *kocket_struct, kocket_client_id)) < 0) {
		WARNING_LOG("Failed to enqueue the given kocket_struct.\n");
		return err;
	}
	return KOCKET_NO_ERROR;
}

int kocket_read(u64 req_id, KocketStruct* kocket_struct, bool wait_response) {
	int ret = 0;
	if ((ret = kocket_queue_find(&kocket_reads_queue, req_id, kocket_struct)) < 0) {
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
	void* payload = calloc(payload_size, sizeof(u8));
	if (payload == NULL) {
		WARNING_LOG("Failed to allocate the buffer for the payload.\n");
		return -KOCKET_IO_ERROR;
	}
	
	mem_cpy(payload, kocket_struct, sizeof(KocketStruct) - sizeof(u8*));
	mem_cpy(payload + sizeof(KocketStruct) - sizeof(u8*), kocket_struct.payload, kocket.payload_size);

	if (send(kocket.socket, payload, payload_size, 0) < (ssize_t) payload_size) {
		SAFE_FREE(payload);
		PERROR_LOG("An error occurred while sending %u bytes", data_size);
		return -KOCKET_IO_ERROR;
	}
	
	SAFE_FREE(payload);

	return KOCKET_NO_ERROR;
}

static int kocket_recv(ClientKocket kocket) {
	KocketStruct kocket_struct = {0};

	if (recv(kocket.socket, &kocket_struct, sizeof(KocketStruct) - sizeof(u8*), 0) < (sizeof(KocketStruct) - sizeof(u8*))) {
		PERROR_LOG("An error occurred while reading from the client.\n");
		return -KOCKET_IO_ERROR;
	}

	kocket_struct.payload = (u8*) calloc(kocket_struct.payload_size, sizeof(u8));
	if (kocket_struct.payload == NULL) {
		WARNING_LOG("An error occurred while allocating the buffer for the payload.\n");
		return -KOCKET_IO_ERROR;
	}
	
	if (recv(kocket.socket, kocket_struct.payload, kocket_struct.payload_size, 0) < kocket_struct.payload_size) {
		SAFE_FREE(kocket_struct -> payload);
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

// This will be the function executed by the kocket-thread.
void kocket_dispatcher(void* kocket_arg) {
	int err = 0;
	ClientKocket* kocket = (ClientKocket*) kocket_arg;
	while (!kthread_should_stop()) {
		int ret = poll(kocket -> poll_fd, 1, KOCKET_TIMEOUT_MS);
		if (ret < 0) {
			kocket_deallocate(kocket, -KOCKET_IO_ERROR, NULL);
			PERROR_LOG("Failed to perform the read/accept poll");
			return;
		} else if (ret != 0 && ((kocket -> poll_fd)[i].revents & POLLIN) && (err = kocket_recv(*kocket)) < 0) {
			kocket_deallocate(kocket, err, NULL);
			WARNING_LOG("An error occurred while receiving.\n");
			return; 
		}
		
		if ((err = is_kocket_queue_empty(&kocket_writing_queue)) > 0) {
			for (kocket_writing_queue.size > 0) {
				u32 kocket_client_id = 0;
				KocketStruct kocket_struct = {0};
				if ((err = kocket_dequeue(kocket_writing_queue, &kocket_struct, &kocket_client_id)) < 0) {
					kocket_deallocate(kocket, err, NULL);
					WARNING_LOG("Failed to dequeue from the kocket_writing_queue.\n");
					return;
				}
				
				if ((err = kocket_send(*kocket, kocket_struct)) < 0) {
					kocket_deallocate(kocket, err, NULL);
					WARNING_LOG("Failed to send the queued kocket_struct.\n");
					return;
				}
			}
		} else if (err < 0) {
			kocket_deallocate(kocket, err, NULL);
			WARNING_LOG("An error occurred while checking if the kocket_writing_queue was empty.\n");
			return;
		}
	}
	
	return KOCKET_NO_ERROR;
}

#endif //_U_KOCKET_H_

