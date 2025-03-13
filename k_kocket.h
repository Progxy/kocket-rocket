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

#ifndef _K_KOCKET_H_
#define _K_KOCKET_H_

#include "common_kocket.h"
#include "./crypto/chacha20.h"

int kocket_write(u32 kocket_client_id, KocketStruct kocket_struct);
int kocket_read(u64 req_id, KocketStruct* kocket_struct, bool wait_response);
int kocket_init(ServerKocket* kocket, struct task_struct *kthread);
void kocket_deinit(ServerKocket* kocket);
void kocket_dispatcher(void* kocket_arg);

/* -------------------------------------------------------------------------------------------------------- */
int kocket_init(ServerKocket* kocket, struct task_struct *kthread) {
	kocket -> socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (kocket -> socket == -1) {
		PERROR_LOG("An error occurred while creating the socket");
		return -KOCKET_IO_ERROR;
	}

	kocket -> sock_addr.sin_family = AF_INET;
	kocket -> sock_addr.sin_port = htons(kocket -> port);
	kocket -> sock_addr.sin_addr.s_addr = htonl(kocket -> kocket_address);

	if (bind(kocket -> socket, (struct sockaddr *) &(kocket -> sock_addr), sizeof(kocket -> sock_addr)) < 0) {
		close(kocket -> socket);
		PERROR_LOG("An error occurred while binding the socket");
		return -KOCKET_IO_ERROR;
	}

	if (listen(kocket -> socket, kocket -> backlog) < 0) {
		PERROR_LOG("An error occurred while trying to listen on the socket");
		close(kocket -> socket);
		return -KOCKET_IO_ERROR;
	}

	// TODO: Implement the algorithms needed for ensuring connection security
	if (kocket -> use_secure_connection) {
		WARNING_LOG("The secure connection stack has not been implemented yet.\n");
		return -KOCKET_TODO;
	}

	kocket -> polls = (struct pollfd*) calloc(1, sizeof(struct pollfd));
	if (kocket -> polls == NULL) {
		WARNING_LOG("Failed to reallocate the buffer for polls array.\n");
		return -KOCKET_IO_ERROR;
	} 
	
	(kocket -> polls)[0].fd = kocket -> socket;
	(kocket -> polls)[0].events = POLLIN;

	mutex_init(&kocket_status_lock);

	kthread = kthread_run(kocket_dispatcher, (void*) kocket, "kocket_kthread");
	if (kthread == NULL) {
		WARNING_LOG("Failed to create and run the kthread.\n");
		return -KOCKET_IO_ERROR;
	}

	return KOCKET_NO_ERROR;
}

int kocket_deinit(ServerKocket* kocket, KocketStatus status, struct task_struct* kthread) {
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
	
	SAFE_FREE(kocket -> clients);
	SAFE_FREE(kocket -> polls);
	kocket -> clients_cnt = 0;
	
	// Close the server socket, to prevent incoming connections 
	close(kocket -> socket);
	
	mutex_lock(&kocket_status_lock);
	
	kocket_status = status;
	
	mutex_unlock(&kocket_status_lock);

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
		// It probably needs to have a waiter queue, for which it waits on the semaphore of its waiter entry (which locks cause will be initialized to 0);
		// Furthermore, the waiter will be woken when the enqueue operation finds that someone was waiting for the enqueued resource, calling semaphore_up.
		return KOCKET_NO_ERROR;
	} else if (ret == KOCKET_REQ_NOT_FOUND) return KOCKET_NO_ERROR;

	return KOCKET_NO_ERROR;
}

static int kocket_send(ServerKocket kocket, u32 kocket_client_id, KocketStruct kocket_struct) {
	if (kocket_client_id >= kocket.clients_cnt) {
		WARNING_LOG("ServerKocket client if out of bound: %u >= %u.\n", kocket_client_id, kocket.clients_cnt);
		return -INVALID_KOCKET_CLIENT_ID;
	}
	
	u32 payload_size = sizeof(KocketStruct) - sizeof(u8*) + kocket_struct.payload_size;
	void* payload = calloc(payload_size, sizeof(u8));
	if (payload == NULL) {
		WARNING_LOG("Failed to allocate the buffer for the payload.\n");
		return -KOCKET_IO_ERROR;
	}
	
	mem_cpy(payload, kocket_struct, sizeof(KocketStruct) - sizeof(u8*));
	mem_cpy(payload + sizeof(KocketStruct) - sizeof(u8*), kocket_struct.payload, kocket.payload_size);

	if (send((kocket.clients)[kocket_client_id], payload, payload_size, 0) < (ssize_t) payload_size) {
		SAFE_FREE(payload);
		PERROR_LOG("An error occurred while sending %u bytes to client %u", data_size, kocket_client_id);
		return -KOCKET_IO_ERROR;
	}
	
	SAFE_FREE(payload);

	return KOCKET_NO_ERROR;
}

static int kocket_recv(ServerKocket kocket, u32 kocket_client_id) {
	if (kocket_client_id >= kocket.clients_cnt) {
		WARNING_LOG("ServerKocket client if out of bound: %u >= %u.\n", kocket_client_id, kocket.clients_cnt);
		return -INVALID_KOCKET_CLIENT_ID;
	}
	
	KocketStruct kocket_struct = {0};

	if (recv((kocket.clients)[kocket_client_id], &kocket_struct, sizeof(KocketStruct) - sizeof(u8*), 0) < (sizeof(KocketStruct) - sizeof(u8*))) {
		PERROR_LOG("An error occurred while reading from the client.\n");
		return -KOCKET_IO_ERROR;
	}

	kocket_struct.payload = (u8*) calloc(kocket_struct.payload_size, sizeof(u8));
	if (kocket_struct.payload == NULL) {
		WARNING_LOG("An error occurred while allocating the buffer for the payload.\n");
		return -KOCKET_IO_ERROR;
	}
	
	if (recv((kocket.clients)[kocket_client_id], kocket_struct.payload, kocket_struct.payload_size, 0) < kocket_struct.payload_size) {
		SAFE_FREE(kocket_struct -> payload);
		PERROR_LOG("An error occurred while reading from the client.\n");
		return -KOCKET_IO_ERROR;
	}
	
	int ret = 0;
	if (kocket_struct.type_id < kocket -> kocket_types_cnt && (kocket -> kocket_types)[kocket_struct.type_id].has_handler) {
		if ((ret = (*((kocket.kocket_types)[kocket_struct.type_id].kocket_handler)) (kocket_struct)) < 0) {
			WARNING_LOG("An error occurred while executing the handler for the type: '%s'\n", (kocket.kocket_types)[kocket_struct.type_id].type_name);
			return ret;
		}
	} 

	if ((ret = kocket_enqueue(&kocket_writing_queue, kocket_struct, kocket_client_id)) < 0) {
		WARNING_LOG("Failed to enqueue the given kocket_struct.\n");
		return ret;
	}
	
	return KOCKET_NO_ERROR;
}

static int kocket_poll_read_accept(ServerKocket* kocket) {
	int ret = poll(kocket -> polls, kocket -> clients_cnt + 1, KOCKET_TIMEOUT_MS);
	if (ret < 0) {
		PERROR_LOG("Failed to perform the read/accept poll");
		return -KOCKET_IO_ERROR;
	} else if (ret == 0) return KOCKET_NO_ERROR;

	if ((kocket -> polls)[0].revents & POLLIN) {
		int new_client = accept4(server_sock, NULL, NULL, SOCK_NONBLOCK);
		if (new_client > 0) {
			// TODO: Check if it needs to first establish a secure channel
			kocket -> clients = (int*) realloc(kocket -> clients, (++(kocket -> clients_cnt)) * sizeof(int));
			if (kocket -> clients == NULL) {
				WARNING_LOG("Failed to reallocate the buffer for clients array.\n");
				return -KOCKET_IO_ERROR;
			} 
			
			(kocket -> clients)[kocket -> clients_cnt - 1] = new_client;

			kocket -> polls = (struct pollfd*) realloc(kocket -> polls, (kocket -> clients_cnt + 1) * sizeof(struct pollfd));
			if (kocket -> polls == NULL) {
				WARNING_LOG("Failed to reallocate the buffer for polls array.\n");
				return -KOCKET_IO_ERROR;
			} 
			
			(kocket -> polls)[kocket -> clients_cnt - 1].fd = new_client;
			(kocket -> polls)[kocket -> clients_cnt - 1].events = POLLIN;
		}
	}

	for (unsigned int i = 1; i < kocket -> clients_cnt + 1; ++i) {
		if ((kocket -> polls)[i].fd != -1 && ((kocket -> polls)[i].revents & POLLIN) && (err = kocket_recv(*kocket, i) < 0) {
			close((kocket -> polls)[i].fd);
			
			mem_move(kocket -> polls + i, kocket -> polls + i + 1, sizeof(struct pollfd) * (kocket -> clients_cnt - i - 1));
			mem_move(kocket -> clients + i, kocket -> clients + i + 1, sizeof(int) * (kocket -> clients_cnt - i - 1)); 
			
			kocket -> clients = (int*) realloc(kocket -> clients, (--(kocket -> clients_cnt)) * sizeof(int));
			if (kocket -> clients == NULL) {
				WARNING_LOG("Failed to reallocate the buffer for clients array.\n");
				return -KOCKET_IO_ERROR;
			} 
			
			kocket -> polls = (struct pollfd*) realloc(kocket -> polls, (kocket -> clients_cnt + 1) * sizeof(struct pollfd));
			if (kocket -> polls == NULL) {
				WARNING_LOG("Failed to reallocate the buffer for polls array.\n");
				return -KOCKET_IO_ERROR;
			}
		}
	}

	return KOCKET_NO_ERROR;
}

// This will be the function executed by the kocket-thread.
void kocket_dispatcher(void* kocket_arg) {
	ServerKocket* kocket = (ServerKocket*) kocket_arg;
	while (!kthread_should_stop()) {
		if ((ret = kocket_poll_read_accept(kocket)) < 0) {ret
			kocket_deinit(kocket, ret, NULL);
			WARNING_LOG("An error occurred while polling read/accept.\n");
			return;
		}

		// TODO: As the send operations are non-blocking, we should probably also check using polling if we can send data.
		while ((err = is_kocket_queue_empty(&kocket_writing_queue)) > 0) {
			u32 kocket_client_id = 0;
			KocketStruct kocket_struct = {0};
			if ((err = kocket_dequeue(kocket_writing_queue, &kocket_struct, &kocket_client_id)) < 0) {
				kocket_deinit(kocket, err, NULL);
				WARNING_LOG("Failed to dequeue from the kocket_writing_queue.\n");
				return;
			}
			
			if ((err = kocket_send(*kocket, kocket_client_id, kocket_struct)) < 0) {
				kocket_deinit(kocket, err, NULL);
				WARNING_LOG("Failed to send the queued kocket_struct.\n");
				return;
			}
		}

		if (err < 0) {
			kocket_deinit(kocket, err, NULL);
			WARNING_LOG("An error occurred while checking if the kocket_writing_queue was empty.\n");
			return;
		}
	}
	
	return KOCKET_NO_ERROR;
}

#endif //_K_KOCKET_H_

