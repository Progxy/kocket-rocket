#ifndef _K_KOCKET_H_
#define _K_KOCKET_H_

#include "common_kocket.h"

int kocket_write(u32 kocket_client_id, KocketStruct kocket_struct);
int kocket_read(u32 req_id, KocketStruct* kocket_struct, bool wait_response);
int kocket_init(Kocket* kocket);
void kocket_deallocate(Kocket* kocket);
int kocket_dispatcher(Kocket* kocket);

/* -------------------------------------------------------------------------------------------------------- */
int kocket_init(Kocket* kocket) {
	mem_set(kocket, 0, sizeof(Kocket));
	
	kocket -> socket = socket(AF_INET, SOCK_STREAM, SOCK_NONBLOCK);
	if (kocket -> socket == -1) {
		PERROR_LOG("An error occurred while creating the socket");
		return -KOCKET_IO_ERROR;
	}

	kocket -> sock_addr.sin_family = AF_INET;
	kocket -> sock_addr.sin_port = htons(kocket -> port);
	kocket -> sock_addr.sin_addr.s_addr = htonl(kocket -> kocket_address);

	if (bind(kocket -> socket, (struct sockaddr *)&kocket -> sock_addr, sizeof(kocket -> sock_addr)) < 0) {
		close(kocket -> socket);
		PERROR_LOG("An error occurred while binding the socket");
		return -KOCKET_IO_ERROR;
	}

	if (listen(kocket -> socket, kocket -> backlog) < 0) {
		PERROR_LOG("An error occurred while trying to listen on the socket");
		close(kocket -> socket);
		return -KOCKET_IO_ERROR;
	}

	if (use_secure_connection) {
		WARNING_LOG("The secure connection stack has not been implemented yet.\n");
		return -KOCKET_TODO;
	}

	// TODO: Should probably create the thread from here, in that case start the thread and store the thread_pid within a given ptr

	return KOCKET_NO_ERROR;
}

void kocket_deallocate(Kocket* kocket) {
	// TODO: Stop the thread if it still running, preventing race conditions on the use of the kocket passed
	
	kocket_deallocate_queue(&kocket_writing_queue);
	kocket_deallocate_queue(&kocket_reads_queue);
	
	// Close all the clients connections
	// TODO: Probably should be better to introduce a default type_flag to close the connection
	for (u32 i = 0; i < kocket -> clients_cnt; ++i) close((kocket -> clients)[i]);
	
	SAFE_FREE(kocket -> clients);
	SAFE_FREE(kocket -> polls);
	kocket -> clients_cnt = 0;
	
	// Close the server socket, to prevent incoming connections 
	close(kocket -> socket);
	
	return KOCKET_NO_ERROR;
}

int kocket_write(u32 kocket_client_id, KocketStruct kocket_struct) {
	if ((err = kocket_enqueue(&kocket_writing_queue, kocket_struct, kocket_client_id)) < 0) {
		WARNING_LOG("Failed to enqueue the given kocket_struct.\n");
		return err;
	}
	return KOCKET_NO_ERROR;
}

int kocket_read(u32 req_id, KocketStruct* kocket_struct, bool wait_response) {
	int ret = 0;
	if ((ret = kocket_queue_find(&kocket_reads_queue, req_id, kocket_struct)) < 0) {
		WARNING_LOG("An error occurred while finding withing the queue")
		return ret;
	}
	
	if (ret == KOCKET_REQ_NOT_FOUND && wait_response) {
		// TODO: find a way to wait until the response with matching req_id arrives.
		return KOCKET_NO_ERROR;
	} else if (ret == KOCKET_REQ_NOT_FOUND) return KOCKET_NO_ERROR;

	return KOCKET_NO_ERROR;
}

static int kocket_send(Kocket kocket, u32 kocket_client_id, KocketStruct kocket_struct) {
	if (kocket_client_id >= kocket.clients_cnt) {
		WARNING_LOG("Kocket client if out of bound: %u >= %u.\n", kocket_client_id, kocket.clients_cnt);
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

	// TODO: Check if setting the following with the NON-BLOCKING flag would be useful
	if (send((kocket.clients)[kocket_client_id], payload, payload_size, 0) < (ssize_t) payload_size) {
		SAFE_FREE(payload);
		PERROR_LOG("An error occurred while sending %u bytes to client %u", data_size, kocket_client_id);
		return -KOCKET_IO_ERROR;
	}
	
	SAFE_FREE(payload);

	return KOCKET_NO_ERROR;
}

static int kocket_recv(Kocket kocket, u32 kocket_client_id) {
	if (kocket_client_id >= kocket.clients_cnt) {
		WARNING_LOG("Kocket client if out of bound: %u >= %u.\n", kocket_client_id, kocket.clients_cnt);
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
	if ((ret = type_has_handler(kocket, kocket_struct.type_id)) > KOCKET_HAS_NO_HANDLER) {
		if ((ret = (*((kocket.kocket_types)[kocket_struct.type_id].kocket_handler)) (kocket_struct)) < 0) {
			WARNING_LOG("An error occurred while executing the handler for the type: '%s'\n", (kocket.kocket_types)[kocket_struct.type_id].type_name);
			return ret;
		}
	} else if (ret < 0) {
		WARNING_LOG("An error occurred while trying to check if type '%s' has an handler.\n", (kocket.kocket_types)[kocket_struct.type_id].type_name);
		return ret;
	}

	if ((ret = kocket_enqueue(&kocket_writing_queue, kocket_struct, kocket_client_id)) < 0) {
		WARNING_LOG("Failed to enqueue the given kocket_struct.\n");
		return ret;
	}
	
	return KOCKET_NO_ERROR;
}

// This will be the function executed by the kocket-thread.
// On this function error the function that executes this function in the thread, 
// should be responsible of calling the init, deallocation and setting the global error status
int kocket_dispatcher(Kocket* kocket) {
	while (TRUE) {
		int ret = poll(kocket -> polls, kocket -> clients_cnt + 1, KOCKET_TIMEOUT_MS);
		if (ret < 0) {
			PERROR_LOG("Failed to perform the read/accept poll");
			return -KOCKET_IO_ERROR;
		} else if (ret != 0) {
			if ((kocket -> polls)[0].revents & POLLIN) {
				int new_client = accept4(server_sock, NULL, NULL, SOCK_NONBLOCK);
				if (new_client > 0) {
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
				if ((kocket -> polls)[i].fd != -1 && ((kocket -> polls)[i].revents & POLLIN) && (err = kocket_recv(*kocket, i)) {
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

					close((kocket -> polls)[i].fd);
				}
			}
		}

		if ((err = is_kocket_queue_empty(&kocket_writing_queue)) > 0) {
			for (kocket_writing_queue.size > 0) {
				u32 kocket_client_id = 0;
				KocketStruct kocket_struct = {0};
				if ((err = kocket_dequeue(kocket_writing_queue, &kocket_struct, &kocket_client_id)) < 0) {
					WARNING_LOG("Failed to dequeue from the kocket_writing_queue.\n");
					return err;
				}
				
				if ((err = kocket_send(*kocket, kocket_client_id, kocket_struct)) < 0) {
					WARNING_LOG("Failed to send the queued kocket_struct.\n");
					return err;
				}
			}
		} else if (err < 0) {
			WARNING_LOG("An error occurred while checking if the kocket_writing_queue was empty.\n");
			return err;
		}
	}
	
	return KOCKET_NO_ERROR;
}

#endif //_K_KOCKET_H_

