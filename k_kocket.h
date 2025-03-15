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
#include <linux/signal.h>

// ------------------
//  Static Variables
// ------------------
static struct task_struct* kthread = NULL;

/* -------------------------------------------------------------------------------------------------------- */
// ------------------------
//  Functions Declarations
// ------------------------
int kocket_init(ServerKocket kocket);
int kocket_deinit(KocketStatus status);
static void kocket_deinit_thread(ServerKocket* kocket, KocketStatus status);
int kocket_write(u32 kocket_client_id, KocketStruct* kocket_struct);
int kocket_read(u64 req_id, KocketStruct* kocket_struct, bool wait_response);
static int kocket_send(ServerKocket kocket, u32 kocket_client_id, KocketStruct kocket_struct);
static int kocket_recv(ServerKocket kocket, u32 kocket_client_id) ;
static int kocket_poll_read_accept(ServerKocket* kocket);
int kocket_dispatcher(void* kocket_arg);

/* -------------------------------------------------------------------------------------------------------- */
int kocket_init(ServerKocket kocket) {
	int err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &(kocket.socket));
	if (kocket.socket == NULL) {
		PERROR_LOG("An error occurred while creating the socket", err);
		return -KOCKET_IO_ERROR;
	}

	kocket.sock_addr.sin_family = AF_INET;
	kocket.sock_addr.sin_port = htons(kocket.port);
	kocket.sock_addr.sin_addr.s_addr = htonl(kocket.address);
	
	const struct proto_ops* kocket_sock_ops = kocket.socket -> ops;
	if ((err = kocket_sock_ops -> bind(kocket.socket, (struct sockaddr*) &(kocket.sock_addr), sizeof(kocket.sock_addr))) < 0) {
		sock_release(kocket.socket);
		PERROR_LOG("An error occurred while binding the socket", err);
		return -KOCKET_IO_ERROR;
	}

	if ((err = kocket_sock_ops -> listen(kocket.socket, kocket.backlog)) < 0) {
		PERROR_LOG("An error occurred while trying to listen on the socket", err);
		sock_release(kocket.socket);
		return -KOCKET_IO_ERROR;
	}

	// TODO: Implement the algorithms needed for ensuring connection security
	if (kocket.use_secure_connection) {
		sock_release(kocket.socket);
		WARNING_LOG("The secure connection stack has not been implemented yet.\n");
		return -KOCKET_TODO;
	}

	kocket.poll_sockets = (PollSocket*) kocket_calloc(1, sizeof(PollSocket));
	if (kocket.poll_sockets == NULL) {
		sock_release(kocket.socket);
		WARNING_LOG("Failed to allocate the buffer for polls array.\n");
		return -KOCKET_IO_ERROR;
	} 

	(kocket.poll_sockets)[0].socket = kocket.socket;
	
	mutex_init(&kocket_status_lock);

	if ((err = kocket_alloc_queue(&kocket_writing_queue)) < 0) {
		WARNING_LOG("Failed to allocate the writing_queue.\n");
		return err;
	}

	if ((err = kocket_alloc_queue(&kocket_reads_queue)) < 0) {
		WARNING_LOG("Failed to allocate the writing_queue.\n");
		return err;
	}
	
	ServerKocket* server_kocket = (ServerKocket*) kocket_calloc(1, sizeof(ServerKocket));
	if (server_kocket == NULL) {
		sock_release(kocket.socket);
		KOCKET_SAFE_FREE(kocket.poll_sockets);
		WARNING_LOG("Failed to allocate the buffer for server_socket.\n");
		return -KOCKET_IO_ERROR;	
	}

	mem_cpy(server_kocket, &kocket, sizeof(ServerKocket));

	kthread = kthread_run(kocket_dispatcher, server_kocket, "kocket_kthread");
	if (IS_ERR(kthread)) {
		sock_release(server_kocket -> socket);
		KOCKET_SAFE_FREE(server_kocket -> poll_sockets);
		KOCKET_SAFE_FREE(server_kocket);
		WARNING_LOG("Failed to create and run the kthread.\n");
		return -KOCKET_IO_ERROR;
	}

	return KOCKET_NO_ERROR;
}

#include <linux/sched.h>
int kocket_deinit(KocketStatus status) {
	WARNING_LOG("kthread: %p, __state: %u", kthread, kthread -> __state);
	if (!IS_ERR_OR_NULL(kthread) && task_state_index(kthread) != TASK_DEAD) {
		WARNING_LOG("task_state: %d", task_state_index(kthread));
		kthread_stop(kthread);
	}
	
	mutex_lock(&kocket_status_lock);

	kocket_status = status;

	mutex_unlock(&kocket_status_lock);

	return KOCKET_NO_ERROR;
}

static void kocket_deinit_thread(ServerKocket* kocket, KocketStatus status) {
	mutex_lock(&kocket_status_lock);
	kocket_status = status;
	mutex_unlock(&kocket_status_lock);
	
	if (kocket_deallocate_queue(&kocket_writing_queue, FALSE)) {
		WARNING_LOG("Failed to deallocate the queue.\n");
	}

	if (kocket_deallocate_queue(&kocket_reads_queue, TRUE)) {
		WARNING_LOG("Failed to deallocate the queue.\n");
	}
	
	// Close all the clients connections
	// TODO: Probably should be better to introduce a default kocket_type,
	// to close the connection on both ends instead of closing only from this side
	for (u32 i = 0; i < kocket -> clients_cnt; ++i) sock_release((kocket -> clients)[i]);
	
	KOCKET_SAFE_FREE(kocket -> clients);
	KOCKET_SAFE_FREE(kocket -> poll_sockets);
	kocket -> clients_cnt = 0;
	
	// Close the server socket, to prevent incoming connections 
	sock_release(kocket -> socket);

	return;
}

int kocket_write(u32 kocket_client_id, KocketStruct* kocket_struct) {
	mutex_lock(&kocket_status_lock);
	if (kocket_status) return kocket_status;
	mutex_unlock(&kocket_status_lock);
	
	u8 initialization_vector[64] = {0};
	kocket_struct -> req_id = *KOCKET_CAST_PTR(cha_cha20(initialization_vector), u64);
	
	int err = 0;
	if ((err = kocket_enqueue(&kocket_writing_queue, *kocket_struct, kocket_client_id)) < 0) {
		WARNING_LOG("Failed to enqueue the given kocket_struct.\n");
		return err;
	}
	
	return KOCKET_NO_ERROR;
}

int kocket_read(u64 req_id, KocketStruct* kocket_struct, bool wait_response) {
	mutex_lock(&kocket_status_lock);
	if (kocket_status) return kocket_status;
	mutex_unlock(&kocket_status_lock);
	
	int ret = 0;
	if ((ret = kocket_dequeue_find(&kocket_reads_queue, req_id, kocket_struct)) < 0) {
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
	void* payload = kocket_calloc(payload_size, sizeof(u8));
	if (payload == NULL) {
		WARNING_LOG("Failed to allocate the buffer for the payload.\n");
		return -KOCKET_IO_ERROR;
	}
	
	mem_cpy(payload, &kocket_struct, sizeof(KocketStruct) - sizeof(u8*));
	mem_cpy(payload + sizeof(KocketStruct) - sizeof(u8*), kocket_struct.payload, kocket_struct.payload_size);

	int err = 0;
	struct kvec vec = { .iov_len = payload_size, .iov_base = payload };
	struct msghdr msg_hdr = {0};
	if ((err = kernel_sendmsg((kocket.clients)[kocket_client_id], &msg_hdr, &vec, payload_size, payload_size)) < (ssize_t) payload_size) {
		KOCKET_SAFE_FREE(payload);
		PERROR_LOG("An error occurred while sending %u bytes to client %u", err, payload_size, kocket_client_id);
		return -KOCKET_IO_ERROR;
	}
	
	KOCKET_SAFE_FREE(payload);

	return KOCKET_NO_ERROR;
}

static int kocket_recv(ServerKocket kocket, u32 kocket_client_id) {
	if (kocket_client_id >= kocket.clients_cnt) {
		WARNING_LOG("ServerKocket client if out of bound: %u >= %u.\n", kocket_client_id, kocket.clients_cnt);
		return -INVALID_KOCKET_CLIENT_ID;
	}
	
	int err = 0;
	struct msghdr msg_hdr = {0};
	KocketStruct kocket_struct = {0};
	struct kvec vec = { .iov_len = sizeof(KocketStruct) - sizeof(u8*), .iov_base = &kocket_struct };
	if ((err = kernel_recvmsg((kocket.clients)[kocket_client_id], &msg_hdr, &vec, sizeof(KocketStruct) - sizeof(u8*), sizeof(KocketStruct) - sizeof(u8*), 0)) < (sizeof(KocketStruct) - sizeof(u8*))) {
		PERROR_LOG("An error occurred while reading from the client", err);
		return -KOCKET_IO_ERROR;
	}

	kocket_struct.payload = (u8*) kocket_calloc(kocket_struct.payload_size, sizeof(u8));
	if (kocket_struct.payload == NULL) {
		WARNING_LOG("An error occurred while allocating the buffer for the payload.\n");
		return -KOCKET_IO_ERROR;
	}
	
	msg_hdr = (struct msghdr) {0};
	vec = (struct kvec) { .iov_len = kocket_struct.payload_size, .iov_base = kocket_struct.payload };
	if ((err = kernel_recvmsg((kocket.clients)[kocket_client_id], &msg_hdr, &vec, kocket_struct.payload_size, kocket_struct.payload_size, 0)) < kocket_struct.payload_size) {
		KOCKET_SAFE_FREE(kocket_struct.payload);
		PERROR_LOG("An error occurred while reading from the client", err);
		return -KOCKET_IO_ERROR;
	}
	
	int ret = 0;
	if (kocket_struct.type_id < kocket.kocket_types_cnt && (kocket.kocket_types)[kocket_struct.type_id].has_handler) {
		if ((ret = (*((kocket.kocket_types)[kocket_struct.type_id].kocket_handler)) (kocket_client_id, kocket_struct)) < 0) {
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

static int kocket_release_client(ServerKocket* kocket, u32 index) {
	if (kocket -> clients_cnt <= index) {
		WARNING_LOG("Index out of bound: %u > %u\n", index, kocket -> clients_cnt);
		return -KOCKET_INVALID_PARAMETERS;
	}
	
	sock_release((kocket -> clients)[index]);
	
	mem_move(kocket -> poll_sockets + index, kocket -> poll_sockets + index + 1, sizeof(PollSocket) * (kocket -> clients_cnt - index - 1));
	mem_move(kocket -> clients + index, kocket -> clients + index + 1, sizeof(struct socket*) * (kocket -> clients_cnt - index - 1)); 
	
	kocket -> clients = (struct socket**) kocket_realloc(kocket -> clients, (--(kocket -> clients_cnt)) * sizeof(struct socket*));
	if (kocket -> clients == NULL) {
		WARNING_LOG("Failed to reallocate the buffer for clients array.\n");
		return -KOCKET_IO_ERROR;
	} 
	
	kocket -> poll_sockets = (PollSocket*) kocket_realloc(kocket -> poll_sockets, (kocket -> clients_cnt + 1) * sizeof(PollSocket));
	if (kocket -> poll_sockets == NULL) {
		WARNING_LOG("Failed to reallocate the buffer for polls array.\n");
		return -KOCKET_IO_ERROR;
	}

	return KOCKET_NO_ERROR;
}

static int kocket_poll(PollSocket* poll_sockets, u32 sks_cnt, u32 timeout) {
    if (poll_sockets == NULL) {
		WARNING_LOG("poll_sockets must be non-NULL: %p.\n", poll_sockets);
		return -KOCKET_INVALID_PARAMETERS;
	}
	
	int mask = 0;
	for (u32 i = 0; i < sks_cnt; ++i) {
		struct sock* sk = poll_sockets[i].socket -> sk;
		wait_event_interruptible_timeout(sk -> sk_wq -> wait,
			!skb_queue_empty(&(sk -> sk_receive_queue)) ||
			sock_writeable(sk)                          ||
			sk -> sk_err                                ||
			!skb_queue_empty(&(sk -> sk_error_queue))   ||
			(sk -> sk_shutdown & RCV_SHUTDOWN),
			timeout / sks_cnt
		);
		
		if (sk -> sk_state == TCP_LISTEN) {
			poll_sockets[i].reg_events = inet_csk_listen_poll(sk);
			continue;
		}
		
		if (!skb_queue_empty(&(sk -> sk_receive_queue))) poll_sockets[i].reg_events |= POLLIN | POLLRDNORM;
		if (sock_writeable(sk)) poll_sockets[i].reg_events |= POLLOUT | POLLWRNORM;
		if (sk -> sk_err || !skb_queue_empty(&(sk -> sk_error_queue))) poll_sockets[i].reg_events |= POLLERR;
		if (sk -> sk_shutdown & RCV_SHUTDOWN) poll_sockets[i].reg_events |= POLLHUP;
		mask |= poll_sockets[i].reg_events;
	}

    return mask; 
}

static int kocket_poll_read_accept(ServerKocket* kocket) {
	int ret = 0;
	if ((kocket -> poll_sockets)[0].reg_events & POLLIN) {
		struct socket* new_client = {0};
		if ((ret = kernel_accept(kocket -> socket, &new_client, SOCK_NONBLOCK)) < 0) {
			PERROR_LOG("Failed to accept the incoming connection request", ret);
			return ret;
		}
		
		// TODO: Check if it needs to first establish a secure channel
		kocket -> clients = (struct socket**) kocket_realloc(kocket -> clients, (++(kocket -> clients_cnt)) * sizeof(struct socket*));
		if (kocket -> clients == NULL) {
			WARNING_LOG("Failed to reallocate the buffer for clients array.\n");
			return -KOCKET_IO_ERROR;
		} 
		
		(kocket -> clients)[kocket -> clients_cnt - 1] = new_client;

		kocket -> poll_sockets = (PollSocket*) kocket_realloc(kocket -> poll_sockets, (kocket -> clients_cnt + 1) * sizeof(PollSocket));
		if (kocket -> poll_sockets == NULL) {
			WARNING_LOG("Failed to reallocate the buffer for polls array.\n");
			return -KOCKET_IO_ERROR;
		} 
	} else if ((kocket -> poll_sockets)[0].reg_events & POLLERR) {
		WARNING_LOG("An error occurred in the server socket.\n");
		return -KOCKET_IO_ERROR;
	}
	
	int err = 0;
	for (unsigned int i = 1; i < kocket -> clients_cnt + 1; ++i) {
		if (((kocket -> poll_sockets)[i].reg_events & POLLERR) || (((kocket -> poll_sockets)[i].reg_events & POLLIN) && (err = kocket_recv(*kocket, i) < 0))) {
			if ((err = kocket_release_client(kocket, i)) < 0) { 
				WARNING_LOG("Failed to release the client %u.\n", i + 1);
				return err;
			}
		}
	}

	return KOCKET_NO_ERROR;
}

static int kocket_poll_write(ServerKocket* kocket) {
	int err = 0;
	if ((err = is_kocket_queue_empty(&kocket_writing_queue)) < 0) {
		WARNING_LOG("An error occurred while checking if the kocket_writing_queue was empty.\n");
		return err;
	}
	
	u32 kocket_queue_size = err;
	for (u32 i = 0; i < kocket_queue_size; ++i) {
		u32 kocket_client_id = 0;
		if ((err = kocket_queue_get_n_client_id(&kocket_writing_queue, i, &kocket_client_id)) < 0) {
			WARNING_LOG("Failed to get the %u client_id from the kocket_writing_queue.\n", i + 1);
			return err;
		}

		if (!((kocket -> poll_sockets)[kocket_client_id + 1].reg_events & POLLOUT)) continue;
		
		KocketStruct kocket_struct = {0};
		if ((err = kocket_dequeue(&kocket_writing_queue, &kocket_struct, &kocket_client_id)) < 0) {
			WARNING_LOG("Failed to dequeue from the kocket_writing_queue.\n");
			return err;
		}
		
		if ((err = kocket_send(*kocket, kocket_client_id, kocket_struct)) < 0) {
			WARNING_LOG("Failed to send the queued kocket_struct.\n");
			return err;
		}
	}

	return KOCKET_NO_ERROR;
}

// This will be the function executed by the kocket-thread.
int kocket_dispatcher(void* kocket_arg) {
	ServerKocket kocket = *KOCKET_CAST_PTR(kocket_arg, ServerKocket);
	KOCKET_SAFE_FREE(kocket_arg);
	
	allow_signal(SIGKILL | SIGTERM);

	int err = KOCKET_NO_ERROR;
	while (!kthread_should_stop()) {
		int ret = 0;
		if ((ret = kocket_poll(kocket.poll_sockets, kocket.clients_cnt + 1, KOCKET_TIMEOUT_MS)) == 0) continue;
		else if (ret < 0) {
			WARNING_LOG("An error occurred while polling.\n");
			err = ret;
			break;
		}
		
		if ((ret = kocket_poll_read_accept(&kocket)) < 0) {
			WARNING_LOG("An error occurred while polling read/accept.\n");
			err = ret;
			break;
		}

		if ((ret = kocket_poll_write(&kocket)) < 0) {
			WARNING_LOG("An error occurred while polling write.\n");
			err = ret;
			break;
		}

		if (signal_pending(kthread)) break;
	}
	
	kocket_deinit_thread(&kocket, err);

	// do_exit(0);
		
	return err;
}

#endif //_K_KOCKET_H_

