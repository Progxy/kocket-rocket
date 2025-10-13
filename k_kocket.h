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
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/jiffies.h>
#include <linux/completion.h>
#include <linux/delay.h>

// ------------------
//  Static Variables
// ------------------
static struct task_struct* kthread = NULL;

/* -------------------------------------------------------------------------------------------------------- */
// ------------------------
//  Functions Declarations
// ------------------------
static void kocket_deinit_structures(ServerKocket* kocket);
static int kocket_init_connection(ServerKocket* kocket);
static int kocket_init_structures(ServerKocket kocket, ServerKocket* server_kocket);
int kocket_init(ServerKocket kocket);
int kocket_deinit(KocketStatus status);
static void kocket_deinit_thread(ServerKocket* kocket, KocketStatus status);
static inline KocketStatus check_kocket_status(void);
int kocket_write(KocketPacketEntry* packet_entry, bool update_req_id);
int kocket_read(u64 req_id, KocketPacketEntry* kocket_packet, bool wait_response);
static int kocket_send(ServerKocket kocket, KocketPacketEntry packet_entry);
static int kocket_recv(ServerKocket kocket, u32 kocket_client_id);
static int kocket_release_client(ServerKocket* kocket, u32 index);
static int kocket_poll(PollSocket* poll_sockets, u32 sks_cnt, u32 timeout);
static int kocket_poll_read_accept(ServerKocket* kocket);
static int kocket_poll_write(ServerKocket* kocket);
int kocket_dispatcher(void* kocket_arg);
void wait_queue_free_elements(KocketQueue* kocket_queue);
void packet_queue_free_elements(KocketQueue* kocket_queue);

/* -------------------------------------------------------------------------------------------------------- */
static void kocket_deinit_structures(ServerKocket* kocket) {
	if (kocket_deallocate_queue(&kocket_writing_queue)) {
		WARNING_LOG("Failed to deallocate the queue.");
	}

	if (kocket_deallocate_queue(&kocket_reads_queue)) {
		WARNING_LOG("Failed to deallocate the queue.");
	}

	if (kocket_deallocate_queue(&kocket_wait_queue)) {
		WARNING_LOG("Failed to deallocate the queue.");
	}
	
	// Close all the clients connections
	DEBUG_LOG("Releasing sockets.");
	for (u32 i = 0; i < kocket -> clients_cnt; ++i) sock_release((kocket -> clients)[i]);
	
	KOCKET_SAFE_FREE(kocket -> clients);
	KOCKET_SAFE_FREE(kocket -> poll_sockets);
	kocket -> clients_cnt = 0;
	
	for (u32 i = 0; i < kocket -> kocket_types_cnt; ++i) KOCKET_SAFE_FREE((kocket -> kocket_types)[i].type_name);
	KOCKET_SAFE_FREE(kocket -> kocket_types);
	
	// Close the server socket, to prevent incoming connections 
	sock_release(kocket -> socket);
	
	return;
}

static int kocket_init_connection(ServerKocket* kocket) {
	int err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &(kocket -> socket));
	if (kocket -> socket == NULL) {
		PERROR_LOG("An error occurred while creating the socket", err);
		return -KOCKET_IO_ERROR;
	}

	(kocket -> poll_sockets)[0].socket = kocket -> socket;

	kocket -> sock_addr.sin_family = AF_INET;
	kocket -> sock_addr.sin_port = htons(kocket -> port);
	kocket -> sock_addr.sin_addr.s_addr = htonl(kocket -> address);
	
	const struct proto_ops* kocket_sock_ops = kocket -> socket -> ops;
	if ((err = kocket_sock_ops -> bind(kocket -> socket, (struct sockaddr*) &(kocket -> sock_addr), sizeof(kocket -> sock_addr))) < 0) {
		PERROR_LOG("An error occurred while binding the socket", err);
		return -KOCKET_IO_ERROR;
	}

	if ((err = kocket_sock_ops -> listen(kocket -> socket, kocket -> backlog)) < 0) {
		PERROR_LOG("An error occurred while trying to listen on the socket", err);
		return -KOCKET_IO_ERROR;
	}

	// TODO: Implement the algorithms needed for ensuring connection security
	if (kocket -> use_secure_connection) {
		WARNING_LOG("The secure connection stack has not been implemented yet.");
		return -KOCKET_TODO;
	}

	return KOCKET_NO_ERROR;
}

static int kocket_init_structures(ServerKocket kocket, ServerKocket* server_kocket) {
	int err = 0;
	if ((err = kocket_alloc_queue(&kocket_writing_queue, sizeof(KocketPacketEntry), packet_queue_free_elements)) < 0) {
		WARNING_LOG("Failed to allocate the writing_queue.");
		return err;
	}

	if ((err = kocket_alloc_queue(&kocket_reads_queue, sizeof(KocketPacketEntry), packet_queue_free_elements)) < 0) {
		WARNING_LOG("Failed to allocate the writing_queue.");
		return err;
	}
	
	if ((err = kocket_alloc_queue(&kocket_wait_queue, sizeof(KocketWaitEntry), wait_queue_free_elements)) < 0) {
		WARNING_LOG("Failed to allocate the writing_queue.");
		return err;
	}
	
	mem_cpy(server_kocket, &kocket, sizeof(ServerKocket));

	server_kocket -> poll_sockets = (PollSocket*) kocket_calloc(1, sizeof(PollSocket));
	if (server_kocket -> poll_sockets == NULL) {
		WARNING_LOG("Failed to allocate the buffer for polls array.");
		return -KOCKET_IO_ERROR;
	}

	server_kocket -> kocket_types = (KocketType*) kocket_calloc(kocket.kocket_types_cnt, sizeof(KocketType));
	if (server_kocket -> kocket_types == NULL) {
		WARNING_LOG("Failed to allocate the buffer for kocket_types.");
		return -KOCKET_IO_ERROR;
	}

	mem_cpy(server_kocket -> kocket_types, kocket.kocket_types, sizeof(KocketType) * server_kocket -> kocket_types_cnt);

	for (u32 i = 0; i < server_kocket -> kocket_types_cnt; ++i) (server_kocket -> kocket_types)[i].type_name = NULL;

	for (u32 i = 0; i < server_kocket -> kocket_types_cnt; ++i) {
		u64 type_name_len = str_len((kocket.kocket_types)[i].type_name);
		(server_kocket -> kocket_types)[i].type_name = (char*) kocket_calloc(type_name_len + 1, sizeof(char));
		if ((server_kocket -> kocket_types)[i].type_name == NULL) {
			WARNING_LOG("Failed to allocate buffer for type_name %u.", i + 1);
			return -KOCKET_IO_ERROR;
		}
		mem_cpy((server_kocket -> kocket_types)[i].type_name, (kocket.kocket_types)[i].type_name, type_name_len);
	}

	return KOCKET_NO_ERROR;
}

int kocket_init(ServerKocket kocket) {
	ServerKocket* server_kocket = (ServerKocket*) kocket_calloc(1, sizeof(ServerKocket));
	if (server_kocket == NULL) {
		WARNING_LOG("Failed to allocate the buffer for server_kocket.");
		return -KOCKET_IO_ERROR;	
	}
	
	int err = 0;
	if ((err = kocket_init_structures(kocket, server_kocket)) < 0) {
		kocket_deinit_structures(server_kocket);
		KOCKET_SAFE_FREE(server_kocket);
		WARNING_LOG("An error occurred while initializing the structures.");
		return err;
	}
	
	if ((err = kocket_init_connection(server_kocket)) < 0) {
		kocket_deinit_structures(server_kocket);
		KOCKET_SAFE_FREE(server_kocket);
		WARNING_LOG("An error occurred while initializing the connection.");
		return err;
	}

	kocket_mutex_init(&kocket_status_lock);

	kthread = kthread_run(kocket_dispatcher, server_kocket, "kocket_kthread");
	if (IS_ERR(kthread)) {
		kocket_deinit_structures(server_kocket);
		KOCKET_SAFE_FREE(server_kocket);
		WARNING_LOG("Failed to create and run the kthread.");
		return -KOCKET_IO_ERROR;
	}

	return KOCKET_NO_ERROR;
}

int kocket_deinit(KocketStatus status) {
	kocket_mutex_lock(&kocket_status_lock, DEFAULT_LOCK_TIMEOUT_SEC);
	
	if (kocket_status != KOCKET_NO_ERROR) {
		kocket_mutex_unlock(&kocket_status_lock);
		return KOCKET_NO_ERROR;
	}
	
	// TODO: This one did not catch the dead kthread one time, requires both investigation and testing
	if (!IS_ERR_OR_NULL(kthread)) {
		kocket_mutex_unlock(&kocket_status_lock);
		
		int err = kthread_stop(kthread);
		if (err < 0) {
			PERROR_LOG("kthread_stop failed", err);
			return err;
		}
	}
	
	kocket_status = status;
	kocket_mutex_unlock(&kocket_status_lock);

	return KOCKET_NO_ERROR;
}

static void kocket_deinit_thread(ServerKocket* kocket, KocketStatus status) {
	kocket_mutex_lock(&kocket_status_lock, DEFAULT_LOCK_TIMEOUT_SEC);
	kocket_status = status;
	kocket_mutex_unlock(&kocket_status_lock);
	
	kocket_deinit_structures(kocket);

	return;
}

static inline KocketStatus check_kocket_status(void) {
	KocketStatus status = KOCKET_NO_ERROR;
	kocket_mutex_lock(&kocket_status_lock, DEFAULT_LOCK_TIMEOUT_SEC);
	status = kocket_status;
	kocket_mutex_unlock(&kocket_status_lock);
	return status;
}

/// NOTE: This function expects that the payload within kocket_packet has been dynamically allocated
int kocket_write(KocketPacketEntry* packet_entry, bool update_req_id) {
	KocketStatus status = KOCKET_NO_ERROR;
	if ((status = check_kocket_status()) < 0) return status;
	
	if (update_req_id) {
		u8 initialization_vector[64] = {0};
		packet_entry -> kocket_packet.req_id = *KOCKET_CAST_PTR(cha_cha20(initialization_vector), u64);
	}
	
	int err = 0;
	if ((err = kocket_enqueue(&kocket_writing_queue, packet_entry)) < 0) {
		WARNING_LOG("Failed to enqueue the given kocket_packet.");
		return err;
	}
	
	return KOCKET_NO_ERROR;
}

int kocket_read(u64 req_id, KocketPacketEntry* kocket_packet, bool wait_response) {
	KocketStatus status = KOCKET_NO_ERROR;
	if ((status = check_kocket_status()) < 0) return status;
	
	int ret = 0;
	KocketWaitEntry* wait_entry = NULL;
	if ((ret = kocket_dequeue_packet(&kocket_reads_queue, req_id, kocket_packet, wait_response ? &kocket_wait_queue : NULL, wait_response ? &wait_entry : NULL)) < 0) {
		WARNING_LOG("An error occurred while finding withing the queue.");
		return ret;
	}
	
	if (ret == KOCKET_REQ_NOT_FOUND && wait_response) {
		kocket_mutex_lock(&(wait_entry -> lock), DEFAULT_LOCK_TIMEOUT_SEC);
		
		if ((ret = kocket_dequeue_packet(&kocket_reads_queue, req_id, kocket_packet, NULL, NULL)) < 0) {
			WARNING_LOG("An error occurred while finding withing the queue.");
			return ret;
		}
		
		kocket_mutex_unlock(&(wait_entry -> lock));

		if ((ret = kocket_dequeue_wait(&kocket_wait_queue, req_id)) < 0) {
			WARNING_LOG("An error occurred while dequeuing the wait with req_id: %llu", req_id);
			return ret;
		}

		if (ret == KOCKET_REQ_NOT_FOUND) {
			WARNING_LOG("Something must be wrong as even after waiting the data was still not there, req_id: %llu", req_id);
			return -ret;
		}

		return KOCKET_NO_ERROR;
	} else if (ret == KOCKET_REQ_NOT_FOUND) return ret;

	return KOCKET_NO_ERROR;
}

static int kocket_send(ServerKocket kocket, KocketPacketEntry packet_entry) {
	if (packet_entry.kocket_client_id >= kocket.clients_cnt) {
		WARNING_LOG("ServerKocket client if out of bound: %u >= %u.", packet_entry.kocket_client_id, kocket.clients_cnt);
		return -INVALID_KOCKET_CLIENT_ID;
	}
	
	KocketPacket kocket_packet = packet_entry.kocket_packet;
	u32 payload_size = sizeof(KocketPacket) - sizeof(u8*) + kocket_packet.payload_size;
	void* payload = kocket_calloc(payload_size, sizeof(u8));
	if (payload == NULL) {
		WARNING_LOG("Failed to allocate the buffer for the payload.");
		return -KOCKET_IO_ERROR;
	}
	
	DEBUG_LOG("Sending %u bytes to client %u, payload: %p", payload_size, packet_entry.kocket_client_id, payload);

	mem_cpy(payload, &kocket_packet, sizeof(KocketPacket) - sizeof(u8*));
	mem_cpy(KOCKET_CAST_PTR(payload, u8) + (sizeof(KocketPacket) - sizeof(u8*)), kocket_packet.payload, kocket_packet.payload_size);

	int err = 0;
	struct msghdr msg_hdr = {0};
	struct kvec vec = { .iov_len = payload_size, .iov_base = payload };
	if ((err = kernel_sendmsg((kocket.clients)[packet_entry.kocket_client_id], &msg_hdr, &vec, payload_size, payload_size)) < (ssize_t) payload_size) {
		KOCKET_SAFE_FREE(payload);
		PERROR_LOG("An error occurred while sending %u bytes to client %u", err, payload_size, packet_entry.kocket_client_id);
		return -KOCKET_IO_ERROR;
	}
	
	KOCKET_SAFE_FREE(payload);

	return KOCKET_NO_ERROR;
}

static int dispatch_handler_as_task(void* task_args) {
	KocketTask* handler_task = (KocketTask*) task_args;

	unsigned long flags = 0;
	local_irq_save(flags);

	if ((handler_task -> result = (handler_task -> kocket_handler)(handler_task -> kocket_packet_entry)) < 0) {
		WARNING_LOG("An error occurred while executing the handler for the type: '%s'", handler_task -> type_name);
	}
	
	complete(&handler_task -> done);

	local_irq_restore(flags);

	return 0;
}

static int kocket_recv(ServerKocket kocket, u32 kocket_client_id) {
	if (kocket_client_id >= kocket.clients_cnt) {
		WARNING_LOG("ServerKocket client is out of bound: %u >= %u.", kocket_client_id, kocket.clients_cnt);
		return -INVALID_KOCKET_CLIENT_ID;
	}
	
	int err = 0;
	struct msghdr msg_hdr = {0};
	KocketPacket kocket_packet = {0};
	u32 kocket_packet_hdr_size = sizeof(KocketPacket) - sizeof(u8*);
	struct kvec vec = { .iov_len = kocket_packet_hdr_size, .iov_base = &kocket_packet };
	if ((err = kernel_recvmsg((kocket.clients)[kocket_client_id], &msg_hdr, &vec, kocket_packet_hdr_size, kocket_packet_hdr_size, 0)) < kocket_packet_hdr_size) {
		CHECK_RECV_ERR(err, kocket_packet_hdr_size, kocket_packet.req_id);
		PERROR_LOG("An error occurred while reading from the client", err);
		return -KOCKET_IO_ERROR;
	}

	DEBUG_LOG("Receiving %u bytes from client %u", kocket_packet.payload_size, kocket_client_id);

	if (kocket_packet.payload_size > 0) {
		kocket_packet.payload = (u8*) kocket_calloc(kocket_packet.payload_size, sizeof(u8));
		if (kocket_packet.payload == NULL) {
			WARNING_LOG("An error occurred while allocating the buffer for the payload.");
			return -KOCKET_IO_ERROR;
		}
		
		struct msghdr payload_msg_hdr = {0};
		struct kvec payload_vec = { .iov_len = kocket_packet.payload_size, .iov_base = kocket_packet.payload };
		if ((err = kernel_recvmsg((kocket.clients)[kocket_client_id], &payload_msg_hdr, &payload_vec, kocket_packet.payload_size, kocket_packet.payload_size, 0)) < kocket_packet.payload_size) {
			KOCKET_SAFE_FREE(kocket_packet.payload);
			CHECK_RECV_ERR(err, kocket_packet.payload_size, kocket_packet.req_id);
			PERROR_LOG("An error occurred while reading from the client", err);
			return -KOCKET_IO_ERROR;
		}
	}

	int ret = 0;
	KocketPacketEntry packet_entry = { .kocket_packet = kocket_packet, .kocket_client_id = kocket_client_id };
	if (kocket_packet.type_id < kocket.kocket_types_cnt && (kocket.kocket_types)[kocket_packet.type_id].has_handler) {
		DEBUG_LOG("Handling kocket with type id: %u", kocket_packet.type_id);
		
		KocketTask* handler_task = kocket_calloc(1, sizeof(KocketTask));
		if (handler_task == NULL) {
			WARNING_LOG("An error occurred while allocating the task handler.");
			return -KOCKET_IO_ERROR;
		}

		handler_task -> kocket_packet_entry = packet_entry;
		handler_task -> kocket_handler = *((kocket.kocket_types)[kocket_packet.type_id].kocket_handler);
		init_completion(&handler_task -> done);

	    struct task_struct* task_handler = kthread_run(dispatch_handler_as_task, handler_task, (kocket.kocket_types)[kocket_packet.type_id].type_name);
		if (IS_ERR(task_handler)) {
			KOCKET_SAFE_FREE(handler_task);
			WARNING_LOG("Failed to create and run the kthread.");
			return -KOCKET_IO_ERROR;
		}

		wait_for_completion(&handler_task -> done);
		
		ret = handler_task -> result;
		KOCKET_SAFE_FREE(handler_task);

		if (ret < 0) {
			WARNING_LOG("An error occurred while executing the handler for the type: '%s'", (kocket.kocket_types)[kocket_packet.type_id].type_name);
			return ret;
		}

		return KOCKET_NO_ERROR;
	} 
	
	if ((ret = kocket_enqueue(&kocket_reads_queue, &packet_entry)) < 0) {
		WARNING_LOG("Failed to enqueue the given packet_entry.");
		return ret;
	}
	
	DEBUG_LOG("Kocket with type id: %u appended to the queue.", kocket_packet.type_id);

	if ((ret = wake_waiting_entry(&kocket_wait_queue, kocket_packet.req_id))) {
		WARNING_LOG("Failed to wake entry waiting for req_id: %llu.", kocket_packet.req_id);
		return ret;
	}
	
	return KOCKET_NO_ERROR;
}

static int kocket_release_client(ServerKocket* kocket, u32 index) {
	if (kocket -> clients_cnt <= index) {
		WARNING_LOG("Index out of bound: %u > %u", index, kocket -> clients_cnt);
		return -KOCKET_INVALID_PARAMETERS;
	}
	
	DEBUG_LOG("Releasing socket %u", index);
	sock_release((kocket -> clients)[index]);
	
	mem_move(kocket -> poll_sockets + index, kocket -> poll_sockets + index + 1, sizeof(PollSocket) * (kocket -> clients_cnt - index - 1));
	mem_move(kocket -> clients + index, kocket -> clients + index + 1, sizeof(struct socket*) * (kocket -> clients_cnt - index - 1)); 
	
	kocket -> clients = (struct socket**) kocket_realloc(kocket -> clients, (--(kocket -> clients_cnt)) * sizeof(struct socket*));
	if (kocket -> clients == NULL && kocket -> clients_cnt > 0) {
		WARNING_LOG("Failed to reallocate the buffer for clients array.");
		return -KOCKET_IO_ERROR;
	} 
	
	kocket -> poll_sockets = (PollSocket*) kocket_realloc(kocket -> poll_sockets, (kocket -> clients_cnt + 1) * sizeof(PollSocket));
	if (kocket -> poll_sockets == NULL) {
		WARNING_LOG("Failed to reallocate the buffer for polls array.");
		return -KOCKET_IO_ERROR;
	}

	return KOCKET_NO_ERROR;
}

static int can_read_full_packet(ServerKocket kocket, u32 kocket_client_id) {
	if (kocket_client_id >= kocket.clients_cnt) {
		WARNING_LOG("ServerKocket client is out of bound: %u >= %u.", kocket_client_id, kocket.clients_cnt);
		return -INVALID_KOCKET_CLIENT_ID;
	}

	int err = 0;
	struct msghdr msg_hdr = {0};
	KocketPacket kocket_packet = {0};
	u32 kocket_packet_hdr_size = sizeof(KocketPacket) - sizeof(u8*);
	struct kvec vec = { .iov_len = kocket_packet_hdr_size, .iov_base = &kocket_packet };

	// Peek the packet header for retrieving payload info
	if ((err = kernel_recvmsg((kocket.clients)[kocket_client_id], &msg_hdr, &vec, kocket_packet_hdr_size, kocket_packet_hdr_size, MSG_PEEK)) < kocket_packet_hdr_size) {
		if (err < 0) {
			WARNING_LOG("An error occurred while reading from the server");
			return -KOCKET_IO_ERROR;
		} else if (err == 0) {                                                                  
			WARNING_LOG("The connection has been closed");                                      
			return -KOCKET_CLOSED_CONNECTION;                                                   
		}																		 
		
		return KOCKET_NO_ERROR;
	}

	// If payload is present peek the payload
	// NOTE: the previous peek does not consume data, therefore the header will still be there before the payload
	if (kocket_packet.payload_size > 0) {
		kocket_packet.payload = (u8*) kocket_calloc(kocket_packet.payload_size + kocket_packet_hdr_size, sizeof(u8));
		if (kocket_packet.payload == NULL) {
			WARNING_LOG("An error occurred while allocating the buffer for the payload.");
			return -KOCKET_IO_ERROR;
		}
		
		struct msghdr payload_msg_hdr = {0};
		struct kvec payload_vec = { .iov_len = kocket_packet.payload_size + kocket_packet_hdr_size, .iov_base = kocket_packet.payload };
		if ((err = kernel_recvmsg((kocket.clients)[kocket_client_id], &payload_msg_hdr, &payload_vec, kocket_packet.payload_size + kocket_packet_hdr_size, kocket_packet.payload_size + kocket_packet_hdr_size, MSG_PEEK)) < kocket_packet.payload_size + kocket_packet_hdr_size) {
			KOCKET_SAFE_FREE(kocket_packet.payload);
			
			if (err < 0) {
				WARNING_LOG("An error occurred while reading from the server");
				return -KOCKET_IO_ERROR;
			} else if (err == 0) {                                                                  
				WARNING_LOG("The connection has been closed");                                      
				return -KOCKET_CLOSED_CONNECTION;                                                   
			}																		 
			
			return KOCKET_NO_ERROR;
		}
	}

	KOCKET_SAFE_FREE(kocket_packet.payload);

	return KOCKET_PACKET_AVAILABLE;
}

static int kocket_poll(PollSocket* poll_sockets, u32 sks_cnt, u32 timeout) {
    if (poll_sockets == NULL) {
		WARNING_LOG("poll_sockets must be non-NULL: %p.", poll_sockets);
		return -KOCKET_INVALID_PARAMETERS;
	}
	
	int mask = 0;
	for (u32 i = 0; i < sks_cnt; ++i) {
		struct sock* sk = poll_sockets[i].socket -> sk;
		lock_sock(sk);
		
		if (sk -> sk_state == TCP_LISTEN) {
			poll_sockets[i].reg_events = inet_csk_listen_poll(sk);
			release_sock(sk);
			mask |= poll_sockets[i].reg_events;
			continue;
		}

		int ret = 0;
		if ((ret = wait_event_interruptible_timeout(sk -> sk_wq -> wait, 
			!skb_queue_empty(&(sk -> sk_receive_queue)) || sock_writeable(sk) || sk -> sk_err || !skb_queue_empty(&(sk -> sk_error_queue)) || (sk -> sk_shutdown & RCV_SHUTDOWN), 
			jiffies + timeout)) == 0) {
			release_sock(sk);
			continue;
		}

		// Check for error or connection closed
		if (sk -> sk_err || !skb_queue_empty(&(sk -> sk_error_queue))) {
			release_sock(sk);
			WARNING_LOG("POLLERR: %u", sk -> sk_err);
			poll_sockets[i].reg_events = POLLERR;
			mask |= poll_sockets[i].reg_events;
			continue;
		} else if (sk -> sk_shutdown & RCV_SHUTDOWN) {
			release_sock(sk);
			DEBUG_LOG("Connection closed by client %u", i);
			poll_sockets[i].reg_events = POLLHUP;
			mask |= poll_sockets[i].reg_events;
			continue;
		}
		
		if (!skb_queue_empty(&(sk -> sk_receive_queue))) poll_sockets[i].reg_events |= POLLIN | POLLRDNORM;
		if (sock_writeable(sk)) poll_sockets[i].reg_events |= POLLOUT | POLLWRNORM;
		
		release_sock(sk);

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
		
		DEBUG_LOG("New client connected number: %u", kocket -> clients_cnt);

		// TODO: Check if it needs to first establish a secure channel
		kocket -> clients = (struct socket**) kocket_realloc(kocket -> clients, (++(kocket -> clients_cnt)) * sizeof(struct socket*));
		if (kocket -> clients == NULL) {
			WARNING_LOG("Failed to reallocate the buffer for clients array.");
			return -KOCKET_IO_ERROR;
		} 
		
		(kocket -> clients)[kocket -> clients_cnt - 1] = new_client;

		kocket -> poll_sockets = (PollSocket*) kocket_realloc(kocket -> poll_sockets, (kocket -> clients_cnt + 1) * sizeof(PollSocket));
		if (kocket -> poll_sockets == NULL) {
			WARNING_LOG("Failed to reallocate the buffer for polls array.");
			return -KOCKET_IO_ERROR;
		} 

		(kocket -> poll_sockets)[kocket -> clients_cnt].socket = new_client;

	} else if ((kocket -> poll_sockets)[0].reg_events & POLLERR) {
		WARNING_LOG("An error occurred in the server socket.");
		return -KOCKET_IO_ERROR;
	}
	
	int err = 0;
	for (unsigned int i = 1; i < kocket -> clients_cnt + 1; ++i) {
		if (((kocket -> poll_sockets)[i].reg_events & POLLERR) || ((kocket -> poll_sockets)[i].reg_events & POLLHUP)) {
			if ((err = kocket_release_client(kocket, i - 1)) < 0) { 
				WARNING_LOG("Failed to release the client %u.", i);
				return err;
			}
		}
		
		if (((kocket -> poll_sockets)[i].reg_events & POLLIN) && (err = can_read_full_packet(*kocket, i - 1)) == KOCKET_PACKET_AVAILABLE) {
		   	if ((err = kocket_recv(*kocket, i - 1)) < 0) {
				WARNING_LOG("Failed to receive data: '%s'", kocket_status_str[err > 0 ? err : -err]);
				if ((err = kocket_release_client(kocket, i - 1)) < 0) { 
					WARNING_LOG("Failed to release the client %u.", i);
					return err;
				}
			}
		} else if (err < 0) {
			WARNING_LOG("Failed to check if the entire packet is available for read: '%s'", kocket_status_str[err > 0 ? err : -err]);
			if ((err = kocket_release_client(kocket, i - 1)) < 0) { 
				WARNING_LOG("Failed to release the client %u.", i);
				return err;
			}
		}
	}

	return KOCKET_NO_ERROR;
}

static int kocket_poll_write(ServerKocket* kocket) {
	int err = 0;
	if ((err = is_kocket_queue_empty(&kocket_writing_queue)) < 0) {
		WARNING_LOG("An error occurred while checking if the kocket_writing_queue was empty.");
		return err;
	}

	int kocket_queue_size = err;
	for (u32 i = 0; i < kocket_queue_size; ++i) {
		u32 kocket_client_id = 0;
		if ((err = kocket_queue_get_n_client_id(&kocket_writing_queue, i, &kocket_client_id)) < 0) {
			WARNING_LOG("Failed to get the %u entry's client_id from the kocket_writing_queue.", i + 1);
			return err;
		}

		if (!((kocket -> poll_sockets)[kocket_client_id + 1].reg_events & POLLOUT)) continue;
		
		DEBUG_LOG("Writing to client: %u", kocket_client_id);

		KocketPacketEntry packet_entry = {0};
		if ((err = kocket_dequeue(&kocket_writing_queue, &packet_entry)) < 0) {
			WARNING_LOG("Failed to dequeue from the kocket_writing_queue.");
			return err;
		}
		
		if ((err = kocket_send(*kocket, packet_entry)) < 0) {
			WARNING_LOG("Failed to send the queued kocket_packet.");
			return err;
		}

		KOCKET_SAFE_FREE(packet_entry.kocket_packet.payload);

		kocket_queue_size--;
		(kocket -> poll_sockets)[kocket_client_id + 1].reg_events = 0;
	}

	return KOCKET_NO_ERROR;
}

// This will be the function executed by the kocket-thread.
int kocket_dispatcher(void* kocket_arg) {
	ServerKocket kocket = *KOCKET_CAST_PTR(kocket_arg, ServerKocket);
	KOCKET_SAFE_FREE(kocket_arg);
	
	allow_signal(SIGKILL | SIGTERM);

	int ret = 0;
	int err = KOCKET_NO_ERROR;
	while (!kthread_should_stop()) {
		if ((ret = kocket_poll(kocket.poll_sockets, kocket.clients_cnt + 1, KOCKET_TIMEOUT_SEC)) == 0) continue;
		else if (ret < 0) {
			WARNING_LOG("An error occurred while polling.");
			err = ret;
			break;
		}

		if ((ret = kocket_poll_read_accept(&kocket)) < 0) {
			WARNING_LOG("An error occurred while polling read/accept.");
			err = ret;
			break;
		}

		if ((ret = kocket_poll_write(&kocket)) < 0) {
			WARNING_LOG("An error occurred while polling write.");
			err = ret;
			break;
		}
		
		if (signal_pending(kthread)) break;
	}
	
	DEBUG_LOG("Deinit kthread, err: %d.", err);

	kocket_deinit_thread(&kocket, err);

	return err;
}

void wait_queue_free_elements(KocketQueue* kocket_queue) {
	KocketWaitEntry* kocket_wait_entries = KOCKET_CAST_PTR(kocket_queue -> elements, KocketWaitEntry);
	for (u32 i = 0; i < kocket_queue -> size; ++i) mutex_destroy(&(kocket_wait_entries[i].lock));
	KOCKET_SAFE_FREE(kocket_queue -> elements);
	return;
}

void packet_queue_free_elements(KocketQueue* kocket_queue) {
	KocketPacketEntry* kocket_packet_entries = KOCKET_CAST_PTR(kocket_queue -> elements, KocketPacketEntry);
	for (u32 i = 0; i < kocket_queue -> size; ++i) KOCKET_SAFE_FREE(kocket_packet_entries[i].kocket_packet.payload);
	KOCKET_SAFE_FREE(kocket_queue -> elements);
	return;
}

#endif //_K_KOCKET_H_

