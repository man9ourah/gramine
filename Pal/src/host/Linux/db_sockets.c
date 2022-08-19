/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <asm/ioctls.h>
#include <asm/poll.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/time.h>
#include <sys/mman.h>

#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "socket_utils.h"
#include "toml_utils.h"

static struct handle_ops g_tcp_handle_ops;
static struct handle_ops g_udp_handle_ops;
static struct handle_ops g_xdp_handle_ops;
static struct socket_ops g_tcp_sock_ops;
static struct socket_ops g_udp_sock_ops;
static struct socket_ops g_xdp_sock_ops;

static size_t g_default_recv_buf_size = 0;
static size_t g_default_send_buf_size = 0;

static PAL_HANDLE create_sock_handle(int fd, enum pal_socket_domain domain,
                                     enum pal_socket_type type, struct handle_ops* handle_ops,
                                     struct socket_ops* ops, bool is_nonblocking) {
    PAL_HANDLE handle = calloc(1, sizeof(*handle));
    if (!handle) {
        return NULL;
    }

    handle->hdr.type = PAL_TYPE_SOCKET;
    handle->hdr.ops = handle_ops;
    handle->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    handle->sock.fd = fd;
    handle->sock.domain = domain;
    handle->sock.type = type;
    handle->sock.ops = ops;

    // all of the next options does not apply to AF_XDP
    if (handle->sock.domain == PAL_XDP) {
        return handle;
    }

    handle->sock.recv_buf_size = __atomic_load_n(&g_default_recv_buf_size, __ATOMIC_RELAXED);
    if (!handle->sock.recv_buf_size) {
        int val = 0;
        int len = sizeof(val);
        int ret = DO_SYSCALL(getsockopt, fd, SOL_SOCKET, SO_RCVBUF, &val, &len);
        if (ret < 0) {
            log_error("%s: getsockopt SO_RCVBUF failed: %d", __func__, ret);
            free(handle);
            return NULL;
        }
        handle->sock.recv_buf_size = val;
        __atomic_store_n(&g_default_recv_buf_size, val, __ATOMIC_RELAXED);
    }

    handle->sock.send_buf_size = __atomic_load_n(&g_default_send_buf_size, __ATOMIC_RELAXED);
    if (!handle->sock.send_buf_size) {
        int val = 0;
        int len = sizeof(val);
        int ret = DO_SYSCALL(getsockopt, fd, SOL_SOCKET, SO_SNDBUF, &val, &len);
        if (ret < 0) {
            log_error("%s: getsockopt SO_SNDBUF failed: %d", __func__, ret);
            free(handle);
            return NULL;
        }
        handle->sock.send_buf_size = val;
        __atomic_store_n(&g_default_send_buf_size, val, __ATOMIC_RELAXED);
    }

    handle->sock.linger = 0;
    handle->sock.recvtimeout_us = 0;
    handle->sock.sendtimeout_us = 0;
    handle->sock.is_nonblocking = is_nonblocking;
    handle->sock.reuseaddr = false;
    handle->sock.keepalive = false;
    handle->sock.tcp_cork = false;
    handle->sock.tcp_nodelay = false;
    handle->sock.ipv6_v6only = false;

    return handle;
}

int _DkSocketCreate(enum pal_socket_domain domain, enum pal_socket_type type,
                    pal_stream_options_t options, PAL_HANDLE* out_handle) {
    int linux_domain;
    int linux_type;
    switch (domain) {
        case PAL_IPV4:
            linux_domain = AF_INET;
            break;
        case PAL_IPV6:
            linux_domain = AF_INET6;
            break;
        case PAL_XDP:
            linux_domain = AF_XDP;
            break;
        default:
            BUG();
    }
    struct handle_ops* handle_ops = NULL;
    struct socket_ops* sock_ops = NULL;
    switch (type) {
        case PAL_SOCKET_TCP:
            linux_type = SOCK_STREAM;
            handle_ops = &g_tcp_handle_ops;
            sock_ops = &g_tcp_sock_ops;
            break;
        case PAL_SOCKET_UDP:
            linux_type = SOCK_DGRAM;
            handle_ops = &g_udp_handle_ops;
            sock_ops = &g_udp_sock_ops;
            break;
        case PAL_SOCKET_RAW:
            linux_type = SOCK_RAW;
            if (domain == PAL_XDP) {
                handle_ops = &g_xdp_handle_ops;
                sock_ops = &g_xdp_sock_ops;
                break;
            }
            // other than using xdp, SOCK_RAW is not supported yet!
            // fall through
        default:
            BUG();
    }

    if (options & PAL_OPTION_NONBLOCK) {
        linux_type |= SOCK_NONBLOCK;
    }
    linux_type |= SOCK_CLOEXEC;

    int fd = DO_SYSCALL(socket, linux_domain, linux_type, 0);
    if (fd < 0) {
        return unix_to_pal_error(fd);
    }

    PAL_HANDLE handle = create_sock_handle(fd, domain, type, handle_ops, sock_ops,
                                           !!(options & PAL_OPTION_NONBLOCK));
    if (!handle) {
        int ret = DO_SYSCALL(close, fd);
        if (ret < 0) {
            log_error("%s:%d closing socket fd failed: %d", __func__, __LINE__, ret);
        }
        return -PAL_ERROR_NOMEM;
    }

    *out_handle = handle;
    return 0;
}

static int close(PAL_HANDLE handle) {
    int ret = DO_SYSCALL(close, handle->sock.fd);
    if (ret < 0) {
        log_error("%s: closing socket fd failed: %d", __func__, ret);
        /* We cannot do anything about it anyway... */
    }
    return 0;
}

static int do_getsockname(int fd, struct sockaddr_storage* sa_storage) {
    int linux_addrlen_int = sizeof(*sa_storage);
    int ret = DO_SYSCALL(getsockname, fd, sa_storage, &linux_addrlen_int);
    return unix_to_pal_error(ret);
}

// following two functions adopted from linux kernel
static int recv_xsks_map_fd_from_ctrl_node(int ctrl_sock_fd){
	char cms[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	int value;
	int len;

	iov.iov_base = &value;
	iov.iov_len = sizeof(int);

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = (void*)cms;
	msg.msg_controllen = sizeof(cms);

	len = DO_SYSCALL(recvmsg, ctrl_sock_fd, &msg, 0);

	if (len <= 0) {
        return -PAL_ERROR_CONNFAILED_PIPE;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	int fd = *(int *)CMSG_DATA(cmsg);

	return fd;
}

static int recv_xsks_map_fd(char* ctrl_server_path){
	struct sockaddr_un server;
	int ctrl_sock_fd;

	ctrl_sock_fd = DO_SYSCALL(socket, AF_UNIX, SOCK_STREAM, 0);
	if (ctrl_sock_fd < 0) {
		return -PAL_ERROR_NOTCONNECTION;
	}

    memset(&server, 0, sizeof(server));
    server.sun_family = AF_UNIX;

    int unix_server_path_len = strnlen(ctrl_server_path, sizeof(server.sun_path));
    if(unix_server_path_len == sizeof(server.sun_path)){
        return -PAL_ERROR_ADDRNOTEXIST;
    }
    memcpy(server.sun_path, ctrl_server_path, unix_server_path_len);

	if (DO_SYSCALL(connect, ctrl_sock_fd, (struct sockaddr *)&server, sizeof(struct sockaddr_un))) {
        DO_SYSCALL(close, ctrl_sock_fd);
        return -PAL_ERROR_NOTCONNECTION;
	}

	return recv_xsks_map_fd_from_ctrl_node(ctrl_sock_fd);
}

static int xdp_update_bpf_xsk_map(PAL_HANDLE handle, uint32_t queue_id){
    // first we need to get the xsk map from the control process.
    // the user should have provide a unix socket addrees the control process
    // is listening to; lets parse it
    toml_table_t* manifest_root = g_pal_public_state.manifest_root;
    assert(manifest_root);
    toml_table_t* toml_sys_table = toml_table_in(manifest_root, "sys");
    if (!toml_sys_table) {
        return -PAL_ERROR_ADDRNOTEXIST;
    }
    toml_table_t* toml_net_table = toml_table_in(toml_sys_table, "net");
    if (!toml_net_table) {
        return -PAL_ERROR_ADDRNOTEXIST;
    }
    char* xdp_ctrl_server_path = NULL;
    if (toml_string_in(toml_net_table, "xdp_ctrl_addr", &xdp_ctrl_server_path) < 0){
        return -PAL_ERROR_ADDRNOTEXIST;
    }

    // now we attempt to connect to the ctrl process and get the bpf xsks map
    int xsks_map_fd = recv_xsks_map_fd(xdp_ctrl_server_path);
    if (xsks_map_fd < 0) {
        return xsks_map_fd;
    }

    // we got the xsks map fd! now we insert our socket fd into the map
    int sock_fd = handle->sock.fd;
    union bpf_attr bpfattr;
    memset(&bpfattr, 0, sizeof(bpfattr));
    bpfattr.map_fd = xsks_map_fd;
    bpfattr.key = (__u64)(unsigned long)(&queue_id);
    bpfattr.value = (__u64)(unsigned long)(&sock_fd);
    bpfattr.flags = 0;

    int ret = DO_SYSCALL(bpf, BPF_MAP_UPDATE_ELEM, &bpfattr, sizeof(bpfattr));
    if (ret < 0) {
        return -PAL_ERROR_DENIED;
    }

    return 0;
}

static int bind(PAL_HANDLE handle, struct pal_socket_addr* addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    if (addr->domain != handle->sock.domain) {
        return -PAL_ERROR_INVAL;
    }

    union {
        struct sockaddr_storage sa_storage;
        struct sockaddr_in addr_ipv4;
        struct sockaddr_in6 addr_ipv6;
        struct sockaddr_xdp addr_xdp;
    } linux_addr;
    size_t linux_addrlen;
    pal_to_linux_sockaddr(addr, &linux_addr.sa_storage, &linux_addrlen);
    assert(linux_addrlen <= INT_MAX);

    int ret = DO_SYSCALL(bind, handle->sock.fd, &linux_addr.sa_storage, (int)linux_addrlen);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    switch (addr->domain) {
        case PAL_IPV4:
            if (!addr->ipv4.port) {
                ret = do_getsockname(handle->sock.fd, &linux_addr.sa_storage);
                if (ret < 0) {
                    /* This should never happen, but we have to handle it somehow. Socket was bound,
                     * but something is wrong... */
                    return ret;
                }
                assert(linux_addr.addr_ipv4.sin_family == AF_INET);
                addr->ipv4.port = linux_addr.addr_ipv4.sin_port;
            }
            break;
        case PAL_IPV6:
            if (!addr->ipv6.port) {
                ret = do_getsockname(handle->sock.fd, &linux_addr.sa_storage);
                if (ret < 0) {
                    /* This should never happen, but we have to handle it somehow. Socket was bound,
                     * but something is wrong... */
                    return ret;
                }
                assert(linux_addr.addr_ipv6.sin6_family == AF_INET6);
                addr->ipv6.port = linux_addr.addr_ipv6.sin6_port;
            }
            break;
        case PAL_XDP:
            ret = xdp_update_bpf_xsk_map(handle, addr->xdp.queue_id);
            if (ret < 0) {
                return ret;
            }
            break;
        default:
            BUG();
    }
    return 0;
}

static int tcp_listen(PAL_HANDLE handle, unsigned int backlog) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    int ret = DO_SYSCALL(listen, handle->sock.fd, backlog);
    return unix_to_pal_error(ret);
}

static int tcp_accept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* out_client,
                      struct pal_socket_addr* out_client_addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);

    struct sockaddr_storage sa_storage = { 0 };
    int linux_addrlen = sizeof(sa_storage);
    int flags = options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0;
    flags |= SOCK_CLOEXEC;

    int fd = DO_SYSCALL(accept4, handle->sock.fd, &sa_storage, &linux_addrlen, flags);
    if (fd < 0) {
        return unix_to_pal_error(fd);
    }

    PAL_HANDLE client = create_sock_handle(fd, handle->sock.domain, handle->sock.type,
                                           handle->hdr.ops, handle->sock.ops,
                                           !!(options & PAL_OPTION_NONBLOCK));
    if (!client) {
        int ret = DO_SYSCALL(close, fd);
        if (ret < 0) {
            log_error("%s:%d closing socket fd failed: %d", __func__, __LINE__, ret);
        }
        return -PAL_ERROR_NOMEM;
    }

    *out_client = client;
    if (out_client_addr) {
        linux_to_pal_sockaddr(&sa_storage, out_client_addr);
        assert(out_client_addr->domain == client->sock.domain);
    }
    return 0;
}

static int connect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                   struct pal_socket_addr* out_local_addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    if (addr->domain != PAL_DISCONNECT && addr->domain != handle->sock.domain) {
        return -PAL_ERROR_INVAL;
    }

    struct sockaddr_storage sa_storage;
    size_t linux_addrlen;
    pal_to_linux_sockaddr(addr, &sa_storage, &linux_addrlen);
    assert(linux_addrlen <= INT_MAX);

    int ret = DO_SYSCALL(connect, handle->sock.fd, &sa_storage, (int)linux_addrlen);
    if (ret < 0) {
        /* XXX: Non blocking socket. Currently there is no way of notifying LibOS of successful or
         * failed connection, so we have to block and wait. */
        if (ret != -EINPROGRESS) {
            return unix_to_pal_error(ret);
        }
        struct pollfd pfd = {
            .fd = handle->sock.fd,
            .events = POLLOUT,
        };
        ret = DO_SYSCALL(poll, &pfd, 1, /*timeout=*/-1);
        if (ret != 1 || pfd.revents == 0) {
            return ret < 0 ? unix_to_pal_error(ret) : -PAL_ERROR_INVAL;
        }
        int val = 0;
        unsigned int len = sizeof(val);
        ret = DO_SYSCALL(getsockopt, handle->sock.fd, SOL_SOCKET, SO_ERROR, &val, &len);
        if (ret < 0 || val < 0) {
            return ret < 0 ? unix_to_pal_error(ret) : -PAL_ERROR_INVAL;
        }
        if (val) {
            return unix_to_pal_error(-val);
        }
        /* Connect succeeded. */
    }

    if (out_local_addr) {
        ret = do_getsockname(handle->sock.fd, &sa_storage);
        if (ret < 0) {
            /* This should never happen, but we have to handle it somehow. */
            return ret;
        }
        linux_to_pal_sockaddr(&sa_storage, out_local_addr);
    }
    return 0;
}

/**
 * this function calls the mmap syscall.. on success, it will write the mapped address
 * to the passed addr params and return 0, otherwise return -1 for error.
 */
static int do_xdp_rings_mmap(void** addr, size_t size, int flags, int fd, off_t offset){
    void* mapped_address = (void*)DO_SYSCALL(mmap, *addr, size, PROT_READ | PROT_WRITE, flags, fd, offset);
    if (mapped_address != MAP_FAILED) {
        *addr = mapped_address;
        return 0;
    }
    return -1;
}

static int attrquerybyhdl_xdp(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);

    switch (attr->xdp_socket.sockopt) {
        case PAL_XDP_GETSOCKOPT_MMAP_OFFSETS:;
            struct xdp_mmap_offsets xdp_off;
            int len = sizeof(xdp_off);
            int ret = DO_SYSCALL(getsockopt, handle->sock.fd, SOL_XDP, XDP_MMAP_OFFSETS, &xdp_off, &len);
            if (ret < 0) {
                return unix_to_pal_error(ret);
            }
            attr->xdp_socket.fill_producer     = xdp_off.fr.producer;
            attr->xdp_socket.fill_consumer     = xdp_off.fr.consumer;
            attr->xdp_socket.fill_desc         = xdp_off.fr.desc;
            attr->xdp_socket.fill_flags        = xdp_off.fr.flags;
            attr->xdp_socket.complete_producer = xdp_off.cr.producer;
            attr->xdp_socket.complete_consumer = xdp_off.cr.consumer;
            attr->xdp_socket.complete_desc     = xdp_off.cr.desc;
            attr->xdp_socket.complete_flags    = xdp_off.cr.flags;
            attr->xdp_socket.tx_producer       = xdp_off.tx.producer;
            attr->xdp_socket.tx_consumer       = xdp_off.tx.consumer;
            attr->xdp_socket.tx_desc           = xdp_off.tx.desc;
            attr->xdp_socket.tx_flags          = xdp_off.tx.flags;
            attr->xdp_socket.rx_producer       = xdp_off.rx.producer;
            attr->xdp_socket.rx_consumer       = xdp_off.rx.consumer;
            attr->xdp_socket.rx_desc           = xdp_off.rx.desc;
            attr->xdp_socket.rx_flags          = xdp_off.rx.flags;
            return ret;
            break;

        case PAL_XDP_MMAP_FILL_RING:
            return do_xdp_rings_mmap(&attr->xdp_socket.untrusted_ring_mapping,
                    attr->xdp_socket.ring_size, attr->xdp_socket.rings_mmap_flags,
                    handle->sock.fd, XDP_UMEM_PGOFF_FILL_RING);
            break;
        case PAL_XDP_MMAP_COMP_RING:
            return do_xdp_rings_mmap(&attr->xdp_socket.untrusted_ring_mapping,
                    attr->xdp_socket.ring_size, attr->xdp_socket.rings_mmap_flags,
                    handle->sock.fd, XDP_UMEM_PGOFF_COMPLETION_RING);
            break;
        case PAL_XDP_MMAP_TX_RING:
            return do_xdp_rings_mmap(&attr->xdp_socket.untrusted_ring_mapping,
                    attr->xdp_socket.ring_size, attr->xdp_socket.rings_mmap_flags,
                    handle->sock.fd, XDP_PGOFF_TX_RING);
            break;
        case PAL_XDP_MMAP_RX_RING:
            return do_xdp_rings_mmap(&attr->xdp_socket.untrusted_ring_mapping,
                    attr->xdp_socket.ring_size, attr->xdp_socket.rings_mmap_flags,
                    handle->sock.fd, XDP_PGOFF_RX_RING);
            break;

        // TODO: we dont need those for now (for xdp init I mean)
        case PAL_XDP_GETSOCKOPT_OPTIONS:
        case PAL_XDP_GETSOCKOPT_STATS:
            return -PAL_ERROR_NOTIMPLEMENTED;
            break;
        default:
            return -PAL_ERROR_INVAL;
            break;
    }

    return -PAL_ERROR_INVAL;
};

static int attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);

    memset(attr, 0, sizeof(*attr));

    attr->handle_type = PAL_TYPE_SOCKET;
    attr->nonblocking = handle->sock.is_nonblocking;

    int val = 0;
    int ret = DO_SYSCALL(ioctl, handle->sock.fd, FIONREAD, &val);
    attr->pending_size = ret >= 0 && val >= 0 ? val : 0;

    attr->socket.linger = handle->sock.linger;
    attr->socket.recv_buf_size = handle->sock.recv_buf_size;
    attr->socket.send_buf_size = handle->sock.send_buf_size;
    attr->socket.receivetimeout_us = handle->sock.recvtimeout_us;
    attr->socket.sendtimeout_us = handle->sock.sendtimeout_us;
    attr->socket.reuseaddr = handle->sock.reuseaddr;
    attr->socket.keepalive = handle->sock.keepalive;
    attr->socket.tcp_cork = handle->sock.tcp_cork;
    attr->socket.tcp_nodelay = handle->sock.tcp_nodelay;
    attr->socket.ipv6_v6only = handle->sock.ipv6_v6only;

    return 0;
};

/* Warning: if this is used to change two fields and the second set fails, the first set is not
 * undone. */
static int attrsetbyhdl_common(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    if (attr->handle_type != PAL_TYPE_SOCKET) {
        return -PAL_ERROR_INVAL;
    }

    if (attr->nonblocking != handle->sock.is_nonblocking) {
        int ret = DO_SYSCALL(fcntl, handle->sock.fd, F_GETFL);
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        int flags = ret;
        if (attr->nonblocking) {
            flags |= O_NONBLOCK;
        } else {
            flags &= ~O_NONBLOCK;
        }
        ret = DO_SYSCALL(fcntl, handle->sock.fd, F_SETFL, flags);
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.is_nonblocking = attr->nonblocking;
    }

    if (attr->socket.linger != handle->sock.linger) {
        if (attr->socket.linger > INT_MAX) {
            return -PAL_ERROR_INVAL;
        }
        struct linger linger = {
            .l_onoff = attr->socket.linger ? 1 : 0,
            .l_linger = attr->socket.linger,
        };
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_LINGER, &linger,
                             sizeof(linger));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.linger = attr->socket.linger;
    }

    if (attr->socket.recv_buf_size != handle->sock.recv_buf_size) {
        if (attr->socket.recv_buf_size > INT_MAX || attr->socket.recv_buf_size % 2) {
            return -PAL_ERROR_INVAL;
        }
        /* The Linux kernel will double this value. */
        int val = attr->socket.recv_buf_size / 2;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.recv_buf_size = attr->socket.recv_buf_size;
    }

    if (attr->socket.send_buf_size != handle->sock.send_buf_size) {
        if (attr->socket.send_buf_size > INT_MAX || attr->socket.send_buf_size % 2) {
            return -PAL_ERROR_INVAL;
        }
        /* The Linux kernel will double this value. */
        int val = attr->socket.send_buf_size / 2;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.send_buf_size = attr->socket.send_buf_size;
    }

    if (attr->socket.receivetimeout_us != handle->sock.recvtimeout_us) {
        struct timeval tv = {
            .tv_sec = attr->socket.receivetimeout_us / TIME_US_IN_S,
            .tv_usec = attr->socket.receivetimeout_us % TIME_US_IN_S,
        };
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.recvtimeout_us = attr->socket.receivetimeout_us;
    }

    if (attr->socket.sendtimeout_us != handle->sock.sendtimeout_us) {
        struct timeval tv = {
            .tv_sec = attr->socket.sendtimeout_us / TIME_US_IN_S,
            .tv_usec = attr->socket.sendtimeout_us % TIME_US_IN_S,
        };
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.sendtimeout_us = attr->socket.sendtimeout_us;
    }

    if (attr->socket.keepalive != handle->sock.keepalive) {
        int val = attr->socket.keepalive;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_KEEPALIVE, &val,
                             sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.keepalive = attr->socket.keepalive;
    }

    if (attr->socket.reuseaddr != handle->sock.reuseaddr) {
        int val = attr->socket.reuseaddr;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_SOCKET, SO_REUSEADDR, &val,
                             sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.reuseaddr = attr->socket.reuseaddr;
    }

    if (attr->socket.ipv6_v6only != handle->sock.ipv6_v6only) {
        int val = attr->socket.ipv6_v6only;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                             sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.ipv6_v6only = attr->socket.ipv6_v6only;
    }

    return 0;
}

static int attrsetbyhdl_tcp(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(handle->sock.type == PAL_SOCKET_TCP);

    int ret = attrsetbyhdl_common(handle, attr);
    if (ret < 0) {
        return ret;
    }

    if (attr->socket.tcp_cork != handle->sock.tcp_cork) {
        int val = attr->socket.tcp_cork;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_TCP, TCP_CORK, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.tcp_cork = attr->socket.tcp_cork;
    }

    if (attr->socket.tcp_nodelay != handle->sock.tcp_nodelay) {
        int val = attr->socket.tcp_nodelay;
        int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_TCP, TCP_NODELAY, &val, sizeof(val));
        if (ret < 0) {
            return unix_to_pal_error(ret);
        }
        handle->sock.tcp_nodelay = attr->socket.tcp_nodelay;
    }

    return 0;
}

static int attrsetbyhdl_udp(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(handle->sock.type == PAL_SOCKET_UDP);

    return attrsetbyhdl_common(handle, attr);
}

static int attrsetbyhdl_xdp(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    if (attr->handle_type != PAL_TYPE_SOCKET) {
        return -PAL_ERROR_INVAL;
    }

    struct xdp_umem_reg mr;
    int optname;
    void* optval;
    size_t optlen;

    switch (attr->xdp_socket.sockopt) {
        case PAL_XDP_SETSOCKOPT_UMEM_REG:;
            mr.addr       = attr->xdp_socket.umem_addr;
            mr.len        = attr->xdp_socket.umem_len;
            mr.chunk_size = attr->xdp_socket.umem_chunk_size;
            mr.headroom   = attr->xdp_socket.umem_chunk_headroom;
            mr.flags      = attr->xdp_socket.umem_flags;
            optname = XDP_UMEM_REG;
            optval = &mr;
            optlen = sizeof(mr);
            break;
        case PAL_XDP_SETSOCKOPT_FILL_RING:;
            optname = XDP_UMEM_FILL_RING;
            optval = &attr->xdp_socket.ring_size;
            optlen = sizeof(attr->xdp_socket.ring_size);
            break;
        case PAL_XDP_SETSOCKOPT_COMP_RING:;
            optname = XDP_UMEM_COMPLETION_RING;
            optval = &attr->xdp_socket.ring_size;
            optlen = sizeof(attr->xdp_socket.ring_size);
            break;
        case PAL_XDP_SETSOCKOPT_TX_RING:;
            optname = XDP_TX_RING;
            optval = &attr->xdp_socket.ring_size;
            optlen = sizeof(attr->xdp_socket.ring_size);
            break;
        case PAL_XDP_SETSOCKOPT_RX_RING:;
            optname = XDP_RX_RING;
            optval = &attr->xdp_socket.ring_size;
            optlen = sizeof(attr->xdp_socket.ring_size);
            break;
        default:
            return -PAL_ERROR_INVAL;
            break;
    }

    int ret = DO_SYSCALL(setsockopt, handle->sock.fd, SOL_XDP, optname, optval, optlen);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    return ret;
}

static int xdp_send(PAL_HANDLE handle, struct pal_iovec* pal_iov, size_t iov_len, size_t* out_size,
                struct pal_socket_addr* addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);

    int ret = DO_SYSCALL(sendto, handle->sock.fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }
    return 0;
}

static int send(PAL_HANDLE handle, struct pal_iovec* pal_iov, size_t iov_len, size_t* out_size,
                struct pal_socket_addr* addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);

    struct sockaddr_storage sa_storage;
    size_t linux_addrlen = 0;
    if (addr) {
        if (addr->domain != handle->sock.domain) {
            return -PAL_ERROR_INVAL;
        }
        pal_to_linux_sockaddr(addr, &sa_storage, &linux_addrlen);
        assert(linux_addrlen <= INT_MAX);
    }

    struct iovec* iov = malloc(iov_len * sizeof(*iov));
    if (!iov) {
        return -PAL_ERROR_NOMEM;
    }
    for (size_t i = 0; i < iov_len; i++) {
        iov[i].iov_base = pal_iov[i].iov_base;
        iov[i].iov_len = pal_iov[i].iov_len;
    }

    struct msghdr msg = {
        .msg_name = addr ? &sa_storage : NULL,
        .msg_namelen = linux_addrlen,
        .msg_iov = iov,
        .msg_iovlen = iov_len,
    };
    int ret = DO_SYSCALL(sendmsg, handle->sock.fd, &msg, 0);
    free(iov);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }
    *out_size = ret;
    return 0;
}

static int recv(PAL_HANDLE handle, struct pal_iovec* pal_iov, size_t iov_len,
                size_t* out_total_size, struct pal_socket_addr* addr, bool force_nonblocking) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);

    struct sockaddr_storage sa_storage;
    struct iovec* iov = malloc(iov_len * sizeof(*iov));
    if (!iov) {
        return -PAL_ERROR_NOMEM;
    }
    for (size_t i = 0; i < iov_len; i++) {
        iov[i].iov_base = pal_iov[i].iov_base;
        iov[i].iov_len = pal_iov[i].iov_len;
    }

    unsigned int flags = force_nonblocking ? MSG_DONTWAIT : 0;
    if (handle->sock.type == PAL_SOCKET_UDP) {
        /* Reads from PAL UDP sockets always return the full packed length. See also the definition
         * of `DkSocketRecv`. */
        flags |= MSG_TRUNC;
    }
    struct msghdr msg = {
        .msg_name = addr ? &sa_storage : NULL,
        .msg_namelen = addr ? sizeof(sa_storage) : 0,
        .msg_iov = iov,
        .msg_iovlen = iov_len,
    };
    int ret = DO_SYSCALL(recvmsg, handle->sock.fd, &msg, flags);
    free(iov);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }
    *out_total_size = ret;
    if (addr) {
        linux_to_pal_sockaddr(&sa_storage, addr);
    }
    return 0;
}

static int delete_tcp(PAL_HANDLE handle, enum pal_delete_mode mode) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    int how;
    switch (mode) {
        case PAL_DELETE_ALL:
            how = SHUT_RDWR;
            break;
        case PAL_DELETE_READ:
            how = SHUT_RD;
            break;
        case PAL_DELETE_WRITE:
            how = SHUT_WR;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    int ret = DO_SYSCALL(shutdown, handle->sock.fd, how);
    return unix_to_pal_error(ret);
}

static int delete_udp(PAL_HANDLE handle, enum pal_delete_mode mode) {
    __UNUSED(handle);
    __UNUSED(mode);
    return 0;
}

static struct socket_ops g_tcp_sock_ops = {
    .bind = bind,
    .listen = tcp_listen,
    .accept = tcp_accept,
    .connect = connect,
    .send = send,
    .recv = recv,
};

static struct socket_ops g_udp_sock_ops = {
    .bind = bind,
    .connect = connect,
    .send = send,
    .recv = recv,
};

static struct socket_ops g_xdp_sock_ops = {
    .bind = bind,
    .send = xdp_send,
    .recv = recv,
};

static struct handle_ops g_tcp_handle_ops = {
    .attrquerybyhdl = attrquerybyhdl,
    .attrsetbyhdl = attrsetbyhdl_tcp,
    .delete = delete_tcp,
    .close = close,
};

static struct handle_ops g_udp_handle_ops = {
    .attrquerybyhdl = attrquerybyhdl,
    .attrsetbyhdl = attrsetbyhdl_udp,
    .delete = delete_udp,
    .close = close,
};

static struct handle_ops g_xdp_handle_ops = {
    .attrquerybyhdl = attrquerybyhdl_xdp,
    .attrsetbyhdl = attrsetbyhdl_xdp,
    .close = close,
};

void fixup_socket_handle_after_deserialization(PAL_HANDLE handle) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    switch (handle->sock.type) {
        case PAL_SOCKET_TCP:
            handle->sock.ops = &g_tcp_sock_ops;
            handle->hdr.ops = &g_tcp_handle_ops;
            break;
        case PAL_SOCKET_UDP:
            handle->sock.ops = &g_udp_sock_ops;
            handle->hdr.ops = &g_udp_handle_ops;
            break;
        default:
            BUG();
    }
}

int _DkSocketBind(PAL_HANDLE handle, struct pal_socket_addr* addr) {
    if (!handle->sock.ops->bind) {
        return -PAL_ERROR_NOTSUPPORT;
    }

    return handle->sock.ops->bind(handle, addr);
}

int _DkSocketListen(PAL_HANDLE handle, unsigned int backlog) {
    if (!handle->sock.ops->listen) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->listen(handle, backlog);
}

int _DkSocketAccept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* out_client,
                    struct pal_socket_addr* out_client_addr) {
    if (!handle->sock.ops->accept) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->accept(handle, options, out_client, out_client_addr);
}

int _DkSocketConnect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                     struct pal_socket_addr* out_local_addr) {
    if (!handle->sock.ops->connect) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->connect(handle, addr, out_local_addr);
}

int _DkSocketSend(PAL_HANDLE handle, struct pal_iovec* iov, size_t iov_len, size_t* out_size,
                  struct pal_socket_addr* addr) {
    if (!handle->sock.ops->send) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->send(handle, iov, iov_len, out_size, addr);
}

int _DkSocketRecv(PAL_HANDLE handle, struct pal_iovec* iov, size_t iov_len, size_t* out_total_size,
                  struct pal_socket_addr* addr, bool force_nonblocking) {
    if (!handle->sock.ops->recv) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->recv(handle, iov, iov_len, out_total_size, addr, force_nonblocking);
}
