
/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */

/*
 * Implementation of XDP sockets.
 */

#include "pal.h"
#include "shim_fs.h"
#include "shim_socket.h"
#include "socket_utils.h"

// this is the min chunk size set by kernel code
#define XDP_UMEM_MIN_CHUNK_SIZE 2048

void* do_xdp_mmap(struct shim_handle* handle, void* addr, size_t size, int prot, int flags,
            uint64_t offset){
    // ok, hear me out.. for this one, we pass it on to the PAL using
    // DkStreamAttributesQueryByHandle call, instead of the other alternatives
    // (like DkStreamMap). Why? three reasons: 1) Because we can; i.e. in terms of passed params.
    // 2) if we do it with other calls, we will contaminate their execution paths with lots of
    // if conditions just for xdp sockets (other sockets wont have mmap).. this makes it very
    // complex. 3) XDP code becomes much more contained and focused this way; vs being all over
    // place with other handle types... so here it goes!
    PAL_STREAM_ATTR attr;
    memset(&attr, 0, sizeof(attr));
    attr.handle_type = PAL_TYPE_SOCKET;

    switch (offset) {
        case XDP_UMEM_PGOFF_FILL_RING:
            attr.xdp_socket.sockopt = PAL_XDP_MMAP_FILL_RING;
            break;
        case XDP_UMEM_PGOFF_COMPLETION_RING:
            attr.xdp_socket.sockopt = PAL_XDP_MMAP_COMP_RING;
            break;
        case XDP_PGOFF_TX_RING:
            attr.xdp_socket.sockopt = PAL_XDP_MMAP_TX_RING;
            break;
        case XDP_PGOFF_RX_RING:
            attr.xdp_socket.sockopt = PAL_XDP_MMAP_RX_RING;
            break;
        default:
            return (void*)-1; // MAP_FAILED
    }
    // we can ignore prot.. rings will always be READ | WRITE
    attr.xdp_socket.ring_size = size;
    attr.xdp_socket.rings_mmap_flags = flags;
    // pass the addr too, it could have a hint
    attr.xdp_socket.untrusted_ring_mapping = addr;
    // FIXME: this PAL call is not really fitting. maybe we should find a better one?
    int ret = DkStreamAttributesQueryByHandle(handle->info.sock.pal_handle, &attr);
    if(ret < 0){
        return (void*)-1; // MAP_FAILED
    }
    return attr.xdp_socket.untrusted_ring_mapping;
}

static int create(struct shim_handle* handle) {
    assert(handle->info.sock.domain == AF_XDP);
    assert(handle->info.sock.type == SOCK_RAW);

    // xdp sockets can only have SOCK_RAW as the type
    if (handle->info.sock.type != SOCK_RAW) {
      return -ESOCKTNOSUPPORT;
    }
    // and no protocol.
    if (handle->info.sock.protocol) {
      return -EPROTONOSUPPORT;
    }

    /* We don't need to take the lock - handle was just created. */
    enum pal_socket_domain pal_domain = PAL_XDP;
    enum pal_socket_type pal_type = PAL_SOCKET_RAW;
    pal_stream_options_t options = 0;
    PAL_HANDLE pal_handle = NULL;
    int ret = DkSocketCreate(pal_domain, pal_type, options, &pal_handle);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }
    handle->info.sock.pal_handle = pal_handle;
    handle->type = TYPE_SOCK;
    handle->fs = &socket_builtin_fs;
    handle->flags = O_RDWR;
    handle->info.sock.can_be_written = true;

    return 0;
}

static int bind(struct shim_handle* handle, void* _addr, size_t addrlen) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    if (addrlen < sizeof(struct sockaddr_xdp)) {
      return -EINVAL;
    }

    struct sockaddr_xdp* addr = _addr;
    if (addr->sxdp_family != AF_XDP) {
      return -EINVAL;
    }

    uint32_t flags = addr->sxdp_flags;
    if (flags & ~(XDP_SHARED_UMEM | XDP_COPY | XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP)){
      return -EINVAL;
    }

    // TODO: here we should also check and make sure that xdp socket is initialized
    // check kernel source, things like: rings, umem.. etc

    struct pal_socket_addr pal_xdp_addr;
    linux_to_pal_sockaddr(_addr, &pal_xdp_addr);

    int ret = DkSocketBind(sock->pal_handle, &pal_xdp_addr);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    pal_to_linux_sockaddr(&pal_xdp_addr, &sock->local_addr, &sock->local_addrlen);
    return 0;
}

static int listen(struct shim_handle* handle, unsigned int backlog) {
    __UNUSED(backlog);
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    // xdp sockets does not support listen
    return -EOPNOTSUPP;
}

static int accept(struct shim_handle* handle, bool is_nonblocking,
                  struct shim_handle** client_ptr) {
    __UNUSED(handle);
    __UNUSED(is_nonblocking);
    __UNUSED(client_ptr);

    // xdp sockets does not support accept
    return -EOPNOTSUPP;
}

static int connect(struct shim_handle* handle, void* _addr, size_t addrlen) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));
    __UNUSED(_addr);
    __UNUSED(addrlen);

    // xdp sockets does not support connect
    return -EOPNOTSUPP;
}

static int disconnect(struct shim_handle* handle) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    // xdp sockets does not support "disconnect"
    return -EOPNOTSUPP;
}

static int setsockopt(struct shim_handle* handle, int level, int optname, void* optval,
                      size_t len) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    if (sock->domain != AF_XDP) {
      return -EINVAL;
    }

    if (level != SOL_XDP) {
        return -ENOPROTOOPT;
    }

    PAL_STREAM_ATTR attr;
    memset(&attr, 0, sizeof(attr));
    attr.handle_type = PAL_TYPE_SOCKET;

    switch (optname) {
        case XDP_UMEM_REG:
            if (len < sizeof(struct xdp_umem_reg)) {
                return -EINVAL;
            }
            struct xdp_umem_reg* mr = optval;
            bool unaligned_chunks = mr->flags & XDP_UMEM_UNALIGNED_CHUNK_FLAG;

            if (mr->chunk_size < XDP_UMEM_MIN_CHUNK_SIZE || mr->chunk_size > PAGE_SIZE) {
                return -EINVAL;
            }
            if (mr->flags & ~XDP_UMEM_UNALIGNED_CHUNK_FLAG){
                return -EINVAL;
            }
            if (!unaligned_chunks && !IS_POWER_OF_2(mr->chunk_size)){
                return -EINVAL;
            }
            if (!IS_ALIGNED_PTR(mr->addr, PAGE_SIZE)) {
                return -EINVAL;
            }
            if ((mr->addr + mr->len) < mr->addr){
                return -EINVAL;
            }
            if (mr->headroom >= mr->chunk_size){
                return -EINVAL;
            }
            // FIXME: we need to check that umem buffer is valid, currently we cannot do that;
            // the untrusted mmap for Linux-SGX PAL bypasses the vma which is how the
            // is_user_memory_* functions works.. thus it will always return false for
            // untrusted mmap.

            // i think we have coverd major errors.. do the thingy
            attr.xdp_socket.sockopt             = PAL_XDP_SETSOCKOPT_UMEM_REG;
            attr.xdp_socket.umem_addr           = mr->addr;
            attr.xdp_socket.umem_len            = mr->len;
            attr.xdp_socket.umem_chunk_size     = mr->chunk_size;
            attr.xdp_socket.umem_chunk_headroom = mr->headroom;
            attr.xdp_socket.umem_flags          = mr->flags;
            break;

        case XDP_UMEM_COMPLETION_RING:
            if (!is_user_memory_readable((const void*)optval, sizeof(int))){
                return -EINVAL;
            }
            attr.xdp_socket.sockopt   = PAL_XDP_SETSOCKOPT_COMP_RING;
            attr.xdp_socket.ring_size = *(int*)optval;
            break;
        case XDP_UMEM_FILL_RING:
            if (!is_user_memory_readable((const void*)optval, sizeof(int))){
                return -EINVAL;
            }
            attr.xdp_socket.sockopt   = PAL_XDP_SETSOCKOPT_FILL_RING;
            attr.xdp_socket.ring_size = *(int*)optval;
            break;
        case XDP_RX_RING:
            if (!is_user_memory_readable((const void*)optval, sizeof(int))){
                return -EINVAL;
            }
            attr.xdp_socket.sockopt   = PAL_XDP_SETSOCKOPT_RX_RING;
            attr.xdp_socket.ring_size = *(int*)optval;
            break;
        case XDP_TX_RING:
            if (!is_user_memory_readable((const void*)optval, sizeof(int))){
                return -EINVAL;
            }
            attr.xdp_socket.sockopt   = PAL_XDP_SETSOCKOPT_TX_RING;
            attr.xdp_socket.ring_size = *(int*)optval;
            break;
        default:
            return -ENOPROTOOPT;
            break;
    }

    int ret = DkStreamAttributesSetByHandle(handle->info.sock.pal_handle, &attr);
    return pal_to_unix_errno(ret);
}

static int getsockopt(struct shim_handle* handle, int level, int optname, void* optval,
                      size_t* len) {
    struct shim_sock_handle* sock = &handle->info.sock;
    assert(locked(&sock->lock));

    if (sock->domain != AF_XDP) {
      return -EINVAL;
    }
    if (level != SOL_XDP) {
        return -ENOPROTOOPT;
    }

    PAL_STREAM_ATTR attr;
    memset(&attr, 0, sizeof(attr));
    attr.handle_type = PAL_TYPE_SOCKET;

    switch (optname) {
        case XDP_MMAP_OFFSETS:;
            attr.xdp_socket.sockopt = PAL_XDP_GETSOCKOPT_MMAP_OFFSETS;
            int ret = DkStreamAttributesQueryByHandle(handle->info.sock.pal_handle, &attr);

            // TODO: we should really check those returned offsets
            struct xdp_mmap_offsets* xdp_off = optval;
            xdp_off->fr.producer = attr.xdp_socket.fill_producer;
            xdp_off->fr.consumer = attr.xdp_socket.fill_consumer;
            xdp_off->fr.desc     = attr.xdp_socket.fill_desc;
            xdp_off->fr.flags    = attr.xdp_socket.fill_flags;
            xdp_off->cr.producer = attr.xdp_socket.complete_producer;
            xdp_off->cr.consumer = attr.xdp_socket.complete_consumer;
            xdp_off->cr.desc     = attr.xdp_socket.complete_desc;
            xdp_off->cr.flags    = attr.xdp_socket.complete_flags;
            xdp_off->tx.producer = attr.xdp_socket.tx_producer;
            xdp_off->tx.consumer = attr.xdp_socket.tx_consumer;
            xdp_off->tx.desc     = attr.xdp_socket.tx_desc;
            xdp_off->tx.flags    = attr.xdp_socket.tx_flags;
            xdp_off->rx.producer = attr.xdp_socket.rx_producer;
            xdp_off->rx.consumer = attr.xdp_socket.rx_consumer;
            xdp_off->rx.desc     = attr.xdp_socket.rx_desc;
            xdp_off->rx.flags    = attr.xdp_socket.rx_flags;
            *len = sizeof(*xdp_off);

            return pal_to_unix_errno(ret);
            break;

        case XDP_OPTIONS:
        case XDP_STATISTICS:
            // TODO: we dont need those for now (for xdp init I mean)
            return -EOPNOTSUPP;
            break;
        default:
            return -ENOPROTOOPT;
            break;
    }
}

static int send(struct shim_handle* handle, struct iovec* iov, size_t iov_len, size_t* size_out,
                void* _addr, size_t addrlen) {
    // Note about this one: the kernel implementation of this call for this type
    // of socket does not even look at the passed parameter like the msg/size/addr...
    // it only wake the device (if needed) and return! 
    //
    // In other words, if we decided to go with a design that does not require us to
    // wake up (unsetting the flag XDP_USE_NEED_WAKEUP),, we can ignore this syscall
    // completely! This only works in the zero-copy mode, though, which require special
    // NIC that we dont have when devloping this. In copy-mode (which is what
    // we have with veth), we have to implement this so the user can tell the kernel
    // to send.. this is not the fastest way thought. I also believe that this
    // optimization should happen from the user side (i.e. not calling send in
    // first place) rather than in us ignoring it.
    assert(handle->type == TYPE_SOCK);
    struct shim_sock_handle* sock = &handle->info.sock;
    int ret = DkSocketSend(sock->pal_handle, NULL, 0, 0, NULL);
    return ret;
}

static int recv(struct shim_handle* handle, struct iovec* iov, size_t iov_len, size_t* size_out,
                void* _addr, size_t* addrlen, bool is_nonblocking) {

    // TODO: implement
    // same note for send
    return -ENOPROTOOPT;
}

struct shim_sock_ops sock_xdp_ops = {
    .create = create,
    .bind = bind,
    .listen = listen,
    .accept = accept,
    .connect = connect,
    .disconnect = disconnect,
    .getsockopt = getsockopt,
    .setsockopt = setsockopt,
    .send = send,
    .recv = recv,
};
