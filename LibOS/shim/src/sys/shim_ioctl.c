/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system call "ioctl".
 */

#include <asm/ioctls.h>

#include "pal.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_process.h"
#include "shim_signal.h"
#include "shim_table.h"

static void signal_io(IDTYPE caller, void* arg) {
    __UNUSED(caller);
    __UNUSED(arg);
    /* TODO: fill these values e.g. by getting the handle in arg; this is completely unusable now */
    siginfo_t info = {
        .si_signo = SIGIO,
        .si_code = SI_SIGIO,
        .si_band = 0,
        .si_fd = 0,
    };
    if (kill_current_proc(&info) < 0) {
        log_warning("signal_io: failed to deliver a signal");
    }
}

/**
 * searches for the interface index in the manifest
 *
 * @return 0 if interface index is not provided in manifest as 0 is an invalid index
 */
static int get_if_index(const char* ifname){
    long ifindex = 0;
    struct pal_public_state* pal_state = DkGetPalPublicState();
    toml_table_t* manifest_root = pal_state->manifest_root;
    assert(manifest_root);

    toml_table_t* toml_sys_table = toml_table_in(manifest_root, "sys");
    if (!toml_sys_table) {
        return 0;
    }
    toml_table_t* toml_net_table = toml_table_in(toml_sys_table, "net");
    if (!toml_net_table) {
        return 0;
    }
    toml_raw_t toml_raw_ifindex = toml_raw_in(toml_net_table, ifname);
    if (!toml_raw_ifindex) {
        return 0;
    }
    if (toml_rtoi(toml_raw_ifindex, &ifindex) < 0){
        return 0;
    }
    return ifindex;
}

long shim_do_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg) {
    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret;
    switch (cmd) {
        case TIOCGPGRP:
            if (!hdl->uri || strcmp(hdl->uri, "dev:tty") != 0) {
                ret = -ENOTTY;
                break;
            }

            if (!is_user_memory_writable((void*)arg, sizeof(int))) {
                ret = -EFAULT;
                break;
            }
            *(int*)arg = __atomic_load_n(&g_process.pgid, __ATOMIC_ACQUIRE);
            ret = 0;
            break;
        case FIONBIO:
            if (!is_user_memory_readable((void*)arg, sizeof(int))) {
                ret = -EFAULT;
                break;
            }
            int nonblocking_on = *(int*)arg;
            ret = set_handle_nonblocking(hdl, !!nonblocking_on);
            break;
        case FIONCLEX:
            hdl->flags &= ~FD_CLOEXEC;
            ret = 0;
            break;
        case FIOCLEX:
            hdl->flags |= FD_CLOEXEC;
            ret = 0;
            break;
        case FIOASYNC:
            ret = install_async_event(hdl->pal_handle, 0, &signal_io, NULL);
            break;
        case FIONREAD: {
            if (!is_user_memory_writable((void*)arg, sizeof(int))) {
                ret = -EFAULT;
                break;
            }

            struct shim_fs* fs = hdl->fs;
            if (!fs || !fs->fs_ops) {
                ret = -EACCES;
                break;
            }

            int size = 0;
            if (fs->fs_ops->hstat) {
                struct stat stat;
                ret = fs->fs_ops->hstat(hdl, &stat);
                if (ret < 0)
                    break;
                size = stat.st_size;
            } else if (hdl->pal_handle) {
                PAL_STREAM_ATTR attr;
                ret = DkStreamAttributesQueryByHandle(hdl->pal_handle, &attr);
                if (ret < 0) {
                    ret = pal_to_unix_errno(ret);
                    break;
                }
                size = attr.pending_size;
            }

            int offset = 0;
            if (fs->fs_ops->seek) {
                ret = fs->fs_ops->seek(hdl, 0, SEEK_CUR);
                if (ret < 0)
                    break;
                offset = ret;
            }

            *(int*)arg = size - offset;
            ret = 0;
            break;
        }
        case SIOCGIFINDEX:;
            if (!is_user_memory_readable((void*)arg, sizeof(struct ifreq)) ||
                    !is_user_memory_writable((void*)arg, sizeof(struct ifreq))) {
                ret = -EFAULT;
                break;
            }

            struct ifreq* req = (struct ifreq*) arg;
            const char* ifname = req->ifr_name;
            int ifname_len = strnlen(ifname, IF_NAMESIZE);
            if (ifname_len == IF_NAMESIZE || ifname_len == 0) {
                ret = -EINVAL;
                break;
            }

            // now we get the interface index from the manifest
            int ifindex = get_if_index(ifname);
            req->ifr_ifindex = ifindex;
            if (ifindex == 0) {
                ret = -ENODEV;
                break;
            }

            ret = 0;
            break;
        default:
            ret = -ENOSYS;
            break;
    }

    put_handle(hdl);
    if (ret == -EINTR) {
        ret = -ERESTARTSYS;
    }
    return ret;
}
