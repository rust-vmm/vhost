// Copyright (C) 2020 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-Google file.

//! Kernel-based virtio-net vhost backend.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};

use super::vhost_binding::{vhost_vring_file, VHOST_NET_SET_BACKEND};
use super::{ioctl_result, Error, Result, VhostKernBackend};
use libc;
use vm_memory::GuestAddressSpace;
use vmm_sys_util::ioctl::ioctl_with_ref;

const DEVICE: &str = "/dev/vhost-net";

/// Handle for running VHOST_NET ioctls.
pub struct Net<AS: GuestAddressSpace> {
    fd: File,
    mem: AS,
}

impl<AS: GuestAddressSpace> Net<AS> {
    /// Open a handle to a new VHOST-NET instance.
    pub fn new(mem: AS) -> Result<Self> {
        Ok(Net {
            fd: OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(DEVICE)
                .map_err(Error::VhostOpen)?,
            mem,
        })
    }

    /// Set the file descriptor of interface device that will serve as the VHOST_NET backend.
    /// This will start the vhost worker for the given queue.
    pub fn set_backend(&self, queue_index: usize, fd: Option<&File>) -> Result<()> {
        let vring_file = vhost_vring_file {
            index: queue_index as u32,
            fd: fd.map_or(-1, |fd| fd.as_raw_fd()),
        };

        // This ioctl is called on a valid vhost_net fd.
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_NET_SET_BACKEND(), &vring_file) };
        ioctl_result(ret, ())
    }
}

impl<AS: GuestAddressSpace> VhostKernBackend for Net<AS> {
    type AS = AS;

    fn mem(&self) -> &Self::AS {
        &self.mem
    }
}

impl<AS: GuestAddressSpace> AsRawFd for Net<AS> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
