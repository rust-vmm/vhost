// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-Google file.

//! Kernel-based vsock vhost backend.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};

use super::vhost_binding::{VHOST_VSOCK_SET_GUEST_CID, VHOST_VSOCK_SET_RUNNING};
use super::{ioctl_result, Error, Result, VhostKernBackend};
use libc;
use vm_memory::GuestAddressSpace;
use vmm_sys_util::ioctl::ioctl_with_ref;

const VHOST_PATH: &str = "/dev/vhost-vsock";

/// Handle for running VHOST_VSOCK ioctls.
pub struct Vsock<AS: GuestAddressSpace> {
    fd: File,
    mem: AS,
}

impl<AS: GuestAddressSpace> Vsock<AS> {
    /// Open a handle to a new VHOST-VSOCK instance.
    pub fn new(mem: AS) -> Result<Self> {
        Ok(Vsock {
            fd: OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(VHOST_PATH)
                .map_err(Error::VhostOpen)?,
            mem,
        })
    }

    /// Set the CID for the guest.  This number is used for routing all data destined for
    /// running in the guest. Each guest on a hypervisor must have an unique CID
    ///
    /// # Arguments
    /// * `cid` - CID to assign to the guest
    pub fn set_guest_cid(&self, cid: u64) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_VSOCK_SET_GUEST_CID(), &cid) };
        ioctl_result(ret, ())
    }

    /// Tell the VHOST driver to start performing data transfer.
    pub fn start(&self) -> Result<()> {
        self.set_running(true)
    }

    /// Tell the VHOST driver to stop performing data transfer.
    pub fn stop(&self) -> Result<()> {
        self.set_running(false)
    }

    fn set_running(&self, running: bool) -> Result<()> {
        let on: ::std::os::raw::c_int = if running { 1 } else { 0 };
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_VSOCK_SET_RUNNING(), &on) };
        ioctl_result(ret, ())
    }
}

impl<AS: GuestAddressSpace> VhostKernBackend for Vsock<AS> {
    type AS = AS;

    fn mem(&self) -> &Self::AS {
        &self.mem
    }
}

impl<AS: GuestAddressSpace> AsRawFd for Vsock<AS> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
