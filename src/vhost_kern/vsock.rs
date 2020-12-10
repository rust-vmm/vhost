// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-Google file.

//! Kernel-based vhost-vsock backend.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};

use super::vhost_binding::{VHOST_VSOCK_SET_GUEST_CID, VHOST_VSOCK_SET_RUNNING};
use super::{ioctl_result, Error, Result, VhostKernBackend};
use libc;
use vm_memory::GuestAddressSpace;
use vmm_sys_util::ioctl::ioctl_with_ref;
use vsock::VhostVsock;

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

impl<AS: GuestAddressSpace> VhostVsock for Vsock<AS> {
    /// Set the CID for the guest.  This number is used for routing all data destined for
    /// running in the guest. Each guest on a hypervisor must have an unique CID
    ///
    /// # Arguments
    /// * `cid` - CID to assign to the guest
    fn set_guest_cid(&mut self, cid: u64) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_VSOCK_SET_GUEST_CID(), &cid) };
        ioctl_result(ret, ())
    }

    /// Tell the VHOST driver to start performing data transfer.
    fn start(&mut self) -> Result<()> {
        self.set_running(true)
    }

    /// Tell the VHOST driver to stop performing data transfer.
    fn stop(&mut self) -> Result<()> {
        self.set_running(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
    use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};
    use vmm_sys_util::eventfd::EventFd;

    #[test]
    fn test_vhost_vsock() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10_0000)]).unwrap();
        let mut vsock = Vsock::new(&mem).unwrap();

        // Must set current process to be the owner before issuing other IOCTLs.
        vsock.set_owner().unwrap();

        let features = vsock.get_features().unwrap();
        vsock.set_features(features).unwrap();

        let hva = mem.get_host_address(GuestAddress(0)).unwrap() as *const u8 as u64;
        let meminfo = vec![VhostUserMemoryRegionInfo {
            guest_phys_addr: 0,
            memory_size: 0x10_0000,
            userspace_addr: hva,
            mmap_offset: 0,
            mmap_handle: 0,
        }];
        vsock.set_mem_table(&meminfo).unwrap();

        vsock.set_vring_num(0, 256).unwrap();

        let config = VringConfigData {
            queue_max_size: 256,
            queue_size: 256,
            flags: 0,
            desc_table_addr: hva + 0x1_0000,
            used_ring_addr: hva + 0x2_0000,
            avail_ring_addr: hva + 0x3_0000,
            log_addr: None,
        };
        vsock.set_vring_addr(0, &config).unwrap();

        let fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        vsock.set_vring_call(0, &fd).unwrap();
        vsock.set_vring_kick(0, &fd).unwrap();
        vsock.set_vring_err(0, &fd).unwrap();

        vsock.set_guest_cid(10).unwrap();

        // It depends on recent kernel versions.
        //vsock.start().unwrap();
        //vsock.stop().unwrap();

        let base = vsock.get_vring_base(0).unwrap();
        vsock.set_vring_base(0, base as u16).unwrap();

        assert_ne!(vsock.as_raw_fd(), -1);
        assert_eq!(vsock.mem(), &mem);
    }
}
