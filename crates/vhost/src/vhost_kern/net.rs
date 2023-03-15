// Copyright (C) 2021 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Kernel-based vhost-net backend

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};

use vm_memory::GuestAddressSpace;
use vmm_sys_util::ioctl::ioctl_with_ref;

use super::vhost_binding::*;
use super::{ioctl_result, Error, Result, VhostKernBackend};

use crate::net::*;

const VHOST_NET_PATH: &str = "/dev/vhost-net";

/// Handle for running VHOST_NET ioctls
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
                .open(VHOST_NET_PATH)
                .map_err(Error::VhostOpen)?,
            mem,
        })
    }
}

impl<AS: GuestAddressSpace> VhostNet for Net<AS> {
    fn set_backend(&self, queue_index: usize, fd: Option<&File>) -> Result<()> {
        let vring_file = vhost_vring_file {
            index: queue_index as u32,
            fd: fd.map_or(-1, |v| v.as_raw_fd()),
        };

        let ret = unsafe { ioctl_with_ref(self, VHOST_NET_SET_BACKEND(), &vring_file) };
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

#[cfg(test)]
mod tests {
    use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::{
        VhostBackend, VhostUserDirtyLogRegion, VhostUserMemoryRegionInfo, VringConfigData,
    };
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_net_new_device() {
        let m = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10_0000)]).unwrap();
        let net = Net::new(&m).unwrap();

        assert!(net.as_raw_fd() >= 0);
        assert!(net.mem().find_region(GuestAddress(0x100)).is_some());
        assert!(net.mem().find_region(GuestAddress(0x10_0000)).is_none());
    }

    #[test]
    #[serial]
    fn test_net_is_valid() {
        let m = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10_0000)]).unwrap();
        let net = Net::new(&m).unwrap();

        let mut config = VringConfigData {
            queue_max_size: 32,
            queue_size: 32,
            flags: 0,
            desc_table_addr: 0x1000,
            used_ring_addr: 0x2000,
            avail_ring_addr: 0x3000,
            log_addr: None,
        };
        assert!(net.is_valid(&config));

        config.queue_size = 0;
        assert!(!net.is_valid(&config));
        config.queue_size = 31;
        assert!(!net.is_valid(&config));
        config.queue_size = 33;
        assert!(!net.is_valid(&config));
    }

    #[test]
    #[serial]
    fn test_net_ioctls() {
        let m = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10_0000)]).unwrap();
        let net = Net::new(&m).unwrap();
        let backend = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();

        let features = net.get_features().unwrap();
        net.set_features(features).unwrap();

        net.set_owner().unwrap();

        let region: Vec<VhostUserMemoryRegionInfo> = Vec::new();
        net.set_mem_table(&region).unwrap_err();

        let region = VhostUserMemoryRegionInfo {
            guest_phys_addr: 0x0,
            memory_size: 0x10_0000,
            userspace_addr: m.get_host_address(GuestAddress(0x0)).unwrap() as u64,
            mmap_offset: 0,
            mmap_handle: -1,
        };
        net.set_mem_table(&[region]).unwrap();

        net.set_log_base(
            0x4000,
            Some(VhostUserDirtyLogRegion {
                mmap_size: 0x1000,
                mmap_offset: 0x10,
                mmap_handle: 1,
            }),
        )
        .unwrap_err();
        net.set_log_base(0x4000, None).unwrap();

        let eventfd = EventFd::new(0).unwrap();
        net.set_log_fd(eventfd.as_raw_fd()).unwrap();

        net.set_vring_num(0, 32).unwrap();

        let config = VringConfigData {
            queue_max_size: 32,
            queue_size: 32,
            flags: 0,
            desc_table_addr: 0x1000,
            used_ring_addr: 0x2000,
            avail_ring_addr: 0x3000,
            log_addr: None,
        };
        net.set_vring_addr(0, &config).unwrap();
        net.set_vring_base(0, 1).unwrap();
        net.set_vring_call(0, &eventfd).unwrap();
        net.set_vring_kick(0, &eventfd).unwrap();
        net.set_vring_err(0, &eventfd).unwrap();
        assert_eq!(net.get_vring_base(0).unwrap(), 1);

        net.set_backend(0, Some(&backend)).unwrap_err();
        net.set_backend(0, None).unwrap();
    }
}
