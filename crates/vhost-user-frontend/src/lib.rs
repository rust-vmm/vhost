// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#[macro_use]
extern crate log;

mod device;
mod epoll_helper;
mod seccomp_filters;
mod thread_helper;
mod vhost_user;

pub use crate::device::*;
pub use crate::epoll_helper::*;
pub use crate::seccomp_filters::*;
pub(crate) use crate::thread_helper::*;
pub use crate::vhost_user::*;

use std::fmt::{self, Debug};

use virtio_queue::{Queue, QueueT};
use vm_memory::{
    bitmap::AtomicBitmap, GuestAddress, GuestMemory,
};

type GuestMemoryMmap = vm_memory::GuestMemoryMmap<AtomicBitmap>;
type GuestRegionMmap = vm_memory::GuestRegionMmap<AtomicBitmap>;
type MmapRegion = vm_memory::MmapRegion<AtomicBitmap>;

const VIRTIO_F_RING_INDIRECT_DESC: u32 = 28;
const VIRTIO_F_RING_EVENT_IDX: u32 = 29;
const VIRTIO_F_VERSION_1: u32 = 32;
const VIRTIO_F_IOMMU_PLATFORM: u32 = 33;
const VIRTIO_F_IN_ORDER: u32 = 35;
const VIRTIO_F_ORDER_PLATFORM: u32 = 36;
#[allow(dead_code)]
const VIRTIO_F_SR_IOV: u32 = 37;
const VIRTIO_F_NOTIFICATION_DATA: u32 = 38;

#[derive(Debug)]
pub enum ActivateError {
    EpollCtl(std::io::Error),
    BadActivate,
    /// Queue number is not correct
    BadQueueNum,
    /// Failed to clone Kill event fd
    CloneKillEventFd,
    /// Failed to clone exit event fd
    CloneExitEventFd(std::io::Error),
    // Failed to spawn thread
    ThreadSpawn(std::io::Error),
    /// Failed to create Vhost-user interrupt eventfd
    VhostIrqCreate,
    /// Failed to setup vhost-user-fs daemon.
    VhostUserFsSetup(vhost_user::Error),
    /// Failed to setup vhost-user-net daemon.
    VhostUserNetSetup(vhost_user::Error),
    /// Failed to setup vhost-user-blk daemon.
    VhostUserBlkSetup(vhost_user::Error),
    /// Failed to reset vhost-user daemon.
    VhostUserReset(vhost_user::Error),
    /// Cannot create seccomp filter
    CreateSeccompFilter(seccompiler::Error),
    /// Cannot create rate limiter
    CreateRateLimiter(std::io::Error),
}

pub type ActivateResult = std::result::Result<(), ActivateError>;

// Types taken from linux/virtio_ids.h
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub enum VirtioDeviceType {
    Net = 1,
    Block = 2,
    Console = 3,
    Rng = 4,
    Balloon = 5,
    Fs9P = 9,
    Gpu = 16,
    Input = 18,
    Vsock = 19,
    Iommu = 23,
    Mem = 24,
    Fs = 26,
    Pmem = 27,
    I2c = 34,
    Watchdog = 35, // Temporary until official number allocated
    Gpio = 41,
    Unknown = 0xFF,
}

impl From<u32> for VirtioDeviceType {
    fn from(t: u32) -> Self {
        match t {
            1 => VirtioDeviceType::Net,
            2 => VirtioDeviceType::Block,
            3 => VirtioDeviceType::Console,
            4 => VirtioDeviceType::Rng,
            5 => VirtioDeviceType::Balloon,
            9 => VirtioDeviceType::Fs9P,
            16 => VirtioDeviceType::Gpu,
            18 => VirtioDeviceType::Input,
            19 => VirtioDeviceType::Vsock,
            23 => VirtioDeviceType::Iommu,
            24 => VirtioDeviceType::Mem,
            26 => VirtioDeviceType::Fs,
            27 => VirtioDeviceType::Pmem,
            34 => VirtioDeviceType::I2c,
            35 => VirtioDeviceType::Watchdog,
            41 => VirtioDeviceType::Gpio,
            _ => VirtioDeviceType::Unknown,
        }
    }
}

impl From<&str> for VirtioDeviceType {
    fn from(t: &str) -> Self {
        match t {
            "net" => VirtioDeviceType::Net,
            "block" => VirtioDeviceType::Block,
            "console" => VirtioDeviceType::Console,
            "rng" => VirtioDeviceType::Rng,
            "balloon" => VirtioDeviceType::Balloon,
            "fs9p" => VirtioDeviceType::Fs9P,
            "gpu" => VirtioDeviceType::Gpu,
            "input" => VirtioDeviceType::Input,
            "vsock" => VirtioDeviceType::Vsock,
            "iommu" => VirtioDeviceType::Iommu,
            "mem" => VirtioDeviceType::Mem,
            "fs" => VirtioDeviceType::Fs,
            "pmem" => VirtioDeviceType::Pmem,
            "i2c" => VirtioDeviceType::I2c,
            "watchdog" => VirtioDeviceType::Watchdog,
            "gpio" => VirtioDeviceType::Gpio,
            _ => VirtioDeviceType::Unknown,
        }
    }
}

impl From<VirtioDeviceType> for String {
    fn from(t: VirtioDeviceType) -> String {
        match t {
            VirtioDeviceType::Net => "net",
            VirtioDeviceType::Block => "block",
            VirtioDeviceType::Console => "console",
            VirtioDeviceType::Rng => "rng",
            VirtioDeviceType::Balloon => "balloon",
            VirtioDeviceType::Gpu => "gpu",
            VirtioDeviceType::Fs9P => "9p",
            VirtioDeviceType::Input => "input",
            VirtioDeviceType::Vsock => "vsock",
            VirtioDeviceType::Iommu => "iommu",
            VirtioDeviceType::Mem => "mem",
            VirtioDeviceType::Fs => "fs",
            VirtioDeviceType::Pmem => "pmem",
            VirtioDeviceType::I2c => "i2c",
            VirtioDeviceType::Watchdog => "watchdog",
            VirtioDeviceType::Gpio => "gpio",
            VirtioDeviceType::Unknown => "UNKNOWN",
        }
        .to_string()
    }
}

// In order to use the `{}` marker, the trait `fmt::Display` must be implemented
// manually for the type VirtioDeviceType.
impl fmt::Display for VirtioDeviceType {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", String::from(*self))
    }
}

impl VirtioDeviceType {
    // Returns (number, size) of all queues
    pub fn queue_num_and_size(&self) -> (usize, usize) {
        match *self {
            VirtioDeviceType::Net => (0, 0),
            VirtioDeviceType::Block => (0, 0),
            VirtioDeviceType::Console => (0, 0),
            VirtioDeviceType::Rng => (0, 0),
            VirtioDeviceType::Balloon => (0, 0),
            VirtioDeviceType::Gpu => (0, 0),
            VirtioDeviceType::Fs9P => (0, 0),
            VirtioDeviceType::Input => (0, 0),
            VirtioDeviceType::Vsock => (0, 0),
            VirtioDeviceType::Iommu => (0, 0),
            VirtioDeviceType::Mem => (0, 0),
            VirtioDeviceType::Fs => (0, 0),
            VirtioDeviceType::Pmem => (0, 0),
            VirtioDeviceType::I2c => (1, 1024),
            VirtioDeviceType::Watchdog => (0, 0),
            VirtioDeviceType::Gpio => (2, 256),
            _ => (0, 0),
        }
    }
}

/// Trait for devices with access to data in memory being limited and/or
/// translated.
pub trait AccessPlatform: Send + Sync + Debug {
    /// Provide a way to translate GVA address ranges into GPAs.
    fn translate_gva(&self, base: u64, size: u64) -> std::result::Result<u64, std::io::Error>;
    /// Provide a way to translate GPA address ranges into GVAs.
    fn translate_gpa(&self, base: u64, size: u64) -> std::result::Result<u64, std::io::Error>;
}

/// Helper for cloning a Queue since QueueState doesn't derive Clone
pub fn clone_queue(queue: &Queue) -> Queue {
    let mut q = Queue::new(queue.max_size()).unwrap();

    q.set_next_avail(queue.next_avail());
    q.set_next_used(queue.next_used());
    q.set_event_idx(queue.event_idx_enabled());
    q.set_size(queue.size());
    q.set_ready(queue.ready());
    q.try_set_desc_table_address(GuestAddress(queue.desc_table()))
        .unwrap();
    q.try_set_avail_ring_address(GuestAddress(queue.avail_ring()))
        .unwrap();
    q.try_set_used_ring_address(GuestAddress(queue.used_ring()))
        .unwrap();

    q
}

/// Convert an absolute address into an address space (GuestMemory)
/// to a host pointer and verify that the provided size define a valid
/// range within a single memory region.
/// Return None if it is out of bounds or if addr+size overlaps a single region.
pub fn get_host_address_range<M: GuestMemory + ?Sized>(
    mem: &M,
    addr: GuestAddress,
    size: usize,
) -> Option<*mut u8> {
    if mem.check_range(addr, size) {
        Some(mem.get_host_address(addr).unwrap())
    } else {
        None
    }
}
