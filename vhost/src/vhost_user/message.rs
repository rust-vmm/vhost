// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Define communication messages for the vhost-user protocol.
//!
//! For message definition, please refer to the [vhost-user spec](https://qemu.readthedocs.io/en/latest/interop/vhost-user.html).

#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use std::fmt::Debug;
use std::fs::File;
use std::io;
use std::marker::PhantomData;
use std::ops::Deref;

use vm_memory::{mmap::NewBitmap, ByteValued, Error as MmapError, FileOffset, MmapRegion};

#[cfg(feature = "xen")]
use vm_memory::{GuestAddress, MmapRange, MmapXenFlags};

use super::{Error, Result};
use crate::VringConfigData;

/// The vhost-user specification uses a field of u32 to store message length.
/// On the other hand, preallocated buffers are needed to receive messages from the Unix domain
/// socket. To preallocating a 4GB buffer for each vhost-user message is really just an overhead.
/// Among all defined vhost-user messages, only the VhostUserConfig and VhostUserMemory has variable
/// message size. For the VhostUserConfig, a maximum size of 4K is enough because the user
/// configuration space for virtio devices is (4K - 0x100) bytes at most. For the VhostUserMemory,
/// 4K should be enough too because it can support 255 memory regions at most.
pub const MAX_MSG_SIZE: usize = 0x1000;

/// The VhostUserMemory message has variable message size and variable number of attached file
/// descriptors. Each user memory region entry in the message payload occupies 32 bytes,
/// so setting maximum number of attached file descriptors based on the maximum message size.
/// But rust only implements Default and AsMut traits for arrays with 0 - 32 entries, so further
/// reduce the maximum number...
// pub const MAX_ATTACHED_FD_ENTRIES: usize = (MAX_MSG_SIZE - 8) / 32;
pub const MAX_ATTACHED_FD_ENTRIES: usize = 32;

/// Starting position (inclusion) of the device configuration space in virtio devices.
pub const VHOST_USER_CONFIG_OFFSET: u32 = 0x100;

/// Ending position (exclusion) of the device configuration space in virtio devices.
pub const VHOST_USER_CONFIG_SIZE: u32 = 0x1000;

/// Maximum number of vrings supported.
pub const VHOST_USER_MAX_VRINGS: u64 = 0x8000u64;

pub(super) trait Req:
    Clone + Copy + Debug + PartialEq + Eq + PartialOrd + Ord + Send + Sync + Into<u32> + TryFrom<u32>
{
}

macro_rules! enum_value {
    (
        $(#[$meta:meta])*
        $vis:vis enum $enum:ident: $T:tt {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $(= $val:expr)?,
            )*
        }
    ) => {
        #[repr($T)]
        $(#[$meta])*
        $vis enum $enum {
            $($(#[$variant_meta])* $variant $(= $val)?,)*
        }

        impl std::convert::TryFrom<$T> for $enum {
            type Error = ();

            fn try_from(v: $T) -> std::result::Result<Self, Self::Error> {
                match v {
                    $(v if v == $enum::$variant as $T => Ok($enum::$variant),)*
                    _ => Err(()),
                }
            }
        }

        impl std::convert::From<$enum> for $T {
            fn from(v: $enum) -> $T {
                v as $T
            }
        }
    }
}

enum_value! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    /// Type of requests sending from frontends to backends.
    pub enum FrontendReq: u32 {
        /// Get from the underlying vhost implementation the features bit mask.
        GET_FEATURES = 1,
        /// Enable features in the underlying vhost implementation using a bit mask.
        SET_FEATURES = 2,
        /// Set the current Frontend as an owner of the session.
        SET_OWNER = 3,
        /// No longer used.
        RESET_OWNER = 4,
        /// Set the memory map regions on the backend so it can translate the vring addresses.
        SET_MEM_TABLE = 5,
        /// Set logging shared memory space.
        SET_LOG_BASE = 6,
        /// Set the logging file descriptor, which is passed as ancillary data.
        SET_LOG_FD = 7,
        /// Set the size of the queue.
        SET_VRING_NUM = 8,
        /// Set the addresses of the different aspects of the vring.
        SET_VRING_ADDR = 9,
        /// Set the base offset in the available vring.
        SET_VRING_BASE = 10,
        /// Get the available vring base offset.
        GET_VRING_BASE = 11,
        /// Set the event file descriptor for adding buffers to the vring.
        SET_VRING_KICK = 12,
        /// Set the event file descriptor to signal when buffers are used.
        SET_VRING_CALL = 13,
        /// Set the event file descriptor to signal when error occurs.
        SET_VRING_ERR = 14,
        /// Get the protocol feature bit mask from the underlying vhost implementation.
        GET_PROTOCOL_FEATURES = 15,
        /// Enable protocol features in the underlying vhost implementation.
        SET_PROTOCOL_FEATURES = 16,
        /// Query how many queues the backend supports.
        GET_QUEUE_NUM = 17,
        /// Signal backend to enable or disable corresponding vring.
        SET_VRING_ENABLE = 18,
        /// Ask vhost user backend to broadcast a fake RARP to notify the migration is terminated
        /// for guest that does not support GUEST_ANNOUNCE.
        SEND_RARP = 19,
        /// Set host MTU value exposed to the guest.
        NET_SET_MTU = 20,
        /// Set the socket file descriptor for backend initiated requests.
        SET_BACKEND_REQ_FD = 21,
        /// Send IOTLB messages with struct vhost_iotlb_msg as payload.
        IOTLB_MSG = 22,
        /// Set the endianness of a VQ for legacy devices.
        SET_VRING_ENDIAN = 23,
        /// Fetch the contents of the virtio device configuration space.
        GET_CONFIG = 24,
        /// Change the contents of the virtio device configuration space.
        SET_CONFIG = 25,
        /// Create a session for crypto operation.
        CREATE_CRYPTO_SESSION = 26,
        /// Close a session for crypto operation.
        CLOSE_CRYPTO_SESSION = 27,
        /// Advise backend that a migration with postcopy enabled is underway.
        POSTCOPY_ADVISE = 28,
        /// Advise backend that a transition to postcopy mode has happened.
        POSTCOPY_LISTEN = 29,
        /// Advise that postcopy migration has now completed.
        POSTCOPY_END = 30,
        /// Get a shared buffer from backend.
        GET_INFLIGHT_FD = 31,
        /// Send the shared inflight buffer back to backend.
        SET_INFLIGHT_FD = 32,
        /// Sets the GPU protocol socket file descriptor.
        GPU_SET_SOCKET = 33,
        /// Ask the vhost user backend to disable all rings and reset all internal
        /// device state to the initial state.
        RESET_DEVICE = 34,
        /// Indicate that a buffer was added to the vring instead of signalling it
        /// using the vring’s kick file descriptor.
        VRING_KICK = 35,
        /// Return a u64 payload containing the maximum number of memory slots.
        GET_MAX_MEM_SLOTS = 36,
        /// Update the memory tables by adding the region described.
        ADD_MEM_REG = 37,
        /// Update the memory tables by removing the region described.
        REM_MEM_REG = 38,
        /// Notify the backend with updated device status as defined in the VIRTIO
        /// specification.
        SET_STATUS = 39,
        /// Query the backend for its device status as defined in the VIRTIO
        /// specification.
        GET_STATUS = 40,
        /// Begin transfer of internal state to/from the backend for migration
        /// purposes.
        SET_DEVICE_STATE_FD = 42,
        /// After transferring state, check the backend for any errors that may have
        /// occurred during the transfer
        CHECK_DEVICE_STATE = 43,
    }
}

impl Req for FrontendReq {}

enum_value! {
    /// Type of requests sending from backends to frontends.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum BackendReq: u32 {
        /// Send IOTLB messages with struct vhost_iotlb_msg as payload.
        IOTLB_MSG = 1,
        /// Notify that the virtio device's configuration space has changed.
        CONFIG_CHANGE_MSG = 2,
        /// Set host notifier for a specified queue.
        VRING_HOST_NOTIFIER_MSG = 3,
        /// Indicate that a buffer was used from the vring.
        VRING_CALL = 4,
        /// Indicate that an error occurred on the specific vring.
        VRING_ERR = 5,
        /// Virtio-fs draft: map file content into the window.
        FS_MAP = 6,
        /// Virtio-fs draft: unmap file content from the window.
        FS_UNMAP = 7,
        /// Virtio-fs draft: sync file content.
        FS_SYNC = 8,
        /// Virtio-fs draft: perform a read/write from an fd directly to GPA.
        FS_IO = 9,
    }
}

impl Req for BackendReq {}

/// Vhost message Validator.
pub trait VhostUserMsgValidator: ByteValued {
    /// Validate message syntax only.
    /// It doesn't validate message semantics such as protocol version number and dependency
    /// on feature flags etc.
    fn is_valid(&self) -> bool {
        true
    }
}

// Bit mask for common message flags.
bitflags! {
    /// Common message flags for vhost-user requests and replies.
    pub struct VhostUserHeaderFlag: u32 {
        /// Bits[0..2] is message version number.
        const VERSION = 0x3;
        /// Mark message as reply.
        const REPLY = 0x4;
        /// Sender anticipates a reply message from the peer.
        const NEED_REPLY = 0x8;
        /// All valid bits.
        const ALL_FLAGS = 0xc;
        /// All reserved bits.
        const RESERVED_BITS = !0xf;
    }
}

/// Common message header for vhost-user requests and replies.
/// A vhost-user message consists of 3 header fields and an optional payload. All numbers are in the
/// machine native byte order.
#[repr(C, packed)]
#[derive(Copy)]
pub(super) struct VhostUserMsgHeader<R: Req> {
    request: u32,
    flags: u32,
    size: u32,
    _r: PhantomData<R>,
}

impl<R: Req> Debug for VhostUserMsgHeader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostUserMsgHeader")
            .field("request", &{ self.request })
            .field("flags", &{ self.flags })
            .field("size", &{ self.size })
            .finish()
    }
}

impl<R: Req> Clone for VhostUserMsgHeader<R> {
    fn clone(&self) -> VhostUserMsgHeader<R> {
        *self
    }
}

impl<R: Req> PartialEq for VhostUserMsgHeader<R> {
    fn eq(&self, other: &Self) -> bool {
        self.request == other.request && self.flags == other.flags && self.size == other.size
    }
}

impl<R: Req> VhostUserMsgHeader<R> {
    /// Create a new instance of `VhostUserMsgHeader`.
    pub fn new(request: R, flags: u32, size: u32) -> Self {
        // Default to protocol version 1
        let fl = (flags & VhostUserHeaderFlag::ALL_FLAGS.bits()) | 0x1;
        VhostUserMsgHeader {
            request: request.into(),
            flags: fl,
            size,
            _r: PhantomData,
        }
    }

    /// Get message type.
    pub fn get_code(&self) -> Result<R> {
        R::try_from(self.request).map_err(|_| Error::InvalidMessage)
    }

    /// Set message type.
    pub fn set_code(&mut self, request: R) {
        self.request = request.into();
    }

    /// Get message version number.
    pub fn get_version(&self) -> u32 {
        self.flags & 0x3
    }

    /// Set message version number.
    pub fn set_version(&mut self, ver: u32) {
        self.flags &= !0x3;
        self.flags |= ver & 0x3;
    }

    /// Check whether it's a reply message.
    pub fn is_reply(&self) -> bool {
        (self.flags & VhostUserHeaderFlag::REPLY.bits()) != 0
    }

    /// Mark message as reply.
    pub fn set_reply(&mut self, is_reply: bool) {
        if is_reply {
            self.flags |= VhostUserHeaderFlag::REPLY.bits();
        } else {
            self.flags &= !VhostUserHeaderFlag::REPLY.bits();
        }
    }

    /// Check whether reply for this message is requested.
    pub fn is_need_reply(&self) -> bool {
        (self.flags & VhostUserHeaderFlag::NEED_REPLY.bits()) != 0
    }

    /// Mark that reply for this message is needed.
    pub fn set_need_reply(&mut self, need_reply: bool) {
        if need_reply {
            self.flags |= VhostUserHeaderFlag::NEED_REPLY.bits();
        } else {
            self.flags &= !VhostUserHeaderFlag::NEED_REPLY.bits();
        }
    }

    /// Check whether it's the reply message for the request `req`.
    pub fn is_reply_for(&self, req: &VhostUserMsgHeader<R>) -> bool {
        if let (Ok(code1), Ok(code2)) = (self.get_code(), req.get_code()) {
            self.is_reply() && !req.is_reply() && code1 == code2
        } else {
            false
        }
    }

    /// Get message size.
    pub fn get_size(&self) -> u32 {
        self.size
    }

    /// Set message size.
    pub fn set_size(&mut self, size: u32) {
        self.size = size;
    }
}

impl<R: Req> Default for VhostUserMsgHeader<R> {
    fn default() -> Self {
        VhostUserMsgHeader {
            request: 0,
            flags: 0x1,
            size: 0,
            _r: PhantomData,
        }
    }
}

// SAFETY: Safe because all fields of VhostUserMsgHeader are POD.
unsafe impl<R: Req> ByteValued for VhostUserMsgHeader<R> {}

impl<T: Req> VhostUserMsgValidator for VhostUserMsgHeader<T> {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        if self.get_code().is_err() {
            return false;
        } else if self.size as usize > MAX_MSG_SIZE {
            return false;
        } else if self.get_version() != 0x1 {
            return false;
        } else if (self.flags & VhostUserHeaderFlag::RESERVED_BITS.bits()) != 0 {
            return false;
        }
        true
    }
}

// Bit mask for transport specific flags in VirtIO feature set defined by vhost-user.
bitflags! {
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    /// Transport specific flags in VirtIO feature set defined by vhost-user.
    pub struct VhostUserVirtioFeatures: u64 {
        /// Log dirtied shared memory pages.
        const LOG_ALL = 0x400_0000;
        /// Feature flag for the protocol feature.
        const PROTOCOL_FEATURES = 0x4000_0000;
    }
}

// Bit mask for vhost-user protocol feature flags.
bitflags! {
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    /// Vhost-user protocol feature flags.
    pub struct VhostUserProtocolFeatures: u64 {
        /// Support multiple queues.
        const MQ = 0x0000_0001;
        /// Support logging through shared memory fd.
        const LOG_SHMFD = 0x0000_0002;
        /// Support broadcasting fake RARP packet.
        const RARP = 0x0000_0004;
        /// Support sending reply messages for requests with NEED_REPLY flag set.
        const REPLY_ACK = 0x0000_0008;
        /// Support setting MTU for virtio-net devices.
        const MTU = 0x0000_0010;
        /// Allow the backend to send requests to the frontend by an optional communication channel.
        const BACKEND_REQ = 0x0000_0020;
        /// Support setting backend endian by SET_VRING_ENDIAN.
        const CROSS_ENDIAN = 0x0000_0040;
        /// Support crypto operations.
        const CRYPTO_SESSION = 0x0000_0080;
        /// Support sending userfault_fd from backends to frontends.
        const PAGEFAULT = 0x0000_0100;
        /// Support Virtio device configuration.
        const CONFIG = 0x0000_0200;
        /// Allow the backend to send fds (at most 8 descriptors in each message) to the frontend.
        const BACKEND_SEND_FD = 0x0000_0400;
        /// Allow the backend to register a host notifier.
        const HOST_NOTIFIER = 0x0000_0800;
        /// Support inflight shmfd.
        const INFLIGHT_SHMFD = 0x0000_1000;
        /// Support resetting the device.
        const RESET_DEVICE = 0x0000_2000;
        /// Support inband notifications.
        const INBAND_NOTIFICATIONS = 0x0000_4000;
        /// Support configuring memory slots.
        const CONFIGURE_MEM_SLOTS = 0x0000_8000;
        /// Support reporting status.
        const STATUS = 0x0001_0000;
        /// Support Xen mmap.
        const XEN_MMAP = 0x0002_0000;
        /// Support transferring internal device state.
        const DEVICE_STATE = 0x0008_0000;
    }
}

/// An empty message.
#[derive(Copy, Clone, Default)]
pub struct VhostUserEmpty;

// SAFETY: Safe because type is zero size.
unsafe impl ByteValued for VhostUserEmpty {}

impl VhostUserMsgValidator for VhostUserEmpty {}

/// A generic message to encapsulate a 64-bit value.
#[repr(transparent)]
#[derive(Copy, Clone, Default)]
pub struct VhostUserU64 {
    /// The encapsulated 64-bit common value.
    pub value: u64,
}

impl VhostUserU64 {
    /// Create a new instance.
    pub fn new(value: u64) -> Self {
        VhostUserU64 { value }
    }
}

// SAFETY: Safe because all fields of VhostUserU64 are POD.
unsafe impl ByteValued for VhostUserU64 {}

impl VhostUserMsgValidator for VhostUserU64 {}

/// Memory region descriptor for the SET_MEM_TABLE request.
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct VhostUserMemory {
    /// Number of memory regions in the payload.
    pub num_regions: u32,
    /// Padding for alignment.
    pub padding1: u32,
}

impl VhostUserMemory {
    /// Create a new instance.
    pub fn new(cnt: u32) -> Self {
        VhostUserMemory {
            num_regions: cnt,
            padding1: 0,
        }
    }
}

// SAFETY: Safe because all fields of VhostUserMemory are POD.
unsafe impl ByteValued for VhostUserMemory {}

impl VhostUserMsgValidator for VhostUserMemory {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        if self.padding1 != 0 {
            return false;
        } else if self.num_regions == 0 || self.num_regions > MAX_ATTACHED_FD_ENTRIES as u32 {
            return false;
        }
        true
    }
}

/// Memory region descriptors as payload for the SET_MEM_TABLE request.
#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
pub struct VhostUserMemoryRegion {
    /// Guest physical address of the memory region.
    pub guest_phys_addr: u64,
    /// Size of the memory region.
    pub memory_size: u64,
    /// Virtual address in the current process.
    pub user_addr: u64,
    /// Offset where region starts in the mapped memory.
    pub mmap_offset: u64,

    #[cfg(feature = "xen")]
    /// Xen specific flags.
    pub xen_mmap_flags: u32,

    #[cfg(feature = "xen")]
    /// Xen specific data.
    pub xen_mmap_data: u32,
}

impl VhostUserMemoryRegion {
    fn is_valid_common(&self) -> bool {
        self.memory_size != 0
            && self.guest_phys_addr.checked_add(self.memory_size).is_some()
            && self.user_addr.checked_add(self.memory_size).is_some()
            && self.mmap_offset.checked_add(self.memory_size).is_some()
    }
}

#[cfg(not(feature = "xen"))]
impl VhostUserMemoryRegion {
    /// Create a new instance.
    pub fn new(guest_phys_addr: u64, memory_size: u64, user_addr: u64, mmap_offset: u64) -> Self {
        VhostUserMemoryRegion {
            guest_phys_addr,
            memory_size,
            user_addr,
            mmap_offset,
        }
    }

    /// Creates mmap region from Self.
    pub fn mmap_region<B: NewBitmap>(&self, file: File) -> Result<MmapRegion<B>> {
        MmapRegion::<B>::from_file(
            FileOffset::new(file, self.mmap_offset),
            self.memory_size as usize,
        )
        .map_err(MmapError::MmapRegion)
        .map_err(|e| Error::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e)))
    }

    fn is_valid(&self) -> bool {
        self.is_valid_common()
    }
}

#[cfg(feature = "xen")]
impl VhostUserMemoryRegion {
    /// Create a new instance.
    pub fn with_xen(
        guest_phys_addr: u64,
        memory_size: u64,
        user_addr: u64,
        mmap_offset: u64,
        xen_mmap_flags: u32,
        xen_mmap_data: u32,
    ) -> Self {
        VhostUserMemoryRegion {
            guest_phys_addr,
            memory_size,
            user_addr,
            mmap_offset,
            xen_mmap_flags,
            xen_mmap_data,
        }
    }

    /// Creates mmap region from Self.
    pub fn mmap_region<B: NewBitmap>(&self, file: File) -> Result<MmapRegion<B>> {
        let range = MmapRange::new(
            self.memory_size as usize,
            Some(FileOffset::new(file, self.mmap_offset)),
            GuestAddress(self.guest_phys_addr),
            self.xen_mmap_flags,
            self.xen_mmap_data,
        );

        MmapRegion::<B>::from_range(range)
            .map_err(MmapError::MmapRegion)
            .map_err(|e| Error::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e)))
    }

    fn is_valid(&self) -> bool {
        if !self.is_valid_common() {
            false
        } else {
            // Only of one of FOREIGN or GRANT should be set.
            match MmapXenFlags::from_bits(self.xen_mmap_flags) {
                Some(flags) => flags.is_valid(),
                None => false,
            }
        }
    }
}

// SAFETY: Safe because all fields of VhostUserMemoryRegion are POD.
unsafe impl ByteValued for VhostUserMemoryRegion {}

impl VhostUserMsgValidator for VhostUserMemoryRegion {
    fn is_valid(&self) -> bool {
        self.is_valid()
    }
}

/// Payload of the VhostUserMemory message.
pub type VhostUserMemoryPayload = Vec<VhostUserMemoryRegion>;

/// Single memory region descriptor as payload for ADD_MEM_REG and REM_MEM_REG
/// requests.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VhostUserSingleMemoryRegion {
    /// Padding for correct alignment
    padding: u64,
    /// General memory region
    region: VhostUserMemoryRegion,
}

impl Deref for VhostUserSingleMemoryRegion {
    type Target = VhostUserMemoryRegion;

    fn deref(&self) -> &VhostUserMemoryRegion {
        &self.region
    }
}

#[cfg(not(feature = "xen"))]
impl VhostUserSingleMemoryRegion {
    /// Create a new instance.
    pub fn new(guest_phys_addr: u64, memory_size: u64, user_addr: u64, mmap_offset: u64) -> Self {
        VhostUserSingleMemoryRegion {
            padding: 0,
            region: VhostUserMemoryRegion::new(
                guest_phys_addr,
                memory_size,
                user_addr,
                mmap_offset,
            ),
        }
    }
}

#[cfg(feature = "xen")]
impl VhostUserSingleMemoryRegion {
    /// Create a new instance.
    pub fn new(
        guest_phys_addr: u64,
        memory_size: u64,
        user_addr: u64,
        mmap_offset: u64,
        xen_mmap_flags: u32,
        xen_mmap_data: u32,
    ) -> Self {
        VhostUserSingleMemoryRegion {
            padding: 0,
            region: VhostUserMemoryRegion::with_xen(
                guest_phys_addr,
                memory_size,
                user_addr,
                mmap_offset,
                xen_mmap_flags,
                xen_mmap_data,
            ),
        }
    }
}

// SAFETY: Safe because all fields of VhostUserSingleMemoryRegion are POD.
unsafe impl ByteValued for VhostUserSingleMemoryRegion {}
impl VhostUserMsgValidator for VhostUserSingleMemoryRegion {}

/// Vring state descriptor.
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct VhostUserVringState {
    /// Vring index.
    pub index: u32,
    /// A common 32bit value to encapsulate vring state etc.
    pub num: u32,
}

impl VhostUserVringState {
    /// Create a new instance.
    pub fn new(index: u32, num: u32) -> Self {
        VhostUserVringState { index, num }
    }
}

// SAFETY: Safe because all fields of VhostUserVringState are POD.
unsafe impl ByteValued for VhostUserVringState {}

impl VhostUserMsgValidator for VhostUserVringState {}

// Bit mask for vring address flags.
bitflags! {
    /// Flags for vring address.
    pub struct VhostUserVringAddrFlags: u32 {
        /// Support log of vring operations.
        /// Modifications to "used" vring should be logged.
        const VHOST_VRING_F_LOG = 0x1;
    }
}

/// Vring address descriptor.
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct VhostUserVringAddr {
    /// Vring index.
    pub index: u32,
    /// Vring flags defined by VhostUserVringAddrFlags.
    pub flags: u32,
    /// Ring address of the vring descriptor table.
    pub descriptor: u64,
    /// Ring address of the vring used ring.
    pub used: u64,
    /// Ring address of the vring available ring.
    pub available: u64,
    /// Guest address for logging.
    pub log: u64,
}

impl VhostUserVringAddr {
    /// Create a new instance.
    pub fn new(
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Self {
        VhostUserVringAddr {
            index,
            flags: flags.bits(),
            descriptor,
            used,
            available,
            log,
        }
    }

    /// Create a new instance from `VringConfigData`.
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::useless_conversion))]
    pub fn from_config_data(index: u32, config_data: &VringConfigData) -> Self {
        let log_addr = config_data.log_addr.unwrap_or(0);
        VhostUserVringAddr {
            index,
            flags: config_data.flags,
            descriptor: config_data.desc_table_addr,
            used: config_data.used_ring_addr,
            available: config_data.avail_ring_addr,
            log: log_addr,
        }
    }
}

// SAFETY: Safe because all fields of VhostUserVringAddr are POD.
unsafe impl ByteValued for VhostUserVringAddr {}

impl VhostUserMsgValidator for VhostUserVringAddr {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        if (self.flags & !VhostUserVringAddrFlags::all().bits()) != 0 {
            return false;
        } else if self.descriptor & 0xf != 0 {
            return false;
        } else if self.available & 0x1 != 0 {
            return false;
        } else if self.used & 0x3 != 0 {
            return false;
        }
        true
    }
}

// Bit mask for the vhost-user device configuration message.
bitflags! {
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    /// Flags for the device configuration message.
    pub struct VhostUserConfigFlags: u32 {
        /// Vhost frontend messages used for writeable fields.
        const WRITABLE = 0x1;
        /// Vhost frontend messages used for live migration.
        const LIVE_MIGRATION = 0x2;
    }
}

/// Message to read/write device configuration space.
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct VhostUserConfig {
    /// Offset of virtio device's configuration space.
    pub offset: u32,
    /// Configuration space access size in bytes.
    pub size: u32,
    /// Flags for the device configuration operation.
    pub flags: u32,
}

impl VhostUserConfig {
    /// Create a new instance.
    pub fn new(offset: u32, size: u32, flags: VhostUserConfigFlags) -> Self {
        VhostUserConfig {
            offset,
            size,
            flags: flags.bits(),
        }
    }
}

// SAFETY: Safe because all fields of VhostUserConfig are POD.
unsafe impl ByteValued for VhostUserConfig {}

impl VhostUserMsgValidator for VhostUserConfig {
    #[allow(clippy::if_same_then_else)]
    fn is_valid(&self) -> bool {
        let end_addr = match self.size.checked_add(self.offset) {
            Some(addr) => addr,
            None => return false,
        };
        if (self.flags & !VhostUserConfigFlags::all().bits()) != 0 {
            return false;
        } else if self.size == 0 || end_addr > VHOST_USER_CONFIG_SIZE {
            return false;
        }
        true
    }
}

/// Payload for the VhostUserConfig message.
pub type VhostUserConfigPayload = Vec<u8>;

/// Single memory region descriptor as payload for ADD_MEM_REG and REM_MEM_REG
/// requests.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct VhostUserInflight {
    /// Size of the area to track inflight I/O.
    pub mmap_size: u64,
    /// Offset of this area from the start of the supplied file descriptor.
    pub mmap_offset: u64,
    /// Number of virtqueues.
    pub num_queues: u16,
    /// Size of virtqueues.
    pub queue_size: u16,
}

impl VhostUserInflight {
    /// Create a new instance.
    pub fn new(mmap_size: u64, mmap_offset: u64, num_queues: u16, queue_size: u16) -> Self {
        VhostUserInflight {
            mmap_size,
            mmap_offset,
            num_queues,
            queue_size,
        }
    }
}

// SAFETY: Safe because all fields of VhostUserInflight are POD.
unsafe impl ByteValued for VhostUserInflight {}

impl VhostUserMsgValidator for VhostUserInflight {
    fn is_valid(&self) -> bool {
        if self.num_queues == 0 || self.queue_size == 0 {
            return false;
        }
        true
    }
}

/// Single memory region descriptor as payload for SET_LOG_BASE request.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct VhostUserLog {
    /// Size of the area to log dirty pages.
    pub mmap_size: u64,
    /// Offset of this area from the start of the supplied file descriptor.
    pub mmap_offset: u64,
}

impl VhostUserLog {
    /// Create a new instance.
    pub fn new(mmap_size: u64, mmap_offset: u64) -> Self {
        VhostUserLog {
            mmap_size,
            mmap_offset,
        }
    }
}

// SAFETY: Safe because all fields of VhostUserLog are POD.
unsafe impl ByteValued for VhostUserLog {}

impl VhostUserMsgValidator for VhostUserLog {
    fn is_valid(&self) -> bool {
        if self.mmap_size == 0 || self.mmap_offset.checked_add(self.mmap_size).is_none() {
            return false;
        }
        true
    }
}

enum_value! {
    /// Direction of state transfer for migration
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum VhostTransferStateDirection: u32 {
        /// Outgoing migration: Transfer state from back-end to front-end
        SAVE = 0,
        /// Incoming migration: Transfer state from front-end to back-end
        LOAD = 1,
    }
}

enum_value! {
    /// Migration phases during which state transfer can occur
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum VhostTransferStatePhase: u32 {
        /// The device (and all its vrings) are stopped
        STOPPED = 0,
    }
}

/// Query/send virtio-fs migration state
// Note: this struct is not defined as `packed` in the SPEC and although
// it is not necessary, since the struct has no padding, it simplifies
// reviewing it because it is a requirement for implementing `ByteValued`.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct VhostUserTransferDeviceState {
    /// Direction of state transfer (save/load)
    pub direction: u32,
    /// Migration phase during which the transfer takes place
    pub phase: u32,
}

// SAFETY: Safe because VhostUserTransferDeviceState is a POD
// (i.e., none of its fields are references or raw pointers),
// and there is no compiler-inserted padding.
unsafe impl ByteValued for VhostUserTransferDeviceState {}

impl VhostUserTransferDeviceState {
    /// Create a new instance.
    pub fn new(direction: VhostTransferStateDirection, phase: VhostTransferStatePhase) -> Self {
        VhostUserTransferDeviceState {
            direction: direction as u32,
            phase: phase as u32,
        }
    }
}

impl VhostUserMsgValidator for VhostUserTransferDeviceState {
    fn is_valid(&self) -> bool {
        VhostTransferStateDirection::try_from(self.direction).is_ok()
            && VhostTransferStatePhase::try_from(self.phase).is_ok()
    }
}

// Bit mask for flags in virtio-fs backend messages
bitflags! {
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    /// Flags for virtio-fs backend messages.
    pub struct VhostUserFSBackendMsgFlags: u64 {
        /// Empty permission.
        const EMPTY = 0x0;
        /// Read permission.
        const MAP_R = 0x1;
        /// Write permission.
        const MAP_W = 0x2;
    }
}

/// Max entries in one virtio-fs backend request.
pub const VHOST_USER_FS_BACKEND_ENTRIES: usize = 8;

/// Backend request message to update the MMIO window.
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct VhostUserFSBackendMsg {
    /// File offset.
    pub fd_offset: [u64; VHOST_USER_FS_BACKEND_ENTRIES],
    /// Offset into the DAX window.
    pub cache_offset: [u64; VHOST_USER_FS_BACKEND_ENTRIES],
    /// Size of region to map.
    pub len: [u64; VHOST_USER_FS_BACKEND_ENTRIES],
    /// Flags for the mmap operation
    pub flags: [VhostUserFSBackendMsgFlags; VHOST_USER_FS_BACKEND_ENTRIES],
}

// SAFETY: Safe because all fields of VhostUserFSBackendMsg are POD.
unsafe impl ByteValued for VhostUserFSBackendMsg {}

impl VhostUserMsgValidator for VhostUserFSBackendMsg {
    fn is_valid(&self) -> bool {
        for i in 0..VHOST_USER_FS_BACKEND_ENTRIES {
            if ({ self.flags[i] }.bits() & !VhostUserFSBackendMsgFlags::all().bits()) != 0
                || self.fd_offset[i].checked_add(self.len[i]).is_none()
                || self.cache_offset[i].checked_add(self.len[i]).is_none()
            {
                return false;
            }
        }
        true
    }
}

/// Inflight I/O descriptor state for split virtqueues
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct DescStateSplit {
    /// Indicate whether this descriptor (only head) is inflight or not.
    pub inflight: u8,
    /// Padding
    padding: [u8; 5],
    /// List of last batch of used descriptors, only when batching is used for submitting
    pub next: u16,
    /// Preserve order of fetching available descriptors, only for head descriptor
    pub counter: u64,
}

impl DescStateSplit {
    /// New instance of DescStateSplit struct
    pub fn new() -> Self {
        Self::default()
    }
}

/// Inflight I/O queue region for split virtqueues
#[repr(C, packed)]
pub struct QueueRegionSplit {
    /// Features flags of this region
    pub features: u64,
    /// Version of this region
    pub version: u16,
    /// Number of DescStateSplit entries
    pub desc_num: u16,
    /// List to track last batch of used descriptors
    pub last_batch_head: u16,
    /// Idx value of used ring
    pub used_idx: u16,
    /// Pointer to an array of DescStateSplit entries
    pub desc: u64,
}

impl QueueRegionSplit {
    /// New instance of QueueRegionSplit struct
    pub fn new(features: u64, queue_size: u16) -> Self {
        QueueRegionSplit {
            features,
            version: 1,
            desc_num: queue_size,
            last_batch_head: 0,
            used_idx: 0,
            desc: 0,
        }
    }
}

/// Inflight I/O descriptor state for packed virtqueues
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct DescStatePacked {
    /// Indicate whether this descriptor (only head) is inflight or not.
    pub inflight: u8,
    /// Padding
    padding: u8,
    /// Link to next free entry
    pub next: u16,
    /// Link to last entry of descriptor list, only for head
    pub last: u16,
    /// Length of descriptor list, only for head
    pub num: u16,
    /// Preserve order of fetching avail descriptors, only for head
    pub counter: u64,
    /// Buffer ID
    pub id: u16,
    /// Descriptor flags
    pub flags: u16,
    /// Buffer length
    pub len: u32,
    /// Buffer address
    pub addr: u64,
}

impl DescStatePacked {
    /// New instance of DescStatePacked struct
    pub fn new() -> Self {
        Self::default()
    }
}

/// Inflight I/O queue region for packed virtqueues
#[repr(C, packed)]
pub struct QueueRegionPacked {
    /// Features flags of this region
    pub features: u64,
    /// version of this region
    pub version: u16,
    /// size of descriptor state array
    pub desc_num: u16,
    /// head of free DescStatePacked entry list
    pub free_head: u16,
    /// old head of free DescStatePacked entry list
    pub old_free_head: u16,
    /// used idx of descriptor ring
    pub used_idx: u16,
    /// old used idx of descriptor ring
    pub old_used_idx: u16,
    /// device ring wrap counter
    pub used_wrap_counter: u8,
    /// old device ring wrap counter
    pub old_used_wrap_counter: u8,
    /// Padding
    padding: [u8; 7],
    /// Pointer to array tracking state of each descriptor from descriptor ring
    pub desc: u64,
}

impl QueueRegionPacked {
    /// New instance of QueueRegionPacked struct
    pub fn new(features: u64, queue_size: u16) -> Self {
        QueueRegionPacked {
            features,
            version: 1,
            desc_num: queue_size,
            free_head: 0,
            old_free_head: 0,
            used_idx: 0,
            old_used_idx: 0,
            used_wrap_counter: 0,
            old_used_wrap_counter: 0,
            padding: [0; 7],
            desc: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[cfg(feature = "xen")]
    impl VhostUserMemoryRegion {
        fn new(guest_phys_addr: u64, memory_size: u64, user_addr: u64, mmap_offset: u64) -> Self {
            Self::with_xen(
                guest_phys_addr,
                memory_size,
                user_addr,
                mmap_offset,
                MmapXenFlags::FOREIGN.bits(),
                0,
            )
        }
    }

    #[test]
    fn check_transfer_state_direction_code() {
        let load_code: u32 = VhostTransferStateDirection::LOAD.into();
        assert!(VhostTransferStateDirection::try_from(load_code).is_ok());
        assert_eq!(load_code, load_code.clone());

        let save_code: u32 = VhostTransferStateDirection::SAVE.into();
        assert!(VhostTransferStateDirection::try_from(save_code).is_ok());
        assert_eq!(save_code, save_code.clone());

        assert!(VhostTransferStateDirection::try_from(3).is_err());
    }

    #[test]
    fn check_transfer_state_phase_code() {
        let code: u32 = VhostTransferStatePhase::STOPPED.into();
        assert!(VhostTransferStatePhase::try_from(code).is_ok());
        assert_eq!(code, code.clone());

        assert!(VhostTransferStatePhase::try_from(1).is_err());
    }

    #[test]
    fn check_frontend_request_code() {
        let code: u32 = FrontendReq::GET_FEATURES.into();
        assert!(FrontendReq::try_from(code).is_ok());
        assert_eq!(code, code.clone());
        assert!(FrontendReq::try_from(10000).is_err());
    }

    #[test]
    fn check_backend_request_code() {
        let code: u32 = BackendReq::CONFIG_CHANGE_MSG.into();
        assert!(BackendReq::try_from(code).is_ok());
        assert_eq!(code, code.clone());
        assert!(BackendReq::try_from(10000).is_err());
    }

    #[test]
    fn msg_header_ops() {
        let mut hdr = VhostUserMsgHeader::new(FrontendReq::GET_FEATURES, 0, 0x100);
        assert_eq!(hdr.get_code().unwrap(), FrontendReq::GET_FEATURES);
        hdr.set_code(FrontendReq::SET_FEATURES);
        assert_eq!(hdr.get_code().unwrap(), FrontendReq::SET_FEATURES);

        assert_eq!(hdr.get_version(), 0x1);

        assert!(!hdr.is_reply());
        hdr.set_reply(true);
        assert!(hdr.is_reply());
        hdr.set_reply(false);

        assert!(!hdr.is_need_reply());
        hdr.set_need_reply(true);
        assert!(hdr.is_need_reply());
        hdr.set_need_reply(false);

        assert_eq!(hdr.get_size(), 0x100);
        hdr.set_size(0x200);
        assert_eq!(hdr.get_size(), 0x200);

        assert!(!hdr.is_need_reply());
        assert!(!hdr.is_reply());
        assert_eq!(hdr.get_version(), 0x1);

        // Check message length
        assert!(hdr.is_valid());
        hdr.set_size(0x2000);
        assert!(!hdr.is_valid());
        hdr.set_size(0x100);
        assert_eq!(hdr.get_size(), 0x100);
        assert!(hdr.is_valid());
        hdr.set_size((MAX_MSG_SIZE - mem::size_of::<VhostUserMsgHeader<FrontendReq>>()) as u32);
        assert!(hdr.is_valid());
        hdr.set_size(0x0);
        assert!(hdr.is_valid());

        // Check version
        hdr.set_version(0x0);
        assert!(!hdr.is_valid());
        hdr.set_version(0x2);
        assert!(!hdr.is_valid());
        hdr.set_version(0x1);
        assert!(hdr.is_valid());

        // Test Debug, Clone, PartiaEq trait
        assert_eq!(hdr, hdr.clone());
        assert_eq!(hdr.clone().get_code().unwrap(), hdr.get_code().unwrap());
        assert_eq!(format!("{:?}", hdr.clone()), format!("{:?}", hdr));
    }

    #[test]
    fn test_vhost_user_message_u64() {
        let val = VhostUserU64::default();
        let val1 = VhostUserU64::new(0);

        let a = val.value;
        let b = val1.value;
        assert_eq!(a, b);
        let a = VhostUserU64::new(1).value;
        assert_eq!(a, 1);
    }

    #[test]
    fn check_user_memory() {
        let mut msg = VhostUserMemory::new(1);
        assert!(msg.is_valid());
        msg.num_regions = MAX_ATTACHED_FD_ENTRIES as u32;
        assert!(msg.is_valid());

        msg.num_regions += 1;
        assert!(!msg.is_valid());
        msg.num_regions = 0xFFFFFFFF;
        assert!(!msg.is_valid());
        msg.num_regions = MAX_ATTACHED_FD_ENTRIES as u32;
        msg.padding1 = 1;
        assert!(!msg.is_valid());
    }

    #[test]
    fn check_user_memory_region() {
        let mut msg = VhostUserMemoryRegion::new(0, 0x1000, 0, 0);
        assert!(msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFFEFFF;
        assert!(msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFFF000;
        assert!(!msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFF0000;
        msg.memory_size = 0;
        assert!(!msg.is_valid());
        let a = msg.guest_phys_addr;
        let b = msg.guest_phys_addr;
        assert_eq!(a, b);

        let msg = VhostUserMemoryRegion::default();
        let a = msg.guest_phys_addr;
        assert_eq!(a, 0);
        let a = msg.memory_size;
        assert_eq!(a, 0);
        let a = msg.user_addr;
        assert_eq!(a, 0);
        let a = msg.mmap_offset;
        assert_eq!(a, 0);
    }

    #[test]
    fn test_vhost_user_state() {
        let state = VhostUserVringState::new(5, 8);

        let a = state.index;
        assert_eq!(a, 5);
        let a = state.num;
        assert_eq!(a, 8);
        assert!(state.is_valid());

        let state = VhostUserVringState::default();
        let a = state.index;
        assert_eq!(a, 0);
        let a = state.num;
        assert_eq!(a, 0);
        assert!(state.is_valid());
    }

    #[test]
    fn test_vhost_user_addr() {
        let mut addr = VhostUserVringAddr::new(
            2,
            VhostUserVringAddrFlags::VHOST_VRING_F_LOG,
            0x1000,
            0x2000,
            0x3000,
            0x4000,
        );

        let a = addr.index;
        assert_eq!(a, 2);
        let a = addr.flags;
        assert_eq!(a, VhostUserVringAddrFlags::VHOST_VRING_F_LOG.bits());
        let a = addr.descriptor;
        assert_eq!(a, 0x1000);
        let a = addr.used;
        assert_eq!(a, 0x2000);
        let a = addr.available;
        assert_eq!(a, 0x3000);
        let a = addr.log;
        assert_eq!(a, 0x4000);
        assert!(addr.is_valid());

        addr.descriptor = 0x1001;
        assert!(!addr.is_valid());
        addr.descriptor = 0x1000;

        addr.available = 0x3001;
        assert!(!addr.is_valid());
        addr.available = 0x3000;

        addr.used = 0x2001;
        assert!(!addr.is_valid());
        addr.used = 0x2000;
        assert!(addr.is_valid());
    }

    #[test]
    fn test_vhost_user_state_from_config() {
        let config = VringConfigData {
            queue_max_size: 256,
            queue_size: 128,
            flags: VhostUserVringAddrFlags::VHOST_VRING_F_LOG.bits(),
            desc_table_addr: 0x1000,
            used_ring_addr: 0x2000,
            avail_ring_addr: 0x3000,
            log_addr: Some(0x4000),
        };
        let addr = VhostUserVringAddr::from_config_data(2, &config);

        let a = addr.index;
        assert_eq!(a, 2);
        let a = addr.flags;
        assert_eq!(a, VhostUserVringAddrFlags::VHOST_VRING_F_LOG.bits());
        let a = addr.descriptor;
        assert_eq!(a, 0x1000);
        let a = addr.used;
        assert_eq!(a, 0x2000);
        let a = addr.available;
        assert_eq!(a, 0x3000);
        let a = addr.log;
        assert_eq!(a, 0x4000);
        assert!(addr.is_valid());
    }

    #[test]
    fn check_user_vring_addr() {
        let mut msg =
            VhostUserVringAddr::new(0, VhostUserVringAddrFlags::all(), 0x0, 0x0, 0x0, 0x0);
        assert!(msg.is_valid());

        msg.descriptor = 1;
        assert!(!msg.is_valid());
        msg.descriptor = 0;

        msg.available = 1;
        assert!(!msg.is_valid());
        msg.available = 0;

        msg.used = 1;
        assert!(!msg.is_valid());
        msg.used = 0;

        msg.flags |= 0x80000000;
        assert!(!msg.is_valid());
        msg.flags &= !0x80000000;
    }

    #[test]
    fn check_user_config_msg() {
        let mut msg =
            VhostUserConfig::new(0, VHOST_USER_CONFIG_SIZE, VhostUserConfigFlags::WRITABLE);

        assert!(msg.is_valid());
        msg.size = 0;
        assert!(!msg.is_valid());
        msg.size = 1;
        assert!(msg.is_valid());
        msg.offset = u32::MAX;
        assert!(!msg.is_valid());
        msg.offset = VHOST_USER_CONFIG_SIZE;
        assert!(!msg.is_valid());
        msg.offset = VHOST_USER_CONFIG_SIZE - 1;
        assert!(msg.is_valid());
        msg.size = 2;
        assert!(!msg.is_valid());
        msg.size = 1;
        msg.flags |= VhostUserConfigFlags::LIVE_MIGRATION.bits();
        assert!(msg.is_valid());
        msg.flags |= 0x4;
        assert!(!msg.is_valid());
    }

    #[test]
    fn test_vhost_user_fs_backend() {
        let mut fs_backend = VhostUserFSBackendMsg::default();

        assert!(fs_backend.is_valid());

        fs_backend.fd_offset[0] = 0xffff_ffff_ffff_ffff;
        fs_backend.len[0] = 0x1;
        assert!(!fs_backend.is_valid());

        assert_ne!(
            VhostUserFSBackendMsgFlags::MAP_R,
            VhostUserFSBackendMsgFlags::MAP_W
        );
        assert_eq!(VhostUserFSBackendMsgFlags::EMPTY.bits(), 0);
    }
}
