// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2021 Alibaba Cloud Computing. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Struct to maintain state information and manipulate vhost-user queues.

use std::fs::File;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::result::Result;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use virtio_queue::{Error as VirtQueError, Queue, QueueT};
use vm_memory::{GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

/// Trait for objects returned by `VringT::get_ref()`.
pub trait VringStateGuard<'a, M: GuestAddressSpace> {
    /// Type for guard returned by `VringT::get_ref()`.
    type G: Deref<Target = VringState<M>>;
}

/// Trait for objects returned by `VringT::get_mut()`.
pub trait VringStateMutGuard<'a, M: GuestAddressSpace> {
    /// Type for guard returned by `VringT::get_mut()`.
    type G: DerefMut<Target = VringState<M>>;
}

pub trait VringT<M: GuestAddressSpace>:
    for<'a> VringStateGuard<'a, M> + for<'a> VringStateMutGuard<'a, M>
{
    /// Create a new instance of Vring.
    fn new(mem: M, max_queue_size: u16) -> Result<Self, VirtQueError>
    where
        Self: Sized;

    /// Get an immutable reference to the kick event fd.
    fn get_ref(&self) -> <Self as VringStateGuard<M>>::G;

    /// Get a mutable reference to the kick event fd.
    fn get_mut(&self) -> <Self as VringStateMutGuard<M>>::G;

    /// Add an used descriptor into the used queue.
    fn add_used(&self, desc_index: u16, len: u32) -> Result<(), VirtQueError>;

    /// Notify the vhost-user master that used descriptors have been put into the used queue.
    fn signal_used_queue(&self) -> io::Result<()>;

    /// Enable event notification for queue.
    fn enable_notification(&self) -> Result<bool, VirtQueError>;

    /// Disable event notification for queue.
    fn disable_notification(&self) -> Result<(), VirtQueError>;

    /// Check whether a notification to the guest is needed.
    fn needs_notification(&self) -> Result<bool, VirtQueError>;

    /// Set vring enabled state.
    fn set_enabled(&self, enabled: bool);

    /// Set queue addresses for descriptor table, available ring and used ring.
    fn set_queue_info(
        &self,
        desc_table: u64,
        avail_ring: u64,
        used_ring: u64,
    ) -> Result<(), VirtQueError>;

    /// Get queue next avail head.
    fn queue_next_avail(&self) -> u16;

    /// Set queue next avail head.
    fn set_queue_next_avail(&self, base: u16);

    /// Set configured queue size.
    fn set_queue_size(&self, num: u16);

    /// Enable/disable queue event index feature.
    fn set_queue_event_idx(&self, enabled: bool);

    /// Set queue enabled state.
    fn set_queue_ready(&self, ready: bool);

    /// Set `EventFd` for kick.
    fn set_kick(&self, file: Option<File>);

    /// Read event from the kick `EventFd`.
    fn read_kick(&self) -> io::Result<bool>;

    /// Set `EventFd` for call.
    fn set_call(&self, file: Option<File>);

    /// Set `EventFd` for err.
    fn set_err(&self, file: Option<File>);
}

/// Struct to maintain raw state information for a vhost-user queue.
///
/// This struct maintains all information of a virito queue, and could be used as an `VringT`
/// object for single-threaded context.
pub struct VringState<M: GuestAddressSpace = GuestMemoryAtomic<GuestMemoryMmap>> {
    queue: Queue,
    kick: Option<EventFd>,
    call: Option<EventFd>,
    err: Option<EventFd>,
    enabled: bool,
    mem: M,
}

impl<M: GuestAddressSpace> VringState<M> {
    /// Create a new instance of Vring.
    fn new(mem: M, max_queue_size: u16) -> Result<Self, VirtQueError> {
        Ok(VringState {
            queue: Queue::new(max_queue_size)?,
            kick: None,
            call: None,
            err: None,
            enabled: false,
            mem,
        })
    }

    /// Get an immutable reference to the underlying raw `Queue` object.
    pub fn get_queue(&self) -> &Queue {
        &self.queue
    }

    /// Get a mutable reference to the underlying raw `Queue` object.
    pub fn get_queue_mut(&mut self) -> &mut Queue {
        &mut self.queue
    }

    /// Add an used descriptor into the used queue.
    pub fn add_used(&mut self, desc_index: u16, len: u32) -> Result<(), VirtQueError> {
        self.queue
            .add_used(self.mem.memory().deref(), desc_index, len)
    }

    /// Notify the vhost-user master that used descriptors have been put into the used queue.
    pub fn signal_used_queue(&self) -> io::Result<()> {
        if let Some(call) = self.call.as_ref() {
            call.write(1)
        } else {
            Ok(())
        }
    }

    /// Enable event notification for queue.
    pub fn enable_notification(&mut self) -> Result<bool, VirtQueError> {
        self.queue.enable_notification(self.mem.memory().deref())
    }

    /// Disable event notification for queue.
    pub fn disable_notification(&mut self) -> Result<(), VirtQueError> {
        self.queue.disable_notification(self.mem.memory().deref())
    }

    /// Check whether a notification to the guest is needed.
    pub fn needs_notification(&mut self) -> Result<bool, VirtQueError> {
        self.queue.needs_notification(self.mem.memory().deref())
    }

    /// Set vring enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Set queue addresses for descriptor table, available ring and used ring.
    pub fn set_queue_info(
        &mut self,
        desc_table: u64,
        avail_ring: u64,
        used_ring: u64,
    ) -> Result<(), VirtQueError> {
        self.queue
            .try_set_desc_table_address(GuestAddress(desc_table))?;
        self.queue
            .try_set_avail_ring_address(GuestAddress(avail_ring))?;
        self.queue
            .try_set_used_ring_address(GuestAddress(used_ring))
    }

    /// Get queue next avail head.
    fn queue_next_avail(&self) -> u16 {
        self.queue.next_avail()
    }

    /// Set queue next avail head.
    fn set_queue_next_avail(&mut self, base: u16) {
        self.queue.set_next_avail(base);
    }

    /// Set configured queue size.
    fn set_queue_size(&mut self, num: u16) {
        self.queue.set_size(num);
    }

    /// Enable/disable queue event index feature.
    fn set_queue_event_idx(&mut self, enabled: bool) {
        self.queue.set_event_idx(enabled);
    }

    /// Set queue enabled state.
    fn set_queue_ready(&mut self, ready: bool) {
        self.queue.set_ready(ready);
    }

    /// Get the `EventFd` for kick.
    pub fn get_kick(&self) -> &Option<EventFd> {
        &self.kick
    }

    /// Set `EventFd` for kick.
    fn set_kick(&mut self, file: Option<File>) {
        // SAFETY:
        // EventFd requires that it has sole ownership of its fd. So does File, so this is safe.
        // Ideally, we'd have a generic way to refer to a uniquely-owned fd, such as that proposed
        // by Rust RFC #3128.
        self.kick = file.map(|f| unsafe { EventFd::from_raw_fd(f.into_raw_fd()) });
    }

    /// Read event from the kick `EventFd`.
    fn read_kick(&self) -> io::Result<bool> {
        if let Some(kick) = &self.kick {
            kick.read()?;
        }

        Ok(self.enabled)
    }

    /// Set `EventFd` for call.
    fn set_call(&mut self, file: Option<File>) {
        // SAFETY: see comment in set_kick()
        self.call = file.map(|f| unsafe { EventFd::from_raw_fd(f.into_raw_fd()) });
    }

    /// Get the `EventFd` for call.
    pub fn get_call(&self) -> &Option<EventFd> {
        &self.call
    }

    /// Set `EventFd` for err.
    fn set_err(&mut self, file: Option<File>) {
        // SAFETY: see comment in set_kick()
        self.err = file.map(|f| unsafe { EventFd::from_raw_fd(f.into_raw_fd()) });
    }
}

/// A `VringState` object protected by Mutex for multi-threading context.
#[derive(Clone)]
pub struct VringMutex<M: GuestAddressSpace = GuestMemoryAtomic<GuestMemoryMmap>> {
    state: Arc<Mutex<VringState<M>>>,
}

impl<M: GuestAddressSpace> VringMutex<M> {
    /// Get a mutable guard to the underlying raw `VringState` object.
    fn lock(&self) -> MutexGuard<VringState<M>> {
        self.state.lock().unwrap()
    }
}

impl<'a, M: 'a + GuestAddressSpace> VringStateGuard<'a, M> for VringMutex<M> {
    type G = MutexGuard<'a, VringState<M>>;
}

impl<'a, M: 'a + GuestAddressSpace> VringStateMutGuard<'a, M> for VringMutex<M> {
    type G = MutexGuard<'a, VringState<M>>;
}

impl<M: 'static + GuestAddressSpace> VringT<M> for VringMutex<M> {
    fn new(mem: M, max_queue_size: u16) -> Result<Self, VirtQueError> {
        Ok(VringMutex {
            state: Arc::new(Mutex::new(VringState::new(mem, max_queue_size)?)),
        })
    }

    fn get_ref(&self) -> <Self as VringStateGuard<M>>::G {
        self.state.lock().unwrap()
    }

    fn get_mut(&self) -> <Self as VringStateMutGuard<M>>::G {
        self.lock()
    }

    fn add_used(&self, desc_index: u16, len: u32) -> Result<(), VirtQueError> {
        self.lock().add_used(desc_index, len)
    }

    fn signal_used_queue(&self) -> io::Result<()> {
        self.get_ref().signal_used_queue()
    }

    fn enable_notification(&self) -> Result<bool, VirtQueError> {
        self.lock().enable_notification()
    }

    fn disable_notification(&self) -> Result<(), VirtQueError> {
        self.lock().disable_notification()
    }

    fn needs_notification(&self) -> Result<bool, VirtQueError> {
        self.lock().needs_notification()
    }

    fn set_enabled(&self, enabled: bool) {
        self.lock().set_enabled(enabled)
    }

    fn set_queue_info(
        &self,
        desc_table: u64,
        avail_ring: u64,
        used_ring: u64,
    ) -> Result<(), VirtQueError> {
        self.lock()
            .set_queue_info(desc_table, avail_ring, used_ring)
    }

    fn queue_next_avail(&self) -> u16 {
        self.get_ref().queue_next_avail()
    }

    fn set_queue_next_avail(&self, base: u16) {
        self.lock().set_queue_next_avail(base)
    }

    fn set_queue_size(&self, num: u16) {
        self.lock().set_queue_size(num);
    }

    fn set_queue_event_idx(&self, enabled: bool) {
        self.lock().set_queue_event_idx(enabled);
    }

    fn set_queue_ready(&self, ready: bool) {
        self.lock().set_queue_ready(ready);
    }

    fn set_kick(&self, file: Option<File>) {
        self.lock().set_kick(file);
    }

    fn read_kick(&self) -> io::Result<bool> {
        self.get_ref().read_kick()
    }

    fn set_call(&self, file: Option<File>) {
        self.lock().set_call(file)
    }

    fn set_err(&self, file: Option<File>) {
        self.lock().set_err(file)
    }
}

/// A `VringState` object protected by RwLock for multi-threading context.
#[derive(Clone)]
pub struct VringRwLock<M: GuestAddressSpace = GuestMemoryAtomic<GuestMemoryMmap>> {
    state: Arc<RwLock<VringState<M>>>,
}

impl<M: GuestAddressSpace> VringRwLock<M> {
    /// Get a mutable guard to the underlying raw `VringState` object.
    fn write_lock(&self) -> RwLockWriteGuard<VringState<M>> {
        self.state.write().unwrap()
    }
}

impl<'a, M: 'a + GuestAddressSpace> VringStateGuard<'a, M> for VringRwLock<M> {
    type G = RwLockReadGuard<'a, VringState<M>>;
}

impl<'a, M: 'a + GuestAddressSpace> VringStateMutGuard<'a, M> for VringRwLock<M> {
    type G = RwLockWriteGuard<'a, VringState<M>>;
}

impl<M: 'static + GuestAddressSpace> VringT<M> for VringRwLock<M> {
    fn new(mem: M, max_queue_size: u16) -> Result<Self, VirtQueError> {
        Ok(VringRwLock {
            state: Arc::new(RwLock::new(VringState::new(mem, max_queue_size)?)),
        })
    }

    fn get_ref(&self) -> <Self as VringStateGuard<M>>::G {
        self.state.read().unwrap()
    }

    fn get_mut(&self) -> <Self as VringStateMutGuard<M>>::G {
        self.write_lock()
    }

    fn add_used(&self, desc_index: u16, len: u32) -> Result<(), VirtQueError> {
        self.write_lock().add_used(desc_index, len)
    }

    fn signal_used_queue(&self) -> io::Result<()> {
        self.get_ref().signal_used_queue()
    }

    fn enable_notification(&self) -> Result<bool, VirtQueError> {
        self.write_lock().enable_notification()
    }

    fn disable_notification(&self) -> Result<(), VirtQueError> {
        self.write_lock().disable_notification()
    }

    fn needs_notification(&self) -> Result<bool, VirtQueError> {
        self.write_lock().needs_notification()
    }

    fn set_enabled(&self, enabled: bool) {
        self.write_lock().set_enabled(enabled)
    }

    fn set_queue_info(
        &self,
        desc_table: u64,
        avail_ring: u64,
        used_ring: u64,
    ) -> Result<(), VirtQueError> {
        self.write_lock()
            .set_queue_info(desc_table, avail_ring, used_ring)
    }

    fn queue_next_avail(&self) -> u16 {
        self.get_ref().queue_next_avail()
    }

    fn set_queue_next_avail(&self, base: u16) {
        self.write_lock().set_queue_next_avail(base)
    }

    fn set_queue_size(&self, num: u16) {
        self.write_lock().set_queue_size(num);
    }

    fn set_queue_event_idx(&self, enabled: bool) {
        self.write_lock().set_queue_event_idx(enabled);
    }

    fn set_queue_ready(&self, ready: bool) {
        self.write_lock().set_queue_ready(ready);
    }

    fn set_kick(&self, file: Option<File>) {
        self.write_lock().set_kick(file);
    }

    fn read_kick(&self) -> io::Result<bool> {
        self.get_ref().read_kick()
    }

    fn set_call(&self, file: Option<File>) {
        self.write_lock().set_call(file)
    }

    fn set_err(&self, file: Option<File>) {
        self.write_lock().set_err(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use vm_memory::bitmap::AtomicBitmap;
    use vmm_sys_util::eventfd::EventFd;

    #[test]
    fn test_new_vring() {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[(GuestAddress(0x100000), 0x10000)])
                .unwrap(),
        );
        let vring = VringMutex::new(mem, 0x1000).unwrap();

        assert!(vring.get_ref().get_kick().is_none());
        assert!(!vring.get_mut().enabled);
        assert!(!vring.lock().queue.ready());
        assert!(!vring.lock().queue.event_idx_enabled());

        vring.set_enabled(true);
        assert!(vring.get_ref().enabled);

        vring.set_queue_info(0x100100, 0x100200, 0x100300).unwrap();
        assert_eq!(vring.lock().get_queue().desc_table(), 0x100100);
        assert_eq!(vring.lock().get_queue().avail_ring(), 0x100200);
        assert_eq!(vring.lock().get_queue().used_ring(), 0x100300);

        assert_eq!(vring.queue_next_avail(), 0);
        vring.set_queue_next_avail(0x20);
        assert_eq!(vring.queue_next_avail(), 0x20);

        vring.set_queue_size(0x200);
        assert_eq!(vring.lock().queue.size(), 0x200);

        vring.set_queue_event_idx(true);
        assert!(vring.lock().queue.event_idx_enabled());

        vring.set_queue_ready(true);
        assert!(vring.lock().queue.ready());
    }

    #[test]
    fn test_vring_set_fd() {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        let vring = VringMutex::new(mem, 0x1000).unwrap();

        vring.set_enabled(true);
        assert!(vring.get_ref().enabled);

        let eventfd = EventFd::new(0).unwrap();
        let file = unsafe { File::from_raw_fd(eventfd.as_raw_fd()) };
        assert!(vring.get_mut().kick.is_none());
        assert!(vring.read_kick().unwrap());
        vring.set_kick(Some(file));
        eventfd.write(1).unwrap();
        assert!(vring.read_kick().unwrap());
        assert!(vring.get_ref().kick.is_some());
        vring.set_kick(None);
        assert!(vring.get_ref().kick.is_none());
        std::mem::forget(eventfd);

        let eventfd = EventFd::new(0).unwrap();
        let file = unsafe { File::from_raw_fd(eventfd.as_raw_fd()) };
        assert!(vring.get_ref().call.is_none());
        vring.set_call(Some(file));
        assert!(vring.get_ref().call.is_some());
        vring.set_call(None);
        assert!(vring.get_ref().call.is_none());
        std::mem::forget(eventfd);

        let eventfd = EventFd::new(0).unwrap();
        let file = unsafe { File::from_raw_fd(eventfd.as_raw_fd()) };
        assert!(vring.get_ref().err.is_none());
        vring.set_err(Some(file));
        assert!(vring.get_ref().err.is_some());
        vring.set_err(None);
        assert!(vring.get_ref().err.is_none());
        std::mem::forget(eventfd);
    }
}
