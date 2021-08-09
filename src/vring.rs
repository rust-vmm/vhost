// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2021 Alibaba Cloud Computing. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Struct to maintain state information and manipulate vhost-user queues.

use std::fs::File;
use std::io;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use virtio_queue::Queue;
use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

/// Struct to maintain raw state information for a vhost-user queue.
pub struct VringState {
    queue: Queue<GuestMemoryAtomic<GuestMemoryMmap>>,
    kick: Option<EventFd>,
    call: Option<EventFd>,
    err: Option<EventFd>,
    enabled: bool,
}

impl VringState {
    fn new(atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>, max_queue_size: u16) -> Self {
        VringState {
            queue: Queue::new(atomic_mem, max_queue_size),
            kick: None,
            call: None,
            err: None,
            enabled: false,
        }
    }

    /// Get a mutable reference to the underlying `Queue` object.
    pub fn get_queue_mut(&mut self) -> &mut Queue<GuestMemoryAtomic<GuestMemoryMmap>> {
        &mut self.queue
    }

    /// Get a immutable reference to the underlying kick event fd.
    pub fn get_kick(&self) -> &Option<EventFd> {
        &self.kick
    }
}

/// Struct to maintain state information and manipulate a vhost-user queue.
#[derive(Clone)]
pub struct Vring {
    state: Arc<RwLock<VringState>>,
}

impl Vring {
    /// Get a immutable guard to the underlying raw `VringState` object.
    pub fn get_ref(&self) -> RwLockReadGuard<VringState> {
        self.state.read().unwrap()
    }

    /// Get a mutable guard to the underlying raw `VringState` object.
    pub fn get_mut(&self) -> RwLockWriteGuard<VringState> {
        self.state.write().unwrap()
    }

    pub(crate) fn new(mem: GuestMemoryAtomic<GuestMemoryMmap>, max_queue_size: u16) -> Self {
        Vring {
            state: Arc::new(RwLock::new(VringState::new(mem, max_queue_size))),
        }
    }

    pub(crate) fn set_enabled(&self, enabled: bool) {
        self.get_mut().enabled = enabled;
    }

    pub(crate) fn set_queue_info(&self, desc_table: u64, avail_ring: u64, used_ring: u64) {
        let mut state = self.get_mut();

        state.queue.desc_table = GuestAddress(desc_table);
        state.queue.avail_ring = GuestAddress(avail_ring);
        state.queue.used_ring = GuestAddress(used_ring);
    }

    pub(crate) fn queue_next_avail(&self) -> u16 {
        self.get_ref().queue.next_avail()
    }

    pub(crate) fn set_queue_next_avail(&self, base: u16) {
        self.get_mut().queue.set_next_avail(base);
    }

    pub(crate) fn set_queue_size(&self, num: u16) {
        self.get_mut().queue.size = num;
    }

    pub(crate) fn set_queue_event_idx(&self, enabled: bool) {
        self.get_mut().queue.set_event_idx(enabled);
    }

    pub(crate) fn set_queue_ready(&self, ready: bool) {
        self.get_mut().queue.ready = ready;
    }

    pub(crate) fn set_kick(&self, file: Option<File>) {
        // SAFETY:
        // EventFd requires that it has sole ownership of its fd. So does File, so this is safe.
        // Ideally, we'd have a generic way to refer to a uniquely-owned fd, such as that proposed
        // by Rust RFC #3128.
        self.get_mut().kick = file.map(|f| unsafe { EventFd::from_raw_fd(f.into_raw_fd()) });
    }

    pub(crate) fn read_kick(&self) -> io::Result<bool> {
        let state = self.get_ref();

        if let Some(kick) = &state.kick {
            kick.read()?;
        }

        Ok(state.enabled)
    }

    pub(crate) fn set_call(&self, file: Option<File>) {
        // SAFETY: see comment in set_kick()
        self.get_mut().call = file.map(|f| unsafe { EventFd::from_raw_fd(f.into_raw_fd()) });
    }

    pub(crate) fn set_err(&self, file: Option<File>) {
        // SAFETY: see comment in set_kick()
        self.get_mut().err = file.map(|f| unsafe { EventFd::from_raw_fd(f.into_raw_fd()) });
    }
}
