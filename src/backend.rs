// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2019-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::result;
use std::sync::{Arc, RwLock};

use vhost::vhost_user::message::VhostUserProtocolFeatures;
use vhost::vhost_user::SlaveFsCacheReq;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

use super::Vring;

/// This trait must be implemented by the caller in order to provide backend
/// specific implementation.
pub trait VhostUserBackend: Send + Sync + 'static {
    /// Number of queues.
    fn num_queues(&self) -> usize;

    /// Depth of each queue.
    fn max_queue_size(&self) -> usize;

    /// Available virtio features.
    fn features(&self) -> u64;

    /// Acked virtio features.
    fn acked_features(&mut self, _features: u64) {}

    /// Virtio protocol features.
    fn protocol_features(&self) -> VhostUserProtocolFeatures;

    /// Tell the backend if EVENT_IDX has been negotiated.
    fn set_event_idx(&mut self, enabled: bool);

    /// Update guest memory regions.
    fn update_memory(
        &mut self,
        atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> result::Result<(), io::Error>;

    /// This function gets called if the backend registered some additional
    /// listeners onto specific file descriptors. The library can handle
    /// virtqueues on its own, but does not know what to do with events
    /// happening on custom listeners.
    fn handle_event(
        &self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Arc<RwLock<Vring>>],
        thread_id: usize,
    ) -> result::Result<bool, io::Error>;

    /// Get virtio device configuration.
    /// A default implementation is provided as we cannot expect all backends
    /// to implement this function.
    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        Vec::new()
    }

    /// Set virtio device configuration.
    /// A default implementation is provided as we cannot expect all backends
    /// to implement this function.
    fn set_config(&mut self, _offset: u32, _buf: &[u8]) -> result::Result<(), io::Error> {
        Ok(())
    }

    /// Provide an exit EventFd
    /// When this EventFd is written to the worker thread will exit. An optional id may
    /// also be provided, if it not provided then the exit event will be first event id
    /// after the last queue
    fn exit_event(&self, _thread_index: usize) -> Option<(EventFd, Option<u16>)> {
        None
    }

    /// Set slave fd.
    /// A default implementation is provided as we cannot expect all backends
    /// to implement this function.
    fn set_slave_req_fd(&mut self, _vu_req: SlaveFsCacheReq) {}

    fn queues_per_thread(&self) -> Vec<u64> {
        vec![0xffff_ffff]
    }
}
