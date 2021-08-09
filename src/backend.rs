// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2019-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Traits for vhost user backend servers to implement virtio data plain services.
//!
//! Define two traits for vhost user backend servers to implement virtio data plane services.
//! The only difference between the two traits is mutability. The [VhostUserBackend] trait is
//! designed with interior mutability, so the implementor may choose the suitable way to protect
//! itself from concurrent accesses. The [VhostUserBackendMut] is designed without interior
//! mutability, and an implementation of:
//! ```ignore
//! impl<T: VhostUserBackendMut> VhostUserBackend for RwLock<T> { }
//! ```
//! is provided for convenience.
//!
//! [VhostUserBackend]: trait.VhostUserBackend.html
//! [VhostUserBackendMut]: trait.VhostUserBackendMut.html

use std::io;
use std::ops::Deref;
use std::result;
use std::sync::{Arc, Mutex, RwLock};

use vhost::vhost_user::message::VhostUserProtocolFeatures;
use vhost::vhost_user::SlaveFsCacheReq;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

use super::Vring;

/// Trait with interior mutability for vhost user backend servers to implement concrete services.
///
/// To support multi-threading and asynchronous IO, we enforce `the Send + Sync + 'static`.
/// So there's no plan for support of "Rc<T>" and "RefCell<T>".
pub trait VhostUserBackend: Send + Sync + 'static {
    /// Get number of queues supported.
    fn num_queues(&self) -> usize;

    /// Get maximum queue size supported.
    fn max_queue_size(&self) -> usize;

    /// Get available virtio features.
    fn features(&self) -> u64;

    /// Set acknowledged virtio features.
    fn acked_features(&self, _features: u64) {}

    /// Get available vhost protocol features.
    fn protocol_features(&self) -> VhostUserProtocolFeatures;

    /// Enable or disable the virtio EVENT_IDX feature
    fn set_event_idx(&self, enabled: bool);

    /// Get virtio device configuration.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        Vec::new()
    }

    /// Set virtio device configuration.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn set_config(&self, _offset: u32, _buf: &[u8]) -> result::Result<(), io::Error> {
        Ok(())
    }

    /// Update guest memory regions.
    fn update_memory(
        &self,
        atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> result::Result<(), io::Error>;

    /// Set handler for communicating with the master by the slave communication channel.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    ///
    /// TODO: this interface is designed only for vhost-user-fs, it should be refined.
    fn set_slave_req_fd(&self, _vu_req: SlaveFsCacheReq) {}

    /// Get the map to map queue index to worker thread index.
    ///
    /// A return value of [2, 2, 4] means: the first two queues will be handled by worker thread 0,
    /// the following two queues will be handled by worker thread 1, and the last four queues will
    /// be handled by worker thread 2.
    fn queues_per_thread(&self) -> Vec<u64> {
        vec![0xffff_ffff]
    }

    /// Provide an optional exit EventFd for the specified worker thread.
    ///
    /// If an (`EventFd`, `token`) pair is returned, the returned `EventFd` will be monitored for IO
    /// events by using epoll with the specified `token`. When the returned EventFd is written to,
    /// the worker thread will exit.
    fn exit_event(&self, _thread_index: usize) -> Option<(EventFd, u16)> {
        None
    }

    /// Handle IO events for backend registered file descriptors.
    ///
    /// This function gets called if the backend registered some additional listeners onto specific
    /// file descriptors. The library can handle virtqueues on its own, but does not know what to
    /// do with events happening on custom listeners.
    fn handle_event(
        &self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Vring],
        thread_id: usize,
    ) -> result::Result<bool, io::Error>;
}

/// Trait without interior mutability for vhost user backend servers to implement concrete services.
pub trait VhostUserBackendMut: Send + Sync + 'static {
    /// Get number of queues supported.
    fn num_queues(&self) -> usize;

    /// Get maximum queue size supported.
    fn max_queue_size(&self) -> usize;

    /// Get available virtio features.
    fn features(&self) -> u64;

    /// Set acknowledged virtio features.
    fn acked_features(&mut self, _features: u64) {}

    /// Get available vhost protocol features.
    fn protocol_features(&self) -> VhostUserProtocolFeatures;

    /// Enable or disable the virtio EVENT_IDX feature
    fn set_event_idx(&mut self, enabled: bool);

    /// Get virtio device configuration.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        Vec::new()
    }

    /// Set virtio device configuration.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn set_config(&mut self, _offset: u32, _buf: &[u8]) -> result::Result<(), io::Error> {
        Ok(())
    }

    /// Update guest memory regions.
    fn update_memory(
        &mut self,
        atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> result::Result<(), io::Error>;

    /// Set handler for communicating with the master by the slave communication channel.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    ///
    /// TODO: this interface is designed only for vhost-user-fs, it should be refined.
    fn set_slave_req_fd(&mut self, _vu_req: SlaveFsCacheReq) {}

    /// Get the map to map queue index to worker thread index.
    ///
    /// A return value of [2, 2, 4] means: the first two queues will be handled by worker thread 0,
    /// the following two queues will be handled by worker thread 1, and the last four queues will
    /// be handled by worker thread 2.
    fn queues_per_thread(&self) -> Vec<u64> {
        vec![0xffff_ffff]
    }

    /// Provide an optional exit EventFd for the specified worker thread.
    ///
    /// If an (`EventFd`, `token`) pair is returned, the returned `EventFd` will be monitored for IO
    /// events by using epoll with the specified `token`. When the returned EventFd is written to,
    /// the worker thread will exit.
    fn exit_event(&self, _thread_index: usize) -> Option<(EventFd, u16)> {
        None
    }

    /// Handle IO events for backend registered file descriptors.
    ///
    /// This function gets called if the backend registered some additional listeners onto specific
    /// file descriptors. The library can handle virtqueues on its own, but does not know what to
    /// do with events happening on custom listeners.
    fn handle_event(
        &mut self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Vring],
        thread_id: usize,
    ) -> result::Result<bool, io::Error>;
}

impl<T: VhostUserBackend> VhostUserBackend for Arc<T> {
    fn num_queues(&self) -> usize {
        self.deref().num_queues()
    }

    fn max_queue_size(&self) -> usize {
        self.deref().max_queue_size()
    }

    fn features(&self) -> u64 {
        self.deref().features()
    }

    fn acked_features(&self, features: u64) {
        self.deref().acked_features(features)
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        self.deref().protocol_features()
    }

    fn set_event_idx(&self, enabled: bool) {
        self.deref().set_event_idx(enabled)
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        self.deref().get_config(offset, size)
    }

    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<(), io::Error> {
        self.deref().set_config(offset, buf)
    }

    fn update_memory(
        &self,
        atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> Result<(), io::Error> {
        self.deref().update_memory(atomic_mem)
    }

    fn set_slave_req_fd(&self, vu_req: SlaveFsCacheReq) {
        self.deref().set_slave_req_fd(vu_req)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.deref().queues_per_thread()
    }

    fn exit_event(&self, thread_index: usize) -> Option<(EventFd, u16)> {
        self.deref().exit_event(thread_index)
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Vring],
        thread_id: usize,
    ) -> Result<bool, io::Error> {
        self.deref()
            .handle_event(device_event, evset, vrings, thread_id)
    }
}

impl<T: VhostUserBackendMut> VhostUserBackend for Mutex<T> {
    fn num_queues(&self) -> usize {
        self.lock().unwrap().num_queues()
    }

    fn max_queue_size(&self) -> usize {
        self.lock().unwrap().max_queue_size()
    }

    fn features(&self) -> u64 {
        self.lock().unwrap().features()
    }

    fn acked_features(&self, features: u64) {
        self.lock().unwrap().acked_features(features)
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        self.lock().unwrap().protocol_features()
    }

    fn set_event_idx(&self, enabled: bool) {
        self.lock().unwrap().set_event_idx(enabled)
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        self.lock().unwrap().get_config(offset, size)
    }

    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<(), io::Error> {
        self.lock().unwrap().set_config(offset, buf)
    }

    fn update_memory(
        &self,
        atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> Result<(), io::Error> {
        self.lock().unwrap().update_memory(atomic_mem)
    }

    fn set_slave_req_fd(&self, vu_req: SlaveFsCacheReq) {
        self.lock().unwrap().set_slave_req_fd(vu_req)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.lock().unwrap().queues_per_thread()
    }

    fn exit_event(&self, thread_index: usize) -> Option<(EventFd, u16)> {
        self.lock().unwrap().exit_event(thread_index)
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Vring],
        thread_id: usize,
    ) -> Result<bool, io::Error> {
        self.lock()
            .unwrap()
            .handle_event(device_event, evset, vrings, thread_id)
    }
}

impl<T: VhostUserBackendMut> VhostUserBackend for RwLock<T> {
    fn num_queues(&self) -> usize {
        self.read().unwrap().num_queues()
    }

    fn max_queue_size(&self) -> usize {
        self.read().unwrap().max_queue_size()
    }

    fn features(&self) -> u64 {
        self.read().unwrap().features()
    }

    fn acked_features(&self, features: u64) {
        self.write().unwrap().acked_features(features)
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        self.read().unwrap().protocol_features()
    }

    fn set_event_idx(&self, enabled: bool) {
        self.write().unwrap().set_event_idx(enabled)
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        self.read().unwrap().get_config(offset, size)
    }

    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<(), io::Error> {
        self.write().unwrap().set_config(offset, buf)
    }

    fn update_memory(
        &self,
        atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> Result<(), io::Error> {
        self.write().unwrap().update_memory(atomic_mem)
    }

    fn set_slave_req_fd(&self, vu_req: SlaveFsCacheReq) {
        self.write().unwrap().set_slave_req_fd(vu_req)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.read().unwrap().queues_per_thread()
    }

    fn exit_event(&self, thread_index: usize) -> Option<(EventFd, u16)> {
        self.read().unwrap().exit_event(thread_index)
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Vring],
        thread_id: usize,
    ) -> Result<bool, io::Error> {
        self.write()
            .unwrap()
            .handle_event(device_event, evset, vrings, thread_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epoll::Events;
    use std::io::Error;
    use std::sync::Mutex;

    struct MockVhostBackend {
        events: u64,
        event_idx: bool,
        acked_features: u64,
    }

    impl MockVhostBackend {
        fn new() -> Self {
            MockVhostBackend {
                events: 0,
                event_idx: false,
                acked_features: 0,
            }
        }
    }

    impl VhostUserBackendMut for MockVhostBackend {
        fn num_queues(&self) -> usize {
            2
        }

        fn max_queue_size(&self) -> usize {
            256
        }

        fn features(&self) -> u64 {
            0xffff_ffff_ffff_ffff
        }

        fn acked_features(&mut self, features: u64) {
            self.acked_features = features;
        }

        fn protocol_features(&self) -> VhostUserProtocolFeatures {
            VhostUserProtocolFeatures::all()
        }

        fn set_event_idx(&mut self, enabled: bool) {
            self.event_idx = enabled;
        }

        fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
            assert_eq!(offset, 0x200);
            assert_eq!(size, 8);

            vec![0xa5u8; 8]
        }

        fn set_config(&mut self, offset: u32, buf: &[u8]) -> Result<(), Error> {
            assert_eq!(offset, 0x200);
            assert_eq!(buf.len(), 8);
            assert_eq!(buf, &[0xa5u8; 8]);

            Ok(())
        }

        fn update_memory(
            &mut self,
            _atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>,
        ) -> Result<(), Error> {
            Ok(())
        }

        fn set_slave_req_fd(&mut self, _vu_req: SlaveFsCacheReq) {}

        fn queues_per_thread(&self) -> Vec<u64> {
            vec![1, 1]
        }

        fn exit_event(&self, _thread_index: usize) -> Option<(EventFd, u16)> {
            let event_fd = EventFd::new(0).unwrap();

            Some((event_fd, 0x100))
        }

        fn handle_event(
            &mut self,
            _device_event: u16,
            _evset: Events,
            _vrings: &[Vring],
            _thread_id: usize,
        ) -> Result<bool, Error> {
            self.events += 1;

            Ok(false)
        }
    }

    #[test]
    fn test_new_mock_backend_mutex() {
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));

        assert_eq!(backend.num_queues(), 2);
        assert_eq!(backend.max_queue_size(), 256);
        assert_eq!(backend.features(), 0xffff_ffff_ffff_ffff);
        assert_eq!(
            backend.protocol_features(),
            VhostUserProtocolFeatures::all()
        );
        assert_eq!(backend.queues_per_thread(), [1, 1]);

        assert_eq!(backend.get_config(0x200, 8), vec![0xa5; 8]);
        backend.set_config(0x200, &vec![0xa5; 8]).unwrap();

        backend.acked_features(0xffff);
        assert_eq!(backend.lock().unwrap().acked_features, 0xffff);

        backend.set_event_idx(true);
        assert_eq!(backend.lock().unwrap().event_idx, true);
    }

    #[test]
    fn test_new_mock_backend_rwlock() {
        let backend = Arc::new(RwLock::new(MockVhostBackend::new()));

        assert_eq!(backend.num_queues(), 2);
        assert_eq!(backend.max_queue_size(), 256);
        assert_eq!(backend.features(), 0xffff_ffff_ffff_ffff);
        assert_eq!(
            backend.protocol_features(),
            VhostUserProtocolFeatures::all()
        );
        assert_eq!(backend.queues_per_thread(), [1, 1]);

        assert_eq!(backend.get_config(0x200, 8), vec![0xa5; 8]);
        backend.set_config(0x200, &vec![0xa5; 8]).unwrap();

        backend.acked_features(0xffff);
        assert_eq!(backend.read().unwrap().acked_features, 0xffff);

        backend.set_event_idx(true);
        assert_eq!(backend.read().unwrap().event_idx, true);
    }
}
