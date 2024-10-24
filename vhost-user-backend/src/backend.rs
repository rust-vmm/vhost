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

use std::fs::File;
use std::io::Result;
use std::ops::Deref;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, RwLock};

use vhost::vhost_user::message::{
    VhostTransferStateDirection, VhostTransferStatePhase, VhostUserProtocolFeatures,
    VhostUserSharedMsg,
};
use vhost::vhost_user::Backend;
use vm_memory::bitmap::Bitmap;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

#[cfg(feature = "gpu-socket")]
use vhost::vhost_user::GpuBackend;

use super::vring::VringT;
use super::GM;

/// Trait with interior mutability for vhost user backend servers to implement concrete services.
///
/// To support multi-threading and asynchronous IO, we enforce `Send + Sync` bound.
pub trait VhostUserBackend: Send + Sync {
    type Bitmap: Bitmap + 'static;
    type Vring: VringT<GM<Self::Bitmap>>;

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
    fn set_config(&self, _offset: u32, _buf: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Update guest memory regions.
    fn update_memory(&self, mem: GM<Self::Bitmap>) -> Result<()>;

    /// Set handler for communicating with the frontend by the backend communication channel.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn set_backend_req_fd(&self, _backend: Backend) {}

    /// This function gets an owned file descriptor that the front-end can use otherwise
    /// no file descriptor.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn get_shared_object(&self, _uuid: VhostUserSharedMsg) -> Result<Option<OwnedFd>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support get shared object",
        ))
    }

    #[cfg(feature = "gpu-socket")]
    /// Set handler for communicating with the frontend by the gpu specific backend communication
    /// channel.
    ///
    /// This method only exits when the crate feature gpu-socket is enabled, because this is only
    /// useful for a gpu device.
    fn set_gpu_socket(&self, _gpu_backend: GpuBackend);

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
    /// The returned `EventFd` will be monitored for IO events. When the
    /// returned EventFd is written to, the worker thread will exit.
    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
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
        evset: EventSet,
        vrings: &[Self::Vring],
        thread_id: usize,
    ) -> Result<()>;

    /// Initiate transfer of internal state for the purpose of migration to/from the back-end.
    ///
    /// Depending on `direction`, the state should either be saved (i.e. serialized and written to
    /// `file`) or loaded (i.e. read from `file` and deserialized). The back-end can choose to use
    /// a different channel than file. If so, it must return a File that the front-end can use.
    /// Note that this function must not block during transfer, i.e. I/O to/from `file` must be
    /// done outside of this function.
    fn set_device_state_fd(
        &self,
        _direction: VhostTransferStateDirection,
        _phase: VhostTransferStatePhase,
        _file: File,
    ) -> Result<Option<File>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support state transfer",
        ))
    }

    /// After transferring internal state, check for any resulting errors, including potential
    /// deserialization errors when loading state.
    ///
    /// Although this function return a `Result`, the front-end will not receive any details about
    /// this error.
    fn check_device_state(&self) -> Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support state transfer",
        ))
    }
}

/// Trait without interior mutability for vhost user backend servers to implement concrete services.
pub trait VhostUserBackendMut: Send + Sync {
    type Bitmap: Bitmap + 'static;
    type Vring: VringT<GM<Self::Bitmap>>;

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
    fn set_config(&mut self, _offset: u32, _buf: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Update guest memory regions.
    fn update_memory(&mut self, mem: GM<Self::Bitmap>) -> Result<()>;

    /// Set handler for communicating with the frontend by the backend communication channel.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn set_backend_req_fd(&mut self, _backend: Backend) {}

    /// This function gets an owned file descriptor that the front-end can use otherwise
    /// no file descriptor.
    ///
    /// A default implementation is provided as we cannot expect all backends to implement this
    /// function.
    fn get_shared_object(&mut self, _uuid: VhostUserSharedMsg) -> Result<Option<OwnedFd>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support get shared object",
        ))
    }

    #[cfg(feature = "gpu-socket")]
    /// Set handler for communicating with the frontend by the gpu specific backend communication
    /// channel.
    ///
    /// This method only exits when the crate feature gpu-socket is enabled, because this is only
    /// useful for a gpu device.
    fn set_gpu_socket(&mut self, gpu_backend: GpuBackend);

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
    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
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
        evset: EventSet,
        vrings: &[Self::Vring],
        thread_id: usize,
    ) -> Result<()>;

    /// Initiate transfer of internal state for the purpose of migration to/from the back-end.
    ///
    /// Depending on `direction`, the state should either be saved (i.e. serialized and written to
    /// `file`) or loaded (i.e. read from `file` and deserialized).  Note that this function must
    /// not block during transfer, i.e. I/O to/from `file` must be done outside of this function.
    fn set_device_state_fd(
        &mut self,
        _direction: VhostTransferStateDirection,
        _phase: VhostTransferStatePhase,
        _file: File,
    ) -> Result<Option<File>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support state transfer",
        ))
    }

    /// After transferring internal state, check for any resulting errors, including potential
    /// deserialization errors when loading state.
    ///
    /// Although this function return a `Result`, the front-end will not receive any details about
    /// this error.
    fn check_device_state(&self) -> Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "back end does not support state transfer",
        ))
    }
}

impl<T: VhostUserBackend> VhostUserBackend for Arc<T> {
    type Bitmap = T::Bitmap;
    type Vring = T::Vring;

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

    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<()> {
        self.deref().set_config(offset, buf)
    }

    fn update_memory(&self, mem: GM<Self::Bitmap>) -> Result<()> {
        self.deref().update_memory(mem)
    }

    fn set_backend_req_fd(&self, backend: Backend) {
        self.deref().set_backend_req_fd(backend)
    }

    fn get_shared_object(&self, uuid: VhostUserSharedMsg) -> Result<Option<OwnedFd>> {
        self.deref().get_shared_object(uuid)
    }

    #[cfg(feature = "gpu-socket")]
    fn set_gpu_socket(&self, gpu_backend: GpuBackend) {
        self.deref().set_gpu_socket(gpu_backend)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.deref().queues_per_thread()
    }

    fn exit_event(&self, thread_index: usize) -> Option<EventFd> {
        self.deref().exit_event(thread_index)
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[Self::Vring],
        thread_id: usize,
    ) -> Result<()> {
        self.deref()
            .handle_event(device_event, evset, vrings, thread_id)
    }

    fn set_device_state_fd(
        &self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        file: File,
    ) -> Result<Option<File>> {
        self.deref().set_device_state_fd(direction, phase, file)
    }

    fn check_device_state(&self) -> Result<()> {
        self.deref().check_device_state()
    }
}

impl<T: VhostUserBackendMut> VhostUserBackend for Mutex<T> {
    type Bitmap = T::Bitmap;
    type Vring = T::Vring;

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

    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<()> {
        self.lock().unwrap().set_config(offset, buf)
    }

    fn update_memory(&self, mem: GM<Self::Bitmap>) -> Result<()> {
        self.lock().unwrap().update_memory(mem)
    }

    fn set_backend_req_fd(&self, backend: Backend) {
        self.lock().unwrap().set_backend_req_fd(backend)
    }

    fn get_shared_object(&self, uuid: VhostUserSharedMsg) -> Result<Option<OwnedFd>> {
        self.lock().unwrap().get_shared_object(uuid)
    }

    #[cfg(feature = "gpu-socket")]
    fn set_gpu_socket(&self, gpu_backend: GpuBackend) {
        self.lock().unwrap().set_gpu_socket(gpu_backend)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.lock().unwrap().queues_per_thread()
    }

    fn exit_event(&self, thread_index: usize) -> Option<EventFd> {
        self.lock().unwrap().exit_event(thread_index)
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[Self::Vring],
        thread_id: usize,
    ) -> Result<()> {
        self.lock()
            .unwrap()
            .handle_event(device_event, evset, vrings, thread_id)
    }

    fn set_device_state_fd(
        &self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        file: File,
    ) -> Result<Option<File>> {
        self.lock()
            .unwrap()
            .set_device_state_fd(direction, phase, file)
    }

    fn check_device_state(&self) -> Result<()> {
        self.lock().unwrap().check_device_state()
    }
}

impl<T: VhostUserBackendMut> VhostUserBackend for RwLock<T> {
    type Bitmap = T::Bitmap;
    type Vring = T::Vring;

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

    fn set_config(&self, offset: u32, buf: &[u8]) -> Result<()> {
        self.write().unwrap().set_config(offset, buf)
    }

    fn update_memory(&self, mem: GM<Self::Bitmap>) -> Result<()> {
        self.write().unwrap().update_memory(mem)
    }

    fn set_backend_req_fd(&self, backend: Backend) {
        self.write().unwrap().set_backend_req_fd(backend)
    }

    fn get_shared_object(&self, uuid: VhostUserSharedMsg) -> Result<Option<OwnedFd>> {
        self.write().unwrap().get_shared_object(uuid)
    }

    #[cfg(feature = "gpu-socket")]
    fn set_gpu_socket(&self, gpu_backend: GpuBackend) {
        self.write().unwrap().set_gpu_socket(gpu_backend)
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.read().unwrap().queues_per_thread()
    }

    fn exit_event(&self, thread_index: usize) -> Option<EventFd> {
        self.read().unwrap().exit_event(thread_index)
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[Self::Vring],
        thread_id: usize,
    ) -> Result<()> {
        self.write()
            .unwrap()
            .handle_event(device_event, evset, vrings, thread_id)
    }

    fn set_device_state_fd(
        &self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        file: File,
    ) -> Result<Option<File>> {
        self.write()
            .unwrap()
            .set_device_state_fd(direction, phase, file)
    }

    fn check_device_state(&self) -> Result<()> {
        self.read().unwrap().check_device_state()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::VringRwLock;
    use libc::EFD_NONBLOCK;
    use std::sync::Mutex;
    use uuid::Uuid;
    use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    pub struct MockVhostBackend {
        events: u64,
        event_idx: bool,
        acked_features: u64,
        exit_event_fds: Vec<EventFd>,
    }

    impl MockVhostBackend {
        pub fn new() -> Self {
            let mut backend = MockVhostBackend {
                events: 0,
                event_idx: false,
                acked_features: 0,
                exit_event_fds: vec![],
            };

            // Create a event_fd for each thread. We make it NONBLOCKing in
            // order to allow tests maximum flexibility in checking whether
            // signals arrived or not.
            backend.exit_event_fds = (0..backend.queues_per_thread().len())
                .map(|_| EventFd::new(EFD_NONBLOCK).unwrap())
                .collect();

            backend
        }
    }

    impl VhostUserBackendMut for MockVhostBackend {
        type Bitmap = ();
        type Vring = VringRwLock;

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

        fn set_config(&mut self, offset: u32, buf: &[u8]) -> Result<()> {
            assert_eq!(offset, 0x200);
            assert_eq!(buf.len(), 8);
            assert_eq!(buf, &[0xa5u8; 8]);

            Ok(())
        }

        fn update_memory(&mut self, _atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>) -> Result<()> {
            Ok(())
        }

        fn set_backend_req_fd(&mut self, _backend: Backend) {}

        fn get_shared_object(&mut self, _uuid: VhostUserSharedMsg) -> Result<Option<OwnedFd>> {
            Ok(None)
        }

        #[cfg(feature = "gpu-socket")]
        fn set_gpu_socket(&mut self, _gpu_backend: GpuBackend) {}

        fn queues_per_thread(&self) -> Vec<u64> {
            vec![1, 1]
        }

        fn exit_event(&self, thread_index: usize) -> Option<EventFd> {
            Some(
                self.exit_event_fds
                    .get(thread_index)?
                    .try_clone()
                    .expect("Could not clone exit eventfd"),
            )
        }

        fn handle_event(
            &mut self,
            _device_event: u16,
            _evset: EventSet,
            _vrings: &[VringRwLock],
            _thread_id: usize,
        ) -> Result<()> {
            self.events += 1;

            Ok(())
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
        backend.set_config(0x200, &[0xa5; 8]).unwrap();

        backend.acked_features(0xffff);
        assert_eq!(backend.lock().unwrap().acked_features, 0xffff);

        backend.set_event_idx(true);
        assert!(backend.lock().unwrap().event_idx);

        let _ = backend.exit_event(0).unwrap();

        let uuid = VhostUserSharedMsg {
            uuid: Uuid::new_v4(),
        };
        backend.get_shared_object(uuid).unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        backend.update_memory(mem).unwrap();
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
        backend.set_config(0x200, &[0xa5; 8]).unwrap();

        backend.acked_features(0xffff);
        assert_eq!(backend.read().unwrap().acked_features, 0xffff);

        backend.set_event_idx(true);
        assert!(backend.read().unwrap().event_idx);

        let _ = backend.exit_event(0).unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        backend.update_memory(mem.clone()).unwrap();

        let uuid = VhostUserSharedMsg {
            uuid: Uuid::new_v4(),
        };
        backend.get_shared_object(uuid).unwrap();

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        backend
            .handle_event(0x1, EventSet::IN, &[vring], 0)
            .unwrap();
    }
}
