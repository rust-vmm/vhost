// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2019-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::error;
use std::fs::File;
use std::io;
#[cfg(feature = "postcopy")]
use std::os::fd::FromRawFd;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::thread;

use crate::bitmap::{BitmapReplace, MemRegionBitmap, MmapLogReg};
#[cfg(feature = "postcopy")]
use userfaultfd::{Uffd, UffdBuilder};
use vhost::vhost_user::message::{
    VhostTransferStateDirection, VhostTransferStatePhase, VhostUserConfigFlags, VhostUserLog,
    VhostUserMemoryRegion, VhostUserProtocolFeatures, VhostUserSharedMsg,
    VhostUserSingleMemoryRegion, VhostUserVirtioFeatures, VhostUserVringAddrFlags,
    VhostUserVringState,
};
#[cfg(feature = "gpu-socket")]
use vhost::vhost_user::GpuBackend;
use vhost::vhost_user::{
    Backend, Error as VhostUserError, Result as VhostUserResult, VhostUserBackendReqHandlerMut,
};

use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use virtio_queue::{Error as VirtQueError, QueueT};
use vm_memory::mmap::NewBitmap;
use vm_memory::{
    GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap,
};
use vmm_sys_util::epoll::EventSet;

use super::backend::VhostUserBackend;
use super::event_loop::VringEpollHandler;
use super::event_loop::{VringEpollError, VringEpollResult};
use super::vring::VringT;
use super::GM;

// vhost in the kernel usually supports 509 mem slots.
// The 509 used to be the KVM limit, it supported 512, but 3 were used
// for internal purposes (nowadays, it supports more than that).
const MAX_MEM_SLOTS: u64 = 509;

#[derive(Debug)]
/// Errors related to vhost-user handler.
pub enum VhostUserHandlerError {
    /// Failed to create a `Vring`.
    CreateVring(VirtQueError),
    /// Failed to create vring worker.
    CreateEpollHandler(VringEpollError),
    /// Failed to spawn vring worker.
    SpawnVringWorker(io::Error),
    /// Could not find the mapping from memory regions.
    MissingMemoryMapping,
}

impl std::fmt::Display for VhostUserHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VhostUserHandlerError::CreateVring(e) => {
                write!(f, "failed to create vring: {}", e)
            }
            VhostUserHandlerError::CreateEpollHandler(e) => {
                write!(f, "failed to create vring epoll handler: {}", e)
            }
            VhostUserHandlerError::SpawnVringWorker(e) => {
                write!(f, "failed spawning the vring worker: {}", e)
            }
            VhostUserHandlerError::MissingMemoryMapping => write!(f, "Missing memory mapping"),
        }
    }
}

impl error::Error for VhostUserHandlerError {}

/// Result of vhost-user handler operations.
pub type VhostUserHandlerResult<T> = std::result::Result<T, VhostUserHandlerError>;

#[derive(Debug)]
struct AddrMapping {
    #[cfg(feature = "postcopy")]
    local_addr: u64,
    vmm_addr: u64,
    size: u64,
    gpa_base: u64,
}

pub struct VhostUserHandler<T: VhostUserBackend> {
    backend: T,
    handlers: Vec<Arc<VringEpollHandler<T>>>,
    owned: bool,
    features_acked: bool,
    acked_features: u64,
    acked_protocol_features: u64,
    num_queues: usize,
    max_queue_size: usize,
    queues_per_thread: Vec<u64>,
    mappings: Vec<AddrMapping>,
    atomic_mem: GM<T::Bitmap>,
    vrings: Vec<T::Vring>,
    #[cfg(feature = "postcopy")]
    uffd: Option<Uffd>,
    worker_threads: Vec<thread::JoinHandle<VringEpollResult<()>>>,
}

// Ensure VhostUserHandler: Clone + Send + Sync + 'static.
impl<T> VhostUserHandler<T>
where
    T: VhostUserBackend + Clone + 'static,
    T::Vring: Clone + Send + Sync + 'static,
    T::Bitmap: Clone + Send + Sync + 'static,
{
    pub(crate) fn new(backend: T, atomic_mem: GM<T::Bitmap>) -> VhostUserHandlerResult<Self> {
        let num_queues = backend.num_queues();
        let max_queue_size = backend.max_queue_size();
        let queues_per_thread = backend.queues_per_thread();

        let mut vrings = Vec::new();
        for _ in 0..num_queues {
            let vring = T::Vring::new(atomic_mem.clone(), max_queue_size as u16)
                .map_err(VhostUserHandlerError::CreateVring)?;
            vrings.push(vring);
        }

        let mut handlers = Vec::new();
        let mut worker_threads = Vec::new();
        for (thread_id, queues_mask) in queues_per_thread.iter().enumerate() {
            let mut thread_vrings = Vec::new();
            for (index, vring) in vrings.iter().enumerate() {
                if (queues_mask >> index) & 1u64 == 1u64 {
                    thread_vrings.push(vring.clone());
                }
            }

            let handler = Arc::new(
                VringEpollHandler::new(backend.clone(), thread_vrings, thread_id)
                    .map_err(VhostUserHandlerError::CreateEpollHandler)?,
            );
            let handler2 = handler.clone();
            let worker_thread = thread::Builder::new()
                .name("vring_worker".to_string())
                .spawn(move || handler2.run())
                .map_err(VhostUserHandlerError::SpawnVringWorker)?;

            handlers.push(handler);
            worker_threads.push(worker_thread);
        }

        Ok(VhostUserHandler {
            backend,
            handlers,
            owned: false,
            features_acked: false,
            acked_features: 0,
            acked_protocol_features: 0,
            num_queues,
            max_queue_size,
            queues_per_thread,
            mappings: Vec::new(),
            atomic_mem,
            vrings,
            #[cfg(feature = "postcopy")]
            uffd: None,
            worker_threads,
        })
    }
}

impl<T: VhostUserBackend> VhostUserHandler<T> {
    pub(crate) fn send_exit_event(&self) {
        for handler in self.handlers.iter() {
            handler.send_exit_event();
        }
    }

    fn vmm_va_to_gpa(&self, vmm_va: u64) -> VhostUserHandlerResult<u64> {
        for mapping in self.mappings.iter() {
            if vmm_va >= mapping.vmm_addr && vmm_va < mapping.vmm_addr + mapping.size {
                return Ok(vmm_va - mapping.vmm_addr + mapping.gpa_base);
            }
        }

        Err(VhostUserHandlerError::MissingMemoryMapping)
    }
}

impl<T> VhostUserHandler<T>
where
    T: VhostUserBackend,
{
    pub(crate) fn get_epoll_handlers(&self) -> Vec<Arc<VringEpollHandler<T>>> {
        self.handlers.clone()
    }

    fn vring_needs_init(&self, vring: &T::Vring) -> bool {
        let vring_state = vring.get_ref();

        // If the vring wasn't initialized and we already have an EventFd for
        // VRING_KICK, initialize it now.
        !vring_state.get_queue().ready() && vring_state.get_kick().is_some()
    }

    fn initialize_vring(&self, vring: &T::Vring, index: u8) -> VhostUserResult<()> {
        assert!(vring.get_ref().get_kick().is_some());

        if let Some(fd) = vring.get_ref().get_kick() {
            for (thread_index, queues_mask) in self.queues_per_thread.iter().enumerate() {
                let shifted_queues_mask = queues_mask >> index;
                if shifted_queues_mask & 1u64 == 1u64 {
                    let evt_idx = queues_mask.count_ones() - shifted_queues_mask.count_ones();
                    self.handlers[thread_index]
                        .register_event(fd.as_raw_fd(), EventSet::IN, u64::from(evt_idx))
                        .map_err(VhostUserError::ReqHandlerError)?;
                    break;
                }
            }
        }

        vring.set_queue_ready(true);

        Ok(())
    }

    /// Helper to check if VirtioFeature enabled
    fn check_feature(&self, feat: VhostUserVirtioFeatures) -> VhostUserResult<()> {
        if self.acked_features & feat.bits() != 0 {
            Ok(())
        } else {
            Err(VhostUserError::InactiveFeature(feat))
        }
    }
}

impl<T: VhostUserBackend> VhostUserBackendReqHandlerMut for VhostUserHandler<T>
where
    T::Bitmap: BitmapReplace + NewBitmap + Clone,
{
    fn set_owner(&mut self) -> VhostUserResult<()> {
        if self.owned {
            return Err(VhostUserError::InvalidOperation("already claimed"));
        }
        self.owned = true;
        Ok(())
    }

    fn reset_owner(&mut self) -> VhostUserResult<()> {
        self.owned = false;
        self.features_acked = false;
        self.acked_features = 0;
        self.acked_protocol_features = 0;
        Ok(())
    }

    fn get_features(&mut self) -> VhostUserResult<u64> {
        Ok(self.backend.features())
    }

    fn set_features(&mut self, features: u64) -> VhostUserResult<()> {
        if (features & !self.backend.features()) != 0 {
            return Err(VhostUserError::InvalidParam);
        }

        self.acked_features = features;
        self.features_acked = true;

        // Upon receiving a `VHOST_USER_SET_FEATURES` message from the front-end without
        // `VHOST_USER_F_PROTOCOL_FEATURES` set, the back-end must enable all rings immediately.
        // While processing the rings (whether they are enabled or not), the back-end must support
        // changing some configuration aspects on the fly.
        // (see https://qemu-project.gitlab.io/qemu/interop/vhost-user.html#ring-states)
        //
        // Note: If `VHOST_USER_F_PROTOCOL_FEATURES` has been negotiated we must leave
        // the vrings in their current state.
        if self.acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0 {
            for vring in self.vrings.iter_mut() {
                vring.set_enabled(true);
            }
        }

        let event_idx: bool = (self.acked_features & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        for vring in self.vrings.iter_mut() {
            vring.set_queue_event_idx(event_idx);
        }
        self.backend.set_event_idx(event_idx);
        self.backend.acked_features(self.acked_features);

        Ok(())
    }

    fn set_mem_table(
        &mut self,
        ctx: &[VhostUserMemoryRegion],
        files: Vec<File>,
    ) -> VhostUserResult<()> {
        // We need to create tuple of ranges from the list of VhostUserMemoryRegion
        // that we get from the caller.
        let mut regions = Vec::new();
        let mut mappings: Vec<AddrMapping> = Vec::new();

        for (region, file) in ctx.iter().zip(files) {
            let guest_region = GuestRegionMmap::new(
                region.mmap_region(file)?,
                GuestAddress(region.guest_phys_addr),
            )
            .map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;
            mappings.push(AddrMapping {
                #[cfg(feature = "postcopy")]
                local_addr: guest_region.as_ptr() as u64,
                vmm_addr: region.user_addr,
                size: region.memory_size,
                gpa_base: region.guest_phys_addr,
            });
            regions.push(guest_region);
        }

        let mem = GuestMemoryMmap::from_regions(regions).map_err(|e| {
            VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
        })?;

        // Updating the inner GuestMemory object here will cause all our vrings to
        // see the new one the next time they call to `atomic_mem.memory()`.
        self.atomic_mem.lock().unwrap().replace(mem);

        self.backend
            .update_memory(self.atomic_mem.clone())
            .map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;
        self.mappings = mappings;

        Ok(())
    }

    fn set_vring_num(&mut self, index: u32, num: u32) -> VhostUserResult<()> {
        let vring = self
            .vrings
            .get(index as usize)
            .ok_or_else(|| VhostUserError::InvalidParam)?;

        if num == 0 || num as usize > self.max_queue_size {
            return Err(VhostUserError::InvalidParam);
        }
        vring.set_queue_size(num as u16);
        Ok(())
    }

    fn set_vring_addr(
        &mut self,
        index: u32,
        _flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        _log: u64,
    ) -> VhostUserResult<()> {
        let vring = self
            .vrings
            .get(index as usize)
            .ok_or_else(|| VhostUserError::InvalidParam)?;

        if !self.mappings.is_empty() {
            let desc_table = self.vmm_va_to_gpa(descriptor).map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;
            let avail_ring = self.vmm_va_to_gpa(available).map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;
            let used_ring = self.vmm_va_to_gpa(used).map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;
            vring
                .set_queue_info(desc_table, avail_ring, used_ring)
                .map_err(|_| VhostUserError::InvalidParam)?;

            // SET_VRING_BASE will only restore the 'avail' index, however, after the guest driver
            // changes, for instance, after reboot, the 'used' index should be reset to 0.
            //
            // So let's fetch the used index from the vring as set by the guest here to keep
            // compatibility with the QEMU's vhost-user library just in case, any implementation
            // expects the 'used' index to be set when receiving a SET_VRING_ADDR message.
            //
            // Note: I'm not sure why QEMU's vhost-user library sets the 'user' index here,
            // _probably_ to make sure that the VQ is already configured. A better solution would
            // be to receive the 'used' index in SET_VRING_BASE, as is done when using packed VQs.
            let idx = vring
                .queue_used_idx()
                .map_err(|_| VhostUserError::BackendInternalError)?;
            vring.set_queue_next_used(idx);

            Ok(())
        } else {
            Err(VhostUserError::InvalidParam)
        }
    }

    fn set_vring_base(&mut self, index: u32, base: u32) -> VhostUserResult<()> {
        let vring = self
            .vrings
            .get(index as usize)
            .ok_or_else(|| VhostUserError::InvalidParam)?;

        vring.set_queue_next_avail(base as u16);

        Ok(())
    }

    fn get_vring_base(&mut self, index: u32) -> VhostUserResult<VhostUserVringState> {
        let vring = self
            .vrings
            .get(index as usize)
            .ok_or_else(|| VhostUserError::InvalidParam)?;

        // Quote from vhost-user specification:
        // Client must start ring upon receiving a kick (that is, detecting
        // that file descriptor is readable) on the descriptor specified by
        // VHOST_USER_SET_VRING_KICK, and stop ring upon receiving
        // VHOST_USER_GET_VRING_BASE.
        vring.set_queue_ready(false);

        if let Some(fd) = vring.get_ref().get_kick() {
            for (thread_index, queues_mask) in self.queues_per_thread.iter().enumerate() {
                let shifted_queues_mask = queues_mask >> index;
                if shifted_queues_mask & 1u64 == 1u64 {
                    let evt_idx = queues_mask.count_ones() - shifted_queues_mask.count_ones();
                    self.handlers[thread_index]
                        .unregister_event(fd.as_raw_fd(), EventSet::IN, u64::from(evt_idx))
                        .map_err(VhostUserError::ReqHandlerError)?;
                    break;
                }
            }
        }

        let next_avail = vring.queue_next_avail();

        vring.set_kick(None);
        vring.set_call(None);

        Ok(VhostUserVringState::new(index, u32::from(next_avail)))
    }

    fn set_vring_kick(&mut self, index: u8, file: Option<File>) -> VhostUserResult<()> {
        let vring = self
            .vrings
            .get(index as usize)
            .ok_or_else(|| VhostUserError::InvalidParam)?;

        // SAFETY: EventFd requires that it has sole ownership of its fd. So
        // does File, so this is safe.
        // Ideally, we'd have a generic way to refer to a uniquely-owned fd,
        // such as that proposed by Rust RFC #3128.
        vring.set_kick(file);

        if self.vring_needs_init(vring) {
            self.initialize_vring(vring, index)?;
        }

        Ok(())
    }

    fn set_vring_call(&mut self, index: u8, file: Option<File>) -> VhostUserResult<()> {
        let vring = self
            .vrings
            .get(index as usize)
            .ok_or_else(|| VhostUserError::InvalidParam)?;

        vring.set_call(file);

        if self.vring_needs_init(vring) {
            self.initialize_vring(vring, index)?;
        }

        Ok(())
    }

    fn set_vring_err(&mut self, index: u8, file: Option<File>) -> VhostUserResult<()> {
        let vring = self
            .vrings
            .get(index as usize)
            .ok_or_else(|| VhostUserError::InvalidParam)?;

        vring.set_err(file);

        Ok(())
    }

    fn get_protocol_features(&mut self) -> VhostUserResult<VhostUserProtocolFeatures> {
        Ok(self.backend.protocol_features())
    }

    fn set_protocol_features(&mut self, features: u64) -> VhostUserResult<()> {
        // Note: backend that reported VHOST_USER_F_PROTOCOL_FEATURES must
        // support this message even before VHOST_USER_SET_FEATURES was
        // called.
        self.acked_protocol_features = features;
        Ok(())
    }

    fn get_queue_num(&mut self) -> VhostUserResult<u64> {
        Ok(self.num_queues as u64)
    }

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> VhostUserResult<()> {
        // This request should be handled only when VHOST_USER_F_PROTOCOL_FEATURES
        // has been negotiated.
        self.check_feature(VhostUserVirtioFeatures::PROTOCOL_FEATURES)?;

        let vring = self
            .vrings
            .get(index as usize)
            .ok_or_else(|| VhostUserError::InvalidParam)?;

        // Backend must not pass data to/from the backend until ring is
        // enabled by VHOST_USER_SET_VRING_ENABLE with parameter 1,
        // or after it has been disabled by VHOST_USER_SET_VRING_ENABLE
        // with parameter 0.
        vring.set_enabled(enable);

        Ok(())
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        _flags: VhostUserConfigFlags,
    ) -> VhostUserResult<Vec<u8>> {
        Ok(self.backend.get_config(offset, size))
    }

    fn set_config(
        &mut self,
        offset: u32,
        buf: &[u8],
        _flags: VhostUserConfigFlags,
    ) -> VhostUserResult<()> {
        self.backend
            .set_config(offset, buf)
            .map_err(VhostUserError::ReqHandlerError)
    }

    fn set_backend_req_fd(&mut self, backend: Backend) {
        if self.acked_protocol_features & VhostUserProtocolFeatures::REPLY_ACK.bits() != 0 {
            backend.set_reply_ack_flag(true);
        }
        if self.acked_protocol_features & VhostUserProtocolFeatures::SHARED_OBJECT.bits() != 0 {
            backend.set_shared_object_flag(true);
        }
        self.backend.set_backend_req_fd(backend);
    }

    #[cfg(feature = "gpu-socket")]
    fn set_gpu_socket(&mut self, gpu_backend: GpuBackend) {
        self.backend.set_gpu_socket(gpu_backend);
    }

    fn get_shared_object(&mut self, uuid: VhostUserSharedMsg) -> VhostUserResult<OwnedFd> {
        match self.backend.get_shared_object(uuid) {
            Ok(Some(owned_fd)) => Ok(owned_fd),
            Ok(None) => Err(VhostUserError::IncorrectFds),
            Err(e) => Err(VhostUserError::ReqHandlerError(io::Error::new(
                io::ErrorKind::Other,
                e,
            ))),
        }
    }

    fn get_inflight_fd(
        &mut self,
        _inflight: &vhost::vhost_user::message::VhostUserInflight,
    ) -> VhostUserResult<(vhost::vhost_user::message::VhostUserInflight, File)> {
        // Assume the backend hasn't negotiated the inflight feature; it
        // wouldn't be correct for the backend to do so, as we don't (yet)
        // provide a way for it to handle such requests.
        Err(VhostUserError::InvalidOperation("not supported"))
    }

    fn set_inflight_fd(
        &mut self,
        _inflight: &vhost::vhost_user::message::VhostUserInflight,
        _file: File,
    ) -> VhostUserResult<()> {
        Err(VhostUserError::InvalidOperation("not supported"))
    }

    fn get_max_mem_slots(&mut self) -> VhostUserResult<u64> {
        Ok(MAX_MEM_SLOTS)
    }

    fn add_mem_region(
        &mut self,
        region: &VhostUserSingleMemoryRegion,
        file: File,
    ) -> VhostUserResult<()> {
        let guest_region = Arc::new(
            GuestRegionMmap::new(
                region.mmap_region(file)?,
                GuestAddress(region.guest_phys_addr),
            )
            .map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?,
        );

        let addr_mapping = AddrMapping {
            #[cfg(feature = "postcopy")]
            local_addr: guest_region.as_ptr() as u64,
            vmm_addr: region.user_addr,
            size: region.memory_size,
            gpa_base: region.guest_phys_addr,
        };

        let mem = self
            .atomic_mem
            .memory()
            .insert_region(guest_region)
            .map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;

        self.atomic_mem.lock().unwrap().replace(mem);

        self.backend
            .update_memory(self.atomic_mem.clone())
            .map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;

        self.mappings.push(addr_mapping);

        Ok(())
    }

    fn remove_mem_region(&mut self, region: &VhostUserSingleMemoryRegion) -> VhostUserResult<()> {
        let (mem, _) = self
            .atomic_mem
            .memory()
            .remove_region(GuestAddress(region.guest_phys_addr), region.memory_size)
            .map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;

        self.atomic_mem.lock().unwrap().replace(mem);

        self.backend
            .update_memory(self.atomic_mem.clone())
            .map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;

        self.mappings
            .retain(|mapping| mapping.gpa_base != region.guest_phys_addr);

        Ok(())
    }

    fn set_device_state_fd(
        &mut self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        file: File,
    ) -> VhostUserResult<Option<File>> {
        self.backend
            .set_device_state_fd(direction, phase, file)
            .map_err(VhostUserError::ReqHandlerError)
    }

    fn check_device_state(&mut self) -> VhostUserResult<()> {
        self.backend
            .check_device_state()
            .map_err(VhostUserError::ReqHandlerError)
    }

    #[cfg(feature = "postcopy")]
    fn postcopy_advice(&mut self) -> VhostUserResult<File> {
        let mut uffd_builder = UffdBuilder::new();

        let uffd = uffd_builder
            .close_on_exec(true)
            .non_blocking(true)
            .user_mode_only(false)
            .create()
            .map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;

        // We need to duplicate the uffd fd because we need both
        // to return File with fd and store fd inside uffd.
        //
        // SAFETY:
        // We know that uffd is correctly created.
        // This means fd inside uffd is also a valid fd.
        // Duplicating a valid fd is safe.
        let uffd_dup = unsafe { libc::dup(uffd.as_raw_fd()) };
        if uffd_dup < 0 {
            return Err(VhostUserError::ReqHandlerError(io::Error::last_os_error()));
        }

        // SAFETY:
        // We know that uffd_dup is a valid fd.
        let uffd_file = unsafe { File::from_raw_fd(uffd_dup) };

        self.uffd = Some(uffd);

        Ok(uffd_file)
    }

    #[cfg(feature = "postcopy")]
    fn postcopy_listen(&mut self) -> VhostUserResult<()> {
        let Some(ref uffd) = self.uffd else {
            return Err(VhostUserError::ReqHandlerError(io::Error::new(
                io::ErrorKind::Other,
                "No registered UFFD handler",
            )));
        };

        for mapping in self.mappings.iter() {
            uffd.register(
                mapping.local_addr as *mut libc::c_void,
                mapping.size as usize,
            )
            .map_err(|e| {
                VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e))
            })?;
        }

        Ok(())
    }

    #[cfg(feature = "postcopy")]
    fn postcopy_end(&mut self) -> VhostUserResult<()> {
        self.uffd = None;
        Ok(())
    }

    // Sets logging (i.e., bitmap) shared memory space.
    //
    // During live migration, the front-end may need to track the modifications the back-end
    // makes to the memory mapped regions. The front-end should mark the dirty pages in a log.
    // Once it complies to this logging, it may declare the `VHOST_F_LOG_ALL` vhost feature.
    //
    // If the backend has the `VHOST_USER_PROTOCOL_F_LOG_SHMFD` protocol feature it may receive
    // the `VHOST_USER_SET_LOG_BASE` message. The log memory file descriptor is provided in `file`,
    // the size and offset of shared memory area are provided in the `VhostUserLog` message.
    //
    // See https://qemu-project.gitlab.io/qemu/interop/vhost-user.html#migration.
    // TODO: We ignore the `LOG_ALL` flag on `SET_FEATURES`, so we will continue marking pages as
    // dirty even if the migration fails. We need to disable the logging after receiving  a
    // `SET_FEATURE` without the `LOG_ALL` flag.
    fn set_log_base(&mut self, log: &VhostUserLog, file: File) -> VhostUserResult<()> {
        let mem = self.atomic_mem.memory();

        let logmem = Arc::new(
            MmapLogReg::from_file(file.as_fd(), log.mmap_offset, log.mmap_size)
                .map_err(VhostUserError::ReqHandlerError)?,
        );

        // Let's create all bitmaps first before replacing them, in case any of them fails
        let mut bitmaps = Vec::new();
        for region in mem.iter() {
            let bitmap = <<T as VhostUserBackend>::Bitmap as BitmapReplace>::InnerBitmap::new(
                region,
                Arc::clone(&logmem),
            )
            .map_err(VhostUserError::ReqHandlerError)?;

            bitmaps.push((region, bitmap));
        }

        for (region, bitmap) in bitmaps {
            region.bitmap().replace(bitmap);
        }

        Ok(())
    }
}

impl<T: VhostUserBackend> Drop for VhostUserHandler<T> {
    fn drop(&mut self) {
        // Signal all working threads to exit.
        self.send_exit_event();

        for thread in self.worker_threads.drain(..) {
            if let Err(e) = thread.join() {
                error!("Error in vring worker: {:?}", e);
            }
        }
    }
}
