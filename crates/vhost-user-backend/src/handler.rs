// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2019-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::error;
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::thread;

use vhost::vhost_user::message::{
    VhostUserConfigFlags, VhostUserMemoryRegion, VhostUserProtocolFeatures,
    VhostUserSingleMemoryRegion, VhostUserVirtioFeatures, VhostUserVringAddrFlags,
    VhostUserVringState,
};
use vhost::vhost_user::{
    Error as VhostUserError, Result as VhostUserResult, SlaveFsCacheReq,
    VhostUserSlaveReqHandlerMut,
};
use virtio_bindings::bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use virtio_queue::{Error as VirtQueError, QueueT};
use vm_memory::bitmap::Bitmap;
use vm_memory::mmap::NewBitmap;
use vm_memory::{
    FileOffset, GuestAddress, GuestAddressSpace, GuestMemoryMmap, GuestRegionMmap, MmapRegion,
};
use vmm_sys_util::epoll::EventSet;

use super::backend::VhostUserBackend;
use super::event_loop::VringEpollHandler;
use super::event_loop::{VringEpollError, VringEpollResult};
use super::vring::VringT;
use super::GM;

const MAX_MEM_SLOTS: u64 = 32;

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

struct AddrMapping {
    vmm_addr: u64,
    size: u64,
    gpa_base: u64,
}

pub struct VhostUserHandler<S, V, B: Bitmap + 'static> {
    backend: S,
    handlers: Vec<Arc<VringEpollHandler<S, V, B>>>,
    owned: bool,
    features_acked: bool,
    acked_features: u64,
    acked_protocol_features: u64,
    num_queues: usize,
    max_queue_size: usize,
    queues_per_thread: Vec<u64>,
    mappings: Vec<AddrMapping>,
    atomic_mem: GM<B>,
    vrings: Vec<V>,
    worker_threads: Vec<thread::JoinHandle<VringEpollResult<()>>>,
}

// Ensure VhostUserHandler: Clone + Send + Sync + 'static.
impl<S, V, B> VhostUserHandler<S, V, B>
where
    S: VhostUserBackend<V, B> + Clone + 'static,
    V: VringT<GM<B>> + Clone + Send + Sync + 'static,
    B: Bitmap + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(backend: S, atomic_mem: GM<B>) -> VhostUserHandlerResult<Self> {
        let num_queues = backend.num_queues();
        let max_queue_size = backend.max_queue_size();
        let queues_per_thread = backend.queues_per_thread();

        let mut vrings = Vec::new();
        for _ in 0..num_queues {
            let vring = V::new(atomic_mem.clone(), max_queue_size as u16)
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
            worker_threads,
        })
    }
}

impl<S, V, B: Bitmap> VhostUserHandler<S, V, B> {
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

impl<S, V, B> VhostUserHandler<S, V, B>
where
    S: VhostUserBackend<V, B>,
    V: VringT<GM<B>>,
    B: Bitmap,
{
    pub(crate) fn get_epoll_handlers(&self) -> Vec<Arc<VringEpollHandler<S, V, B>>> {
        self.handlers.clone()
    }

    fn vring_needs_init(&self, vring: &V) -> bool {
        let vring_state = vring.get_ref();

        // If the vring wasn't initialized and we already have an EventFd for
        // VRING_KICK, initialize it now.
        !vring_state.get_queue().ready() && vring_state.get_kick().is_some()
    }

    fn initialize_vring(&self, vring: &V, index: u8) -> VhostUserResult<()> {
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

        self.vrings[index as usize].set_queue_ready(true);

        Ok(())
    }
}

impl<S, V, B> VhostUserSlaveReqHandlerMut for VhostUserHandler<S, V, B>
where
    S: VhostUserBackend<V, B>,
    V: VringT<GM<B>>,
    B: NewBitmap + Clone,
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

        // If VHOST_USER_F_PROTOCOL_FEATURES has not been negotiated,
        // the ring is initialized in an enabled state.
        // If VHOST_USER_F_PROTOCOL_FEATURES has been negotiated,
        // the ring is initialized in a disabled state. Client must not
        // pass data to/from the backend until ring is enabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has
        // been disabled by VHOST_USER_SET_VRING_ENABLE with parameter 0.
        let vring_enabled =
            self.acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0;
        for vring in self.vrings.iter_mut() {
            vring.set_enabled(vring_enabled);
        }

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
        let mut regions: Vec<(GuestAddress, usize, Option<FileOffset>)> = Vec::new();
        let mut mappings: Vec<AddrMapping> = Vec::new();

        for (region, file) in ctx.iter().zip(files) {
            let g_addr = GuestAddress(region.guest_phys_addr);
            let len = region.memory_size as usize;
            let f_off = FileOffset::new(file, region.mmap_offset);

            regions.push((g_addr, len, Some(f_off)));
            mappings.push(AddrMapping {
                vmm_addr: region.user_addr,
                size: region.memory_size,
                gpa_base: region.guest_phys_addr,
            });
        }

        let mem = GuestMemoryMmap::from_ranges_with_files(regions).map_err(|e| {
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
        if index as usize >= self.num_queues || num == 0 || num as usize > self.max_queue_size {
            return Err(VhostUserError::InvalidParam);
        }
        self.vrings[index as usize].set_queue_size(num as u16);
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
        if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }

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
            self.vrings[index as usize]
                .set_queue_info(desc_table, avail_ring, used_ring)
                .map_err(|_| VhostUserError::InvalidParam)?;
            Ok(())
        } else {
            Err(VhostUserError::InvalidParam)
        }
    }

    fn set_vring_base(&mut self, index: u32, base: u32) -> VhostUserResult<()> {
        let event_idx: bool = (self.acked_features & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;

        self.vrings[index as usize].set_queue_next_avail(base as u16);
        self.vrings[index as usize].set_queue_event_idx(event_idx);
        self.backend.set_event_idx(event_idx);

        Ok(())
    }

    fn get_vring_base(&mut self, index: u32) -> VhostUserResult<VhostUserVringState> {
        if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }
        // Quote from vhost-user specification:
        // Client must start ring upon receiving a kick (that is, detecting
        // that file descriptor is readable) on the descriptor specified by
        // VHOST_USER_SET_VRING_KICK, and stop ring upon receiving
        // VHOST_USER_GET_VRING_BASE.
        self.vrings[index as usize].set_queue_ready(false);
        if let Some(fd) = self.vrings[index as usize].get_ref().get_kick() {
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

        self.vrings[index as usize].set_kick(None);
        self.vrings[index as usize].set_call(None);

        // Strictly speaking, we should do this upon receiving the first kick,
        // but it's actually easier to just do it here so we're ready in case
        // the vring gets re-initialized by the guest.
        self.vrings[index as usize]
            .get_mut()
            .get_queue_mut()
            .reset();

        let next_avail = self.vrings[index as usize].queue_next_avail();

        Ok(VhostUserVringState::new(index, u32::from(next_avail)))
    }

    fn set_vring_kick(&mut self, index: u8, file: Option<File>) -> VhostUserResult<()> {
        if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }

        // SAFETY: EventFd requires that it has sole ownership of its fd. So
        // does File, so this is safe.
        // Ideally, we'd have a generic way to refer to a uniquely-owned fd,
        // such as that proposed by Rust RFC #3128.
        self.vrings[index as usize].set_kick(file);

        if self.vring_needs_init(&self.vrings[index as usize]) {
            self.initialize_vring(&self.vrings[index as usize], index)?;
        }

        Ok(())
    }

    fn set_vring_call(&mut self, index: u8, file: Option<File>) -> VhostUserResult<()> {
        if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }

        self.vrings[index as usize].set_call(file);

        if self.vring_needs_init(&self.vrings[index as usize]) {
            self.initialize_vring(&self.vrings[index as usize], index)?;
        }

        Ok(())
    }

    fn set_vring_err(&mut self, index: u8, file: Option<File>) -> VhostUserResult<()> {
        if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }

        self.vrings[index as usize].set_err(file);

        Ok(())
    }

    fn get_protocol_features(&mut self) -> VhostUserResult<VhostUserProtocolFeatures> {
        Ok(self.backend.protocol_features())
    }

    fn set_protocol_features(&mut self, features: u64) -> VhostUserResult<()> {
        // Note: slave that reported VHOST_USER_F_PROTOCOL_FEATURES must
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
        if self.acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0 {
            return Err(VhostUserError::InvalidOperation(
                "protocol features not set",
            ));
        } else if index as usize >= self.num_queues {
            return Err(VhostUserError::InvalidParam);
        }

        // Slave must not pass data to/from the backend until ring is
        // enabled by VHOST_USER_SET_VRING_ENABLE with parameter 1,
        // or after it has been disabled by VHOST_USER_SET_VRING_ENABLE
        // with parameter 0.
        self.vrings[index as usize].set_enabled(enable);

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

    fn set_slave_req_fd(&mut self, vu_req: SlaveFsCacheReq) {
        if self.acked_protocol_features & VhostUserProtocolFeatures::REPLY_ACK.bits() != 0 {
            vu_req.set_reply_ack_flag(true);
        }

        self.backend.set_slave_req_fd(vu_req);
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
        let mmap_region = MmapRegion::from_file(
            FileOffset::new(file, region.mmap_offset),
            region.memory_size as usize,
        )
        .map_err(|e| VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e)))?;
        let guest_region = Arc::new(
            GuestRegionMmap::new(mmap_region, GuestAddress(region.guest_phys_addr)).map_err(
                |e| VhostUserError::ReqHandlerError(io::Error::new(io::ErrorKind::Other, e)),
            )?,
        );

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

        self.mappings.push(AddrMapping {
            vmm_addr: region.user_addr,
            size: region.memory_size,
            gpa_base: region.guest_phys_addr,
        });

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
}

impl<S, V, B: Bitmap> Drop for VhostUserHandler<S, V, B> {
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
