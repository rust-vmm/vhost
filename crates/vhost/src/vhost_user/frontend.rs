// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Traits and Struct for vhost-user frontend.

use std::fs::File;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use vm_memory::ByteValued;
use vmm_sys_util::eventfd::EventFd;

use super::connection::Endpoint;
use super::message::*;
use super::{take_single_file, Error as VhostUserError, Result as VhostUserResult};
use crate::backend::{
    VhostBackend, VhostUserDirtyLogRegion, VhostUserMemoryRegionInfo, VringConfigData,
};
use crate::{Error, Result};

/// Trait for vhost-user frontend to provide extra methods not covered by the VhostBackend yet.
pub trait VhostUserFrontend: VhostBackend {
    /// Get the protocol feature bitmask from the underlying vhost implementation.
    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures>;

    /// Enable protocol features in the underlying vhost implementation.
    fn set_protocol_features(&mut self, features: VhostUserProtocolFeatures) -> Result<()>;

    /// Query how many queues the backend supports.
    fn get_queue_num(&mut self) -> Result<u64>;

    /// Signal backend to enable or disable corresponding vring.
    ///
    /// Backend must not pass data to/from the backend until ring is enabled by
    /// VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has been
    /// disabled by VHOST_USER_SET_VRING_ENABLE with parameter 0.
    fn set_vring_enable(&mut self, queue_index: usize, enable: bool) -> Result<()>;

    /// Fetch the contents of the virtio device configuration space.
    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
        buf: &[u8],
    ) -> Result<(VhostUserConfig, VhostUserConfigPayload)>;

    /// Change the virtio device configuration space. It also can be used for live migration on the
    /// destination host to set readonly configuration space fields.
    fn set_config(&mut self, offset: u32, flags: VhostUserConfigFlags, buf: &[u8]) -> Result<()>;

    /// Setup backend communication channel.
    fn set_backend_request_fd(&mut self, fd: &dyn AsRawFd) -> Result<()>;

    /// Retrieve shared buffer for inflight I/O tracking.
    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)>;

    /// Set shared buffer for inflight I/O tracking.
    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, fd: RawFd) -> Result<()>;

    /// Query the maximum amount of memory slots supported by the backend.
    fn get_max_mem_slots(&mut self) -> Result<u64>;

    /// Add a new guest memory mapping for vhost to use.
    fn add_mem_region(&mut self, region: &VhostUserMemoryRegionInfo) -> Result<()>;

    /// Remove a guest memory mapping from vhost.
    fn remove_mem_region(&mut self, region: &VhostUserMemoryRegionInfo) -> Result<()>;
}

fn error_code<T>(err: VhostUserError) -> Result<T> {
    Err(Error::VhostUserProtocol(err))
}

/// Struct for the vhost-user frontend endpoint.
#[derive(Clone)]
pub struct Frontend {
    node: Arc<Mutex<FrontendInternal>>,
}

impl Frontend {
    /// Create a new instance.
    fn new(ep: Endpoint<FrontendReq>, max_queue_num: u64) -> Self {
        Frontend {
            node: Arc::new(Mutex::new(FrontendInternal {
                main_sock: ep,
                virtio_features: 0,
                acked_virtio_features: 0,
                protocol_features: 0,
                acked_protocol_features: 0,
                protocol_features_ready: false,
                max_queue_num,
                error: None,
                hdr_flags: VhostUserHeaderFlag::empty(),
            })),
        }
    }

    fn node(&self) -> MutexGuard<FrontendInternal> {
        self.node.lock().unwrap()
    }

    /// Create a new instance from a Unix stream socket.
    pub fn from_stream(sock: UnixStream, max_queue_num: u64) -> Self {
        Self::new(Endpoint::<FrontendReq>::from_stream(sock), max_queue_num)
    }

    /// Create a new vhost-user frontend endpoint.
    ///
    /// Will retry as the backend may not be ready to accept the connection.
    ///
    /// # Arguments
    /// * `path` - path of Unix domain socket listener to connect to
    pub fn connect<P: AsRef<Path>>(path: P, max_queue_num: u64) -> Result<Self> {
        let mut retry_count = 5;
        let endpoint = loop {
            match Endpoint::<FrontendReq>::connect(&path) {
                Ok(endpoint) => break Ok(endpoint),
                Err(e) => match &e {
                    VhostUserError::SocketConnect(why) => {
                        if why.kind() == std::io::ErrorKind::ConnectionRefused && retry_count > 0 {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            retry_count -= 1;
                            continue;
                        } else {
                            break Err(e);
                        }
                    }
                    _ => break Err(e),
                },
            }
        }?;

        Ok(Self::new(endpoint, max_queue_num))
    }

    /// Set the header flags that should be applied to all following messages.
    pub fn set_hdr_flags(&self, flags: VhostUserHeaderFlag) {
        let mut node = self.node();
        node.hdr_flags = flags;
    }
}

impl VhostBackend for Frontend {
    /// Get from the underlying vhost implementation the feature bitmask.
    fn get_features(&self) -> Result<u64> {
        let mut node = self.node();
        let hdr = node.send_request_header(FrontendReq::GET_FEATURES, None)?;
        let val = node.recv_reply::<VhostUserU64>(&hdr)?;
        node.virtio_features = val.value;
        Ok(node.virtio_features)
    }

    /// Enable features in the underlying vhost implementation using a bitmask.
    fn set_features(&self, features: u64) -> Result<()> {
        let mut node = self.node();
        let val = VhostUserU64::new(features);
        let hdr = node.send_request_with_body(FrontendReq::SET_FEATURES, &val, None)?;
        node.acked_virtio_features = features & node.virtio_features;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    /// Set the current Frontend as an owner of the session.
    fn set_owner(&self) -> Result<()> {
        // We unwrap() the return value to assert that we are not expecting threads to ever fail
        // while holding the lock.
        let mut node = self.node();
        let hdr = node.send_request_header(FrontendReq::SET_OWNER, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    fn reset_owner(&self) -> Result<()> {
        let mut node = self.node();
        let hdr = node.send_request_header(FrontendReq::RESET_OWNER, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    /// Set the memory map regions on the backend so it can translate the vring
    /// addresses. In the ancillary data there is an array of file descriptors
    fn set_mem_table(&self, regions: &[VhostUserMemoryRegionInfo]) -> Result<()> {
        if regions.is_empty() || regions.len() > MAX_ATTACHED_FD_ENTRIES {
            return error_code(VhostUserError::InvalidParam);
        }

        let mut ctx = VhostUserMemoryContext::new();
        for region in regions.iter() {
            if region.memory_size == 0 || region.mmap_handle < 0 {
                return error_code(VhostUserError::InvalidParam);
            }

            ctx.append(&region.to_region(), region.mmap_handle);
        }

        let mut node = self.node();
        let body = VhostUserMemory::new(ctx.regions.len() as u32);
        // SAFETY: Safe because ctx.regions is a valid Vec() at this point.
        let (_, payload, _) = unsafe { ctx.regions.align_to::<u8>() };
        let hdr = node.send_request_with_payload(
            FrontendReq::SET_MEM_TABLE,
            &body,
            payload,
            Some(ctx.fds.as_slice()),
        )?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    // Clippy doesn't seem to know that if let with && is still experimental
    #[allow(clippy::unnecessary_unwrap)]
    fn set_log_base(&self, base: u64, region: Option<VhostUserDirtyLogRegion>) -> Result<()> {
        let mut node = self.node();
        let val = VhostUserU64::new(base);

        if node.acked_protocol_features & VhostUserProtocolFeatures::LOG_SHMFD.bits() != 0
            && region.is_some()
        {
            let region = region.unwrap();
            let log = VhostUserLog {
                mmap_size: region.mmap_size,
                mmap_offset: region.mmap_offset,
            };
            let hdr = node.send_request_with_body(
                FrontendReq::SET_LOG_BASE,
                &log,
                Some(&[region.mmap_handle]),
            )?;
            node.wait_for_ack(&hdr).map_err(|e| e.into())
        } else {
            let _ = node.send_request_with_body(FrontendReq::SET_LOG_BASE, &val, None)?;
            Ok(())
        }
    }

    fn set_log_fd(&self, fd: RawFd) -> Result<()> {
        let mut node = self.node();
        let fds = [fd];
        let hdr = node.send_request_header(FrontendReq::SET_LOG_FD, Some(&fds))?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    /// Set the size of the queue.
    fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }

        let val = VhostUserVringState::new(queue_index as u32, num.into());
        let hdr = node.send_request_with_body(FrontendReq::SET_VRING_NUM, &val, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    /// Sets the addresses of the different aspects of the vring.
    fn set_vring_addr(&self, queue_index: usize, config_data: &VringConfigData) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num
            || config_data.flags & !(VhostUserVringAddrFlags::all().bits()) != 0
        {
            return error_code(VhostUserError::InvalidParam);
        }

        let val = VhostUserVringAddr::from_config_data(queue_index as u32, config_data);
        let hdr = node.send_request_with_body(FrontendReq::SET_VRING_ADDR, &val, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    /// Sets the base offset in the available vring.
    fn set_vring_base(&self, queue_index: usize, base: u16) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }

        let val = VhostUserVringState::new(queue_index as u32, base.into());
        let hdr = node.send_request_with_body(FrontendReq::SET_VRING_BASE, &val, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    fn get_vring_base(&self, queue_index: usize) -> Result<u32> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }

        let req = VhostUserVringState::new(queue_index as u32, 0);
        let hdr = node.send_request_with_body(FrontendReq::GET_VRING_BASE, &req, None)?;
        let reply = node.recv_reply::<VhostUserVringState>(&hdr)?;
        Ok(reply.num)
    }

    /// Set the event file descriptor to signal when buffers are used.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// will be used instead of waiting for the call.
    fn set_vring_call(&self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }
        let hdr =
            node.send_fd_for_vring(FrontendReq::SET_VRING_CALL, queue_index, fd.as_raw_fd())?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    /// Set the event file descriptor for adding buffers to the vring.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// should be used instead of waiting for a kick.
    fn set_vring_kick(&self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }
        let hdr =
            node.send_fd_for_vring(FrontendReq::SET_VRING_KICK, queue_index, fd.as_raw_fd())?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    /// Set the event file descriptor to signal when error occurs.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data.
    fn set_vring_err(&self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let mut node = self.node();
        if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }
        let hdr =
            node.send_fd_for_vring(FrontendReq::SET_VRING_ERR, queue_index, fd.as_raw_fd())?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }
}

impl VhostUserFrontend for Frontend {
    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures> {
        let mut node = self.node();
        node.check_feature(VhostUserVirtioFeatures::PROTOCOL_FEATURES)?;
        let hdr = node.send_request_header(FrontendReq::GET_PROTOCOL_FEATURES, None)?;
        let val = node.recv_reply::<VhostUserU64>(&hdr)?;
        node.protocol_features = val.value;
        // Should we support forward compatibility?
        // If so just mask out unrecognized flags instead of return errors.
        match VhostUserProtocolFeatures::from_bits(node.protocol_features) {
            Some(val) => Ok(val),
            None => error_code(VhostUserError::InvalidMessage),
        }
    }

    fn set_protocol_features(&mut self, features: VhostUserProtocolFeatures) -> Result<()> {
        let mut node = self.node();
        node.check_feature(VhostUserVirtioFeatures::PROTOCOL_FEATURES)?;
        let val = VhostUserU64::new(features.bits());
        let hdr = node.send_request_with_body(FrontendReq::SET_PROTOCOL_FEATURES, &val, None)?;
        // Don't wait for ACK here because the protocol feature negotiation process hasn't been
        // completed yet.
        node.acked_protocol_features = features.bits();
        node.protocol_features_ready = true;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    fn get_queue_num(&mut self) -> Result<u64> {
        let mut node = self.node();
        node.check_proto_feature(VhostUserProtocolFeatures::MQ)?;

        let hdr = node.send_request_header(FrontendReq::GET_QUEUE_NUM, None)?;
        let val = node.recv_reply::<VhostUserU64>(&hdr)?;
        if val.value > VHOST_USER_MAX_VRINGS {
            return error_code(VhostUserError::InvalidMessage);
        }
        node.max_queue_num = val.value;
        Ok(node.max_queue_num)
    }

    fn set_vring_enable(&mut self, queue_index: usize, enable: bool) -> Result<()> {
        let mut node = self.node();
        // set_vring_enable() is supported only when PROTOCOL_FEATURES has been enabled.
        if node.acked_virtio_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0 {
            return error_code(VhostUserError::InactiveFeature(
                VhostUserVirtioFeatures::PROTOCOL_FEATURES,
            ));
        } else if queue_index as u64 >= node.max_queue_num {
            return error_code(VhostUserError::InvalidParam);
        }

        let flag = enable.into();
        let val = VhostUserVringState::new(queue_index as u32, flag);
        let hdr = node.send_request_with_body(FrontendReq::SET_VRING_ENABLE, &val, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
        buf: &[u8],
    ) -> Result<(VhostUserConfig, VhostUserConfigPayload)> {
        let body = VhostUserConfig::new(offset, size, flags);
        if !body.is_valid() {
            return error_code(VhostUserError::InvalidParam);
        }

        let mut node = self.node();
        // depends on VhostUserProtocolFeatures::CONFIG
        node.check_proto_feature(VhostUserProtocolFeatures::CONFIG)?;

        // vhost-user spec states that:
        // "Frontend payload: virtio device config space"
        // "Backend payload: virtio device config space"
        let hdr = node.send_request_with_payload(FrontendReq::GET_CONFIG, &body, buf, None)?;
        let (body_reply, buf_reply, rfds) =
            node.recv_reply_with_payload::<VhostUserConfig>(&hdr)?;
        if rfds.is_some() {
            return error_code(VhostUserError::InvalidMessage);
        } else if body_reply.size == 0 {
            return error_code(VhostUserError::BackendInternalError);
        } else if body_reply.size != body.size
            || body_reply.size as usize != buf.len()
            || body_reply.offset != body.offset
        {
            return error_code(VhostUserError::InvalidMessage);
        }

        Ok((body_reply, buf_reply))
    }

    fn set_config(&mut self, offset: u32, flags: VhostUserConfigFlags, buf: &[u8]) -> Result<()> {
        if buf.len() > MAX_MSG_SIZE {
            return error_code(VhostUserError::InvalidParam);
        }
        let body = VhostUserConfig::new(offset, buf.len() as u32, flags);
        if !body.is_valid() {
            return error_code(VhostUserError::InvalidParam);
        }

        let mut node = self.node();
        // depends on VhostUserProtocolFeatures::CONFIG
        node.check_proto_feature(VhostUserProtocolFeatures::CONFIG)?;

        let hdr = node.send_request_with_payload(FrontendReq::SET_CONFIG, &body, buf, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    fn set_backend_request_fd(&mut self, fd: &dyn AsRawFd) -> Result<()> {
        let mut node = self.node();
        node.check_proto_feature(VhostUserProtocolFeatures::BACKEND_REQ)?;
        let fds = [fd.as_raw_fd()];
        let hdr = node.send_request_header(FrontendReq::SET_BACKEND_REQ_FD, Some(&fds))?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)> {
        let mut node = self.node();
        node.check_proto_feature(VhostUserProtocolFeatures::INFLIGHT_SHMFD)?;

        let hdr = node.send_request_with_body(FrontendReq::GET_INFLIGHT_FD, inflight, None)?;
        let (inflight, files) = node.recv_reply_with_files::<VhostUserInflight>(&hdr)?;

        match take_single_file(files) {
            Some(file) => Ok((inflight, file)),
            None => error_code(VhostUserError::IncorrectFds),
        }
    }

    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, fd: RawFd) -> Result<()> {
        let mut node = self.node();
        node.check_proto_feature(VhostUserProtocolFeatures::INFLIGHT_SHMFD)?;

        if inflight.mmap_size == 0 || inflight.num_queues == 0 || inflight.queue_size == 0 || fd < 0
        {
            return error_code(VhostUserError::InvalidParam);
        }

        let hdr =
            node.send_request_with_body(FrontendReq::SET_INFLIGHT_FD, inflight, Some(&[fd]))?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    fn get_max_mem_slots(&mut self) -> Result<u64> {
        let mut node = self.node();
        node.check_proto_feature(VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS)?;

        let hdr = node.send_request_header(FrontendReq::GET_MAX_MEM_SLOTS, None)?;
        let val = node.recv_reply::<VhostUserU64>(&hdr)?;

        Ok(val.value)
    }

    fn add_mem_region(&mut self, region: &VhostUserMemoryRegionInfo) -> Result<()> {
        let mut node = self.node();
        node.check_proto_feature(VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS)?;
        if region.memory_size == 0 || region.mmap_handle < 0 {
            return error_code(VhostUserError::InvalidParam);
        }

        let body = region.to_single_region();
        let fds = [region.mmap_handle];
        let hdr = node.send_request_with_body(FrontendReq::ADD_MEM_REG, &body, Some(&fds))?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }

    fn remove_mem_region(&mut self, region: &VhostUserMemoryRegionInfo) -> Result<()> {
        let mut node = self.node();
        node.check_proto_feature(VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS)?;
        if region.memory_size == 0 {
            return error_code(VhostUserError::InvalidParam);
        }

        let body = region.to_single_region();
        let hdr = node.send_request_with_body(FrontendReq::REM_MEM_REG, &body, None)?;
        node.wait_for_ack(&hdr).map_err(|e| e.into())
    }
}

impl AsRawFd for Frontend {
    fn as_raw_fd(&self) -> RawFd {
        let node = self.node();
        node.main_sock.as_raw_fd()
    }
}

/// Context object to pass guest memory configuration to VhostUserFrontend::set_mem_table().
struct VhostUserMemoryContext {
    regions: VhostUserMemoryPayload,
    fds: Vec<RawFd>,
}

impl VhostUserMemoryContext {
    /// Create a context object.
    pub fn new() -> Self {
        VhostUserMemoryContext {
            regions: VhostUserMemoryPayload::new(),
            fds: Vec::new(),
        }
    }

    /// Append a user memory region and corresponding RawFd into the context object.
    pub fn append(&mut self, region: &VhostUserMemoryRegion, fd: RawFd) {
        self.regions.push(*region);
        self.fds.push(fd);
    }
}

struct FrontendInternal {
    // Used to send requests to the backend.
    main_sock: Endpoint<FrontendReq>,
    // Cached virtio features from the backend.
    virtio_features: u64,
    // Cached acked virtio features from the driver.
    acked_virtio_features: u64,
    // Cached vhost-user protocol features from the backend.
    protocol_features: u64,
    // Cached vhost-user protocol features.
    acked_protocol_features: u64,
    // Cached vhost-user protocol features are ready to use.
    protocol_features_ready: bool,
    // Cached maxinum number of queues supported from the backend.
    max_queue_num: u64,
    // Internal flag to mark failure state.
    error: Option<i32>,
    // List of header flags.
    hdr_flags: VhostUserHeaderFlag,
}

impl FrontendInternal {
    fn send_request_header(
        &mut self,
        code: FrontendReq,
        fds: Option<&[RawFd]>,
    ) -> VhostUserResult<VhostUserMsgHeader<FrontendReq>> {
        self.check_state()?;
        let hdr = self.new_request_header(code, 0);
        self.main_sock.send_header(&hdr, fds)?;
        Ok(hdr)
    }

    fn send_request_with_body<T: ByteValued>(
        &mut self,
        code: FrontendReq,
        msg: &T,
        fds: Option<&[RawFd]>,
    ) -> VhostUserResult<VhostUserMsgHeader<FrontendReq>> {
        if mem::size_of::<T>() > MAX_MSG_SIZE {
            return Err(VhostUserError::InvalidParam);
        }
        self.check_state()?;

        let hdr = self.new_request_header(code, mem::size_of::<T>() as u32);
        self.main_sock.send_message(&hdr, msg, fds)?;
        Ok(hdr)
    }

    fn send_request_with_payload<T: ByteValued>(
        &mut self,
        code: FrontendReq,
        msg: &T,
        payload: &[u8],
        fds: Option<&[RawFd]>,
    ) -> VhostUserResult<VhostUserMsgHeader<FrontendReq>> {
        let len = mem::size_of::<T>() + payload.len();
        if len > MAX_MSG_SIZE {
            return Err(VhostUserError::InvalidParam);
        }
        if let Some(fd_arr) = fds {
            if fd_arr.len() > MAX_ATTACHED_FD_ENTRIES {
                return Err(VhostUserError::InvalidParam);
            }
        }
        self.check_state()?;

        let hdr = self.new_request_header(code, len as u32);
        self.main_sock
            .send_message_with_payload(&hdr, msg, payload, fds)?;
        Ok(hdr)
    }

    fn send_fd_for_vring(
        &mut self,
        code: FrontendReq,
        queue_index: usize,
        fd: RawFd,
    ) -> VhostUserResult<VhostUserMsgHeader<FrontendReq>> {
        if queue_index as u64 >= self.max_queue_num {
            return Err(VhostUserError::InvalidParam);
        }
        self.check_state()?;

        // Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag.
        // This flag is set when there is no file descriptor in the ancillary data. This signals
        // that polling will be used instead of waiting for the call.
        let msg = VhostUserU64::new(queue_index as u64);
        let hdr = self.new_request_header(code, mem::size_of::<VhostUserU64>() as u32);
        self.main_sock.send_message(&hdr, &msg, Some(&[fd]))?;
        Ok(hdr)
    }

    fn recv_reply<T: ByteValued + Sized + VhostUserMsgValidator>(
        &mut self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
    ) -> VhostUserResult<T> {
        if mem::size_of::<T>() > MAX_MSG_SIZE || hdr.is_reply() {
            return Err(VhostUserError::InvalidParam);
        }
        self.check_state()?;

        let (reply, body, rfds) = self.main_sock.recv_body::<T>()?;
        if !reply.is_reply_for(hdr) || rfds.is_some() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }
        Ok(body)
    }

    fn recv_reply_with_files<T: ByteValued + Sized + VhostUserMsgValidator>(
        &mut self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
    ) -> VhostUserResult<(T, Option<Vec<File>>)> {
        if mem::size_of::<T>() > MAX_MSG_SIZE || hdr.is_reply() {
            return Err(VhostUserError::InvalidParam);
        }
        self.check_state()?;

        let (reply, body, files) = self.main_sock.recv_body::<T>()?;
        if !reply.is_reply_for(hdr) || files.is_none() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }
        Ok((body, files))
    }

    fn recv_reply_with_payload<T: ByteValued + Sized + VhostUserMsgValidator>(
        &mut self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
    ) -> VhostUserResult<(T, Vec<u8>, Option<Vec<File>>)> {
        if mem::size_of::<T>() > MAX_MSG_SIZE
            || hdr.get_size() as usize <= mem::size_of::<T>()
            || hdr.get_size() as usize > MAX_MSG_SIZE
            || hdr.is_reply()
        {
            return Err(VhostUserError::InvalidParam);
        }
        self.check_state()?;

        let mut buf: Vec<u8> = vec![0; hdr.get_size() as usize - mem::size_of::<T>()];
        let (reply, body, bytes, files) = self.main_sock.recv_payload_into_buf::<T>(&mut buf)?;
        if !reply.is_reply_for(hdr)
            || reply.get_size() as usize != mem::size_of::<T>() + bytes
            || files.is_some()
            || !body.is_valid()
            || bytes != buf.len()
        {
            return Err(VhostUserError::InvalidMessage);
        }

        Ok((body, buf, files))
    }

    fn wait_for_ack(&mut self, hdr: &VhostUserMsgHeader<FrontendReq>) -> VhostUserResult<()> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::REPLY_ACK.bits() == 0
            || !hdr.is_need_reply()
        {
            return Ok(());
        }
        self.check_state()?;

        let (reply, body, rfds) = self.main_sock.recv_body::<VhostUserU64>()?;
        if !reply.is_reply_for(hdr) || rfds.is_some() || !body.is_valid() {
            return Err(VhostUserError::InvalidMessage);
        }
        if body.value != 0 {
            return Err(VhostUserError::BackendInternalError);
        }
        Ok(())
    }

    fn check_feature(&self, feat: VhostUserVirtioFeatures) -> VhostUserResult<()> {
        if self.virtio_features & feat.bits() != 0 {
            Ok(())
        } else {
            Err(VhostUserError::InactiveFeature(feat))
        }
    }

    fn check_proto_feature(&self, feat: VhostUserProtocolFeatures) -> VhostUserResult<()> {
        if self.acked_protocol_features & feat.bits() != 0 {
            Ok(())
        } else {
            Err(VhostUserError::InactiveOperation(feat))
        }
    }

    fn check_state(&self) -> VhostUserResult<()> {
        match self.error {
            Some(e) => Err(VhostUserError::SocketBroken(
                std::io::Error::from_raw_os_error(e),
            )),
            None => Ok(()),
        }
    }

    #[inline]
    fn new_request_header(
        &self,
        request: FrontendReq,
        size: u32,
    ) -> VhostUserMsgHeader<FrontendReq> {
        VhostUserMsgHeader::new(request, self.hdr_flags.bits() | 0x1, size)
    }
}

#[cfg(test)]
mod tests {
    use super::super::connection::Listener;
    use super::*;
    use vmm_sys_util::rand::rand_alphanumerics;

    use std::path::PathBuf;

    fn temp_path() -> PathBuf {
        PathBuf::from(format!(
            "/tmp/vhost_test_{}",
            rand_alphanumerics(8).to_str().unwrap()
        ))
    }

    fn create_pair<P: AsRef<Path>>(path: P) -> (Frontend, Endpoint<FrontendReq>) {
        let listener = Listener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();
        let frontend = Frontend::connect(path, 2).unwrap();
        let backend = listener.accept().unwrap().unwrap();
        (frontend, Endpoint::from_stream(backend))
    }

    #[test]
    fn create_frontend() {
        let path = temp_path();
        let listener = Listener::new(&path, true).unwrap();
        listener.set_nonblocking(true).unwrap();

        let frontend = Frontend::connect(&path, 1).unwrap();
        let mut backend = Endpoint::<FrontendReq>::from_stream(listener.accept().unwrap().unwrap());

        assert!(frontend.as_raw_fd() > 0);
        // Send two messages continuously
        frontend.set_owner().unwrap();
        frontend.reset_owner().unwrap();

        let (hdr, rfds) = backend.recv_header().unwrap();
        assert_eq!(hdr.get_code().unwrap(), FrontendReq::SET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());

        let (hdr, rfds) = backend.recv_header().unwrap();
        assert_eq!(hdr.get_code().unwrap(), FrontendReq::RESET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());
    }

    #[test]
    fn test_create_failure() {
        let path = temp_path();
        let _ = Listener::new(&path, true).unwrap();
        let _ = Listener::new(&path, false).is_err();
        assert!(Frontend::connect(&path, 1).is_err());

        let listener = Listener::new(&path, true).unwrap();
        assert!(Listener::new(&path, false).is_err());
        listener.set_nonblocking(true).unwrap();

        let _frontend = Frontend::connect(&path, 1).unwrap();
        let _backend = listener.accept().unwrap().unwrap();
    }

    #[test]
    fn test_features() {
        let path = temp_path();
        let (frontend, mut peer) = create_pair(path);

        frontend.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code().unwrap(), FrontendReq::SET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(0x15);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = frontend.get_features().unwrap();
        assert_eq!(features, 0x15u64);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        let hdr = VhostUserMsgHeader::new(FrontendReq::SET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(0x15);
        peer.send_message(&hdr, &msg, None).unwrap();
        frontend.set_features(0x15).unwrap();
        let (_hdr, msg, rfds) = peer.recv_body::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
        let val = msg.value;
        assert_eq!(val, 0x15);

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_FEATURES, 0x4, 8);
        let msg = 0x15u32;
        peer.send_message(&hdr, &msg, None).unwrap();
        assert!(frontend.get_features().is_err());
    }

    #[test]
    fn test_protocol_features() {
        let path = temp_path();
        let (mut frontend, mut peer) = create_pair(path);

        frontend.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code().unwrap(), FrontendReq::SET_OWNER);
        assert!(rfds.is_none());

        assert!(frontend.get_protocol_features().is_err());
        assert!(frontend
            .set_protocol_features(VhostUserProtocolFeatures::all())
            .is_err());

        let vfeatures = 0x15 | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(vfeatures);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = frontend.get_features().unwrap();
        assert_eq!(features, vfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        frontend.set_features(vfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_body::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
        let val = msg.value;
        assert_eq!(val, vfeatures);

        let pfeatures = VhostUserProtocolFeatures::all();
        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_PROTOCOL_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(pfeatures.bits());
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = frontend.get_protocol_features().unwrap();
        assert_eq!(features, pfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        frontend.set_protocol_features(pfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_body::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
        let val = msg.value;
        assert_eq!(val, pfeatures.bits());

        let hdr = VhostUserMsgHeader::new(FrontendReq::SET_PROTOCOL_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(pfeatures.bits());
        peer.send_message(&hdr, &msg, None).unwrap();
        assert!(frontend.get_protocol_features().is_err());
    }

    #[test]
    fn test_frontend_set_config_negative() {
        let path = temp_path();
        let (mut frontend, _peer) = create_pair(path);
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

        frontend
            .set_config(0x100, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .unwrap_err();

        {
            let mut node = frontend.node();
            node.virtio_features = 0xffff_ffff;
            node.acked_virtio_features = 0xffff_ffff;
            node.protocol_features = 0xffff_ffff;
            node.acked_protocol_features = 0xffff_ffff;
        }

        frontend
            .set_config(0, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .unwrap();
        frontend
            .set_config(
                VHOST_USER_CONFIG_SIZE,
                VhostUserConfigFlags::WRITABLE,
                &buf[0..4],
            )
            .unwrap_err();
        frontend
            .set_config(0x1000, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .unwrap_err();
        frontend
            .set_config(
                0x100,
                // This is a negative test, so we are setting unexpected flags.
                VhostUserConfigFlags::from_bits_retain(0xffff_ffff),
                &buf[0..4],
            )
            .unwrap_err();
        frontend
            .set_config(VHOST_USER_CONFIG_SIZE, VhostUserConfigFlags::WRITABLE, &buf)
            .unwrap_err();
        frontend
            .set_config(VHOST_USER_CONFIG_SIZE, VhostUserConfigFlags::WRITABLE, &[])
            .unwrap_err();
    }

    fn create_pair2() -> (Frontend, Endpoint<FrontendReq>) {
        let path = temp_path();
        let (frontend, peer) = create_pair(path);

        {
            let mut node = frontend.node();
            node.virtio_features = 0xffff_ffff;
            node.acked_virtio_features = 0xffff_ffff;
            node.protocol_features = 0xffff_ffff;
            node.acked_protocol_features = 0xffff_ffff;
        }

        (frontend, peer)
    }

    #[test]
    fn test_frontend_get_config_negative0() {
        let (mut frontend, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

        let mut hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        hdr.set_code(FrontendReq::GET_FEATURES);
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
        hdr.set_code(FrontendReq::GET_CONFIG);
    }

    #[test]
    fn test_frontend_get_config_negative1() {
        let (mut frontend, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

        let mut hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        hdr.set_reply(false);
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_frontend_get_config_negative2() {
        let (mut frontend, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());
    }

    #[test]
    fn test_frontend_get_config_negative3() {
        let (mut frontend, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.offset = 0;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_frontend_get_config_negative4() {
        let (mut frontend, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.offset = 0x101;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_frontend_get_config_negative5() {
        let (mut frontend, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.offset = (MAX_MSG_SIZE + 1) as u32;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_frontend_get_config_negative6() {
        let (mut frontend, mut peer) = create_pair2();
        let buf = vec![0x0; MAX_MSG_SIZE + 1];

        let hdr = VhostUserMsgHeader::new(FrontendReq::GET_CONFIG, 0x4, 16);
        let mut msg = VhostUserConfig::new(0x100, 4, VhostUserConfigFlags::empty());
        peer.send_message_with_payload(&hdr, &msg, &buf[0..4], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_ok());

        msg.size = 6;
        peer.send_message_with_payload(&hdr, &msg, &buf[0..6], None)
            .unwrap();
        assert!(frontend
            .get_config(0x100, 4, VhostUserConfigFlags::WRITABLE, &buf[0..4])
            .is_err());
    }

    #[test]
    fn test_maset_set_mem_table_failure() {
        let (frontend, _peer) = create_pair2();

        frontend.set_mem_table(&[]).unwrap_err();
        let tables = vec![VhostUserMemoryRegionInfo::default(); MAX_ATTACHED_FD_ENTRIES + 1];
        frontend.set_mem_table(&tables).unwrap_err();
    }
}
