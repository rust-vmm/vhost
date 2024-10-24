// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::mem;
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::slice;
use std::sync::{Arc, Mutex};

use vm_memory::ByteValued;

use super::backend_req::Backend;
use super::connection::Endpoint;
#[cfg(feature = "gpu-socket")]
use super::gpu_backend_req::GpuBackend;
use super::message::*;
use super::{take_single_file, Error, Result};

/// Services provided to the frontend by the backend with interior mutability.
///
/// The [VhostUserBackendReqHandler] trait defines the services provided to the frontend by the backend.
/// And the [VhostUserBackendReqHandlerMut] trait is a helper mirroring [VhostUserBackendReqHandler],
/// but without interior mutability.
/// The vhost-user specification defines a frontend communication channel, by which frontends could
/// request services from backends. The [VhostUserBackendReqHandler] trait defines services provided by
/// backends, and it's used both on the frontend side and backend side.
///
/// - on the frontend side, a stub forwarder implementing [VhostUserBackendReqHandler] will proxy
///   service requests to backends.
/// - on the backend side, the [BackendReqHandler] will forward service requests to a handler
///   implementing [VhostUserBackendReqHandler].
///
/// The [VhostUserBackendReqHandler] trait is design with interior mutability to improve performance
/// for multi-threading.
///
/// [VhostUserBackendReqHandler]: trait.VhostUserBackendReqHandler.html
/// [VhostUserBackendReqHandlerMut]: trait.VhostUserBackendReqHandlerMut.html
/// [BackendReqHandler]: struct.BackendReqHandler.html
#[allow(missing_docs)]
pub trait VhostUserBackendReqHandler {
    fn set_owner(&self) -> Result<()>;
    fn reset_owner(&self) -> Result<()>;
    fn get_features(&self) -> Result<u64>;
    fn set_features(&self, features: u64) -> Result<()>;
    fn set_mem_table(&self, ctx: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()>;
    fn set_vring_num(&self, index: u32, num: u32) -> Result<()>;
    fn set_vring_addr(
        &self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()>;
    fn set_vring_base(&self, index: u32, base: u32) -> Result<()>;
    fn get_vring_base(&self, index: u32) -> Result<VhostUserVringState>;
    fn set_vring_kick(&self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_call(&self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_err(&self, index: u8, fd: Option<File>) -> Result<()>;

    fn get_protocol_features(&self) -> Result<VhostUserProtocolFeatures>;
    fn set_protocol_features(&self, features: u64) -> Result<()>;
    fn get_queue_num(&self) -> Result<u64>;
    fn set_vring_enable(&self, index: u32, enable: bool) -> Result<()>;
    fn get_config(&self, offset: u32, size: u32, flags: VhostUserConfigFlags) -> Result<Vec<u8>>;
    fn set_config(&self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()>;
    fn set_backend_req_fd(&self, _backend: Backend) {}
    fn get_shared_object(&self, uuid: VhostUserSharedMsg) -> Result<OwnedFd>;
    #[cfg(feature = "gpu-socket")]
    fn set_gpu_socket(&self, gpu_backend: GpuBackend);
    fn get_inflight_fd(&self, inflight: &VhostUserInflight) -> Result<(VhostUserInflight, File)>;
    fn set_inflight_fd(&self, inflight: &VhostUserInflight, file: File) -> Result<()>;
    fn get_max_mem_slots(&self) -> Result<u64>;
    fn add_mem_region(&self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()>;
    fn remove_mem_region(&self, region: &VhostUserSingleMemoryRegion) -> Result<()>;
    fn set_device_state_fd(
        &self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        fd: File,
    ) -> Result<Option<File>>;
    fn check_device_state(&self) -> Result<()>;
    #[cfg(feature = "postcopy")]
    fn postcopy_advice(&self) -> Result<File>;
    #[cfg(feature = "postcopy")]
    fn postcopy_listen(&self) -> Result<()>;
    #[cfg(feature = "postcopy")]
    fn postcopy_end(&self) -> Result<()>;
    fn set_log_base(&self, log: &VhostUserLog, file: File) -> Result<()>;
}

/// Services provided to the frontend by the backend without interior mutability.
///
/// This is a helper trait mirroring the [VhostUserBackendReqHandler] trait.
#[allow(missing_docs)]
pub trait VhostUserBackendReqHandlerMut {
    fn set_owner(&mut self) -> Result<()>;
    fn reset_owner(&mut self) -> Result<()>;
    fn get_features(&mut self) -> Result<u64>;
    fn set_features(&mut self, features: u64) -> Result<()>;
    fn set_mem_table(&mut self, ctx: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()>;
    fn set_vring_num(&mut self, index: u32, num: u32) -> Result<()>;
    fn set_vring_addr(
        &mut self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()>;
    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()>;
    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState>;
    fn set_vring_kick(&mut self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_call(&mut self, index: u8, fd: Option<File>) -> Result<()>;
    fn set_vring_err(&mut self, index: u8, fd: Option<File>) -> Result<()>;

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures>;
    fn set_protocol_features(&mut self, features: u64) -> Result<()>;
    fn get_queue_num(&mut self) -> Result<u64>;
    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()>;
    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
    ) -> Result<Vec<u8>>;
    fn set_config(&mut self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()>;
    fn set_backend_req_fd(&mut self, _backend: Backend) {}
    #[cfg(feature = "gpu-socket")]
    fn set_gpu_socket(&mut self, _gpu_backend: GpuBackend);
    fn get_shared_object(&mut self, uuid: VhostUserSharedMsg) -> Result<OwnedFd>;
    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)>;
    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, file: File) -> Result<()>;
    fn get_max_mem_slots(&mut self) -> Result<u64>;
    fn add_mem_region(&mut self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()>;
    fn remove_mem_region(&mut self, region: &VhostUserSingleMemoryRegion) -> Result<()>;
    fn set_device_state_fd(
        &mut self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        fd: File,
    ) -> Result<Option<File>>;
    fn check_device_state(&mut self) -> Result<()>;
    #[cfg(feature = "postcopy")]
    fn postcopy_advice(&mut self) -> Result<File>;
    #[cfg(feature = "postcopy")]
    fn postcopy_listen(&mut self) -> Result<()>;
    #[cfg(feature = "postcopy")]
    fn postcopy_end(&mut self) -> Result<()>;
    fn set_log_base(&mut self, log: &VhostUserLog, file: File) -> Result<()>;
}

impl<T: VhostUserBackendReqHandlerMut> VhostUserBackendReqHandler for Mutex<T> {
    fn set_owner(&self) -> Result<()> {
        self.lock().unwrap().set_owner()
    }

    fn reset_owner(&self) -> Result<()> {
        self.lock().unwrap().reset_owner()
    }

    fn get_features(&self) -> Result<u64> {
        self.lock().unwrap().get_features()
    }

    fn set_features(&self, features: u64) -> Result<()> {
        self.lock().unwrap().set_features(features)
    }

    fn set_mem_table(&self, ctx: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()> {
        self.lock().unwrap().set_mem_table(ctx, files)
    }

    fn set_vring_num(&self, index: u32, num: u32) -> Result<()> {
        self.lock().unwrap().set_vring_num(index, num)
    }

    fn set_vring_addr(
        &self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()> {
        self.lock()
            .unwrap()
            .set_vring_addr(index, flags, descriptor, used, available, log)
    }

    fn set_vring_base(&self, index: u32, base: u32) -> Result<()> {
        self.lock().unwrap().set_vring_base(index, base)
    }

    fn get_vring_base(&self, index: u32) -> Result<VhostUserVringState> {
        self.lock().unwrap().get_vring_base(index)
    }

    fn set_vring_kick(&self, index: u8, fd: Option<File>) -> Result<()> {
        self.lock().unwrap().set_vring_kick(index, fd)
    }

    fn set_vring_call(&self, index: u8, fd: Option<File>) -> Result<()> {
        self.lock().unwrap().set_vring_call(index, fd)
    }

    fn set_vring_err(&self, index: u8, fd: Option<File>) -> Result<()> {
        self.lock().unwrap().set_vring_err(index, fd)
    }

    fn get_protocol_features(&self) -> Result<VhostUserProtocolFeatures> {
        self.lock().unwrap().get_protocol_features()
    }

    fn set_protocol_features(&self, features: u64) -> Result<()> {
        self.lock().unwrap().set_protocol_features(features)
    }

    fn get_queue_num(&self) -> Result<u64> {
        self.lock().unwrap().get_queue_num()
    }

    fn set_vring_enable(&self, index: u32, enable: bool) -> Result<()> {
        self.lock().unwrap().set_vring_enable(index, enable)
    }

    fn get_config(&self, offset: u32, size: u32, flags: VhostUserConfigFlags) -> Result<Vec<u8>> {
        self.lock().unwrap().get_config(offset, size, flags)
    }

    fn set_config(&self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()> {
        self.lock().unwrap().set_config(offset, buf, flags)
    }

    fn set_backend_req_fd(&self, backend: Backend) {
        self.lock().unwrap().set_backend_req_fd(backend)
    }

    fn get_shared_object(&self, uuid: VhostUserSharedMsg) -> Result<OwnedFd> {
        self.lock().unwrap().get_shared_object(uuid)
    }
    #[cfg(feature = "gpu-socket")]
    fn set_gpu_socket(&self, gpu_backend: GpuBackend) {
        self.lock().unwrap().set_gpu_socket(gpu_backend);
    }

    fn get_inflight_fd(&self, inflight: &VhostUserInflight) -> Result<(VhostUserInflight, File)> {
        self.lock().unwrap().get_inflight_fd(inflight)
    }

    fn set_inflight_fd(&self, inflight: &VhostUserInflight, file: File) -> Result<()> {
        self.lock().unwrap().set_inflight_fd(inflight, file)
    }

    fn get_max_mem_slots(&self) -> Result<u64> {
        self.lock().unwrap().get_max_mem_slots()
    }

    fn add_mem_region(&self, region: &VhostUserSingleMemoryRegion, fd: File) -> Result<()> {
        self.lock().unwrap().add_mem_region(region, fd)
    }

    fn remove_mem_region(&self, region: &VhostUserSingleMemoryRegion) -> Result<()> {
        self.lock().unwrap().remove_mem_region(region)
    }

    fn set_device_state_fd(
        &self,
        direction: VhostTransferStateDirection,
        phase: VhostTransferStatePhase,
        fd: File,
    ) -> Result<Option<File>> {
        self.lock()
            .unwrap()
            .set_device_state_fd(direction, phase, fd)
    }

    fn check_device_state(&self) -> Result<()> {
        self.lock().unwrap().check_device_state()
    }

    #[cfg(feature = "postcopy")]
    fn postcopy_advice(&self) -> Result<File> {
        self.lock().unwrap().postcopy_advice()
    }

    #[cfg(feature = "postcopy")]
    fn postcopy_listen(&self) -> Result<()> {
        self.lock().unwrap().postcopy_listen()
    }

    #[cfg(feature = "postcopy")]
    fn postcopy_end(&self) -> Result<()> {
        self.lock().unwrap().postcopy_end()
    }
    fn set_log_base(&self, log: &VhostUserLog, file: File) -> Result<()> {
        self.lock().unwrap().set_log_base(log, file)
    }
}

/// Server to handle service requests from frontends from the frontend communication channel.
///
/// The [BackendReqHandler] acts as a server on the backend side, to handle service requests from
/// frontends on the frontend communication channel. It's actually a proxy invoking the registered
/// handler implementing [VhostUserBackendReqHandler] to do the real work.
///
/// The lifetime of the BackendReqHandler object should be the same as the underline Unix Domain
/// Socket, so it gets simpler to recover from disconnect.
///
/// [VhostUserBackendReqHandler]: trait.VhostUserBackendReqHandler.html
/// [BackendReqHandler]: struct.BackendReqHandler.html
pub struct BackendReqHandler<S: VhostUserBackendReqHandler> {
    // underlying Unix domain socket for communication
    main_sock: Endpoint<VhostUserMsgHeader<FrontendReq>>,
    // the vhost-user backend device object
    backend: Arc<S>,

    virtio_features: u64,
    acked_virtio_features: u64,
    protocol_features: VhostUserProtocolFeatures,
    acked_protocol_features: u64,

    // sending ack for messages without payload
    reply_ack_enabled: bool,
    // whether the endpoint has encountered any failure
    error: Option<i32>,
}

impl<S: VhostUserBackendReqHandler> BackendReqHandler<S> {
    /// Create a vhost-user backend endpoint.
    pub(super) fn new(
        main_sock: Endpoint<VhostUserMsgHeader<FrontendReq>>,
        backend: Arc<S>,
    ) -> Self {
        BackendReqHandler {
            main_sock,
            backend,
            virtio_features: 0,
            acked_virtio_features: 0,
            protocol_features: VhostUserProtocolFeatures::empty(),
            acked_protocol_features: 0,
            reply_ack_enabled: false,
            error: None,
        }
    }

    fn check_feature(&self, feat: VhostUserVirtioFeatures) -> Result<()> {
        if self.acked_virtio_features & feat.bits() != 0 {
            Ok(())
        } else {
            Err(Error::InactiveFeature(feat))
        }
    }

    fn check_proto_feature(&self, feat: VhostUserProtocolFeatures) -> Result<()> {
        if self.acked_protocol_features & feat.bits() != 0 {
            Ok(())
        } else {
            Err(Error::InactiveOperation(feat))
        }
    }

    /// Create a vhost-user backend endpoint from a connected socket.
    pub fn from_stream(socket: UnixStream, backend: Arc<S>) -> Self {
        Self::new(Endpoint::from_stream(socket), backend)
    }

    /// Create a new vhost-user backend endpoint.
    ///
    /// # Arguments
    /// * - `path` - path of Unix domain socket listener to connect to
    /// * - `backend` - handler for requests from the frontend to the backend
    pub fn connect(path: &str, backend: Arc<S>) -> Result<Self> {
        Ok(Self::new(
            Endpoint::<VhostUserMsgHeader<FrontendReq>>::connect(path)?,
            backend,
        ))
    }

    /// Mark endpoint as failed with specified error code.
    pub fn set_failed(&mut self, error: i32) {
        self.error = Some(error);
    }

    /// Main entrance to server backend request from the backend communication channel.
    ///
    /// Receive and handle one incoming request message from the frontend. The caller needs to:
    /// - serialize calls to this function
    /// - decide what to do when error happens
    /// - optional recover from failure
    pub fn handle_request(&mut self) -> Result<()> {
        // Return error if the endpoint is already in failed state.
        self.check_state()?;

        // The underlying communication channel is a Unix domain socket in
        // stream mode, and recvmsg() is a little tricky here. To successfully
        // receive attached file descriptors, we need to receive messages and
        // corresponding attached file descriptors in this way:
        // . recv messsage header and optional attached file
        // . validate message header
        // . recv optional message body and payload according size field in
        //   message header
        // . validate message body and optional payload
        let (hdr, files) = self.main_sock.recv_header()?;
        self.check_attached_files(&hdr, &files)?;

        let (size, buf) = match hdr.get_size() {
            0 => (0, vec![0u8; 0]),
            len => {
                let (size2, rbuf) = self.main_sock.recv_data(len as usize)?;
                if size2 != len as usize {
                    return Err(Error::InvalidMessage);
                }
                (size2, rbuf)
            }
        };

        match hdr.get_code() {
            Ok(FrontendReq::SET_OWNER) => {
                self.check_request_size(&hdr, size, 0)?;
                let res = self.backend.set_owner();
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::RESET_OWNER) => {
                self.check_request_size(&hdr, size, 0)?;
                let res = self.backend.reset_owner();
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::GET_FEATURES) => {
                self.check_request_size(&hdr, size, 0)?;
                let features = self.backend.get_features()?;
                let msg = VhostUserU64::new(features);
                self.send_reply_message(&hdr, &msg)?;
                self.virtio_features = features;
                self.update_reply_ack_flag();
            }
            Ok(FrontendReq::SET_FEATURES) => {
                let msg = self.extract_request_body::<VhostUserU64>(&hdr, size, &buf)?;
                let res = self.backend.set_features(msg.value);
                self.acked_virtio_features = msg.value;
                self.update_reply_ack_flag();
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::SET_MEM_TABLE) => {
                let res = self.set_mem_table(&hdr, size, &buf, files);
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::SET_VRING_NUM) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self.backend.set_vring_num(msg.index, msg.num);
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::SET_VRING_ADDR) => {
                let msg = self.extract_request_body::<VhostUserVringAddr>(&hdr, size, &buf)?;
                let flags = match VhostUserVringAddrFlags::from_bits(msg.flags) {
                    Some(val) => val,
                    None => return Err(Error::InvalidMessage),
                };
                let res = self.backend.set_vring_addr(
                    msg.index,
                    flags,
                    msg.descriptor,
                    msg.used,
                    msg.available,
                    msg.log,
                );
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::SET_VRING_BASE) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self.backend.set_vring_base(msg.index, msg.num);
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::GET_VRING_BASE) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let reply = self.backend.get_vring_base(msg.index)?;
                self.send_reply_message(&hdr, &reply)?;
            }
            Ok(FrontendReq::SET_VRING_CALL) => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_call(index, file);
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::SET_VRING_KICK) => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_kick(index, file);
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::SET_VRING_ERR) => {
                self.check_request_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, file) = self.handle_vring_fd_request(&buf, files)?;
                let res = self.backend.set_vring_err(index, file);
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::GET_PROTOCOL_FEATURES) => {
                self.check_request_size(&hdr, size, 0)?;
                let features = self.backend.get_protocol_features()?;

                // Enable the `XEN_MMAP` protocol feature for backends if xen feature is enabled.
                #[cfg(feature = "xen")]
                let features = features | VhostUserProtocolFeatures::XEN_MMAP;

                let msg = VhostUserU64::new(features.bits());
                self.send_reply_message(&hdr, &msg)?;
                self.protocol_features = features;
                self.update_reply_ack_flag();
            }
            Ok(FrontendReq::SET_PROTOCOL_FEATURES) => {
                let msg = self.extract_request_body::<VhostUserU64>(&hdr, size, &buf)?;
                let res = self.backend.set_protocol_features(msg.value);
                self.acked_protocol_features = msg.value;
                self.update_reply_ack_flag();
                self.send_ack_message(&hdr, res)?;

                #[cfg(feature = "xen")]
                self.check_proto_feature(VhostUserProtocolFeatures::XEN_MMAP)?;
            }
            Ok(FrontendReq::GET_QUEUE_NUM) => {
                self.check_proto_feature(VhostUserProtocolFeatures::MQ)?;
                self.check_request_size(&hdr, size, 0)?;
                let num = self.backend.get_queue_num()?;
                let msg = VhostUserU64::new(num);
                self.send_reply_message(&hdr, &msg)?;
            }
            Ok(FrontendReq::SET_VRING_ENABLE) => {
                let msg = self.extract_request_body::<VhostUserVringState>(&hdr, size, &buf)?;
                self.check_feature(VhostUserVirtioFeatures::PROTOCOL_FEATURES)?;
                let enable = match msg.num {
                    1 => true,
                    0 => false,
                    _ => return Err(Error::InvalidParam),
                };

                let res = self.backend.set_vring_enable(msg.index, enable);
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::GET_CONFIG) => {
                self.check_proto_feature(VhostUserProtocolFeatures::CONFIG)?;
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                self.get_config(&hdr, &buf)?;
            }
            Ok(FrontendReq::SET_CONFIG) => {
                self.check_proto_feature(VhostUserProtocolFeatures::CONFIG)?;
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                let res = self.set_config(size, &buf);
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::SET_BACKEND_REQ_FD) => {
                self.check_proto_feature(VhostUserProtocolFeatures::BACKEND_REQ)?;
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                let res = self.set_backend_req_fd(files);
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::GET_SHARED_OBJECT) => {
                self.check_proto_feature(VhostUserProtocolFeatures::SHARED_OBJECT)?;
                self.check_request_size(&hdr, size, hdr.get_size() as usize)?;
                let msg = self.extract_request_body::<VhostUserSharedMsg>(&hdr, size, &buf)?;
                let res = self.backend.get_shared_object(msg);

                match res {
                    Ok(file) => {
                        let hdr = self.new_reply_header::<VhostUserEmpty>(&hdr, 0)?;
                        self.main_sock.send_message(
                            &hdr,
                            &VhostUserEmpty,
                            Some(&[file.as_raw_fd()]),
                        )?;
                    }
                    Err(_) => {
                        self.main_sock.send_message(&hdr, &VhostUserEmpty, None)?;
                    }
                }
            }
            Ok(FrontendReq::GET_INFLIGHT_FD) => {
                self.check_proto_feature(VhostUserProtocolFeatures::INFLIGHT_SHMFD)?;

                let msg = self.extract_request_body::<VhostUserInflight>(&hdr, size, &buf)?;
                let (inflight, file) = self.backend.get_inflight_fd(&msg)?;
                let reply_hdr = self.new_reply_header::<VhostUserInflight>(&hdr, 0)?;
                self.main_sock
                    .send_message(&reply_hdr, &inflight, Some(&[file.as_raw_fd()]))?;
            }
            Ok(FrontendReq::SET_INFLIGHT_FD) => {
                self.check_proto_feature(VhostUserProtocolFeatures::INFLIGHT_SHMFD)?;
                let file = take_single_file(files).ok_or(Error::IncorrectFds)?;
                let msg = self.extract_request_body::<VhostUserInflight>(&hdr, size, &buf)?;
                let res = self.backend.set_inflight_fd(&msg, file);
                self.send_ack_message(&hdr, res)?;
            }
            #[cfg(feature = "gpu-socket")]
            Ok(FrontendReq::GPU_SET_SOCKET) => {
                let res = self.set_gpu_socket(files);
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::GET_MAX_MEM_SLOTS) => {
                self.check_proto_feature(VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS)?;
                self.check_request_size(&hdr, size, 0)?;
                let num = self.backend.get_max_mem_slots()?;
                let msg = VhostUserU64::new(num);
                self.send_reply_message(&hdr, &msg)?;
            }
            Ok(FrontendReq::ADD_MEM_REG) => {
                self.check_proto_feature(VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS)?;
                let mut files = files.ok_or(Error::InvalidParam)?;
                if files.len() != 1 {
                    return Err(Error::InvalidParam);
                }
                let msg =
                    self.extract_request_body::<VhostUserSingleMemoryRegion>(&hdr, size, &buf)?;
                let res = self.backend.add_mem_region(&msg, files.swap_remove(0));
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::REM_MEM_REG) => {
                self.check_proto_feature(VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS)?;

                let msg =
                    self.extract_request_body::<VhostUserSingleMemoryRegion>(&hdr, size, &buf)?;
                let res = self.backend.remove_mem_region(&msg);
                self.send_ack_message(&hdr, res)?;
            }
            Ok(FrontendReq::SET_DEVICE_STATE_FD) => {
                let file = take_single_file(files).ok_or(Error::IncorrectFds)?;
                let msg =
                    self.extract_request_body::<VhostUserTransferDeviceState>(&hdr, size, &buf)?;
                let reply_hdr = self.new_reply_header::<VhostUserU64>(&hdr, 0)?;

                let direction: VhostTransferStateDirection = msg
                    .direction
                    .try_into()
                    .map_err(|_| Error::InvalidMessage)?;
                let phase: VhostTransferStatePhase =
                    msg.phase.try_into().map_err(|_| Error::InvalidMessage)?;
                let res = self.backend.set_device_state_fd(direction, phase, file);

                // The value returned is both an indication for success, and whether a file
                // descriptor for a back-end-provided channel is returned: Bits 0–7 are 0 on
                // success, and non-zero on error. Bit 8 is the invalid FD flag; this flag is
                // set when there is no file descriptor returned.
                match res {
                    Ok(None) => {
                        let msg = VhostUserU64::new(0x100); // set invalid FD flag
                        self.main_sock.send_message(&reply_hdr, &msg, None)?;
                    }
                    Ok(Some(file)) => {
                        let msg = VhostUserU64::new(0);
                        self.main_sock
                            .send_message(&reply_hdr, &msg, Some(&[file.as_raw_fd()]))?;
                    }
                    Err(_) => {
                        let msg = VhostUserU64::new(0x101);
                        self.main_sock.send_message(&reply_hdr, &msg, None)?;
                    }
                }
            }
            Ok(FrontendReq::CHECK_DEVICE_STATE) => {
                let res = self.backend.check_device_state();

                // We must return a value in the payload to indicate success or error:
                // 0 is success, any non-zero value is an error.
                let msg = match res {
                    Ok(_) => VhostUserU64::new(0),
                    Err(_) => VhostUserU64::new(1),
                };
                self.send_reply_message(&hdr, &msg)?;
            }
            #[cfg(feature = "postcopy")]
            Ok(FrontendReq::POSTCOPY_ADVISE) => {
                self.check_proto_feature(VhostUserProtocolFeatures::PAGEFAULT)?;

                let res = self.backend.postcopy_advice();
                match res {
                    Ok(uffd_file) => {
                        let hdr = self.new_reply_header::<VhostUserEmpty>(&hdr, 0)?;
                        self.main_sock.send_message(
                            &hdr,
                            &VhostUserEmpty,
                            Some(&[uffd_file.as_raw_fd()]),
                        )?
                    }
                    Err(_) => self.main_sock.send_message(&hdr, &VhostUserEmpty, None)?,
                }
            }
            #[cfg(feature = "postcopy")]
            Ok(FrontendReq::POSTCOPY_LISTEN) => {
                self.check_proto_feature(VhostUserProtocolFeatures::PAGEFAULT)?;
                let res = self.backend.postcopy_listen();
                self.send_ack_message(&hdr, res)?;
            }
            #[cfg(feature = "postcopy")]
            Ok(FrontendReq::POSTCOPY_END) => {
                self.check_proto_feature(VhostUserProtocolFeatures::PAGEFAULT)?;
                let res = self.backend.postcopy_end();
                self.send_ack_message(&hdr, res)?;
            }
            // Sets logging shared memory space.
            // When the back-end has `VHOST_USER_PROTOCOL_F_LOG_SHMFD` protocol feature, the log
            // memory `fd` is provided in the ancillary data of `VHOST_USER_SET_LOG_BASE` message,
            // the size and offset of shared memory area provided in the message.
            // See https://qemu-project.gitlab.io/qemu/interop/vhost-user.html#migration.
            Ok(FrontendReq::SET_LOG_BASE) => {
                self.check_proto_feature(VhostUserProtocolFeatures::LOG_SHMFD)?;
                let file = take_single_file(files).ok_or(Error::IncorrectFds)?;
                let msg = self.extract_request_body::<VhostUserLog>(&hdr, size, &buf)?;
                self.backend.set_log_base(&msg, file)?;
                self.send_reply_message(&hdr, &msg)?;
            }
            _ => {
                return Err(Error::InvalidMessage);
            }
        }
        Ok(())
    }

    fn set_mem_table(
        &mut self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
        size: usize,
        buf: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<()> {
        self.check_request_size(hdr, size, hdr.get_size() as usize)?;

        // check message size is consistent
        let hdrsize = mem::size_of::<VhostUserMemory>();
        if size < hdrsize {
            return Err(Error::InvalidMessage);
        }
        // SAFETY: Safe because we checked that `buf` size is at least that of
        // VhostUserMemory.
        let msg = unsafe { &*(buf.as_ptr() as *const VhostUserMemory) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if size != hdrsize + msg.num_regions as usize * mem::size_of::<VhostUserMemoryRegion>() {
            return Err(Error::InvalidMessage);
        }

        // validate number of fds matching number of memory regions
        let files = files.ok_or(Error::InvalidMessage)?;
        if files.len() != msg.num_regions as usize {
            return Err(Error::InvalidMessage);
        }

        // Validate memory regions
        //
        // SAFETY: Safe because we checked that `buf` size is equal to that of
        // VhostUserMemory, plus `msg.num_regions` elements of VhostUserMemoryRegion.
        let regions = unsafe {
            slice::from_raw_parts(
                buf.as_ptr().add(hdrsize) as *const VhostUserMemoryRegion,
                msg.num_regions as usize,
            )
        };
        for region in regions.iter() {
            if !region.is_valid() {
                return Err(Error::InvalidMessage);
            }
        }

        self.backend.set_mem_table(regions, files)
    }

    fn get_config(&mut self, hdr: &VhostUserMsgHeader<FrontendReq>, buf: &[u8]) -> Result<()> {
        let payload_offset = mem::size_of::<VhostUserConfig>();
        if buf.len() > MAX_MSG_SIZE || buf.len() < payload_offset {
            return Err(Error::InvalidMessage);
        }
        // SAFETY: Safe because we checked that `buf` size is at least that of VhostUserConfig.
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const VhostUserConfig) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if buf.len() - payload_offset != msg.size as usize {
            return Err(Error::InvalidMessage);
        }
        let flags = match VhostUserConfigFlags::from_bits(msg.flags) {
            Some(val) => val,
            None => return Err(Error::InvalidMessage),
        };
        let res = self.backend.get_config(msg.offset, msg.size, flags);

        // vhost-user backend's payload size MUST match frontend's request
        // on success, uses zero length of payload to indicate an error
        // to vhost-user frontend.
        match res {
            Ok(ref buf) if buf.len() == msg.size as usize => {
                let reply = VhostUserConfig::new(msg.offset, buf.len() as u32, flags);
                self.send_reply_with_payload(hdr, &reply, buf.as_slice())?;
            }
            Ok(_) => {
                let reply = VhostUserConfig::new(msg.offset, 0, flags);
                self.send_reply_message(hdr, &reply)?;
            }
            Err(_) => {
                let reply = VhostUserConfig::new(msg.offset, 0, flags);
                self.send_reply_message(hdr, &reply)?;
            }
        }
        Ok(())
    }

    fn set_config(&mut self, size: usize, buf: &[u8]) -> Result<()> {
        if size > MAX_MSG_SIZE || size < mem::size_of::<VhostUserConfig>() {
            return Err(Error::InvalidMessage);
        }
        // SAFETY: Safe because we checked that `buf` size is at least that of VhostUserConfig.
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const VhostUserConfig) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if size - mem::size_of::<VhostUserConfig>() != msg.size as usize {
            return Err(Error::InvalidMessage);
        }
        let flags = VhostUserConfigFlags::from_bits(msg.flags).ok_or(Error::InvalidMessage)?;

        self.backend
            .set_config(msg.offset, &buf[mem::size_of::<VhostUserConfig>()..], flags)
    }

    fn set_backend_req_fd(&mut self, files: Option<Vec<File>>) -> Result<()> {
        let file = take_single_file(files).ok_or(Error::InvalidMessage)?;
        // SAFETY: Safe because we have ownership of the files that were
        // checked when received. We have to trust that they are Unix sockets
        // since we have no way to check this. If not, it will fail later.
        let sock = unsafe { UnixStream::from_raw_fd(file.into_raw_fd()) };
        let backend = Backend::from_stream(sock);
        self.backend.set_backend_req_fd(backend);
        Ok(())
    }

    #[cfg(feature = "gpu-socket")]
    fn set_gpu_socket(&mut self, files: Option<Vec<File>>) -> Result<()> {
        let file = take_single_file(files).ok_or(Error::InvalidMessage)?;
        // SAFETY: Safe because we have ownership of the files that were
        // checked when received. We have to trust that they are Unix sockets
        // since we have no way to check this. If not, it will fail later.
        let sock = unsafe { UnixStream::from_raw_fd(file.into_raw_fd()) };
        let gpu_backend = GpuBackend::from_stream(sock);
        self.backend.set_gpu_socket(gpu_backend);
        Ok(())
    }

    fn handle_vring_fd_request(
        &mut self,
        buf: &[u8],
        files: Option<Vec<File>>,
    ) -> Result<(u8, Option<File>)> {
        if buf.len() > MAX_MSG_SIZE || buf.len() < mem::size_of::<VhostUserU64>() {
            return Err(Error::InvalidMessage);
        }
        // SAFETY: Safe because we checked that `buf` size is at least that of VhostUserU64.
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const VhostUserU64) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }

        // Bits (0-7) of the payload contain the vring index. Bit 8 is the
        // invalid FD flag. This bit is set when there is no file descriptor
        // in the ancillary data. This signals that polling will be used
        // instead of waiting for the call.
        // If Bit 8 is unset, the data must contain a file descriptor.
        let has_fd = (msg.value & 0x100u64) == 0;

        let file = take_single_file(files);

        if has_fd && file.is_none() || !has_fd && file.is_some() {
            return Err(Error::InvalidMessage);
        }

        Ok((msg.value as u8, file))
    }

    fn check_state(&self) -> Result<()> {
        match self.error {
            Some(e) => Err(Error::SocketBroken(std::io::Error::from_raw_os_error(e))),
            None => Ok(()),
        }
    }

    fn check_request_size(
        &self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
        size: usize,
        expected: usize,
    ) -> Result<()> {
        if hdr.get_size() as usize != expected
            || hdr.is_reply()
            || hdr.get_version() != 0x1
            || size != expected
        {
            return Err(Error::InvalidMessage);
        }
        Ok(())
    }

    fn check_attached_files(
        &self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
        files: &Option<Vec<File>>,
    ) -> Result<()> {
        match hdr.get_code() {
            Ok(
                FrontendReq::SET_MEM_TABLE
                | FrontendReq::SET_VRING_CALL
                | FrontendReq::SET_VRING_KICK
                | FrontendReq::SET_VRING_ERR
                | FrontendReq::SET_LOG_BASE
                | FrontendReq::SET_LOG_FD
                | FrontendReq::SET_BACKEND_REQ_FD
                | FrontendReq::SET_INFLIGHT_FD
                | FrontendReq::ADD_MEM_REG
                | FrontendReq::SET_DEVICE_STATE_FD
                | FrontendReq::GPU_SET_SOCKET,
            ) => Ok(()),
            _ if files.is_some() => Err(Error::InvalidMessage),
            _ => Ok(()),
        }
    }

    fn extract_request_body<T: Sized + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<FrontendReq>,
        size: usize,
        buf: &[u8],
    ) -> Result<T> {
        self.check_request_size(hdr, size, mem::size_of::<T>())?;
        // SAFETY: Safe because we checked that `buf` size is equal to T size.
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const T) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        Ok(msg)
    }

    fn update_reply_ack_flag(&mut self) {
        let vflag = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let pflag = VhostUserProtocolFeatures::REPLY_ACK;

        self.reply_ack_enabled = (self.virtio_features & vflag) != 0
            && self.protocol_features.contains(pflag)
            && (self.acked_protocol_features & pflag.bits()) != 0;
    }

    fn new_reply_header<T: Sized>(
        &self,
        req: &VhostUserMsgHeader<FrontendReq>,
        payload_size: usize,
    ) -> Result<VhostUserMsgHeader<FrontendReq>> {
        if mem::size_of::<T>() > MAX_MSG_SIZE
            || payload_size > MAX_MSG_SIZE
            || mem::size_of::<T>() + payload_size > MAX_MSG_SIZE
        {
            return Err(Error::InvalidParam);
        }
        self.check_state()?;
        Ok(VhostUserMsgHeader::new(
            req.get_code()?,
            VhostUserHeaderFlag::REPLY.bits(),
            (mem::size_of::<T>() + payload_size) as u32,
        ))
    }

    fn send_ack_message(
        &mut self,
        req: &VhostUserMsgHeader<FrontendReq>,
        res: Result<()>,
    ) -> Result<()> {
        if self.reply_ack_enabled && req.is_need_reply() {
            let hdr = self.new_reply_header::<VhostUserU64>(req, 0)?;
            let val = match res {
                Ok(_) => 0,
                Err(_) => 1,
            };
            let msg = VhostUserU64::new(val);
            self.main_sock.send_message(&hdr, &msg, None)?;
        }
        res
    }

    fn send_reply_message<T: ByteValued>(
        &mut self,
        req: &VhostUserMsgHeader<FrontendReq>,
        msg: &T,
    ) -> Result<()> {
        let hdr = self.new_reply_header::<T>(req, 0)?;
        self.main_sock.send_message(&hdr, msg, None)?;
        Ok(())
    }

    fn send_reply_with_payload<T: ByteValued>(
        &mut self,
        req: &VhostUserMsgHeader<FrontendReq>,
        msg: &T,
        payload: &[u8],
    ) -> Result<()> {
        let hdr = self.new_reply_header::<T>(req, payload.len())?;
        self.main_sock
            .send_message_with_payload(&hdr, msg, payload, None)?;
        Ok(())
    }
}

impl<S: VhostUserBackendReqHandler> AsRawFd for BackendReqHandler<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.main_sock.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::AsRawFd;

    use super::*;
    use crate::vhost_user::dummy_backend::DummyBackendReqHandler;

    #[test]
    fn test_backend_req_handler_new() {
        let (p1, _p2) = UnixStream::pair().unwrap();
        let endpoint = Endpoint::<VhostUserMsgHeader<FrontendReq>>::from_stream(p1);
        let backend = Arc::new(Mutex::new(DummyBackendReqHandler::new()));
        let mut handler = BackendReqHandler::new(endpoint, backend);

        handler.check_state().unwrap();
        handler.set_failed(libc::EAGAIN);
        handler.check_state().unwrap_err();
        assert!(handler.as_raw_fd() >= 0);
    }
}
