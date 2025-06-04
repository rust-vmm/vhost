// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard};

use super::connection::Endpoint;
use super::message::*;
use super::{Error, HandlerResult, Result, VhostUserFrontendReqHandler};

use vm_memory::ByteValued;

struct BackendInternal {
    sock: Endpoint<VhostUserMsgHeader<BackendReq>>,

    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,

    // Protocol feature VHOST_USER_PROTOCOL_F_SHARED_OBJECT has been negotiated.
    shared_object_negotiated: bool,

    // whether the endpoint has encountered any failure
    error: Option<i32>,
}

impl BackendInternal {
    fn check_state(&self) -> Result<u64> {
        match self.error {
            Some(e) => Err(Error::SocketBroken(std::io::Error::from_raw_os_error(e))),
            None => Ok(0),
        }
    }

    fn send_message<T: ByteValued>(
        &mut self,
        request: BackendReq,
        body: &T,
        fds: Option<&[RawFd]>,
    ) -> Result<u64> {
        self.check_state()?;

        let len = mem::size_of::<T>();
        let mut hdr = VhostUserMsgHeader::new(request, 0, len as u32);
        if self.reply_ack_negotiated {
            hdr.set_need_reply(true);
        }
        self.sock.send_message(&hdr, body, fds)?;

        self.wait_for_ack(&hdr)
    }

    fn wait_for_ack(&mut self, hdr: &VhostUserMsgHeader<BackendReq>) -> Result<u64> {
        self.check_state()?;
        if !self.reply_ack_negotiated {
            return Ok(0);
        }

        let (reply, body, rfds) = self.sock.recv_body::<VhostUserU64>()?;
        if !reply.is_reply_for(hdr) || rfds.is_some() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if body.value != 0 {
            return Err(Error::FrontendInternalError);
        }

        Ok(body.value)
    }
}

/// Request proxy to send vhost-user backend requests to the frontend through the backend
/// communication channel.
///
/// The [Backend] acts as a message proxy to forward vhost-user backend requests to the
/// frontend through the vhost-user backend communication channel. The forwarded messages will be
/// handled by the [FrontendReqHandler] server.
///
/// [Backend]: struct.Backend.html
/// [FrontendReqHandler]: struct.FrontendReqHandler.html
#[derive(Clone)]
pub struct Backend {
    // underlying Unix domain socket for communication
    node: Arc<Mutex<BackendInternal>>,
}

impl Backend {
    fn new(ep: Endpoint<VhostUserMsgHeader<BackendReq>>) -> Self {
        Backend {
            node: Arc::new(Mutex::new(BackendInternal {
                sock: ep,
                reply_ack_negotiated: false,
                shared_object_negotiated: false,
                error: None,
            })),
        }
    }

    fn node(&self) -> MutexGuard<BackendInternal> {
        self.node.lock().unwrap()
    }

    fn send_message<T: ByteValued>(
        &self,
        request: BackendReq,
        body: &T,
        fds: Option<&[RawFd]>,
    ) -> io::Result<u64> {
        self.node()
            .send_message(request, body, fds)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))
    }

    /// Create a new instance from a `UnixStream` object.
    pub fn from_stream(sock: UnixStream) -> Self {
        Self::new(Endpoint::<VhostUserMsgHeader<BackendReq>>::from_stream(
            sock,
        ))
    }

    /// Set the negotiation state of the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature.
    ///
    /// When the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature has been negotiated,
    /// the "REPLY_ACK" flag will be set in the message header for every backend to frontend request
    /// message.
    pub fn set_reply_ack_flag(&self, enable: bool) {
        self.node().reply_ack_negotiated = enable;
    }

    /// Set the negotiation state of the `VHOST_USER_PROTOCOL_F_SHARED_OBJECT` protocol feature.
    ///
    /// When the `VHOST_USER_PROTOCOL_F_SHARED_OBJECT` protocol feature has been negotiated,
    /// the backend is allowed to send "SHARED_OBJECT_*" messages to the frontend.
    pub fn set_shared_object_flag(&self, enable: bool) {
        self.node().shared_object_negotiated = enable;
    }

    /// Mark endpoint as failed with specified error code.
    pub fn set_failed(&self, error: i32) {
        self.node().error = Some(error);
    }
}

impl VhostUserFrontendReqHandler for Backend {
    /// Forward vhost-user shared-object add request to the frontend.
    fn shared_object_add(&self, uuid: &VhostUserSharedMsg) -> HandlerResult<u64> {
        if !self.node().shared_object_negotiated {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Shared Object feature not negotiated",
            ));
        }
        self.send_message(BackendReq::SHARED_OBJECT_ADD, uuid, None)
    }

    /// Forward vhost-user shared-object remove request to the frontend.
    fn shared_object_remove(&self, uuid: &VhostUserSharedMsg) -> HandlerResult<u64> {
        if !self.node().shared_object_negotiated {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Shared Object feature not negotiated",
            ));
        }
        self.send_message(BackendReq::SHARED_OBJECT_REMOVE, uuid, None)
    }

    /// Forward vhost-user shared-object lookup request to the frontend.
    fn shared_object_lookup(
        &self,
        uuid: &VhostUserSharedMsg,
        fd: &dyn AsRawFd,
    ) -> HandlerResult<u64> {
        if !self.node().shared_object_negotiated {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Shared Object feature not negotiated",
            ));
        }
        self.send_message(
            BackendReq::SHARED_OBJECT_LOOKUP,
            uuid,
            Some(&[fd.as_raw_fd()]),
        )
    }

    /// Forward vhost-user memory map file request to the frontend.
    fn shmem_map(&self, req: &VhostUserMMap, fd: &dyn AsRawFd) -> HandlerResult<u64> {
        self.send_message(BackendReq::SHMEM_MAP, req, Some(&[fd.as_raw_fd()]))
    }

    /// Forward vhost-user memory unmap file request to the frontend.
    fn shmem_unmap(&self, req: &VhostUserMMap) -> HandlerResult<u64> {
        self.send_message(BackendReq::SHMEM_UNMAP, req, None)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::AsRawFd;

    use super::*;

    fn frontend_backend_pair() -> (Endpoint<VhostUserMsgHeader<BackendReq>>, Backend) {
        let (p1, p2) = UnixStream::pair().unwrap();
        let backend = Backend::from_stream(p1);
        let frontend = Endpoint::<VhostUserMsgHeader<BackendReq>>::from_stream(p2);
        (frontend, backend)
    }

    #[test]
    fn test_backend_req_set_failed() {
        let (_, backend) = frontend_backend_pair();

        assert!(backend.node().error.is_none());
        backend.set_failed(libc::EAGAIN);
        assert_eq!(backend.node().error, Some(libc::EAGAIN));
    }

    #[test]
    fn test_backend_req_send_failure() {
        let (_, backend) = frontend_backend_pair();

        backend.set_failed(libc::ECONNRESET);
        backend
            .shared_object_add(&VhostUserSharedMsg::default())
            .unwrap_err();
        backend
            .shared_object_remove(&VhostUserSharedMsg::default())
            .unwrap_err();
        backend.node().error = None;
    }

    #[test]
    fn test_backend_req_recv_negative() {
        let (mut frontend, backend) = frontend_backend_pair();

        let len = mem::size_of::<VhostUserSharedMsg>();
        let mut hdr = VhostUserMsgHeader::new(
            BackendReq::SHARED_OBJECT_ADD,
            VhostUserHeaderFlag::REPLY.bits(),
            len as u32,
        );
        let body = VhostUserU64::new(0);

        frontend
            .send_message(&hdr, &body, Some(&[frontend.as_raw_fd()]))
            .unwrap();
        backend
            .shared_object_add(&VhostUserSharedMsg::default())
            .unwrap_err();

        backend.set_shared_object_flag(true);
        backend
            .shared_object_add(&VhostUserSharedMsg::default())
            .unwrap();

        backend.set_reply_ack_flag(true);
        backend
            .shared_object_add(&VhostUserSharedMsg::default())
            .unwrap_err();

        hdr.set_code(BackendReq::SHARED_OBJECT_REMOVE);
        frontend.send_message(&hdr, &body, None).unwrap();
        backend
            .shared_object_add(&VhostUserSharedMsg::default())
            .unwrap_err();
        hdr.set_code(BackendReq::SHARED_OBJECT_ADD);

        let body = VhostUserU64::new(1);
        frontend.send_message(&hdr, &body, None).unwrap();
        backend
            .shared_object_add(&VhostUserSharedMsg::default())
            .unwrap_err();

        let body = VhostUserU64::new(0);
        frontend.send_message(&hdr, &body, None).unwrap();
        backend
            .shared_object_add(&VhostUserSharedMsg::default())
            .unwrap();
    }

    #[test]
    fn test_shmem_map() {
        let (mut fronted, backend) = frontend_backend_pair();

        let (_, some_fd_to_send) = UnixStream::pair().unwrap();
        let map_request = VhostUserMMap {
            shmid: 0,
            padding: Default::default(),
            fd_offset: 0,
            shm_offset: 1028,
            len: 4096,
            flags: (VhostUserMMapFlags::MAP_R | VhostUserMMapFlags::MAP_W).bits(),
        };

        backend.shmem_map(&map_request, &some_fd_to_send).unwrap();

        let (hdr, request, fd) = fronted.recv_body::<VhostUserMMap>().unwrap();
        assert_eq!(hdr.get_code().unwrap(), BackendReq::SHMEM_MAP);
        assert!(fd.is_some());
        assert_eq!({ request.shm_offset }, { map_request.shm_offset });
        assert_eq!({ request.len }, { map_request.len },);
        assert_eq!({ request.flags }, { map_request.flags });
    }

    #[test]
    fn test_shmem_unmap() {
        let (mut frontend, backend) = frontend_backend_pair();

        let unmap_request = VhostUserMMap {
            shmid: 0,
            padding: Default::default(),
            fd_offset: 0,
            shm_offset: 1028,
            len: 4096,
            flags: 0,
        };

        backend.shmem_unmap(&unmap_request).unwrap();

        let (hdr, request, fd) = frontend.recv_body::<VhostUserMMap>().unwrap();
        assert_eq!(hdr.get_code().unwrap(), BackendReq::SHMEM_UNMAP);
        assert!(fd.is_none());
        assert_eq!({ request.shm_offset }, { unmap_request.shm_offset });
        assert_eq!({ request.len }, { unmap_request.len });
    }
}
