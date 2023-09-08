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
    sock: Endpoint<BackendReq>,

    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,

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
    fn new(ep: Endpoint<BackendReq>) -> Self {
        Backend {
            node: Arc::new(Mutex::new(BackendInternal {
                sock: ep,
                reply_ack_negotiated: false,
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
        Self::new(Endpoint::<BackendReq>::from_stream(sock))
    }

    /// Set the negotiation state of the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature.
    ///
    /// When the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature has been negotiated,
    /// the "REPLY_ACK" flag will be set in the message header for every backend to frontend request
    /// message.
    pub fn set_reply_ack_flag(&self, enable: bool) {
        self.node().reply_ack_negotiated = enable;
    }

    /// Mark endpoint as failed with specified error code.
    pub fn set_failed(&self, error: i32) {
        self.node().error = Some(error);
    }
}

impl VhostUserFrontendReqHandler for Backend {
    /// Forward vhost-user-fs map file requests to the backend.
    fn fs_backend_map(&self, fs: &VhostUserFSBackendMsg, fd: &dyn AsRawFd) -> HandlerResult<u64> {
        self.send_message(BackendReq::FS_MAP, fs, Some(&[fd.as_raw_fd()]))
    }

    /// Forward vhost-user-fs unmap file requests to the frontend.
    fn fs_backend_unmap(&self, fs: &VhostUserFSBackendMsg) -> HandlerResult<u64> {
        self.send_message(BackendReq::FS_UNMAP, fs, None)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::AsRawFd;

    use super::*;

    #[test]
    fn test_backend_req_set_failed() {
        let (p1, _p2) = UnixStream::pair().unwrap();
        let backend = Backend::from_stream(p1);

        assert!(backend.node().error.is_none());
        backend.set_failed(libc::EAGAIN);
        assert_eq!(backend.node().error, Some(libc::EAGAIN));
    }

    #[test]
    fn test_backend_req_send_failure() {
        let (p1, p2) = UnixStream::pair().unwrap();
        let backend = Backend::from_stream(p1);

        backend.set_failed(libc::ECONNRESET);
        backend
            .fs_backend_map(&VhostUserFSBackendMsg::default(), &p2)
            .unwrap_err();
        backend
            .fs_backend_unmap(&VhostUserFSBackendMsg::default())
            .unwrap_err();
        backend.node().error = None;
    }

    #[test]
    fn test_backend_req_recv_negative() {
        let (p1, p2) = UnixStream::pair().unwrap();
        let backend = Backend::from_stream(p1);
        let mut frontend = Endpoint::<BackendReq>::from_stream(p2);

        let len = mem::size_of::<VhostUserFSBackendMsg>();
        let mut hdr = VhostUserMsgHeader::new(
            BackendReq::FS_MAP,
            VhostUserHeaderFlag::REPLY.bits(),
            len as u32,
        );
        let body = VhostUserU64::new(0);

        frontend
            .send_message(&hdr, &body, Some(&[frontend.as_raw_fd()]))
            .unwrap();
        backend
            .fs_backend_map(&VhostUserFSBackendMsg::default(), &frontend)
            .unwrap();

        backend.set_reply_ack_flag(true);
        backend
            .fs_backend_map(&VhostUserFSBackendMsg::default(), &frontend)
            .unwrap_err();

        hdr.set_code(BackendReq::FS_UNMAP);
        frontend.send_message(&hdr, &body, None).unwrap();
        backend
            .fs_backend_map(&VhostUserFSBackendMsg::default(), &frontend)
            .unwrap_err();
        hdr.set_code(BackendReq::FS_MAP);

        let body = VhostUserU64::new(1);
        frontend.send_message(&hdr, &body, None).unwrap();
        backend
            .fs_backend_map(&VhostUserFSBackendMsg::default(), &frontend)
            .unwrap_err();

        let body = VhostUserU64::new(0);
        frontend.send_message(&hdr, &body, None).unwrap();
        backend
            .fs_backend_map(&VhostUserFSBackendMsg::default(), &frontend)
            .unwrap();
    }
}
