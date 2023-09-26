// Copyright (C) 2019-2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use super::connection::Endpoint;
use super::message::*;
use super::{Error, HandlerResult, Result};

/// Define services provided by frontends for the backend communication channel.
///
/// The vhost-user specification defines a backend communication channel, by which backends could
/// request services from frontends. The [VhostUserFrontendReqHandler] trait defines services provided
/// by frontends, and it's used both on the frontend side and backend side.
/// - on the backend side, a stub forwarder implementing [VhostUserFrontendReqHandler] will proxy
///   service requests to frontends. The [Backend] is an example stub forwarder.
/// - on the frontend side, the [FrontendReqHandler] will forward service requests to a handler
///   implementing [VhostUserFrontendReqHandler].
///
/// The [VhostUserFrontendReqHandler] trait is design with interior mutability to improve performance
/// for multi-threading.
///
/// [VhostUserFrontendReqHandler]: trait.VhostUserFrontendReqHandler.html
/// [FrontendReqHandler]: struct.FrontendReqHandler.html
/// [Backend]: struct.Backend.html
pub trait VhostUserFrontendReqHandler {
    /// Handle device configuration change notifications.
    fn handle_config_change(&self) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs map file requests.
    fn fs_backend_map(&self, _fs: &VhostUserFSBackendMsg, _fd: &dyn AsRawFd) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs unmap file requests.
    fn fs_backend_unmap(&self, _fs: &VhostUserFSBackendMsg) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs sync file requests.
    fn fs_backend_sync(&self, _fs: &VhostUserFSBackendMsg) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs file IO requests.
    fn fs_backend_io(&self, _fs: &VhostUserFSBackendMsg, _fd: &dyn AsRawFd) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    // fn handle_iotlb_msg(&mut self, iotlb: VhostUserIotlb);
    // fn handle_vring_host_notifier(&mut self, area: VhostUserVringArea, fd: &dyn AsRawFd);
}

/// A helper trait mirroring [VhostUserFrontendReqHandler] but without interior mutability.
///
/// [VhostUserFrontendReqHandler]: trait.VhostUserFrontendReqHandler.html
pub trait VhostUserFrontendReqHandlerMut {
    /// Handle device configuration change notifications.
    fn handle_config_change(&mut self) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs map file requests.
    fn fs_backend_map(
        &mut self,
        _fs: &VhostUserFSBackendMsg,
        _fd: &dyn AsRawFd,
    ) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs unmap file requests.
    fn fs_backend_unmap(&mut self, _fs: &VhostUserFSBackendMsg) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs sync file requests.
    fn fs_backend_sync(&mut self, _fs: &VhostUserFSBackendMsg) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    /// Handle virtio-fs file IO requests.
    fn fs_backend_io(
        &mut self,
        _fs: &VhostUserFSBackendMsg,
        _fd: &dyn AsRawFd,
    ) -> HandlerResult<u64> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
    }

    // fn handle_iotlb_msg(&mut self, iotlb: VhostUserIotlb);
    // fn handle_vring_host_notifier(&mut self, area: VhostUserVringArea, fd: RawFd);
}

impl<S: VhostUserFrontendReqHandlerMut> VhostUserFrontendReqHandler for Mutex<S> {
    fn handle_config_change(&self) -> HandlerResult<u64> {
        self.lock().unwrap().handle_config_change()
    }

    fn fs_backend_map(&self, fs: &VhostUserFSBackendMsg, fd: &dyn AsRawFd) -> HandlerResult<u64> {
        self.lock().unwrap().fs_backend_map(fs, fd)
    }

    fn fs_backend_unmap(&self, fs: &VhostUserFSBackendMsg) -> HandlerResult<u64> {
        self.lock().unwrap().fs_backend_unmap(fs)
    }

    fn fs_backend_sync(&self, fs: &VhostUserFSBackendMsg) -> HandlerResult<u64> {
        self.lock().unwrap().fs_backend_sync(fs)
    }

    fn fs_backend_io(&self, fs: &VhostUserFSBackendMsg, fd: &dyn AsRawFd) -> HandlerResult<u64> {
        self.lock().unwrap().fs_backend_io(fs, fd)
    }
}

/// Server to handle service requests from backends from the backend communication channel.
///
/// The [FrontendReqHandler] acts as a server on the frontend side, to handle service requests from
/// backends on the backend communication channel. It's actually a proxy invoking the registered
/// handler implementing [VhostUserFrontendReqHandler] to do the real work.
///
/// [FrontendReqHandler]: struct.FrontendReqHandler.html
/// [VhostUserFrontendReqHandler]: trait.VhostUserFrontendReqHandler.html
pub struct FrontendReqHandler<S: VhostUserFrontendReqHandler> {
    // underlying Unix domain socket for communication
    sub_sock: Endpoint<BackendReq>,
    tx_sock: UnixStream,
    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,
    // the VirtIO backend device object
    backend: Arc<S>,
    // whether the endpoint has encountered any failure
    error: Option<i32>,
}

impl<S: VhostUserFrontendReqHandler> FrontendReqHandler<S> {
    /// Create a server to handle service requests from backends on the backend communication channel.
    ///
    /// This opens a pair of connected anonymous sockets to form the backend communication channel.
    /// The socket fd returned by [Self::get_tx_raw_fd()] should be sent to the backend by
    /// [VhostUserFrontend::set_backend_request_fd()].
    ///
    /// [Self::get_tx_raw_fd()]: struct.FrontendReqHandler.html#method.get_tx_raw_fd
    /// [VhostUserFrontend::set_backend_request_fd()]: trait.VhostUserFrontend.html#tymethod.set_backend_request_fd
    pub fn new(backend: Arc<S>) -> Result<Self> {
        let (tx, rx) = UnixStream::pair().map_err(Error::SocketError)?;

        Ok(FrontendReqHandler {
            sub_sock: Endpoint::<BackendReq>::from_stream(rx),
            tx_sock: tx,
            reply_ack_negotiated: false,
            backend,
            error: None,
        })
    }

    /// Get the socket fd for the backend to communication with the frontend.
    ///
    /// The returned fd should be sent to the backend by [VhostUserFrontend::set_backend_request_fd()].
    ///
    /// [VhostUserFrontend::set_backend_request_fd()]: trait.VhostUserFrontend.html#tymethod.set_backend_request_fd
    pub fn get_tx_raw_fd(&self) -> RawFd {
        self.tx_sock.as_raw_fd()
    }

    /// Set the negotiation state of the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature.
    ///
    /// When the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature has been negotiated,
    /// the "REPLY_ACK" flag will be set in the message header for every backend to frontend request
    /// message.
    pub fn set_reply_ack_flag(&mut self, enable: bool) {
        self.reply_ack_negotiated = enable;
    }

    /// Mark endpoint as failed or in normal state.
    pub fn set_failed(&mut self, error: i32) {
        if error == 0 {
            self.error = None;
        } else {
            self.error = Some(error);
        }
    }

    /// Main entrance to server backend request from the backend communication channel.
    ///
    /// The caller needs to:
    /// - serialize calls to this function
    /// - decide what to do when errer happens
    /// - optional recover from failure
    pub fn handle_request(&mut self) -> Result<u64> {
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
        let (hdr, files) = self.sub_sock.recv_header()?;
        self.check_attached_files(&hdr, &files)?;
        let (size, buf) = match hdr.get_size() {
            0 => (0, vec![0u8; 0]),
            len => {
                if len as usize > MAX_MSG_SIZE {
                    return Err(Error::InvalidMessage);
                }
                let (size2, rbuf) = self.sub_sock.recv_data(len as usize)?;
                if size2 != len as usize {
                    return Err(Error::InvalidMessage);
                }
                (size2, rbuf)
            }
        };

        let res = match hdr.get_code() {
            Ok(BackendReq::CONFIG_CHANGE_MSG) => {
                self.check_msg_size(&hdr, size, 0)?;
                self.backend
                    .handle_config_change()
                    .map_err(Error::ReqHandlerError)
            }
            Ok(BackendReq::FS_MAP) => {
                let msg = self.extract_msg_body::<VhostUserFSBackendMsg>(&hdr, size, &buf)?;
                // check_attached_files() has validated files
                self.backend
                    .fs_backend_map(&msg, &files.unwrap()[0])
                    .map_err(Error::ReqHandlerError)
            }
            Ok(BackendReq::FS_UNMAP) => {
                let msg = self.extract_msg_body::<VhostUserFSBackendMsg>(&hdr, size, &buf)?;
                self.backend
                    .fs_backend_unmap(&msg)
                    .map_err(Error::ReqHandlerError)
            }
            Ok(BackendReq::FS_SYNC) => {
                let msg = self.extract_msg_body::<VhostUserFSBackendMsg>(&hdr, size, &buf)?;
                self.backend
                    .fs_backend_sync(&msg)
                    .map_err(Error::ReqHandlerError)
            }
            Ok(BackendReq::FS_IO) => {
                let msg = self.extract_msg_body::<VhostUserFSBackendMsg>(&hdr, size, &buf)?;
                // check_attached_files() has validated files
                self.backend
                    .fs_backend_io(&msg, &files.unwrap()[0])
                    .map_err(Error::ReqHandlerError)
            }
            _ => Err(Error::InvalidMessage),
        };

        self.send_ack_message(&hdr, &res)?;

        res
    }

    fn check_state(&self) -> Result<()> {
        match self.error {
            Some(e) => Err(Error::SocketBroken(std::io::Error::from_raw_os_error(e))),
            None => Ok(()),
        }
    }

    fn check_msg_size(
        &self,
        hdr: &VhostUserMsgHeader<BackendReq>,
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
        hdr: &VhostUserMsgHeader<BackendReq>,
        files: &Option<Vec<File>>,
    ) -> Result<()> {
        match hdr.get_code() {
            Ok(BackendReq::FS_MAP | BackendReq::FS_IO) => {
                // Expect a single file is passed.
                match files {
                    Some(files) if files.len() == 1 => Ok(()),
                    _ => Err(Error::InvalidMessage),
                }
            }
            _ if files.is_some() => Err(Error::InvalidMessage),
            _ => Ok(()),
        }
    }

    fn extract_msg_body<T: Sized + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<BackendReq>,
        size: usize,
        buf: &[u8],
    ) -> Result<T> {
        self.check_msg_size(hdr, size, mem::size_of::<T>())?;
        // SAFETY: Safe because we checked that `buf` size is equal to T size.
        let msg = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const T) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        Ok(msg)
    }

    fn new_reply_header<T: Sized>(
        &self,
        req: &VhostUserMsgHeader<BackendReq>,
    ) -> Result<VhostUserMsgHeader<BackendReq>> {
        if mem::size_of::<T>() > MAX_MSG_SIZE {
            return Err(Error::InvalidParam);
        }
        self.check_state()?;
        Ok(VhostUserMsgHeader::new(
            req.get_code()?,
            VhostUserHeaderFlag::REPLY.bits(),
            mem::size_of::<T>() as u32,
        ))
    }

    fn send_ack_message(
        &mut self,
        req: &VhostUserMsgHeader<BackendReq>,
        res: &Result<u64>,
    ) -> Result<()> {
        if self.reply_ack_negotiated && req.is_need_reply() {
            let hdr = self.new_reply_header::<VhostUserU64>(req)?;
            let def_err = libc::EINVAL;
            let val = match res {
                Ok(n) => *n,
                Err(e) => match e {
                    Error::ReqHandlerError(ioerr) => match ioerr.raw_os_error() {
                        Some(rawerr) => -rawerr as u64,
                        None => -def_err as u64,
                    },
                    _ => -def_err as u64,
                },
            };
            let msg = VhostUserU64::new(val);
            self.sub_sock.send_message(&hdr, &msg, None)?;
        }
        Ok(())
    }
}

impl<S: VhostUserFrontendReqHandler> AsRawFd for FrontendReqHandler<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.sub_sock.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "vhost-user-backend")]
    use crate::vhost_user::Backend;
    #[cfg(feature = "vhost-user-backend")]
    use std::os::unix::io::FromRawFd;

    struct MockFrontendReqHandler {}

    impl VhostUserFrontendReqHandlerMut for MockFrontendReqHandler {
        /// Handle virtio-fs map file requests from the backend.
        fn fs_backend_map(
            &mut self,
            _fs: &VhostUserFSBackendMsg,
            _fd: &dyn AsRawFd,
        ) -> HandlerResult<u64> {
            Ok(0)
        }

        /// Handle virtio-fs unmap file requests from the backend.
        fn fs_backend_unmap(&mut self, _fs: &VhostUserFSBackendMsg) -> HandlerResult<u64> {
            Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
        }
    }

    #[test]
    fn test_new_frontend_req_handler() {
        let backend = Arc::new(Mutex::new(MockFrontendReqHandler {}));
        let mut handler = FrontendReqHandler::new(backend).unwrap();

        assert!(handler.get_tx_raw_fd() >= 0);
        assert!(handler.as_raw_fd() >= 0);
        handler.check_state().unwrap();

        assert_eq!(handler.error, None);
        handler.set_failed(libc::EAGAIN);
        assert_eq!(handler.error, Some(libc::EAGAIN));
        handler.check_state().unwrap_err();
    }

    #[cfg(feature = "vhost-user-backend")]
    #[test]
    fn test_frontend_backend_req_handler() {
        let backend = Arc::new(Mutex::new(MockFrontendReqHandler {}));
        let mut handler = FrontendReqHandler::new(backend).unwrap();

        // SAFETY: Safe because `handler` contains valid fds, and we are
        // checking if `dup` returns a valid fd.
        let fd = unsafe { libc::dup(handler.get_tx_raw_fd()) };
        if fd < 0 {
            panic!("failed to duplicated tx fd!");
        }
        // SAFETY: Safe because we checked if fd is valid.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        let backend = Backend::from_stream(stream);

        std::thread::spawn(move || {
            let res = handler.handle_request().unwrap();
            assert_eq!(res, 0);
            handler.handle_request().unwrap_err();
        });

        backend
            .fs_backend_map(&VhostUserFSBackendMsg::default(), &fd)
            .unwrap();
        // When REPLY_ACK has not been negotiated, the frontend has no way to detect failure from
        // backend side.
        backend
            .fs_backend_unmap(&VhostUserFSBackendMsg::default())
            .unwrap();
    }

    #[cfg(feature = "vhost-user-backend")]
    #[test]
    fn test_frontend_backend_req_handler_with_ack() {
        let backend = Arc::new(Mutex::new(MockFrontendReqHandler {}));
        let mut handler = FrontendReqHandler::new(backend).unwrap();
        handler.set_reply_ack_flag(true);

        // SAFETY: Safe because `handler` contains valid fds, and we are
        // checking if `dup` returns a valid fd.
        let fd = unsafe { libc::dup(handler.get_tx_raw_fd()) };
        if fd < 0 {
            panic!("failed to duplicated tx fd!");
        }
        // SAFETY: Safe because we checked if fd is valid.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        let backend = Backend::from_stream(stream);

        std::thread::spawn(move || {
            let res = handler.handle_request().unwrap();
            assert_eq!(res, 0);
            handler.handle_request().unwrap_err();
        });

        backend.set_reply_ack_flag(true);
        backend
            .fs_backend_map(&VhostUserFSBackendMsg::default(), &fd)
            .unwrap();
        backend
            .fs_backend_unmap(&VhostUserFSBackendMsg::default())
            .unwrap_err();
    }
}
