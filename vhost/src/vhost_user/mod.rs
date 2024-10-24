// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The protocol for vhost-user is based on the existing implementation of vhost for the Linux
//! Kernel. The protocol defines two sides of the communication, frontend and backend. Frontend is
//! the application that shares its virtqueues. Backend is the consumer of the virtqueues.
//!
//! The communication channel between the frontend and the backend includes two sub channels. One is
//! used to send requests from the frontend to the backend and optional replies from the backend to the
//! frontend. This sub channel is created on frontend startup by connecting to the backend service
//! endpoint. The other is used to send requests from the backend to the frontend and optional replies
//! from the frontend to the backend. This sub channel is created by the frontend issuing a
//! VHOST_USER_SET_BACKEND_REQ_FD request to the backend with an auxiliary file descriptor.
//!
//! Unix domain socket is used as the underlying communication channel because the frontend needs to
//! send file descriptors to the backend.
//!
//! Most messages that can be sent via the Unix domain socket implementing vhost-user have an
//! equivalent ioctl to the kernel implementation.

use std::fs::File;
use std::io::Error as IOError;

pub mod message;
pub use self::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

mod connection;
pub use self::connection::Listener;

#[cfg(feature = "vhost-user-frontend")]
mod frontend;
#[cfg(feature = "vhost-user-frontend")]
pub use self::frontend::{Frontend, VhostUserFrontend};
#[cfg(feature = "vhost-user")]
mod frontend_req_handler;
#[cfg(feature = "vhost-user")]
pub use self::frontend_req_handler::{
    FrontendReqHandler, VhostUserFrontendReqHandler, VhostUserFrontendReqHandlerMut,
};

#[cfg(feature = "vhost-user-backend")]
mod backend;
#[cfg(feature = "vhost-user-backend")]
pub use self::backend::BackendListener;
#[cfg(feature = "vhost-user-backend")]
mod backend_req_handler;
#[cfg(feature = "vhost-user-backend")]
pub use self::backend_req_handler::{
    BackendReqHandler, VhostUserBackendReqHandler, VhostUserBackendReqHandlerMut,
};
#[cfg(feature = "vhost-user-backend")]
mod backend_req;
#[cfg(feature = "vhost-user-backend")]
pub use self::backend_req::Backend;
#[cfg(feature = "gpu-socket")]
mod gpu_backend_req;
#[cfg(feature = "gpu-socket")]
pub mod gpu_message;
#[cfg(feature = "gpu-socket")]
pub use self::gpu_backend_req::GpuBackend;

/// Errors for vhost-user operations
#[derive(Debug)]
pub enum Error {
    /// Invalid parameters.
    InvalidParam,
    /// Invalid operation due to some reason
    InvalidOperation(&'static str),
    /// Unsupported operation due to missing feature
    InactiveFeature(VhostUserVirtioFeatures),
    /// Unsupported operations due to that the protocol feature hasn't been negotiated.
    InactiveOperation(VhostUserProtocolFeatures),
    /// Invalid message format, flag or content.
    InvalidMessage,
    /// Only part of a message have been sent or received successfully
    PartialMessage,
    /// The peer disconnected from the socket.
    Disconnected,
    /// Message is too large
    OversizedMsg,
    /// Fd array in question is too big or too small
    IncorrectFds,
    /// Can't connect to peer.
    SocketConnect(std::io::Error),
    /// Generic socket errors.
    SocketError(std::io::Error),
    /// The socket is broken or has been closed.
    SocketBroken(std::io::Error),
    /// Should retry the socket operation again.
    SocketRetry(std::io::Error),
    /// Failure from the backend side.
    BackendInternalError,
    /// Failure from the frontend side.
    FrontendInternalError,
    /// Virtio/protocol features mismatch.
    FeatureMismatch,
    /// Error from request handler
    ReqHandlerError(IOError),
    /// memfd file creation error
    MemFdCreateError,
    /// File truncate error
    FileTrucateError,
    /// memfd file seal errors
    MemFdSealError,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidParam => write!(f, "invalid parameters"),
            Error::InvalidOperation(reason) => write!(f, "invalid operation: {}", reason),
            Error::InactiveFeature(bits) => write!(f, "inactive feature: {}", bits.bits()),
            Error::InactiveOperation(bits) => {
                write!(f, "inactive protocol operation: {}", bits.bits())
            }
            Error::InvalidMessage => write!(f, "invalid message"),
            Error::PartialMessage => write!(f, "partial message"),
            Error::Disconnected => write!(f, "peer disconnected"),
            Error::OversizedMsg => write!(f, "oversized message"),
            Error::IncorrectFds => write!(f, "wrong number of attached fds"),
            Error::SocketError(e) => write!(f, "socket error: {}", e),
            Error::SocketConnect(e) => write!(f, "can't connect to peer: {}", e),
            Error::SocketBroken(e) => write!(f, "socket is broken: {}", e),
            Error::SocketRetry(e) => write!(f, "temporary socket error: {}", e),
            Error::BackendInternalError => write!(f, "backend internal error"),
            Error::FrontendInternalError => write!(f, "Frontend internal error"),
            Error::FeatureMismatch => write!(f, "virtio/protocol features mismatch"),
            Error::ReqHandlerError(e) => write!(f, "handler failed to handle request: {}", e),
            Error::MemFdCreateError => {
                write!(f, "handler failed to allocate memfd during get_inflight_fd")
            }
            Error::FileTrucateError => {
                write!(f, "handler failed to trucate memfd during get_inflight_fd")
            }
            Error::MemFdSealError => write!(
                f,
                "handler failed to apply seals to memfd during get_inflight_fd"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Determine whether to rebuild the underline communication channel.
    pub fn should_reconnect(&self) -> bool {
        match *self {
            // Should reconnect because it may be caused by temporary network errors.
            Error::PartialMessage => true,
            // Should reconnect because the underline socket is broken.
            Error::SocketBroken(_) => true,
            // Backend internal error, hope it recovers on reconnect.
            Error::BackendInternalError => true,
            // Frontend internal error, hope it recovers on reconnect.
            Error::FrontendInternalError => true,
            // Should just retry the IO operation instead of rebuilding the underline connection.
            Error::SocketRetry(_) => false,
            // Looks like the peer deliberately disconnected the socket.
            Error::Disconnected => false,
            Error::InvalidParam | Error::InvalidOperation(_) => false,
            Error::InactiveFeature(_) | Error::InactiveOperation(_) => false,
            Error::InvalidMessage | Error::IncorrectFds | Error::OversizedMsg => false,
            Error::SocketError(_) | Error::SocketConnect(_) => false,
            Error::FeatureMismatch => false,
            Error::ReqHandlerError(_) => false,
            Error::MemFdCreateError | Error::FileTrucateError | Error::MemFdSealError => false,
        }
    }
}

impl std::convert::From<vmm_sys_util::errno::Error> for Error {
    /// Convert raw socket errors into meaningful vhost-user errors.
    ///
    /// The vmm_sys_util::errno::Error is a simple wrapper over the raw errno, which doesn't means
    /// much to the vhost-user connection manager. So convert it into meaningful errors to simplify
    /// the connection manager logic.
    ///
    /// # Return:
    /// * - Error::SocketRetry: temporary error caused by signals or short of resources.
    /// * - Error::SocketBroken: the underline socket is broken.
    /// * - Error::SocketError: other socket related errors.
    #[allow(unreachable_patterns)] // EWOULDBLOCK equals to EGAIN on linux
    fn from(err: vmm_sys_util::errno::Error) -> Self {
        match err.errno() {
            // The socket is marked nonblocking and the requested operation would block.
            libc::EAGAIN => Error::SocketRetry(IOError::from_raw_os_error(libc::EAGAIN)),
            // The socket is marked nonblocking and the requested operation would block.
            libc::EWOULDBLOCK => Error::SocketRetry(IOError::from_raw_os_error(libc::EWOULDBLOCK)),
            // A signal occurred before any data was transmitted
            libc::EINTR => Error::SocketRetry(IOError::from_raw_os_error(libc::EINTR)),
            // The  output  queue  for  a network interface was full.  This generally indicates
            // that the interface has stopped sending, but may be caused by transient congestion.
            libc::ENOBUFS => Error::SocketRetry(IOError::from_raw_os_error(libc::ENOBUFS)),
            // No memory available.
            libc::ENOMEM => Error::SocketRetry(IOError::from_raw_os_error(libc::ENOMEM)),
            // Connection reset by peer.
            libc::ECONNRESET => Error::SocketBroken(IOError::from_raw_os_error(libc::ECONNRESET)),
            // The local end has been shut down on a connection oriented socket. In this  case the
            // process will also receive a SIGPIPE unless MSG_NOSIGNAL is set.
            libc::EPIPE => Error::SocketBroken(IOError::from_raw_os_error(libc::EPIPE)),
            // Write permission is denied on the destination socket file, or search permission is
            // denied for one of the directories the path prefix.
            libc::EACCES => Error::SocketConnect(IOError::from_raw_os_error(libc::EACCES)),
            // Catch all other errors
            e => Error::SocketError(IOError::from_raw_os_error(e)),
        }
    }
}

/// Result of vhost-user operations
pub type Result<T> = std::result::Result<T, Error>;

/// Result of request handler.
pub type HandlerResult<T> = std::result::Result<T, IOError>;

/// Utility function to take the first element from option of a vector of files.
/// Returns `None` if the vector contains no file or more than one file.
pub(crate) fn take_single_file(files: Option<Vec<File>>) -> Option<File> {
    let mut files = files?;
    if files.len() != 1 {
        return None;
    }
    Some(files.swap_remove(0))
}

// Utility to generate `TryFrom` and `From` implementation for enums
macro_rules! enum_value {
    (
        $(#[$meta:meta])*
        $vis:vis enum $enum:ident: $T:tt {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $(= $val:expr)?,
            )*
        }
    ) => {
        #[repr($T)]
        $(#[$meta])*
        $vis enum $enum {
            $($(#[$variant_meta])* $variant $(= $val)?,)*
        }

        impl std::convert::TryFrom<$T> for $enum {
            type Error = ();

            fn try_from(v: $T) -> std::result::Result<Self, Self::Error> {
                match v {
                    $(v if v == $enum::$variant as $T => Ok($enum::$variant),)*
                    _ => Err(()),
                }
            }
        }

        impl std::convert::From<$enum> for $T {
            fn from(v: $enum) -> $T {
                v as $T
            }
        }
    }
}

use enum_value;

#[cfg(all(test, feature = "vhost-user-backend"))]
mod dummy_backend;

#[cfg(all(test, feature = "vhost-user-frontend", feature = "vhost-user-backend"))]
mod tests {
    use message::VhostUserSharedMsg;
    use std::fs::File;
    use std::os::unix::io::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use uuid::Uuid;
    use vmm_sys_util::rand::rand_alphanumerics;
    use vmm_sys_util::tempfile::TempFile;

    use super::dummy_backend::{DummyBackendReqHandler, VIRTIO_FEATURES};
    use super::message::*;
    use super::*;
    use crate::backend::VhostBackend;
    use crate::{VhostUserDirtyLogRegion, VhostUserMemoryRegionInfo, VringConfigData};

    fn temp_path() -> PathBuf {
        PathBuf::from(format!(
            "/tmp/vhost_test_{}",
            rand_alphanumerics(8).to_str().unwrap()
        ))
    }

    fn create_backend<P, S>(path: P, backend: Arc<S>) -> (Frontend, BackendReqHandler<S>)
    where
        P: AsRef<Path>,
        S: VhostUserBackendReqHandler,
    {
        let listener = Listener::new(&path, true).unwrap();
        let mut backend_listener = BackendListener::new(listener, backend).unwrap();
        let frontend = Frontend::connect(&path, 1).unwrap();
        (frontend, backend_listener.accept().unwrap().unwrap())
    }

    #[test]
    fn create_dummy_backend() {
        let backend = Arc::new(Mutex::new(DummyBackendReqHandler::new()));

        backend.set_owner().unwrap();
        assert!(backend.set_owner().is_err());
    }

    #[test]
    fn test_set_owner() {
        let backend_be = Arc::new(Mutex::new(DummyBackendReqHandler::new()));
        let path = temp_path();
        let (frontend, mut backend) = create_backend(path, backend_be.clone());

        assert!(!backend_be.lock().unwrap().owned);
        frontend.set_owner().unwrap();
        backend.handle_request().unwrap();
        assert!(backend_be.lock().unwrap().owned);
        frontend.set_owner().unwrap();
        assert!(backend.handle_request().is_err());
        assert!(backend_be.lock().unwrap().owned);
    }

    #[test]
    fn test_set_features() {
        let mbar = Arc::new(Barrier::new(2));
        let sbar = mbar.clone();
        let path = temp_path();
        let backend_be = Arc::new(Mutex::new(DummyBackendReqHandler::new()));
        let (mut frontend, mut backend) = create_backend(path, backend_be.clone());

        thread::spawn(move || {
            backend.handle_request().unwrap();
            assert!(backend_be.lock().unwrap().owned);

            backend.handle_request().unwrap();
            backend.handle_request().unwrap();
            assert_eq!(
                backend_be.lock().unwrap().acked_features,
                VIRTIO_FEATURES & !0x1
            );

            backend.handle_request().unwrap();
            backend.handle_request().unwrap();
            assert_eq!(
                backend_be.lock().unwrap().acked_protocol_features,
                VhostUserProtocolFeatures::all().bits()
            );

            sbar.wait();
        });

        frontend.set_owner().unwrap();

        // set virtio features
        let features = frontend.get_features().unwrap();
        assert_eq!(features, VIRTIO_FEATURES);
        frontend.set_features(VIRTIO_FEATURES & !0x1).unwrap();

        // set vhost protocol features
        let features = frontend.get_protocol_features().unwrap();
        assert_eq!(features.bits(), VhostUserProtocolFeatures::all().bits());
        frontend.set_protocol_features(features).unwrap();

        mbar.wait();
    }

    #[test]
    fn test_frontend_backend_process() {
        let mbar = Arc::new(Barrier::new(2));
        let sbar = mbar.clone();
        let path = temp_path();
        let backend_be = Arc::new(Mutex::new(DummyBackendReqHandler::new()));
        let (mut frontend, mut backend) = create_backend(path, backend_be.clone());

        thread::spawn(move || {
            // set_own()
            backend.handle_request().unwrap();
            assert!(backend_be.lock().unwrap().owned);

            // get/set_features()
            backend.handle_request().unwrap();
            backend.handle_request().unwrap();
            assert_eq!(
                backend_be.lock().unwrap().acked_features,
                VIRTIO_FEATURES & !0x1
            );

            backend.handle_request().unwrap();
            backend.handle_request().unwrap();

            let mut features = VhostUserProtocolFeatures::all();

            // Disable Xen mmap feature.
            if !cfg!(feature = "xen") {
                features.remove(VhostUserProtocolFeatures::XEN_MMAP);
            }

            assert_eq!(
                backend_be.lock().unwrap().acked_protocol_features,
                features.bits()
            );

            // get_inflight_fd()
            backend.handle_request().unwrap();
            // set_inflight_fd()
            backend.handle_request().unwrap();

            // get_shared_object()
            backend.handle_request().unwrap();

            // get_queue_num()
            backend.handle_request().unwrap();

            // set_mem_table()
            backend.handle_request().unwrap();

            // get/set_config()
            backend.handle_request().unwrap();
            backend.handle_request().unwrap();

            // set_backend_request_fd
            backend.handle_request().unwrap();

            // set_vring_enable
            backend.handle_request().unwrap();

            // set_log_base,set_log_fd()
            backend.handle_request().unwrap_err();
            backend.handle_request().unwrap_err();

            // set_vring_xxx
            backend.handle_request().unwrap();
            backend.handle_request().unwrap();
            backend.handle_request().unwrap();
            backend.handle_request().unwrap();
            backend.handle_request().unwrap();
            backend.handle_request().unwrap();

            // get_max_mem_slots()
            backend.handle_request().unwrap();

            // add_mem_region()
            backend.handle_request().unwrap();

            // remove_mem_region()
            backend.handle_request().unwrap();

            sbar.wait();
        });

        frontend.set_owner().unwrap();

        // set virtio features
        let features = frontend.get_features().unwrap();
        assert_eq!(features, VIRTIO_FEATURES);
        frontend.set_features(VIRTIO_FEATURES & !0x1).unwrap();

        // set vhost protocol features
        let mut features = frontend.get_protocol_features().unwrap();
        assert_eq!(features.bits(), VhostUserProtocolFeatures::all().bits());

        // Disable Xen mmap feature.
        if !cfg!(feature = "xen") {
            features.remove(VhostUserProtocolFeatures::XEN_MMAP);
        }

        frontend.set_protocol_features(features).unwrap();

        // Retrieve inflight I/O tracking information
        let (inflight_info, inflight_file) = frontend
            .get_inflight_fd(&VhostUserInflight {
                num_queues: 2,
                queue_size: 256,
                ..Default::default()
            })
            .unwrap();
        // Set the buffer back to the backend
        frontend
            .set_inflight_fd(&inflight_info, inflight_file.as_raw_fd())
            .unwrap();

        frontend
            .get_shared_object(&VhostUserSharedMsg {
                uuid: Uuid::new_v4(),
            })
            .unwrap();
        let num = frontend.get_queue_num().unwrap();
        assert_eq!(num, 2);

        let eventfd = vmm_sys_util::eventfd::EventFd::new(0).unwrap();
        let mem = [VhostUserMemoryRegionInfo::new(
            0,
            0x10_0000,
            0,
            0,
            eventfd.as_raw_fd(),
        )];
        frontend.set_mem_table(&mem).unwrap();

        frontend
            .set_config(0x100, VhostUserConfigFlags::WRITABLE, &[0xa5u8; 4])
            .unwrap();
        let buf = [0x0u8; 4];
        let (reply_body, reply_payload) = frontend
            .get_config(0x100, 4, VhostUserConfigFlags::empty(), &buf)
            .unwrap();
        let offset = reply_body.offset;
        assert_eq!(offset, 0x100);
        assert_eq!(&reply_payload, &[0xa5; 4]);

        frontend.set_backend_request_fd(&eventfd).unwrap();
        frontend.set_vring_enable(0, true).unwrap();

        frontend
            .set_log_base(
                0,
                Some(VhostUserDirtyLogRegion {
                    mmap_size: 0x1000,
                    mmap_offset: 0,
                    mmap_handle: eventfd.as_raw_fd(),
                }),
            )
            .unwrap();
        frontend.set_log_fd(eventfd.as_raw_fd()).unwrap();

        frontend.set_vring_num(0, 256).unwrap();
        frontend.set_vring_base(0, 0).unwrap();
        let config = VringConfigData {
            queue_max_size: 256,
            queue_size: 128,
            flags: VhostUserVringAddrFlags::VHOST_VRING_F_LOG.bits(),
            desc_table_addr: 0x1000,
            used_ring_addr: 0x2000,
            avail_ring_addr: 0x3000,
            log_addr: Some(0x4000),
        };
        frontend.set_vring_addr(0, &config).unwrap();
        frontend.set_vring_call(0, &eventfd).unwrap();
        frontend.set_vring_kick(0, &eventfd).unwrap();
        frontend.set_vring_err(0, &eventfd).unwrap();

        let max_mem_slots = frontend.get_max_mem_slots().unwrap();
        assert_eq!(max_mem_slots, 509);

        let region_file: File = TempFile::new().unwrap().into_file();
        let region =
            VhostUserMemoryRegionInfo::new(0x10_0000, 0x10_0000, 0, 0, region_file.as_raw_fd());
        frontend.add_mem_region(&region).unwrap();

        frontend.remove_mem_region(&region).unwrap();

        mbar.wait();
    }

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", Error::InvalidParam), "invalid parameters");
        assert_eq!(
            format!("{}", Error::InvalidOperation("reason")),
            "invalid operation: reason"
        );
    }

    #[test]
    fn test_should_reconnect() {
        assert!(Error::PartialMessage.should_reconnect());
        assert!(Error::BackendInternalError.should_reconnect());
        assert!(Error::FrontendInternalError.should_reconnect());
        assert!(!Error::InvalidParam.should_reconnect());
        assert!(!Error::InvalidOperation("reason").should_reconnect());
        assert!(
            !Error::InactiveFeature(VhostUserVirtioFeatures::PROTOCOL_FEATURES).should_reconnect()
        );
        assert!(!Error::InactiveOperation(VhostUserProtocolFeatures::all()).should_reconnect());
        assert!(!Error::InvalidMessage.should_reconnect());
        assert!(!Error::IncorrectFds.should_reconnect());
        assert!(!Error::OversizedMsg.should_reconnect());
        assert!(!Error::FeatureMismatch.should_reconnect());
    }

    #[test]
    fn test_error_from_sys_util_error() {
        let e: Error = vmm_sys_util::errno::Error::new(libc::EAGAIN).into();
        if let Error::SocketRetry(e1) = e {
            assert_eq!(e1.raw_os_error().unwrap(), libc::EAGAIN);
        } else {
            panic!("invalid error code conversion!");
        }
    }
}
