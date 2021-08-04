// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The protocol for vhost-user is based on the existing implementation of vhost for the Linux
//! Kernel. The protocol defines two sides of the communication, master and slave. Master is
//! the application that shares its virtqueues. Slave is the consumer of the virtqueues.
//!
//! The communication channel between the master and the slave includes two sub channels. One is
//! used to send requests from the master to the slave and optional replies from the slave to the
//! master. This sub channel is created on master startup by connecting to the slave service
//! endpoint. The other is used to send requests from the slave to the master and optional replies
//! from the master to the slave. This sub channel is created by the master issuing a
//! VHOST_USER_SET_SLAVE_REQ_FD request to the slave with an auxiliary file descriptor.
//!
//! Unix domain socket is used as the underlying communication channel because the master needs to
//! send file descriptors to the slave.
//!
//! Most messages that can be sent via the Unix domain socket implementing vhost-user have an
//! equivalent ioctl to the kernel implementation.

use std::fs::File;
use std::io::Error as IOError;

pub mod message;

mod connection;
pub use self::connection::Listener;

#[cfg(feature = "vhost-user-master")]
mod master;
#[cfg(feature = "vhost-user-master")]
pub use self::master::{Master, VhostUserMaster};
#[cfg(feature = "vhost-user")]
mod master_req_handler;
#[cfg(feature = "vhost-user")]
pub use self::master_req_handler::{
    MasterReqHandler, VhostUserMasterReqHandler, VhostUserMasterReqHandlerMut,
};

#[cfg(feature = "vhost-user-slave")]
mod slave;
#[cfg(feature = "vhost-user-slave")]
pub use self::slave::SlaveListener;
#[cfg(feature = "vhost-user-slave")]
mod slave_req_handler;
#[cfg(feature = "vhost-user-slave")]
pub use self::slave_req_handler::{
    SlaveReqHandler, VhostUserSlaveReqHandler, VhostUserSlaveReqHandlerMut,
};
#[cfg(feature = "vhost-user-slave")]
mod slave_fs_cache;
#[cfg(feature = "vhost-user-slave")]
pub use self::slave_fs_cache::SlaveFsCacheReq;

/// Errors for vhost-user operations
#[derive(Debug)]
pub enum Error {
    /// Invalid parameters.
    InvalidParam,
    /// Unsupported operations due to that the protocol feature hasn't been negotiated.
    InvalidOperation,
    /// Invalid message format, flag or content.
    InvalidMessage,
    /// Only part of a message have been sent or received successfully
    PartialMessage,
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
    /// Failure from the slave side.
    SlaveInternalError,
    /// Failure from the master side.
    MasterInternalError,
    /// Virtio/protocol features mismatch.
    FeatureMismatch,
    /// Error from request handler
    ReqHandlerError(IOError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidParam => write!(f, "invalid parameters"),
            Error::InvalidOperation => write!(f, "invalid operation"),
            Error::InvalidMessage => write!(f, "invalid message"),
            Error::PartialMessage => write!(f, "partial message"),
            Error::OversizedMsg => write!(f, "oversized message"),
            Error::IncorrectFds => write!(f, "wrong number of attached fds"),
            Error::SocketError(e) => write!(f, "socket error: {}", e),
            Error::SocketConnect(e) => write!(f, "can't connect to peer: {}", e),
            Error::SocketBroken(e) => write!(f, "socket is broken: {}", e),
            Error::SocketRetry(e) => write!(f, "temporary socket error: {}", e),
            Error::SlaveInternalError => write!(f, "slave internal error"),
            Error::MasterInternalError => write!(f, "Master internal error"),
            Error::FeatureMismatch => write!(f, "virtio/protocol features mismatch"),
            Error::ReqHandlerError(e) => write!(f, "handler failed to handle request: {}", e),
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
            // Slave internal error, hope it recovers on reconnect.
            Error::SlaveInternalError => true,
            // Master internal error, hope it recovers on reconnect.
            Error::MasterInternalError => true,
            // Should just retry the IO operation instead of rebuilding the underline connection.
            Error::SocketRetry(_) => false,
            Error::InvalidParam | Error::InvalidOperation => false,
            Error::InvalidMessage | Error::IncorrectFds | Error::OversizedMsg => false,
            Error::SocketError(_) | Error::SocketConnect(_) => false,
            Error::FeatureMismatch => false,
            Error::ReqHandlerError(_) => false,
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

#[cfg(all(test, feature = "vhost-user-slave"))]
mod dummy_slave;

#[cfg(all(test, feature = "vhost-user-master", feature = "vhost-user-slave"))]
mod tests {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use vmm_sys_util::rand::rand_alphanumerics;
    use vmm_sys_util::tempfile::TempFile;

    use super::dummy_slave::{DummySlaveReqHandler, VIRTIO_FEATURES};
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

    fn create_slave<P, S>(path: P, backend: Arc<S>) -> (Master, SlaveReqHandler<S>)
    where
        P: AsRef<Path>,
        S: VhostUserSlaveReqHandler,
    {
        let listener = Listener::new(&path, true).unwrap();
        let mut slave_listener = SlaveListener::new(listener, backend).unwrap();
        let master = Master::connect(&path, 1).unwrap();
        (master, slave_listener.accept().unwrap().unwrap())
    }

    #[test]
    fn create_dummy_slave() {
        let slave = Arc::new(Mutex::new(DummySlaveReqHandler::new()));

        slave.set_owner().unwrap();
        assert!(slave.set_owner().is_err());
    }

    #[test]
    fn test_set_owner() {
        let slave_be = Arc::new(Mutex::new(DummySlaveReqHandler::new()));
        let path = temp_path();
        let (master, mut slave) = create_slave(&path, slave_be.clone());

        assert_eq!(slave_be.lock().unwrap().owned, false);
        master.set_owner().unwrap();
        slave.handle_request().unwrap();
        assert_eq!(slave_be.lock().unwrap().owned, true);
        master.set_owner().unwrap();
        assert!(slave.handle_request().is_err());
        assert_eq!(slave_be.lock().unwrap().owned, true);
    }

    #[test]
    fn test_set_features() {
        let mbar = Arc::new(Barrier::new(2));
        let sbar = mbar.clone();
        let path = temp_path();
        let slave_be = Arc::new(Mutex::new(DummySlaveReqHandler::new()));
        let (mut master, mut slave) = create_slave(&path, slave_be.clone());

        thread::spawn(move || {
            slave.handle_request().unwrap();
            assert_eq!(slave_be.lock().unwrap().owned, true);

            slave.handle_request().unwrap();
            slave.handle_request().unwrap();
            assert_eq!(
                slave_be.lock().unwrap().acked_features,
                VIRTIO_FEATURES & !0x1
            );

            slave.handle_request().unwrap();
            slave.handle_request().unwrap();
            assert_eq!(
                slave_be.lock().unwrap().acked_protocol_features,
                VhostUserProtocolFeatures::all().bits()
            );

            sbar.wait();
        });

        master.set_owner().unwrap();

        // set virtio features
        let features = master.get_features().unwrap();
        assert_eq!(features, VIRTIO_FEATURES);
        master.set_features(VIRTIO_FEATURES & !0x1).unwrap();

        // set vhost protocol features
        let features = master.get_protocol_features().unwrap();
        assert_eq!(features.bits(), VhostUserProtocolFeatures::all().bits());
        master.set_protocol_features(features).unwrap();

        mbar.wait();
    }

    #[test]
    fn test_master_slave_process() {
        let mbar = Arc::new(Barrier::new(2));
        let sbar = mbar.clone();
        let path = temp_path();
        let slave_be = Arc::new(Mutex::new(DummySlaveReqHandler::new()));
        let (mut master, mut slave) = create_slave(&path, slave_be.clone());

        thread::spawn(move || {
            // set_own()
            slave.handle_request().unwrap();
            assert_eq!(slave_be.lock().unwrap().owned, true);

            // get/set_features()
            slave.handle_request().unwrap();
            slave.handle_request().unwrap();
            assert_eq!(
                slave_be.lock().unwrap().acked_features,
                VIRTIO_FEATURES & !0x1
            );

            slave.handle_request().unwrap();
            slave.handle_request().unwrap();
            assert_eq!(
                slave_be.lock().unwrap().acked_protocol_features,
                VhostUserProtocolFeatures::all().bits()
            );

            // get_inflight_fd()
            slave.handle_request().unwrap();
            // set_inflight_fd()
            slave.handle_request().unwrap();

            // get_queue_num()
            slave.handle_request().unwrap();

            // set_mem_table()
            slave.handle_request().unwrap();

            // get/set_config()
            slave.handle_request().unwrap();
            slave.handle_request().unwrap();

            // set_slave_request_fd
            slave.handle_request().unwrap();

            // set_vring_enable
            slave.handle_request().unwrap();

            // set_log_base,set_log_fd()
            slave.handle_request().unwrap_err();
            slave.handle_request().unwrap_err();

            // set_vring_xxx
            slave.handle_request().unwrap();
            slave.handle_request().unwrap();
            slave.handle_request().unwrap();
            slave.handle_request().unwrap();
            slave.handle_request().unwrap();
            slave.handle_request().unwrap();

            // get_max_mem_slots()
            slave.handle_request().unwrap();

            // add_mem_region()
            slave.handle_request().unwrap();

            // remove_mem_region()
            slave.handle_request().unwrap();

            sbar.wait();
        });

        master.set_owner().unwrap();

        // set virtio features
        let features = master.get_features().unwrap();
        assert_eq!(features, VIRTIO_FEATURES);
        master.set_features(VIRTIO_FEATURES & !0x1).unwrap();

        // set vhost protocol features
        let features = master.get_protocol_features().unwrap();
        assert_eq!(features.bits(), VhostUserProtocolFeatures::all().bits());
        master.set_protocol_features(features).unwrap();

        // Retrieve inflight I/O tracking information
        let (inflight_info, inflight_file) = master
            .get_inflight_fd(&VhostUserInflight {
                num_queues: 2,
                queue_size: 256,
                ..Default::default()
            })
            .unwrap();
        // Set the buffer back to the backend
        master
            .set_inflight_fd(&inflight_info, inflight_file.as_raw_fd())
            .unwrap();

        let num = master.get_queue_num().unwrap();
        assert_eq!(num, 2);

        let eventfd = vmm_sys_util::eventfd::EventFd::new(0).unwrap();
        let mem = [VhostUserMemoryRegionInfo {
            guest_phys_addr: 0,
            memory_size: 0x10_0000,
            userspace_addr: 0,
            mmap_offset: 0,
            mmap_handle: eventfd.as_raw_fd(),
        }];
        master.set_mem_table(&mem).unwrap();

        master
            .set_config(0x100, VhostUserConfigFlags::WRITABLE, &[0xa5u8])
            .unwrap();
        let buf = [0x0u8; 4];
        let (reply_body, reply_payload) = master
            .get_config(0x100, 4, VhostUserConfigFlags::empty(), &buf)
            .unwrap();
        let offset = reply_body.offset;
        assert_eq!(offset, 0x100);
        assert_eq!(reply_payload[0], 0xa5);

        master.set_slave_request_fd(&eventfd).unwrap();
        master.set_vring_enable(0, true).unwrap();

        master
            .set_log_base(
                0,
                Some(VhostUserDirtyLogRegion {
                    mmap_size: 0x1000,
                    mmap_offset: 0,
                    mmap_handle: eventfd.as_raw_fd(),
                }),
            )
            .unwrap();
        master.set_log_fd(eventfd.as_raw_fd()).unwrap();

        master.set_vring_num(0, 256).unwrap();
        master.set_vring_base(0, 0).unwrap();
        let config = VringConfigData {
            queue_max_size: 256,
            queue_size: 128,
            flags: VhostUserVringAddrFlags::VHOST_VRING_F_LOG.bits(),
            desc_table_addr: 0x1000,
            used_ring_addr: 0x2000,
            avail_ring_addr: 0x3000,
            log_addr: Some(0x4000),
        };
        master.set_vring_addr(0, &config).unwrap();
        master.set_vring_call(0, &eventfd).unwrap();
        master.set_vring_kick(0, &eventfd).unwrap();
        master.set_vring_err(0, &eventfd).unwrap();

        let max_mem_slots = master.get_max_mem_slots().unwrap();
        assert_eq!(max_mem_slots, 32);

        let region_file: File = TempFile::new().unwrap().into_file();
        let region = VhostUserMemoryRegionInfo {
            guest_phys_addr: 0x10_0000,
            memory_size: 0x10_0000,
            userspace_addr: 0,
            mmap_offset: 0,
            mmap_handle: region_file.as_raw_fd(),
        };
        master.add_mem_region(&region).unwrap();

        master.remove_mem_region(&region).unwrap();

        mbar.wait();
    }

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", Error::InvalidParam), "invalid parameters");
        assert_eq!(format!("{}", Error::InvalidOperation), "invalid operation");
    }

    #[test]
    fn test_should_reconnect() {
        assert_eq!(Error::PartialMessage.should_reconnect(), true);
        assert_eq!(Error::SlaveInternalError.should_reconnect(), true);
        assert_eq!(Error::MasterInternalError.should_reconnect(), true);
        assert_eq!(Error::InvalidParam.should_reconnect(), false);
        assert_eq!(Error::InvalidOperation.should_reconnect(), false);
        assert_eq!(Error::InvalidMessage.should_reconnect(), false);
        assert_eq!(Error::IncorrectFds.should_reconnect(), false);
        assert_eq!(Error::OversizedMsg.should_reconnect(), false);
        assert_eq!(Error::FeatureMismatch.should_reconnect(), false);
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
