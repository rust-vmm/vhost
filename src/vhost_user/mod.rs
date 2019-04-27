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

use libc;
use std::io::Error as IOError;

mod connection;
pub use self::connection::Listener;
pub mod message;

pub mod sock_ctrl_msg;

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
        }
    }
}

impl Error {
    /// Determine whether to rebuild the underline communication channel.
    pub fn should_reconnect(&self) -> bool {
        match *self {
            // Should reconnect because it may be caused by temporary network errors.
            Error::PartialMessage => true,
            // Should reconnect because the underline socket is broken.
            Error::SocketBroken(_) => true,
            // Should just retry the IO operation instead of rebuilding the underline connection.
            Error::SocketRetry(_) => false,
            Error::InvalidParam | Error::InvalidOperation => false,
            Error::InvalidMessage | Error::IncorrectFds | Error::OversizedMsg => false,
            Error::SocketError(_) | Error::SocketConnect(_) => false,
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
