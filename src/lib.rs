// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2019-2021 Alibaba Cloud Computing. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A simple framework to run a vhost-user backend service.

#[macro_use]
extern crate log;

use std::fmt::{Display, Formatter};
use std::io;
use std::result;
use std::sync::{Arc, Mutex};
use std::thread;

use vhost::vhost_user::{
    Error as VhostUserError, Listener, SlaveListener, VhostUserSlaveReqHandlerMut,
};
use vm_memory::bitmap::Bitmap;
use vm_memory::mmap::NewBitmap;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap, MmapRegion};

use self::handler::VhostUserHandler;

mod backend;
pub use self::backend::{VhostUserBackend, VhostUserBackendMut};

mod event_loop;
pub use self::event_loop::VringEpollHandler;

mod handler;
pub use self::handler::VhostUserHandlerError;

mod vring;
pub use self::vring::{Vring, VringState};

/// An alias for `GuestMemoryAtomic<GuestMemoryMmap<B>>` to simplify code.
type GM<B> = GuestMemoryAtomic<GuestMemoryMmap<B>>;

#[derive(Debug)]
/// Errors related to vhost-user daemon.
pub enum Error {
    /// Failed to create a new vhost-user handler.
    NewVhostUserHandler(VhostUserHandlerError),
    /// Failed creating vhost-user slave listener.
    CreateSlaveListener(VhostUserError),
    /// Failed creating vhost-user slave handler.
    CreateSlaveReqHandler(VhostUserError),
    /// Failed starting daemon thread.
    StartDaemon(io::Error),
    /// Failed waiting for daemon thread.
    WaitDaemon(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    /// Failed handling a vhost-user request.
    HandleRequest(VhostUserError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Error::NewVhostUserHandler(e) => write!(f, "cannot create vhost user handler: {}", e),
            Error::CreateSlaveListener(e) => write!(f, "cannot create slave listener: {}", e),
            Error::CreateSlaveReqHandler(e) => write!(f, "cannot create slave req handler: {}", e),
            Error::StartDaemon(e) => write!(f, "failed to start daemon: {}", e),
            Error::WaitDaemon(_e) => write!(f, "failed to wait for daemon exit"),
            Error::HandleRequest(e) => write!(f, "failed to handle request: {}", e),
        }
    }
}

/// Result of vhost-user daemon operations.
pub type Result<T> = result::Result<T, Error>;

/// Implement a simple framework to run a vhost-user service daemon.
///
/// This structure is the public API the backend is allowed to interact with in order to run
/// a fully functional vhost-user daemon.
pub struct VhostUserDaemon<S: VhostUserBackend<B>, B: Bitmap + 'static> {
    name: String,
    handler: Arc<Mutex<VhostUserHandler<S, B>>>,
    main_thread: Option<thread::JoinHandle<Result<()>>>,
}

impl<S: VhostUserBackend<B> + Clone, B: NewBitmap + Clone + Send + Sync> VhostUserDaemon<S, B> {
    /// Create the daemon instance, providing the backend implementation of `VhostUserBackend`.
    ///
    /// Under the hood, this will start a dedicated thread responsible for listening onto
    /// registered event. Those events can be vring events or custom events from the backend,
    /// but they get to be registered later during the sequence.
    pub fn new(
        name: String,
        backend: S,
        atomic_mem: GuestMemoryAtomic<GuestMemoryMmap<B>>,
    ) -> Result<Self> {
        let handler = Arc::new(Mutex::new(
            VhostUserHandler::new(backend, atomic_mem).map_err(Error::NewVhostUserHandler)?,
        ));

        Ok(VhostUserDaemon {
            name,
            handler,
            main_thread: None,
        })
    }

    /// Connect to the vhost-user socket and run a dedicated thread handling all requests coming
    /// through this socket.
    ///
    /// This runs in an infinite loop that should be terminating once the other end of the socket
    /// (the VMM) disconnects.
    pub fn start(&mut self, listener: Listener) -> Result<()> {
        let mut slave_listener = SlaveListener::new(listener, self.handler.clone())
            .map_err(Error::CreateSlaveListener)?;
        let mut slave_handler = slave_listener
            .accept()
            .map_err(Error::CreateSlaveReqHandler)?
            .unwrap();
        let handle = thread::Builder::new()
            .name(self.name.clone())
            .spawn(move || loop {
                slave_handler
                    .handle_request()
                    .map_err(Error::HandleRequest)?;
            })
            .map_err(Error::StartDaemon)?;

        self.main_thread = Some(handle);

        Ok(())
    }

    /// Wait for the thread handling the vhost-user socket connection to terminate.
    pub fn wait(&mut self) -> Result<()> {
        if let Some(handle) = self.main_thread.take() {
            match handle.join().map_err(Error::WaitDaemon)? {
                Ok(()) => Ok(()),
                Err(Error::HandleRequest(VhostUserError::SocketBroken(_))) => Ok(()),
                Err(e) => Err(e),
            }
        } else {
            Ok(())
        }
    }

    /// Retrieve the vring epoll handler.
    ///
    /// This is necessary to perform further actions like registering and unregistering some extra
    /// event file descriptors.
    pub fn get_epoll_handlers(&self) -> Vec<Arc<VringEpollHandler<S, B>>> {
        self.handler.lock().unwrap().get_epoll_handlers()
    }
}

#[cfg(test)]
mod tests {
    use super::backend::tests::MockVhostBackend;
    use super::*;
    use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    #[test]
    fn test_new_daemon() {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));
        let daemon = VhostUserDaemon::new("test".to_owned(), backend, mem).unwrap();

        assert_eq!(daemon.get_epoll_handlers().len(), 2);
        //daemon.start(Listener::new()).unwrap();
    }
}
