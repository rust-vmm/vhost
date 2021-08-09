// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A simple framework to run a vhost-user backend service.

#[macro_use]
extern crate log;

use std::io;
use std::result;
use std::sync::{Arc, Mutex};
use std::thread;

use vhost::vhost_user::message::VhostUserSingleMemoryRegion;
use vhost::vhost_user::{
    Error as VhostUserError, Listener, SlaveListener, VhostUserSlaveReqHandlerMut,
};
use virtio_queue::Queue;
use vm_memory::{
    GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap, GuestRegionMmap, MmapRegion,
};
use vmm_sys_util::eventfd::EventFd;

use self::handler::VhostUserHandler;

mod backend;
pub use self::backend::{VhostUserBackend, VhostUserBackendMut};

mod event_loop;
pub use self::event_loop::{VringEpollError, VringEpollHandler, VringEpollResult};

mod handler;
pub use self::handler::VhostUserHandlerError;

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

/// Result of vhost-user daemon operations.
pub type Result<T> = result::Result<T, Error>;

/// Implement a simple framework to run a vhost user service daemon.
///
/// This structure is the public API the backend is allowed to interact with in order to run
/// a fully functional vhost-user daemon.
pub struct VhostUserDaemon<S: VhostUserBackend> {
    name: String,
    handler: Arc<Mutex<VhostUserHandler<S>>>,
    main_thread: Option<thread::JoinHandle<Result<()>>>,
}

impl<S: VhostUserBackend + Clone> VhostUserDaemon<S> {
    /// Create the daemon instance, providing the backend implementation of `VhostUserBackend`.
    ///
    /// Under the hood, this will start a dedicated thread responsible for listening onto
    /// registered event. Those events can be vring events or custom events from the backend,
    /// but they get to be registered later during the sequence.
    pub fn new(name: String, backend: S) -> Result<Self> {
        let handler = Arc::new(Mutex::new(
            VhostUserHandler::new(backend).map_err(Error::NewVhostUserHandler)?,
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
    pub fn get_epoll_handlers(&self) -> Vec<Arc<VringEpollHandler<S>>> {
        self.handler.lock().unwrap().get_epoll_handlers()
    }
}

pub struct Vring {
    queue: Queue<GuestMemoryAtomic<GuestMemoryMmap>>,
    kick: Option<EventFd>,
    call: Option<EventFd>,
    err: Option<EventFd>,
    enabled: bool,
}

impl Vring {
    fn new(atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>, max_queue_size: u16) -> Self {
        Vring {
            queue: Queue::new(atomic_mem, max_queue_size),
            kick: None,
            call: None,
            err: None,
            enabled: false,
        }
    }

    pub fn mut_queue(&mut self) -> &mut Queue<GuestMemoryAtomic<GuestMemoryMmap>> {
        &mut self.queue
    }

    pub fn signal_used_queue(&mut self) -> result::Result<(), io::Error> {
        if let Some(call) = self.call.as_ref() {
            call.write(1)
        } else {
            Ok(())
        }
    }
}
