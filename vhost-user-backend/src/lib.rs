// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2019-2021 Alibaba Cloud Computing. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! A simple framework to run a vhost-user backend service.

#[macro_use]
extern crate log;

use std::fmt::{Display, Formatter};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use vhost::vhost_user::{BackendListener, BackendReqHandler, Error as VhostUserError, Listener};
use vm_memory::mmap::NewBitmap;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use self::handler::VhostUserHandler;

mod backend;
pub use self::backend::{VhostUserBackend, VhostUserBackendMut};

mod event_loop;
pub use self::event_loop::VringEpollHandler;

mod handler;
pub use self::handler::VhostUserHandlerError;

pub mod bitmap;

mod vring;
pub use self::vring::{
    VringMutex, VringRwLock, VringState, VringStateGuard, VringStateMutGuard, VringT,
};

/// Due to the way `xen` handles memory mappings we can not combine it with
/// `postcopy` feature which relies on persistent memory mappings. Thus we
/// disallow enabling both features at the same time.
#[cfg(all(feature = "postcopy", feature = "xen"))]
compile_error!("Both `postcopy` and `xen` features can not be enabled at the same time.");

/// An alias for `GuestMemoryAtomic<GuestMemoryMmap<B>>` to simplify code.
type GM<B> = GuestMemoryAtomic<GuestMemoryMmap<B>>;

#[derive(Debug)]
/// Errors related to vhost-user daemon.
pub enum Error {
    /// Failed to create a new vhost-user handler.
    NewVhostUserHandler(VhostUserHandlerError),
    /// Failed creating vhost-user backend listener.
    CreateBackendListener(VhostUserError),
    /// Failed creating vhost-user backend handler.
    CreateBackendReqHandler(VhostUserError),
    /// Failed creating listener socket
    CreateVhostUserListener(VhostUserError),
    /// Failed starting daemon thread.
    StartDaemon(std::io::Error),
    /// Failed waiting for daemon thread.
    WaitDaemon(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    /// Failed handling a vhost-user request.
    HandleRequest(VhostUserError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Error::NewVhostUserHandler(e) => write!(f, "cannot create vhost user handler: {}", e),
            Error::CreateBackendListener(e) => write!(f, "cannot create backend listener: {}", e),
            Error::CreateBackendReqHandler(e) => {
                write!(f, "cannot create backend req handler: {}", e)
            }
            Error::CreateVhostUserListener(e) => {
                write!(f, "cannot create vhost-user listener: {}", e)
            }
            Error::StartDaemon(e) => write!(f, "failed to start daemon: {}", e),
            Error::WaitDaemon(_e) => write!(f, "failed to wait for daemon exit"),
            Error::HandleRequest(e) => write!(f, "failed to handle request: {}", e),
        }
    }
}

/// Result of vhost-user daemon operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Implement a simple framework to run a vhost-user service daemon.
///
/// This structure is the public API the backend is allowed to interact with in order to run
/// a fully functional vhost-user daemon.
pub struct VhostUserDaemon<T: VhostUserBackend> {
    name: String,
    handler: Arc<Mutex<VhostUserHandler<T>>>,
    main_thread: Option<thread::JoinHandle<Result<()>>>,
}

impl<T> VhostUserDaemon<T>
where
    T: VhostUserBackend + Clone + 'static,
    T::Bitmap: NewBitmap + Clone + Send + Sync,
    T::Vring: Clone + Send + Sync,
{
    /// Create the daemon instance, providing the backend implementation of `VhostUserBackend`.
    ///
    /// Under the hood, this will start a dedicated thread responsible for listening onto
    /// registered event. Those events can be vring events or custom events from the backend,
    /// but they get to be registered later during the sequence.
    pub fn new(
        name: String,
        backend: T,
        atomic_mem: GuestMemoryAtomic<GuestMemoryMmap<T::Bitmap>>,
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

    /// Run a dedicated thread handling all requests coming through the socket.
    /// This runs in an infinite loop that should be terminating once the other
    /// end of the socket (the VMM) hangs up.
    ///
    /// This function is the common code for starting a new daemon, no matter if
    /// it acts as a client or a server.
    fn start_daemon(
        &mut self,
        mut handler: BackendReqHandler<Mutex<VhostUserHandler<T>>>,
    ) -> Result<()> {
        let handle = thread::Builder::new()
            .name(self.name.clone())
            .spawn(move || loop {
                handler.handle_request().map_err(Error::HandleRequest)?;
            })
            .map_err(Error::StartDaemon)?;

        self.main_thread = Some(handle);

        Ok(())
    }

    /// Connect to the vhost-user socket and run a dedicated thread handling
    /// all requests coming through this socket. This runs in an infinite loop
    /// that should be terminating once the other end of the socket (the VMM)
    /// hangs up.
    pub fn start_client(&mut self, socket_path: &str) -> Result<()> {
        let backend_handler = BackendReqHandler::connect(socket_path, self.handler.clone())
            .map_err(Error::CreateBackendReqHandler)?;
        self.start_daemon(backend_handler)
    }

    /// Listen to the vhost-user socket and run a dedicated thread handling all requests coming
    /// through this socket.
    ///
    /// This runs in an infinite loop that should be terminating once the other end of the socket
    /// (the VMM) disconnects.
    ///
    /// *Note:* A convenience function [VhostUserDaemon::serve] exists that
    /// may be a better option than this for simple use-cases.
    // TODO: the current implementation has limitations that only one incoming connection will be
    // handled from the listener. Should it be enhanced to support reconnection?
    pub fn start(&mut self, listener: Listener) -> Result<()> {
        let mut backend_listener = BackendListener::new(listener, self.handler.clone())
            .map_err(Error::CreateBackendListener)?;
        let backend_handler = self.accept(&mut backend_listener)?;
        self.start_daemon(backend_handler)
    }

    fn accept(
        &self,
        backend_listener: &mut BackendListener<Mutex<VhostUserHandler<T>>>,
    ) -> Result<BackendReqHandler<Mutex<VhostUserHandler<T>>>> {
        loop {
            match backend_listener.accept() {
                Err(e) => return Err(Error::CreateBackendListener(e)),
                Ok(Some(v)) => return Ok(v),
                Ok(None) => continue,
            }
        }
    }

    /// Wait for the thread handling the vhost-user socket connection to terminate.
    ///
    /// *Note:* A convenience function [VhostUserDaemon::serve] exists that
    /// may be a better option than this for simple use-cases.
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

    /// Bind to socket, handle a single connection and shutdown
    ///
    /// This is a convenience function that provides an easy way to handle the
    /// following actions without needing to call the low-level functions:
    /// - Create a listener
    /// - Start listening
    /// - Handle a single event
    /// - Send the exit event to all handler threads
    ///
    /// Internal `Err` results that indicate a device disconnect will be treated
    /// as success and `Ok(())` will be returned in those cases.
    ///
    /// *Note:* See [VhostUserDaemon::start] and [VhostUserDaemon::wait] if you
    /// need more flexibility.
    pub fn serve<P: AsRef<Path>>(&mut self, socket: P) -> Result<()> {
        let listener = Listener::new(socket, true).map_err(Error::CreateVhostUserListener)?;

        self.start(listener)?;
        let result = self.wait();

        // Regardless of the result, we want to signal worker threads to exit
        self.handler.lock().unwrap().send_exit_event();

        // For this convenience function we are not treating certain "expected"
        // outcomes as error. Disconnects and partial messages can be usual
        // behaviour seen from quitting guests.
        match &result {
            Err(e) => match e {
                Error::HandleRequest(VhostUserError::Disconnected) => Ok(()),
                Error::HandleRequest(VhostUserError::PartialMessage) => Ok(()),
                _ => result,
            },
            _ => result,
        }
    }

    /// Retrieve the vring epoll handler.
    ///
    /// This is necessary to perform further actions like registering and unregistering some extra
    /// event file descriptors.
    pub fn get_epoll_handlers(&self) -> Vec<Arc<VringEpollHandler<T>>> {
        // Do not expect poisoned lock.
        self.handler.lock().unwrap().get_epoll_handlers()
    }
}

#[cfg(test)]
mod tests {
    use super::backend::tests::MockVhostBackend;
    use super::*;
    use libc::EAGAIN;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::Barrier;
    use std::time::Duration;
    use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    #[test]
    fn test_new_daemon() {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));
        let mut daemon = VhostUserDaemon::new("test".to_owned(), backend, mem).unwrap();

        let handlers = daemon.get_epoll_handlers();
        assert_eq!(handlers.len(), 2);

        let barrier = Arc::new(Barrier::new(2));
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("socket");

        thread::scope(|s| {
            s.spawn(|| {
                barrier.wait();
                let socket = UnixStream::connect(&path).unwrap();
                barrier.wait();
                drop(socket)
            });

            let listener = Listener::new(&path, false).unwrap();
            barrier.wait();
            daemon.start(listener).unwrap();
            barrier.wait();
            // Above process generates a `HandleRequest(PartialMessage)` error.
            daemon.wait().unwrap_err();
            daemon.wait().unwrap();
        });
    }

    #[test]
    fn test_new_daemon_client() {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));
        let mut daemon = VhostUserDaemon::new("test".to_owned(), backend, mem).unwrap();

        let handlers = daemon.get_epoll_handlers();
        assert_eq!(handlers.len(), 2);

        let barrier = Arc::new(Barrier::new(2));
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("socket");

        thread::scope(|s| {
            s.spawn(|| {
                let listener = UnixListener::bind(&path).unwrap();
                barrier.wait();
                let (stream, _) = listener.accept().unwrap();
                barrier.wait();
                drop(stream)
            });

            barrier.wait();
            daemon
                .start_client(path.as_path().to_str().unwrap())
                .unwrap();
            barrier.wait();
            // Above process generates a `HandleRequest(PartialMessage)` error.
            daemon.wait().unwrap_err();
            daemon.wait().unwrap();
        });
    }

    #[test]
    fn test_daemon_serve() {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));
        let mut daemon = VhostUserDaemon::new("test".to_owned(), backend.clone(), mem).unwrap();
        let tmpdir = tempfile::tempdir().unwrap();
        let socket_path = tmpdir.path().join("socket");

        thread::scope(|s| {
            s.spawn(|| {
                let _ = daemon.serve(&socket_path);
            });

            // We have no way to wait for when the server becomes available...
            // So we will have to spin!
            while !socket_path.exists() {
                thread::sleep(Duration::from_millis(10));
            }

            // Check that no exit events got triggered yet
            for thread_id in 0..backend.queues_per_thread().len() {
                let fd = backend.exit_event(thread_id).unwrap();
                // Reading from exit fd should fail since nothing was written yet
                assert_eq!(
                    fd.read().unwrap_err().raw_os_error().unwrap(),
                    EAGAIN,
                    "exit event should not have been raised yet!"
                );
            }

            let socket = UnixStream::connect(&socket_path).unwrap();
            // disconnect immediately again
            drop(socket);
        });

        // Check that exit events got triggered
        let backend = backend.lock().unwrap();
        for thread_id in 0..backend.queues_per_thread().len() {
            let fd = backend.exit_event(thread_id).unwrap();
            assert!(fd.read().is_ok(), "No exit event was raised!");
        }
    }
}
