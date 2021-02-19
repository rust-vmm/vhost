// Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate log;

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::prelude::IntoRawFd;
use std::result;
use std::sync::{Arc, Mutex, RwLock};
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

pub mod backend;
pub use backend::{VhostUserBackend, VhostUserBackendMut};

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
    /// Failed to process queue.
    ProcessQueue(VringEpollHandlerError),
    /// Failed to register listener.
    RegisterListener(io::Error),
    /// Failed to unregister listener.
    UnregisterListener(io::Error),
}

/// Result of vhost-user daemon operations.
pub type Result<T> = result::Result<T, Error>;

/// This structure is the public API the backend is allowed to interact with
/// in order to run a fully functional vhost-user daemon.
pub struct VhostUserDaemon<S: VhostUserBackend> {
    name: String,
    handler: Arc<Mutex<VhostUserHandler<S>>>,
    main_thread: Option<thread::JoinHandle<Result<()>>>,
}

impl<S: VhostUserBackend + Clone> VhostUserDaemon<S> {
    /// Create the daemon instance, providing the backend implementation of
    /// VhostUserBackend.
    /// Under the hood, this will start a dedicated thread responsible for
    /// listening onto registered event. Those events can be vring events or
    /// custom events from the backend, but they get to be registered later
    /// during the sequence.
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

    /// Connect to the vhost-user socket and run a dedicated thread handling
    /// all requests coming through this socket. This runs in an infinite loop
    /// that should be terminating once the other end of the socket (the VMM)
    /// disconnects.
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

    /// Wait for the thread handling the vhost-user socket connection to
    /// terminate.
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

    /// Retrieve the vring worker. This is necessary to perform further
    /// actions like registering and unregistering some extra event file
    /// descriptors.
    pub fn get_vring_workers(&self) -> Vec<Arc<VringWorker>> {
        self.handler.lock().unwrap().get_vring_workers()
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

#[derive(Debug)]
/// Errors related to vring epoll handler.
pub enum VringEpollHandlerError {
    /// Failed to process the queue from the backend.
    ProcessQueueBackendProcessing(io::Error),
    /// Failed to signal used queue.
    SignalUsedQueue(io::Error),
    /// Failed to read the event from kick EventFd.
    HandleEventReadKick(io::Error),
    /// Failed to handle the event from the backend.
    HandleEventBackendHandling(io::Error),
}

/// Result of vring epoll handler operations.
type VringEpollHandlerResult<T> = std::result::Result<T, VringEpollHandlerError>;

struct VringEpollHandler<S: VhostUserBackend> {
    backend: S,
    vrings: Vec<Arc<RwLock<Vring>>>,
    exit_event_id: Option<u16>,
    thread_id: usize,
}

impl<S: VhostUserBackend> VringEpollHandler<S> {
    fn handle_event(
        &self,
        device_event: u16,
        evset: epoll::Events,
    ) -> VringEpollHandlerResult<bool> {
        if self.exit_event_id == Some(device_event) {
            return Ok(true);
        }

        let num_queues = self.vrings.len();
        if (device_event as usize) < num_queues {
            if let Some(kick) = &self.vrings[device_event as usize].read().unwrap().kick {
                kick.read()
                    .map_err(VringEpollHandlerError::HandleEventReadKick)?;
            }

            // If the vring is not enabled, it should not be processed.
            // The event is only read to be discarded.
            if !self.vrings[device_event as usize].read().unwrap().enabled {
                return Ok(false);
            }
        }

        self.backend
            .handle_event(device_event, evset, &self.vrings, self.thread_id)
            .map_err(VringEpollHandlerError::HandleEventBackendHandling)
    }
}

#[derive(Debug)]
/// Errors related to vring worker.
enum VringWorkerError {
    /// Failed while waiting for events.
    EpollWait(io::Error),
    /// Failed to handle the event.
    HandleEvent(VringEpollHandlerError),
}

/// Result of vring worker operations.
type VringWorkerResult<T> = std::result::Result<T, VringWorkerError>;

pub struct VringWorker {
    epoll_file: File,
}

impl AsRawFd for VringWorker {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_file.as_raw_fd()
    }
}

impl VringWorker {
    fn run<S: VhostUserBackend>(&self, handler: VringEpollHandler<S>) -> VringWorkerResult<()> {
        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN];

        'epoll: loop {
            let num_events = match epoll::wait(self.epoll_file.as_raw_fd(), -1, &mut events[..]) {
                Ok(res) => res,
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // It's well defined from the epoll_wait() syscall
                        // documentation that the epoll loop can be interrupted
                        // before any of the requested events occurred or the
                        // timeout expired. In both those cases, epoll_wait()
                        // returns an error of type EINTR, but this should not
                        // be considered as a regular error. Instead it is more
                        // appropriate to retry, by calling into epoll_wait().
                        continue;
                    }
                    return Err(VringWorkerError::EpollWait(e));
                }
            };

            for event in events.iter().take(num_events) {
                let evset = match epoll::Events::from_bits(event.events) {
                    Some(evset) => evset,
                    None => {
                        let evbits = event.events;
                        println!("epoll: ignoring unknown event set: 0x{:x}", evbits);
                        continue;
                    }
                };

                let ev_type = event.data as u16;

                if handler
                    .handle_event(ev_type, evset)
                    .map_err(VringWorkerError::HandleEvent)?
                {
                    break 'epoll;
                }
            }
        }

        Ok(())
    }

    /// Register a custom event only meaningful to the caller. When this event
    /// is later triggered, and because only the caller knows what to do about
    /// it, the backend implementation of `handle_event` will be called.
    /// This lets entire control to the caller about what needs to be done for
    /// this special event, without forcing it to run its own dedicated epoll
    /// loop for it.
    pub fn register_listener(
        &self,
        fd: RawFd,
        ev_type: epoll::Events,
        data: u64,
    ) -> result::Result<(), io::Error> {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(ev_type, data),
        )
    }

    /// Unregister a custom event. If the custom event is triggered after this
    /// function has been called, nothing will happen as it will be removed
    /// from the list of file descriptors the epoll loop is listening to.
    pub fn unregister_listener(
        &self,
        fd: RawFd,
        ev_type: epoll::Events,
        data: u64,
    ) -> result::Result<(), io::Error> {
        epoll::ctl(
            self.epoll_file.as_raw_fd(),
            epoll::ControlOptions::EPOLL_CTL_DEL,
            fd,
            epoll::Event::new(ev_type, data),
        )
    }
}
