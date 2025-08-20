// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2019-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::io::{self, Result};
use std::marker::PhantomData;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex;

use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};
use vmm_sys_util::eventfd::EventFd;

use super::backend::VhostUserBackend;
use super::vring::VringT;

/// Errors related to vring epoll event handling.
#[derive(Debug)]
pub enum VringPollError {
    /// Failed to create epoll file descriptor.
    PollerCreate(io::Error),
    /// Failed while waiting for events.
    PollerWait(io::Error),
    /// Could not register exit event
    RegisterExitEvent(io::Error),
    /// Failed to read the event from kick EventFd.
    HandleEventReadKick(io::Error),
    /// Failed to handle the event from the backend.
    HandleEventBackendHandling(io::Error),
    /// Failed to clone registry.
    RegistryClone(io::Error),
}

impl Display for VringPollError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            VringPollError::PollerCreate(e) => write!(f, "cannot create poller: {e}"),
            VringPollError::PollerWait(e) => write!(f, "failed to wait for poller event: {e}"),
            VringPollError::RegisterExitEvent(e) => write!(f, "cannot register exit event: {e}"),
            VringPollError::HandleEventReadKick(e) => {
                write!(f, "cannot read vring kick event: {e}")
            }
            VringPollError::HandleEventBackendHandling(e) => {
                write!(f, "failed to handle poll event: {e}")
            }
            VringPollError::RegistryClone(e) => write!(f, "cannot clone poller's registry: {e}"),
        }
    }
}

impl std::error::Error for VringPollError {}

/// Result of vring epoll operations.
pub type VringEpollResult<T> = std::result::Result<T, VringPollError>;

pub enum EventSet {
    Readable,
    Writable,
    All,
}

impl EventSet {
    fn to_interest(&self) -> Interest {
        match self {
            EventSet::Readable => Interest::READABLE,
            EventSet::Writable => Interest::WRITABLE,
            EventSet::All => Interest::READABLE | Interest::WRITABLE,
        }
    }
}

fn event_to_event_set(evt: &Event) -> Option<EventSet> {
    if evt.is_readable() && evt.is_writable() {
        return Some(EventSet::All);
    }
    if evt.is_readable() {
        return Some(EventSet::Readable);
    }
    if evt.is_writable() {
        return Some(EventSet::Writable);
    }
    None
}

/// Epoll event handler to manage and process epoll events for registered file descriptor.
///
/// The `VringEpollHandler` structure provides interfaces to:
/// - add file descriptors to be monitored by the epoll fd
/// - remove registered file descriptors from the epoll fd
/// - run the event loop to handle pending events on the epoll fd
pub struct VringEpollHandler<T: VhostUserBackend> {
    poller: Mutex<Poll>,
    registry: Registry,
    // Record the registered fd.
    // Because in mio, consecutive calls to register is unspecified behavior.
    fd_set: Mutex<HashSet<RawFd>>,
    backend: T,
    vrings: Vec<T::Vring>,
    thread_id: usize,
    exit_event_fd: Option<EventFd>,
    phantom: PhantomData<T::Bitmap>,
}

impl<T: VhostUserBackend> VringEpollHandler<T> {
    /// Send `exit event` to break the event loop.
    pub fn send_exit_event(&self) {
        if let Some(eventfd) = self.exit_event_fd.as_ref() {
            let _ = eventfd.write(1);
        }
    }
}

impl<T> VringEpollHandler<T>
where
    T: VhostUserBackend,
{
    /// Create a `VringEpollHandler` instance.
    pub(crate) fn new(
        backend: T,
        vrings: Vec<T::Vring>,
        thread_id: usize,
    ) -> VringEpollResult<Self> {
        let poller = Poll::new().map_err(VringPollError::PollerCreate)?;
        let exit_event_fd = backend.exit_event(thread_id);
        let fd_set = Mutex::new(HashSet::new());

        let registry = poller
            .registry()
            .try_clone()
            .map_err(VringPollError::RegistryClone)?;
        if let Some(exit_event_fd) = &exit_event_fd {
            let id = backend.num_queues();

            registry
                .register(
                    &mut SourceFd(&exit_event_fd.as_raw_fd()),
                    Token(id),
                    Interest::READABLE,
                )
                .map_err(VringPollError::RegisterExitEvent)?;

            fd_set.lock().unwrap().insert(exit_event_fd.as_raw_fd());
        }

        Ok(VringEpollHandler {
            poller: Mutex::new(poller),
            registry,
            fd_set,
            backend,
            vrings,
            thread_id,
            exit_event_fd,
            phantom: PhantomData,
        })
    }

    /// Register an event into the epoll fd.
    ///
    /// When this event is later triggered, the backend implementation of `handle_event` will be
    /// called.
    pub fn register_listener(&self, fd: RawFd, ev_type: EventSet, data: u64) -> Result<()> {
        // `data` range [0...num_queues] is reserved for queues and exit event.
        if data <= self.backend.num_queues() as u64 {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        } else {
            self.register_event(fd, ev_type, data)
        }
    }

    /// Unregister an event from the epoll fd.
    ///
    /// If the event is triggered after this function has been called, the event will be silently
    /// dropped.
    pub fn unregister_listener(&self, fd: RawFd, ev_type: EventSet, data: u64) -> Result<()> {
        // `data` range [0...num_queues] is reserved for queues and exit event.
        if data <= self.backend.num_queues() as u64 {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        } else {
            self.unregister_event(fd, ev_type, data)
        }
    }

    pub(crate) fn register_event(&self, fd: RawFd, ev_type: EventSet, data: u64) -> Result<()> {
        let mut fd_set = self.fd_set.lock().unwrap();
        if fd_set.contains(&fd) {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        self.registry
            .register(
                &mut SourceFd(&fd),
                Token(data as usize),
                ev_type.to_interest(),
            )
            .map_err(std::io::Error::other)?;
        fd_set.insert(fd);
        Ok(())
    }

    pub(crate) fn unregister_event(&self, fd: RawFd, _ev_type: EventSet, _data: u64) -> Result<()> {
        let mut fd_set = self.fd_set.lock().unwrap();
        if !fd_set.contains(&fd) {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        self.registry
            .deregister(&mut SourceFd(&fd))
            .map_err(|e| std::io::Error::other(format!("Failed to deregister fd {}: {}", fd, e)))?;
        fd_set.remove(&fd);
        Ok(())
    }

    /// Run the event poll loop to handle all pending events on registered fds.
    ///
    /// The event loop will be terminated once an event is received from the `exit event fd`
    /// associated with the backend.
    pub(crate) fn run(&self) -> VringEpollResult<()> {
        const EPOLL_EVENTS_LEN: usize = 100;

        let mut events = Events::with_capacity(EPOLL_EVENTS_LEN);
        'poll: loop {
            self.poller
                .lock()
                .unwrap()
                .poll(&mut events, None)
                .map_err(VringPollError::PollerWait)?;

            for event in events.iter() {
                let token = event.token();

                if let Some(evt_set) = event_to_event_set(event) {
                    if self.handle_event(token.0 as u16, evt_set)? {
                        break 'poll;
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_event(&self, device_event: u16, event: EventSet) -> VringEpollResult<bool> {
        if self.exit_event_fd.is_some() && device_event as usize == self.backend.num_queues() {
            return Ok(true);
        }

        if (device_event as usize) < self.vrings.len() {
            let vring = &self.vrings[device_event as usize];
            let enabled = vring
                .read_kick()
                .map_err(VringPollError::HandleEventReadKick)?;

            // If the vring is not enabled, it should not be processed.
            if !enabled {
                return Ok(false);
            }
        }

        self.backend
            .handle_event(device_event, event, &self.vrings, self.thread_id)
            .map_err(VringPollError::HandleEventBackendHandling)?;

        Ok(false)
    }
}

impl<T: VhostUserBackend> AsRawFd for VringEpollHandler<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.poller.lock().unwrap().as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::super::backend::tests::MockVhostBackend;
    use super::super::vring::VringRwLock;
    use super::*;
    use std::sync::{Arc, Mutex};
    use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};
    use vmm_sys_util::eventfd::EventFd;

    #[test]
    fn test_vring_epoll_handler() {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));

        let handler = VringEpollHandler::new(backend, vec![vring], 0x1).unwrap();

        let eventfd = EventFd::new(0).unwrap();
        handler
            .register_listener(eventfd.as_raw_fd(), EventSet::Readable, 3)
            .unwrap();
        // Register an already registered fd.
        handler
            .register_listener(eventfd.as_raw_fd(), EventSet::Readable, 3)
            .unwrap_err();
        // Register an invalid data.
        handler
            .register_listener(eventfd.as_raw_fd(), EventSet::Readable, 1)
            .unwrap_err();

        handler
            .unregister_listener(eventfd.as_raw_fd(), EventSet::Readable, 3)
            .unwrap();
        // unregister an already unregistered fd.
        handler
            .unregister_listener(eventfd.as_raw_fd(), EventSet::Readable, 3)
            .unwrap_err();
        // unregister an invalid data.
        handler
            .unregister_listener(eventfd.as_raw_fd(), EventSet::Readable, 1)
            .unwrap_err();
        // Check we retrieve the correct file descriptor
        assert_eq!(
            handler.as_raw_fd(),
            handler.poller.lock().unwrap().as_raw_fd()
        );
    }
}
