// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2019-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::io::{self, Result};
use std::marker::PhantomData;
use std::os::fd::IntoRawFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex;

use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};
use vmm_sys_util::event::EventNotifier;

use super::backend::VhostUserBackend;
use super::vring::VringT;

/// Errors related to vring epoll/kqueue event handling.
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

/// Result of vring epoll/kqueue operations.
pub type VringPollResult<T> = std::result::Result<T, VringPollError>;

#[derive(Debug, Clone, Copy)]
pub enum EventSet {
    Readable,
    Writable,
    All,
}

impl EventSet {
    fn to_interest(self) -> Interest {
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

/// Epoll/kqueue event handler to manage and process epoll/kqueue events for registered file descriptor.
///
/// The `VringPollHandler` structure provides interfaces to:
/// - add file descriptors to be monitored by the epoll/kqueue fd
/// - remove registered file descriptors from the epoll/kqueue fd
/// - run the event loop to handle pending events on the epoll/kqueue fd
pub struct VringPollHandler<T: VhostUserBackend> {
    poller: Mutex<Poll>,
    registry: Registry,
    // Record the registered fd.
    // Because in mio, consecutive calls to register is unspecified behavior.
    fd_set: Mutex<HashSet<RawFd>>,
    backend: T,
    vrings: Vec<T::Vring>,
    thread_id: usize,
    exit_event_fd: Option<EventNotifier>,
    phantom: PhantomData<T::Bitmap>,
}

impl<T: VhostUserBackend> VringPollHandler<T> {
    /// Send `exit event` to break the event loop.
    pub fn send_exit_event(&self) {
        if let Some(eventfd) = self.exit_event_fd.as_ref() {
            let _ = eventfd.notify();
        }
    }
}

impl<T> VringPollHandler<T>
where
    T: VhostUserBackend,
{
    /// Create a `VringPollHandler` instance.
    pub(crate) fn new(
        backend: T,
        vrings: Vec<T::Vring>,
        thread_id: usize,
    ) -> VringPollResult<Self> {
        let poller = Poll::new().map_err(VringPollError::PollerCreate)?;
        let exit_event_fd = backend.exit_event(thread_id);
        let fd_set = Mutex::new(HashSet::new());

        let registry = poller
            .registry()
            .try_clone()
            .map_err(VringPollError::RegistryClone)?;
        let exit_event_fd = if let Some((consumer, notifier)) = exit_event_fd {
            let id = backend.num_queues();

            registry
                .register(
                    &mut SourceFd(&consumer.as_raw_fd()),
                    Token(id),
                    Interest::READABLE,
                )
                .map_err(VringPollError::RegisterExitEvent)?;

            fd_set.lock().unwrap().insert(consumer.into_raw_fd());
            Some(notifier)
        } else {
            None
        };

        Ok(VringPollHandler {
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

    /// Register an event into the epoll/kqueue fd.
    ///
    /// When this event is later triggered, the backend implementation of `handle_event` will be
    /// called.
    pub fn register_listener(&self, fd: RawFd, ev_type: EventSet, data: usize) -> Result<()> {
        // `data` range [0...num_queues] is reserved for queues and exit event.
        if data <= self.backend.num_queues() {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        } else {
            self.register_event(fd, ev_type, data)
        }
    }

    /// Unregister an event from the epoll/kqueue fd.
    ///
    /// If the event is triggered after this function has been called, the event will be silently
    /// dropped.
    pub fn unregister_listener(&self, fd: RawFd, data: usize) -> Result<()> {
        // `data` range [0...num_queues] is reserved for queues and exit event.
        if data <= self.backend.num_queues() {
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        } else {
            self.unregister_event(fd)
        }
    }

    pub(crate) fn register_event(&self, fd: RawFd, ev_type: EventSet, data: usize) -> Result<()> {
        let mut fd_set = self.fd_set.lock().unwrap();
        if fd_set.contains(&fd) {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        self.registry
            .register(&mut SourceFd(&fd), Token(data), ev_type.to_interest())
            .map_err(std::io::Error::other)?;
        fd_set.insert(fd);
        Ok(())
    }

    pub(crate) fn unregister_event(&self, fd: RawFd) -> Result<()> {
        let mut fd_set = self.fd_set.lock().unwrap();
        if !fd_set.contains(&fd) {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        self.registry
            .deregister(&mut SourceFd(&fd))
            .map_err(|e| std::io::Error::other(format!("Failed to deregister fd {fd}: {e}")))?;
        fd_set.remove(&fd);
        Ok(())
    }

    /// Run the event poll loop to handle all pending events on registered fds.
    ///
    /// The event loop will be terminated once an event is received from the `exit event fd`
    /// associated with the backend.
    pub(crate) fn run(&self) -> VringPollResult<()> {
        const POLL_EVENTS_LEN: usize = 100;

        let mut events = Events::with_capacity(POLL_EVENTS_LEN);
        'poll: loop {
            self.poller
                .lock()
                .unwrap()
                .poll(&mut events, None)
                .map_err(VringPollError::PollerWait)?;

            for event in &events {
                let token = event.token();

                if let Some(evt_set) = event_to_event_set(event) {
                    if self.handle_event(token.0, evt_set)? {
                        break 'poll;
                    }
                } else {
                    println!("ignoring unknown event set: {:#x}", event.token().0);
                }
            }
        }

        Ok(())
    }

    fn handle_event(&self, device_event: usize, evset: EventSet) -> VringPollResult<bool> {
        if self.exit_event_fd.is_some() && device_event == self.backend.num_queues() {
            return Ok(true);
        }

        if device_event < self.vrings.len() {
            let vring = &self.vrings[device_event];
            let enabled = vring
                .read_kick()
                .map_err(VringPollError::HandleEventReadKick)?;

            // If the vring is not enabled, it should not be processed.
            if !enabled {
                return Ok(false);
            }
        }

        self.backend
            .handle_event(device_event, evset, &self.vrings, self.thread_id)
            .map_err(VringPollError::HandleEventBackendHandling)?;

        Ok(false)
    }
}

impl<T: VhostUserBackend> AsRawFd for VringPollHandler<T> {
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
    use vmm_sys_util::event::{new_event_consumer_and_notifier, EventFlag};

    #[test]
    fn test_vring_poll_handler() {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));

        let handler = VringPollHandler::new(backend, vec![vring], 0x1).unwrap();

        let (consumer, _notifier) = new_event_consumer_and_notifier(EventFlag::empty()).unwrap();
        handler
            .register_listener(consumer.as_raw_fd(), EventSet::Readable, 3)
            .unwrap();
        // Register an already registered fd.
        handler
            .register_listener(consumer.as_raw_fd(), EventSet::Readable, 3)
            .unwrap_err();
        // Register an invalid data.
        handler
            .register_listener(consumer.as_raw_fd(), EventSet::Readable, 1)
            .unwrap_err();

        handler
            .unregister_listener(consumer.as_raw_fd(), 3)
            .unwrap();
        // unregister an already unregistered fd.
        handler
            .unregister_listener(consumer.as_raw_fd(), 3)
            .unwrap_err();
        // unregister an invalid data.
        handler
            .unregister_listener(consumer.as_raw_fd(), 1)
            .unwrap_err();
        // Check we retrieve the correct file descriptor
        assert_eq!(
            handler.as_raw_fd(),
            handler.poller.lock().unwrap().as_raw_fd()
        );
    }
}
