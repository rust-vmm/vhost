// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2019-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};
use std::io::{self, Result};
use std::marker::PhantomData;
use std::os::unix::io::{AsRawFd, RawFd};

use vm_memory::bitmap::Bitmap;
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::EventFd;

use super::backend::VhostUserBackend;
use super::vring::VringT;
use super::GM;

/// Errors related to vring epoll event handling.
#[derive(Debug)]
pub enum VringEpollError {
    /// Failed to create epoll file descriptor.
    EpollCreateFd(io::Error),
    /// Failed while waiting for events.
    EpollWait(io::Error),
    /// Could not register exit event
    RegisterExitEvent(io::Error),
    /// Failed to read the event from kick EventFd.
    HandleEventReadKick(io::Error),
    /// Failed to handle the event from the backend.
    HandleEventBackendHandling(io::Error),
}

impl Display for VringEpollError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            VringEpollError::EpollCreateFd(e) => write!(f, "cannot create epoll fd: {}", e),
            VringEpollError::EpollWait(e) => write!(f, "failed to wait for epoll event: {}", e),
            VringEpollError::RegisterExitEvent(e) => write!(f, "cannot register exit event: {}", e),
            VringEpollError::HandleEventReadKick(e) => {
                write!(f, "cannot read vring kick event: {}", e)
            }
            VringEpollError::HandleEventBackendHandling(e) => {
                write!(f, "failed to handle epoll event: {}", e)
            }
        }
    }
}

impl std::error::Error for VringEpollError {}

/// Result of vring epoll operations.
pub type VringEpollResult<T> = std::result::Result<T, VringEpollError>;

/// Epoll event handler to manage and process epoll events for registered file descriptor.
///
/// The `VringEpollHandler` structure provides interfaces to:
/// - add file descriptors to be monitored by the epoll fd
/// - remove registered file descriptors from the epoll fd
/// - run the event loop to handle pending events on the epoll fd
pub struct VringEpollHandler<S, V, B> {
    epoll: Epoll,
    backend: S,
    vrings: Vec<V>,
    thread_id: usize,
    exit_event_fd: Option<EventFd>,
    phantom: PhantomData<B>,
}

impl<S, V, B> VringEpollHandler<S, V, B> {
    /// Send `exit event` to break the event loop.
    pub fn send_exit_event(&self) {
        if let Some(eventfd) = self.exit_event_fd.as_ref() {
            let _ = eventfd.write(1);
        }
    }
}

impl<S, V, B> VringEpollHandler<S, V, B>
where
    S: VhostUserBackend<V, B>,
    V: VringT<GM<B>>,
    B: Bitmap + 'static,
{
    /// Create a `VringEpollHandler` instance.
    pub(crate) fn new(backend: S, vrings: Vec<V>, thread_id: usize) -> VringEpollResult<Self> {
        let epoll = Epoll::new().map_err(VringEpollError::EpollCreateFd)?;

        let handler = match backend.exit_event(thread_id) {
            Some(exit_event_fd) => {
                let id = backend.num_queues();
                epoll
                    .ctl(
                        ControlOperation::Add,
                        exit_event_fd.as_raw_fd(),
                        EpollEvent::new(EventSet::IN, id as u64),
                    )
                    .map_err(VringEpollError::RegisterExitEvent)?;

                VringEpollHandler {
                    epoll,
                    backend,
                    vrings,
                    thread_id,
                    exit_event_fd: Some(exit_event_fd),
                    phantom: PhantomData,
                }
            }
            None => VringEpollHandler {
                epoll,
                backend,
                vrings,
                thread_id,
                exit_event_fd: None,
                phantom: PhantomData,
            },
        };

        Ok(handler)
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
        self.epoll
            .ctl(ControlOperation::Add, fd, EpollEvent::new(ev_type, data))
    }

    pub(crate) fn unregister_event(&self, fd: RawFd, ev_type: EventSet, data: u64) -> Result<()> {
        self.epoll
            .ctl(ControlOperation::Delete, fd, EpollEvent::new(ev_type, data))
    }

    /// Run the event poll loop to handle all pending events on registered fds.
    ///
    /// The event loop will be terminated once an event is received from the `exit event fd`
    /// associated with the backend.
    pub(crate) fn run(&self) -> VringEpollResult<()> {
        const EPOLL_EVENTS_LEN: usize = 100;
        let mut events = vec![EpollEvent::new(EventSet::empty(), 0); EPOLL_EVENTS_LEN];

        'epoll: loop {
            let num_events = match self.epoll.wait(-1, &mut events[..]) {
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
                    return Err(VringEpollError::EpollWait(e));
                }
            };

            for event in events.iter().take(num_events) {
                let evset = match EventSet::from_bits(event.events) {
                    Some(evset) => evset,
                    None => {
                        let evbits = event.events;
                        println!("epoll: ignoring unknown event set: 0x{:x}", evbits);
                        continue;
                    }
                };

                let ev_type = event.data() as u16;

                // handle_event() returns true if an event is received from the exit event fd.
                if self.handle_event(ev_type, evset)? {
                    break 'epoll;
                }
            }
        }

        Ok(())
    }

    fn handle_event(&self, device_event: u16, evset: EventSet) -> VringEpollResult<bool> {
        if self.exit_event_fd.is_some() && device_event as usize == self.backend.num_queues() {
            return Ok(true);
        }

        if (device_event as usize) < self.vrings.len() {
            let vring = &self.vrings[device_event as usize];
            let enabled = vring
                .read_kick()
                .map_err(VringEpollError::HandleEventReadKick)?;

            // If the vring is not enabled, it should not be processed.
            if !enabled {
                return Ok(false);
            }
        }

        self.backend
            .handle_event(device_event, evset, &self.vrings, self.thread_id)
            .map_err(VringEpollError::HandleEventBackendHandling)
    }
}

impl<S, V, B> AsRawFd for VringEpollHandler<S, V, B> {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll.as_raw_fd()
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
            .register_listener(eventfd.as_raw_fd(), EventSet::IN, 3)
            .unwrap();
        // Register an already registered fd.
        handler
            .register_listener(eventfd.as_raw_fd(), EventSet::IN, 3)
            .unwrap_err();
        // Register an invalid data.
        handler
            .register_listener(eventfd.as_raw_fd(), EventSet::IN, 1)
            .unwrap_err();

        handler
            .unregister_listener(eventfd.as_raw_fd(), EventSet::IN, 3)
            .unwrap();
        // unregister an already unregistered fd.
        handler
            .unregister_listener(eventfd.as_raw_fd(), EventSet::IN, 3)
            .unwrap_err();
        // unregister an invalid data.
        handler
            .unregister_listener(eventfd.as_raw_fd(), EventSet::IN, 1)
            .unwrap_err();
        // Check we retrieve the correct file descriptor
        assert_eq!(handler.as_raw_fd(), handler.epoll.as_raw_fd());
    }
}
