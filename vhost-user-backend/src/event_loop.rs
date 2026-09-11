// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2019-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::io::{self, ErrorKind, Result};
use std::marker::PhantomData;
use std::os::fd::IntoRawFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex;

use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::event::{
    new_event_consumer_and_notifier, EventConsumer, EventFlag, EventNotifier,
};

use super::backend::VhostUserBackend;
use super::vring::VringT;

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
    /// Vring index out or range.
    VringIndexOutOfRange(usize),
    /// Failed to create event consumer and notifier pair.
    NewEventConsumerNotifier(io::Error),
    /// Could not register vring enabled event fd.
    RegisterVringEnabledEvent(io::Error),
    /// Failed to consume event from vring enabled event fd.
    HandleVringEnabledEventConsume(io::Error),
}

impl Display for VringEpollError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            VringEpollError::EpollCreateFd(e) => write!(f, "cannot create epoll fd: {e}"),
            VringEpollError::EpollWait(e) => write!(f, "failed to wait for epoll event: {e}"),
            VringEpollError::RegisterExitEvent(e) => write!(f, "cannot register exit event: {e}"),
            VringEpollError::HandleEventReadKick(e) => {
                write!(f, "cannot read vring kick event: {e}")
            }
            VringEpollError::HandleEventBackendHandling(e) => {
                write!(f, "failed to handle epoll event: {e}")
            }
            VringEpollError::VringIndexOutOfRange(idx) => {
                write!(f, "vring index out of range: {idx}")
            }
            VringEpollError::NewEventConsumerNotifier(e) => {
                write!(f, "failed to create event consumer and notifier: {e}")
            }
            VringEpollError::RegisterVringEnabledEvent(e) => {
                write!(f, "cannot register vring enabled event fd: {e}")
            }
            VringEpollError::HandleVringEnabledEventConsume(e) => {
                write!(f, "failed to consume vring enabled event: {e}")
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
pub struct VringEpollHandler<T: VhostUserBackend> {
    epoll: Epoll,
    backend: T,
    vrings: Vec<T::Vring>,
    thread_id: usize,
    exit_event_fd: Option<EventNotifier>,
    vring_enabled_event_fd: (EventConsumer, EventNotifier),
    vrings_with_pending_events: Mutex<HashSet<u16>>,
    phantom: PhantomData<T::Bitmap>,
}

impl<T: VhostUserBackend> VringEpollHandler<T> {
    /// Send `exit event` to break the event loop.
    pub fn send_exit_event(&self) {
        if let Some(eventfd) = self.exit_event_fd.as_ref() {
            let _ = eventfd.notify();
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
        let epoll = Epoll::new().map_err(VringEpollError::EpollCreateFd)?;
        let exit_event_fd = backend.exit_event(thread_id);

        let exit_event_fd = if let Some((consumer, notifier)) = exit_event_fd {
            let id = backend.num_queues();
            epoll
                .ctl(
                    ControlOperation::Add,
                    consumer.into_raw_fd(),
                    EpollEvent::new(EventSet::IN, id as u64),
                )
                .map_err(VringEpollError::RegisterExitEvent)?;
            Some(notifier)
        } else {
            None
        };

        let vring_enabled_event_fd =
            new_event_consumer_and_notifier(EventFlag::NONBLOCK | EventFlag::CLOEXEC)
                .map_err(VringEpollError::NewEventConsumerNotifier)?;
        let vring_enabled_event = backend.num_queues() as u64;
        epoll
            .ctl(
                ControlOperation::Add,
                vring_enabled_event_fd.0.as_raw_fd(),
                EpollEvent::new(EventSet::IN, vring_enabled_event),
            )
            .map_err(VringEpollError::RegisterVringEnabledEvent)?;

        Ok(VringEpollHandler {
            epoll,
            backend,
            vrings,
            thread_id,
            exit_event_fd,
            vring_enabled_event_fd,
            vrings_with_pending_events: Mutex::new(HashSet::new()),
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
        if data < self.backend.num_queues() as u64 {
            self.vrings_with_pending_events
                .lock()
                .unwrap()
                .insert(data as u16);
            self.vring_enabled_event_fd.1.notify()?;
        }
        self.epoll
            .ctl(ControlOperation::Add, fd, EpollEvent::new(ev_type, data))
    }

    pub(crate) fn unregister_event(&self, fd: RawFd, ev_type: EventSet, data: u64) -> Result<()> {
        if data < self.backend.num_queues() as u64 {
            self.vrings_with_pending_events
                .lock()
                .unwrap()
                .remove(&(data as u16));
        }
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
                        println!("epoll: ignoring unknown event set: 0x{evbits:x}");
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
        if device_event as usize == self.backend.num_queues() {
            return self.handle_num_queues_event(evset);
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
            .map_err(VringEpollError::HandleEventBackendHandling)?;

        Ok(false)
    }

    fn handle_num_queues_event(&self, evset: EventSet) -> VringEpollResult<bool> {
        // The num_queues event can be triggered by the exit event fd or a vring becoming enabled.
        // The vring_enabled_event_fd is guaranteed to be non-blocking so reading from it will
        // determine which fd triggered the event.
        match self.vring_enabled_event_fd.0.consume() {
            Ok(()) => {
                let vrings_with_pending_events =
                    std::mem::take(&mut *self.vrings_with_pending_events.lock().unwrap());
                for device_event in vrings_with_pending_events {
                    let vring_idx = device_event as usize;
                    if vring_idx >= self.backend.num_queues() {
                        return Err(VringEpollError::VringIndexOutOfRange(vring_idx));
                    }
                    self.backend
                        .handle_event(device_event, evset, &self.vrings, self.thread_id)
                        .map_err(VringEpollError::HandleEventBackendHandling)?;
                }
                // There may have been a notification in the exit fd too, but it wasn't consumed and
                // it's not safe to attempt to because that fd may not be non-blocking. Returning
                // false ensures there will be another iteration of the main loop which will trigger
                // the same event if exit fd is readable.
                Ok(false)
            }
            // With no notification in the vring enabled fd the only other option is the exit fd.
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(true),
            Err(e) => Err(VringEpollError::HandleVringEnabledEventConsume(e)),
        }
    }
}

impl<T: VhostUserBackend> AsRawFd for VringEpollHandler<T> {
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
    use vmm_sys_util::event::{new_event_consumer_and_notifier, EventFlag};

    #[test]
    fn test_vring_epoll_handler() {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0x100000), 0x10000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        let backend = Arc::new(Mutex::new(MockVhostBackend::new()));

        let handler = VringEpollHandler::new(backend, vec![vring], 0x1).unwrap();

        let (consumer, _notifier) = new_event_consumer_and_notifier(EventFlag::empty()).unwrap();
        handler
            .register_listener(consumer.as_raw_fd(), EventSet::IN, 3)
            .unwrap();
        // Register an already registered fd.
        handler
            .register_listener(consumer.as_raw_fd(), EventSet::IN, 3)
            .unwrap_err();
        // Register an invalid data.
        handler
            .register_listener(consumer.as_raw_fd(), EventSet::IN, 1)
            .unwrap_err();

        handler
            .unregister_listener(consumer.as_raw_fd(), EventSet::IN, 3)
            .unwrap();
        // unregister an already unregistered fd.
        handler
            .unregister_listener(consumer.as_raw_fd(), EventSet::IN, 3)
            .unwrap_err();
        // unregister an invalid data.
        handler
            .unregister_listener(consumer.as_raw_fd(), EventSet::IN, 1)
            .unwrap_err();
        // Check we retrieve the correct file descriptor
        assert_eq!(handler.as_raw_fd(), handler.epoll.as_raw_fd());
    }
}
