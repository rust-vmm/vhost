// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Traits and Structs for vhost-user backend.

use std::sync::Arc;

use super::connection::{Endpoint, Listener};
use super::message::*;
use super::{BackendReqHandler, Result, VhostUserBackendReqHandler};

/// Vhost-user backend side connection listener.
pub struct BackendListener<S: VhostUserBackendReqHandler> {
    listener: Listener,
    backend: Option<Arc<S>>,
}

/// Sets up a listener for incoming frontend connections, and handles construction
/// of a Backend on success.
impl<S: VhostUserBackendReqHandler> BackendListener<S> {
    /// Create a unix domain socket for incoming frontend connections.
    pub fn new(listener: Listener, backend: Arc<S>) -> Result<Self> {
        Ok(BackendListener {
            listener,
            backend: Some(backend),
        })
    }

    /// Accept an incoming connection from the frontend, returning Some(Backend) on
    /// success, or None if the socket is nonblocking and no incoming connection
    /// was detected
    pub fn accept(&mut self) -> Result<Option<BackendReqHandler<S>>> {
        if let Some(fd) = self.listener.accept()? {
            return Ok(Some(BackendReqHandler::new(
                Endpoint::<FrontendReq>::from_stream(fd),
                self.backend.take().unwrap(),
            )));
        }
        Ok(None)
    }

    /// Change blocking status on the listener.
    pub fn set_nonblocking(&self, block: bool) -> Result<()> {
        self.listener.set_nonblocking(block)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::vhost_user::dummy_backend::DummyBackendReqHandler;

    #[test]
    fn test_backend_listener_set_nonblocking() {
        let backend = Arc::new(Mutex::new(DummyBackendReqHandler::new()));
        let listener =
            Listener::new("/tmp/vhost_user_lib_unit_test_backend_nonblocking", true).unwrap();
        let backend_listener = BackendListener::new(listener, backend).unwrap();

        backend_listener.set_nonblocking(true).unwrap();
        backend_listener.set_nonblocking(false).unwrap();
        backend_listener.set_nonblocking(false).unwrap();
        backend_listener.set_nonblocking(true).unwrap();
        backend_listener.set_nonblocking(true).unwrap();
    }

    #[cfg(feature = "vhost-user-frontend")]
    #[test]
    fn test_backend_listener_accept() {
        use super::super::Frontend;

        let path = "/tmp/vhost_user_lib_unit_test_backend_accept";
        let backend = Arc::new(Mutex::new(DummyBackendReqHandler::new()));
        let listener = Listener::new(path, true).unwrap();
        let mut backend_listener = BackendListener::new(listener, backend).unwrap();

        backend_listener.set_nonblocking(true).unwrap();
        assert!(backend_listener.accept().unwrap().is_none());
        assert!(backend_listener.accept().unwrap().is_none());

        let _frontend = Frontend::connect(path, 1).unwrap();
        let _backend = backend_listener.accept().unwrap().unwrap();
    }
}
