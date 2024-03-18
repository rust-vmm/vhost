// Copyright (C) 2024 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::vhost_user::connection::Endpoint;
use crate::vhost_user::gpu_message::*;

struct BackendInternal {
    // whether the endpoint has encountered any failure
    error: Option<i32>,
}

/// Proxy for sending messages from the backend to the fronted
/// over the socket obtained from VHOST_USER_GPU_SET_SOCKET.
/// The protocol is documented here: https://www.qemu.org/docs/master/interop/vhost-user-gpu.html
#[derive(Clone)]
pub struct GpuBackend {
    // underlying Unix domain socket for communication
    node: Arc<Mutex<BackendInternal>>,
}

impl GpuBackend {
    fn new(_ep: Endpoint<VhostUserGpuMsgHeader<GpuBackendReq>>) -> Self {
        Self {
            node: Arc::new(Mutex::new(BackendInternal { error: None })),
        }
    }

    fn node(&self) -> MutexGuard<BackendInternal> {
        self.node.lock().unwrap()
    }

    /// Create a new instance from a `UnixStream` object.
    pub fn from_stream(sock: UnixStream) -> Self {
        Self::new(Endpoint::<VhostUserGpuMsgHeader<GpuBackendReq>>::from_stream(sock))
    }

    /// Mark endpoint as failed with specified error code.
    pub fn set_failed(&self, error: i32) {
        self.node().error = Some(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_backend_req_set_failed() {
        let (p1, _p2) = UnixStream::pair().unwrap();
        let backend = GpuBackend::from_stream(p1);
        assert!(backend.node().error.is_none());
        backend.set_failed(libc::EAGAIN);
        assert_eq!(backend.node().error, Some(libc::EAGAIN));
    }
}
