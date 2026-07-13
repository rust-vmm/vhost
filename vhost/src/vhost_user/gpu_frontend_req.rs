// Copyright (C) 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard};
use std::{io, mem};

use vm_memory::ByteValued;

use crate::vhost_user::connection::Endpoint;
use crate::vhost_user::gpu_message::{
    GpuBackendReq, VhostUserGpuHeaderFlag, VhostUserGpuMsgHeader,
};

struct FrontendInternal {
    sock: Endpoint<VhostUserGpuMsgHeader<GpuBackendReq>>,
    error: Option<i32>,
}

impl FrontendInternal {
    fn check_state(&self) -> io::Result<()> {
        match self.error {
            Some(e) => Err(io::Error::from_raw_os_error(e)),
            None => Ok(()),
        }
    }

    fn send_response<T: ByteValued>(
        &mut self,
        request: GpuBackendReq,
        body: &T,
        fds: Option<&[RawFd]>,
    ) -> io::Result<()> {
        self.check_state()?;

        let len = mem::size_of::<T>();
        let hdr =
            VhostUserGpuMsgHeader::new(request, VhostUserGpuHeaderFlag::REPLY.bits(), len as u32);
        self.sock
            .send_message(&hdr, body, fds)
            .map_err(io::Error::other)?;
        Ok(())
    }
}

/// Proxy for receiving messages from the backend and sending responses
/// over the socket obtained from VHOST_USER_GPU_SET_SOCKET.
/// The protocol is documented here: <https://www.qemu.org/docs/master/interop/vhost-user-gpu.html>
#[derive(Clone)]
pub struct GpuFrontend {
    // underlying Unix domain socket for communication
    node: Arc<Mutex<FrontendInternal>>,
}

impl GpuFrontend {
    fn new(ep: Endpoint<VhostUserGpuMsgHeader<GpuBackendReq>>) -> Self {
        Self {
            node: Arc::new(Mutex::new(FrontendInternal {
                sock: ep,
                error: None,
            })),
        }
    }

    fn node(&self) -> MutexGuard<'_, FrontendInternal> {
        self.node.lock().unwrap()
    }

    /// Create a new instance from a `UnixStream` object.
    pub fn from_stream(sock: UnixStream) -> Self {
        Self::new(Endpoint::<VhostUserGpuMsgHeader<GpuBackendReq>>::from_stream(sock))
    }

    /// Read a GPU protocol message from the backend.
    /// Returns (message_type, payload_bytes, optional_fds).
    /// File descriptors are present for DMABUF_SCANOUT and DMABUF_SCANOUT2 messages.
    pub fn read_message(&self) -> io::Result<(GpuBackendReq, Vec<u8>, Option<Vec<File>>)> {
        let mut node = self.node();
        node.check_state()?;

        let (hdr, files) = node.sock.recv_header().map_err(io::Error::other)?;
        let request = hdr.get_code().map_err(io::Error::other)?;
        let size = hdr.get_size() as usize;

        let payload = if size > 0 {
            let (bytes, mut payload, _) =
                node.sock.recv_into_buf(size).map_err(io::Error::other)?;
            payload.truncate(bytes);
            payload
        } else {
            Vec::new()
        };

        Ok((request, payload, files))
    }

    /// Set error state for the endpoint.
    pub fn set_failed(&self, error: i32) {
        self.node().error = Some(error);
    }

    /// Send a typed response to a GPU protocol request.
    pub fn send_response<T: ByteValued>(
        &self,
        request: GpuBackendReq,
        response: &T,
    ) -> io::Result<()> {
        let mut node = self.node();
        node.send_response(request, response, None)?;
        Ok(())
    }
}

impl AsRawFd for GpuFrontend {
    fn as_raw_fd(&self) -> RawFd {
        self.node.lock().unwrap().sock.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vhost_user::gpu_message::{
        VhostUserGpuEdidRequest, VirtioGpuDisplayOne, VirtioGpuRect, VirtioGpuRespDisplayInfo,
    };
    use std::mem::size_of;
    use std::thread;

    fn frontend_backend_pair() -> (GpuFrontend, Endpoint<VhostUserGpuMsgHeader<GpuBackendReq>>) {
        let (fe, be) = UnixStream::pair().unwrap();
        (GpuFrontend::from_stream(fe), Endpoint::from_stream(be))
    }

    #[test]
    fn test_read_message_with_payload() {
        let (frontend, mut backend) = frontend_backend_pair();

        let request = VhostUserGpuEdidRequest { scanout_id: 1 };
        let sender = thread::spawn(move || {
            let hdr = VhostUserGpuMsgHeader::new(
                GpuBackendReq::GET_EDID,
                0,
                size_of::<VhostUserGpuEdidRequest>() as u32,
            );
            backend.send_message(&hdr, &request, None).unwrap();
        });

        let (req, payload, fds) = frontend.read_message().unwrap();
        assert_eq!(req, GpuBackendReq::GET_EDID);
        assert_eq!(payload.len(), size_of::<VhostUserGpuEdidRequest>());
        assert!(fds.is_none());

        sender.join().unwrap();
    }

    #[test]
    fn test_read_message_no_payload() {
        let (frontend, mut backend) = frontend_backend_pair();

        let sender = thread::spawn(move || {
            let hdr = VhostUserGpuMsgHeader::new(GpuBackendReq::GET_DISPLAY_INFO, 0, 0);
            backend.send_header(&hdr, None).unwrap();
        });

        let (req, payload, fds) = frontend.read_message().unwrap();
        assert_eq!(req, GpuBackendReq::GET_DISPLAY_INFO);
        assert!(payload.is_empty());
        assert!(fds.is_none());

        sender.join().unwrap();
    }

    #[test]
    fn test_roundtrip_display_info() {
        let (frontend, mut backend) = frontend_backend_pair();

        let mut expected = VirtioGpuRespDisplayInfo::default();
        expected.pmodes[0] = VirtioGpuDisplayOne {
            r: VirtioGpuRect {
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
            },
            enabled: 1,
            flags: 0,
        };

        let sender = thread::spawn(move || {
            let hdr = VhostUserGpuMsgHeader::new(GpuBackendReq::GET_DISPLAY_INFO, 0, 0);
            backend.send_header(&hdr, None).unwrap();

            let (reply_hdr, body, _fds) = backend.recv_body::<VirtioGpuRespDisplayInfo>().unwrap();
            assert!(reply_hdr.is_reply());
            assert_eq!(
                reply_hdr.get_code().unwrap(),
                GpuBackendReq::GET_DISPLAY_INFO
            );
            body
        });

        let (req, _payload, _fds) = frontend.read_message().unwrap();
        frontend.send_response(req, &expected).unwrap();

        let body = sender.join().unwrap();
        assert_eq!(body, expected);
    }

    #[test]
    fn test_set_failed() {
        let (fe, _be) = UnixStream::pair().unwrap();
        let frontend = GpuFrontend::from_stream(fe);

        frontend.set_failed(libc::EAGAIN);

        assert!(frontend.read_message().is_err());
        assert!(frontend
            .send_response(
                GpuBackendReq::GET_DISPLAY_INFO,
                &VirtioGpuRespDisplayInfo::default()
            )
            .is_err());
    }
}
