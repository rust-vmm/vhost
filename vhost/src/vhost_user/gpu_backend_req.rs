// Copyright (C) 2024 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard};
use std::{io, mem};

use vm_memory::ByteValued;

use crate::vhost_user;
use crate::vhost_user::connection::Endpoint;
use crate::vhost_user::gpu_message::*;
use crate::vhost_user::message::VhostUserMsgValidator;
use crate::vhost_user::Error;

struct BackendInternal {
    sock: Endpoint<VhostUserGpuMsgHeader<GpuBackendReq>>,
    // whether the endpoint has encountered any failure
    error: Option<i32>,
}

fn io_err_convert_fn(info: &str) -> impl Fn(vhost_user::Error) -> io::Error + '_ {
    move |e| io::Error::new(io::ErrorKind::Other, format!("{info}: {e}"))
}

impl BackendInternal {
    fn check_state(&self) -> io::Result<u64> {
        match self.error {
            Some(e) => Err(io_err_convert_fn("check_state")(Error::SocketBroken(
                io::Error::from_raw_os_error(e),
            ))),
            None => Ok(0),
        }
    }

    fn send_header(
        &mut self,
        request: GpuBackendReq,
        fds: Option<&[RawFd]>,
    ) -> io::Result<VhostUserGpuMsgHeader<GpuBackendReq>> {
        self.check_state()?;
        let hdr = VhostUserGpuMsgHeader::new(request, 0, 0);
        self.sock
            .send_header(&hdr, fds)
            .map_err(io_err_convert_fn("send_header"))?;
        Ok(hdr)
    }

    fn send_message<T: ByteValued>(
        &mut self,
        request: GpuBackendReq,
        body: &T,
        fds: Option<&[RawFd]>,
    ) -> io::Result<VhostUserGpuMsgHeader<GpuBackendReq>> {
        self.check_state()?;

        let len = mem::size_of::<T>();
        let hdr = VhostUserGpuMsgHeader::new(request, 0, len as u32);
        self.sock
            .send_message(&hdr, body, fds)
            .map_err(io_err_convert_fn("send_message"))?;
        Ok(hdr)
    }

    // Note that there is no VHOST_USER_PROTOCOL_F_REPLY_ACK for this protocol, some messages always
    // expect a reply/ack and others don't expect a reply/ack at all.
    fn recv_reply<V: ByteValued + Sized + Default + VhostUserMsgValidator>(
        &mut self,
        hdr: &VhostUserGpuMsgHeader<GpuBackendReq>,
    ) -> io::Result<V> {
        self.check_state()?;
        let (reply, body, rfds) = self
            .sock
            .recv_body::<V>()
            .map_err(io_err_convert_fn("recv_body"))?;
        if !reply.is_reply_for(hdr) || rfds.is_some() || !body.is_valid() {
            return Err(io_err_convert_fn("Unexpected reply")(Error::InvalidMessage));
        }
        Ok(body)
    }
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
    fn new(ep: Endpoint<VhostUserGpuMsgHeader<GpuBackendReq>>) -> Self {
        Self {
            node: Arc::new(Mutex::new(BackendInternal {
                sock: ep,
                error: None,
            })),
        }
    }

    fn node(&self) -> MutexGuard<BackendInternal> {
        self.node.lock().unwrap()
    }

    /// Send the VHOST_USER_GPU_GET_DISPLAY_INFO message to the frontend and wait for a reply.
    /// Get the preferred display configuration.
    pub fn get_display_info(&self) -> io::Result<VirtioGpuRespDisplayInfo> {
        let mut node = self.node();

        let hdr = node.send_header(GpuBackendReq::GET_DISPLAY_INFO, None)?;
        node.recv_reply(&hdr)
    }

    /// Send the VHOST_USER_GPU_GET_EDID message to the frontend and wait for a reply.
    /// Retrieve the EDID data for a given scanout.
    /// This message requires the VHOST_USER_GPU_PROTOCOL_F_EDID protocol feature to be supported.
    pub fn get_edid(&self, get_edid: &VhostUserGpuEdidRequest) -> io::Result<VirtioGpuRespGetEdid> {
        let mut node = self.node();

        let hdr = node.send_message(GpuBackendReq::GET_EDID, get_edid, None)?;
        node.recv_reply(&hdr)
    }

    /// Send the VHOST_USER_GPU_SCANOUT message to the frontend. Doesn't wait for a reply.
    /// Set the scanout resolution. To disable a scanout, the dimensions width/height are set to 0.
    pub fn set_scanout(&self, scanout: &VhostUserGpuScanout) -> io::Result<()> {
        let mut node = self.node();

        node.send_message(GpuBackendReq::SCANOUT, scanout, None)?;
        Ok(())
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
    use std::mem::{size_of, size_of_val};
    use std::thread;
    fn frontend_backend_pair() -> (Endpoint<VhostUserGpuMsgHeader<GpuBackendReq>>, GpuBackend) {
        let (backend, frontend) = UnixStream::pair().unwrap();
        let backend = GpuBackend::from_stream(backend);
        let frontend = Endpoint::from_stream(frontend);

        (frontend, backend)
    }

    fn assert_hdr(
        hdr: &VhostUserGpuMsgHeader<GpuBackendReq>,
        expected_req_code: GpuBackendReq,
        expected_size: usize,
    ) {
        let size: u32 = expected_size.try_into().unwrap();
        assert_eq!(hdr, &VhostUserGpuMsgHeader::new(expected_req_code, 0, size));
    }

    fn reply_with_msg<R>(
        frontend: &mut Endpoint<VhostUserGpuMsgHeader<GpuBackendReq>>,
        req_hdr: &VhostUserGpuMsgHeader<GpuBackendReq>,
        reply_body: &R,
    ) where
        R: ByteValued,
    {
        let response_hdr = VhostUserGpuMsgHeader::new(
            req_hdr.get_code().unwrap(),
            VhostUserGpuHeaderFlag::REPLY.bits(),
            size_of::<R>() as u32,
        );

        frontend
            .send_message(&response_hdr, reply_body, None)
            .unwrap();
    }

    #[test]
    fn test_gpu_backend_req_set_failed() {
        let (p1, _p2) = UnixStream::pair().unwrap();
        let backend = GpuBackend::from_stream(p1);
        assert!(backend.node().error.is_none());
        backend.set_failed(libc::EAGAIN);
        assert_eq!(backend.node().error, Some(libc::EAGAIN));
    }

    #[test]
    fn test_get_display_info() {
        let (mut frontend, backend) = frontend_backend_pair();

        let expected_response = {
            let mut resp = VirtioGpuRespDisplayInfo {
                hdr: Default::default(),
                pmodes: Default::default(),
            };
            resp.pmodes[0] = VirtioGpuDisplayOne {
                r: VirtioGpuRect {
                    x: 0,
                    y: 0,
                    width: 640,
                    height: 480,
                },
                enabled: 1,
                flags: 0,
            };
            resp
        };

        let sender_thread = thread::spawn(move || {
            let response = backend.get_display_info().unwrap();
            assert_eq!(response, expected_response);
        });

        let (hdr, fds) = frontend.recv_header().unwrap();
        assert!(fds.is_none());
        assert_hdr(&hdr, GpuBackendReq::GET_DISPLAY_INFO, 0);

        reply_with_msg(&mut frontend, &hdr, &expected_response);
        sender_thread.join().expect("Failed to send!");
    }

    #[test]
    fn test_get_edid_info() {
        let (mut frontend, backend) = frontend_backend_pair();

        let expected_response = VirtioGpuRespGetEdid {
            hdr: Default::default(),
            size: 512,
            padding: 0,
            edid: [1u8; 1024],
        };
        let request = VhostUserGpuEdidRequest { scanout_id: 1 };

        let sender_thread = thread::spawn(move || {
            let response = backend.get_edid(&request).unwrap();
            assert_eq!(response, expected_response);
        });

        let (hdr, req_body, fds) = frontend.recv_body::<VhostUserGpuEdidRequest>().unwrap();
        assert!(fds.is_none());
        assert_hdr(&hdr, GpuBackendReq::GET_EDID, size_of_val(&request));
        assert_eq!(req_body, request);

        reply_with_msg(&mut frontend, &hdr, &expected_response);
        sender_thread.join().expect("Failed to send!");
    }

    #[test]
    fn test_set_scanout() {
        let (mut frontend, backend) = frontend_backend_pair();

        let request = VhostUserGpuScanout {
            scanout_id: 1,
            width: 1920,
            height: 1080,
        };

        let sender_thread = thread::spawn(move || {
            let _: () = backend.set_scanout(&request).unwrap();
        });

        let (hdr, req_body, fds) = frontend.recv_body::<VhostUserGpuScanout>().unwrap();
        assert!(fds.is_none());
        assert_hdr(&hdr, GpuBackendReq::SCANOUT, size_of_val(&request));
        assert_eq!(req_body, request);

        sender_thread.join().expect("Failed to send!");
    }
}
