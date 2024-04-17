// Copyright (C) 2024 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard};
use std::{io, mem, slice};

use vm_memory::ByteValued;

use crate::vhost_user;
use crate::vhost_user::connection::Endpoint;
use crate::vhost_user::gpu_message::*;
use crate::vhost_user::message::{VhostUserEmpty, VhostUserMsgValidator, VhostUserU64};
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

    fn send_message_with_payload<T: ByteValued>(
        &mut self,
        request: GpuBackendReq,
        body: &T,
        data: &[u8],
        fds: Option<&[RawFd]>,
    ) -> io::Result<VhostUserGpuMsgHeader<GpuBackendReq>> {
        self.check_state()?;

        let len = mem::size_of::<T>() + data.len();
        let hdr = VhostUserGpuMsgHeader::new(request, 0, len as u32);
        self.sock
            .send_message_with_payload(&hdr, body, data, fds)
            .map_err(io_err_convert_fn("send_message_with_payload"))?;
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

    /// Send the VHOST_USER_GPU_GET_PROTOCOL_FEATURES message to the frontend and wait for a reply.
    /// Get the supported protocol features bitmask.
    pub fn get_protocol_features(&self) -> io::Result<VhostUserU64> {
        let mut node = self.node();

        let hdr = node.send_header(GpuBackendReq::GET_PROTOCOL_FEATURES, None)?;
        node.recv_reply(&hdr)
    }

    /// Send the VHOST_USER_GPU_SET_PROTOCOL_FEATURES message to the frontend. Doesn't wait for
    /// a reply.
    /// Enable protocol features using a bitmask.
    pub fn set_protocol_features(&self, msg: &VhostUserU64) -> io::Result<()> {
        let mut node = self.node();

        node.send_message(GpuBackendReq::SET_PROTOCOL_FEATURES, msg, None)?;
        Ok(())
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

    /// Sends the VHOST_USER_GPU_UPDATE  message to the frontend. Doesn't wait for a reply.
    /// Updates the scanout content. The data payload contains the graphical bits.
    /// The display should be flushed and presented.
    pub fn update_scanout(&self, update: &VhostUserGpuUpdate, data: &[u8]) -> io::Result<()> {
        let mut node = self.node();

        node.send_message_with_payload(GpuBackendReq::UPDATE, update, data, None)?;
        Ok(())
    }

    /// Send the VHOST_USER_GPU_DMABUF_SCANOUT  message to the frontend. Doesn't wait for a reply.
    /// Set the scanout resolution/configuration, and share a DMABUF file descriptor for the scanout
    /// content, which is passed as ancillary data. To disable a scanout, the dimensions
    /// width/height are set to 0, there is no file descriptor passed.
    pub fn set_dmabuf_scanout(
        &self,
        scanout: &VhostUserGpuDMABUFScanout,
        fd: Option<&impl AsRawFd>,
    ) -> io::Result<()> {
        let mut node = self.node();

        let fd = fd.map(AsRawFd::as_raw_fd);
        let fd = fd.as_ref().map(slice::from_ref);
        node.send_message(GpuBackendReq::DMABUF_SCANOUT, scanout, fd)?;
        Ok(())
    }

    /// Send the VHOST_USER_GPU_DMABUF_SCANOUT2  message to the frontend. Doesn't wait for a reply.
    /// Same as `set_dmabuf_scanout` (VHOST_USER_GPU_DMABUF_SCANOUT), but also sends the dmabuf
    /// modifiers appended to the message, which were not provided in the other message. This
    /// message requires the VhostUserGpuProtocolFeatures::DMABUF2
    /// (VHOST_USER_GPU_PROTOCOL_F_DMABUF2) protocol feature to be supported.
    pub fn set_dmabuf_scanout2(
        &self,
        scanout: &VhostUserGpuDMABUFScanout2,
        fd: Option<&impl AsRawFd>,
    ) -> io::Result<()> {
        let mut node = self.node();

        let fd = fd.map(AsRawFd::as_raw_fd);
        let fd = fd.as_ref().map(slice::from_ref);
        node.send_message(GpuBackendReq::DMABUF_SCANOUT2, scanout, fd)?;
        Ok(())
    }

    /// Send the VHOST_USER_GPU_DMABUF_UPDATE message to the frontend and wait for acknowledgment.
    /// The display should be flushed and presented according to updated region
    /// from VhostUserGpuUpdate.
    pub fn update_dmabuf_scanout(&self, update: &VhostUserGpuUpdate) -> io::Result<()> {
        let mut node = self.node();

        let hdr = node.send_message(GpuBackendReq::DMABUF_UPDATE, update, None)?;
        let _: VhostUserEmpty = node.recv_reply(&hdr)?;
        Ok(())
    }

    /// Send the VHOST_USER_GPU_CURSOR_POS  message to the frontend. Doesn't wait for a reply.
    /// Set/show the cursor position.
    pub fn cursor_pos(&self, cursor_pos: &VhostUserGpuCursorPos) -> io::Result<()> {
        let mut node = self.node();

        node.send_message(GpuBackendReq::CURSOR_POS, cursor_pos, None)?;
        Ok(())
    }

    /// Send the VHOST_USER_GPU_CURSOR_POS_HIDE  message to the frontend. Doesn't wait for a reply.
    /// Set/hide the cursor.
    pub fn cursor_pos_hide(&self, cursor_pos: &VhostUserGpuCursorPos) -> io::Result<()> {
        let mut node = self.node();

        node.send_message(GpuBackendReq::CURSOR_POS_HIDE, cursor_pos, None)?;
        Ok(())
    }

    /// Send the VHOST_USER_GPU_CURSOR_UPDATE  message to the frontend. Doesn't wait for a reply.
    /// Update the cursor shape and location.
    /// `data` represents a 64*64 cursor image (PIXMAN_x8r8g8b8 format).
    pub fn cursor_update(
        &self,
        cursor_update: &VhostUserGpuCursorUpdate,
        data: &[u8; 4 * 64 * 64],
    ) -> io::Result<()> {
        let mut node = self.node();

        node.send_message_with_payload(GpuBackendReq::CURSOR_UPDATE, cursor_update, data, None)?;
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
    use libc::STDOUT_FILENO;
    use std::mem::{size_of, size_of_val};
    use std::thread;
    use std::time::Duration;

    const TEST_DMABUF_SCANOUT_REQUEST: VhostUserGpuDMABUFScanout = VhostUserGpuDMABUFScanout {
        scanout_id: 1,
        x: 0,
        y: 0,
        width: 1920,
        height: 1080,
        fd_width: 1920,
        fd_height: 1080,
        fd_stride: 0,
        fd_flags: 0,
        fd_drm_fourcc: 0,
    };
    const TEST_CURSOR_POS_REQUEST: VhostUserGpuCursorPos = VhostUserGpuCursorPos {
        scanout_id: 1,
        x: 31,
        y: 102,
    };

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

    #[test]
    fn test_update_scanout() {
        let (mut frontend, backend) = frontend_backend_pair();

        let request = VhostUserGpuUpdate {
            scanout_id: 1,
            x: 30,
            y: 40,
            width: 10,
            height: 10,
        };
        let payload = [1u8; 4 * 10 * 10];

        let sender_thread = thread::spawn(move || {
            let _: () = backend.update_scanout(&request, &payload).unwrap();
        });

        let mut recv_buf = [0u8; 4096];
        let (hdr, req_body, recv_buf_len, fds) = frontend
            .recv_payload_into_buf::<VhostUserGpuUpdate>(&mut recv_buf)
            .unwrap();
        assert!(fds.is_none());
        assert_hdr(
            &hdr,
            GpuBackendReq::UPDATE,
            size_of_val(&request) + payload.len(),
        );
        assert_eq!(req_body, request);

        assert_eq!(&payload[..], &recv_buf[..recv_buf_len]);

        sender_thread.join().expect("Failed to send!");
    }

    #[test]
    fn test_set_dmabuf_scanout() {
        let (mut frontend, backend) = frontend_backend_pair();

        let request = TEST_DMABUF_SCANOUT_REQUEST;

        let fd: RawFd = STDOUT_FILENO;

        let sender_thread = thread::spawn(move || {
            let _: () = backend.set_dmabuf_scanout(&request, Some(&fd)).unwrap();
        });

        let (hdr, req_body, fds) = frontend.recv_body::<VhostUserGpuDMABUFScanout>().unwrap();

        assert!(fds.is_some_and(|fds| fds.len() == 1));
        assert_hdr(&hdr, GpuBackendReq::DMABUF_SCANOUT, size_of_val(&request));
        assert_eq!(req_body, request);

        sender_thread.join().expect("Failed to send!");
    }

    #[test]
    fn test_update_dmabuf_scanout() {
        let (mut frontend, backend) = frontend_backend_pair();

        let request = VhostUserGpuUpdate {
            scanout_id: 1,
            x: 30,
            y: 40,
            width: 10,
            height: 10,
        };

        let sender_thread = thread::spawn(move || {
            let _: () = backend.update_dmabuf_scanout(&request).unwrap();
        });

        let (hdr, req_body, fds) = frontend.recv_body::<VhostUserGpuUpdate>().unwrap();
        assert!(fds.is_none());
        assert_hdr(&hdr, GpuBackendReq::DMABUF_UPDATE, size_of_val(&request));
        assert_eq!(req_body, request);

        // let's check if update_dmabuf_scanout blocks
        // The 100ms should be enough for the thread to write to a socket and quit.
        // (worst case on slow computer is that this test succeeds even though it should have failed)
        thread::sleep(Duration::from_millis(100));
        assert!(
            !sender_thread.is_finished(),
            "update_dmabuf_scanout is supposed to block until it receives an empty reply"
        );

        // send ack
        reply_with_msg(&mut frontend, &hdr, &VhostUserEmpty);

        sender_thread.join().expect("Failed to send!");
    }

    #[test]
    fn test_get_protocol_features() {
        let (mut frontend, backend) = frontend_backend_pair();

        let expected_value = VhostUserU64::new(
            (VhostUserGpuProtocolFeatures::DMABUF2 | VhostUserGpuProtocolFeatures::EDID).bits(),
        );

        let sender_thread = thread::spawn(move || {
            let response: VhostUserU64 = backend.get_protocol_features().unwrap();
            assert_eq!(response.value, expected_value.value)
        });

        let (hdr, fds) = frontend.recv_header().unwrap();
        assert!(fds.is_none());
        assert_hdr(&hdr, GpuBackendReq::GET_PROTOCOL_FEATURES, 0);

        reply_with_msg(&mut frontend, &hdr, &expected_value);
        sender_thread.join().expect("Failed to send!");
    }

    #[test]
    fn test_set_protocol_features() {
        let (mut frontend, backend) = frontend_backend_pair();

        let expected_value = VhostUserU64::new(
            (VhostUserGpuProtocolFeatures::DMABUF2 | VhostUserGpuProtocolFeatures::EDID).bits(),
        );

        let sender_thread = thread::spawn(move || {
            let _: () = backend.set_protocol_features(&expected_value).unwrap();
        });

        let (hdr, req_body, fds) = frontend.recv_body::<VhostUserU64>().unwrap();
        assert!(fds.is_none());
        assert_hdr(
            &hdr,
            GpuBackendReq::SET_PROTOCOL_FEATURES,
            size_of_val(&expected_value),
        );
        assert_eq!(req_body.value, expected_value.value);

        sender_thread.join().expect("Failed to send!");
    }

    #[test]
    fn test_set_cursor_pos() {
        let (mut frontend, backend) = frontend_backend_pair();

        let sender_thread = thread::spawn(move || {
            let _: () = backend.cursor_pos(&TEST_CURSOR_POS_REQUEST).unwrap();
        });

        let (hdr, req_body, fds) = frontend.recv_body::<VhostUserGpuCursorPos>().unwrap();
        assert!(fds.is_none());
        assert_hdr(
            &hdr,
            GpuBackendReq::CURSOR_POS,
            size_of_val(&TEST_CURSOR_POS_REQUEST),
        );
        assert_eq!(req_body, TEST_CURSOR_POS_REQUEST);

        sender_thread.join().expect("Failed to send!");
    }

    #[test]
    fn test_set_cursor_pos_hide() {
        let (mut frontend, backend) = frontend_backend_pair();

        let sender_thread = thread::spawn(move || {
            let _: () = backend.cursor_pos_hide(&TEST_CURSOR_POS_REQUEST).unwrap();
        });

        let (hdr, req_body, fds) = frontend.recv_body::<VhostUserGpuCursorPos>().unwrap();
        assert!(fds.is_none());
        assert_hdr(
            &hdr,
            GpuBackendReq::CURSOR_POS_HIDE,
            size_of_val(&TEST_CURSOR_POS_REQUEST),
        );
        assert_eq!(req_body, TEST_CURSOR_POS_REQUEST);

        sender_thread.join().expect("Failed to send!");
    }

    #[test]
    fn test_cursor_update() {
        let (mut frontend, backend) = frontend_backend_pair();

        let request = VhostUserGpuCursorUpdate {
            pos: TEST_CURSOR_POS_REQUEST,
            hot_x: 30,
            hot_y: 30,
        };
        let payload = [2u8; 4 * 64 * 64];

        let sender_thread = thread::spawn(move || {
            let _: () = backend.cursor_update(&request, &payload).unwrap();
        });

        let mut recv_buf = vec![0u8; 1 + size_of_val(&payload)];
        let (hdr, req_body, recv_buf_len, fds) = frontend
            .recv_payload_into_buf::<VhostUserGpuCursorUpdate>(&mut recv_buf)
            .unwrap();
        assert!(fds.is_none());
        assert_hdr(
            &hdr,
            GpuBackendReq::CURSOR_UPDATE,
            size_of_val(&request) + payload.len(),
        );
        assert_eq!(req_body, request);

        assert_eq!(&payload[..], &recv_buf[..recv_buf_len]);

        sender_thread.join().expect("Failed to send!");
    }

    #[test]
    fn test_set_dmabuf_scanout2() {
        let (mut frontend, backend) = frontend_backend_pair();

        let request = VhostUserGpuDMABUFScanout2 {
            dmabuf_scanout: TEST_DMABUF_SCANOUT_REQUEST,
            modifier: 13,
        };

        let fd: RawFd = STDOUT_FILENO;

        let sender_thread = thread::spawn(move || {
            let _: () = backend.set_dmabuf_scanout2(&request, Some(&fd)).unwrap();
        });

        let (hdr, req_body, fds) = frontend.recv_body::<VhostUserGpuDMABUFScanout2>().unwrap();

        assert!(fds.is_some_and(|fds| fds.len() == 1));
        assert_hdr(&hdr, GpuBackendReq::DMABUF_SCANOUT2, size_of_val(&request));
        assert_eq!(req_body, request);

        sender_thread.join().expect("Failed to send!");
    }
}
