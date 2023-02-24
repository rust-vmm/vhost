// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard};

use super::connection::Endpoint;
use super::message::*;
use super::{Error, HandlerResult, Result, VhostUserMasterReqHandler};

use vm_memory::ByteValued;

struct SlaveInternal {
    sock: Endpoint<SlaveReq>,

    // Protocol feature VHOST_USER_PROTOCOL_F_REPLY_ACK has been negotiated.
    reply_ack_negotiated: bool,

    // whether the endpoint has encountered any failure
    error: Option<i32>,
}

impl SlaveInternal {
    fn check_state(&self) -> Result<u64> {
        match self.error {
            Some(e) => Err(Error::SocketBroken(std::io::Error::from_raw_os_error(e))),
            None => Ok(0),
        }
    }

    fn send_message<T: ByteValued>(
        &mut self,
        request: SlaveReq,
        body: &T,
        fds: Option<&[RawFd]>,
    ) -> Result<u64> {
        self.check_state()?;

        let len = mem::size_of::<T>();
        let mut hdr = VhostUserMsgHeader::new(request, 0, len as u32);
        if self.reply_ack_negotiated {
            hdr.set_need_reply(true);
        }
        self.sock.send_message(&hdr, body, fds)?;

        self.wait_for_ack(&hdr)
    }

    fn wait_for_ack(&mut self, hdr: &VhostUserMsgHeader<SlaveReq>) -> Result<u64> {
        self.check_state()?;
        if !self.reply_ack_negotiated {
            return Ok(0);
        }

        let (reply, body, rfds) = self.sock.recv_body::<VhostUserU64>()?;
        if !reply.is_reply_for(hdr) || rfds.is_some() || !body.is_valid() {
            return Err(Error::InvalidMessage);
        }
        if body.value != 0 {
            return Err(Error::MasterInternalError);
        }

        Ok(body.value)
    }
}

/// Request proxy to send vhost-user slave requests to the master through the slave
/// communication channel.
///
/// The [Slave] acts as a message proxy to forward vhost-user slave requests to the
/// master through the vhost-user slave communication channel. The forwarded messages will be
/// handled by the [MasterReqHandler] server.
///
/// [Slave]: struct.Slave.html
/// [MasterReqHandler]: struct.MasterReqHandler.html
#[derive(Clone)]
pub struct Slave {
    // underlying Unix domain socket for communication
    node: Arc<Mutex<SlaveInternal>>,
}

impl Slave {
    fn new(ep: Endpoint<SlaveReq>) -> Self {
        Slave {
            node: Arc::new(Mutex::new(SlaveInternal {
                sock: ep,
                reply_ack_negotiated: false,
                error: None,
            })),
        }
    }

    fn node(&self) -> MutexGuard<SlaveInternal> {
        self.node.lock().unwrap()
    }

    fn send_message<T: ByteValued>(
        &self,
        request: SlaveReq,
        body: &T,
        fds: Option<&[RawFd]>,
    ) -> io::Result<u64> {
        self.node()
            .send_message(request, body, fds)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))
    }

    /// Create a new instance from a `UnixStream` object.
    pub fn from_stream(sock: UnixStream) -> Self {
        Self::new(Endpoint::<SlaveReq>::from_stream(sock))
    }

    /// Set the negotiation state of the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature.
    ///
    /// When the `VHOST_USER_PROTOCOL_F_REPLY_ACK` protocol feature has been negotiated,
    /// the "REPLY_ACK" flag will be set in the message header for every slave to master request
    /// message.
    pub fn set_reply_ack_flag(&self, enable: bool) {
        self.node().reply_ack_negotiated = enable;
    }

    /// Mark endpoint as failed with specified error code.
    pub fn set_failed(&self, error: i32) {
        self.node().error = Some(error);
    }
}

impl VhostUserMasterReqHandler for Slave {
    /// Forward vhost-user-fs map file requests to the slave.
    fn fs_slave_map(&self, fs: &VhostUserFSSlaveMsg, fd: &dyn AsRawFd) -> HandlerResult<u64> {
        self.send_message(SlaveReq::FS_MAP, fs, Some(&[fd.as_raw_fd()]))
    }

    /// Forward vhost-user-fs unmap file requests to the master.
    fn fs_slave_unmap(&self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<u64> {
        self.send_message(SlaveReq::FS_UNMAP, fs, None)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::AsRawFd;

    use super::*;

    #[test]
    fn test_slave_req_set_failed() {
        let (p1, _p2) = UnixStream::pair().unwrap();
        let slave = Slave::from_stream(p1);

        assert!(slave.node().error.is_none());
        slave.set_failed(libc::EAGAIN);
        assert_eq!(slave.node().error, Some(libc::EAGAIN));
    }

    #[test]
    fn test_slave_req_send_failure() {
        let (p1, p2) = UnixStream::pair().unwrap();
        let slave = Slave::from_stream(p1);

        slave.set_failed(libc::ECONNRESET);
        slave
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &p2)
            .unwrap_err();
        slave
            .fs_slave_unmap(&VhostUserFSSlaveMsg::default())
            .unwrap_err();
        slave.node().error = None;
    }

    #[test]
    fn test_slave_req_recv_negative() {
        let (p1, p2) = UnixStream::pair().unwrap();
        let slave = Slave::from_stream(p1);
        let mut master = Endpoint::<SlaveReq>::from_stream(p2);

        let len = mem::size_of::<VhostUserFSSlaveMsg>();
        let mut hdr = VhostUserMsgHeader::new(
            SlaveReq::FS_MAP,
            VhostUserHeaderFlag::REPLY.bits(),
            len as u32,
        );
        let body = VhostUserU64::new(0);

        master
            .send_message(&hdr, &body, Some(&[master.as_raw_fd()]))
            .unwrap();
        slave
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &master)
            .unwrap();

        slave.set_reply_ack_flag(true);
        slave
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &master)
            .unwrap_err();

        hdr.set_code(SlaveReq::FS_UNMAP);
        master.send_message(&hdr, &body, None).unwrap();
        slave
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &master)
            .unwrap_err();
        hdr.set_code(SlaveReq::FS_MAP);

        let body = VhostUserU64::new(1);
        master.send_message(&hdr, &body, None).unwrap();
        slave
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &master)
            .unwrap_err();

        let body = VhostUserU64::new(0);
        master.send_message(&hdr, &body, None).unwrap();
        slave
            .fs_slave_map(&VhostUserFSSlaveMsg::default(), &master)
            .unwrap();
    }
}
