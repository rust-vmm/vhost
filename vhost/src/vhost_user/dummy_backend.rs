// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

use super::message::*;
use super::*;

pub const MAX_QUEUE_NUM: usize = 2;
pub const MAX_VRING_NUM: usize = 256;
pub const MAX_MEM_SLOTS: usize = 509;
pub const VIRTIO_FEATURES: u64 = 0x40000003;

#[derive(Default)]
pub struct DummyBackendReqHandler {
    pub owned: bool,
    pub features_acked: bool,
    pub acked_features: u64,
    pub acked_protocol_features: u64,
    pub queue_num: usize,
    pub vring_num: [u32; MAX_QUEUE_NUM],
    pub vring_base: [u32; MAX_QUEUE_NUM],
    pub call_fd: [Option<File>; MAX_QUEUE_NUM],
    pub kick_fd: [Option<File>; MAX_QUEUE_NUM],
    pub err_fd: [Option<File>; MAX_QUEUE_NUM],
    pub vring_started: [bool; MAX_QUEUE_NUM],
    pub vring_enabled: [bool; MAX_QUEUE_NUM],
    pub inflight_file: Option<File>,
}

impl DummyBackendReqHandler {
    pub fn new() -> Self {
        DummyBackendReqHandler {
            queue_num: MAX_QUEUE_NUM,
            ..Default::default()
        }
    }

    /// Helper to check if VirtioFeature enabled
    fn check_feature(&self, feat: VhostUserVirtioFeatures) -> Result<()> {
        if self.acked_features & feat.bits() != 0 {
            Ok(())
        } else {
            Err(Error::InactiveFeature(feat))
        }
    }

    /// Helper to check is VhostUserProtocolFeatures enabled
    fn check_proto_feature(&self, feat: VhostUserProtocolFeatures) -> Result<()> {
        if self.acked_protocol_features & feat.bits() != 0 {
            Ok(())
        } else {
            Err(Error::InactiveOperation(feat))
        }
    }
}

impl VhostUserBackendReqHandlerMut for DummyBackendReqHandler {
    fn set_owner(&mut self) -> Result<()> {
        if self.owned {
            return Err(Error::InvalidOperation("already claimed"));
        }
        self.owned = true;
        Ok(())
    }

    fn reset_owner(&mut self) -> Result<()> {
        self.owned = false;
        self.features_acked = false;
        self.acked_features = 0;
        self.acked_protocol_features = 0;
        Ok(())
    }

    fn get_features(&mut self) -> Result<u64> {
        Ok(VIRTIO_FEATURES)
    }

    fn set_features(&mut self, features: u64) -> Result<()> {
        if !self.owned {
            return Err(Error::InvalidOperation("not owned"));
        } else if self.features_acked {
            return Err(Error::InvalidOperation("features already set"));
        } else if (features & !VIRTIO_FEATURES) != 0 {
            return Err(Error::InvalidParam);
        }

        self.acked_features = features;
        self.features_acked = true;

        // If VHOST_USER_F_PROTOCOL_FEATURES has not been negotiated,
        // the ring is initialized in an enabled state.
        // If VHOST_USER_F_PROTOCOL_FEATURES has been negotiated,
        // the ring is initialized in a disabled state. Client must not
        // pass data to/from the backend until ring is enabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has
        // been disabled by VHOST_USER_SET_VRING_ENABLE with parameter 0.
        let vring_enabled =
            self.acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0;
        for enabled in &mut self.vring_enabled {
            *enabled = vring_enabled;
        }

        Ok(())
    }

    fn set_mem_table(&mut self, _ctx: &[VhostUserMemoryRegion], _files: Vec<File>) -> Result<()> {
        Ok(())
    }

    fn set_vring_num(&mut self, index: u32, num: u32) -> Result<()> {
        if index as usize >= self.queue_num || num == 0 || num as usize > MAX_VRING_NUM {
            return Err(Error::InvalidParam);
        }
        self.vring_num[index as usize] = num;
        Ok(())
    }

    fn set_vring_addr(
        &mut self,
        index: u32,
        _flags: VhostUserVringAddrFlags,
        _descriptor: u64,
        _used: u64,
        _available: u64,
        _log: u64,
    ) -> Result<()> {
        if index as usize >= self.queue_num {
            return Err(Error::InvalidParam);
        }
        Ok(())
    }

    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()> {
        if index as usize >= self.queue_num || base as usize >= MAX_VRING_NUM {
            return Err(Error::InvalidParam);
        }
        self.vring_base[index as usize] = base;
        Ok(())
    }

    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState> {
        if index as usize >= self.queue_num {
            return Err(Error::InvalidParam);
        }
        // Quotation from vhost-user spec:
        // Client must start ring upon receiving a kick (that is, detecting
        // that file descriptor is readable) on the descriptor specified by
        // VHOST_USER_SET_VRING_KICK, and stop ring upon receiving
        // VHOST_USER_GET_VRING_BASE.
        self.vring_started[index as usize] = false;
        Ok(VhostUserVringState::new(
            index,
            self.vring_base[index as usize],
        ))
    }

    fn set_vring_kick(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        if index as usize >= self.queue_num || index as usize > self.queue_num {
            return Err(Error::InvalidParam);
        }
        self.kick_fd[index as usize] = fd;

        // Quotation from vhost-user spec:
        // Client must start ring upon receiving a kick (that is, detecting
        // that file descriptor is readable) on the descriptor specified by
        // VHOST_USER_SET_VRING_KICK, and stop ring upon receiving
        // VHOST_USER_GET_VRING_BASE.
        //
        // So we should add fd to event monitor(select, poll, epoll) here.
        self.vring_started[index as usize] = true;
        Ok(())
    }

    fn set_vring_call(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        if index as usize >= self.queue_num || index as usize > self.queue_num {
            return Err(Error::InvalidParam);
        }
        self.call_fd[index as usize] = fd;
        Ok(())
    }

    fn set_vring_err(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        if index as usize >= self.queue_num || index as usize > self.queue_num {
            return Err(Error::InvalidParam);
        }
        self.err_fd[index as usize] = fd;
        Ok(())
    }

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures> {
        Ok(VhostUserProtocolFeatures::all())
    }

    fn set_protocol_features(&mut self, features: u64) -> Result<()> {
        // Note: backend that reported VHOST_USER_F_PROTOCOL_FEATURES must
        // support this message even before VHOST_USER_SET_FEATURES was
        // called.
        // What happens if the frontend calls set_features() with
        // VHOST_USER_F_PROTOCOL_FEATURES cleared after calling this
        // interface?
        self.acked_protocol_features = features;
        Ok(())
    }

    fn get_queue_num(&mut self) -> Result<u64> {
        Ok(MAX_QUEUE_NUM as u64)
    }

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()> {
        // This request should be handled only when VHOST_USER_F_PROTOCOL_FEATURES
        // has been negotiated.
        self.check_feature(VhostUserVirtioFeatures::PROTOCOL_FEATURES)?;

        if index as usize >= self.queue_num || index as usize > self.queue_num {
            return Err(Error::InvalidParam);
        }

        // Backend must not pass data to/from the backend until ring is
        // enabled by VHOST_USER_SET_VRING_ENABLE with parameter 1,
        // or after it has been disabled by VHOST_USER_SET_VRING_ENABLE
        // with parameter 0.
        self.vring_enabled[index as usize] = enable;
        Ok(())
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        _flags: VhostUserConfigFlags,
    ) -> Result<Vec<u8>> {
        self.check_proto_feature(VhostUserProtocolFeatures::CONFIG)?;

        if !(VHOST_USER_CONFIG_OFFSET..VHOST_USER_CONFIG_SIZE).contains(&offset)
            || size > VHOST_USER_CONFIG_SIZE - VHOST_USER_CONFIG_OFFSET
            || size + offset > VHOST_USER_CONFIG_SIZE
        {
            return Err(Error::InvalidParam);
        }
        assert_eq!(offset, 0x100);
        assert_eq!(size, 4);
        Ok(vec![0xa5; size as usize])
    }

    fn set_config(&mut self, offset: u32, buf: &[u8], _flags: VhostUserConfigFlags) -> Result<()> {
        let size = buf.len() as u32;
        self.check_proto_feature(VhostUserProtocolFeatures::CONFIG)?;

        if !(VHOST_USER_CONFIG_OFFSET..VHOST_USER_CONFIG_SIZE).contains(&offset)
            || size > VHOST_USER_CONFIG_SIZE - VHOST_USER_CONFIG_OFFSET
            || size + offset > VHOST_USER_CONFIG_SIZE
        {
            return Err(Error::InvalidParam);
        }
        assert_eq!(offset, 0x100);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf, &[0xa5; 4]);
        Ok(())
    }

    #[cfg(feature = "gpu-socket")]
    fn set_gpu_socket(&mut self, _gpu_backend: GpuBackend) {}

    fn get_shared_object(&mut self, _uuid: VhostUserSharedMsg) -> Result<OwnedFd> {
        let file = tempfile::tempfile().unwrap();

        // SAFETY: We are calling `OwnedFd::from_raw_fd` to take ownership of the raw file descriptor.
        // This is safe in this context because:
        // 1. The file descriptor returned by `into_raw_fd()` is valid and open.
        // 2. We ensure that `OwnedFd` will properly close the file descriptor when it is dropped.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        Ok(owned_fd)
    }

    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)> {
        let file = tempfile::tempfile().unwrap();
        self.inflight_file = Some(file.try_clone().unwrap());
        Ok((
            VhostUserInflight {
                mmap_size: 0x1000,
                mmap_offset: 0,
                num_queues: inflight.num_queues,
                queue_size: inflight.queue_size,
            },
            file,
        ))
    }

    fn set_inflight_fd(&mut self, _inflight: &VhostUserInflight, _file: File) -> Result<()> {
        Ok(())
    }

    fn get_max_mem_slots(&mut self) -> Result<u64> {
        Ok(MAX_MEM_SLOTS as u64)
    }

    fn add_mem_region(&mut self, _region: &VhostUserSingleMemoryRegion, _fd: File) -> Result<()> {
        Ok(())
    }

    fn remove_mem_region(&mut self, _region: &VhostUserSingleMemoryRegion) -> Result<()> {
        Ok(())
    }

    fn set_device_state_fd(
        &mut self,
        _direction: VhostTransferStateDirection,
        _phase: VhostTransferStatePhase,
        _fd: File,
    ) -> Result<Option<File>> {
        Err(Error::ReqHandlerError(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dummy back end does not support state transfer",
        )))
    }

    fn check_device_state(&mut self) -> Result<()> {
        Err(Error::ReqHandlerError(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dummy back end does not support state transfer",
        )))
    }

    #[cfg(feature = "postcopy")]
    fn postcopy_advice(&mut self) -> Result<File> {
        let file = tempfile::tempfile().unwrap();
        Ok(file)
    }

    #[cfg(feature = "postcopy")]
    fn postcopy_listen(&mut self) -> Result<()> {
        Ok(())
    }

    #[cfg(feature = "postcopy")]
    fn postcopy_end(&mut self) -> Result<()> {
        Ok(())
    }
    fn set_log_base(&mut self, _log: &VhostUserLog, _file: File) -> Result<()> {
        Err(Error::InvalidMessage)
    }
}
