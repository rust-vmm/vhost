// Copyright (C) 2024 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation parts of the protocol on the socket from VHOST_USER_SET_GPU_SOCKET
//! see: https://www.qemu.org/docs/master/interop/vhost-user-gpu.html

use super::enum_value;
use crate::vhost_user::message::{MsgHeader, Req, VhostUserMsgValidator};
use crate::vhost_user::Error;

use std::fmt::Debug;
use std::marker::PhantomData;
use vm_memory::ByteValued;

enum_value! {
    /// Type of requests sending from gpu backends to gpu frontends.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    #[allow(non_camel_case_types, clippy::upper_case_acronyms)]
    pub enum GpuBackendReq: u32 {
        /// Get the supported protocol features bitmask.
        GET_PROTOCOL_FEATURES = 1,
        /// Enable protocol features using a bitmask.
        SET_PROTOCOL_FEATURES = 2,
        /// Get the preferred display configuration.
        GET_DISPLAY_INFO = 3,
        /// Set/show the cursor position.
        CURSOR_POS = 4,
        /// Set/hide the cursor.
        CURSOR_POS_HIDE = 5,
        /// Update the cursor shape and location.
        CURSOR_UPDATE = 6,
        /// Set the scanout resolution.
        /// To disable a scanout, the dimensions width/height are set to 0.
        SCANOUT = 7,
        /// Update the scanout content. The data payload contains the graphical bits.
        /// The display should be flushed and presented.
        UPDATE = 8,
        /// Set the scanout resolution/configuration, and share a DMABUF file descriptor for the
        /// scanout content, which is passed as ancillary data.
        /// To disable a scanout, the dimensions width/height are set to 0, there is no file
        /// descriptor passed.
        DMABUF_SCANOUT = 9,
        /// The display should be flushed and presented according to updated region from
        /// VhostUserGpuUpdate.
        /// Note: there is no data payload, since the scanout is shared thanks to DMABUF,
        /// that must have been set previously with VHOST_USER_GPU_DMABUF_SCANOUT.
        DMABUF_UPDATE = 10,
        /// Retrieve the EDID data for a given scanout.
        /// This message requires the VHOST_USER_GPU_PROTOCOL_F_EDID protocol feature to be
        /// supported.
        GET_EDID = 11,
        /// Same as DMABUF_SCANOUT, but also sends the dmabuf modifiers appended to the message,
        /// which were not provided in the other message.
        /// This message requires the VHOST_USER_GPU_PROTOCOL_F_DMABUF2 protocol feature to be
        /// supported.
        DMABUF_SCANOUT2 = 12,
    }
}

impl Req for GpuBackendReq {}

// Bit mask for common message flags.
bitflags! {
    /// Common message flags for vhost-user requests and replies.
    pub struct VhostUserGpuHeaderFlag: u32 {
        /// Mark message as reply.
        const REPLY = 0x4;
    }
}

/// A vhost-user message consists of 3 header fields and an optional payload. All numbers are in the
/// machine native byte order.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(super) struct VhostUserGpuMsgHeader<R: Req> {
    request: u32,
    flags: u32,
    size: u32,
    _r: PhantomData<R>,
}

impl<R: Req> Debug for VhostUserGpuMsgHeader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostUserMsgHeader")
            .field("request", &{ self.request })
            .field("flags", &{ self.flags })
            .field("size", &{ self.size })
            .finish()
    }
}

impl<R: Req> PartialEq for VhostUserGpuMsgHeader<R> {
    fn eq(&self, other: &Self) -> bool {
        self.request == other.request && self.flags == other.flags && self.size == other.size
    }
}

#[allow(dead_code)]
impl<R: Req> VhostUserGpuMsgHeader<R> {
    /// Create a new instance of `VhostUserMsgHeader`.
    pub fn new(request: R, flags: u32, size: u32) -> Self {
        VhostUserGpuMsgHeader {
            request: request.into(),
            flags,
            size,
            _r: PhantomData,
        }
    }

    /// Get message type.
    pub fn get_code(&self) -> crate::vhost_user::Result<R> {
        R::try_from(self.request).map_err(|_| Error::InvalidMessage)
    }

    /// Check whether it's a reply message.
    pub fn is_reply(&self) -> bool {
        (self.flags & VhostUserGpuHeaderFlag::REPLY.bits()) != 0
    }

    /// Mark message as reply.
    pub fn set_reply(&mut self, is_reply: bool) {
        if is_reply {
            self.flags |= VhostUserGpuHeaderFlag::REPLY.bits();
        } else {
            self.flags &= !VhostUserGpuHeaderFlag::REPLY.bits();
        }
    }

    /// Check whether it's the reply message for the request `req`.
    pub fn is_reply_for(&self, req: &VhostUserGpuMsgHeader<R>) -> bool {
        if let (Ok(code1), Ok(code2)) = (self.get_code(), req.get_code()) {
            self.is_reply() && !req.is_reply() && code1 == code2
        } else {
            false
        }
    }

    /// Get message size.
    pub fn get_size(&self) -> u32 {
        self.size
    }

    /// Set message size.
    pub fn set_size(&mut self, size: u32) {
        self.size = size;
    }
}

impl<R: Req> Default for VhostUserGpuMsgHeader<R> {
    fn default() -> Self {
        VhostUserGpuMsgHeader {
            request: 0,
            flags: 0,
            size: 0,
            _r: PhantomData,
        }
    }
}

// SAFETY: Safe because all fields of VhostUserGpuMsgHeader are POD.
unsafe impl<R: Req> ByteValued for VhostUserGpuMsgHeader<R> {}

impl<T: Req> VhostUserMsgValidator for VhostUserGpuMsgHeader<T> {
    fn is_valid(&self) -> bool {
        self.get_code().is_ok() && VhostUserGpuHeaderFlag::from_bits(self.flags).is_some()
    }
}

impl<R: Req> MsgHeader for VhostUserGpuMsgHeader<R> {
    type Request = R;
    const MAX_MSG_SIZE: usize = u32::MAX as usize;
}

// Bit mask for vhost-user-gpu protocol feature flags.
bitflags! {
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    /// Vhost-user-gpu protocol feature flags from the vhost-user-gpu specification.
    pub struct VhostUserGpuProtocolFeatures: u64 {
        /// Frontend support for EDID
        const EDID = 0;
        /// Frontend support for DMABUF_SCANOUT2
        const DMABUF2 = 1;
    }
}

/// The virtio_gpu_ctrl_hdr from virtio specification
/// Defined here because some GpuBackend commands return virtio structs, which contain this header.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioGpuCtrlHdr {
    /// Specifies the type of the driver request (VIRTIO_GPU_CMD_*)
    /// or device response (VIRTIO_GPU_RESP_*).
    pub type_: u32,
    /// Request / response flags.
    pub flags: u32,
    /// Set VIRTIO_GPU_FLAG_FENCE bit in the response
    pub fence_id: u64,
    /// Rendering context (used in 3D mode only).
    pub ctx_id: u32,
    /// ring_idx indicates the value of a context-specific ring index.
    /// The minimum value is 0 and maximum value is 63 (inclusive).
    pub ring_idx: u8,
    /// padding of the structure
    pub padding: [u8; 3],
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VirtioGpuCtrlHdr {}

/// The virtio_gpu_rect struct from virtio specification.
/// Part of the reply for GpuBackend::get_display_info
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioGpuRect {
    /// The position field x describes how the displays are arranged
    pub x: u32,
    /// The position field y describes how the displays are arranged
    pub y: u32,
    /// Display resolution width
    pub width: u32,
    /// Display resolution height
    pub height: u32,
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VirtioGpuRect {}

/// The virtio_gpu_display_one struct from virtio specification.
/// Part of the reply for GpuBackend::get_display_info
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioGpuDisplayOne {
    /// Preferred display resolutions and display positions relative to each other
    pub r: VirtioGpuRect,
    /// The enabled field is set when the user enabled the display.
    pub enabled: u32,
    /// The display flags
    pub flags: u32,
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VirtioGpuDisplayOne {}

/// Constant for maximum number of scanouts, defined in the virtio specification.
pub const VIRTIO_GPU_MAX_SCANOUTS: usize = 16;

/// The virtio_gpu_resp_display_info from the virtio specification.
/// This it the reply from GpuBackend::get_display_info
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioGpuRespDisplayInfo {
    /// The fixed header struct
    pub hdr: VirtioGpuCtrlHdr,
    /// pmodes contains whether the scanout is enabled and what
    /// its preferred position and size is
    pub pmodes: [VirtioGpuDisplayOne; VIRTIO_GPU_MAX_SCANOUTS],
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VirtioGpuRespDisplayInfo {}

impl VhostUserMsgValidator for VirtioGpuRespDisplayInfo {}

/// The VhostUserGpuEdidRequest from the vhost-user-gpu specification.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct VhostUserGpuEdidRequest {
    /// The id of the scanout to retrieve EDID data for
    pub scanout_id: u32,
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VhostUserGpuEdidRequest {}

impl VhostUserMsgValidator for VhostUserGpuEdidRequest {}

/// The VhostUserGpuUpdate from the vhost-user-gpu specification.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct VhostUserGpuUpdate {
    /// The id of the scanout that is being updated
    pub scanout_id: u32,
    /// The x coordinate of the region to update
    pub x: u32,
    /// The y coordinate of the region to update
    pub y: u32,
    /// The width of the region to update
    pub width: u32,
    /// The height of the region to update
    pub height: u32,
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VhostUserGpuUpdate {}

impl VhostUserMsgValidator for VhostUserGpuUpdate {}

/// The VhostUserGpuDMABUFScanout from the vhost-user-gpu specification.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct VhostUserGpuDMABUFScanout {
    /// The id of the scanout to update
    pub scanout_id: u32,
    /// The position field x of the scanout within the DMABUF
    pub x: u32,
    /// The position field y of the scanout within the DMABUF
    pub y: u32,
    /// Scanout width size
    pub width: u32,
    /// Scanout height size
    pub height: u32,
    /// The DMABUF width
    pub fd_width: u32,
    /// The DMABUF height
    pub fd_height: u32,
    /// The DMABUF stride
    pub fd_stride: u32,
    /// The DMABUF flags
    pub fd_flags: u32,
    /// The DMABUF fourcc
    pub fd_drm_fourcc: u32,
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VhostUserGpuDMABUFScanout {}

impl VhostUserMsgValidator for VhostUserGpuDMABUFScanout {}

/// The VhostUserGpuDMABUFScanout2 from the vhost-user-gpu specification.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(C, packed)]
pub struct VhostUserGpuDMABUFScanout2 {
    /// The dmabuf scanout parameters
    pub dmabuf_scanout: VhostUserGpuDMABUFScanout,
    /// The DMABUF modifiers
    pub modifier: u64,
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VhostUserGpuDMABUFScanout2 {}

impl VhostUserMsgValidator for VhostUserGpuDMABUFScanout2 {}

/// The VhostUserGpuCursorPos from the vhost-user-gpu specification.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct VhostUserGpuCursorPos {
    /// The scanout where the cursor is located
    pub scanout_id: u32,
    /// The cursor position field x
    pub x: u32,
    /// The cursor position field y
    pub y: u32,
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VhostUserGpuCursorPos {}

impl VhostUserMsgValidator for VhostUserGpuCursorPos {}

/// The VhostUserGpuCursorUpdate from the vhost-user-gpu specification.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct VhostUserGpuCursorUpdate {
    /// The cursor location
    pub pos: VhostUserGpuCursorPos,
    /// The cursor hot location x
    pub hot_x: u32,
    /// The cursor hot location y
    pub hot_y: u32,
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VhostUserGpuCursorUpdate {}

impl VhostUserMsgValidator for VhostUserGpuCursorUpdate {}

/// The virtio_gpu_resp_edid struct from the virtio specification.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct VirtioGpuRespGetEdid {
    /// The fixed header struct
    pub hdr: VirtioGpuCtrlHdr,
    /// The actual size of the `edid` field.
    pub size: u32,
    /// Padding of the structure
    pub padding: u32,
    /// The EDID display data blob (as specified by VESA) for the scanout.
    pub edid: [u8; 1024],
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VirtioGpuRespGetEdid {}

impl Default for VirtioGpuRespGetEdid {
    fn default() -> Self {
        VirtioGpuRespGetEdid {
            hdr: VirtioGpuCtrlHdr::default(),
            size: u32::default(),
            padding: u32::default(),
            edid: [0; 1024], // Default value for the edid array (filled with zeros)
        }
    }
}

impl VhostUserMsgValidator for VirtioGpuRespGetEdid {}

/// The VhostUserGpuScanout from the vhost-user-gpu specification.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct VhostUserGpuScanout {
    /// The id of the scanout
    pub scanout_id: u32,
    /// The scanout width
    pub width: u32,
    /// The scanout height
    pub height: u32,
}

// SAFETY: Safe because all fields are POD.
unsafe impl ByteValued for VhostUserGpuScanout {}

impl VhostUserMsgValidator for VhostUserGpuScanout {}
