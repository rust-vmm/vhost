// Copyright (C) 2021 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Trait to control vhost-net backend drivers.

use std::fs::File;

use crate::backend::VhostBackend;
use crate::Result;

/// Trait to control vhost-net backend drivers.
pub trait VhostNet: VhostBackend {
    /// Set fd as VHOST_NET backend.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the virtqueue
    /// * `fd` - The file descriptor which servers as the backend
    fn set_backend(&self, queue_idx: usize, fd: Option<&File>) -> Result<()>;
}
