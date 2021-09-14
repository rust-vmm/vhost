// Copyright (C) 2021 Red Hat, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Trait to control vhost-vdpa backend drivers.

use vmm_sys_util::eventfd::EventFd;

use crate::backend::VhostBackend;
use crate::Result;

/// vhost vdpa IOVA range
pub struct VhostVdpaIovaRange {
    /// First address that can be mapped by vhost-vDPA.
    pub first: u64,
    /// Last address that can be mapped by vhost-vDPA.
    pub last: u64,
}

/// Trait to control vhost-vdpa backend drivers.
pub trait VhostVdpa: VhostBackend {
    /// Get the device id.
    /// The device ids follow the same definition of the device id defined in virtio-spec.
    fn get_device_id(&self) -> Result<u32>;

    /// Get the status.
    /// The status bits follow the same definition of the device status defined in virtio-spec.
    fn get_status(&self) -> Result<u8>;

    /// Set the status.
    /// The status bits follow the same definition of the device status defined in virtio-spec.
    ///
    /// # Arguments
    /// * `status` - Status bits to set
    fn set_status(&self, status: u8) -> Result<()>;

    /// Get the device configuration.
    ///
    /// # Arguments
    /// * `offset` - Offset in the device configuration space
    /// * `buffer` - Buffer for configuration data
    fn get_config(&self, offset: u32, buffer: &mut [u8]) -> Result<()>;

    /// Set the device configuration.
    ///
    /// # Arguments
    /// * `offset` - Offset in the device configuration space
    /// * `buffer` - Buffer for configuration data
    fn set_config(&self, offset: u32, buffer: &[u8]) -> Result<()>;

    /// Set the status for a given vring.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to enable/disable.
    /// * `enabled` - true to enable the vring, false to disable it.
    fn set_vring_enable(&self, queue_index: usize, enabled: bool) -> Result<()>;

    /// Get the maximum number of descriptors in the vring supported by the device.
    fn get_vring_num(&self) -> Result<u16>;

    /// Set the eventfd to trigger when device configuration change.
    ///
    /// # Arguments
    /// * `fd` - EventFd to trigger.
    fn set_config_call(&self, fd: &EventFd) -> Result<()>;

    /// Get the valid I/O virtual addresses range supported by the device.
    fn get_iova_range(&self) -> Result<VhostVdpaIovaRange>;

    /// Map DMA region.
    ///
    /// # Arguments
    /// * `iova` - I/O virtual address.
    /// * `size` - Size of the I/O mapping.
    /// * `vaddr` - Virtual address in the current process.
    /// * `readonly` - true if the region is read-only, false if reads and writes are allowed.
    fn dma_map(&self, iova: u64, size: u64, vaddr: *const u8, readonly: bool) -> Result<()>;

    /// Unmap DMA region.
    ///
    /// # Arguments
    /// * `iova` - I/O virtual address.
    /// * `size` - Size of the I/O mapping.
    fn dma_unmap(&self, iova: u64, size: u64) -> Result<()>;
}
