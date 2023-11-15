// Copyright (C) 2024 Red Hat, Inc.
//
// SPDX-License-Identifier: Apache-2.0

use std::ops::Index;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::{io, ptr};
use vm_memory::bitmap::{Bitmap, BitmapSlice, WithBitmapSlice};
use vm_memory::mmap::NewBitmap;
use vm_memory::{Address, GuestMemoryRegion};

// Size in bytes of the `VHOST_LOG_PAGE`
const LOG_PAGE_SIZE: usize = 0x1000;
// Number of bits grouped together as a basic storage unit ("word") in the bitmap
// (i.e., in this case one byte tracks 8 pages, one bit per page).
const LOG_WORD_SIZE: usize = u8::BITS as usize;

/// A `Bitmap` with an internal `Bitmap` that can be replaced at runtime
pub trait BitmapReplace: Bitmap {
    type InnerBitmap: MemRegionBitmap;

    /// Replace the internal `Bitmap`
    fn replace(&self, bitmap: Self::InnerBitmap);
}

/// A bitmap relative to a memory region
pub trait MemRegionBitmap: Sized {
    /// Creates a new bitmap relative to `region`, using the `logmem` as
    /// backing memory for the bitmap
    fn new<R: GuestMemoryRegion>(region: &R, logmem: Arc<MmapLogReg>) -> io::Result<Self>;
}

// TODO: This impl is a quick and dirty hack to allow the tests to continue using
// `GuestMemoryMmap<()>`. Sadly this is exposed in the public API, but it should
// be moved to an internal mock library.
impl BitmapReplace for () {
    type InnerBitmap = ();

    // this implementation must not be used if the backend sets `VHOST_USER_PROTOCOL_F_LOG_SHMFD`
    fn replace(&self, _bitmap: ()) {
        panic!("The unit bitmap () must not be used if VHOST_USER_PROTOCOL_F_LOG_SHMFD is set");
    }
}

impl MemRegionBitmap for () {
    fn new<R: GuestMemoryRegion>(_region: &R, _logmem: Arc<MmapLogReg>) -> io::Result<Self> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// `BitmapMmapRegion` implements a bitmap tha can be replaced at runtime.
/// The main use case is to support live migration on vhost-user backends
/// (see `VHOST_USER_PROTOCOL_F_LOG_SHMFD` and `VHOST_USER_SET_LOG_BASE` in the vhost-user protocol
/// specification). It uses a fixed memory page size of `VHOST_LOG_PAGE` bytes (i.e., `4096` bytes),
/// so it converts addresses to page numbers before setting or clearing the bits.
///
/// To use this bitmap you need to define the memory as `GuestMemoryMmap<BitmapMmapRegion>`.
///
/// Note:
/// This implementation uses `std::sync::RwLock`, the priority policy of the lock is dependent on
/// the underlying operating system's implementation and does not guarantee any particular policy,
/// in systems other than linux a thread trying to acquire the lock may starve.
#[derive(Default, Debug, Clone)]
pub struct BitmapMmapRegion {
    // TODO: To avoid both reader and writer starvation we can replace the `std::sync::RwLock` with
    // `parking_lot::RwLock`.
    inner: Arc<RwLock<Option<AtomicBitmapMmap>>>,
    base_address: usize, // The slice's base address
}

impl Bitmap for BitmapMmapRegion {
    fn mark_dirty(&self, offset: usize, len: usize) {
        let inner = self.inner.read().unwrap();
        if let Some(bitmap) = inner.as_ref() {
            if let Some(absolute_offset) = self.base_address.checked_add(offset) {
                bitmap.mark_dirty(absolute_offset, len);
            }
        }
    }

    fn dirty_at(&self, offset: usize) -> bool {
        let inner = self.inner.read().unwrap();
        inner
            .as_ref()
            .is_some_and(|bitmap| bitmap.dirty_at(self.base_address.saturating_add(offset)))
    }

    fn slice_at(&self, offset: usize) -> <Self as WithBitmapSlice>::S {
        Self {
            inner: Arc::clone(&self.inner),
            base_address: self.base_address.saturating_add(offset),
        }
    }
}

impl BitmapReplace for BitmapMmapRegion {
    type InnerBitmap = AtomicBitmapMmap;

    fn replace(&self, bitmap: AtomicBitmapMmap) {
        let mut inner = self.inner.write().unwrap();
        inner.replace(bitmap);
    }
}

impl BitmapSlice for BitmapMmapRegion {}

impl<'a> WithBitmapSlice<'a> for BitmapMmapRegion {
    type S = Self;
}

impl NewBitmap for BitmapMmapRegion {
    fn with_len(_len: usize) -> Self {
        Self::default()
    }
}

/// `AtomicBitmapMmap` implements a simple memory-mapped bitmap on the page level with test
/// and set operations. The main use case is to support live migration on vhost-user backends
/// (see `VHOST_USER_PROTOCOL_F_LOG_SHMFD` and `VHOST_USER_SET_LOG_BASE` in the vhost-user protocol
/// specification). It uses a fixed memory page size of `LOG_PAGE_SIZE` bytes, so it converts
/// addresses to page numbers before setting or clearing the bits.
#[derive(Debug)]
pub struct AtomicBitmapMmap {
    logmem: Arc<MmapLogReg>,
    pages_before_region: usize, // Number of pages to ignore from the start of the bitmap
    number_of_pages: usize,     // Number of total pages indexed in the bitmap for this region
}

// `AtomicBitmapMmap` implements a simple bitmap, it is page-size aware and relative
// to a memory region. It  handling the `log` memory mapped area. Each page is indexed
// inside a word of `LOG_WORD_SIZE` bits, so even if the bitmap starts at the beginning of
// the mapped area, the memory region does not necessarily have to start at the beginning of
// that word.
// Note: we don't implement `Bitmap` because we cannot implement `slice_at()`
impl MemRegionBitmap for AtomicBitmapMmap {
    // Creates a new memory-mapped bitmap for the memory region. This bitmap must fit within the
    // log mapped memory.
    fn new<R: GuestMemoryRegion>(region: &R, logmem: Arc<MmapLogReg>) -> io::Result<Self> {
        let region_start_addr: usize = region.start_addr().raw_value().io_try_into()?;
        let region_len: usize = region.len().io_try_into()?;
        if region_len == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        // The size of the log should be large enough to cover all known guest addresses.
        let region_end_addr = region_start_addr
            .checked_add(region_len - 1)
            .ok_or(io::Error::from(io::ErrorKind::InvalidData))?;
        let region_end_log_word = page_word(page_number(region_end_addr));
        if region_end_log_word >= logmem.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        // The frontend sends a single bitmap (i.e., the log memory to be mapped using `fd`,
        // `mmap_offset` and `mmap_size`) that covers the entire guest memory.
        // However, since each memory region requires a bitmap relative to them, we have to
        // adjust the offset and size, in number of pages, of this region.
        let offset_pages = page_number(region_start_addr);
        let size_page = page_number(region_len);

        Ok(Self {
            logmem,
            pages_before_region: offset_pages,
            number_of_pages: size_page,
        })
    }
}

impl AtomicBitmapMmap {
    // Sets the memory range as dirty. The `offset` is relative to the memory region,
    // so an offset of `0` references the start of the memory region. Any attempt to
    // access beyond the end of the bitmap are simply ignored.
    fn mark_dirty(&self, offset: usize, len: usize) {
        if len == 0 {
            return;
        }

        let first_page = page_number(offset);
        let last_page = page_number(offset.saturating_add(len - 1));
        for page in first_page..=last_page {
            if page >= self.number_of_pages {
                break; // ignore out of bound access
            }

            // get the absolute page number
            let page = self.pages_before_region + page;
            self.logmem[page_word(page)].fetch_or(1 << page_bit(page), Ordering::Relaxed);
        }
    }

    // Check whether the specified offset is marked as dirty. The `offset` is relative
    // to the memory region, so a `0` offset references the start of the memory region.
    // Any attempt to access beyond the end of the bitmap are simply ignored.
    fn dirty_at(&self, offset: usize) -> bool {
        let page = page_number(offset);
        if page >= self.number_of_pages {
            return false; // ignore out of bound access
        }

        // get the absolute page number
        let page = self.pages_before_region + page;
        let page_bit = self.logmem[page_word(page)].load(Ordering::Relaxed) & (1 << page_bit(page));
        page_bit != 0
    }
}

/// `MmaplogReg` mmaps the frontend bitmap backing memory in the current process.
#[derive(Debug)]
pub struct MmapLogReg {
    addr: *const AtomicU8,
    len: usize,
}

// SAFETY: Send is not automatically implemented because the raw pointer.
// No one besides `MmapLogReg` has the raw pointer, so we can safely transfer it to another thread.
unsafe impl Send for MmapLogReg {}

// SAFETY: Sync is not automatically implemented because the raw pointer.
// `MmapLogReg` doesn't have any interior mutability and all access to `&AtomicU8`
// are done through atomic operations.
unsafe impl Sync for MmapLogReg {}

impl MmapLogReg {
    // Note: We could try to adjust the mapping area to only cover the memory region, but
    // the region's starting address is not guarantee to be LOG_WORD_SIZE-page aligned
    // which makes the implementation needlessly cumbersome.
    // Note: The specification does not define whether the offset must be page-aligned or not.
    // But, since we are receiving the offset from the frontend to be used to call mmap,
    // we assume it is properly aligned (currently, qemu always send a 0 offset).
    pub(crate) fn from_file(fd: BorrowedFd, offset: u64, len: u64) -> io::Result<Self> {
        let offset: isize = offset.io_try_into()?;
        let len: usize = len.io_try_into()?;

        // Let's uphold the safety contract for `std::ptr::offset()`.
        if len > isize::MAX as usize {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        // SAFETY: `fd` is a valid file descriptor and we are not using `libc::MAP_FIXED`.
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                offset as libc::off_t,
            )
        };

        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            addr: addr as *const AtomicU8,
            len,
        })
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl Index<usize> for MmapLogReg {
    type Output = AtomicU8;

    // It's ok to get a reference to an atomic value.
    fn index(&self, index: usize) -> &Self::Output {
        assert!(index < self.len);
        // Note: Instead of `&*` we can use `AtomicU8::from_ptr()` as soon it gets stabilized.
        // SAFETY: `self.addr` is a valid and properly aligned pointer. Also, `self.addr` + `index`
        // doesn't wrap around and is contained within the mapped memory region.
        unsafe { &*self.addr.add(index) }
    }
}

impl Drop for MmapLogReg {
    fn drop(&mut self) {
        // SAFETY: `addr` is properly aligned, also we are sure that this is the
        // last reference alive and/or we have an exclusive access to this object.
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.len as libc::size_t);
        }
    }
}

trait IoTryInto<T: TryFrom<Self>>: Sized {
    fn io_try_into(self) -> io::Result<T>;
}

impl<TySrc, TyDst> IoTryInto<TyDst> for TySrc
where
    TyDst: TryFrom<TySrc>,
    <TyDst as TryFrom<TySrc>>::Error: Send + Sync + std::error::Error + 'static,
{
    fn io_try_into(self) -> io::Result<TyDst> {
        self.try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

#[inline]
// Get the page number corresponding to the address `addr`
fn page_number(addr: usize) -> usize {
    addr / LOG_PAGE_SIZE
}

#[inline]
// Get the word within the bitmap of the page.
// Each page is indexed inside a word of `LOG_WORD_SIZE` bits.
fn page_word(page: usize) -> usize {
    page / LOG_WORD_SIZE
}

#[inline]
// Get the bit index inside a word of `LOG_WORD_SIZE` bits
fn page_bit(page: usize) -> usize {
    page % LOG_WORD_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::AsFd;
    use vm_memory::{GuestAddress, GuestRegionMmap};
    use vmm_sys_util::tempfile::TempFile;

    // Helper method to check whether a specified range is clean.
    pub fn range_is_clean<B: Bitmap>(b: &B, start: usize, len: usize) -> bool {
        (start..start + len).all(|offset| !b.dirty_at(offset))
    }

    // Helper method to check whether a specified range is dirty.
    pub fn range_is_dirty<B: Bitmap>(b: &B, start: usize, len: usize) -> bool {
        (start..start + len).all(|offset| b.dirty_at(offset))
    }

    fn tmp_file(len: usize) -> File {
        let mut f = TempFile::new().unwrap().into_file();
        let buf = vec![0; len];
        f.write_all(buf.as_ref()).unwrap();
        f
    }

    fn test_all(b: &BitmapMmapRegion, len: usize) {
        assert!(range_is_clean(b, 0, len), "The bitmap should be clean");

        b.mark_dirty(0, len);
        assert!(range_is_dirty(b, 0, len), "The bitmap should be dirty");
    }

    #[test]
    #[cfg(not(miri))] // Miri cannot mmap files
    fn test_bitmap_region_bigger_than_log() {
        // Let's create a log memory area to track 8 pages,
        // since 1 bit correspond to 1 page, we need a 1-byte log memory area.
        let mmap_offset: u64 = 0;
        let mmap_size = 1; // // 1 byte = 8 bits/pages
        let f = tmp_file(mmap_size);

        // A guest memory region of 16 pages
        let region_start_addr = GuestAddress(mmap_offset);
        let region_len = LOG_PAGE_SIZE * 16;
        let region: GuestRegionMmap<()> =
            GuestRegionMmap::from_range(region_start_addr, region_len, None).unwrap();

        let logmem =
            Arc::new(MmapLogReg::from_file(f.as_fd(), mmap_offset, mmap_size as u64).unwrap());

        let log = AtomicBitmapMmap::new(&region, logmem);

        assert!(log.is_err());
    }
    #[test]
    #[cfg(not(miri))] // Miri cannot mmap files
    fn test_bitmap_log_and_region_same_size() {
        // A log memory area able to track 32 pages
        let mmap_offset: u64 = 0;
        let mmap_size = 4; // 4 bytes * 8 bits = 32 bits/pages
        let f = tmp_file(mmap_size);

        // A 32-page guest memory region
        let region_start_addr = GuestAddress::new(mmap_offset);
        let region_len = LOG_PAGE_SIZE * 32;
        let region: GuestRegionMmap<()> =
            GuestRegionMmap::from_range(region_start_addr, region_len, None).unwrap();

        let logmem =
            Arc::new(MmapLogReg::from_file(f.as_fd(), mmap_offset, mmap_size as u64).unwrap());

        let log = AtomicBitmapMmap::new(&region, logmem);
        assert!(log.is_ok());
        let log = log.unwrap();

        let bitmap = BitmapMmapRegion::default();
        bitmap.replace(log);

        test_all(&bitmap, region_len);
    }

    #[test]
    #[cfg(not(miri))] // Miri cannot mmap files
    fn test_bitmap_region_smaller_than_log() {
        // A log memory area able to track 32 pages
        let mmap_offset: u64 = 0;
        let mmap_size = 4; // 4 bytes * 8 bits = 32 bits/pages
        let f = tmp_file(mmap_size);

        // A 16-page guest memory region
        let region_start_addr = GuestAddress::new(mmap_offset);
        let region_len = LOG_PAGE_SIZE * 16;
        let region: GuestRegionMmap<()> =
            GuestRegionMmap::from_range(region_start_addr, region_len, None).unwrap();

        let logmem =
            Arc::new(MmapLogReg::from_file(f.as_fd(), mmap_offset, mmap_size as u64).unwrap());

        let log = AtomicBitmapMmap::new(&region, logmem);
        assert!(log.is_ok());
        let log = log.unwrap();

        let bitmap = BitmapMmapRegion::default();

        bitmap.replace(log);

        test_all(&bitmap, region_len);
    }

    #[test]
    #[cfg(not(miri))] // Miri cannot mmap files
    fn test_bitmap_region_smaller_than_one_word() {
        // A log memory area able to track 32 pages
        let mmap_offset: u64 = 0;
        let mmap_size = 4; // 4 bytes * 8 bits = 32 bits/pages
        let f = tmp_file(mmap_size);

        // A 6-page guest memory region
        let region_start_addr = GuestAddress::new(mmap_offset);
        let region_len = LOG_PAGE_SIZE * 6;
        let region: GuestRegionMmap<()> =
            GuestRegionMmap::from_range(region_start_addr, region_len, None).unwrap();

        let logmem =
            Arc::new(MmapLogReg::from_file(f.as_fd(), mmap_offset, mmap_size as u64).unwrap());

        let log = AtomicBitmapMmap::new(&region, logmem);
        assert!(log.is_ok());
        let log = log.unwrap();

        let bitmap = BitmapMmapRegion::default();
        bitmap.replace(log);

        test_all(&bitmap, region_len);
    }

    #[test]
    #[cfg(not(miri))] // Miri cannot mmap files
    fn test_bitmap_two_regions_overlapping_word_first_dirty() {
        // A log memory area able to track 32 pages
        let mmap_offset: u64 = 0;
        let mmap_size = 4; // 4 bytes * 8 bits = 32 bits/pages
        let f = tmp_file(mmap_size);

        let logmem =
            Arc::new(MmapLogReg::from_file(f.as_fd(), mmap_offset, mmap_size as u64).unwrap());

        // A 11-page guest memory region
        let region0_start_addr = GuestAddress::new(mmap_offset);
        let region0_len = LOG_PAGE_SIZE * 11;
        let region0: GuestRegionMmap<()> =
            GuestRegionMmap::from_range(region0_start_addr, region0_len, None).unwrap();

        let log0 = AtomicBitmapMmap::new(&region0, Arc::clone(&logmem));
        assert!(log0.is_ok());
        let log0 = log0.unwrap();
        let bitmap0 = BitmapMmapRegion::default();
        bitmap0.replace(log0);

        // A 1-page guest memory region
        let region1_start_addr = GuestAddress::new(mmap_offset + LOG_PAGE_SIZE as u64 * 14);
        let region1_len = LOG_PAGE_SIZE;
        let region1: GuestRegionMmap<()> =
            GuestRegionMmap::from_range(region1_start_addr, region1_len, None).unwrap();

        let log1 = AtomicBitmapMmap::new(&region1, Arc::clone(&logmem));
        assert!(log1.is_ok());
        let log1 = log1.unwrap();

        let bitmap1 = BitmapMmapRegion::default();
        bitmap1.replace(log1);

        // Both regions should be clean
        assert!(
            range_is_clean(&bitmap0, 0, region0_len),
            "The bitmap0 should be clean"
        );
        assert!(
            range_is_clean(&bitmap1, 0, region1_len),
            "The bitmap1 should be clean"
        );

        // Marking region 0, region 1 should continue be clean
        bitmap0.mark_dirty(0, region0_len);

        assert!(
            range_is_dirty(&bitmap0, 0, region0_len),
            "The bitmap0 should be dirty"
        );
        assert!(
            range_is_clean(&bitmap1, 0, region1_len),
            "The bitmap1 should be clean"
        );
    }

    #[test]
    #[cfg(not(miri))] // Miri cannot mmap files
    fn test_bitmap_two_regions_overlapping_word_second_dirty() {
        // A log memory area able to track 32 pages
        let mmap_offset: u64 = 0;
        let mmap_size = 4; // 4 bytes * 8 bits = 32 bits/pages
        let f = tmp_file(mmap_size);

        let logmem =
            Arc::new(MmapLogReg::from_file(f.as_fd(), mmap_offset, mmap_size as u64).unwrap());

        // A 11-page guest memory region
        let region0_start_addr = GuestAddress::new(mmap_offset);
        let region0_len = LOG_PAGE_SIZE * 11;
        let region0: GuestRegionMmap<()> =
            GuestRegionMmap::from_range(region0_start_addr, region0_len, None).unwrap();

        let log0 = AtomicBitmapMmap::new(&region0, Arc::clone(&logmem));
        assert!(log0.is_ok());
        let log0 = log0.unwrap();

        let bitmap0 = BitmapMmapRegion::default();
        bitmap0.replace(log0);

        // A 1-page guest memory region
        let region1_start_addr = GuestAddress::new(mmap_offset + LOG_PAGE_SIZE as u64 * 14);
        let region1_len = LOG_PAGE_SIZE;
        let region1: GuestRegionMmap<()> =
            GuestRegionMmap::from_range(region1_start_addr, region1_len, None).unwrap();

        let log1 = AtomicBitmapMmap::new(&region1, Arc::clone(&logmem));
        assert!(log1.is_ok());
        let log1 = log1.unwrap();

        let bitmap1 = BitmapMmapRegion::default();
        bitmap1.replace(log1);

        // Both regions should be clean
        assert!(
            range_is_clean(&bitmap0, 0, region0_len),
            "The bitmap0 should be clean"
        );
        assert!(
            range_is_clean(&bitmap1, 0, region1_len),
            "The bitmap1 should be clean"
        );

        // Marking region 1, region 0 should continue be clean
        bitmap1.mark_dirty(0, region1_len);

        assert!(
            range_is_dirty(&bitmap1, 0, region1_len),
            "The bitmap0 should be dirty"
        );
        assert!(
            range_is_clean(&bitmap0, 0, region0_len),
            "The bitmap1 should be clean"
        );
    }

    #[test]
    #[cfg(not(miri))] // Miri cannot mmap files
    fn test_bitmap_region_slice() {
        // A log memory area able to track 32 pages
        let mmap_offset: u64 = 0;
        let mmap_size = 4; // 4 bytes * 8 bits = 32 bits/pages
        let f = tmp_file(mmap_size);

        // A 32-page guest memory region
        let region_start_addr = GuestAddress::new(mmap_offset);
        let region_len = LOG_PAGE_SIZE * 32;
        let region: GuestRegionMmap<()> =
            GuestRegionMmap::from_range(region_start_addr, region_len, None).unwrap();

        let logmem =
            Arc::new(MmapLogReg::from_file(f.as_fd(), mmap_offset, mmap_size as u64).unwrap());

        let log = AtomicBitmapMmap::new(&region, logmem);
        assert!(log.is_ok());
        let log = log.unwrap();

        let bitmap = BitmapMmapRegion::default();
        bitmap.replace(log);

        assert!(
            range_is_clean(&bitmap, 0, region_len),
            "The bitmap should be clean"
        );

        // Let's get a slice of half the bitmap
        let slice_len = region_len / 2;
        let slice = bitmap.slice_at(slice_len);
        assert!(
            range_is_clean(&slice, 0, slice_len),
            "The slice should be clean"
        );

        slice.mark_dirty(0, slice_len);
        assert!(
            range_is_dirty(&slice, 0, slice_len),
            "The slice should be dirty"
        );
        assert!(
            range_is_clean(&bitmap, 0, slice_len),
            "The first half of the bitmap should be clean"
        );
        assert!(
            range_is_dirty(&bitmap, slice_len, region_len - slice_len),
            "The last half of the bitmap should be dirty"
        );
    }
}
