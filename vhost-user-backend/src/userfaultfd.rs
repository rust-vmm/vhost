// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

const UFFDIO_API: libc::Ioctl = libc::_IOWR::<UffdioApi>(0xaa, 0x3f);
const UFFDIO_REGISTER: libc::Ioctl = libc::_IOWR::<UffdioRegister>(0xaa, 0x00);
const USERFAULTFD_IOC_NEW: libc::Ioctl = libc::_IO(0xaa, 0x00);

const UFFD_API: u64 = 0xaa;
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;

#[repr(C)]
struct UffdioApi {
    api: u64,
    features: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdioRegister {
    range_start: u64,
    range_len: u64,
    mode: u64,
    ioctls: u64,
}

pub(crate) struct Uffd(File);

impl Uffd {
    pub(crate) fn new() -> io::Result<Self> {
        let flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
        // Try with `/dev/userfaultfd`, and fallback to `userfaultfd(2)` if not found
        let uffd = match File::options()
            .read(true)
            .write(true)
            .open("/dev/userfaultfd")
        {
            Ok(dev) => {
                // SAFETY: USERFAULTFD_IOC_NEW takes the userfaultfd(2) flags and returns a new fd.
                let fd = unsafe { libc::ioctl(dev.as_raw_fd(), USERFAULTFD_IOC_NEW, flags) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: The ioctl returned a new fd that only us have
                unsafe { File::from_raw_fd(fd) }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // SAFETY: userfaultfd(2) only takes flags and returns a new fd.
                let fd = unsafe { libc::syscall(libc::SYS_userfaultfd, flags as libc::c_long) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: The syscall returned a new fd that only us have
                unsafe { File::from_raw_fd(fd as RawFd) }
            }
            Err(e) => return Err(e),
        };

        let mut api = UffdioApi {
            api: UFFD_API,
            features: 0,
            ioctls: 0,
        };
        // SAFETY: `api` is a valid struct uffdio_api for this ioctl.
        let ret = unsafe { libc::ioctl(uffd.as_raw_fd(), UFFDIO_API, &mut api) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Uffd(uffd))
    }

    pub(crate) fn register(&self, addr: u64, len: u64) -> io::Result<()> {
        let mut register = UffdioRegister {
            range_start: addr,
            range_len: len,
            mode: UFFDIO_REGISTER_MODE_MISSING,
            ioctls: 0,
        };
        // SAFETY: `register` is a valid struct uffdio_register for this ioctl.
        let ret = unsafe { libc::ioctl(self.0.as_raw_fd(), UFFDIO_REGISTER, &mut register) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

impl AsRawFd for Uffd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
