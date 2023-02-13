use std::ffi::CString;
use std::fs::File;
use std::io::Result;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use vhost::vhost_user::message::{
    VhostUserConfigFlags, VhostUserHeaderFlag, VhostUserInflight, VhostUserProtocolFeatures,
};
use vhost::vhost_user::{Listener, Master, Slave, VhostUserMaster};
use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vhost_user_backend::{VhostUserBackendMut, VhostUserDaemon, VringRwLock};
use vm_memory::{
    FileOffset, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

struct MockVhostBackend {
    events: u64,
    event_idx: bool,
    acked_features: u64,
}

impl MockVhostBackend {
    fn new() -> Self {
        MockVhostBackend {
            events: 0,
            event_idx: false,
            acked_features: 0,
        }
    }
}

impl VhostUserBackendMut<VringRwLock, ()> for MockVhostBackend {
    fn num_queues(&self) -> usize {
        2
    }

    fn max_queue_size(&self) -> usize {
        256
    }

    fn features(&self) -> u64 {
        0xffff_ffff_ffff_ffff
    }

    fn acked_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::all()
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        assert_eq!(offset, 0x200);
        assert_eq!(size, 8);

        vec![0xa5u8; 8]
    }

    fn set_config(&mut self, offset: u32, buf: &[u8]) -> Result<()> {
        assert_eq!(offset, 0x200);
        assert_eq!(buf, &[0xa5u8; 8]);

        Ok(())
    }

    fn update_memory(&mut self, atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>) -> Result<()> {
        let mem = atomic_mem.memory();
        let region = mem.find_region(GuestAddress(0x100000)).unwrap();
        assert_eq!(region.size(), 0x100000);
        Ok(())
    }

    fn set_slave_req_fd(&mut self, _slave: Slave) {}

    fn queues_per_thread(&self) -> Vec<u64> {
        vec![1, 1]
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        let event_fd = EventFd::new(0).unwrap();

        Some(event_fd)
    }

    fn handle_event(
        &mut self,
        _device_event: u16,
        _evset: EventSet,
        _vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> Result<bool> {
        self.events += 1;

        Ok(false)
    }
}

fn setup_master(path: &Path, barrier: Arc<Barrier>) -> Master {
    barrier.wait();
    let mut master = Master::connect(path, 1).unwrap();
    master.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
    // Wait before issue service requests.
    barrier.wait();

    let features = master.get_features().unwrap();
    let proto = master.get_protocol_features().unwrap();
    master.set_features(features).unwrap();
    master.set_protocol_features(proto).unwrap();
    assert!(proto.contains(VhostUserProtocolFeatures::REPLY_ACK));

    master
}

fn vhost_user_client(path: &Path, barrier: Arc<Barrier>) {
    barrier.wait();
    let mut master = Master::connect(path, 1).unwrap();
    master.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
    // Wait before issue service requests.
    barrier.wait();

    let features = master.get_features().unwrap();
    let proto = master.get_protocol_features().unwrap();
    master.set_features(features).unwrap();
    master.set_protocol_features(proto).unwrap();
    assert!(proto.contains(VhostUserProtocolFeatures::REPLY_ACK));

    let queue_num = master.get_queue_num().unwrap();
    assert_eq!(queue_num, 2);

    master.set_owner().unwrap();
    //master.set_owner().unwrap_err();
    master.reset_owner().unwrap();
    master.reset_owner().unwrap();
    master.set_owner().unwrap();

    master.set_features(features).unwrap();
    master.set_protocol_features(proto).unwrap();
    assert!(proto.contains(VhostUserProtocolFeatures::REPLY_ACK));

    let memfd = nix::sys::memfd::memfd_create(
        &CString::new("test").unwrap(),
        nix::sys::memfd::MemFdCreateFlag::empty(),
    )
    .unwrap();
    let file = unsafe { File::from_raw_fd(memfd) };
    file.set_len(0x100000).unwrap();
    let file_offset = FileOffset::new(file, 0);
    let mem = GuestMemoryMmap::<()>::from_ranges_with_files(&[(
        GuestAddress(0x100000),
        0x100000,
        Some(file_offset),
    )])
    .unwrap();
    let addr = mem.get_host_address(GuestAddress(0x100000)).unwrap() as u64;
    let reg = mem.find_region(GuestAddress(0x100000)).unwrap();
    let fd = reg.file_offset().unwrap();
    let regions = [VhostUserMemoryRegionInfo {
        guest_phys_addr: 0x100000,
        memory_size: 0x100000,
        userspace_addr: addr,
        mmap_offset: 0,
        mmap_handle: fd.file().as_raw_fd(),
    }];
    master.set_mem_table(&regions).unwrap();

    master.set_vring_num(0, 256).unwrap();

    let config = VringConfigData {
        queue_max_size: 256,
        queue_size: 256,
        flags: 0,
        desc_table_addr: addr,
        used_ring_addr: addr + 0x10000,
        avail_ring_addr: addr + 0x20000,
        log_addr: None,
    };
    master.set_vring_addr(0, &config).unwrap();

    let eventfd = EventFd::new(0).unwrap();
    master.set_vring_kick(0, &eventfd).unwrap();
    master.set_vring_call(0, &eventfd).unwrap();
    master.set_vring_err(0, &eventfd).unwrap();
    master.set_vring_enable(0, true).unwrap();

    let buf = [0u8; 8];
    let (_cfg, data) = master
        .get_config(0x200, 8, VhostUserConfigFlags::empty(), &buf)
        .unwrap();
    assert_eq!(&data, &[0xa5u8; 8]);
    master
        .set_config(0x200, VhostUserConfigFlags::empty(), &data)
        .unwrap();

    let (tx, _rx) = UnixStream::pair().unwrap();
    master.set_slave_request_fd(&tx).unwrap();

    let state = master.get_vring_base(0).unwrap();
    master.set_vring_base(0, state as u16).unwrap();

    assert_eq!(master.get_max_mem_slots().unwrap(), 32);
    let region = VhostUserMemoryRegionInfo {
        guest_phys_addr: 0x800000,
        memory_size: 0x100000,
        userspace_addr: addr,
        mmap_offset: 0,
        mmap_handle: fd.file().as_raw_fd(),
    };
    master.add_mem_region(&region).unwrap();
    master.remove_mem_region(&region).unwrap();
}

fn vhost_user_server(cb: fn(&Path, Arc<Barrier>)) {
    let mem = GuestMemoryAtomic::new(GuestMemoryMmap::<()>::new());
    let backend = Arc::new(Mutex::new(MockVhostBackend::new()));
    let mut daemon = VhostUserDaemon::new("test".to_owned(), backend, mem).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let tmpdir = tempfile::tempdir().unwrap();
    let mut path = tmpdir.path().to_path_buf();
    path.push("socket");

    let barrier2 = barrier.clone();
    let path1 = path.clone();
    let thread = thread::spawn(move || cb(&path1, barrier2));

    let listener = Listener::new(&path, false).unwrap();
    barrier.wait();
    daemon.start(listener).unwrap();
    barrier.wait();

    // handle service requests from clients.
    thread.join().unwrap();
}

#[test]
fn test_vhost_user_server() {
    vhost_user_server(vhost_user_client);
}

fn vhost_user_enable(path: &Path, barrier: Arc<Barrier>) {
    let master = setup_master(path, barrier);
    master.set_owner().unwrap();
    master.set_owner().unwrap_err();
}

#[test]
fn test_vhost_user_enable() {
    vhost_user_server(vhost_user_enable);
}

fn vhost_user_set_inflight(path: &Path, barrier: Arc<Barrier>) {
    let mut master = setup_master(path, barrier);
    let eventfd = EventFd::new(0).unwrap();
    // No implementation for inflight_fd yet.
    let inflight = VhostUserInflight {
        mmap_size: 0x100000,
        mmap_offset: 0,
        num_queues: 1,
        queue_size: 256,
    };
    master
        .set_inflight_fd(&inflight, eventfd.as_raw_fd())
        .unwrap_err();
}

#[test]
fn test_vhost_user_set_inflight() {
    vhost_user_server(vhost_user_set_inflight);
}

fn vhost_user_get_inflight(path: &Path, barrier: Arc<Barrier>) {
    let mut master = setup_master(path, barrier);
    // No implementation for inflight_fd yet.
    let inflight = VhostUserInflight {
        mmap_size: 0x100000,
        mmap_offset: 0,
        num_queues: 1,
        queue_size: 256,
    };
    assert!(master.get_inflight_fd(&inflight).is_err());
}

#[test]
fn test_vhost_user_get_inflight() {
    vhost_user_server(vhost_user_get_inflight);
}
