use std::ffi::CString;
use std::fs::File;
use std::io::Result;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use vhost::vhost_user::message::{
    VhostUserConfigFlags, VhostUserHeaderFlag, VhostUserInflight, VhostUserProtocolFeatures,
};
use vhost::vhost_user::{Backend, Frontend, Listener, VhostUserFrontend};
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
    const SUPPORTED_FEATURES: u64 = 0xffff_ffff_ffff_ffff;

    fn new() -> Self {
        MockVhostBackend {
            events: 0,
            event_idx: false,
            acked_features: 0,
        }
    }
}

impl VhostUserBackendMut for MockVhostBackend {
    type Bitmap = ();
    type Vring = VringRwLock;

    fn num_queues(&self) -> usize {
        2
    }

    fn max_queue_size(&self) -> usize {
        256
    }

    fn features(&self) -> u64 {
        Self::SUPPORTED_FEATURES
    }

    fn acked_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::all()
    }

    fn reset_device(&mut self) {
        self.events = 0;
        self.event_idx = false;
        self.acked_features = 0;
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

    fn set_backend_req_fd(&mut self, _backend: Backend) {}

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
    ) -> Result<()> {
        self.events += 1;

        Ok(())
    }
}

fn setup_frontend(path: &Path, barrier: Arc<Barrier>) -> Frontend {
    barrier.wait();
    let mut frontend = Frontend::connect(path, 1).unwrap();
    frontend.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
    // Wait before issue service requests.
    barrier.wait();

    let features = frontend.get_features().unwrap();
    let proto = frontend.get_protocol_features().unwrap();
    frontend.set_features(features).unwrap();
    frontend.set_protocol_features(proto).unwrap();
    assert!(proto.contains(VhostUserProtocolFeatures::REPLY_ACK));

    frontend
}

fn vhost_user_client(path: &Path, barrier: Arc<Barrier>) {
    barrier.wait();
    let mut frontend = Frontend::connect(path, 1).unwrap();
    frontend.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
    // Wait before issue service requests.
    barrier.wait();

    let features = frontend.get_features().unwrap();
    let proto = frontend.get_protocol_features().unwrap();
    frontend.set_features(features).unwrap();
    frontend.set_protocol_features(proto).unwrap();
    assert!(proto.contains(VhostUserProtocolFeatures::REPLY_ACK));

    let queue_num = frontend.get_queue_num().unwrap();
    assert_eq!(queue_num, 2);

    frontend.set_owner().unwrap();
    //frontend.set_owner().unwrap_err();
    frontend.reset_owner().unwrap();
    frontend.reset_owner().unwrap();
    frontend.set_owner().unwrap();

    frontend.set_features(features).unwrap();
    frontend.set_protocol_features(proto).unwrap();
    assert!(proto.contains(VhostUserProtocolFeatures::REPLY_ACK));

    let memfd = nix::sys::memfd::memfd_create(
        &CString::new("test").unwrap(),
        nix::sys::memfd::MemFdCreateFlag::empty(),
    )
    .unwrap();
    let file = File::from(memfd);
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
    let regions = [VhostUserMemoryRegionInfo::new(
        0x100000,
        0x100000,
        addr,
        0,
        fd.file().as_raw_fd(),
    )];
    frontend.set_mem_table(&regions).unwrap();

    frontend.set_vring_num(0, 256).unwrap();

    let config = VringConfigData {
        queue_max_size: 256,
        queue_size: 256,
        flags: 0,
        desc_table_addr: addr,
        used_ring_addr: addr + 0x10000,
        avail_ring_addr: addr + 0x20000,
        log_addr: None,
    };
    frontend.set_vring_addr(0, &config).unwrap();

    let eventfd = EventFd::new(0).unwrap();
    frontend.set_vring_kick(0, &eventfd).unwrap();
    frontend.set_vring_call(0, &eventfd).unwrap();
    frontend.set_vring_err(0, &eventfd).unwrap();
    frontend.set_vring_enable(0, true).unwrap();

    let buf = [0u8; 8];
    let (_cfg, data) = frontend
        .get_config(0x200, 8, VhostUserConfigFlags::empty(), &buf)
        .unwrap();
    assert_eq!(&data, &[0xa5u8; 8]);
    frontend
        .set_config(0x200, VhostUserConfigFlags::empty(), &data)
        .unwrap();

    let (tx, _rx) = UnixStream::pair().unwrap();
    frontend.set_backend_request_fd(&tx).unwrap();

    let state = frontend.get_vring_base(0).unwrap();
    frontend.set_vring_base(0, state as u16).unwrap();

    assert_eq!(frontend.get_max_mem_slots().unwrap(), 509);
    let region = VhostUserMemoryRegionInfo::new(0x800000, 0x100000, addr, 0, fd.file().as_raw_fd());
    frontend.add_mem_region(&region).unwrap();
    frontend.remove_mem_region(&region).unwrap();
}

/// Provide a vhost-user back-end for front-end testing.
///
/// Set up a `MockVhostBackend` vhost-user back-end and run `cb` in a thread, passing the
/// vhost-user socket's path and a barrier to await request processing.  `cb` is supposed to run
/// the front-end tests.
///
/// After request processing has begun, run `server_fn`, passing both a reference to the back-end
/// and the same barrier as given to `cb`.  `server_fn` may perform additional back-end tests while
/// `cb` is still run in its thread.
///
/// After `server_fn` is done, await `cb` (joining its thread), and return.
fn vhost_user_server_with_fn<F: FnOnce(Arc<Mutex<MockVhostBackend>>, Arc<Barrier>)>(
    cb: fn(&Path, Arc<Barrier>),
    server_fn: F,
) {
    let mem = GuestMemoryAtomic::new(GuestMemoryMmap::<()>::new());
    let backend = Arc::new(Mutex::new(MockVhostBackend::new()));
    let mut daemon = VhostUserDaemon::new("test".to_owned(), backend.clone(), mem).unwrap();

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

    server_fn(backend, barrier);

    // handle service requests from clients.
    thread.join().unwrap();
}

fn vhost_user_server(cb: fn(&Path, Arc<Barrier>)) {
    vhost_user_server_with_fn(cb, |_, _| {})
}

#[test]
fn test_vhost_user_server() {
    vhost_user_server(vhost_user_client);
}

fn vhost_user_enable(path: &Path, barrier: Arc<Barrier>) {
    let frontend = setup_frontend(path, barrier);
    frontend.set_owner().unwrap();
    frontend.set_owner().unwrap_err();
}

#[test]
fn test_vhost_user_enable() {
    vhost_user_server(vhost_user_enable);
}

fn vhost_user_set_inflight(path: &Path, barrier: Arc<Barrier>) {
    let mut frontend = setup_frontend(path, barrier);
    let eventfd = EventFd::new(0).unwrap();
    // No implementation for inflight_fd yet.
    let inflight = VhostUserInflight {
        mmap_size: 0x100000,
        mmap_offset: 0,
        num_queues: 1,
        queue_size: 256,
    };
    frontend
        .set_inflight_fd(&inflight, eventfd.as_raw_fd())
        .unwrap_err();
}

#[test]
fn test_vhost_user_set_inflight() {
    vhost_user_server(vhost_user_set_inflight);
}

fn vhost_user_get_inflight(path: &Path, barrier: Arc<Barrier>) {
    let mut frontend = setup_frontend(path, barrier);
    // No implementation for inflight_fd yet.
    let inflight = VhostUserInflight {
        mmap_size: 0x100000,
        mmap_offset: 0,
        num_queues: 1,
        queue_size: 256,
    };
    assert!(frontend.get_inflight_fd(&inflight).is_err());
}

#[test]
fn test_vhost_user_get_inflight() {
    vhost_user_server(vhost_user_get_inflight);
}

#[cfg(feature = "postcopy")]
fn vhost_user_postcopy_advise(path: &Path, barrier: Arc<Barrier>) {
    let mut frontend = setup_frontend(path, barrier);
    let _uffd_file = frontend.postcopy_advise().unwrap();
}

#[cfg(feature = "postcopy")]
fn vhost_user_postcopy_listen(path: &Path, barrier: Arc<Barrier>) {
    let mut frontend = setup_frontend(path, barrier);
    let _uffd_file = frontend.postcopy_advise().unwrap();
    frontend.postcopy_listen().unwrap();
}

#[cfg(feature = "postcopy")]
fn vhost_user_postcopy_end(path: &Path, barrier: Arc<Barrier>) {
    let mut frontend = setup_frontend(path, barrier);
    let _uffd_file = frontend.postcopy_advise().unwrap();
    frontend.postcopy_listen().unwrap();
    frontend.postcopy_end().unwrap();
}

// These tests need an access to the `/dev/userfaultfd`
// in order to pass.
#[cfg(feature = "postcopy")]
#[test]
fn test_vhost_user_postcopy() {
    vhost_user_server(vhost_user_postcopy_advise);
    vhost_user_server(vhost_user_postcopy_listen);
    vhost_user_server(vhost_user_postcopy_end);
}

fn vhost_user_reset_device(path: &Path, barrier: Arc<Barrier>) {
    let mut frontend = setup_frontend(path, barrier.clone());

    // Signal that we are about to reset
    barrier.wait();
    // Wait until server has checked non-reset state
    barrier.wait();

    frontend.reset_device().unwrap();

    // Signal reset is done
    barrier.wait();
}

#[test]
fn test_vhost_user_reset_device() {
    vhost_user_server_with_fn(vhost_user_reset_device, |backend, barrier| {
        // Wait until `vhost_user_reset_device()` is before reset
        barrier.wait();
        // Check non-reset state
        assert!(backend.lock().unwrap().acked_features == MockVhostBackend::SUPPORTED_FEATURES);
        // Set up some arbitrary internal state
        backend.lock().unwrap().events = 42;

        // Allow reset
        barrier.wait();
        // Wait for reset to be done
        barrier.wait();

        // Check reset state
        assert!(backend.lock().unwrap().acked_features == 0);
        assert!(backend.lock().unwrap().events == 0);
    });
}
