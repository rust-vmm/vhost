# vhost-user-backend

## Design

The `vhost-user-backend` crate provides a framework to implement `vhost-user` backend services,
which includes following external public APIs:
- A daemon control object (`VhostUserDaemon`) to start and stop the service daemon.
- A vhost-user backend trait (`VhostUserBackendMut`) to handle vhost-user control messages and virtio
  messages.
- A vring access trait (`VringT`) to access virtio queues, and three implementations of the trait:
  `VringState`, `VringMutex` and `VringRwLock`.

## Usage
The `vhost-user-backend` crate provides a framework to implement vhost-user backend services. The main interface provided by `vhost-user-backend` library is the `struct VhostUserDaemon`:
```rust
pub struct VhostUserDaemon<S, V, B = ()>
where
    S: VhostUserBackend<V, B>,
    V: VringT<GM<B>> + Clone + Send + Sync + 'static,
    B: Bitmap + 'static,
{
    pub fn new(name: String, backend: S, atomic_mem: GuestMemoryAtomic<GuestMemoryMmap<B>>) -> Result<Self>;
    pub fn start(&mut self, listener: Listener) -> Result<()>;
    pub fn wait(&mut self) -> Result<()>;
    pub fn get_epoll_handlers(&self) -> Vec<Arc<VringEpollHandler<S, V, B>>>;
}
```

### Create a `VhostUserDaemon` Instance
The `VhostUserDaemon::new()` creates an instance of `VhostUserDaemon` object. The client needs to
pass in an `VhostUserBackend` object, which will be used to configure the `VhostUserDaemon`
instance, handle control messages from the vhost-user master and handle virtio requests from
virtio queues. A group of working threads will be created to handle virtio requests from configured
virtio queues.

### Start the `VhostUserDaemon`
The `VhostUserDaemon::start()` method waits for an incoming connection from the vhost-user masters
on the `listener`. Once a connection is ready, a main thread will be created to handle vhost-user
messages from the vhost-user master.

### Stop the `VhostUserDaemon`
The `VhostUserDaemon::stop()` method waits for the main thread to exit. An exit event must be sent
to the main thread by writing to the `exit_event` EventFd before waiting for it to exit.

### Threading Model
The main thread and virtio queue working threads will concurrently access the underlying virtio
queues, so all virtio queue in multi-threading model. But the main thread only accesses virtio
queues for configuration, so client could adopt locking policies to optimize for the virtio queue
working threads.

## Example
Example code to handle virtio messages from a virtio queue:
```rust
impl VhostUserBackendMut for VhostUserService {
    fn process_queue(&mut self, vring: &VringMutex) -> Result<bool> {
        let mut used_any = false;
        let mem = match &self.mem {
            Some(m) => m.memory(),
            None => return Err(Error::NoMemoryConfigured),
        };

        let mut vring_state = vring.get_mut();

        while let Some(avail_desc) = vring_state
            .get_queue_mut()
            .iter()
            .map_err(|_| Error::IterateQueue)?
            .next()
        {
            // Process the request...

            if self.event_idx {
                if vring_state.add_used(head_index, 0).is_err() {
                    warn!("Couldn't return used descriptors to the ring");
                }

                match vring_state.needs_notification() {
                    Err(_) => {
                        warn!("Couldn't check if queue needs to be notified");
                        vring_state.signal_used_queue().unwrap();
                    }
                    Ok(needs_notification) => {
                        if needs_notification {
                            vring_state.signal_used_queue().unwrap();
                        }
                    }
                }
            } else {
                if vring_state.add_used(head_index, 0).is_err() {
                    warn!("Couldn't return used descriptors to the ring");
                }
                vring_state.signal_used_queue().unwrap();
            }
        }

        Ok(used_any)
    }
}
```

## License

This project is licensed under

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
