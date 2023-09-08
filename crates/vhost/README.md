# vHost
A pure rust library for vDPA, vhost and vhost-user.

The `vhost` crate aims to help implementing dataplane for virtio backend drivers. It supports three different types of dataplane drivers:
- vhost: the dataplane is implemented by linux kernel
- vhost-user: the dataplane is implemented by dedicated vhost-user servers
- vDPA(vhost DataPath Accelerator): the dataplane is implemented by hardwares

The main relationship among Traits and Structs exported by the `vhost` crate is as below:

![vhost Architecture](/docs/vhost_architecture.png)
## Kernel-based vHost Backend Drivers
The vhost drivers in Linux provide in-kernel virtio device emulation. Normally
the hypervisor userspace process emulates I/O accesses from the guest.
Vhost puts virtio emulation code into the kernel, taking hypervisor userspace
out of the picture. This allows device emulation code to directly call into
kernel subsystems instead of performing system calls from userspace.
The hypervisor relies on ioctl based interfaces to control those in-kernel
vhost drivers, such as vhost-net, vhost-scsi and vhost-vsock etc.

## vHost-user Backend Drivers
The [vhost-user protocol](https://qemu.readthedocs.io/en/latest/interop/vhost-user.html#communication) aims to implement vhost backend drivers in
userspace, which complements the ioctl interface used to control the vhost
implementation in the Linux kernel. It implements the control plane needed
to establish virtqueue sharing with a user space process on the same host.
It uses communication over a Unix domain socket to share file descriptors in
the ancillary data of the message.

The protocol defines two sides of the communication, frontend and backend.
Frontend is the application that shares its virtqueues, backend is the consumer
of the virtqueues. Frontend and backend can be either a client (i.e. connecting)
or server (listening) in the socket communication.

## Xen support

Supporting Xen requires special handling while mapping the guest memory. The
`vm-memory` crate implements xen memory mapping support via a separate feature
`xen`, and this crate uses the same feature name to enable Xen support.

Also, for xen mappings, the memory regions passed by the frontend contains few
extra fields as described in the vhost-user protocol documentation.

It was decided by the `rust-vmm` maintainers to keep the interface simple and
build the crate for either standard Unix memory mapping or Xen, and not both.
