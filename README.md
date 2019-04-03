# vHost
A crate to implement the vHost ioctl interfaces and vHost-user protocol.

## vHost Ioctl Interfaces
The vhost drivers in Linux provide in-kernel virtio device emulation. Normally the hypervisor userspace process emulates I/O accesses from the guest. Vhost puts virtio emulation code into the kernel, taking hypervisor userspace out of the picture. This allows device emulation code to directly call into kernel subsystems instead of performing system calls from userspace. The hypervisor relies on ioctl based interfaces to control those in-kernel vhost drivers, such as vhost-net, vhost-scsi and vhost-vsock etc.

## vHost-user Protocol
The vHost-user protocol is aiming to complement the ioctl interface used to control the vhost implementation in the Linux kernel. It implements the control plane needed to establish virtqueue sharing with a user space process on the same host. It uses communication over a Unix domain socket to share file descriptors in the ancillary data of the message.

The protocol defines two sides of the communication, master and slave. Master is the application that shares its virtqueues, slave is the consumer of the virtqueues. Master and slave can be either a client (i.e. connecting) or server (listening) in the socket communication.
