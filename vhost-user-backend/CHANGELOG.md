# Changelog
## [Unreleased]

### Added

### Changed

### Fixed

### Deprecated

## v0.11.0

### Added
- [[#173]](https://github.com/rust-vmm/vhost/pull/173) vhost-user-backend: Added convenience function `serve`

### Changed
- [[#187]](https://github.com/rust-vmm/vhost/pull/187) Clean master slave
  - Replaced master/slave with frontend/backend in the codebase and public API.
- [[#192]](https://github.com/rust-vmm/vhost/pull/192) vhost-user-backend: remove return value from handle_event
- [[#155]](https://github.com/rust-vmm/vhost/pull/155) Converted generic type
  parameters of VhostUserBackend into associated types.
- [[#116]](https://github.com/rust-vmm/vhost/pull/116) Upgrade to 2021 edition

## v0.10.1

### Fixed
- [[#180]](https://github.com/rust-vmm/vhost/pull/180) vhost-user-backend: fetch 'used' index from guest

## v0.10.0

### Added
- [[#169]](https://github.com/rust-vmm/vhost/pull/160) vhost-user-backend: Add support for Xen memory mappings

### Fixed
- [[#161]](https://github.com/rust-vmm/vhost/pull/161) get_vring_base should not reset the queue

## v0.9.0

### Added
- [[#138]](https://github.com/rust-vmm/vhost/pull/138): vhost-user-backend: add repository metadata

### Changed
- Updated dependency virtio-bindings 0.1.0 -> 0.2.0
- Updated dependency virtio-queue 0.7.0 -> 0.8.0
- Updated dependency vm-memory 0.10.0 -> 0.11.0

### Fixed
- [[#154]](https://github.com/rust-vmm/vhost/pull/154): Fix return value of GET_VRING_BASE message
- [[#142]](https://github.com/rust-vmm/vhost/pull/142): vhost_user: Slave requests aren't only FS specific

## v0.8.0

### Added
- [[#120]](https://github.com/rust-vmm/vhost/pull/120): vhost_kern: vdpa: Add missing ioctls

### Changed
- Updated dependency vhost 0.5 -> 0.6
- Updated dependency virtio-queue 0.6 -> 0.7.0
- Updated depepdency vm-memory 0.9 to 0.10.0
- Updated depepdency vmm-sys-util 0.10 to 0.11.0

## v0.7.0

### Changed

- Started using caret dependencies
- Updated dependency nix 0.24 -> 0.25
- Updated depepdency log 0.4.6 -> 0.4.17
- Updated dependency vhost 0.4 -> 0.5
- Updated dependency virtio-queue 0.5.0 -> 0.6
- Updated dependency vm-memory 0.7 -> 0.9

## v0.6.0

### Changed

- Moved to rust-vmm/virtio-queue v0.5.0

### Fixed

- Fixed vring initialization logic

## v0.5.1

### Changed
- Moved to rust-vmm/vmm-sys-util 0.10.0

## v0.5.0

### Changed

- Moved to rust-vmm/virtio-queue v0.4.0

## v0.4.0

### Changed

- Moved to rust-vmm/virtio-queue v0.3.0
- Relaxed rust-vmm/vm-memory dependency to require ">=0.7"

## v0.3.0

### Changed

- Moved to rust-vmm/vhost v0.4.0

## v0.2.0

### Added

- Ability to run the daemon as a client
- VringEpollHandler implements AsRawFd

## v0.1.0

First release
