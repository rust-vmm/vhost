# Changelog
## [Unreleased]

### Added
- [[#268]](https://github.com/rust-vmm/vhost/pull/268) Add support for `VHOST_USER_GET_SHARED_OBJECT`

### Changed

### Deprecated

### Fixed

## v0.16.0

### Added
- [[#241]](https://github.com/rust-vmm/vhost/pull/241) Add shared objects support
- [[#239]](https://github.com/rust-vmm/vhost/pull/239) Add support for `VHOST_USER_GPU_SET_SOCKET`

### Changed
- [[#257]](https://github.com/rust-vmm/vhost/pull/257) Update virtio-queue version from 0.12.0 to 0.13.0 and vm-memory from 0.14.0 to 0.15.0.
- [[#240]](https://github.com/rust-vmm/vhost/pull/240) Move the set of event_idx property from set_vring_base callback to set_features one

## v0.15.0

### Changed
- [[#237]](https://github.com/rust-vmm/vhost/pull/237) Update virtio-queue dependency to 0.12.0

## v0.14.0

### Added
- [[#203]](https://github.com/rust-vmm/vhost/pull/203) Add back-end's internal state migration support
- [[#218]](https://github.com/rust-vmm/vhost/pull/218) Adding POSTCOPY support
- [[#206]](https://github.com/rust-vmm/vhost/pull/206) Add bitmap support for tracking dirty pages during migration

## v0.13.1

### Fixed

- [[#227]](https://github.com/rust-vmm/vhost/pull/227) vhost-user-backend: Fix SET_VRING_KICK should not disable the vring

## v0.13.0

### Changed
- [[#224]](https://github.com/rust-vmm/vhost/pull/224) vhost-user-backend: bump up MAX_MEM_SLOTS to 509

## v0.12.0

### Fixed
- [[#210](https://github.com/rust-vmm/vhost/pull/210)] Enable all vrings upon receipt of `VHOST_USER_SET_FEATURES`
  message.
- [[#212](https://github.com/rust-vmm/vhost/pull/212)] Validate queue index in `VhostUserHandler::set_vring_base`
  to avoid potential out-of-bounds panic.

### Changed
- [[#214](https://github.com/rust-vmm/vhost/pull/214)] Avoid indexing the same Vec multiple times by locally caching the
  result of `Vec:get`.
- [[#219]](https://github.com/rust-vmm/vhost/pull/219) Update vmm-sys-util dependency to 0.12.1 and vm-memory dependency to 0.14.0.

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
