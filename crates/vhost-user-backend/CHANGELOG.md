# Changelog
## [Unreleased]

### Added

### Changed

### Fixed

### Deprecated

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
