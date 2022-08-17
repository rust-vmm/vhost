# Changelog
## [Unreleased]

### Added

### Changed

### Fixed

### Deprecated


## [0.5.0]

### Changed
- [[#113]](https://github.com/rust-vmm/vhost/pull/113) Improved error messages.
- [[#115]](https://github.com/rust-vmm/vhost/pull/115) Use caret requirements for dependencies.

## [v0.4.0]

### Added
- [[#109]](https://github.com/rust-vmm/vhost/pull/109) vhost_kern: vdpa: Override the implementation of valid()

### Fixed
- [[#102]](https://github.com/rust-vmm/vhost/pull/102) Fix warnings and update test coverage
- [[#104]](https://github.com/rust-vmm/vhost/pull/104) fix CODEOWNERS file
- [[#107]](https://github.com/rust-vmm/vhost/pull/107) vhost_kern/vdpa: fix get_iova_range()

## [v0.3.0]

### Added
- [[#92]](https://github.com/rust-vmm/vhost/pull/92) implement vhost_net backend
- [[#97]](https://github.com/rust-vmm/vhost/pull/97) add method to restore Vdpa objects

### Changed
- [[#90]](https://github.com/rust-vmm/vhost/pull/90) add vdpa and vhost-vdpa simple description
- [[#90]](https://github.com/rust-vmm/vhost/pull/90) use vmm_sys_util::fam for vhost_vdpa_config
- [[#95]](https://github.com/rust-vmm/vhost/pull/95) relax vm-memory dependency
- [[#98]](https://github.com/rust-vmm/vhost/pull/98) generate documentation for doc.rs with all features enabled

### Fixed
- [[#98]](https://github.com/rust-vmm/vhost/pull/98) fix a bug in SlaveReqHandler::set_config() which passes wrong configuration data to backend

### Deprecated
- [[#90]](https://github.com/rust-vmm/vhost/pull/90) remove parse_iotlb_msg

## [v0.2.0]

### Added

- [[#74]](https://github.com/rust-vmm/vhost/pull/74) Implement FromRawFd for Listener

- [[#33]](https://github.com/rust-vmm/vhost/pull/33) Add vhost-vDPA support (in-kernel)

### Changed

- [[#68]](https://github.com/rust-vmm/vhost/pull/68) Enforce ByteValued for received structs

## [v0.1.0]

First release
