# Changelog
## [Unreleased]

### Added
- [[#268]](https://github.com/rust-vmm/vhost/pull/268) Add support for `VHOST_USER_GET_SHARED_OBJECT`

### Changed

### Deprecated

### Fixed

## [0.12.0]

### Added
- [[#241]](https://github.com/rust-vmm/vhost/pull/241) Add shared objects support
- [[#239]](https://github.com/rust-vmm/vhost/pull/239) Add support for `VHOST_USER_GPU_SET_SOCKET`

### Changed
- [[#257]](https://github.com/rust-vmm/vhost/pull/257) Update vm-memory from 0.14.0 to 0.15.0.
- [[#243]](https://github.com/rust-vmm/vhost/pull/243) Ignore unknown bits in `VHOST_USER_GET_PROTOCOL_FEATURES` response.

### Remove
- [[#246]](https://github.com/rust-vmm/vhost/pull/246) Remove support for FS_* requests

## [0.11.0]

### Added
- [[#203]](https://github.com/rust-vmm/vhost/pull/203) Add back-end's internal state migration support
- [[#218]](https://github.com/rust-vmm/vhost/pull/218) Adding POSTCOPY support
- [[#206]](https://github.com/rust-vmm/vhost/pull/206) Add bitmap support for tracking dirty pages during migration

## [0.10.0]

### Changed
- [[#219]](https://github.com/rust-vmm/vhost/pull/219) Update vmm-sys-util dependency to 0.12.1.

### Remove
- [[#202](https://github.com/rust-vmm/vhost/pull/202)] Do not expose for internal-usage-only `NOOP` and `MAX_CMD` requests.
- [[#205](https://github.com/rust-vmm/vhost/pull/205)] Remove some commented out code.

### Fixed
- [[#208](https://github.com/rust-vmm/vhost/pull/208)] Fix various message structs being `repr(Rust)` instead of `repr(C)`.

## [0.9.0]

### Changed
- [[#187]](https://github.com/rust-vmm/vhost/pull/187) Clean master slave
  - Replaced master/slave with frontend/backend in the codebase and public API.
  - Replaced master/slave with frontend/backend in the crate features.
- Updated dependency bitflags from 1.0 to 2.4
- [[#116]](https://github.com/rust-vmm/vhost/pull/116) Upgrade to 2021 edition

### Fixed
- [[#184]](https://github.com/rust-vmm/vhost/pull/184) Safety fixes
- [[#186]](https://github.com/rust-vmm/vhost/pull/186) vhost: Fix clippy warnings.

## [0.8.1]

### Fixed
- [[#175]](https://github.com/rust-vmm/vhost/pull/175) vhost: Always enable vm-memory/backend-mmap

## [0.8.0]

### Added
- [[#169]](https://github.com/rust-vmm/vhost/pull/160) vhost: Add xen memory mapping support

### Fixed
- [[#165]](https://github.com/rust-vmm/vhost/pull/165) vhost: vdpa: Provide custom set_vring_addr() implementation
- [[#172]](https://github.com/rust-vmm/vhost/pull/172) Vhost user fix

## [0.7.0]

### Added
- [[#137]](https://github.com/rust-vmm/vhost/pull/137) vhost_user: add Error::Disconnected

### Changed
- Updated dependency vm-memory 0.10.0 to 0.11.0

### Fixed
- [[#135]](https://github.com/rust-vmm/vhost/pull/135) vhost_user: fix UB on invalid master request
- [[#136]](https://github.com/rust-vmm/vhost/pull/136) vhost_user: fix unsound send_message functions
- [[#153]](https://github.com/rust-vmm/vhost/pull/153) Fix set_vring_addr issues

### Deprecated

## [0.6.0]

### Upgraded
- vm-memory from 0.9 to 0.10
- vmm-sys-util from 0.10 to 0.11

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
