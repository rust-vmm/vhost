# buildkite custom pipelines

This folder contains the custom pipelines for this repository.

If we add a new pipeline we need to enable it in
https://buildkite.com/rust-vmm/vhost-ci/steps

Custom pipelines currently defined are:
- `custom-tests.json`
  Custom tests to enable only certain features.

- `rust-vmm-ci-tests.json`
  This is based on `rust-vmm-ci/.buildkite/test_description.json`.
  We can't run rust-vmm-ci tests because they enable all the features with
  `--all-features` and our crates have features that may not be compatible with
  others (e.g. `xen`). Waiting to solve this problem in rust-vmm-ci (see
  https://github.com/rust-vmm/rust-vmm-ci/issues/152), we use a custom
  pipeline based on that but that does not use `--all-features`.
