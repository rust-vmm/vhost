# buildkite custom pipelines

This folder contains the custom pipelines for this repository.

If we add a new pipeline we need to enable it in
https://buildkite.com/rust-vmm/vhost-ci/steps

Custom pipelines currently defined are:
- `custom-tests.json`
  Custom tests to enable only certain features.
