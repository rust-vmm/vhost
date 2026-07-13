// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

fn main() {
    println!("cargo::rerun-if-env-changed=DOCS_RS");
    if std::env::var("DOCS_RS").is_ok() {
        println!("cargo::rustc-cfg=RUSTDOC_disable_feature_compat_errors");
    }
}
