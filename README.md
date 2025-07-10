# kspy

## Introduction

kspy is an eBPF-based kernel monitoring and detection tool developed using the **aya** framework. It intercepts the Linux kernel's `vfs_write` system call in real-time to capture file write activities and reports the related data to a user-space server for analysis and processing. This project can be used to detect malicious file writes such as WebShells and respond automatically based on detection results.

### Key Technologies

* **eBPF**: Utilizes eBPF technology to efficiently intercept and process system call events in kernel space.
* **aya**: Built with the Rust ecosystem's aya framework for writing, loading, and interacting with eBPF programs in user space.
* **vfs\_write interception**: Attaches a KProbe to `vfs_write` to capture all file write operations.
* **User-space communication**: Kernel events are reported to user space via a perf buffer. The user space can optionally enable the `webshell-detect` feature to send captured file contents to a remote server for intelligent detection.

### Runtime Environment & Compatibility

* Supports **Linux** only, preferably kernel version 5.x or higher.
* Requires using [aya-tool](https://aya-rs.dev/book/aya/aya-tool/) to **generate Linux kernel filesystem related data structure bindings for the current environment, replacing the content of `kspy-ebpf/src/vmlinux.rs`**. The generated bindings may contain field names conflicting with Rust reserved keywords and need to be manually renamed to avoid compilation errors.

```bash
aya-tool generate file > vmlinux.rs
```

### Usage & Features

* **Make sure the `kspy-ebpf/src/vmlinux.rs` file is generated as described above.**
* Supports capturing file write events and path filtering by default.
* To enable WebShell detection, compile with the `--features webshell-detect` flag and **ensure the user space can access the detection server** (the URL is defined as `GRADIO_SERVER_PREDICT_URL` in `kspy-ebpf/src/client.rs`). The detection service is based on a Gradio-powered model frontend implemented in the [webshell\_bert\_detect](https://github.com/goodpeanuts/webshell_bert_detect) project (`server.py`), which you need to deploy yourself or replace with another available detection service.
* Running the eBPF program requires root privileges. For logging or debugging, set environment variable `RUST_LOG=info`.

```bash
cargo build --release --features webshell-detect \
&& sudo RUST_LOG=info ./target/release/kspy
```

### Project Structure

* `kspy-ebpf/`: eBPF kernel module responsible for intercepting system calls and reporting events.
* `kspy/`: User-space main program responsible for loading eBPF, processing events, and communicating with the detection server.
* `kspy-common/`: Shared data structure definitions between kernel and user space.
* `php_wbs/`: Target environment including a PHP website and Docker configuration for WebShell offense and defense experiments.

### Target Environment (php\_wbs)

The `php_wbs` directory provides a Docker-based PHP-Apache target environment including a file upload page (`upload.php`) to simulate WebShell attack and defense scenarios. Before use, grant the PHP process necessary file system permissions. Start the environment with:

```shell
cd php_wbs
docker-compose up -d
```

[dataset/upload.py](https://github.com/goodpeanuts/webshell_bert_detect/blob/master/dataset/upload.py) in [webshell_bert_detect](https://github.com/goodpeanuts/webshell_bert_detect) provide a Python script to upload files to the target environment for testing. You can use it to upload files and test the detection capabilities of kspy.

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package kspy --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/kspy` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, kspy is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
