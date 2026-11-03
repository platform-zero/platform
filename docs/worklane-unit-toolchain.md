# Worklane unit-only validation in the v3 workspace

Validation runs outside a Herdr pane. Do not run Worklane's legacy remote release-check/lab-acceptance scripts against shared lab hosts for this v3 deployment.

The existing Rust 1.88.0 toolchain and cached Cargo registry were located under `/home/dev`, owned by `software_lab`. They were **read/copied only** into dedicated v3 directories; no files, permissions, configuration or caches in that account were modified. All build outputs, Cargo writes and temporary files use the paths below.

- Toolchain: `/mnt/media/p0-v3/toolchains/1.88.0-x86_64-unknown-linux-gnu`
- Cargo cache: `/mnt/media/p0-v3/cache/cargo-worklane`
- Coverage helper: Cargo LLVM Cov 0.9.1, copied into that cache's `bin/`
- Unit-only target: `/mnt/media/p0-v3/cache/worklane-unit-target`
- Temporary directory: `/mnt/media/p0-v3/cache/worklane-tmp`
- Compiler: `rustc 1.88.0 (6b00bc388 2025-06-23)`

Copied executable SHA-256 hashes:

```
cargo          de9be4299324f5c1f5d12103792d35e8b8ab195df3a374194b8ffc33562c7e3d
rustc          ac3e92e45fe15c789939deedf7614f4f9578cc9609cb9ead39c9b1808a316c5b
cargo-llvm-cov 108ee560433a219c05d764364254509676201074a830b4422dee72301faba7ab
```

Reproduce from the workspace root:

```sh
export PATH=/mnt/media/p0-v3/toolchains/1.88.0-x86_64-unknown-linux-gnu/bin:/mnt/media/p0-v3/cache/cargo-worklane/bin:$PATH
export CARGO_HOME=/mnt/media/p0-v3/cache/cargo-worklane
export CARGO_TARGET_DIR=/mnt/media/p0-v3/cache/worklane-unit-target
export TMPDIR=/mnt/media/p0-v3/cache/worklane-tmp
cd worklane
cargo llvm-cov --workspace --lib --bins --offline --fail-under-lines 90 -- --test-threads=1
```

Executed result: **142 unit tests passed**, **90.31% repository line coverage** (11,842 / 13,112 lines). `--lib --bins` excludes separate integration test targets. This does not constitute Worklane/TUIOS/Pi live acceptance, a release publication gate or permission to refresh `dist/` by bypassing Worklane's release process.
