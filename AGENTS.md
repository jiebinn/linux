# Linux Kernel Development

## Cursor Cloud specific instructions

This is the Linux kernel source tree (v6.19). The "application" is a monolithic kernel — there are no web services, containers, or microservices.

### Build

- Configure: `make defconfig` (x86_64 default) or `make menuconfig` for interactive config.
- Build: `make -j$(nproc)` — produces `arch/x86/boot/bzImage`.
- Build out-of-tree modules: `make -C /workspace M=/path/to/module modules`.
- After `make mrproper` (full clean), you must re-run `make defconfig` before building.

### Lint

- Style check patches: `git diff HEAD~1 HEAD | ./scripts/checkpatch.pl --no-tree -`
- Style check files: `./scripts/checkpatch.pl -f path/to/file.c`

### Tests

- KUnit tool self-tests: `python3 tools/testing/kunit/kunit_tool_test.py` (75 tests, always works).
- KUnit kernel tests: `python3 tools/testing/kunit/kunit.py run --build_dir=.kunit` — requires a clean source tree (`make mrproper` first). Note: UML-based KUnit execution may fail in container environments; use `--arch=x86_64 --qemu_config` with QEMU if available.
- Kernel selftests: `make -C tools/testing/selftests` (requires additional dependencies per subsystem).

### Gotchas

- The source tree cannot have mixed build artifacts from different architectures. If you switch between x86_64 build and KUnit (ARCH=um), run `make mrproper` in between.
- `scripts/spdxcheck.py` warns about missing `ply` Python module — this is non-critical and does not affect checkpatch results.
- The kernel cannot be "run" in this environment (no bare metal or QEMU). Development workflow is: edit → build → lint → test (KUnit/selftests).
