# Help wanted

UBDA is open to contributions. Below is the hardening work that would make it stronger, roughly in order of impact. Pick anything, comment on (or open) an issue so others know you are on it, and see [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

Found a vulnerability instead? Please report it privately, see [SECURITY.md](SECURITY.md).


### Replace unmaintained crates

**Medium.** `cargo audit` flags `bincode` (RUSTSEC-2025-0141) and `chrono` (RUSTSEC-2026-0543) as unmaintained. Move to maintained alternatives such as `postcard` and `time` or `jiff`.

### cargo-deny in CI

**Medium.** Fail CI on new advisories, disallowed licenses and duplicate dependencies.

### Fuzz the capability checks

**Medium.** Fuzz targets that try to obtain access without the right capability.
