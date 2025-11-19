# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0](https://github.com/pando85/passless/tree/v0.1.0) - 2025-11-19

### Added

- tpm: Implement indexing and lazy loading for credentials ([bbdef79](https://github.com/pando85/passless/commit/bbdef79c7210db5e96bf322b5efa6f505f4e3766))
- Add password-store initialization with desktop notifications ([06aeeea](https://github.com/pando85/passless/commit/06aeeead7569f9ec44996b360777af3152c454a9))
- Add TPM backend implementation ([bc0deff](https://github.com/pando85/passless/commit/bc0deff91b3ce81a931b45ab74948d902e9b6c15))

### Fixed

- ci: Add `libtss2-dev` dependency to actions workflows ([a93b3ab](https://github.com/pando85/passless/commit/a93b3abd0b720bc600218d0109d5ae154c245d3a))
- Resolve clippy warnings and compilation errors in E2E tests ([e40e082](https://github.com/pando85/passless/commit/e40e08234fd56dac80398501a2686b5ddd6198c2))
- Prevent swtpm zombie processes in E2E tests and use TCP connection ([d9a51c3](https://github.com/pando85/passless/commit/d9a51c3706a894b6292d3def18ab1612e0529691))

### Documentation

- Update README ([7b3b5e6](https://github.com/pando85/passless/commit/7b3b5e678b0044425c5e149744dd7c21fe0e2086))

### Refactor

- Extract shared indexing and caching to common module ([59d34ef](https://github.com/pando85/passless/commit/59d34ef981333a58315c928a2107f2dc0718a0e1))
- Remove unused SharedHarness and apply cargo fmt ([21ea2ef](https://github.com/pando85/passless/commit/21ea2ef6c6f420186dac2bc728de66018904f7e2))

### Testing

- Refactor E2E tests with programmatic backend management ([b9c2792](https://github.com/pando85/passless/commit/b9c2792898b0dc69a1ed55be05c2c0b15501e2ca))

## [v0.0.5](https://github.com/pando85/passless/tree/v0.0.5) - 2025-11-17

### Added

- Add capability setup for memory locking ([c540805](https://github.com/pando85/passless/commit/c540805d450ca2a5a0ab10d875b5330c677e202b))
- Add configurable user verification for registration and authentication ([1a5402e](https://github.com/pando85/passless/commit/1a5402ef4cd342982eeeec0e23e1340dac144fba))

### Documentation

- Add create config to post install instructions ([696dfc2](https://github.com/pando85/passless/commit/696dfc27df38b7d7e18ef468c18b31473f77b685))
- Add security disclaimer ([790e043](https://github.com/pando85/passless/commit/790e043f16cbd1cd1d1a6f49bd5be916c498d3dc))

### Build

- ci: Add pasless.install to AUR publish action ([3c319ca](https://github.com/pando85/passless/commit/3c319ca6889551be1873ae1af980cc5a04169aac))
- systemd: Tune systemd service hardering ([37bf3fe](https://github.com/pando85/passless/commit/37bf3feb94f03b5f1ea2f4244f1d40fa7de0253f))

## [v0.0.4](https://github.com/pando85/passless/tree/v0.0.4) - 2025-11-17

### Build

- aur: Add passless.install to `generate-pkgbuild.rh` ([6bec7a4](https://github.com/pando85/passless/commit/6bec7a47294a008c16f67a4b57bdba81ffb46768))

## [v0.0.3](https://github.com/pando85/passless/tree/v0.0.3) - 2025-11-17

### Build

- deps: Update keylib to 0.2.3 ([e5a3782](https://github.com/pando85/passless/commit/e5a3782a694c5c79a57eae5a4c6af65a7972a107))

## [v0.0.2](https://github.com/pando85/passless/tree/v0.0.2) - 2025-11-17

### Added

- Add systemd service, udev rules and sysusers and fix AUR ([921e390](https://github.com/pando85/passless/commit/921e390e47cc560e4ed1c2697a00111bef929dec))

### Fixed

- Make clippy happy ([7b91c87](https://github.com/pando85/passless/commit/7b91c879b744e831c8e2fbc1845eb6d526acb6a6))

### Documentation

- Add description and features to README ([d2a5b98](https://github.com/pando85/passless/commit/d2a5b98de1923dd02d07c12da04d833a843527f6))
- Update changelog with initial release ([2456c07](https://github.com/pando85/passless/commit/2456c07fa2d9a430633b679698fdc388df20b13a))

### Build

- ci: Add arm64 release ([458f501](https://github.com/pando85/passless/commit/458f5016352f895224791231a4555fe6dce74927))
- deps: Update keylib to 0.2.2 ([9de0393](https://github.com/pando85/passless/commit/9de039394d56cb9ca528bdc3780c05502c5b9f1e))
- Rename package to passless-rs ([871dd05](https://github.com/pando85/passless/commit/871dd057cab1598dfda3e80258c50852fecef9d5))

### Refactor

- Flatten config structure for improved TOML serialization ([2e9787a](https://github.com/pando85/passless/commit/2e9787ae70ad3a5c66fb61f57d058847d91aadfc))

## [v0.0.1](https://github.com/pando85/passless/tree/v0.0.1) - 2025-11-17

### Added

- Add systemd service, udev rules and sysusers and fix AUR ([921e390](https://github.com/pando85/passless/commit/921e390e47cc560e4ed1c2697a00111bef929dec))

### Fixed

- Make clippy happy ([7b91c87](https://github.com/pando85/passless/commit/7b91c879b744e831c8e2fbc1845eb6d526acb6a6))

### Documentation

- Add description and features to README ([d2a5b98](https://github.com/pando85/passless/commit/d2a5b98de1923dd02d07c12da04d833a843527f6))
- Update changelog with initial release ([2456c07](https://github.com/pando85/passless/commit/2456c07fa2d9a430633b679698fdc388df20b13a))

### Build

- ci: Add arm64 release ([458f501](https://github.com/pando85/passless/commit/458f5016352f895224791231a4555fe6dce74927))
- Rename package to passless-rs ([871dd05](https://github.com/pando85/passless/commit/871dd057cab1598dfda3e80258c50852fecef9d5))

### Refactor

- Flatten config structure for improved TOML serialization ([2e9787a](https://github.com/pando85/passless/commit/2e9787ae70ad3a5c66fb61f57d058847d91aadfc))

## [v0.0.0](https://github.com/pando85/passless/tree/v0.0.0) - 2025-11-17

### Added

- Add systemd service, udev rules and sysusers and fix AUR ([921e390](https://github.com/pando85/passless/commit/921e390e47cc560e4ed1c2697a00111bef929dec))

### Fixed

- Make clippy happy ([7b91c87](https://github.com/pando85/passless/commit/7b91c879b744e831c8e2fbc1845eb6d526acb6a6))

### Documentation

- Add description and features to README ([d2a5b98](https://github.com/pando85/passless/commit/d2a5b98de1923dd02d07c12da04d833a843527f6))
- Update changelog with initial release ([2456c07](https://github.com/pando85/passless/commit/2456c07fa2d9a430633b679698fdc388df20b13a))

### Build

- ci: Add arm64 release ([458f501](https://github.com/pando85/passless/commit/458f5016352f895224791231a4555fe6dce74927))
- Rename package to passless-rs ([871dd05](https://github.com/pando85/passless/commit/871dd057cab1598dfda3e80258c50852fecef9d5))

### Refactor

- Flatten config structure for improved TOML serialization ([2e9787a](https://github.com/pando85/passless/commit/2e9787ae70ad3a5c66fb61f57d058847d91aadfc))

## [v0.0.0](https://github.com/pando85/passless/tree/v0.0.0) - 2025-11-17

Initial release.
