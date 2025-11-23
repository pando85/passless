# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.3.3](https://github.com/pando85/passless/tree/v0.3.3) - 2025-11-23

### Fixed

- Change systemd dependency from `network` to `network-online` ([61989b6](https://github.com/pando85/passless/commit/61989b62a77f150eb285227769e00fca7815ff3d))
- Add completions programatically, refactor core in a new crate ([c768792](https://github.com/pando85/passless/commit/c76879205a7ee3d4dfa5f39ef3cfb3f610309661))

### Documentation

- Update changelog with breaking changes for 0.3.0 ([cff653b](https://github.com/pando85/passless/commit/cff653b81b02ac2b53ff43136d8c6e622d34cb3e))

## [v0.3.2](https://github.com/pando85/passless/tree/v0.3.2) - 2025-11-23

### Fixed

- Add passless-config-doc as a member of the workspace ([6046462](https://github.com/pando85/passless/commit/6046462cbf4f297749c7143a69fd4e12104a697f))
- Publish whole workspace ([7d3a029](https://github.com/pando85/passless/commit/7d3a0298e6880a047783d854c31947f7acd6a424))

## [v0.3.1](https://github.com/pando85/passless/tree/v0.3.1) - 2025-11-23

### Fixed

- Add passless-config-doc as a member of the workspace ([6046462](https://github.com/pando85/passless/commit/6046462cbf4f297749c7143a69fd4e12104a697f))

## [v0.3.0](https://github.com/pando85/passless/tree/v0.3.0) - 2025-11-23

### Added

- Add prompt when initializing local or tpm backends ([5ca3420](https://github.com/pando85/passless/commit/5ca3420f9a241707cf5495352d65d992a92245bc))
- Add shell completions and PKGBUILD ([ece791f](https://github.com/pando85/passless/commit/ece791f124f3607c97e713e4cbb048e5e8af9d29))
- Integrate shell completions into PKGBUILD templates ([1e1c2d4](https://github.com/pando85/passless/commit/1e1c2d4b53021e92ddac0776ea002485462da729))

### Fixed

- security: Improve error handling for memory locking and update logging level ([adfb1e1](https://github.com/pando85/passless/commit/adfb1e12577efb06cba5e5cee46506403a8277cb))
- Add network as a requirement for systemd service ([843a3d4](https://github.com/pando85/passless/commit/843a3d405da4f4bc10a54a797237b3e205ad3008))
- Gracefull shutdown when Ctrl+C press ([060d485](https://github.com/pando85/passless/commit/060d485ed81f32de7b13e9497f348a2454fe6ea6))
- Change default local backend path ([821944a](https://github.com/pando85/passless/commit/821944a1832f9d78b598b524e4c3c73a84393fca))
  - **BREAKING**: Default local backend from `$XDG_DATA_HOME/passless`
    to `$XDG_DATA_HOME/passless/local`

### Documentation

- Add docs comments to programmatic config generation ([1be6161](https://github.com/pando85/passless/commit/1be6161b326bf3471e9fde06f8cfea24724e12cc))

### Build

- deps: Update soft-fido2 to version 0.2.1 ([bc2c3da](https://github.com/pando85/passless/commit/bc2c3da7dcd228a8162b7734d47bf37a66625415))

### Refactor

- Simplify config and CLI parsing using clap-serde-derive ([04d51b0](https://github.com/pando85/passless/commit/04d51b085bf963b6c0b147046214110946367f0a))
  - **BREAKING**: CLI flag renamed from `--config` to `--config-file`.

### Testing

- Create dirs for e2e and unit tests ([f46934d](https://github.com/pando85/passless/commit/f46934dcecbcd6665022dea36e94169e572985d2))
- Check commit message in pre-commit ([df23f52](https://github.com/pando85/passless/commit/df23f52770ebbeee01ae8cd843b87f5a279df4e1))

## [v0.2.0](https://github.com/pando85/passless/tree/v0.2.0) - 2025-11-22

### Added

- Switch to soft-fido2 crate and deprecate keylib ([f41e59b](https://github.com/pando85/passless/commit/f41e59baaa60b5e0e2ccea43749d840f40636c8f))
- Support constant signature counter ([805aa24](https://github.com/pando85/passless/commit/805aa2413a0718178f808584ebb504fe978a1c9f))
  - **BREAKING**: Move user_verification config section into security.
Check new config file for migration.

### Fixed

- Use credential ID bytes directly ([cb562e6](https://github.com/pando85/passless/commit/cb562e6d5840caca32112b2c79b96aa83561c63c))
  - **BREAKING**: Local storage use cred ID instead of user ID for
generating file path.
- Write credentials without initializen sign_count and created ([57b3d36](https://github.com/pando85/passless/commit/57b3d367b683c5ea8adf3baa3e80ecc341e9e159))
- Clean cache when updating credential ([faf63ca](https://github.com/pando85/passless/commit/faf63ca8fb6b24d6055003a30b135307df44ba35))
- Remove init pass question related to git init ([7d05d9f](https://github.com/pando85/passless/commit/7d05d9f1b97e598fe03b12b4c5da2504ef04e4ec))

### Documentation

- Fix build status branch name ([73f29e8](https://github.com/pando85/passless/commit/73f29e8a58965e8a78bf7e14349af260bdbbdb0f))
- Fix rust-keylib link ([49dfe35](https://github.com/pando85/passless/commit/49dfe356d29473105cb8866a7995f2d9e091b795))
- Add temporal logo ([57ea1fe](https://github.com/pando85/passless/commit/57ea1fe7d338886868d24da714394de948839d06))

### Build

- deps: Change to soft-fido2 from crates.io ([9c45b02](https://github.com/pando85/passless/commit/9c45b02cf405fa5c361d283646fca0f2636ce38d))

### Refactor

- config: Use type-state pattern to centralize configuration ([1dd798b](https://github.com/pando85/passless/commit/1dd798b19d54a95e2384bdf9fcd87ceddd99d359))

### Testing

- Fix e2e client code and show authenticator logs when fails ([7836c69](https://github.com/pando85/passless/commit/7836c69064d19643b151d17a81262788e530078a))

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
