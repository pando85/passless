# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.11.1](https://github.com/pando85/passless/tree/v0.11.1) - 2026-05-25

### Fixed

- Restore `always_uv` setting to respect the security config instead of the hardcoded value introduced in v0.11.0. Users who have `security.always_uv` enabled will now have it applied correctly again (#270) ([1ad9128](https://github.com/pando85/passless/commit/1ad9128572e9dca398147011f3ca1dda6159552d))

### Build

- deps: Update Rust crate log to v0.4.30 (#269) ([c69e8f2](https://github.com/pando85/passless/commit/c69e8f289c96e7533073a0e4a6e9cc3e997e6042))

## [v0.11.0](https://github.com/pando85/passless/tree/v0.11.0) - 2026-05-24

### Fixed

- Use Critical urgency for prompt notifications (#246) ([d1214bd](https://github.com/pando85/passless/commit/d1214bd1067fca0312b9eb5109e22af0c492eda9))
- **BREAKING:** Support userless passkey login by no longer advertising `alwaysUv=true` in authenticator options (#265) ([a0965dc](https://github.com/pando85/passless/commit/a0965dc94e700e31d1aa6a6e54531627feab841d)). Even when `security.always_uv` is enabled, the CTAP `alwaysUv` capability is no longer advertised. Notification-based user verification is still preserved internally, but clients that relied on CTAP `alwaysUv` capability advertisement may choose different PIN/UV flows. This change is required for browser userless passkey login compatibility.

### Build

- deps: Update Rust crate clap_complete to v4.6.1 (#231) ([c541dbc](https://github.com/pando85/passless/commit/c541dbc46c28817d9ceafe5389d955bef2c70769))
- deps: Update Rust crate clap_complete to v4.6.2 (#233) ([c49bd62](https://github.com/pando85/passless/commit/c49bd620577a338175d2fffa3f75ebb5a72c729f))
- deps: Update Rust crate libc to v0.2.185 (#234) ([e2a7f65](https://github.com/pando85/passless/commit/e2a7f6522634cf0d3ef5230759255eabb110bb5f))
- deps: Update Rust crate notify-rust to v4.15.0 (#235) ([23990c5](https://github.com/pando85/passless/commit/23990c5baae71443ccaa74473112c835895d008e))
- deps: Update Rust crate clap to v4.6.1 (#236) ([0f139b0](https://github.com/pando85/passless/commit/0f139b0f8c8dda2c4780a31f6c89d22942447848))
- deps: Update KSXGitHub/github-actions-deploy-aur action to v4.1.3 (#237) ([dcc0e68](https://github.com/pando85/passless/commit/dcc0e6847cb8877751814a873c32308a6254d7ea))
- deps: Update Rust crate notify-rust to v4.16.0 (#238) ([e88bdb1](https://github.com/pando85/passless/commit/e88bdb18be30518494e5f9754baf23b9eb919237))
- deps: Update softprops/action-gh-release action to v3 (#232) ([337973d](https://github.com/pando85/passless/commit/337973d5aba43dc5ae60ca3769e2adaab454ba16))
- deps: Update clechasseur/rs-clippy-check action to v6 - abandoned (#239) ([bc1c2d2](https://github.com/pando85/passless/commit/bc1c2d210d1200179439d8a84be88ca796706090))
- deps: Update Rust crate shadow-rs to v2 (#242) ([477b389](https://github.com/pando85/passless/commit/477b389917c9f28695daff5556561294c8d6670d))
- deps: Update Rust crate libc to v0.2.186 (#243) ([75d28bb](https://github.com/pando85/passless/commit/75d28bbd1c63ae92e26b3269d624f692053b66cd))
- deps: Update clechasseur/rs-clippy-check action to v6.0.3 (#244) ([dc0e691](https://github.com/pando85/passless/commit/dc0e691e4ad42ffaad73df48685280ecf9dd8adc))
- deps: Update Rust crate tss-esapi to v7.7.0 (#245) ([b51820d](https://github.com/pando85/passless/commit/b51820d01ae216cde7f0bea362a69932679ecfa9))
- deps: Update Rust crate clap_complete to v4.6.3 (#247) ([7cd530c](https://github.com/pando85/passless/commit/7cd530c7ca3e38712f57995f4d19b3d9c771cbd5))
- deps: Update Rust crate rpassword to v7.5.0 (#248) ([81f0b1a](https://github.com/pando85/passless/commit/81f0b1abde704424fed495e6a31f22db9a0a1dd7))
- deps: Update Rust crate rpassword to v7.5.1 (#249) ([fb1dc59](https://github.com/pando85/passless/commit/fb1dc5934d941483bb9d299a3357b7d050e1da03))
- deps: Update Rust crate notify-rust to v4.16.1 (#250) ([78d8417](https://github.com/pando85/passless/commit/78d8417d59723949cc18feaf0c551981e1e06cf8))
- deps: Update pre-commit hook alessandrojcm/commitlint-pre-commit-hook to v9.25.0 (#251) ([1ad97f6](https://github.com/pando85/passless/commit/1ad97f622dfcb3847cb9ddb632907963ffedebcb))
- deps: Update Rust crate rpassword to v7.5.2 (#252) ([72fdec4](https://github.com/pando85/passless/commit/72fdec401d716d5c68454f3057fe5e6906de4a2c))
- deps: Update Rust crate notify-rust to v4.17.0 (#253) ([9d4b9ab](https://github.com/pando85/passless/commit/9d4b9abd09e5ccca9794402a78517bc83ec85f42))
- deps: Update clechasseur/rs-clippy-check action to v6.0.4 (#254) ([89d0064](https://github.com/pando85/passless/commit/89d00645b1dbae183218ededdae90ce6a52fc1d1))
- deps: Update Rust crate clap_complete to v4.6.4 (#255) ([3859979](https://github.com/pando85/passless/commit/3859979d4cd330c1447aed28035b49b8e4ffd2b9))
- deps: Update Rust crate nix to v0.31.3 (#256) ([c2d5d0f](https://github.com/pando85/passless/commit/c2d5d0f7329a83383e5658994628d16c5f64aca9))
- deps: Update Rust crate clap_complete to v4.6.5 (#258) ([d05b255](https://github.com/pando85/passless/commit/d05b255d342c9562ab50c81526b4ece32b8f81ec))
- deps: Update Rust crate git2 to 0.21 (#259) ([c7a4177](https://github.com/pando85/passless/commit/c7a4177d8073dca98fece07df2706c58c3ab93e4))
- deps: Update mindsers/changelog-reader-action action to v2.3.0 (#260) ([2071ad0](https://github.com/pando85/passless/commit/2071ad0a40ae16be8f4815f4a32b35683b42219c))
- deps: Update mindsers/changelog-reader-action action to v2.4.0 (#261) ([6b74366](https://github.com/pando85/passless/commit/6b743662bea4fe72c6bb3f620e020396654a5d2e))
- deps: Update Rust crate serde_json to v1.0.150 (#263) ([e65d495](https://github.com/pando85/passless/commit/e65d49566e765f21272c67d81b847492df230949))
- deps: Update Rust crate rpassword to v7.5.3 (#264) ([27b4e48](https://github.com/pando85/passless/commit/27b4e485029c98671b05613833b1fd26bbb29ff4))

### Refactor

- Extract duplicated auth pattern to helper function ([d24eed3](https://github.com/pando85/passless/commit/d24eed3a494f059bcc0392e846a77a28a79abcd5))

### Chore

- Improve release script and update release skill (#262) ([7174096](https://github.com/pando85/passless/commit/71740969586b60d4aa4de655794a7a5d952edfc0))

## [v0.10.1](https://github.com/pando85/passless/tree/v0.10.1) - 2026-04-09

### Fixed

- Add PIN fallback for credential management when UV unavailable ([513d58c](https://github.com/pando85/passless/commit/513d58c6ecf8ac597e8a18ccc454d169e87f6b37))

## [v0.10.0](https://github.com/pando85/passless/tree/v0.10.0) - 2026-03-23

### Added

- Split PIN state into config and retries files for pass backend ([42bea86](https://github.com/pando85/passless/commit/42bea860fc8cdb4302c810d346bfde0ed9e99166))

### Fixed

- Use correct path for cargo install in workspace ([82eed51](https://github.com/pando85/passless/commit/82eed5186347663a8034202529de3e786e9130fb))
- Pull latest PIN config from git before loading ([19cf0d1](https://github.com/pando85/passless/commit/19cf0d1f08cf1dd5c1f946a6019c455d20657f1c))
- Resolve thread safety and PartialEq issues in PassPinStorage ([902ef16](https://github.com/pando85/passless/commit/902ef1625c5fc451ee91a2b77bee972f30a51bd5))
- Handle RwLock poisoning gracefully in PassPinStorage ([405ede5](https://github.com/pando85/passless/commit/405ede5a306036806118ee6c9fafc0fcbea7397e))

### Build

- deps: Update Rust crate toml to v1.0.7 ([05d19c4](https://github.com/pando85/passless/commit/05d19c416951332fa325aa83a883823a183a68fa))
- deps: Update Rust crate toml to v1.1.0 ([47fc190](https://github.com/pando85/passless/commit/47fc1902063a8ac4141fdd2d321489410e7ed0d6))
- deps: Update Rust crate env_logger to v0.11.10 ([6477b6a](https://github.com/pando85/passless/commit/6477b6a85a48bda70ef501b3cddb38e2abb099c7))

### Styling

- Fix import ordering in tpm.rs ([2fe755c](https://github.com/pando85/passless/commit/2fe755c72fe401c7018beb3810224e924924dae6))

## [v0.9.3](https://github.com/pando85/passless/tree/v0.9.3) - 2026-03-13

### Fixed

- Remove redundant default attribute on constant_signature_counter ([595f781](https://github.com/pando85/passless/commit/595f781216249460f6075d3617b8c735056f045c))
- Use ClapSerde::Opt for config deserialization to respect defaults ([5fd2496](https://github.com/pando85/passless/commit/5fd2496e5dd1de669137c45cecdf120f3ee374c8))
- Use toml::Value for proper serialization in config print ([ea680d0](https://github.com/pando85/passless/commit/ea680d0d8231fe6b395e5469cfcde5917c2851d9))

### Build

- deps: Update Rust crate soft-fido2 to v0.12.2 ([d9a58df](https://github.com/pando85/passless/commit/d9a58df21bc75027bc85e58184b8cbbca1f8ce75))

## [v0.9.2](https://github.com/pando85/passless/tree/v0.9.2) - 2026-03-13

### Fixed

- Return AcceptedWithUp from request_uv to prevent double notification ([1c94602](https://github.com/pando85/passless/commit/1c946023b66b284a8c433ddb17c1bb6fe2105875))

### Build

- deps: Update Rust crate clap_complete to v4.6.0 ([7ed53b8](https://github.com/pando85/passless/commit/7ed53b8c20844128b4c0f3c3d197e0c8571e9817))
- deps: Update Rust crate clap to v4.6.0 ([3c5fe4e](https://github.com/pando85/passless/commit/3c5fe4ed182e8409017a2ed51a15fe1094e44eba))

## [v0.9.1](https://github.com/pando85/passless/tree/v0.9.1) - 2026-03-12

### Added

- Add configurable PIN enforcement policies ([456ad31](https://github.com/pando85/passless/commit/456ad31ee5f9d858365f201796f214b4cb725053))
- Update soft-fido2 to 0.12.1 for proper PIN prompting ([fe549e2](https://github.com/pando85/passless/commit/fe549e2f4df73dcb9842b53b1675316116c15a37))

### Fixed

- Prevent duplicate credential entries when updating sign counter ([3d3f91a](https://github.com/pando85/passless/commit/3d3f91ae7e2cf7dcada1764326d8ae677602024c))

### Build

- deps: Update Rust crate clap_complete to v4.5.67 ([75aeba6](https://github.com/pando85/passless/commit/75aeba6d733a8798522dae510f6e0df03bfa00af))
- deps: Update Rust crate clap to v4.5.61 ([1967937](https://github.com/pando85/passless/commit/19679375a6827410b869fa117e78654d7d910ee4))

## [v0.9.0](https://github.com/pando85/passless/tree/v0.9.0) - 2026-03-11

### Added

- Add PIN storage infrastructure ([69336a4](https://github.com/pando85/passless/commit/69336a420382f4c5251be3c22145efecc8ad5c19))
- Implement PIN set and change commands ([bee72b9](https://github.com/pando85/passless/commit/bee72b9625a491191c184f1edfb0ec6e9e0544c5))
- Wire up PIN storage backends in main.rs ([f683e45](https://github.com/pando85/passless/commit/f683e45b9d06aab4d43fae549e5b88334acba2bc))

### Build

- deps: Update Rust crate tempfile to v3.27.0 ([d9bb6d1](https://github.com/pando85/passless/commit/d9bb6d15249aa5e4248223790da8d1cf6a65fd34))

### Testing

- Add E2E test for PIN set and change commands ([7d26fac](https://github.com/pando85/passless/commit/7d26fac7ee8fe53b4b4f9cc982f5cf230fb4c608))

### Chore

- Disable subject-case commitlint rule ([7a0e6c3](https://github.com/pando85/passless/commit/7a0e6c3571c9e6e97d88d301124b9a27c79454b9))

## [v0.8.2](https://github.com/pando85/passless/tree/v0.8.2) - 2026-03-11

### Build

- Prepare for soft-fido2 0.11.2 ([3c00503](https://github.com/pando85/passless/commit/3c0050376c5f7d2be90ddf891aa508b9c164615d))

## [v0.8.1](https://github.com/pando85/passless/tree/v0.8.1) - 2026-03-10

### Revert

- Downgrade to soft-fido 0.10 ([1b8cc91](https://github.com/pando85/passless/commit/1b8cc91c743b0ffb55ebf21f63b217af90c076b5))

## [v0.8.0](https://github.com/pando85/passless/tree/v0.8.0) - 2026-03-10

### Added

- Add eddsa support for ssh sk keys ([f1c5770](https://github.com/pando85/passless/commit/f1c5770f5aefeee35f49e9003da583ea77df0a97))

### Fixed

- Ensure files and directories are created with user-only permissions ([1c5ca50](https://github.com/pando85/passless/commit/1c5ca50b43a591cfe658d0661cdcfd55c7b57cb9))
- Remove duplicate code in local/init.rs ([cf3e7c9](https://github.com/pando85/passless/commit/cf3e7c9567f1e91c745ada815ef3c6aeb0fc4f59))
- Resolve duplicate definitions and import issues ([d07e629](https://github.com/pando85/passless/commit/d07e629a3dcb45b0f8466dc73e54f9cbb59a0220))
- Allow dead code for write_secure_file utility ([b82a9ee](https://github.com/pando85/passless/commit/b82a9eec535f4cb3893fc4c2e7156ec946dbc002))
- Simplify create_secure_dir_all to only set permissions on target ([ac43b10](https://github.com/pando85/passless/commit/ac43b101b60c79fa8a208babd9a1a808d0e6a445))

### Build

- deps: Update Rust crate syn to v2.0.116 ([9898065](https://github.com/pando85/passless/commit/9898065836fc749ce25a2777348c02aaff77262c))
- deps: Update Rust crate toml to v1.0.2 ([2fb012e](https://github.com/pando85/passless/commit/2fb012ed09654470ea08e6dfffce855cd134ae67))
- deps: Update Rust crate clap to v4.5.59 ([a889c11](https://github.com/pando85/passless/commit/a889c1139021cf1ab21869e70d80909816ff4fe4))
- deps: Update Rust crate toml to v1.0.3 ([72388a6](https://github.com/pando85/passless/commit/72388a6073b35ac8aa1286104ea1acdc6fea4c9d))
- deps: Update Rust crate clap to v4.5.60 ([1137a85](https://github.com/pando85/passless/commit/1137a8564e37dd16b0a6cc1a01ff39e41a567664))
- deps: Update Rust crate syn to v2.0.117 ([5e25d7d](https://github.com/pando85/passless/commit/5e25d7de6a91201a0a35c0fe53088e056f3c1f40))
- deps: Update Rust crate nix to v0.31.2 ([39a8e95](https://github.com/pando85/passless/commit/39a8e95d2c996468ef1c49a6e62cd0e48a7aac77))
- deps: Update Rust crate tempfile to v3.26.0 ([6f93f2e](https://github.com/pando85/passless/commit/6f93f2e2f6e1b6cb5d0d9ff8513f73e574c9131d))
- deps: Update Rust crate quote to v1.0.45 ([e1d8fa0](https://github.com/pando85/passless/commit/e1d8fa027ad5291870dcc4f37492624995ad26d7))
- deps: Update Rust crate toml to v1.0.4 ([4631c1d](https://github.com/pando85/passless/commit/4631c1d6ff18f1267085e8b4d87674b2ab128227))
- deps: Update Rust crate toml to v1.0.6 ([e5ae4cc](https://github.com/pando85/passless/commit/e5ae4ccf37ac197f652b05564b3831af4ab17328))
- deps: Update Rust crate libc to v0.2.183 ([c54a03d](https://github.com/pando85/passless/commit/c54a03d4273868ac3068fa7967890d9097e85358))
- deps: Update Rust crate shadow-rs to v1.7.1 ([6f29752](https://github.com/pando85/passless/commit/6f297525df3c2fe3e6a2b70739bc1651a5f3be1a))

## [v0.7.6](https://github.com/pando85/passless/tree/v0.7.6) - 2026-02-14

### Added

- Improve error handling and add comprehensive tests ([3ebd823](https://github.com/pando85/passless/commit/3ebd823ba5a3ec9b36ace4aa806b52cba676e024))

### Fixed

- Resolve all compilation errors in error handling and testing branch ([faad274](https://github.com/pando85/passless/commit/faad2743e5986c4ef156f62068a65516e039a15f))
- Credential list now reflects changes immediately ([508541a](https://github.com/pando85/passless/commit/508541a1ed927cb43f8b4017f95621f5b7a2e610))

### Build

- deps: Update Rust crate ctrlc to v3.5.2 ([2e7edf9](https://github.com/pando85/passless/commit/2e7edf92a78d7cfdd976e1056a5625e922ea2117))
- deps: Update Rust crate clap_complete to v4.5.66 ([72ccd25](https://github.com/pando85/passless/commit/72ccd2562b651ab4fc363ba464af4725b6a4238e))
- deps: Update Rust crate clap to v4.5.58 ([abc38c0](https://github.com/pando85/passless/commit/abc38c0b7fe602c8e0e5884ea12cf208f4301977))
- deps: Update Rust crate env_logger to v0.11.9 ([dd761a8](https://github.com/pando85/passless/commit/dd761a89a10421b768b8bc9f1322e1ea0e335dc0))
- deps: Update Rust crate toml to v1 ([6ca7e1a](https://github.com/pando85/passless/commit/6ca7e1ad60a7f64713f94d50a995de11df5afcc9))
- deps: Update Rust crate syn to v2.0.115 ([f71ac70](https://github.com/pando85/passless/commit/f71ac70407da544ae62ac4922fc565d02df2cd1e))
- deps: Update Rust crate toml to v1.0.1 ([9eb463b](https://github.com/pando85/passless/commit/9eb463bb324f9d7bd9db37cf266e7bce5e4a7489))

## [v0.7.5](https://github.com/pando85/passless/tree/v0.7.5) - 2026-02-10

### Build

- Fix hidapi linking in AUR build ([c0b6ba2](https://github.com/pando85/passless/commit/c0b6ba265e02f308bd1f4fd4a80d7fb5c1fd0eae))

## [v0.7.4](https://github.com/pando85/passless/tree/v0.7.4) - 2026-02-10

### Build

- deps: Update Rust crate toml to v0.9.12 ([d3a9c03](https://github.com/pando85/passless/commit/d3a9c03712bf8064039bb8e4849a670808858386))
- Force system libgit2 for AUR build compatibility ([1f62032](https://github.com/pando85/passless/commit/1f620328965e99df1fccdca1a689c2587dea227b))
- Force system hidapi for AUR build compatibility ([7c9d6b7](https://github.com/pando85/passless/commit/7c9d6b70060cb207792709fc207b958aa47c3c02))

## [v0.7.3](https://github.com/pando85/passless/tree/v0.7.3) - 2026-02-10

### Build

- deps: Update Rust crate tempfile to v3.25.0 ([422585b](https://github.com/pando85/passless/commit/422585b34d769f76c1d4d40b64d09da7d5d2fe03))

## [v0.7.2](https://github.com/pando85/passless/tree/v0.7.2) - 2026-02-09

### Fixed

- Fix AUR installation failure due to git2 linking issues ([#125](https://github.com/pando85/passless/issues/125))

## [v0.7.1](https://github.com/pando85/passless/tree/v0.7.1) - 2026-01-18

### Documentation

- Add build requirements to development docs ([55f6e4b](https://github.com/pando85/passless/commit/55f6e4b502dcc0b9c097fdb67d5c2709998c1cd3))

### Build

- deps: Update Rust crate clap to v4.5.54 ([b6dada4](https://github.com/pando85/passless/commit/b6dada4f0e99ee22c40e1ca197501809fdb15a46))
- deps: Update Rust crate clap_complete to v4.5.65 ([cd86593](https://github.com/pando85/passless/commit/cd8659363c0aa4d6d0141b68652b9877decaf113))
- deps: Update Rust crate proc-macro2 to v1.0.105 ([666c737](https://github.com/pando85/passless/commit/666c7370e8f190e82a9fcdb4a314eeacccd44e35))
- deps: Update Rust crate syn to v2.0.114 ([dc572a8](https://github.com/pando85/passless/commit/dc572a83474259b16c5d9897a32628c442e4e3a2))
- deps: Update Rust crate serde_json to v1.0.149 ([724774b](https://github.com/pando85/passless/commit/724774bc54ab93223b9a8d4479e2d1842c30abdc))
- deps: Update Rust crate quote to v1.0.43 ([3a14816](https://github.com/pando85/passless/commit/3a14816c13d4668479d9600260c9dd8aecd8ef6f))
- deps: Update Rust crate libc to v0.2.180 ([1df5108](https://github.com/pando85/passless/commit/1df510834979f46a1ff3828ede26e08345686ba5))
- deps: Update Rust crate log to v0.4.29 ([53982bd](https://github.com/pando85/passless/commit/53982bd2cd7e304973982b39458890c86432f2bf))
- deps: Update pre-commit hook adrienverge/yamllint to v1.38.0 ([dd08a66](https://github.com/pando85/passless/commit/dd08a66d28eea7f42788e7cf24e8b21e25896f7a))
- deps: Update pre-commit hook alessandrojcm/commitlint-pre-commit-hook to v9.24.0 ([b5289d7](https://github.com/pando85/passless/commit/b5289d7811075fbdbe1ffbeea746934b14dd63c4))
- deps: Update Rust crate darling to 0.23 ([6431cc4](https://github.com/pando85/passless/commit/6431cc46f6766f0b26d6c7529c1d00d5af4e97f8))
- deps: Update Rust crate nix to 0.30 ([38e8432](https://github.com/pando85/passless/commit/38e8432a3c8449fd77724f529b7502fe6b0d49ce))
- deps: Update Rust crate shadow-rs to v1.5.0 ([6d04f0f](https://github.com/pando85/passless/commit/6d04f0f2ba1382e621ec188dc770e1567063f75d))
- deps: Update Rust crate tempfile to v3.24.0 ([de0e411](https://github.com/pando85/passless/commit/de0e4114e027c6c2a3d7590f2eb4b2e7660f0b81))
- deps: Update Rust crate toml to 0.9 ([4674965](https://github.com/pando85/passless/commit/4674965978f4a2de66b5e87645dc281f41154444))
- deps: Update actions/cache action to v5 ([5d9f68e](https://github.com/pando85/passless/commit/5d9f68ec1bfe30a1b9ea34203c949d8cb7c15a78))
- deps: Update actions/checkout action to v6 ([b446d73](https://github.com/pando85/passless/commit/b446d73850c5809c44193654c502e262ae825f12))
- deps: Update Rust crate prs-lib to v0.5.6 ([cd01c34](https://github.com/pando85/passless/commit/cd01c34a9b510bcc066d48bb0eeef9cff361049a))
- deps: Update Rust crate dirs to v6 ([82868e2](https://github.com/pando85/passless/commit/82868e23b0b3c1401706d4a0b20fe7b39070dc1f))
- deps: Update Rust crate thiserror to v2.0.18 ([4d519ce](https://github.com/pando85/passless/commit/4d519ce0392d5d52d76352b375032caede0513f0))
- deps: Update soft-fido2 to 0.10.1 ([2356efb](https://github.com/pando85/passless/commit/2356efb10cd06315e38bf58345350ab3468c3aee))

### Refactor

- Move tpm backend to feature gate ([66dc244](https://github.com/pando85/passless/commit/66dc2446aa0162c404e12a90e23c64f61b762d7b))

## [v0.7.0](https://github.com/pando85/passless/tree/v0.7.0) - 2025-12-17

### Added

- Add notification timeout for user presence ([5966fb8](https://github.com/pando85/passless/commit/5966fb8ccebe4ac34caeb84592d0612cacff5af6))

### Build

- deps: Update soft-fido2 to version 0.10.0 ([f7d5311](https://github.com/pando85/passless/commit/f7d53116fe2cc7551a264981f8906fae342df90b))

## [v0.6.6](https://github.com/pando85/passless/tree/v0.6.6) - 2025-12-14

### Fixed

- Change verbosity level when decrypting credentials fails ([2d1be63](https://github.com/pando85/passless/commit/2d1be6360ef1544e804abaa474a137cfe3f9e715))

## [v0.6.5](https://github.com/pando85/passless/tree/v0.6.5) - 2025-12-10

### Build

- deps: Update soft-fido2 to version 0.9.0 ([1f97ad2](https://github.com/pando85/passless/commit/1f97ad2ba7e9ff50c8de0cd0007e5e718275b810))

## [v0.6.4](https://github.com/pando85/passless/tree/v0.6.4) - 2025-12-10

### Build

- deps: Update soft-fido2 to version 0.8.0 ([83109a4](https://github.com/pando85/passless/commit/83109a452e1bd26882187f6852b2c318c688a1b8))

### Refactor

- Remove dead code ([d1c1a6c](https://github.com/pando85/passless/commit/d1c1a6cefc8a99ea7f94301235308a0e767f31c3))

## [v0.6.3](https://github.com/pando85/passless/tree/v0.6.3) - 2025-12-09

### Added

- Add build information to version arg ([5871272](https://github.com/pando85/passless/commit/58712721269e70a4b524d2a907b2e0e1a4aa37ef))

### Documentation

- Extend security warning with detailed information ([93c243c](https://github.com/pando85/passless/commit/93c243cac56be4f92bd724a927354bf61acc5364))

### Build

- Update AUR packages description ([d6fd966](https://github.com/pando85/passless/commit/d6fd9667133c13183f5a18a9021b6e4a25640dde))

### Refactor

- Remove AI slop ([19d24fd](https://github.com/pando85/passless/commit/19d24fd75a895373ac2196c84839a034ffce9c62))

### Testing

- Support configurable USB device IDs for multi-device e2e test ([aa5a482](https://github.com/pando85/passless/commit/aa5a48269f3841d6fa6e46fab858a753a1c6d0dc))

## [v0.6.2](https://github.com/pando85/passless/tree/v0.6.2) - 2025-12-05

### Added

- Decouple storage format from soft-fido2 serialization ([85980df](https://github.com/pando85/passless/commit/85980dfc6a7cfce4b789fd65afa52f8a3cada794))

### Build

- deps: Update soft-fido2 to version 0.6.1 ([03c618f](https://github.com/pando85/passless/commit/03c618fea13d205eeaa2be7e0c8163069a068b12))

## [v0.6.1](https://github.com/pando85/passless/tree/v0.6.1) - 2025-12-02

### Build

- Upload files once on release ([7809c30](https://github.com/pando85/passless/commit/7809c3070ce69c45fd9fbc82972fbda224c7c687))

## [v0.6.0](https://github.com/pando85/passless/tree/v0.6.0) - 2025-12-02

### Added

- Add client commands ([f990e1c](https://github.com/pando85/passless/commit/f990e1c9eceade3c6ecc7825b6f1ddaa62e63191))

### Fixed

- Increase performance with lazy evaluation for client device filtering ([45fe73c](https://github.com/pando85/passless/commit/45fe73cdb993137361a28273409893a57c0e211f))

## [v0.5.4](https://github.com/pando85/passless/tree/v0.5.4) - 2025-12-02

### Added

- Shutdown immediately when pressing ctrl+c twice ([429dcc1](https://github.com/pando85/passless/commit/429dcc13e440c871491ffaf37a29f918d7678bf3))

### Build

- deps: Update soft-fido2 to version 0.5.0 ([87c1e67](https://github.com/pando85/passless/commit/87c1e6759f3b37444dc13ddf764dd36063d3168c))

## [v0.5.3](https://github.com/pando85/passless/tree/v0.5.3) - 2025-12-01

### Fixed

- Enable pinUvAuthToken in authenticator ([c91d9ce](https://github.com/pando85/passless/commit/c91d9ceb0c09428c4f625725bac244fbee6b57b2))

### Build

- deps: Update soft-fido2 to version 0.4.3 ([fbbe89f](https://github.com/pando85/passless/commit/fbbe89fcd2260d9dba08a64a18bff4e79a6de769))
- deps: Update soft-fido2 to version 0.4.4 ([ed87dc5](https://github.com/pando85/passless/commit/ed87dc54fd701b4d6a06c48cfff310081b775d6a))

## [v0.5.2](https://github.com/pando85/passless/tree/v0.5.2) - 2025-11-30

### Fixed

- Disable pin Uv auth token ([cc36f08](https://github.com/pando85/passless/commit/cc36f088cbde63a70117f16425270ba5df4b1a76))

## [v0.5.1](https://github.com/pando85/passless/tree/v0.5.1) - 2025-11-30

### Fixed

- Downgrade soft-fido2 to 0.3.2 ([158d880](https://github.com/pando85/passless/commit/158d8805016f5b4c3f59fbd1c717729cd1fe7713))

## [v0.5.0](https://github.com/pando85/passless/tree/v0.5.0) - 2025-11-29

### Fixed

- config: Change default backend to pass ([9d3c048](https://github.com/pando85/passless/commit/9d3c048005c6052c59e9147b629b74dc4c2adc68))
  - **BREAKING**: Default backend is now `pass`.
- Enable pinUvAuthToken ([787101e](https://github.com/pando85/passless/commit/787101e4821cbf35471b9b4eddcd875c30fe34af))

### Build

- deps: Update soft-fido2 to version 0.4.0 ([85d889b](https://github.com/pando85/passless/commit/85d889b8ef6ae87dcb224d3604264e37371f013e))

## [v0.4.2](https://github.com/pando85/passless/tree/v0.4.2) - 2025-11-27

### Fixed

- Replace more bytes prints by credentials ID strings ([7d0da28](https://github.com/pando85/passless/commit/7d0da28f072dd9a65c740439a6267929386614a8))

### Documentation

- Add permanent uhid config to error message ([7666aef](https://github.com/pando85/passless/commit/7666aef5c574b934ac974f30d950426fbdd0cf72))
- Add logo ([9e24da4](https://github.com/pando85/passless/commit/9e24da4720c6d315e72ff3e3750867a0cd938881))
- Resize logo ([08239bf](https://github.com/pando85/passless/commit/08239bfa14cc19810a3da758be5d0644cb6131ce))
- Add white background to the logo ([31b2de1](https://github.com/pando85/passless/commit/31b2de16c32cb6b399893928e42703b9dc96636d))
- Round edges to the logo ([cdc4e0c](https://github.com/pando85/passless/commit/cdc4e0c5427df34c48606012acb4d9d9fe082516))

### Build

- deps: Update soft-fido2 to version 0.3.2 ([e901cbd](https://github.com/pando85/passless/commit/e901cbdfd11b9a508ac85c30dd70bfa62700d2c6))

## [v0.4.1](https://github.com/pando85/passless/tree/v0.4.1) - 2025-11-26

### Fixed

- Add `uhid` module to modules load on install ([a307a90](https://github.com/pando85/passless/commit/a307a90ce6666af7711d5508b43e7ffc96eacb11))
- Show credentials ID as string instead of bytes ([c08b621](https://github.com/pando85/passless/commit/c08b6213b7f5a0c900e227385b03d7eea6c59ee9))

### Documentation

- Add note about sandboxed browsers and PassKeez acknowledgements ([b7964e5](https://github.com/pando85/passless/commit/b7964e5a8ce5213e6d137195452db1986b1cf453))

## [v0.4.0](https://github.com/pando85/passless/tree/v0.4.0) - 2025-11-24

### Added

- Add memory security hardening with zeroizing and mlock probe ([afefc1d](https://github.com/pando85/passless/commit/afefc1d233246e10ab61180fcc20301379c56827))
- Disable mlockall option in flavor of the new mlock just sensitive data ([2247b01](https://github.com/pando85/passless/commit/2247b01fde0a762b4db0681e400e99fd28906f86))
  - **BREAKING**: config `use_mlock` changed to `check_mlock`.

### Fixed

- Force shutdown after 5s trying graceful shutdown ([1646b58](https://github.com/pando85/passless/commit/1646b58204260f48b433d097c0c269de3116239b))
- Use indexes to get metadata from credentials ([1662323](https://github.com/pando85/passless/commit/1662323fd887b3175ac7fe545e00636d8f5da59f))

### Build

- deps: Update soft-fido2 to version 0.3.0 ([cc704e6](https://github.com/pando85/passless/commit/cc704e6839c4f1fce2ae4fad62db43df3a4a8310))
- deps: Update soft-fido2 to version 0.3.1 ([d195555](https://github.com/pando85/passless/commit/d195555a052363ae01869b004995f5c3499cb921))
  - **BREAKING**: The `pass` backend now uses binary credential storage
format instead of JSON. Existing password stores must be recreated as
no migration path is provided. We don't expect more breaking changes
like this in the future. We don't offer a migration mechanism because
probably there are no users but in the future we will offer a way if
this is needed.

### Refactor

- Fix import order according to style ([dc9c479](https://github.com/pando85/passless/commit/dc9c4798a22f0258278fbe1d600a98aa26ecdead))
- Deprecate example for testing config ([960272c](https://github.com/pando85/passless/commit/960272c950040a1e909c0fa771d503bd27a240e7))

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
