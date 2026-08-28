# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.19.0](https://github.com/pando85/passless/tree/v0.19.0) - 2026-08-28

### Added

- Allow profile-scoped shared browser with fixed CDP port and unlimited sessions ([b1bcad2](https://github.com/pando85/passless/commit/b1bcad2bf39735d47185bb0d0eb8bdfc33f91fbd))

### Fixed

- pass: Avoid repeated decryption and GPG key prompts (#454) ([a693a4d](https://github.com/pando85/passless/commit/a693a4d787ead3f4168a79b05abe01e3e5bc1d04))
- WebAuthn sign hardening — TOCTOU, Unix socket server, replay dedup, same-user batch (#450) ([d371a21](https://github.com/pando85/passless/commit/d371a21399be5aae483c9c686c464cffb86d4e2b))
- Increase default max_concurrent_sessions to maximum (#451) ([15564a0](https://github.com/pando85/passless/commit/15564a0c227e92b17ac17261c95f49abff2bd834))
- Shared browser correctness and maintainability improvements ([0e6f542](https://github.com/pando85/passless/commit/0e6f542337afefa96b779cd0b7890372b2ca2e92))
- Keep profile-scoped browser alive for playwright MCP ([385bc1a](https://github.com/pando85/passless/commit/385bc1a12a03c39dedd823f8c17f77fbad164289))
- Launch playwright MCP browser lazily on first CDP connection ([9edaf0c](https://github.com/pando85/passless/commit/9edaf0cdf90b6752f73717018b0e81893913876e))

### Build

- deps: Update Rust crate aes to v0.9.3 (#455) ([770dac7](https://github.com/pando85/passless/commit/770dac7d80fd58a4b7e124e8ac57d3748ad2b53e))

## [v0.18.1](https://github.com/pando85/passless/tree/v0.18.1) - 2026-08-26

### Fixed

- agent: Prevent PR_SET_PDEATHSIG from killing principals on thread exit (#447) ([5974081](https://github.com/pando85/passless/commit/597408113f5a736880598a8af817ecab14dfb4c2))
- Avoid repeated pass sync for PIN state (#448) ([b6e9cbd](https://github.com/pando85/passless/commit/b6e9cbdbc13de9cc2685a0c2bd044bcc5bd41db8))

### Build

- deps: Update dependency @simplewebauthn/server to v13.3.3 (#445) ([6b830ae](https://github.com/pando85/passless/commit/6b830aea228c221eb39345de5ac261af95bc2f99))

## [v0.18.0](https://github.com/pando85/passless/tree/v0.18.0) - 2026-08-25

### Added

- agent: Add lazy Playwright MCP browser bootstrap (#428) ([620a0b7](https://github.com/pando85/passless/commit/620a0b756da2c73fb56d6250242198f57de7ac04))
- agent: Isolate browser leases per principal session (#435) ([c1e92e7](https://github.com/pando85/passless/commit/c1e92e735c8e6cab823991df89ad1041b3fbe59e))
- Use systemd-journal-logger when running as systemd service (#437) ([0014c6a](https://github.com/pando85/passless/commit/0014c6ae56175a8d6bf7bb5047294bbe81846e49))

### Fixed

- agent: Handle SIGTERM and detect orphaned sessions (#438) ([005f8ab](https://github.com/pando85/passless/commit/005f8abbead20431a22f199cf898664867b7b2b6))
- logging: Preserve filters with journald (#443) ([a651052](https://github.com/pando85/passless/commit/a6510522759caff1d9265100f3ae760e981125f5))
- pass: Batch Git sync per operation (#434) ([e57a763](https://github.com/pando85/passless/commit/e57a7638b6326c05543867e05f7b67bcb18a2863))
- Complete encrypted credential backup (#426) ([08b88ae](https://github.com/pando85/passless/commit/08b88aeecd811afa16ab8f2304f0117cc9e232d7))

### Build

- deps: Update Rust crate darling to v0.24.1 (#431) ([c11b040](https://github.com/pando85/passless/commit/c11b040c841da137dcb82342c9e86c5e5ea80e35))
- deps: Update Rust crate psl to v2.1.225 (#430) ([eca06a7](https://github.com/pando85/passless/commit/eca06a715686f7392c79a175a0a9c6e7b82c5944))
- deps: Update Rust crate psl to v2.1.226 (#436) ([dc56364](https://github.com/pando85/passless/commit/dc56364c4a82b99c493ae7cd3f38dffaf9bbe8a5))
- deps: Update Rust crate aes-gcm to v0.11.1 (#439) ([b9188e5](https://github.com/pando85/passless/commit/b9188e5d4db6ce10c9859847905b6a2c39a12e46))
- deps: Update Rust crate log to v0.4.34 (#440) ([3be059e](https://github.com/pando85/passless/commit/3be059e3a11c23c6d9d2ea07c6fb239638b0d737))
- deps: Update Rust crate syn to v3.0.4 (#441) ([814da19](https://github.com/pando85/passless/commit/814da19732cbc6416e0fe508e5d9a4fe4d99ce27))
- deps: Update Rust crate signal-hook to 0.4 (#442) ([5dbdd08](https://github.com/pando85/passless/commit/5dbdd0830fcf6ab0133e4b80341a8b7a1bbbd7ca))

## [v0.17.0](https://github.com/pando85/passless/tree/v0.17.0) - 2026-08-16

### Added

- Improve Playwright MCP browser integration (#423) ([06eec5e](https://github.com/pando85/passless/commit/06eec5e4b834997b7f1a4c9b113d5379204c1545))

### Testing

- Make browser lease tests deterministic (#424) ([6cc76c0](https://github.com/pando85/passless/commit/6cc76c00f97358134dbe38e8dd52455446af61a8))

## [v0.16.0](https://github.com/pando85/passless/tree/v0.16.0) - 2026-08-15

### Added

- agent: Expose effective authority (#409) ([0b00240](https://github.com/pando85/passless/commit/0b00240ea78078796f0acb5997081289a8a0191e))
- agent: Make same-user enrollment ephemeral (#411) ([af94914](https://github.com/pando85/passless/commit/af9491440ab8f6a0806ec95013bf4c146b9e8b4d))
- agent: Support per-RP credential selection (#415) ([f8f1ec2](https://github.com/pando85/passless/commit/f8f1ec299a2f56e1fc81863de37ea68f903c5957))
- Implement unified same-user and isolated agent modes (#402) ([a6facff](https://github.com/pando85/passless/commit/a6facff70fdeb9b2d1c43cb83cc7eec59e6ca9e7))
- Add same-user catch-all RP authentication (#407) ([7cf04e1](https://github.com/pando85/passless/commit/7cf04e1886c777e6e1aef85d54beb05497fb708d))

### Fixed

- agent: Harden security boundaries and usability (#408) ([ec3a750](https://github.com/pando85/passless/commit/ec3a7506f446806ce0f2e0268b5400c6b9417d25))
- agent: Require dangerous profile acknowledgements (#410) ([86f3bb9](https://github.com/pando85/passless/commit/86f3bb91532abb42c086806d5c4162541f4ecc50))
- agent: Restore same-user Chromium port launches (#418) ([001f17a](https://github.com/pando85/passless/commit/001f17a1d081ad42f8c1cd7815af8fd8a798869f))
- Initialize agent runtime in the background (#406) ([3736c2c](https://github.com/pando85/passless/commit/3736c2c2bb83f26fb1a3e0d2a2feffddb35cd315))
- Resolve PIN UV token E2E test failures (#416) ([cca6c38](https://github.com/pando85/passless/commit/cca6c38b89acef2ea14863bec946922400c45a0f))

### Build

- deps: Update Rust crate clap_complete to v4.6.9 (#403) ([c1508a5](https://github.com/pando85/passless/commit/c1508a5a20a208b487ff474adbc22b76237c6878))
- deps: Update Rust crate clap to v4.6.6 (#404) ([584998e](https://github.com/pando85/passless/commit/584998e39f75192bfb7f6f119e9af3811e8bcd0a))
- deps: Update actions/upload-artifact action to v7 (#405) ([92778a1](https://github.com/pando85/passless/commit/92778a19a79d79cd86333985ae1c911ef3c0ffc4))
- deps: Update Rust crate thiserror to v2.0.20 (#413) ([9d08056](https://github.com/pando85/passless/commit/9d0805660c1bb262eb222086c794568d0b9293b9))
- deps: Update Rust crate zbus to v5.19.0 (#414) ([9722c14](https://github.com/pando85/passless/commit/9722c14339c6266d079c34a9fd9ada63a02a7936))
- deps: Update clechasseur/rs-clippy-check action to v6.0.7 (#419) ([4a96ec0](https://github.com/pando85/passless/commit/4a96ec03d3df98e1673823168de4d4a894eeb1cb))
- deps: Update Rust crate psl to v2.1.224 (#420) ([7a75450](https://github.com/pando85/passless/commit/7a754501f46c1c820421fb36195f1d8473052f31))

## [v0.15.1](https://github.com/pando85/passless/tree/v0.15.1) - 2026-08-05

### Fixed

- Advertise dynamic built-in UV state (#395) ([19f4a14](https://github.com/pando85/passless/commit/19f4a14e71ecef8186f27e6d4eab9be07faa7654))

### Documentation

- Add credential backup and backup-eligibility guide (#391) ([6db1c32](https://github.com/pando85/passless/commit/6db1c32e681cb5148f2be0693e89b09ff882c3a3))

### Build

- deps: Update Rust crate base64 to v0.23.1 (#392) ([e8dca3a](https://github.com/pando85/passless/commit/e8dca3a691bfb53502896e5434f98d063b8f17f5))
- deps: Upgrade soft-fido2 to 0.17.0 (#397) ([9b0e218](https://github.com/pando85/passless/commit/9b0e218b2f86e782168b1375884dd695486d2b38))

## [v0.15.0](https://github.com/pando85/passless/tree/v0.15.0) - 2026-08-01

### Added

- Add encrypted credential backup and restore (#383) ([6f707d6](https://github.com/pando85/passless/commit/6f707d6495bb7171dd1440a96288f708a9a086a1))

### Build

- deps: Update Rust crate clap to v4.6.5 (#381) ([e0d8e2d](https://github.com/pando85/passless/commit/e0d8e2d0b507a671fb5823b056497a6d7745b4dc))
- deps: Update soft-fido2 to 0.16.1 (#387) ([51b6e41](https://github.com/pando85/passless/commit/51b6e419bedbb9f622b4125115a6508cbcac30d6))

## [v0.14.0](https://github.com/pando85/passless/tree/v0.14.0) - 2026-07-31

### Added

- agent: Implement CDP port exposure mode (ADR 0004) (#361) ([09fc630](https://github.com/pando85/passless/commit/09fc630b37b16b0c87f1589fa341d2988bf52bf3))
- tpm: Add portable TPM-resident credential key backend (#354) ([7147b31](https://github.com/pando85/passless/commit/7147b31a40ab33749067645e5d0f85c58d492a0c))
- Add portable TPM credential key provider foundation (#352) ([34d99c3](https://github.com/pando85/passless/commit/34d99c3f1b175c6cf8ed0a8da1522f54eb81ecbc))

### Fixed

- notification: Make Dunst UP prompts actionable (#375) ([e27ed11](https://github.com/pando85/passless/commit/e27ed1115fa9df1c7f9a76f1a6ac50e30bcdaed9))
- pass: Refresh credential index after external sync (#379) ([44161d0](https://github.com/pando85/passless/commit/44161d098b97802f02ebc82edf957a0439f932fc))
- storage: Prevent RP ID path traversal and symlink escape (#334) ([0c41375](https://github.com/pando85/passless/commit/0c41375dd02d3be1f0da47040a951ea3b4d0d197))
- Cfg-gate E2E_AUTO_ACCEPT_STORAGE_ENV to release build unused constant warning (#331) ([f9e540d](https://github.com/pando85/passless/commit/f9e540d0d0b689978d89fb51a08acd4ecd91f14a))
- Update soft-fido2 to 0.14.0 to fix UV retry reset (#344) ([851d554](https://github.com/pando85/passless/commit/851d5546a9c1116ed503a46023889d43c7601618))
- Enforce pass-compatible hierarchical .gpg-id recipient resolution (#351) ([73b30b7](https://github.com/pando85/passless/commit/73b30b72dc8d196a53f020a4fe4e5d68445862ba))
- Allow uv-reset without PIN when no PIN is configured (#366) ([eebe2be](https://github.com/pando85/passless/commit/eebe2be3fdbfe081cc99b9af857eb730c9e2557a))

### Documentation

- TEE hardware compatibility analysis for post-2021 Intel Core processors (#313) ([99b1416](https://github.com/pando85/passless/commit/99b141696b901a240c0395ba941f6f88883266ad))
- Clarify WebAuthn client compatibility and credentialsd integration (#353) ([65d1ca7](https://github.com/pando85/passless/commit/65d1ca75442194819b44b765be047828af031769))
- Expand Android section and professionalize TEE compatibility doc (#364) ([58a3be9](https://github.com/pando85/passless/commit/58a3be9ffc8bbc206bd6837509d9880a877cab61))

### Build

- deps: Update KSXGitHub/github-actions-deploy-aur action to v4.2.0 (#311) ([68a49e0](https://github.com/pando85/passless/commit/68a49e0c79b27bee7c39228ac67446cef8cf3ac5))
- deps: Update Rust crate toml to v1.1.3 (#315) ([de9a7dc](https://github.com/pando85/passless/commit/de9a7dcd76ae7e5084804f1172d1f1b86da54645))
- deps: Update Rust crate syn to v2.0.119 (#316) ([3d43c9a](https://github.com/pando85/passless/commit/3d43c9a83f6d051a4c3da83a1033a0338a27d2f7))
- deps: Update Rust crate clap to v4.6.2 (#317) ([3876373](https://github.com/pando85/passless/commit/3876373d82ecbbc636f2c9482969b5ad32d0eeb3))
- deps: Update Rust crate thiserror to v2.0.19 (#321) ([0cc92ec](https://github.com/pando85/passless/commit/0cc92eceb88cef38b9159ea406b2db5aaa936f59))
- deps: Update Rust crate serde to v1.0.229 (#320) ([7234093](https://github.com/pando85/passless/commit/7234093ba67f4e65db8429e7c366fb2e7b929138))
- deps: Update Rust crate quote to v1.0.47 (#323) ([2d5d3e5](https://github.com/pando85/passless/commit/2d5d3e576a0a952feceba216fd158bea68b30efa))
- deps: Update Rust crate proc-macro2 to v1.0.107 (#322) ([0dee97a](https://github.com/pando85/passless/commit/0dee97a322e18f903ac1ca0691fef5204a941fb8))
- deps: Update Rust crate syn to v3 (#324) ([dce6259](https://github.com/pando85/passless/commit/dce6259479db664dd6591a10743507aa8352cedc))
- deps: Update dependency @simplewebauthn/server to v13.3.2 (#326) ([de58525](https://github.com/pando85/passless/commit/de585254606bb893abe742bf96e5ec0403c68c28))
- deps: Update Rust crate psl to v2.1.219 (#327) ([168a571](https://github.com/pando85/passless/commit/168a571957d801f026b8809d51208ac98cc023c0))
- deps: Update Rust crate tokio to v1.53.0 (#329) ([6986eb9](https://github.com/pando85/passless/commit/6986eb9329f1071198eb899e95a95955c83f6a45))
- deps: Update Rust crate zbus to v5.18.0 (#330) ([843617e](https://github.com/pando85/passless/commit/843617e06758ac40f619c4fd959cd679060a946a))
- deps: Update actions/setup-node action to v7 (#332) ([574cbfb](https://github.com/pando85/passless/commit/574cbfb23b7674387cdf742788e4cbceda72d247))
- deps: Update dependency node to v24 (#333) ([d8aea99](https://github.com/pando85/passless/commit/d8aea99092ea5bc312a0de203243f3b3d2b82651))
- deps: Update Rust crate syn to v3.0.1 (#335) ([42868bf](https://github.com/pando85/passless/commit/42868bf4af7e4a7534d48eb63b81de09e24c56a9))
- deps: Update Rust crate syn to v3.0.2 (#337) ([2aedb4a](https://github.com/pando85/passless/commit/2aedb4ae6714aa77baf4fd1dd3003772f32581ac))
- deps: Update dependency ubuntu to v24 (#336) ([8f58443](https://github.com/pando85/passless/commit/8f5844371e4825ec0a2ac0f64d8fc2b1c00fb2f9))
- deps: Update actions/setup-python action to v7 (#338) ([e259ae4](https://github.com/pando85/passless/commit/e259ae4da347345a15fe5b5b93745ae28d77d98d))
- deps: Update Rust crate serde_json to v1.0.151 (#340) ([2848f17](https://github.com/pando85/passless/commit/2848f175c5a0700e299cb548b72befccc9fbcf0c))
- deps: Update Rust crate clap to v4.6.3 (#339) ([fb237f4](https://github.com/pando85/passless/commit/fb237f4e2089ea033ee2b2bf99919265dd45d8df))
- deps: Update Rust crate tokio to v1.53.1 (#342) ([c53d1d5](https://github.com/pando85/passless/commit/c53d1d5984cd539c3648d1b41e7c9e21300c5326))
- deps: Update Rust crate libc to v0.2.187 (#341) ([0acf734](https://github.com/pando85/passless/commit/0acf734400918fc7bd74a89a0270f1005b3a88ca))
- deps: Update Rust crate libc to v0.2.188 (#343) ([39248f5](https://github.com/pando85/passless/commit/39248f51259c0987edad72acb466f5d1b3179e31))
- deps: Update Rust crate clap to v4.6.4 (#347) ([c9fc42d](https://github.com/pando85/passless/commit/c9fc42d89704d5c58c841debf6aeb49a5893bfb6))
- deps: Update Rust crate libc to v0.2.189 (#348) ([ca6aa66](https://github.com/pando85/passless/commit/ca6aa66111ef75d4380173044b3ee71014de6c10))
- deps: Update Rust crate psl to v2.1.220 (#349) ([090337f](https://github.com/pando85/passless/commit/090337f443fb5fe572c036da8489a6f6b9bb0e08))
- deps: Update Rust crate syn to v3.0.3 (#350) ([c3c6653](https://github.com/pando85/passless/commit/c3c6653118120f314b7394feaebf2ecdb8e9e70a))
- deps: Update Rust crate base64 to 0.23 (#358) ([0cf7744](https://github.com/pando85/passless/commit/0cf7744190eaaf6aa96225c39ec36603a35bc657))
- deps: Update Rust crate aes to v0.9.1 (#359) ([d33c6ff](https://github.com/pando85/passless/commit/d33c6ff3e578d73f885e98a563098f679ff79630))
- deps: Update Rust crate psl to v2.1.221 (#360) ([d07b71d](https://github.com/pando85/passless/commit/d07b71d5d1d2ddb0665f8a418230d034e1a27768))
- deps: Update Rust crate psl to v2.1.222 (#362) ([e3bf7d9](https://github.com/pando85/passless/commit/e3bf7d99ac59d23547be31cc681351ca2a89eb89))
- deps: Update clechasseur/rs-clippy-check action to v6.0.6 (#367) ([7d3ea69](https://github.com/pando85/passless/commit/7d3ea69e575a40d5a40e898fa9cf6a85376bb032))
- deps: Update Rust crate aes to v0.9.2 (#368) ([1f73f22](https://github.com/pando85/passless/commit/1f73f225a6a97fa8c968867ab26963df2e615e6a))
- deps: Update Rust crate psl to v2.1.223 (#371) ([b389b03](https://github.com/pando85/passless/commit/b389b0344fcb8eacd8bf0a49b7f1ca9aae5fcfd1))
- deps: Update Rust crate clap_complete to v4.6.8 (#372) ([aae99ee](https://github.com/pando85/passless/commit/aae99ee1be0caf7707517aa29f0b1b8f50153c0f))
- deps: Update Rust crate toml to v1.1.4 (#374) ([9c3c392](https://github.com/pando85/passless/commit/9c3c3929f3619d5507811cd2e7246cfa67a2e225))
- deps: Update actions/stale action to v11 (#373) ([b83aa84](https://github.com/pando85/passless/commit/b83aa8445e8cdfee51dce482dfd33d79d036d221))
- deps: Update Rust crate darling to 0.24 (#378) ([d6a5aaf](https://github.com/pando85/passless/commit/d6a5aaf2b5de8d55a9244db4f1b4982858c450fc))

### Chore

- Update Cargo.lock (#328) ([1432bec](https://github.com/pando85/passless/commit/1432bece7b9ec54bc0e3cd223740a58d9868b598))

## [v0.13.0](https://github.com/pando85/passless/tree/v0.13.0) - 2026-07-12

### Added

- pin: Make UV retry limit configurable (#303) ([95319ae](https://github.com/pando85/passless/commit/95319aef6e7f696ef716bf80422ae2a86293368e))

### Fixed

- runtime: Prevent concurrent daemons from sharing backend state (#305) ([14c2d93](https://github.com/pando85/passless/commit/14c2d9392f715d38e98f20f5002d9b8159bf888d))
- uv: Make UV retry exhaustion visible and preserve UV-blocked errors (#304) ([f72532b](https://github.com/pando85/passless/commit/f72532bab1b81498aa329092e5d7d68fed4736cb))

### Documentation

- Add runtime permissions and hardened setup guide (#299) ([c5b7b3a](https://github.com/pando85/passless/commit/c5b7b3a97ef87ef614f66f745d84317823202de5))

### Chore

- Improve release tooling for shallow clones (#296) ([ff430f0](https://github.com/pando85/passless/commit/ff430f04a3dba4e8c98e9c8bfd01e3c90dcbea08))

## [v0.12.0](https://github.com/pando85/passless/tree/v0.12.0) - 2026-07-06

### Added

- Add authenticated uv retry reset (#295) ([6ea14bf](https://github.com/pando85/passless/commit/6ea14bf7c99bbf9f3c12fa5d17a424f7d0816f83))

### Fixed

- Add user directories to PATH in systemd service (#278) ([03ac850](https://github.com/pando85/passless/commit/03ac8504e74b26e18ff9cb033091b05ce6581f79))

### Documentation

- Add Android passkey compatibility section to README (#291) ([4e5cad4](https://github.com/pando85/passless/commit/4e5cad4061fc5f4270971399a6aa5486e30950e0))

### Build

- deps: Update Rust crate rpassword to v7.5.4 (#274) ([98bda86](https://github.com/pando85/passless/commit/98bda86169c27fc13d65da7ece9ce96c42f6761e))
- deps: Update Rust crate log to v0.4.31 (#275) ([4ca1cfa](https://github.com/pando85/passless/commit/4ca1cfa2c2191156dddd7d8cc8c465f64e173ebb))
- deps: Update Rust crate log to v0.4.32 (#276) ([a592636](https://github.com/pando85/passless/commit/a592636a55ad97e9e98a229ec58447e867ce944a))
- deps: Update Rust crate zeroize to v1.9.0 (#279) ([fe2572a](https://github.com/pando85/passless/commit/fe2572a86c0377a78131925fdc2942db8a51cdec))
- deps: Update Rust crate notify-rust to v4.18.0 (#281) ([f127707](https://github.com/pando85/passless/commit/f1277077013af060608c8bab60ad14212d2608ba))
- deps: Update Rust crate syn to v2.0.118 (#280) ([349dc1f](https://github.com/pando85/passless/commit/349dc1f62a65da816510e53233854323e5d82048))
- deps: Update actions/checkout action to v7 (#282) ([34958dc](https://github.com/pando85/passless/commit/34958dc474d6197d023955b4f416a69ba07e5434))
- deps: Update Rust crate log to v0.4.33 (#283) ([8ad2861](https://github.com/pando85/passless/commit/8ad2861a0b6306f406abda7f45cb3b2e1ecbc1b0))
- deps: Update Rust crate quote to v1.0.46 (#284) ([d97eb18](https://github.com/pando85/passless/commit/d97eb184a144cd6c6b10a3f3e444c4f5100bf22a))
- deps: Update actions/cache action to v6 (#285) ([248d01f](https://github.com/pando85/passless/commit/248d01fcf48aa6e741b6ab2bd9133f2a1be45cc0))
- deps: Update clechasseur/rs-clippy-check action to v6.0.5 (#286) ([1ac1b1b](https://github.com/pando85/passless/commit/1ac1b1b58bfa77484fdaecbae4637a3dcdb4f5f8))
- deps: Update pre-commit hook alessandrojcm/commitlint-pre-commit-hook to v9.26.0 (#287) ([9bd8637](https://github.com/pando85/passless/commit/9bd86373459f8ddb3752909504b7305980568f90))
- deps: Update Rust crate env_logger to v0.11.11 (#288) ([36a298a](https://github.com/pando85/passless/commit/36a298a8b787378dba4e193cb4d5722164b4122b))
- deps: Update Rust crate aes-gcm to 0.11 (#289) ([e282356](https://github.com/pando85/passless/commit/e2823567f0f5e3107424aa89633c5a61981684af))
- deps: Update Rust crate clap_complete to v4.6.6 (#292) ([10b1be2](https://github.com/pando85/passless/commit/10b1be2530f9f1c4328503d64fbdac5d2db74ebd))
- deps: Update Rust crate clap_complete to v4.6.7 (#293) ([499c73f](https://github.com/pando85/passless/commit/499c73fa183fd687481e1ee55e0e3cb79610c90e))

## [v0.11.2](https://github.com/pando85/passless/tree/v0.11.2) - 2026-05-28

### Fixed

- Improve logging and TPM performance for browser freeze issue (#272) ([5a44ef5](https://github.com/pando85/passless/commit/5a44ef5add3199cb0b0ace4fa5b421820bc388b3))

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
