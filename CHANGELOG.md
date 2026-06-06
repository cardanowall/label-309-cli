# Changelog

All notable changes to the Label 309 CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall` (the CLI) is pre-1.0. The command surface,
> flags, and output may change in backward-incompatible ways until a 1.0 release.
> Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-06-06

### Changed

- Track the `cardanowall` SDK 0.3.0, which implements the finalized sealed-PoE scheme-1 construction (a breaking wire-format change for sealed envelopes) and hardened recipient decryption. The command surface and flags are unchanged.

## [0.2.0] - 2026-06-04

### Changed

- Rebranded to **Label 309** (help text and documentation). The `cardanowall` binary name and command set are unchanged.

## [0.1.0] - 2026-06-02

### Added

- Initial public release of the Label 309 CLI (binary `cardanowall`).
