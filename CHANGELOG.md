# Changelog

All notable changes to the Label 309 CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall` (the CLI) is pre-1.0. The command surface,
> flags, and output may change in backward-incompatible ways until a 1.0 release.
> Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-06-12

### Changed

- Version alignment with the coordinated 0.5.0 release; no functional changes.

## [0.4.0] - 2026-06-11

### Changed

- Track the `cardanowall` SDK 0.4.0, which finalizes the sealed-PoE construction and de-chunks record fields (breaking wire-format changes — records sealed by earlier releases do not decrypt or verify under 0.4.0, and vice versa) and reworks verification around a four-state verdict.
- **BREAKING (`verify`):** Exit codes pair with the verdict — `0` valid, `3` pending, `2` unverifiable, `1` failed — and the `--json` report uses the reworked schema (camelCase fields, positional `items`/`merkle` results, severity-tagged issues). A deny-host violation dominates the outcome.
- `--no-fetch` governs content fetches only: item URIs, sealed ciphertext, and Merkle leaves-lists are not fetched (those claims report as not checked), while the transaction metadata is still resolved and verified on-chain.
- Seed inputs accept both the checksummed `L309-SEED-1…` form and raw hex.

### Added

- A run-global recipient keyring for sealed records: repeatable `--secret-key` (bare hex), `--secret-key-file`, and `--secret-key-stdin`; every supplied key is tried against every sealed item.

## [0.3.0] - 2026-06-06

### Changed

- Track the `cardanowall` SDK 0.3.0, which implements the finalized sealed-PoE scheme-1 construction (a breaking wire-format change for sealed envelopes) and hardened recipient decryption. The command surface and flags are unchanged.

## [0.2.0] - 2026-06-04

### Changed

- Rebranded to **Label 309** (help text and documentation). The `cardanowall` binary name and command set are unchanged.

## [0.1.0] - 2026-06-02

### Added

- Initial public release of the Label 309 CLI (binary `cardanowall`).
