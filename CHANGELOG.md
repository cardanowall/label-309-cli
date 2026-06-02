# Changelog

All notable changes to the CIP-309 CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** `cardanowall` (the CLI) is pre-1.0. The command surface,
> flags, and output may change in backward-incompatible ways until a 1.0 release.
> Pre-1.0 versions do not carry the stability guarantees of
> [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial public release of the CIP-309 CLI (binary `cardanowall`): standalone
  `verify`, gateway-agnostic `submit`, off-host `sign`, seed-derived `identity`,
  `merkle` build/verify, the raw-seed-first `inbox` (sync / list / decrypt),
  named `gateway` profiles, and shell `completion` generation.
- A stable exit-code contract (`0` valid / `1` integrity / `2` network / `3`
  pending / `4` CLI input), pinned against the shared verify-report goldens.
