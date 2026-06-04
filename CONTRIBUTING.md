# Contributing to the Label 309 CLI

Thank you for your interest in improving `cardanowall`, the command-line tool for
**Label 309** — an open standard for **Proof of Existence (PoE)** anchored on the
Cardano blockchain.

This tool is **pre-1.0**. It is a thin argument-parsing and output shell over the
Rust Label 309 SDK (the `cardanowall` crate, from the `label-309-rs` repository): the
verifier, the cryptographic primitives, sealed-PoE, Merkle proofs, and the
gateway-agnostic HTTP client all live there. Bug fixes and features that concern
verification or cryptography belong in the SDK; this repository owns the CLI
surface.

All contributions are made under the terms in [Licensing](#licensing) and the
[Developer Certificate of Origin](#developer-certificate-of-origin-dco).

---

## What belongs in this repository

This repository is the **CLI** for Label 309. The command surface, argument
parsing, secret-input hygiene, output rendering, configuration, and the
exit-code contract belong here.

What does **not** belong here:

- **Verification or cryptographic logic**, the wire-format types, sealed-PoE, or
  Merkle code belong in the Rust SDK (`label-309-rs`). A divergence between the CLI's
  behaviour and the SDK is fixed by aligning the CLI to the SDK, not by
  re-implementing logic here.
- **Changes to the wire format, grammar, schemas, registries, or the conformance
  vectors** belong in the `label-309` standard repository. The vectors are
  authoritative; the goldens vendored under `tests/fixtures/` are byte-identical
  copies and must not be edited to make a test pass.
- **Issues in another implementation** belong in its repository — `label-309-ts`
  (npm) or `label-309-py` (PyPI).

If you are unsure, open an issue here and ask.

---

## Building and testing

A recent stable Rust toolchain is all you need; the CLI has no system
dependencies beyond the OS CSPRNG and uses `rustls` for TLS (no OpenSSL).

```sh
cargo build --all-targets --all-features
cargo test --all-features          # full suite, including the vendored goldens
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

CI runs exactly these. A pull request must pass all four.

### Exit-code contract and goldens

The exit-code contract (`0` valid / `1` integrity / `2` network / `3` pending /
`4` CLI input) is a public UX promise. The corpus-replay tests pin it against the
golden verify-reports vendored under `tests/fixtures/sdk-ts/verify-reports`,
which are byte-identical to the vectors the TypeScript and Python SDKs load. Do
not edit a golden to make a test pass: a mismatch means the CLI diverged. If you
believe a vector itself is wrong, raise it in the `label-309` standard repository.

---

## Pull request checklist

- [ ] The change is in the right repository (the CLI vs. the SDK vs. the
      standard).
- [ ] `cargo test`, `cargo clippy -D warnings`, and `cargo fmt --check` all pass.
- [ ] No conformance vector / golden was edited to force a test to pass.
- [ ] New behaviour is covered by a test; the exit-code contract is pinned
      against the vendored goldens.
- [ ] Secrets are never accepted on argv for new commands — follow the existing
      file / stdin / env / hidden-prompt resolution order.
- [ ] Every commit is signed off (see DCO below).

---

## Style and house rules

- Keep the CLI **gateway-agnostic**. Every networked command takes an explicit
  gateway base URL and an opaque API key; do not write behaviour around any
  particular hosted service.
- Never require a secret on the command line. argv leaks into shell history,
  `ps`, and CI logs; resolve seeds and recipient keys from a file, stdin, an
  environment variable, or a hidden interactive prompt.
- Cite only stable, public references — RFCs, CIPs at a permanent address,
  NIST/FIPS publications, BIPs, and the like.

---

## Developer Certificate of Origin (DCO)

This project uses the **Developer Certificate of Origin**. There is **no CLA**.

The DCO is a lightweight attestation that you have the right to submit your
contribution under the project's license. You make it by adding a
`Signed-off-by` line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

Add it automatically with `git commit -s`. The name and email must be real and
match the commit author. By signing off, you certify the statements in the
Developer Certificate of Origin, version 1.1:

> **Developer Certificate of Origin, Version 1.1**
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the
> right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my
> knowledge, is covered under an appropriate open source license and I have the
> right under that license to submit that work with modifications, whether
> created in whole or in part by me, under the same open source license (unless
> I am permitted to submit under a different license), as indicated in the file;
> or
>
> (c) The contribution was provided directly to me by some other person who
> certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public
> and that a record of the contribution (including all personal information I
> submit with it, including my sign-off) is maintained indefinitely and may be
> redistributed consistent with this project or the open source license(s)
> involved.

---

## Licensing

By contributing, you agree that your contributions are licensed under the
project's **Apache License 2.0** (see [`LICENSE`](LICENSE)).

---

## Code of Conduct

All participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
Please read it before contributing.

## Security

Do not report security-impacting issues through public issues or pull requests.
Follow the private process in our [Security Policy](SECURITY.md).
