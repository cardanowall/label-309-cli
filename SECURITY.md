# Security Policy

`cardanowall` (the CLI) is a command-line tool for CIP-309, a standard for
cryptographic Proof of Existence. People rely on its `verify` verdict to decide
whether a proof is trustworthy, so we take reports seriously and ask that they be
handled responsibly.

## Scope

This repository holds the **command-line tool** (crate `cardanowall-cli`, binary
`cardanowall`): argument parsing, secret-input hygiene, output rendering, and the
exit-code contract. The cryptographic and verification logic lives in the Rust
SDK crate `cardanowall` (the `cip309-rs` repository), which this CLI is built on.

In scope for a report here:

- A flaw in the CLI that lets a user be misled about a proof — for example a
  verdict-to-exit-code mapping that reports success on a failed verification, or
  output that misrepresents what was checked.
- A secret-handling flaw: a seed or recipient key being logged, echoed, written
  with unsafe permissions, or otherwise exposed by the CLI.
- A weakening of the CLI's secure-by-default egress (the SSRF guard / deny-host
  policy as surfaced through CLI flags and configuration).

Out of scope here (report it in the relevant repository instead):

- A flaw or ambiguity in the **standard** itself — report it in the `cip309`
  standard repository.
- A bug in the verification or cryptographic logic — that lives in the Rust SDK;
  report it in the `cip309-rs` repository. The TypeScript and Python SDKs live in
  `cip309-ts` and `cip309-py`.

## Core security goals

A report is **high priority** if it undermines any of the standard's core
guarantees as surfaced by this tool:

- **Standalone verifiability** — `verify` proves a record from the transaction
  metadata, the optional content bytes, and a public blockchain explorer alone.
- **Zero issuer trust** — verifying a proof never requires trusting the
  publisher, their domain, or any server, and the deny-host policy cannot be
  bypassed to force a single operator.
- **Secret hygiene** — seeds and recipient keys are never required on argv and
  are never logged or persisted insecurely.

## Reporting a vulnerability

**Please report privately. Do not open a public issue for a security report.**

Preferred channel: GitHub's **private vulnerability reporting** for this
repository (the *Security* tab → *Report a vulnerability*).

Alternative contact: `hello@cardanowall.com`.

Please include, as far as you can:

- A clear description of the issue and the security property it breaks.
- The exact location — command, module, or test — and a minimal reproduction.
- The impact and, if you have one, a suggested remediation.

## What to expect

- We aim to acknowledge a report promptly and to keep you informed as we
  investigate.
- We practise **coordinated disclosure**: we will agree a disclosure timeline
  with you, fix the issue, and credit you unless you prefer otherwise.
- Because this tool is **pre-1.0**, there are no long-term-supported released
  versions yet; fixes land on the current line.

Thank you for helping keep CIP-309 trustworthy.
