# `cardanowall` — CIP-309 standalone verifier & Proof-of-Existence CLI

A single, fast, dependency-free native binary for working with **CIP-309 Proof
of Existence** on Cardano: verify a record, anchor a new one, sign off-host,
derive an identity from a seed, build/verify Merkle proofs, and read a sealed
inbox.

It is **gateway-agnostic**. Every networked command takes an explicit gateway
base URL and an opaque API key — the CLI is bound to no particular operator. The
hosted `cardanowall.com` service is one such gateway; any server that implements
the CIP-309 gateway API works the same way. **`verify` needs no gateway operator
at all** — it talks only to public Cardano explorers (Koios/Blockfrost) and
public Arweave/IPFS gateways, so a proof can be checked with zero trust in the
issuer, their domain, or their server.

Built on the Rust CIP-309 SDK (the `cardanowall` crate); a byte-parity twin of
the TypeScript and Python SDKs.

---

## Install

### From source (today)

```bash
# A release binary at target/release/cardanowall:
cargo build --release

# …or install `cardanowall` onto your PATH:
cargo install --path .
cardanowall --version          # cardanowall <ver> (git <sha>, built <date>)
```

Requires a recent stable Rust toolchain. No Node, no runtime, no network access
to install.

### Prebuilt binaries / crates.io

Tagged releases publish the crate to crates.io and attach prebuilt
per-platform binaries:

```bash
cargo install cardanowall-cli   # installs the `cardanowall` binary
```

Until the first tagged release, build from source as above.

---

## Quick start

```bash
# Inspect an identity derived from a 32-byte seed (offline, no network):
printf '%s' "$SEED_HEX" | cardanowall identity --seed-stdin

# Verify a proof against a public Cardano explorer (no operator server):
cardanowall verify <tx-hash> --cardano-gateway https://api.koios.rest/api/v1

# Save a gateway once, then anchor a file's hash through it:
cardanowall gateway add prod --base-url https://cardanowall.com   # prompts for the key
cardanowall submit --file ./contract.pdf --seed-stdin <<<"$SEED_HEX"
```

---

## Commands

Run `cardanowall <command> --help` for the full, authoritative flag list.

### `verify <tx-hash>`

Standalone verification of the CIP-309 record at a Cardano transaction. Fetches
the metadata from a public explorer, runs structural validation, checks record
signatures, and (with a recipient key) decrypts and re-hashes a sealed payload.

```bash
cardanowall verify <tx-hash> \
  --cardano-gateway https://api.koios.rest/api/v1 \   # repeatable; Koios-compatible
  --blockfrost <project-id> \                          # optional fallback
  --profile signed \                                   # core | signed | sealed | recipient-sealed
  --json --pretty
```

Sealed proofs: pass `--secret-key <hex>` (or `--secret-key-file` / `--secret-key-stdin`,
repeatable, `itemIndex:hex` or `hex`) to decrypt and recompute plaintext hashes.
`--no-fetch` skips all URI/leaves fetches (fully offline structural+signature check).

### `submit`

Anchor a new PoE through a gateway. Mutually exclusive modes:

```bash
cardanowall submit --hash <64-hex-digest>          # anchor a precomputed sha2-256 digest
cardanowall submit --file ./doc.pdf                # hash the file, then anchor
cardanowall submit --merkle ./leaves.txt           # build a Merkle tree, anchor root + leaves
```

Add `--seed` (or the safe variants below) to attach an Ed25519 record signature;
omit it to publish unsigned. Requires a gateway (`--base-url` + `--api-key`, env,
or a saved profile). `--alg blake2b-256` switches the content hash.

### `sign record | prepare | assemble`

Off-host PATH-1 (identity Ed25519) COSE signing — for air-gapped signing where the
keys never touch the gateway.

```bash
cardanowall sign record  --seed-stdin --in record.cbor --json   # sign in one step
cardanowall sign prepare --signer-pubkey <hex> --hash <hex>     # emit the sig-structure to sign elsewhere
cardanowall sign assemble --signer-pubkey <hex> --signature <hex> --in record.cbor
```

### `identity --seed`

Derive and print the public identity from a 32-byte master seed: Ed25519/X25519/
X-Wing public keys, both age recipient strings, and a short display fingerprint.
Fully offline; no network, no API key. `--json` emits the full X-Wing key.

### `merkle build | verify`

```bash
cardanowall merkle build  --in leaves.txt --json            # root + canonical leaves-list
cardanowall merkle verify --root <hex32> --leaf <hex32> --proof proof.json
```

### `inbox sync | list | decrypt`

Discover, list, and decrypt sealed PoE addressed to your identity. Raw-seed-first:
identify with `--seed <hex>` or a raw `--secret-key <hex>` (plus the `-file`/`-stdin`
variants) — never an account envelope.

```bash
cardanowall inbox sync   --seed-stdin
cardanowall inbox list   --seed-stdin --json
cardanowall inbox decrypt <tx-hash> --secret-key-stdin
```

`sync` persists a per-identity cursor under `~/.cardanowall/<id>/inbox.json`.

### `gateway add | use | list | show | remove`

Named gateway profiles (an endpoint + its API key). This is configuration, not a
login — the gateway API is key-based.

```bash
cardanowall gateway add prod --base-url https://cardanowall.com   # hidden key prompt
cardanowall gateway add prod --base-url https://cardanowall.com --api-key-stdin <<<"$KEY"  # for CI
cardanowall gateway use prod
cardanowall gateway list                 # keys masked
cardanowall gateway show prod --reveal   # print the key
```

### `completion <bash|zsh|fish|powershell>`

Print a shell completion script to stdout.

```bash
cardanowall completion zsh  > ~/.zfunc/_cardanowall
cardanowall completion bash > /etc/bash_completion.d/cardanowall
```

---

## Secrets & safety

Secrets are **never required as a command-line argument** — argv leaks into shell
history, `ps`, and CI logs. Every command that needs a seed or recipient key
resolves it in this order:

1. `--seed-file <path>` / `--secret-key-file <path>` (read from a file)
2. `--seed-stdin` / `--secret-key-stdin` (or the value `-`) — read from stdin
3. the matching environment variable (see below)
4. a **hidden interactive prompt** — only on a TTY, when the secret is required
5. otherwise, a clear error pointing at options 1–3

The raw `--seed <hex>` / `--secret-key <hex>` flags still exist for throwaway/test
values (e.g. inspecting a public test vector with `identity`) but are documented
as **insecure** and should not carry a real key.

The moderately-sensitive API key may be stored in a gateway profile; that file is
written with `0600` permissions and the key is masked in `list`/`show`.

---

## Configuration & precedence

Config lives at `~/.cardanowall/config.toml` (override with `CARDANOWALL_CONFIG_PATH`),
written `0600`:

```toml
default_gateway = "prod"

[gateways.prod]
base_url = "https://cardanowall.com"
api_key  = "…"                       # stored only if you saved one

# Public data sources used by `verify` / `inbox` (each string or list):
cardano_gateway = ["https://api.koios.rest/api/v1"]
arweave_gateway = "https://arweave.net"
ipfs_gateway    = "https://ipfs.io"
```

Resolution precedence for every value: **explicit flag → environment variable →
active gateway profile → built-in default** (the built-in default applies to the
public data gateways only; a service `--base-url`/`--api-key` has no default).

---

## Environment variables

Consistent across every command:

| Variable                                   | Flag                | Meaning                          |
| ------------------------------------------ | ------------------- | -------------------------------- |
| `CARDANOWALL_BASE_URL`                     | `--base-url`        | service gateway base URL         |
| `CARDANOWALL_API_KEY`                      | `--api-key`         | opaque bearer API key            |
| `CARDANOWALL_SEED`                         | `--seed`            | 32-byte identity seed (hex)      |
| `CARDANOWALL_RECIPIENT_KEY`                | `--secret-key`      | X25519 recipient key(s)          |
| `CARDANOWALL_CARDANO_GATEWAY`              | `--cardano-gateway` | Koios-compatible explorer URL(s) |
| `CARDANOWALL_ARWEAVE_GATEWAY`              | `--arweave-gateway` | Arweave gateway URL(s)           |
| `CARDANOWALL_IPFS_GATEWAY`                 | `--ipfs-gateway`    | IPFS gateway URL(s)              |
| `CARDANOWALL_BLOCKFROST_PROJECT_ID`        | `--blockfrost`      | Blockfrost fallback              |
| `CARDANOWALL_CONFIRMATION_DEPTH_THRESHOLD` | `--threshold`       | confirmation depth               |
| `CARDANOWALL_DENY_HOST`                    | `--deny-host`       | extra egress deny-list entries   |
| `CARDANOWALL_CONFIG_PATH`                  | —                   | override the config file path    |

---

## Automation & JSON

- `--json` on any command emits machine-readable JSON on **stdout** (add `--pretty`
  to indent). Data goes to stdout; diagnostics go to stderr — pipe-clean.
- In `--json` mode, failures emit a structured error to **stderr**:
  `{"error":{"code":<exit>,"message":"…","command":"…"}}`.
- `--no-color` / `--color <auto|always|never>` and `-q/--quiet` are global. Color
  follows `NO_COLOR` / `CLICOLOR_FORCE` / TTY detection and is never emitted under
  `--json`.
- Provide secrets via env or stdin in CI; never on argv.

## Exit codes

| Code | Meaning                                                           |
| ---- | ----------------------------------------------------------------- |
| `0`  | valid / success                                                   |
| `1`  | integrity-class failure (a cryptographic/structural check failed) |
| `2`  | network-class failure (a fetch/transport error)                   |
| `3`  | pending (insufficient confirmations)                              |
| `4`  | CLI input error (bad arguments, missing required input)           |

`verify` maps the verifier's verdict straight through to `0/1/2/3`.

---

## Service independence

`verify` proves a record using only the transaction metadata, the (optional)
content bytes, and a public blockchain explorer. It contacts no issuer server and
honors a deny-list so it cannot be steered back to a single operator. A proof you
verified once stays verifiable by anyone, forever, with any CIP-309 tooling.

## Related repositories

This CLI is one of the CIP-309 reference projects:

- [`cip309`](https://github.com/cardanowall/cip309) — the CIP-309 standard:
  prose spec, CDDL, JSON schemas, registries, and the conformance vectors.
- [`cip309-rs`](https://github.com/cardanowall/cip309-rs) — the Rust SDK crate
  `cardanowall` this CLI is built on.
- [`cip309-ts`](https://github.com/cardanowall/cip309-ts) — the TypeScript SDKs.
- [`cip309-py`](https://github.com/cardanowall/cip309-py) — the Python SDK.

## License

Apache-2.0.
