# Lighthouse Historical Bug Audit

A categorization of bugs Lighthouse has hit over its lifetime, by **stack location** and **bug
class**, built by scanning sigp/lighthouse issues + PRs (open & closed), their conversations, and
the actual fix diffs. ~370 bugs catalogued. Goal: find ways to catch these classes of bug earlier
and surface structural problems.

## Start here
- **[MASTER-REPORT.md](MASTER-REPORT.md)** — cross-cutting synthesis: the 12 recurring root-cause
  patterns, distribution by class/severity, the prioritized "catch them earlier" toolkit, and
  architectural smells. Read this first.
- **[STRUCTURAL-ANALYSIS.md](STRUCTURAL-ANALYSIS.md)** — phase 2: which patterns are *still
  structurally live in today's code* vs already fixed (re-verified against `unstable`), classified
  redesign / harness / process, weighted by severity × recency, with a priority order. Read second.
- **[SCHEMA.md](SCHEMA.md)** — the shared taxonomy and method each subsystem audit followed.

## Per-subsystem detail (full bug tables + deep dives + per-area synthesis)
| File | Scope |
|---|---|
| [consensus.md](consensus.md) | State transition, fork choice, block/attestation verification, non-finality |
| [networking.md](networking.md) | Gossipsub, discv5, RPC/req-resp, peer management, ENR |
| [sync.md](sync.md) | Range / backfill / lookup sync |
| [execution-layer.md](execution-layer.md) | Engine API, payloads, builder/MEV |
| [database.md](database.md) | Hot/cold store, pruning, schema migrations, tree-states |
| [validator-client.md](validator-client.md) | Duties, slashing protection, web3signer, multi-BN |
| [http-api.md](http-api.md) | Beacon/VC REST API, light-client endpoints, rewards API |
| [data-availability.md](data-availability.md) | Blobs, KZG, PeerDAS / data columns custody |
| [slasher-crypto-misc.md](slasher-crypto-misc.md) | Slasher, BLS/crypto, SSZ, runtime/panics, CLI |
| [critical-incidents-security.md](critical-incidents-security.md) | `security`-label + worst real-world incidents with timelines |

## Caveats
- Counts are approximate; there is intentional overlap between the per-subsystem files and the
  cross-cutting incidents file (the same critical bug is analyzed from both angles).
- Severity ratings are the auditing agents' judgement, not an official Lighthouse classification.
- This is the *categorization* phase. Turning the §4 patterns into structural fixes is the next step.
