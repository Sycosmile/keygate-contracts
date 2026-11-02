# keygate-contracts

[![CI](https://github.com/TeethakingBuilds/keygate-contracts/actions/workflows/rust.yml/badge.svg)](https://github.com/TeethakingBuilds/keygate-contracts/actions/workflows/rust.yml)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![status: unaudited 0.1](https://img.shields.io/badge/status-unaudited%200.1-orange)](./SECURITY.md)

Capability-based access control for [Soroban](https://soroban.stellar.org) smart contracts on the Stellar network.

Instead of every business contract hard-coding "is this the owner?", a keygate deployment answers one question: **may this address perform this action on this resource right now?**

## The model

A **capability** is a triple `(resource, action, holder)` carrying an expiry. `resource` and `action` are free-form strings chosen by the integrator (`"vault:main"` / `"withdraw"`, `"issuer:acme"` / `"mint"`), so the registry is not tied to any particular notion of a role.

Three contracts compose into an authorisation stack:

```
caller ──▶ keygate-policy ──▶ keygate-core ──▶ keygate-circuit-breaker
            "do we permit       "does the        "has this resource
             this action at      holder still     exceeded its budget
             all right now?"      hold it?"        in this window?"
```

| crate | role |
| --- | --- |
| [`keygate-core`](./keygate-core) | Capability registry: issue, renew, revoke, check. Two-step admin handover, freeze switch. |
| [`keygate-policy`](./keygate-policy) | Allow/deny rules per `(resource, action)` in front of a registry. Deny takes an action out of service without touching hundreds of grants. |
| [`keygate-circuit-breaker`](./keygate-circuit-breaker) | Rolling-window budgets that **latch closed** when breached, and stay closed until an explicit reset. |
| [`keygate-multisig`](./keygate-multisig) | m-of-n administration. Relays arbitrary calls (`target`, `func`, encoded `args`) so the registry's admin key is never held by one person. A proposal that targets the multisig itself is applied inline, because Soroban will not let a contract re-enter itself. |

## Why the layers are separate

Keeping policy apart from the registry answers two different questions. The registry asks *does this holder have the capability*; policy asks *do we want that capability to be usable at all right now*. An incident response is one `Deny` rule rather than a bulk revocation, and deleting the rule restores exactly the prior state.

The breaker trips instead of merely rejecting. A `require(amount <= limit)` line stops one withdrawal; a latched breaker stops the draining that follows.

## Getting started

```bash
cargo build --workspace          # host build, for tests
make optimize                    # release wasm for deployment
make check                       # fmt + clippy -D warnings + test
```

Requires a current stable Rust toolchain; `rust-toolchain.toml` pins `rustfmt`, `clippy` and the `wasm32-unknown-unknown` target, so `rustup` provisions everything on first build. `Cargo.lock` is committed and CI builds `--locked` — the SDK's own dependency ranges do not resolve to a compilable graph on their own, so the lockfile is part of the build, not a nicety.

### Deploying

```bash
cargo build --release --target wasm32-unknown-unknown
# then, with the Soroban CLI:
soroban contract deploy --wasm target/wasm32-unknown-unknown/release/keygate_core.wasm
soroban contract invoke --id <core> -- initialize --admin <GADDRESS>
soroban contract invoke --id <core> -- issue \
  --resource "vault:main" --action "withdraw" --holder <GADDRESS> --ttl 3600
soroban contract invoke --id <core> -- check \
  --resource "vault:main" --action "withdraw" --holder <GADDRESS>
# true
```

## Composition inside another contract

`require_access` is the entry point other contracts should call — it authenticates the caller and fails closed:

```rust
let core = KeygateCoreClient::new(env, &core_address);
core.require_access(&caller, &resource, &action);

let breaker = KeygateBreakerClient::new(env, &breaker_address);
if breaker.enforce(&resource, &amount) == Outcome::Breached {
    // Skip the transfer, do not fail the call. A caller that returns an error
    // here reverts the breaker's own frame, and the latch goes with it.
    return Ok(());
}
```

Admin operations on keygate contracts should be routed through `keygate-multisig` and authorised by the multisig's own contract address rather than by a single user key.

## Status and scope

Version 0.1.0. All four crates are covered by unit tests — eighty-five of them, against the SDK's own `Env` — but **this code is unaudited** — read [SECURITY.md](./SECURITY.md) before holding real value with it. Deliberate limitations:

- Capability expiry is reclaimed lazily, on the first `check` of an expired grant. There is no background sweep, so a grant that is never queried stays in storage.
- `keygate-policy` trusts the registry address it was configured with. Repointing it is an admin action and is emitted as an event for indexers.
- A breaker breach is a **value** (`Outcome::Breached`), not an error, because a call that errors loses its writes and would lose the latch with them. That means a guarded call is stopped by the *caller* honouring the outcome; a caller that ignores it spends past its limit once, before the latch shuts everyone out. `enforce` has no way to close that gap on its own — see [SECURITY.md](./SECURITY.md).
- Authorisation itself (`require_auth`) is enforced by the Soroban host. Unit tests mock all auths, so the cryptography of a signature is the host's to prove, not ours. What the tests do pin down is the authority side: every entry point that calls `require_auth` has a test asserting, through `env.auths()`, which address had to sign and for which function and arguments.

## Documentation

- [CONTRIBUTING.md](./CONTRIBUTING.md) — development setup, code style, how to add a crate
- [SECURITY.md](./SECURITY.md) — vulnerability reporting and threat model
- [SUPPORT.md](./SUPPORT.md) — where to ask questions
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)

## License

Apache-2.0. See [LICENSE](./LICENSE).
