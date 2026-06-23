# SEP-2828 second-issuer recompute spike (x402 PR #2666)

Demonstrates that agent-guard can act as an **independent second issuer** of the
SEP-2828 receipts that x402 PR #2666 ("Settlement-Receipt Binding Extension")
binds to — turning the spec's §7 *producer-agnostic* property from "shown with
one issuer (Vaara)" into "demonstrated across two independent codebases".

## What it does

`src/main.rs` reads the **committed** x402 settlement records from
`vaaraio/vaara` tag `v1.1.1` (commit `088a869`), and for each rail/step issues a
SEP-2828 receipt:

- `decisionDerived.evidenceRef.digest` = `sha256(JCS(settlement))` over the
  committed settlement bytes (RFC 8785 via `serde_jcs`).
- `decisionDerived.decision` is mapped from `agent_guard_core::GuardDecision`
  (`Allow→allow`, `Deny→deny`, `AskUser→escalate`) — agent-guard is the issuer.
- Signed **ES256** (ECDSA P-256 / SHA-256, raw R‖S, 128-hex) over
  `JCS({version, alg, backLink, decisionDerived, issuerAsserted})` with
  agent-guard's **own** key, written to `vectors/keys/es256_public.pem`.

The settlement records are reused unchanged; only the receipt and its signing
key are agent-guard's.

## Run

```sh
cargo run                              # issue 4 receipts + write agent-guard's ES256 pubkey
python3 -m venv .venv && ./.venv/bin/pip install rfc8785 cryptography
./.venv/bin/python vectors/_check_independent.py   # the pinned, unmodified checker
```

Expected: every verdict `[OK]`, exit `0`:

```
[OK] generic.step0.action_ref_recomputes / settlement_binding_resolves / receipt_signature_ok
[OK] generic.step1.* ; generic.lifecycle_distinguishes_terminal
[OK] sui.step0.* ; sui.step1.* ; sui.lifecycle_distinguishes_terminal
all verdicts matched expected
```

`_check_independent.py`, `expected.json`, and the four `settlement.json` files
are vendored verbatim from the v1.1.1 pin; the checker imports neither x402 nor
agent-guard (stdlib + `rfc8785` + `cryptography`).

## Scope boundary (read before citing)

Passing the checker proves the receipt **shape** is producer-agnostic: ES256 over
JCS of the five blocks, the evidenceRef digest, and the action_ref recompute all
reproduce from committed bytes under a second issuer's key. It does **not** prove
end-to-end attestation-instance binding — the checker never resolves `backLink`
to a real `ExecutionProof`, so `backLink` / `issuerAsserted` here are
issuer-populated, not bound to a live agent-guard attestation. That deeper
Check-A instance binding is intentionally out of scope for this spike.

This is a standalone crate (own `[workspace]` root); it adds no ES256/JCS
dependencies to the shipped agent-guard crates and touches none of the existing
signing core (`provenance.rs` / `attestation.rs` / `proof.rs`).
