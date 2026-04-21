# Trust Tooling

This guide is for post-integration verification workflows. It is most useful after you already understand the shell-first execution boundary and want stronger proof, signing, or operator-visible diagnostics.

---

`agent-guard` now ships a small trust workflow around three artifacts:

- **policy**: the YAML rules the guard enforces
- **receipt**: a signed execution record emitted after sandboxed execution
- **doctor report**: a host-level capability snapshot for operators and reviewers

If you want teams to move from “it seems safe” to “we can verify what happened,” this is the shortest path.

---

## 1. Generate Keys

Use `guard-verify` to create an Ed25519 keypair:

```bash
cargo run -p guard-verify -- keygen --output guard-signing.key
```

This writes the private key to `guard-signing.key` and prints the corresponding public key.

Recommended practice:

- keep the private key outside your repo
- distribute the public key to services that need to verify policy or receipts
- rotate keys by policy version, not ad hoc

---

## 2. Sign A Policy

Create a detached signature for `policy.yaml`:

```bash
cargo run -p guard-verify -- sign-policy \
  --policy policy.yaml \
  --private-key guard-signing.key \
  --output policy.yaml.sig
```

You can then load that policy through the signed-policy APIs:

- Rust SDK: `Guard::from_signed_yaml()` / `Guard::from_signed_yaml_file()`
- Node: `Guard.fromSignedYaml()` / `Guard.fromSignedYamlFile()`
- Python: `Guard.from_signed_yaml()` / `Guard.from_signed_yaml_file()`

Behavior:

- `check` mode keeps working, but exposes `policy_verification_status`
- `enforce` mode fails closed when signature verification is invalid
- adapter `auto` mode also fails closed on invalid policy verification

---

## 3. Verify Receipts

If a signing key is configured on the guard, sandboxed execution can emit signed receipts.

Inspect a receipt:

```bash
cargo run -p guard-verify -- inspect --receipt receipt.json
```

Verify it against the public key:

```bash
cargo run -p guard-verify -- verify \
  --receipt receipt.json \
  --public-key <public-key-hex>
```

Receipt lifecycle:

1. policy is evaluated
2. execution runs in the selected sandbox
3. the execution context is signed into a receipt
4. auditors can independently verify that receipt later

---

## 4. Generate Doctor Reports

The `doctor` command exposes a stable report interface for the current host:

```bash
cargo run -p guard-verify -- doctor --format text
cargo run -p guard-verify -- doctor --format json
cargo run -p guard-verify -- doctor --format html --output agent-guard-report.html
```

Use the formats like this:

- `text`: operator triage in a terminal
- `json`: machine-readable checks in CI or internal tooling
- `html`: stakeholder review and screenshots

---

## 5. Move From Check To Enforce

A practical rollout is:

1. start in `check` mode for shell or high-risk tools
2. inspect denied / ask-required decisions and refine policy
3. sign the policy before moving sensitive flows into `enforce`
4. enable receipt signing for environments that need proof
5. attach doctor reports to deployment or review workflows

That sequence gives you a cleaner migration path than enabling sandbox enforcement first and explaining the host boundary later.
