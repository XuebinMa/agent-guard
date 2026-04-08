# Phase 8 Design: Trusted Computing & Deep Isolation (v0.3.0)

> Status: **Draft**  
> Target: **Enterprise-grade Provenance & Hardened Isolation**

---

## 1. M8.1: Remote Attestation & Execution Proofs

### Goal
Provide a verifiable audit trail that proves tool execution occurred within a specific sandbox environment and adhered to a signed policy.

### Components
1. **Policy Signing (Ed25519)**:
   - Administrators sign `policy.yaml` using a private key.
   - `agent-guard` refuses to load unsigned or improperly signed policies in "High-Trust" mode.
2. **Execution Proofs**:
   - For every tool call, the engine generates an `ExecutionProof`.
   - Contains `sha256(payload)`, `timestamp`, `sandbox_type`, and a cryptographic signature.
3. **Hardware Root of Trust (TPM 2.0)**:
   - Integrate PCR (Platform Configuration Register) measurements into the proof.
   - Prove the host environment has not been tampered with since boot.

---

## 2. M8.2: Linux Landlock & Enhanced Isolation

### Goal
Implement unprivileged, path-based access control to complement Seccomp-BPF.

### Features
1. **Landlock Integration**:
   - Restrict file access (Read/Write/Execute) to only the designated `working_directory`.
   - Works without `root` privileges, making it safer for containerized deployments.
2. **Namespace Isolation**:
   - Utilize `unshare` for Network, PID, and Mount namespaces to prevent cross-process interference.

---

## 3. M8.3: OTLP (OpenTelemetry) Standardization

### Goal
Align with enterprise observability standards for security event monitoring.

### Deliverables
1. **OTLP Exporter**:
   - Push metrics and audit logs via gRPC or HTTP to OpenTelemetry collectors.
2. **SIEM Connectors**:
   - Pre-configured templates for Splunk, Datadog, and ELK.

---

## 4. Implementation Roadmap

- [ ] **M8.1.a**: Add `attestation` module and `ExecutionProof` types (v0.3.0-alpha.1).
- [ ] **M8.1.b**: Implement Policy Signing & Verification.
- [ ] **M8.2**: Integrate `landlock` crate into the Linux sandbox.
- [ ] **M8.3**: Implement OTLP exporter in `agent-guard-sdk`.
