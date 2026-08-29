# SAP-xCF14 — Security Attestation Protocol

> **版本**：v1.0（Evolving Layer）
> **所属协议家族**：CI-144 Protocol Family
> **家族魔数**：`0xCF14`
> **子协议 ID**：`0x01`
> **总长度**：28 字节（224 bits）

---

## ⚠️ Authority Declaration (MUST READ)

**This repository is the PUBLICATION WINDOW, NOT the authority.**

The **Single Source of Truth (SSOT)** for this specification is maintained in:

> **[CommonIntents/BIND-19/docs/spec/sap-xcf14.md](https://github.com/CommonIntents/BIND-19/blob/v2.0-rc.1/docs/spec/sap-xcf14.md)**

All specification change PRs **MUST** be filed in the BIND-19 repository, updating `docs/spec/` + `src/` + `tests/` together (OpenSSL model: code and docs reviewed in the same PR).

**This repo does NOT accept specification change PRs.** Content here is synced from BIND-19.

| Role | Location |
|---|---|
| **Specification Authority (SSOT)** | [BIND-19/docs/spec/sap-xcf14.md](https://github.com/CommonIntents/BIND-19/blob/v2.0-rc.1/docs/spec/sap-xcf14.md) |
| **Reference Implementation** | [BIND-19/src/sap.rs](https://github.com/CommonIntents/BIND-19/blob/v2.0-alpha/src/sap.rs) |
| **Test Vectors** | [BIND-19/tests/test_vectors/](https://github.com/CommonIntents/BIND-19/tree/v2.0-rc.1/tests/test_vectors) |
| **Publication Window** | This repo |

**Corresponding BIND-19 version**: [`v2.0-rc.1`](https://github.com/CommonIntents/BIND-19/tree/v2.0-rc.1)

---

## Protocol Overview

SAP-xCF14 (Security Attestation Protocol) is the **evolving layer** of the CI-144 Protocol Family. It provides security attestation for the physical features described by PFP, including anti-replay sequence numbers and physical context hash signatures.

### Design Philosophy

| Principle | Embodiment |
|---|---|
| **Extreme Decoupling** | Separated from PFP. SAP is optionally loaded, does not affect PFP hard-real-time decisions |
| **On-Demand Loading** | Low-security scenarios can skip SAP (PFP-only), energy-saving mode |
| **Extreme Reuse** | Reuses Ed25519 signature + SHA-256 hash, does not reinvent crypto primitives |
| **White-Box Observable** | All fields are plaintext and visible. Tuck can verify without decrypting payload |
| **Progressive Growth** | Evolving layer. v1/v2 can coexist, future security mechanisms can be extended |

---

## Byte Layout (28 bytes / 224 bits)

All fields are **plaintext, fixed-offset, fixed-length**.

| Byte | Bits | Field | Description |
|---|---|---|---|
| 0-1 | 0-15 | `Family-Magic` | Fixed `0xCF14` (big-endian) |
| 2 | 0-7 | `Protocol-ID` | Fixed `0x01` (SAP-xCF14) |
| 3 | 0-3 | `Version` | SAP version, current v1.0 = `0001` |
| 3 | 4-7 | `Reserved` | Must be 0 |
| 4-5 | 0-15 | `Seq-Counter` | Anti-replay sequence number (big-endian, monotonically increasing) |
| 6-19 | 0-111 | `PAH-Hash` | Physical context hash (SHA-256 truncated high 112 bits) |
| 20-27 | 0-63 | `PAH-Signature` | PAH signature (64-bit truncated, fast verification layer) |

---

## Key Mechanisms

### 1. Anti-Replay (Seq-Counter)

- **16-bit** monotonically increasing sequence number (big-endian)
- **Cold start**: random initial value, prevents reset-after-reboot attacks
- **Atomic increment**: `AtomicU16` + `fetch_add(1, Ordering::SeqCst)` in multi-threaded environments
- **Cache requirement**: sharded by `(Tenant-ID, Source-ID)`, at least 1024 sources, last 256 sequence numbers per source, TTL auto-cleanup (default 60s)

**Check rule**:
```
IF PFP.Replay-Enable == 1:
    IF Seq-Counter > Last-Seen-Seq[Source-ID]:
        → Allowed (update cache)
    ELSE:
        → Rejected (audit log REJECTED_REPLAY)
ELSE (Replay-Enable == 0):
    → Skip check (Rule 6 downgrade, effective risk forced to MEDIUM)
```

### 2. PAH Dual-Layer Security Architecture

| Layer | Signature Length | Verification Timing | Verifier | Failure Handling |
|---|---|---|---|---|
| Layer 1 (Fast Verification) | 64-bit truncated | Before hard-real-time decision | Tuck | Immediate reject + ERROR level + audible/visual alarm |
| Layer 2 (Full Verification) | 512-bit full | Async after payload decryption | Anaphase / Cloud audit | Do not reject frame, trigger async alarm, 3 consecutive failures → key revocation |

**Truncation algorithm (MUST be consistent across implementations)**:
```
truncated_signature = SHA-256(full_ed25519_signature)[0:8]  // first 8 bytes (MSB, high 64 bits)
```

### 3. Key Rotation (Seq-Counter Wrap Handling)

- **Trigger**: `Seq-Counter >= 65534` (ROTATION_THRESHOLD)
- **Rotation frame**: BIND-19 FrameType=0x07 (`KEY_ROTATION`), carries new key encrypted by master key
- **ACK**: FrameType=0x08, 100ms timeout, max 3 retries
- **Fail-closed**: If all 3 retries fail, sender MUST:
  1. Trigger hard alarm (ERROR level + audible/visual indication)
  2. Stop sending all data frames, enter "key rotation failed" safe state
  3. Wait for manual physical reset or out-of-band management intervention
- **NEVER fall back to old key and continue sending** (state inconsistency is more dangerous than service stoppage)

### 4. Rule 6: Replay-Enable=0 Security Constraint

When PFP.`Replay-Enable == 0`, Tuck MUST enforce:

1. **Risk downgrade**: Effective risk level forced to `MEDIUM` (regardless of original Risk-Level). CATASTROPHIC hard override can never be triggered — fundamentally prevents high-risk physical attacks via replay.
2. **Enhanced verification**: PAH-Signature verification (Layer 1 64-bit) is mandatory. Compensate for missing replay protection with anti-forgery strength. If signature verification fails, reject frame immediately.
3. **Audit mandatory mark**: Audit log MUST explicitly record `REPLAY_DISABLED` event with current hardware clock.

---

## Protocol Stack Position

```
[ 8-byte BIND-19 Header ] + [ PFP 4 bytes ] + [ SAP 28 bytes (optional) ] + [ Payload ]
```

SAP depends on PFP (SAP cannot appear alone). Tuck hard-real-time decisions depend only on PFP; SAP is an optional security enhancement layer.

---

## Relationship with PFP-xCF14

| Dimension | PFP-xCF14 | SAP-xCF14 |
|---|---|---|
| Layer | Frozen | Evolving |
| Length | 4 bytes | 28 bytes |
| Dependencies | None (stands alone) | Depends on PFP (cannot stand alone) |
| Tuck reads | Mandatory (hard-real-time decision) | Not required (optional verification) |
| Change frequency | Never changes (frozen) | Evolvable (v1/v2 can coexist) |
| Core value | Physical feature description | Security attestation (replay protection + signature) |

---

## Test Vectors

33 sets of test vectors for the entire CI-144 v2.0 protocol family are published at:

> [BIND-19/tests/test_vectors/ci-144-v2.0-test-vectors.json](https://github.com/CommonIntents/BIND-19/blob/v2.0-rc.1/tests/test_vectors/ci-144-v2.0-test-vectors.json)

SAP-related vectors:

| Category | Count | Content |
|---|---|---|
| `sap_codec` | 5 | SAP 28-byte encode/decode (Seq-Counter boundary values) |
| `replay_protection` | 5 | Anti-replay check (normal increment / exact replay / old seq / large jump / new source) |
| `rule6_downgrade` | 3 | Rule 6 downgrade (Replay-Enable=0 → MEDIUM) |
| `key_rotation` | 4 | Key rotation state machine (threshold / start / ACK / complete) |
| `pah_signature` | 3 | PAH signature (full Ed25519 / 64-bit truncation / wrong signature) |

Generate test vectors locally:
```bash
cd BIND-19
cargo run --example generate_test_vectors
```

---

## Reference Implementation

The official Rust reference implementation is maintained in BIND-19:

- [src/sap.rs](https://github.com/CommonIntents/BIND-19/blob/v2.0-alpha/src/sap.rs) — SAP encode/decode
- [src/replay_cache.rs](https://github.com/CommonIntents/BIND-19/blob/v2.0-alpha/src/replay_cache.rs) — Anti-replay cache (DashMap sharded)
- [src/rotation.rs](https://github.com/CommonIntents/BIND-19/blob/v2.0-alpha/src/rotation.rs) — Key rotation state machine
- [src/crypto.rs](https://github.com/CommonIntents/BIND-19/blob/v2.0-alpha/src/crypto.rs) — Ed25519 signature + SHA-256 truncation
- [examples/replay_protection.rs](https://github.com/CommonIntents/BIND-19/blob/v2.0-alpha/examples/replay_protection.rs) — Replay protection usage example

---

## Version History

| Version | Date | Changes |
|---|---|---|
| v1.0 | 2026-08-29 | Initial version. 28-byte structure, Seq-Counter anti-replay + PAH-Hash + PAH-Signature dual-layer security + key rotation mechanism. |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

**This repository is a publication window. For the authoritative specification, go to [CommonIntents/BIND-19/docs/spec/sap-xcf14.md](https://github.com/CommonIntents/BIND-19/blob/v2.0-rc.1/docs/spec/sap-xcf14.md).**
