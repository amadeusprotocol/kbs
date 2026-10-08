# AMAHub Key Broker (KBS): client API guide

This guide covers what a client needs: endpoints, JSON shapes, authentication, and how to verify that you are talking to the genuine, attested service. The KBS source code is closed. Everything here can be checked from the outside.

Contents

1. [Base URLs and transport](#1-base-urls-and-transport)
2. [Authentication: bearer tokens](#2-authentication-bearer-tokens)
3. [Secret API](#3-secret-api)
4. [Cluster behaviour](#4-cluster-behaviour)
5. [GET /v1/status: the KBS key](#5-get-v1status-the-kbs-key)
6. [Verifying the KBS: /v1/cluster and /v1/attestation](#6-verifying-the-kbs-v1cluster-and-v1attestation)
7. [Confidential VM secret release](#7-confidential-vm-secret-release)
8. [Errors and a worked example](#8-errors-and-a-worked-example)
9. [What is verified vs. what you trust](#9-what-is-verified-vs-what-you-trust)

---

## 1. Base URL and transport

**Base URL: `https://kbsv2.ama.one`**

- The cluster has two nodes, KBS1 (AMD EPYC Genoa) and KBS2 (AMD EPYC Turin). They serve the same API and hold the same data (see [section 4](#4-cluster-behaviour)).
- To attest a specific node, use `/v1/cluster` and `/v1/attestation?node=<id>` ([section 6](#6-verifying-the-kbs-v1cluster-and-v1attestation)).
- HTTPS with a standard WebPKI certificate.
- CORS: any origin may call `GET` and `POST` with the `Authorization` and `Content-Type` headers.

### TLS is transport only

Trust doesn't come from TLS:

- The **KBS key `rk`** (a hybrid X25519 + ML-KEM-768 public key) is bound into REPORT_DATA of the `/v1/status` report and of every `/v1/attestation` report (sections [5](#5-get-v1status-the-kbs-key) and [6](#6-verifying-the-kbs-v1cluster-and-v1attestation)). Verifying the attestation proves that the measured KBS image, on one of the pinned AMD chips, holds `rk`.
- Secrets the KBS releases to confidential VMs are sealed end-to-end to the receiver's attested key ([section 7](#7-confidential-vm-secret-release)), so they stay confidential even if the TLS connection is intercepted. And valid certs will be intercepted by world governments as those like to spy on thier ppl.

---

## 2. Authentication: bearer tokens

Header (exact, case-sensitive prefix, one space):

```
Authorization: Bearer <token>
```

### Token format

```
token     = base58( json || pk || sig )          Bitcoin base58 alphabet, no checksum
json      = UTF-8 JSON object, any length >= 1 byte, e.g. {"aud":"amadeus","exp":1791500000}
pk        = 48 bytes   BLS12-381 G1 public key, compressed (ZCash serialization)
sig       = 96 bytes   BLS12-381 G2 signature, compressed
msg       = sha256( json || pk )                 32 bytes
sig       = BLS.Sign(sk, msg) with hash-to-G2, DST =
            "AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_APIKEY_"
```

The KBS splits the token from the end: the last 96 bytes are `sig`, the 48 before them are `pk`, and everything before that is `json`. It verifies the signature (with public-key validation and signature group checks) over `sha256(json || pk)`. The signed bytes are the exact JSON bytes you send. No canonicalization happens.

Claims:

| Claim | Type | Rule |
|-------|------|------|
| `aud` | string | must equal `"amadeus"` |
| `exp` | integer, Unix seconds | must be **greater than** the KBS clock (the KBS uses Roughtime-anchored trusted time, not the host clock) |

The KBS ignores any other fields. **The KBS caps neither the lifetime nor the issue time.** A token can be replayed against either node until `exp`, so keep `exp` short (minutes).

### Namespaces

The token's public key *is* the account: secrets are stored under `base58(pk)`. You don't register, and there are no shared namespaces. Anyone with a BLS key pair gets their own namespace. Losing the secret key means losing access. Two tokens signed by the same key see the same secrets, on either node.

### Reference implementation (Python, illustrative)

This uses `py_ecc` (pure Python, slow but dependency-free) and `base58`. It has been checked byte for byte against our production client. It is illustrative, not a hardened client.

```python
# kbs_client.py
# pip install py_ecc base58      (checked with py_ecc 8.0.0, base58 2.1.1)
import hashlib, json, os, time
import base58
from py_ecc.bls import G2Basic

class KbsApiKey(G2Basic):
    DST = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_APIKEY_"

def new_secret_key() -> int:
    return KbsApiKey.KeyGen(os.urandom(32))          # keep this secret

def namespace(sk: int) -> str:
    return base58.b58encode(KbsApiKey.SkToPk(sk)).decode()

def kbs_token(sk: int, ttl_seconds: int = 300) -> str:
    payload = json.dumps({"aud": "amadeus", "exp": int(time.time()) + ttl_seconds},
                         separators=(",", ":")).encode()
    pk = KbsApiKey.SkToPk(sk)                                         # 48 B
    sig = KbsApiKey.Sign(sk, hashlib.sha256(payload + pk).digest())   # 96 B
    return base58.b58encode(payload + pk + sig).decode()
```

Key encodings, if you already hold an AMAHub key:

- A **32-byte hex** secret key is the big-endian scalar: `sk = int.from_bytes(bytes.fromhex(h), "big")`.
- A **64-byte hex** seed (for example a BIP39 seed) is read as a little-endian integer and reduced mod the curve order: `sk = int.from_bytes(seed, "little") % curve_order`, with `from py_ecc.optimized_bls12_381 import curve_order`.

Any BLS12-381 library that implements the IETF hash-to-curve `BLS12381G2_XMD:SHA-256_SSWU_RO_` suite with a custom DST works too (for example blst with the "min_pk" variant).

---

## 3. Secret API

Every endpoint in this table requires a bearer token. Request bodies are JSON and need `Content-Type: application/json`. Responses are `text/plain` unless the table says JSON.

| Method | Path | Body | Success response |
|--------|------|------|------------------|
| POST | `/v1/secret/put` | `{"key": str, "value": str, "label": str?}` | `ok` |
| GET | `/v1/secret/get/{key}` | none | the value, raw text |
| POST | `/v1/secret/get_bulk[?label=<label>]` | JSON array of key names, e.g. `["A","B"]` (may be `[]`) | `KEY=value\n` lines |
| GET | `/v1/secret/delete/{key}` | none | `deleted` |
| POST | `/v1/secret/unlabel` | `{"key": str, "label": str}` | `ok` |
| GET | `/v1/secret/list` | none | JSON `["key1", "key2", ...]` |
| GET | `/v1/secret/list_with_values` | none | JSON `[{"key": str, "value": str, "labels": [str]}]` |

Unauthenticated utility endpoints:

| Method | Path | Response |
|--------|------|----------|
| GET | `/v1/health` | `ok` |
| GET | `/v1/status` | JSON, [section 5](#5-get-v1status-the-kbs-key) |
| GET | `/v1/cluster` | JSON, [section 6](#6-verifying-the-kbs-v1cluster-and-v1attestation) |
| GET | `/v1/attestation?nonce=<64 hex>[&node=<id>]` | JSON, [section 6](#6-verifying-the-kbs-v1cluster-and-v1attestation) |
| GET | `/verify` (and `/`, which redirects there with 307) | the browser verifier page |

`GET /v1/stats` is operator-only; it is not for clients. Other paths exist for cluster-internal use and for confidential VM release ([section 7](#7-confidential-vm-secret-release)); they are not part of the client API.

### Names and limits

- **Key and label charset:** non-empty, ASCII letters, digits, `_` and `-` only (`^[A-Za-z0-9_-]+$`). Anything else gets `400 invalid key name` or `400 invalid label name`.
- **Values** are JSON strings, stored as UTF-8 bytes and returned verbatim.
- **Size limit:** about **1 KB per value, including the key name and its labels**. A write over the limit fails with `500` and nothing is stored. Store larger blobs encrypted elsewhere, and keep their key here.
- **Labels per key:** labels count toward the same limit, so keep them few and short (a handful per key).
- **Bulk:** at most **32** distinct keys per request, counting keys from `?label=` plus keys in the body after de-duplication. Above that you get `400 too many keys requested (max 32)`.
- **Reserved names:** keys that begin with `_` are reserved for platform configuration. Some reserved names are validated on write, and an invalid value gets `400` with an explanation. Don't use `_`-prefixed keys for your own data.

### Semantics

- **put** creates or overwrites `key`. If `label` is given, it is **added** to the key's labels. Existing labels are never removed by a put. A put without `label` leaves the labels as they were.
- **get** returns the raw value. A missing key returns **`400 not found`**, not 404.
- **get_bulk:** if `?label=` is given, the keys carrying that label come first, then the keys in the body, with duplicates removed. Missing keys are skipped silently. The output is one `KEY=value\n` line per key found. A value that contains a newline makes the output ambiguous, so use `get` or `list_with_values` for multi-line values.
- **delete** is a `GET`. It removes the key and all its labels and returns `deleted`, or `400 not found`.
- **unlabel** removes one label from one key. It returns `ok` even if the key didn't carry that label, or doesn't exist.
- **list** returns every key name in your namespace, sorted by byte value, **including** reserved `_` keys.
- **list_with_values** returns keys, values and labels but **omits keys that begin with `_`**.
- Labels are per namespace. A label exists only while at least one key carries it.

### Backups

The store has no recovery path: if every node loses its data, the data is gone. Keep your own backup of anything that matters.

---

## 4. Cluster behaviour

- **Either node accepts reads and writes.** Both nodes hold the full data set.
- **Read-your-writes across nodes:** when both nodes are up, a write made on one node is readable on the other as soon as the call returns.
- If the other node is down or slow to respond, the write still succeeds and returns `ok`; it reaches that node shortly after. The cross-node guarantee does not hold during that window.
- **Concurrent writes:** don't write the same key through both nodes at the same time. Two simultaneous writes to the same key on different nodes have no defined winner, and the nodes can end up with different values. Send writes for a given key through one node, or serialize them yourself.
- **One cluster key:** both nodes publish the same KBS key `rk` (same `rk_hash_hex` in `/v1/status` and `/v1/attestation`). Nodes admit each other only after mutual SNP attestation as the same release on a pinned chip; if they hold different keys, the oldest Roughtime-proven cluster key wins. A new deployment can produce a new `rk`. Pin the **measurement**, not `rk`.

---

## 5. GET /v1/status: the KBS key

No auth. Example shape (long values shortened):

```json
{
  "schema": "biome-kbs-status/v1",
  "seal": "biome-seal/v1",
  "rk_b64": "dOqR5F2F...",
  "rk_hash_hex": "8ffc04f8...",
  "attested": true,
  "born": {
    "seconds": 1791434330,
    "stamps": [
      {"server": "int08h",       "midpoint": 1791434330, "radius": 5, "request_b64": "...", "response_b64": "..."},
      {"server": "roughtime.se", "midpoint": 1791434330, "radius": 1, "request_b64": "...", "response_b64": "..."}
    ]
  },
  "measurement": "<96 hex>",
  "chip_id": "<128 hex>",
  "reported_tcb": "fmc=0 bl=12 tee=0 snp=29 ucode=88",
  "report_b64": "<1184-byte SEV-SNP report>",
  "evlog_b64": "<boot event log>",
  "config_b64": "<this node's public network config, KEY=VALUE lines>",
  "report_data": "sha256(\"kbs-key/v1\" || sha256(config) || rk_hash) || 0*32, rk_hash = sha256(\"biome-rk/v1\" || rk)"
}
```

| Field | Meaning |
|-------|---------|
| `rk_b64` | KBS public key, 1216 bytes (X25519 public key followed by ML-KEM-768 encapsulation key) |
| `rk_hash_hex` | `sha256("biome-rk/v1" \|\| rk)` |
| `seal` | identifier of the sealing scheme the key is used with |
| `attested` | `true` on the production release. `false` means not a TEE build, and the attestation fields are then absent. |
| `born` | Roughtime proof of when this key was created, or `null` |
| `measurement`, `chip_id`, `reported_tcb` | convenience copies. Read the real values from `report_b64`. |
| `report_b64` | SEV-SNP report made when the key was created or adopted. It is **not fresh** (it carries no client nonce). |
| `evlog_b64` | boot event log; informational, not needed for the checks below |
| `config_b64` | the node's public network configuration. Bound into the report. |

### Checking the key binding

1. Check that `attested` is `true`.
2. Decode `rk` from `rk_b64` and check its length is 1216 bytes. Compute `rk_hash = sha256("biome-rk/v1" || rk)` and compare it with `rk_hash_hex`. (Strings are ASCII bytes. `||` means concatenation.)
3. Verify `report_b64` with checklist steps 2 to 9 and 11 to 16 of [section 6](#6-verifying-the-kbs-v1cluster-and-v1attestation). Skip step 10, which is replaced by the next step.
4. Check `REPORT_DATA[0:32] == sha256("kbs-key/v1" || sha256(config) || rk_hash)` and `REPORT_DATA[32:64] == 0`, where `config = base64decode(config_b64)`.
5. **Freshness:** this report proves the binding, not that the node is live now. For liveness, use `/v1/attestation` with your own nonce ([section 6](#6-verifying-the-kbs-v1cluster-and-v1attestation)) and check that it reports the same `rk_hash`.

### The `born` proof (optional)

`born` shows that this `rk` existed at `born.seconds`. It is not needed for confidentiality, but it lets you see when the current cluster key was created. To check it:

1. For each stamp, check that the Roughtime request's nonce (`NONC`) equals `sha256("kbs-identity-time/v1" || rk)`.
2. Verify each response under the server's pinned Ed25519 key, using the Roughtime draft (draft-ietf-ntp-roughtime, wire version `0x8000000c`). That means verifying:
   - the `DELE` signature under the long-term key;
   - the `SREP` signature under the delegated key;
   - the Merkle path that includes your request;
   - that `MIDP` lies within `[MINT, MAXT]`.
3. Check that every pair of stamps agrees: `|midpoint_a - midpoint_b| <= radius_a + radius_b + 10`.
4. `born.seconds` is the median midpoint (with an even count, the upper of the two middle values).

Pinned servers:

| Name | Address | Ed25519 key (base64) |
|------|---------|----------------------|
| `int08h` | `roughtime.int08h.com:2002` | `AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=` |
| `roughtime.se` | `roughtime.se:2002` | `S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=` |

---

## 6. Verifying the KBS: /v1/cluster and /v1/attestation

### GET /v1/cluster

No auth. It lists the node that answered (`self`) and its peers. Use an `id` as the `node=` value in `/v1/attestation`.

```json
{"nodes": [{"id": "<KBS1 id>", "self": true},
           {"id": "<KBS2 id>", "self": false}]}
```

### GET /v1/attestation?nonce=<64 hex>[&node=<id>]

No auth. It returns a **fresh** SEV-SNP report from the node's own chip, bound to your 32-byte nonce and to the KBS key.

- `nonce` must be 64 hex characters (32 bytes). Otherwise you get `400 nonce must be 32 bytes of hex`.
- `node=<id>`, where `<id>` is another node in `/v1/cluster`, makes the node you called **relay** that node's report. Relaying is safe: the peer's own chip signs your nonce, and you verify it exactly as if you'd asked the peer directly. An unknown id gets `404 <id> is not a node of this cluster`. A peer that can't be reached gets `502`. Omitting `node`, or naming the node you called, returns that node's own report.
- Reports are produced one at a time per node, so expect some latency under load.

```json
{
  "schema": "biome-kbs-attestation/v1",
  "nonce_hex": "<your nonce, echoed>",
  "report_b64": "<1184 bytes>",
  "rk_b64": "<1216 bytes>",
  "rk_hash_hex": "<64 hex>",
  "report_data_rule": "REPORT_DATA = sha256(\"kbs-verify/v1\" || nonce || rk_hash) || 0*32, rk_hash = sha256(\"biome-rk/v1\" || rk)",
  "host_data_hex": "3016866b7ab26786386149bc2a4bb30012bbf198eae4a39c99498075e772bf51",
  "key_born": 1791434330,
  "node": {"node_id": "...", "chip": "KBS1", "product": "Genoa", "chip_id": "...", "measurement": "...", "reported_tcb": "...", "attested": true},
  "policy": { "chips": [ {"name", "product", "chip_id", "min_tcb", "vcek_der_b64", ...} ], "guest_policy": {...}, "max_vmpl": 1, "signing_key": "vcek", ... },
  "amd_chains": {"Genoa": "<ASK+ARK PEM>", "Turin": "<ASK+ARK PEM>"},
  "ark_fingerprints": {"Genoa": "4c6598d1...", "Turin": "1f084161..."}
}
```

**Only `report_b64` is signed.** `policy`, `node`, `amd_chains`, `ark_fingerprints` and `host_data_hex` are unsigned conveniences served by the node you're checking. Compare them with the published values below, or with your own copies, before you rely on them. The `/verify` page hardcodes the ARK pins but takes the chip list, VCEK pins, floors and HOST_DATA from this response.

### Published values for the current release

These values are compiled into the release, so changing any of them changes the measurement. `MEASUREMENT.md` in this repo is authoritative. If it disagrees with this table, it wins.

| Item | Value |
|------|-------|
| Measurement | **see `MEASUREMENT.md` in this repo** |
| HOST_DATA | `3016866b7ab26786386149bc2a4bb30012bbf198eae4a39c99498075e772bf51` (= `sha256("biome-kbs/host-data/v1")`) |
| ARK SHA-256, Genoa (also Bergamo, Siena) | `4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1` |
| ARK SHA-256, Turin | `1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a` |
| KBS1 chip (Genoa, CPUID family `0x19`) | CHIP_ID (all 64 bytes) `84cfcf849c7b8e6b3f6f9c0a6878a0a51bb02e61630f72964df1f17bc02251e3474ee18e108fbf77410968afb1c6b5990cd8eef60fb81ff9b39fc302b6e453dd` |
| KBS1 TCB floor | `bl=12 tee=0 snp=29 ucode=88` |
| KBS2 chip (Turin, CPUID family `0x1A`) | hwID (first 8 bytes of CHIP_ID) `a3aa40340bd500ad` |
| KBS2 TCB floor | `fmc=1 bl=3 tee=2 snp=5 ucode=97` |
| Guest policy | `DEBUG` (bit 19) and `MIGRATE_MA` (bit 18) must be 0 |
| Max VMPL | 1 |
| Signing key | VCEK |

### Report layout (SEV-SNP ATTESTATION_REPORT, 1184 bytes, little-endian)

| Offset | Size | Field | Used for |
|--------|------|-------|----------|
| `0x000` | 4 | VERSION | info (currently 5) |
| `0x004` | 4 | GUEST_SVN | info |
| `0x008` | 8 | POLICY (guest policy) | debug and migration bits |
| `0x030` | 4 | VMPL | `<= max_vmpl` |
| `0x038` | 8 | CURRENT_TCB | info |
| `0x040` | 8 | PLATFORM_INFO | optional check |
| `0x048` | 4 | FLAGS; bits 2-4 = SIGNING_KEY (0 VCEK, 1 VLEK, 7 none) | must be 0 |
| `0x050` | 64 | REPORT_DATA | nonce and key binding |
| `0x090` | 48 | MEASUREMENT | compare with published |
| `0x0C0` | 32 | HOST_DATA | fixed value |
| `0x140` | 32 | REPORT_ID | info |
| `0x180` | 8 | REPORTED_TCB | KDS URL, floor |
| `0x188` | 1 | CPUID_FAM_ID | `0x19` Genoa, `0x1A` Turin |
| `0x189` | 1 | CPUID_MOD_ID | info |
| `0x18A` | 1 | CPUID_STEP | info |
| `0x1A0` | 64 | CHIP_ID | pinned chip |
| `0x1E0` | 8 | COMMITTED_TCB | floor |
| `0x1EC` | 4 | COMMITTED_BUILD, COMMITTED_MINOR, COMMITTED_MAJOR (bytes 0, 1, 2) | info |
| `0x000`-`0x29F` | 672 | signed region | ECDSA input |
| `0x2A0` | 72 | SIGNATURE.R: 48 significant bytes, little-endian, then zero padding | |
| `0x2E8` | 72 | SIGNATURE.S: same layout | |

TCB byte layout (8 bytes, applies to both REPORTED_TCB and COMMITTED_TCB):

| Byte | Genoa (and Milan, Bergamo, Siena) | Turin |
|------|-----------------------------------|-------|
| 0 | BL | FMC |
| 1 | TEE | BL |
| 2 | reserved | TEE |
| 3 | reserved | SNP |
| 4-5 | reserved | reserved |
| 6 | SNP | reserved |
| 7 | UCODE | UCODE |

### Verification checklist

These are the checks the `/verify` page runs in the browser, in the same order, plus the comparison against the published measurement (step 16). The page itself only compares measurements *across nodes*, not with a published value.

1. **Fetch.** `GET /v1/cluster`. For each node, generate 32 random bytes as `nonce` and call `GET /v1/attestation?nonce=<hex(nonce)>`, adding `&node=<id>` for nodes other than the one you're calling. Then decode `report = base64decode(report_b64)`. It must be 1184 bytes.
2. **Chip is a pinned one.** Find the chip entry whose product family equals `report[0x188]` (Genoa `0x19`, Turin `0x1A`) and whose `chip_id` matches the start of `hex(report[0x1A0:0x1E0])`.
   - The match must be the full length for the product: 128 hex characters for Genoa, 16 for Turin. Turin reports carry an 8-byte hwID and zeros after it.
   - Entries of any other length never match.
   - Use the published chip list, not just the one in the response.

   If no entry matches, **fail**.
3. **Fetch AMD's certificates** from the AMD Key Distribution Service (KDS):
   - Chain (PEM, ASK first, then ARK): `https://kdsintf.amd.com/vcek/v1/{product}/cert_chain`
   - VCEK (DER), with TCB values taken from REPORTED_TCB (`report[0x180:0x188]`, decoded with the layout table above):
     - Genoa: `https://kdsintf.amd.com/vcek/v1/Genoa/{hex(CHIP_ID), all 64 bytes = 128 hex}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={ucode}`
     - Turin: `https://kdsintf.amd.com/vcek/v1/Turin/{hex(CHIP_ID[0:8]) = 16 hex}?fmcSPL={fmc}&blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={ucode}`
   - KDS rate-limits. On HTTP 429, honor `Retry-After` (about 10 s) and cache what you fetched.
   - If KDS can't be reached, fall back to the chain in `amd_chains[product]` and the pinned VCEK in the chip's `vcek_der_b64`. `/verify` shows this as a warning, not a failure. Every check below still applies.
4. **ARK pin:** check that `sha256(ARK DER)` equals the pinned ARK fingerprint for the product (table above). Hardcode these values; don't take them from the response.
5. **ARK self-signed:** RSASSA-PSS, SHA-384, MGF1-SHA-384, **salt length 48**, over the ARK's TBSCertificate.
6. **ASK signed by ARK:** RSA-PSS SHA-384, salt 48.
7. **VCEK signed by ASK:** RSA-PSS SHA-384, salt 48.
8. **VCEK is the pinned key** (only when the VCEK came from KDS): compare the **SubjectPublicKeyInfo** of KDS's VCEK with that of the chip's pinned `vcek_der_b64`. Compare **public keys, not whole certificates**: KDS re-issues the certificate on each request (new serial and dates) for the same key.
9. **Report signature:** verify ECDSA P-384 with SHA-384 over `report[0x000:0x2A0]`, using the VCEK public key.
   - Build `r` by reversing `report[0x2A0:0x2D0]` (it is stored little-endian).
   - Build `s` by reversing `report[0x2E8:0x318]`.
   - Then verify the signature `(r, s)` as big-endian integers.
10. **REPORT_DATA (fresh and bound to the KBS key):**
    - `rk = base64decode(rk_b64)`; `rk_hash = sha256("biome-rk/v1" || rk)`
    - require `REPORT_DATA[0:32] == sha256("kbs-verify/v1" || nonce || rk_hash)`, where `nonce` is the 32 raw bytes
    - require `REPORT_DATA[32:64]` to be all zeros
    - require `hex(rk_hash) == rk_hash_hex`
11. **TCB floors:** decode REPORTED_TCB (`0x180`) and COMMITTED_TCB (`0x1E0`) with the chip's layout. Every component listed in the chip's floor (`min_tcb`) must be `>=` the floor value, in **both** TCBs.
12. **Debug and migration off:** guest POLICY (`0x008`, u64) bit 19 (`DEBUG`) and bit 18 (`MIGRATE_MA`) must be 0.
13. **VMPL:** the u32 at `0x030` must be `<= max_vmpl` (1).
14. **Signing key:** `(u32 at 0x048 >> 2) & 7 == 0` (VCEK).
15. **HOST_DATA:** `report[0x0C0:0x0E0]` must equal `3016866b…bf51` (table above).
16. **Measurement:** `hex(report[0x090:0x0C0])` must equal the published measurement in **`MEASUREMENT.md` in this repo**. This step is what ties the report to *this* KBS release. Without it, steps 1 to 15 only prove "a genuine SEV-SNP guest on a listed chip".
17. **Cluster consistency** (as `/verify` reports it): all nodes that verified must show the **same measurement**, from **distinct** CHIP_IDs. They should also show the same `rk_hash` (one cluster key).

Optional extra checks that `/verify` doesn't show (both are also part of the published policy):

- PLATFORM_INFO (`0x040`) bit 5 `ALIAS_CHECK_COMPLETE` must be set. Bit 4 `CIPHERTEXT_HIDING_EN` is allowed to be clear.
- The release's `allowed_cpu_families` must be `[25, 26]`.

### Illustrative verifier (Python, offline path)

This uses the release's pinned certificates, so it makes no KDS calls. It needs `cryptography` (tested with 46.x, which warns about the VCEK's zero serial number; newer versions may refuse it, so the browser page parses DER by hand). Pin `MEASUREMENT` and `CHIPS` from the published values.

```python
import base64, hashlib, json, os, urllib.request
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ARK = {"Genoa": "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
       "Turin": "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a"}
FAMILY = {"Genoa": 0x19, "Turin": 0x1A}
HOST_DATA = "3016866b7ab26786386149bc2a4bb30012bbf198eae4a39c99498075e772bf51"
MEASUREMENT = "<from MEASUREMENT.md>"

def tcb(raw, product):
    return (dict(fmc=raw[0], bl=raw[1], tee=raw[2], snp=raw[3], ucode=raw[7]) if product == "Turin"
            else dict(bl=raw[0], tee=raw[1], snp=raw[6], ucode=raw[7]))

def verify(base, node=None):
    nonce = os.urandom(32)
    url = f"{base}/v1/attestation?nonce={nonce.hex()}" + (f"&node={node}" if node else "")
    att = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "kbs-verifier/1"}), timeout=30))
    r = base64.b64decode(att["report_b64"]); assert len(r) == 1184
    u32 = lambda o: int.from_bytes(r[o:o + 4], "little")
    chip_id = r[0x1A0:0x1E0].hex()
    chip = next(c for c in att["policy"]["chips"]          # cross-check against your pinned list too
                if FAMILY[c["product"]] == r[0x188] and chip_id.startswith(c["chip_id"].lower())
                and len(c["chip_id"]) == (16 if c["product"] == "Turin" else 128))
    product = chip["product"]
    pem = att["amd_chains"][product].encode()
    ask, ark = x509.load_pem_x509_certificates(pem)[:2]
    vcek = x509.load_der_x509_certificate(base64.b64decode(chip["vcek_der_b64"]))
    assert hashlib.sha256(ark.public_bytes(Encoding.DER)).hexdigest() == ARK[product]
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
    for sub, iss in ((ark, ark), (ask, ark), (vcek, ask)):
        iss.public_key().verify(sub.signature, sub.tbs_certificate_bytes, pss, hashes.SHA384())
    le = lambda o: int.from_bytes(r[o:o + 48], "little")
    vcek.public_key().verify(utils.encode_dss_signature(le(0x2A0), le(0x2E8)), r[:0x2A0], ec.ECDSA(hashes.SHA384()))
    rk_hash = hashlib.sha256(b"biome-rk/v1" + base64.b64decode(att["rk_b64"])).digest()
    assert r[0x50:0x70] == hashlib.sha256(b"kbs-verify/v1" + nonce + rk_hash).digest() and r[0x70:0x90] == bytes(32)
    assert rk_hash.hex() == att["rk_hash_hex"]
    floor = chip.get("min_tcb", {})
    for t in (tcb(r[0x180:0x188], product), tcb(r[0x1E0:0x1E8], product)):
        assert all(t.get(k, 0) >= v for k, v in floor.items())
    policy = int.from_bytes(r[0x08:0x10], "little")
    assert not (policy >> 19) & 1 and not (policy >> 18) & 1
    assert u32(0x30) <= 1 and (u32(0x48) >> 2) & 7 == 0
    assert r[0xC0:0xE0].hex() == HOST_DATA
    assert r[0x90:0xC0].hex() == MEASUREMENT
    return chip["name"], chip_id, rk_hash.hex()
```

---

## 7. Confidential VM secret release

Owners can mark secrets in their namespace for release to the virtual machines they launch on the AMAHub platform, so a VM receives its boot secrets without the owner's bearer token ever entering the VM.

A VM proves its identity with a fresh AMD SEV-SNP attestation report, together with an operator-signed launch package. The KBS verifies the report against AMD, then checks the VM's launch measurement, chip and guest policy, and that the owner has authorized that operator. Only then does it release that VM's secrets, and only those.

Released secrets are **sealed end-to-end to a key the VM generated and bound into its attestation report**, using a hybrid post-quantum scheme (X25519 + ML-KEM-768 key encapsulation with an AEAD). Only that VM can open them; the operator, the host and anyone intercepting the connection cannot. A sealed reply provides confidentiality to the receiver, not authentication of the KBS; the VM authenticates the KBS by verifying its attestation ([section 6](#6-verifying-the-kbs-v1cluster-and-v1attestation)).

This flow is built for AMAHub platform VMs and is not a public API. Its endpoints exist but are not documented here. The KBS never accepts data sealed to its own key `rk`; `rk` serves as the attested identity of the cluster ([section 5](#5-get-v1status-the-kbs-key)).

---

## 8. Errors and a worked example

Error bodies are short `text/plain` messages.

| Status | When |
|--------|------|
| `200` | success |
| `307` | `GET /` redirects to `/verify` |
| `400` | invalid key or label name; **key not found** (get and delete); too many keys in bulk (max 32); invalid value for a reserved `_` key; nonce not 32 bytes of hex; malformed JSON body |
| `401` | `missing authorization header`, `invalid authorization format` (no `Bearer ` prefix), `auth failed: <reason>`: `invalid base58`, `token too short`, `invalid public key`, `invalid signature`, `signature verification failed`, `invalid token payload`, `invalid audience`, `token expired` |
| `403` | the token is valid but not allowed for this endpoint |
| `404` | unknown route; `node=` is not a cluster member; `/v1/attestation` on a non-TEE build |
| `415` | JSON body sent without `Content-Type: application/json` |
| `422` | JSON body with the wrong shape (for example a missing `key`) |
| `500` | write over the size limit (about 1 KB, [section 3](#names-and-limits)); internal read or write failure |
| `502` | relayed attestation: the peer didn't answer |
| `503` | a feature not enabled on this release |

### Worked example

```sh
KBS='https://kbsv2.ama.one'

# 0. Verify the cluster first (section 6): open $KBS/verify and press "Verify all nodes",
#    or run the Python verifier, and compare the measurement with MEASUREMENT.md.

# 1. Make a short-lived token from your BLS secret key with kbs_token() (section 2).
TOKEN=$(python3 -c 'from kbs_client import kbs_token; import sys; print(kbs_token(int(sys.argv[1], 16)))' "$SK_HEX")

# 2. Write.
curl -s -X POST "$KBS/v1/secret/put" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"key":"DEMO_KEY","value":"hello","label":"demo"}'
# -> ok

# 3. Read it back (every node has it as soon as step 2 returned).
curl -s "$KBS/v1/secret/get/DEMO_KEY" -H "Authorization: Bearer $TOKEN"
# -> hello

# 4. Bulk read by label, list, and clean up.
curl -s -X POST "$KBS/v1/secret/get_bulk?label=demo" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '[]'
# -> DEMO_KEY=hello
curl -s "$KBS/v1/secret/list_with_values" -H "Authorization: Bearer $TOKEN"
# -> [{"key":"DEMO_KEY","value":"hello","labels":["demo"]}]
curl -s "$KBS/v1/secret/delete/DEMO_KEY" -H "Authorization: Bearer $TOKEN"
# -> deleted
```

---

## 9. What is verified vs. what you trust

**What you can verify yourself** (with [section 6](#6-verifying-the-kbs-v1cluster-and-v1attestation) and the published measurement):

- The report was produced by a genuine AMD SEV-SNP processor. The signature chains to AMD's root key, whose hash you pin.
- The processor is one of the two pinned chips (CHIP_ID, and the VCEK public key), running firmware at or above the release's TCB floors.
- The VM has debugging and migration agents disabled, runs at VMPL `<= 1`, and was launched with the fixed KBS HOST_DATA.
- The VM's **launch image is exactly the published release** (MEASUREMENT). The image covers the firmware, the kernel, the initrd containing the KBS program with its compiled-in policy and chip list, the command line, and the vCPU count.
- The report is **fresh** (it contains your nonce), and the KBS key `rk` was held by that image at that moment. Both nodes run the same measurement on different chips and share one `rk`.

**What you trust:**

- **What the program does.** The source is closed. Attestation proves *which* program runs (by measurement) on *which* pinned AMD chips. It does not prove what that program does with your secrets. You rely on our description of the release that `MEASUREMENT.md` identifies:
  - secrets are kept only in TEE memory and on a disk sealed to the chip and measurement;
  - namespaces are enforced;
  - data is shared only with peers that attested as the same release on a pinned chip;
  - there's no admin or debug path.

  Each release is built in a pinned, reproducible build environment, but without the source, outsiders can't rebuild it to confirm the measurement.
- **AMD**: the processor, the PSP firmware, and the key distribution service.
- **Physical security** of the two machines. SEV-SNP doesn't defend against every physical attack by whoever holds the hardware.
- **Unsigned response fields.** `policy`, `node`, `amd_chains` and `host_data_hex` in `/v1/attestation`, and the convenience fields in `/v1/status`, are signed by nobody. Check them against published values.
- **Time:** token expiry and the key's `born` proof rely on the pinned Roughtime servers.
- **Availability and durability:** the operator can stop the nodes or wipe their disks. There is no recovery copy, so keep your own backups.
