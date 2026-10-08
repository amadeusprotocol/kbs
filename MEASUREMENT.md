# Release measurement

The AMAHub Key Broker (KBS) runs inside AMD SEV-SNP confidential VMs. Before the VM
starts, the AMD chip measures everything it will boot. A report signed by the chip
carries that **launch measurement**. A KBS node you talk to is this release only if
its report verifies against AMD and carries exactly this value.

## Current release

```
MEASUREMENT (SHA-384, 48 bytes)
433e4d58b2a0a795bdd5a6a5074feab2e3cf7a13cf7d3adff861a2b73eca77a3612296e15ad228cf36922d02913c30e1
```

| Field | Value |
|---|---|
| Released | 2026-10-14 |
| vCPUs (one measured VMSA each) | 4 |
| SEV features | SNP, DebugSwap |
| Guest kernel | Ubuntu `7.0.0-38-generic` |
| Toolchain | rustc 1.99.0 |
| HOST_DATA (fixed for every KBS launch) | `3016866b7ab26786386149bc2a4bb30012bbf198eae4a39c99498075e772bf51` |

### What the measurement covers

```
MEASUREMENT = SNP launch digest of
  firmware        Oak stage0 IGVM
  vCPU state      4 VMSAs (SNP + DebugSwap)
  hash table      sha256(kernel), sha256(initrd), sha256(cmdline)
initrd          = the KBS program + the release policy (release/policy.json)
```

Changing any byte of the firmware, kernel, KBS program, command line or policy
gives a different measurement. The release policy pins which chips may run this
KBS, so moving it to another machine is also a new release.

| Component | SHA-256 |
|---|---|
| `kbs.igvm` (stage0 firmware) | `3fa4b34e2e0b912088bba1274ac72916f5b299016222ba2e248ea199f8b2ff61` |
| `kbs.vmlinuz` | `9f55ef7253055a9cf68f8a04323c93dead2fca617386d842fbde9ca7b178b27e` |
| `kbs.initrd` | `5b3033a2fc2b90273eda166c0acdace29431c5ab7c3dffe4ec3d471e1edde004` |
| `kbs.cmdline` | `c07bf5fcb76eacd42e11d41aaaccdcfa42a66008da54c8085ef8da46922a25fd` |
| `policy.json` (compiled into the initrd) | `f5ec6e72202e8d6426d732c83579d9e79b1ed6406b57686c75eb51d86dc86ee9` |

Kernel command line: `console=ttyS0 rdinit=/init panic=-1 mitigations=auto quiet loglevel=3`

`release/policy.json` in this repo is the exact policy file (check its SHA-256
against the table). Every node also returns it in `GET /v1/attestation`.

## The cluster

The release currently runs as a single node. It is built as a cluster: nodes on
different pinned chips run the same measurement and share one key, and more
nodes come back as more chips are added to the policy.

| Node | Location | CPU | Chip ID | Minimum firmware (TCB) |
|---|---|---|---|---|
| KBS1 | Datacenter | AMD EPYC Genoa (family 0x19) | `84cfcf849c7b8e6b3f6f9c0a6878a0a51bb02e61630f72964df1f17bc02251e3474ee18e108fbf77410968afb1c6b5990cd8eef60fb81ff9b39fc302b6e453dd` | bl 12 · tee 0 · snp 29 · ucode 88 |

Each chip's VCEK (its AMD-signed key) is pinned in `release/policy.json`. VCEKs are
public-key certificates, so they're safe to publish.

AMD root key (ARK) pins, SHA-256 of the DER certificate served by AMD KDS:

| Product | ARK SHA-256 |
|---|---|
| Genoa | `4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1` |
| Turin | `1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a` |

## How to check it

- **In a browser:** open `https://kbsv2.ama.one/verify` and press
  **Verify all nodes**. The page checks everything locally and shows the measurement
  of each node. It must equal the value above.
- **Programmatically:** follow the checklist in [API.md](API.md#6-verifying-the-kbs-v1cluster-and-v1attestation).

## What this does and doesn't prove

A verified report proves that:
- the program with this exact measurement is running;
- it runs in an SEV-SNP VM on one of the pinned AMD chips, at or above the pinned firmware;
- debugging is off;
- the key the KBS gives you belongs to that VM.

The host operator can't read the VM's memory or change its code without changing
the measurement.

It doesn't prove what that program does. The KBS source is not public yet, so the
measurement is a fixed identity of the release, not something you can rebuild
yourself. Each release is built in a pinned, reproducible build environment. Watch
this file: a new measurement means a new release.

## History

| Date | Measurement | Notes |
|---|---|---|
| 2026-10-16 | `433e4d58…913c30e1` | First public release: single node (KBS1, AMD EPYC Genoa). |
