# Release measurement

The AMAHub Key Broker (KBS) runs inside AMD SEV-SNP confidential VMs. Before the VM
starts, the AMD chip measures everything it will boot. A report signed by the chip
carries that **launch measurement**. A KBS node you talk to is this release only if
its report verifies against AMD and carries exactly this value.

## Current release

```
MEASUREMENT (SHA-384, 48 bytes)
739c9e9c7572653c5a2a4361c93793589929458370d2fc37cbb2df847f59d0c83e64f2fbc8f54c1b9df154eea45571a2
```

| Field | Value |
|---|---|
| Released | 2026-10-08 |
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
| `kbs.initrd` | `beb7f302c09d43023d3645e9d6625869cce373d35fdb7100baa2c2533a3b5563` |
| `kbs.cmdline` | `c07bf5fcb76eacd42e11d41aaaccdcfa42a66008da54c8085ef8da46922a25fd` |
| `policy.json` (compiled into the initrd) | `f0c0f596f4440b1536a7d2772d198315de08b829e4e76b1829b701531414ceb4` |

Kernel command line: `console=ttyS0 rdinit=/init panic=-1 mitigations=auto quiet loglevel=3`

`release/policy.json` in this repo is the exact policy file (check its SHA-256
against the table). Every node also returns it in `GET /v1/attestation`.

## The cluster

Two nodes on two different AMD chips run this same measurement and share one
cluster key. Either node can serve any request.

| Node | Location | CPU | Chip ID | Minimum firmware (TCB) |
|---|---|---|---|---|
| KBS1 | Datacenter | AMD EPYC Genoa (family 0x19) | `84cfcf849c7b8e6b3f6f9c0a6878a0a51bb02e61630f72964df1f17bc02251e3474ee18e108fbf77410968afb1c6b5990cd8eef60fb81ff9b39fc302b6e453dd` | bl 12 · tee 0 · snp 29 · ucode 88 |
| KBS2 | New York | AMD EPYC Turin (family 0x1A) | `a3aa40340bd500ad` (KDS hwID) | fmc 1 · bl 3 · tee 2 · snp 5 · ucode 97 |

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
| 2026-10-08 | `739c9e9c…a45571a2` | First public release: 2-node cluster (KBS1 Genoa, KBS2 Turin). |
