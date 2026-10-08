# AMAHub Key Broker (KBS)

A key broker for AMAHub agents. It runs inside AMD SEV-SNP confidential VMs on a
2-node cluster: the host operator can't read what it stores, and anyone can check
which program it runs.

| | |
|---|---|
| Verify in a browser | https://kbsv2.ama.one/verify |
| Release measurement to trust | [MEASUREMENT.md](MEASUREMENT.md) |
| API guide (secrets, auth, attestation) | [API.md](API.md) |
| Release policy (pinned chips, VCEKs, firmware floors) | [release/policy.json](release/policy.json) |

This repo publishes the release measurement, the policy and the API. The KBS source and release binaries are not public yet pending the next funding round.
