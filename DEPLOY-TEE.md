# Deploying a confidential (TEE) agent on AMAHub

A step-by-step guide for authors, and for AI agents acting for them. It takes
a directory of files to a running AMD SEV-SNP virtual machine whose disk image
is encrypted, whose image key is held by the KBS, and whose secrets are released
only after the VM proves what it is.

Everything here uses two public services:

| Service | Base URL | Used for |
|---|---|---|
| KBS | `https://kbsv2.ama.one` | image key, base pin, owner secrets ([API.md](API.md)) |
| Hub | `https://api-hub.ama.one` | base image, upload, manifest, launch |

Both accept the same bearer token (`Authorization: Bearer <token>`, built with
`kbs_token()` from [API.md section 2](API.md#2-authentication-bearer-tokens)).
The token's BLS public key is your account on both. Tokens must be at most
2048 characters and unexpired.

Contents

1. [What you get, and what you don't](#1-what-you-get-and-what-you-dont)
2. [Roles and names](#2-roles-and-names)
3. [Prerequisites](#3-prerequisites)
4. [Step 1: get the base image](#4-step-1-get-the-base-image)
5. [Step 2: prepare the agent directory](#5-step-2-prepare-the-agent-directory)
6. [Step 3: build the encrypted image](#6-step-3-build-the-encrypted-image)
7. [Step 4: register the image key and base at the KBS](#7-step-4-register-the-image-key-and-base-at-the-kbs)
8. [Step 5: upload the image](#8-step-5-upload-the-image)
9. [Step 6: publish the manifest](#9-step-6-publish-the-manifest)
10. [Step 7: launch](#10-step-7-launch)
11. [Step 8: verify the running VM](#11-step-8-verify-the-running-vm)
12. [Owner secrets](#12-owner-secrets)
13. [Wallet, state disk and new versions](#13-wallet-state-disk-and-new-versions)
14. [Updating deployed agents](#14-updating-deployed-agents)
15. [Troubleshooting](#15-troubleshooting)
16. [Complete example](#16-complete-example)

---

## 1. What you get, and what you don't

A TEE agent is the author's code, sealed from both the machine operator and
the person who launches it.

- The image is encrypted before it leaves your machine. The host stores and
  serves only ciphertext, checked block by block against the image's root hash.
- The image key is released by the KBS only to a VM whose AMD-signed
  attestation report shows exactly your image root, on the base image you
  pinned, on an approved chip, with debugging off. The reply is sealed to a key
  generated inside that VM.
- Each deployment derives its own wallet and its own disk key inside the VM.
  Neither ever leaves it; the KBS never sees them.
- Nobody gets a shell: no console login, no startup script, no owner SSH keys,
  no shared host directory, no snapshots. Your code starts itself.

What this does not give you:

- **No recovery.** The KBS has no backup copy of your image key (keep your own),
  and a deployment's wallet and state disk exist only on the chip it runs on.
  See [section 13](#13-wallet-state-disk-and-new-versions).
- **No protection from your own code.** Whatever the image does with its
  secrets is up to the image.
- Capacity is limited: TEE agents run only on TEE hosts, at one fixed size
  (2 vCPUs, 2 GB RAM, plus swap, 20 GB encrypted state disk).

## 2. Roles and names

| Name | Meaning |
|---|---|
| **Author** | Builds and publishes the image. Holds the image key. `AUTHOR_PK` = base58 public key of the author's token. |
| **Owner** | Launches an instance. May be the author or anyone the agent is published to. |
| **Operator** | Runs the hosts and signs each launch. AMAHub's operator key is `6KTXmJfbfmLGTaoY1NH8jKdHb9RX9aTRLtYBh2c5djwuqMEi5J98rjmXDFELctLH62`. |
| **Agent root** (`ROOT`) | 64 lowercase hex: the dm-verity root hash of your encrypted image. It is the agent's name everywhere, and it changes with every byte of the image. |
| **Base root** (`BASE`) | 64 lowercase hex: the root hash of the base OS image your agent runs on. |
| **Deployment** | One launched instance: a `uid` (12 hex) and an IPv6 address. |

## 3. Prerequisites

On the build machine (any Linux; no root needed):

- `mkfs.erofs` (erofs-utils), `veritysetup` (cryptsetup), `curl`, `jq`
- `python3` with `cryptography`, `py_ecc`, `base58`
- `kbs_client.py` from [API.md section 2](API.md#reference-implementation-python-illustrative)
- [`tools/make-tee-agent.sh`](tools/make-tee-agent.sh) from this repo
- the author's BLS secret key as 64 hex in `$SK_HEX`

```sh
KBS=https://kbsv2.ama.one
HUB=https://api-hub.ama.one
tok() { python3 -c 'from kbs_client import kbs_token; import sys; print(kbs_token(int(sys.argv[1], 16)))' "$SK_HEX"; }
AUTHOR_PK=$(python3 -c 'from kbs_client import namespace; import sys; print(namespace(int(sys.argv[1], 16)))' "$SK_HEX")
```

Tokens are short-lived (5 minutes by default), so call `tok` for each request.
Before trusting the KBS with a key, verify it: [API.md section 6](API.md#6-verifying-the-kbs-v1cluster-and-v1attestation).

## 4. Step 1: get the base image

Your image is a layer over a base OS image. Ask the hub which base is current:

```sh
curl -s "$HUB/v1/tee/base" -H "Authorization: Bearer $(tok)"
# {"error":"ok","root":"<BASE, 64 hex>","url":"<download link, valid 6 hours>"}
BASE=<root from the reply>
```

`404 no_img_base_published` means no base is available yet: stop here.

You only need `BASE` to continue. Download `url` if you want to inspect the
base or test against it. It is a disk image with two partitions: an EROFS root
filesystem and its dm-verity hash tree. Check it against its name with
`veritysetup verify <partition 1> <partition 2> $BASE`.

An agent built for one base runs only on that base. When a newer base is
published, existing agents keep running on the one they pinned.

## 5. Step 2: prepare the agent directory

Make a directory holding the files your agent adds to or changes in the base,
laid out from `/`:

```
agent/
  opt/myagent/...                                   your program
  etc/systemd/system/myagent.service                how it starts
  etc/systemd/system/multi-user.target.wants/myagent.service -> ../myagent.service
  etc/biome/owner-env                               optional, see below
```

Rules that differ from a normal AMAHub VM:

- **Start yourself.** No startup script runs and nobody can log in. Ship a
  systemd unit and enable it with the `wants` symlink, as above. Order it
  `After=biome-bootstrap-net.service` so the environment below is ready.
- **Environment.** At boot the VM writes `/etc/environment` (lines of
  `KEY='value'`; load it with `EnvironmentFile=/etc/environment`):

  | Variable | Value |
  |---|---|
  | `MNEMONIC` | this deployment's wallet, 24 BIP39 words ([section 13](#13-wallet-state-disk-and-new-versions)) |
  | `BIOME_UUID` | the deployment's uid |
  | `BIOME_USER_PK` | the owner's public key |
  | `BIOME_AUTHOR_PK` | the author's public key |
  | `BIOME_AGENT`, `BIOME_BASE` | the agent root and base root |
  | `BIOME_OPERATOR_PK`, `BIOME_NODE`, `BIOME_TEE` | who launched it and where; `BIOME_TEE='true'` |
  | owner secrets | only the names listed in `/etc/biome/owner-env` ([section 12](#12-owner-secrets)) |

- **Owner secrets are opt-in.** List the variable names your agent accepts
  from its owner in `/etc/biome/owner-env`, one per line. Without the file,
  nothing from the owner reaches your code.
- **SSH is off** unless the image itself ships a non-empty
  `/root/.ssh/authorized_keys`. Doing so gives the holder of those keys a root
  shell in every instance, including access to each owner's wallet and secrets.
  Leave it out of production images and say so if you include it.
- **Writes persist.** The image is read-only; everything your agent writes goes
  to the deployment's encrypted state disk and survives reboots.
- Put any secret your code needs at build time straight into the image: it is
  encrypted.

## 6. Step 3: build the encrypted image

```sh
ROOT=$(tools/make-tee-agent.sh agent/ agent.img agent.key)
echo "$ROOT"            # 64 hex: the agent's name from here on
```

This packs the directory into a compressed read-only filesystem, encrypts it
with a fresh 512-bit key (AES-XTS), adds a dm-verity hash tree over the
ciphertext and prints the root hash.

- `agent.img` is what you upload. It must be at most 5 GiB.
- `agent.key` (128 hex) is the image key. **Back it up offline.** Anyone
  holding it can decrypt the image; without it the image is useless.

Building is not reproducible (the key is random): building the same directory
twice gives two different roots, which are two different agents.

## 7. Step 4: register the image key and base at the KBS

Two entries in the author's own namespace:

```sh
put() { jq -n --arg k "$1" --arg v "$2" '{key: $k, value: $v}' |
        curl -sf -X POST "$KBS/v1/secret/put" -H "Authorization: Bearer $(tok)" \
             -H 'Content-Type: application/json' --data-binary @-; echo; }

put "_TEE_AGENT_KEY_$ROOT"  "$(tr -d '\n' < agent.key)"     # -> ok
put "_TEE_AGENT_BASE_$ROOT" "$BASE"                         # -> ok
```

| Key | Value | Meaning |
|---|---|---|
| `_TEE_AGENT_KEY_<ROOT>` | 128 lowercase hex | the image key, released only to an attested VM running exactly `ROOT` |
| `_TEE_AGENT_BASE_<ROOT>` | 64 lowercase hex | the only base that image may boot on |

The KBS checks both formats on write and answers `400` with the reason if
either is wrong. Confirm with `GET /v1/secret/get/_TEE_AGENT_BASE_$ROOT`.
(`list_with_values` hides keys that begin with `_`; `list` shows them.)

**Operator trust.** The key is released only for launches signed by an
operator the author trusts. AMAHub's operator is trusted by default, so most
authors do nothing here. If you have written your own `_BUCKET_sticky` config,
it replaces that default: make sure one of your buckets still lists the
operator, with `vm_tee` not set to `false`:

```json
{"auto": true, "operators": {"6KTXmJfbfmLGTaoY1NH8jKdHb9RX9aTRLtYBh2c5djwuqMEi5J98rjmXDFELctLH62": {}}}
```

To withdraw an image, delete `_TEE_AGENT_KEY_<ROOT>`: no instance of it can
boot again.

## 8. Step 5: upload the image

```sh
SIZE=$(stat -c %s agent.img)
R=$(jq -n --arg n "$ROOT" --argjson s "$SIZE" '{agent_name: $n, size: $s}' |
    curl -s -X POST "$HUB/v1/agent_builder/upload_url" -H "Authorization: Bearer $(tok)" \
         -H 'Content-Type: application/json' --data-binary @-)
# {"error":"ok","upload_id":"<16 hex>","method":"PUT","url":"<presigned>","headers":{"Content-Length":<size>},"expires_in":3600}
ID=$(jq -r .upload_id <<< "$R")

curl -f -X PUT --upload-file agent.img "$(jq -r .url <<< "$R")"

jq -n --arg n "$ROOT" --arg i "$ID" '{agent_name: $n, upload_id: $i}' |
    curl -s -X POST "$HUB/v1/agent_builder/upload_complete" -H "Authorization: Bearer $(tok)" \
         -H 'Content-Type: application/json' --data-binary @-
# {"error":"ok","state":"verifying"}
```

The hub then checks every block of the image against `ROOT`. Poll until it
finishes:

```sh
curl -s "$HUB/v1/agent_builder/upload_status/$ROOT/$ID" -H "Authorization: Bearer $(tok)"
# {"error":"ok","state":"verifying" | "ok" | "error" | "unknown","message":"..."}
```

`state: "ok"` means the image is published under its root. `state: "error"`
carries the reason; upload again from `upload_url`.

| Reply from `upload_url` | Meaning |
|---|---|
| `400 only_tee_agent_images_for_now` | `agent_name` is not 64 lowercase hex |
| `400 bad_size` | size is not a multiple of 4096, is under 12288 or over the maximum in the reply |
| `503 uploads_not_configured`, `507 image_store_full` | try later |

## 9. Step 6: publish the manifest

```sh
jq -n --arg n "$ROOT" --arg b "$BASE" '{
  agent_name: $n,
  manifest: {
    name_display: "My agent",
    description: "What it does.",
    private: true,
    author_fee: 0,
    secrets: {},
    tabs: {default: "", extra: []},
    tee: true,
    base: $b
  }}' |
curl -s -X POST "$HUB/v1/agent_builder/manifest" -H "Authorization: Bearer $(tok)" \
     -H 'Content-Type: application/json' --data-binary @-
# {"error":"ok"}
```

| Field | Rule |
|---|---|
| `agent_name` | must be `ROOT`; a TEE agent's name is its root |
| `tee` | `true` |
| `base` | the same `BASE` you registered at the KBS; a mismatch fails at boot |
| `name_display` | 1 to 64 characters |
| `description` | up to 512 characters |
| `private` | `true`: only you can launch it. `false`: listed publicly; needs an account anchor (card, credits, subscription or an AMA balance), else `402 publish_requires_account` |
| `author_fee` | integer 0 to 10000 |
| `secrets` | map of `NAME: "opt" \| "req"`, names `^[A-Z][A-Z0-9_]*$`, at most 32; shown to owners as the secrets the agent expects |
| `tabs` | `{default, extra: [{name, cmd}]}`; use the empty form above if unsure |

Any other reply than `{"error":"ok"}` means a field broke a rule.

## 10. Step 7: launch

The owner (here, the author) launches an instance:

```sh
jq -n --arg p "$AUTHOR_PK" --arg n "$ROOT" '{agent_pk: $p, agent_name: $n}' |
curl -s -X POST "$HUB/v1/agent/create" -H "Authorization: Bearer $(tok)" \
     -H 'Content-Type: application/json' --data-binary @-
# {"error":"ok","uid":"<12 hex>","ip6":"<address>"}
```

| Reply | Meaning |
|---|---|
| `404 not_found` | no manifest for that `agent_pk` and `agent_name` |
| `401 unauthorized` | bad token, or the agent is private and not yours |
| `409 agent_not_ready` | the upload has not reached `state: "ok"` |
| `503 tee_capacity` | no TEE host has room; retry later |
| `409 concurrent_limit` | your account already has its allowed VM; stop it first |

Watch it come up:

```sh
curl -s "$HUB/v1/agent/my" -H "Authorization: Bearer $(tok)" | jq '.running[] | {uuid, status, ip6}'
```

`status` goes `queued` → `booting` → `running`. A TEE VM that fails
attestation, or cannot open its disks, powers itself off and shows `failed`;
it is not relaunched. See [section 15](#15-troubleshooting).

Stop an instance with `POST $HUB/v1/agent/stop` and body `{"uuid": "<uid>"}`.
A new launch is a new deployment with a new wallet
([section 13](#13-wallet-state-disk-and-new-versions)), so move funds out
before stopping for good.

## 11. Step 8: verify the running VM

The KBS keeps the last attestation it accepted for each deployment, and anyone
can read and re-check it:

```sh
curl -s "$KBS/v1/tee/attestation/<uid or ip6>" | jq '.verdict.ok, .verdict.checks[].name'
```

Or open `https://kbsv2.ama.one/verify/<uid>` in a browser.

The verdict lists each check: operator signature on the launch, HOST_DATA
bound to this deployment, the agent root from the report, AMD certificate chain
and revocation, report signature, firmware measurements and policy. The stored
bundle carries AMD's signature, so it can be re-verified without trusting the
KBS. The agent root in the report is the proof of which image is running;
compare it with the `ROOT` you built.

`404 no attestation stored for this deployment` means the VM never passed
attestation.

## 12. Owner secrets

Owners give a TEE agent secrets through the KBS, not through the hub, and the
owner's token never enters the VM.

1. The owner stores each secret in their own namespace with the label `sticky`:

   ```sh
   curl -s -X POST "$KBS/v1/secret/put" -H "Authorization: Bearer $OWNER_TOKEN" \
        -H 'Content-Type: application/json' \
        -d '{"key":"EXCHANGE_API_KEY","value":"...","label":"sticky"}'
   ```

2. The image lists the name in `/etc/biome/owner-env`.
3. At the next boot, after attestation, the value appears in `/etc/environment`.

Rules:

- A secret is delivered only if **both** hold: the owner labelled it `sticky`
  (or put it in another bucket marked `"auto": true` that trusts the operator
  on `vm_tee`), and the image's `owner-env` names it.
- Names must be valid variable names (`^[A-Za-z_][A-Za-z0-9_]*$`), must not
  begin with `_` or `BIOME_`, and must not be `MNEMONIC`.
- Values must not contain a single quote or a newline, and are limited to
  about 1 KB ([API.md section 3](API.md#names-and-limits)).
- Keep at most 32 secrets under `sticky`. More than that and the KBS refuses
  the whole release, so the VM does not boot.
- Secrets are read at boot. A change reaches a running VM at its next boot.
- The owner's SSH keys, private keys and remote-desktop settings are ignored
  in a TEE VM.
- An owner who has written their own `_BUCKET_sticky` without the AMAHub
  operator releases nothing; that is how an owner revokes.

By labelling a secret `sticky`, the owner releases it to the attested image
they launch. The owner is trusting that image's code, identified by its root,
not the operator.

## 13. Wallet, state disk and new versions

Inside the VM, before any network access, the deployment derives two keys from
the AMD chip: the state disk key and the wallet (`MNEMONIC`). The inputs are:

- the physical chip
- the launch measurement (firmware, kernel, initrd, command line, vCPU count)
- the agent root
- the deployment: uid, owner, author, agent root and base

Consequences:

| Event | Wallet and state disk |
|---|---|
| Reboot of the same deployment | **same** |
| Stop, then launch again (new uid) | new, empty |
| Same agent launched by another owner | new, empty |
| A new version of the image (new root) | new, empty |
| The host is lost or replaced | **gone** |

So today:

- **Every agent that holds funds needs a way for its owner to withdraw them**,
  built into the agent. Nobody else can reach the wallet: not the author, not
  the operator, not the KBS.
- **Releasing a new version is a new agent.** Build it, register its key and
  base, upload, publish its manifest. Owners move by withdrawing from the old
  deployment, launching the new one and depositing again.
- **To update deployments in place, the agent has to update itself.** Keep the
  image fixed and let it follow a release channel you sign:
  [section 14](#14-updating-deployed-agents).
- Treat the wallet as an operating balance, not long-term storage.

**Planned, not yet released:** platform-level updates that keep the wallet. An image will
carry a stable app name, the wallet will be derived from owner, author and app
instead of the image root, and each new image will run under an existing
deployment only after its owner signs an approval for it. Until a KBS release
announces this in [MEASUREMENT.md](MEASUREMENT.md), the table above applies and
none of it should be relied on.

## 14. Updating deployed agents

Because a new image is a new wallet, you cannot move an existing deployment to
new code by uploading a new image. What you can do, today and with no platform
support, is build the update mechanism **into the agent**: the image stays the
same (same root, same wallet, same state disk) and the code it runs follows a
release channel you sign.

```
image (fixed root)                       state disk (encrypted, per deployment)
  /opt/myagent/release.pub   your key      /var/lib/myagent/releases/<version>/
  /opt/myagent/update        updater       /var/lib/myagent/current -> releases/<version>
  /opt/myagent/app/          version 0     /var/lib/myagent/version
```

The image holds a small updater, your release public key and a first version
of the app. The updater downloads newer versions, checks your signature, and
installs them on the state disk. [`tools/agent-update.sh`](tools/agent-update.sh)
is a reference updater you can ship as is.

### What owners are trusting

Say this plainly wherever you publish the agent:

- The attested root now proves the updater and your release key, **not** the
  code that is running. Whoever holds the release key can change that code,
  and so can reach every wallet and owner secret of every deployment on the
  channel.
- Without an updater, nobody can change the code of a deployment, including
  you. Choose per agent; do not add an updater to an agent that does not need
  one.

### 1. Make a release key

```sh
openssl genpkey -algorithm ed25519 -out release.key      # keep offline; never in the image
openssl pkey -in release.key -pubout -out release.pub    # goes into the image
```

Losing `release.key` ends updates for that image. Leaking it gives away every
deployment on it. There is no way to rotate it without a new image.

### 2. Lay out the image

Add to the agent directory from [section 5](#5-step-2-prepare-the-agent-directory):

```
agent/opt/myagent/release.pub
agent/opt/myagent/update                          tools/agent-update.sh
agent/opt/myagent/app/...                         the version bundled with the image
agent/etc/systemd/system/myagent.service
agent/etc/systemd/system/myagent-update.service
agent/etc/systemd/system/myagent-update.timer
agent/etc/systemd/system/multi-user.target.wants/myagent.service -> ../myagent.service
agent/etc/systemd/system/timers.target.wants/myagent-update.timer -> ../myagent-update.timer
```

`myagent.service` runs the installed release if there is one, else the bundled
version:

```ini
[Unit]
After=biome-bootstrap-net.service network-online.target

[Service]
EnvironmentFile=/etc/environment
ExecStart=/bin/sh -c 'd=/var/lib/myagent/current; [ -x "$$d/run" ] || d=/opt/myagent/app; exec "$$d/run"'
Restart=always
```

(`$$` is how a systemd unit writes a literal `$`.)

`myagent-update.service` and `myagent-update.timer`:

```ini
[Service]
Type=oneshot
Environment=APP=myagent CHANNEL=https://updates.example.com/myagent/stable
ExecStart=/opt/myagent/update
```

```ini
[Timer]
OnBootSec=30
OnUnitActiveSec=15min
```

The updater needs `bash`, `curl`, `jq`, `tar`, `sha256sum`, `flock` and
`openssl` 3.x. The current base (`a028fda0…`) ships all of them (OpenSSL 3.5),
along with `python3`; a later base may differ, so check the one you pin.

Then build, register, upload and publish the image as in sections 6 to 9.

### 3. Publish a release

A release is a `.tar.gz` whose top level holds an executable `run`, plus a
signed `latest.json` on any HTTPS host you control:

```sh
VERSION=7                                                # an integer, higher every time
tar -czf myagent-$VERSION.tar.gz -C build/ .             # build/run must exist and be executable
jq -cn --arg a myagent --argjson v "$VERSION" \
      --arg s "$(sha256sum < myagent-$VERSION.tar.gz | cut -d' ' -f1)" \
      --arg u "https://updates.example.com/myagent/stable/myagent-$VERSION.tar.gz" \
      '{app: $a, version: $v, sha256: $s, url: $u}' > latest.json
openssl pkeyutl -sign -inkey release.key -rawin -in latest.json -out latest.json.sig
# upload the bundle first, then latest.json.sig, then latest.json
```

Every deployment installs it at its next check and restarts the agent. The
updater installs a release only if all of these hold:

- the signature on `latest.json` verifies under the key in the image
- `app` is this app
- `version` is higher than any version this deployment has installed
- the bundle matches the signed `sha256`

The host serving the channel is not trusted: it can withhold a release, never
change one.

### 4. New launches

A deployment launched from the same image starts on the bundled version and
updates itself at the first check, 30 seconds after boot. That is enough for
most agents.

If new launches must start on current code (for example the bundled version is
no longer safe to run even briefly), build a new image with the new version
under `opt/myagent/app/` and **the same `release.pub`, app name and channel**,
then publish it as in sections 6 to 9. It is a new root, so a separate agent
for new launches; existing deployments stay on the old root and keep following
the channel. To stop launches of the old image, set its manifest to
`private: true`. Do not delete its `_TEE_AGENT_KEY_<ROOT>`: existing
deployments need it at every boot.

### 5. Rules for a safe channel

- **Releases must be able to start from any earlier state.** Deployments skip
  versions; data migrations run inside the release.
- **Withdraw must survive a bad release.** Keep the owner's withdraw path as
  simple as possible and test it on every release: a release that crashes on
  start is repaired by the next one, a release that cannot withdraw strands
  funds.
- **Protect the updater from the app.** Files in the image can be overwritten
  on the state disk by root. Run the app as an unprivileged user, so a bug in
  it cannot replace `release.pub` or the updater.
- **Show what is running.** Have the agent report its version and the bundle's
  `sha256` (the updater leaves it in `current/.sha256`), so owners can compare
  with what you published.
- **Rollback is limited, not impossible.** The updater never installs a lower
  version, but a host that restores an old copy of the state disk and blocks
  the channel can keep a deployment on an older release you signed. Never sign
  something you would not want run later.
- **Owner approval, if you want it.** For agents where the owner should agree
  to each update, have the updater also require a signature over
  `app`, `version` and `sha256` by the owner's key (`BIOME_USER_PK` in
  `/etc/environment`) before installing. That keeps a leaked release key from
  being enough.
- **What a channel cannot change:** the base image and kernel, and the release
  key itself. Those need a new image, and for existing deployments that means
  withdraw and relaunch.

## 15. Troubleshooting

A TEE VM that cannot attest powers off; the hub shows `failed`. The reasons
the KBS gives, and the fix:

| KBS says | Cause | Fix |
|---|---|---|
| `author … pinned no base for this agent` | `_TEE_AGENT_BASE_<ROOT>` missing | [step 4](#7-step-4-register-the-image-key-and-base-at-the-kbs) |
| `launched on base …, the author pinned …` | manifest `base` differs from the KBS entry | make them equal |
| `operator … has not approved the agent's base` | that base is not offered on this operator's hosts | rebuild on the current base from [step 1](#4-step-1-get-the-base-image) |
| `author … does not trust this operator for TEE launches` | the author's own `_BUCKET_sticky` dropped the operator | [operator trust](#7-step-4-register-the-image-key-and-base-at-the-kbs) |
| `author … has no _TEE_AGENT_KEY_…` | image key missing or deleted | put it again from your backup |
| `…: no bucket trusts this operator on vm_tee` | the owner's `_BUCKET_sticky` dropped the operator | the owner restores it |
| `too many env keys to release (max 32)` | more than 32 secrets under the owner's `sticky` label | the owner unlabels some |

Other symptoms:

- **`running` but the agent does nothing:** the service is not enabled in the
  image (missing `wants` symlink), or it started before
  `biome-bootstrap-net.service`.
- **An owner secret is missing:** not labelled `sticky`, not named in
  `/etc/biome/owner-env`, or its value contains `'` or a newline.
- **Upload `state: "error"`:** the file is not what `make-tee-agent.sh`
  produced for that root; rebuild and upload the new root.

## 16. Complete example

```sh
set -euo pipefail
KBS=https://kbsv2.ama.one  HUB=https://api-hub.ama.one
tok() { python3 -c 'from kbs_client import kbs_token; import sys; print(kbs_token(int(sys.argv[1], 16)))' "$SK_HEX"; }
AUTHOR_PK=$(python3 -c 'from kbs_client import namespace; import sys; print(namespace(int(sys.argv[1], 16)))' "$SK_HEX")
hub() { curl -sf -X POST "$HUB$1" -H "Authorization: Bearer $(tok)" -H 'Content-Type: application/json' --data-binary @-; }
put() { jq -n --arg k "$1" --arg v "$2" '{key: $k, value: $v}' |
        curl -sf -X POST "$KBS/v1/secret/put" -H "Authorization: Bearer $(tok)" -H 'Content-Type: application/json' --data-binary @- >/dev/null; }

# 1. base
BASE=$(curl -sf "$HUB/v1/tee/base" -H "Authorization: Bearer $(tok)" | jq -r .root)

# 2-3. build (agent/ prepared as in section 5); back up agent.key now
ROOT=$(tools/make-tee-agent.sh agent/ agent.img agent.key)

# 4. KBS
put "_TEE_AGENT_KEY_$ROOT"  "$(tr -d '\n' < agent.key)"
put "_TEE_AGENT_BASE_$ROOT" "$BASE"

# 5. upload
R=$(jq -n --arg n "$ROOT" --argjson s "$(stat -c %s agent.img)" '{agent_name: $n, size: $s}' | hub /v1/agent_builder/upload_url)
ID=$(jq -r .upload_id <<< "$R")
curl -f -X PUT --upload-file agent.img "$(jq -r .url <<< "$R")"
jq -n --arg n "$ROOT" --arg i "$ID" '{agent_name: $n, upload_id: $i}' | hub /v1/agent_builder/upload_complete >/dev/null
until S=$(curl -sf "$HUB/v1/agent_builder/upload_status/$ROOT/$ID" -H "Authorization: Bearer $(tok)" | jq -r .state); [ "$S" != verifying ]; do sleep 5; done
[ "$S" = ok ] || { echo "upload failed: $S" >&2; exit 1; }

# 6. manifest
jq -n --arg n "$ROOT" --arg b "$BASE" '{agent_name: $n, manifest: {name_display: "My agent", description: "",
  private: true, author_fee: 0, secrets: {}, tabs: {default: "", extra: []}, tee: true, base: $b}}' |
  hub /v1/agent_builder/manifest

# 7. launch
UID_=$(jq -n --arg p "$AUTHOR_PK" --arg n "$ROOT" '{agent_pk: $p, agent_name: $n}' | hub /v1/agent/create | jq -r .uid)

# 8. verify once it is running
sleep 90
curl -sf "$KBS/v1/tee/attestation/$UID_" | jq '.verdict.ok'      # true
echo "agent $ROOT deployed as $UID_: https://kbsv2.ama.one/verify/$UID_"
```
