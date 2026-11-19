#!/usr/bin/env bash
# make-tee-agent.sh -- turn an agent's files into its encrypted TEE image.
#
#   tee/make-tee-agent.sh <agent dir> <out agent.img> <out.key>
#
# <agent dir> is the agent's layer over the base image: the files it adds or
# changes, laid out from / (what a tested VM's overlay holds under upper/).
# No root needed. Requires mkfs.erofs (erofs-utils), veritysetup (cryptsetup)
# and python3 with the cryptography package. Run as root, files keep their
# owners; run as anyone else, every file is owned by root in the image.
#
# Prints the agent root (64 hex), the agent's identity. <out.key> gets the
# 512-bit image key (128 hex); store it at the KBS as _TEE_AGENT_KEY_<root>,
# where only an attested TEE launch of exactly this image can get it.
#
# Image layout (4 KiB units):
#   [0, DATA)        EROFS (zstd level 15, 4 KiB clusters, tail packing, as
#                    the base root), encrypted like dm-crypt aes-xts-plain64
#                    with a 512-bit key, 4 KiB sectors and iv_large_sectors
#                    (tweak = little-endian 4 KiB sector number)
#   [DATA, END-4K)   dm-verity hash tree over the ciphertext
#   [END-4K, END)    trailer: "BIOMETEE1\n" then "data=<DATA>\n", zero padded
# The agent root is the dm-verity root hash: it commits to every encrypted
# byte. The trailer is not covered; a wrong value only fails verification.
# The guest (initrd mount-overlay) opens it with the kernel's dm-verity and
# dm-crypt using the same parameters.
set -euo pipefail
umask 077

SRC="${1:?usage: make-tee-agent.sh <agent dir> <out agent.img> <out.key>}"
OUT="${2:?usage: make-tee-agent.sh <agent dir> <out agent.img> <out.key>}"
KEY_OUT="${3:?usage: make-tee-agent.sh <agent dir> <out agent.img> <out.key>}"
[[ -d "$SRC" ]] || { echo "make-tee-agent.sh: $SRC is not a directory" >&2; exit 1; }
for t in mkfs.erofs veritysetup python3; do
    command -v "$t" >/dev/null || { echo "make-tee-agent.sh: missing $t" >&2; exit 1; }
done
python3 -c 'import cryptography' 2>/dev/null || { echo "make-tee-agent.sh: python3 cryptography package missing" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PLAIN="$WORK/agent.erofs" IMG="$WORK/agent.raw"

# 1. Read-only, compressed filesystem of exactly the agent's files.
OWNER=(); [[ $EUID == 0 ]] || OWNER=(--all-root)
mkfs.erofs -zzstd,level=15 -b4096 -Eztailpacking -T0 "${OWNER[@]}" "$PLAIN" "$SRC" >/dev/null
DATA=$(( ($(stat -c %s "$PLAIN") + 4095) / 4096 * 4096 ))
truncate -s "$DATA" "$PLAIN"

# 2. Encrypt with a fresh key, sector by sector, as dm-crypt reads it.
python3 - "$PLAIN" "$IMG" "$KEY_OUT" <<'PY'
import os, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
src, dst, key_out = sys.argv[1:]
key = os.urandom(64)
with open(src, "rb") as i, open(dst, "wb") as o:
    n = 0
    while block := i.read(4096):
        enc = Cipher(algorithms.AES(key), modes.XTS(n.to_bytes(16, "little"))).encryptor()
        o.write(enc.update(block) + enc.finalize())
        n += 1
with open(key_out, "w") as f:
    f.write(key.hex() + "\n")
PY

# 3. Integrity over the ciphertext; its root hash is the agent's identity.
ROOT=$(veritysetup format "$IMG" "$IMG" --hash-offset="$DATA" --data-block-size=4096 --hash-block-size=4096 |
    sed -n 's/^Root hash:[[:space:]]*//p')
[[ "$ROOT" =~ ^[0-9a-f]{64}$ ]] || { echo "make-tee-agent.sh: veritysetup gave no root hash" >&2; exit 1; }
veritysetup verify "$IMG" "$IMG" "$ROOT" --hash-offset="$DATA" >/dev/null

# 4. Trailer. The result is the upload: raw, already compact (compressed
# EROFS, no free space).
END=$(( ($(stat -c %s "$IMG") + 4095) / 4096 * 4096 ))
truncate -s "$END" "$IMG"
{ printf 'BIOMETEE1\ndata=%s\n' "$DATA"; head -c 4096 /dev/zero; } | head -c 4096 >> "$IMG"
mv "$IMG" "$OUT"
echo "$ROOT"
