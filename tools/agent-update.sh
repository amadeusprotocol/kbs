#!/usr/bin/env bash
# agent-update.sh -- reference in-agent updater for a TEE agent (DEPLOY-TEE.md,
# "Updating deployed agents"). Ship it inside your image and run it from a
# systemd timer. It follows the author's signed update channel:
#
#   $CHANNEL/latest.json       {"app": "...", "version": <int>, "sha256": "<hex>", "url": "<bundle .tar.gz>"}
#   $CHANNEL/latest.json.sig   Ed25519 signature over the exact bytes of latest.json
#
# A release is installed only if the signature verifies under the public key
# baked into the image, the app name matches, the version is higher than the
# one installed, and the bundle matches the signed sha256. Releases go to
# $STATE (on the deployment's encrypted state disk); `current` is switched
# atomically and the service restarted.
#
# Configuration (environment, or edit the defaults before building the image):
#   APP       app name the manifest must carry
#   CHANNEL   base URL of the channel
#   PUBKEY    Ed25519 public key, PEM (part of the image, so of its root)
#   STATE     where releases live           (default /var/lib/$APP)
#   SERVICE   systemd unit to restart       (default $APP.service; "" = none)
#   OWNER_APPROVAL=1   also require the owner's signature for each version:
#             $CHANNEL/approvals/<uuid>/<version>.sig, checked by $VERIFY_OWNER
#             (default /opt/$APP/owner-approval.py, see that file) against
#             BIOME_USER_PK and BIOME_UUID from /etc/environment. Without a
#             valid approval the release is left for the next run.
# Requires: bash, curl, jq, openssl (3.x), tar, sha256sum.
set -euo pipefail
umask 077

APP="${APP:?APP is required}"
CHANNEL="${CHANNEL:?CHANNEL is required}"
PUBKEY="${PUBKEY:-/opt/$APP/release.pub}"
STATE="${STATE:-/var/lib/$APP}"
SERVICE="${SERVICE-$APP.service}"

mkdir -p "$STATE/releases"
exec 9>"$STATE/.update.lock"
flock -n 9 || exit 0
TMP=$(mktemp -d "$STATE/.update.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

fetch() { curl -fsS --retry 3 --max-time 300 --max-filesize "$3" -o "$2" "$1"; }

fetch "$CHANNEL/latest.json" "$TMP/latest.json" 65536
fetch "$CHANNEL/latest.json.sig" "$TMP/latest.sig" 4096
openssl pkeyutl -verify -pubin -inkey "$PUBKEY" -rawin -in "$TMP/latest.json" -sigfile "$TMP/latest.sig" >/dev/null 2>&1 ||
    { echo "agent-update: bad signature on latest.json" >&2; exit 1; }

app=$(jq -er '.app | strings' "$TMP/latest.json")
version=$(jq -er '.version | numbers | select(. == floor and . > 0)' "$TMP/latest.json")
sha=$(jq -er '.sha256 | strings' "$TMP/latest.json")
url=$(jq -er '.url | strings' "$TMP/latest.json")
[[ "$app" == "$APP" ]] || { echo "agent-update: manifest is for another app" >&2; exit 1; }
[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "agent-update: bad sha256" >&2; exit 1; }

# Never go back: the highest version ever installed is kept on the state disk.
installed=$(cat "$STATE/version" 2>/dev/null || echo 0)
[[ "$installed" =~ ^[0-9]+$ ]] || installed=0
if (( version <= installed )); then
    exit 0
fi

if [[ "${OWNER_APPROVAL:-0}" == 1 ]]; then
    # Parsed, never sourced. Both values come from the verified launch package.
    envval() { sed -n "s/^$1='\\(.*\\)'\$/\\1/p" "${ENV_FILE:-/etc/environment}" | tail -n 1; }
    owner=$(envval BIOME_USER_PK); uuid=$(envval BIOME_UUID)
    [[ "$owner" =~ ^[1-9A-HJ-NP-Za-km-z]{40,80}$ && "$uuid" =~ ^[0-9a-f]{1,32}$ ]] ||
        { echo "agent-update: no owner identity in the environment" >&2; exit 1; }
    if ! fetch "$CHANNEL/approvals/$uuid/$version.sig" "$TMP/approval.sig" 4096 2>/dev/null; then
        echo "agent-update: version $version waits for the owner's approval" >&2
        exit 0
    fi
    "${VERIFY_OWNER:-/opt/$APP/owner-approval.py}" verify "$owner" "$APP" "$uuid" "$version" "$sha" "$TMP/approval.sig" ||
        { echo "agent-update: owner approval for version $version does not verify" >&2; exit 1; }
fi

fetch "$url" "$TMP/bundle.tar.gz" "${MAX_BUNDLE_BYTES:-2147483648}"
echo "$sha  $TMP/bundle.tar.gz" | sha256sum -c --quiet - ||
    { echo "agent-update: bundle does not match the signed sha256" >&2; exit 1; }

dest="$STATE/releases/$version"
rm -rf "$dest.partial"
mkdir "$dest.partial"
tar -xzf "$TMP/bundle.tar.gz" -C "$dest.partial" --no-same-owner
printf '%s\n' "$sha" > "$dest.partial/.sha256"
rm -rf "$dest"
mv "$dest.partial" "$dest"

ln -sfn "releases/$version" "$STATE/current.new"
mv -T "$STATE/current.new" "$STATE/current"
printf '%s\n' "$version" > "$STATE/version.new"
mv "$STATE/version.new" "$STATE/version"
sync

echo "agent-update: installed $APP version $version ($sha)" >&2
if [[ -n "$SERVICE" ]]; then
    systemctl restart "$SERVICE"
fi
# Keep this release and the previous one.
ls -1 "$STATE/releases" | grep -E '^[0-9]+$' | sort -n | head -n -2 | while read -r old; do rm -rf "$STATE/releases/$old"; done
