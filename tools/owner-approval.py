#!/usr/bin/env python3
"""Owner approval of one agent update (DEPLOY-TEE.md, "Owner approval").

  owner-approval.py sign   <sk hex> <app> <uuid> <version> <sha256>         -> signature (hex) on stdout
  owner-approval.py verify <owner pk base58> <app> <uuid> <version> <sha256> <signature file>
                                                                           -> exit 0 if valid

The owner signs with the BLS12-381 key they launched the deployment with (the
key behind their bearer token; its public key is BIOME_USER_PK in the VM).
Needs py_ecc and base58: pip install --target <dir> py_ecc base58, and bundle
<dir> in the image for `verify` (PYTHONPATH=<dir>).
"""
import sys

import base58
from py_ecc.bls import G2Basic


class Approval(G2Basic):
    DST = b"TEE_AGENT_UPDATE_APPROVE_V1_BLS12381G2_XMD:SHA-256_SSWU_RO_"


def message(app, uuid, version, sha256):
    if not str(version).isdigit() or len(sha256) != 64 or "\n" in app + uuid:
        raise ValueError("bad approval fields")
    return f"tee-agent-update-approve/v1\n{app}\n{uuid}\n{int(version)}\n{sha256}\n".encode()


def main(argv):
    if len(argv) == 6 and argv[0] == "sign":
        print(Approval.Sign(int(argv[1], 16), message(*argv[2:6])).hex())
        return 0
    if len(argv) == 7 and argv[0] == "verify":
        signature = bytes.fromhex(open(argv[6]).read().strip())
        pk = base58.b58decode(argv[1])
        if len(pk) == 48 and len(signature) == 96 and Approval.Verify(pk, message(*argv[2:6]), signature):
            return 0
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception:
        sys.exit(1)
