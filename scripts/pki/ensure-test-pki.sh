#!/bin/sh
# Called by `npm test`: (re)generates the disposable, git-ignored test and demo PKIs under .pki/
# when they are missing or were made by a different version of the PKI scripts.
set -eu
umask 077
cd "$(dirname "$0")/../.."
stamp=$(cat scripts/pki/pki-lib.sh scripts/pki/identra-pki.sh scripts/pki/make-test-pki.sh scripts/pki/make-demo-pki.sh | openssl dgst -sha256 -r | cut -c1-64)
if [ "$(cat .pki/stamp 2>/dev/null || true)" = "$stamp" ]; then exit 0; fi
rm -rf .pki/test .pki/demo .pki/stamp
mkdir -p .pki
bash scripts/pki/make-test-pki.sh .pki/test >/dev/null
# The demo set uses the real clock and the default issuer URLs; the tests check it at the current time.
bash scripts/pki/make-demo-pki.sh .pki/demo >/dev/null
echo "$stamp" >.pki/stamp
echo "test PKI generated in .pki/"
