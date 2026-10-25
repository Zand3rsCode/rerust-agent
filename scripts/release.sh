#!/usr/bin/env bash
# Build a release into dist/: the agent for linux amd64 + arm64, install.sh with the version filled in,
# SHA256SUMS and its Ed25519 signature (SHA256SUMS.sig).
#
#   bash scripts/release.sh 0.1.0            build + sign only
#   bash scripts/release.sh 0.1.0 --publish  also create the GitHub release v0.1.0 (gh), notes = its CHANGELOG section
#
# The signing key never goes into the repo: RERUST_SIGNING_KEY (default ~/.config/rerust-agent/release-signing.pem).
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${1:?usage: release.sh <x.y.z> [--publish]}
VERSION=${VERSION#v}
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be x.y.z" >&2; exit 1; }
KEY=${RERUST_SIGNING_KEY:-$HOME/.config/rerust-agent/release-signing.pem}
[[ -f $KEY ]] || { echo "signing key $KEY not found" >&2; exit 1; }
grep -q "^## v$VERSION" CHANGELOG.md || { echo "CHANGELOG.md has no '## v$VERSION' section" >&2; exit 1; }

# The key in install.sh and in the agent must be the signing key's public half.
pub=$(openssl pkey -in "$KEY" -pubout)
[[ "$pub" == "$(cat internal/agent/release_key.pub.pem)" ]] || { echo "internal/agent/release_key.pub.pem is not the signing key's public key" >&2; exit 1; }
grep -qF "$(sed -n 2p internal/agent/release_key.pub.pem)" install.sh || { echo "install.sh carries another release key" >&2; exit 1; }

go vet ./...
go test ./...

rm -rf dist && mkdir dist
for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
        -o "dist/rerust-agent-linux-$arch" ./cmd/rerust-agent
done
sed "s/@VERSION@/$VERSION/" install.sh >dist/install.sh
chmod 755 dist/install.sh dist/rerust-agent-linux-*
(cd dist && sha256sum rerust-agent-linux-amd64 rerust-agent-linux-arm64 install.sh >SHA256SUMS)
openssl pkeyutl -sign -inkey "$KEY" -rawin -in dist/SHA256SUMS -out dist/SHA256SUMS.sig
openssl pkeyutl -verify -pubin -inkey internal/agent/release_key.pub.pem -rawin -in dist/SHA256SUMS -sigfile dist/SHA256SUMS.sig >/dev/null
awk -v v="## v$VERSION" '$0 ~ "^## v" { on = ($1" "$2 == v) } on' CHANGELOG.md | tail -n +2 >dist/notes.md
echo "Built v$VERSION:"; ls -l dist

if [[ ${2:-} == --publish ]]; then
    [[ -z $(git status --porcelain) ]] || { echo "commit your changes first (the release is built from the files on disk)" >&2; exit 1; }
    git fetch -q origin
    [[ $(git rev-parse HEAD) == $(git rev-parse origin/main) ]] || { echo "push main first: GitHub must have this exact commit" >&2; exit 1; }
    gh release create "v$VERSION" --target "$(git rev-parse HEAD)" --title "v$VERSION" --notes-file dist/notes.md \
        dist/rerust-agent-linux-amd64 dist/rerust-agent-linux-arm64 dist/install.sh dist/SHA256SUMS dist/SHA256SUMS.sig
fi
