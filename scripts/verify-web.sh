#!/usr/bin/env bash
# Checks that a Help Peer site serves the web app its commit builds to.
#
#   scripts/verify-web.sh https://help-peer.org
#
# Reads the deployed commit from /api/version, builds that commit's frontend
# in Docker with the pinned images, and compares the result with what the
# site serves. Exit code 0: match. 1: mismatch. 2: could not check.
# Set REPO to clone from somewhere else, e.g. REPO=$PWD for a local checkout.
# Needs bash, curl, git, docker and sha256sum.
set -euo pipefail

site=${1:-}
site=${site%/}
repo=${REPO:-https://github.com/JenD86/help-peer}

fail() {
  echo "ERROR: $*" >&2
  exit 2
}

[ -n "$site" ] || fail "usage: $0 <site url>, e.g. $0 https://help-peer.org"

version=$(curl -fsS "$site/api/version") || fail "could not read $site/api/version"
commit=$(printf '%s' "$version" | sed -n 's/.*"commit":"\([^"]*\)".*/\1/p')
reported=$(printf '%s' "$version" | sed -n 's/.*"index_sha256":"\([0-9a-f]*\)".*/\1/p')
[ -n "$commit" ] && [ -n "$reported" ] || fail "unexpected /api/version response: $version"
[ "$commit" != unknown ] || fail "the site was built without a commit, outside the deploy workflow"
echo "Site reports commit $commit"

tmp=$(mktemp -d)
image=helppeer-verify-$commit
trap 'rm -rf "$tmp"; docker rmi -f "$image" >/dev/null 2>&1 || true' EXIT

echo "Building commit $commit from $repo ..."
git clone --quiet "$repo" "$tmp/repo" || fail "could not clone $repo"
git -C "$tmp/repo" checkout --quiet "$commit" || fail "commit $commit is not in $repo"
docker build --quiet --target frontend-builder -t "$image" "$tmp/repo/web" >/dev/null || fail "build failed"
container=$(docker create "$image")
docker cp "$container:/app/backend/static" "$tmp/static" >/dev/null
docker rm "$container" >/dev/null

status=0

# 1. The site's own claim about index.html.
built=$(sha256sum "$tmp/static/index.html" | cut -d' ' -f1)
if [ "$built" = "$reported" ]; then
  echo "OK    index.html hash matches /api/version"
else
  echo "FAIL  index.html built from $commit has hash $built, the site reports $reported"
  status=1
fi

# 2. The template the site serves, byte for byte. The backend fills the
# placeholders in per page, so the rendered pages can't be compared directly.
curl -fsS "$site/api/template" -o "$tmp/template.html" || fail "could not fetch $site/api/template"
if cmp -s "$tmp/static/index.html" "$tmp/template.html"; then
  echo "OK    served template matches the build"
else
  echo "FAIL  served template differs from the build:"
  diff -u "$tmp/static/index.html" "$tmp/template.html" | head -20 || true
  status=1
fi

# 3. Rendered pages must have every placeholder filled in.
for page in / /upload /download; do
  curl -fsS "$site$page" -o "$tmp/page.html" || fail "could not fetch $site$page"
  if grep -q '{{' "$tmp/page.html"; then
    echo "FAIL  $page still has unfilled placeholders"
    status=1
  else
    echo "OK    $page has no unfilled placeholders"
  fi
done

# 4. The JS and CSS index.html loads. Browsers already refuse a file that
# doesn't match its integrity hash, but this shows the mismatch directly.
for path in $(grep -o '/assets/[^"]*\.\(js\|css\)' "$tmp/static/index.html" | sort -u); do
  if curl -fsS "$site$path" -o "$tmp/asset" && cmp -s "$tmp/asset" "$tmp/static$path"; then
    echo "OK    $path matches the build"
  else
    echo "FAIL  $path differs from the build"
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  echo "MATCH: $site serves the web app commit $commit builds to."
else
  echo "MISMATCH: $site does not serve what commit $commit builds to."
fi
exit "$status"
