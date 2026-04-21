#!/usr/bin/env bash
# Git pre-push hook: run `make ci-check` before a push.
#
# Why this exists: oxwrt-linux and oxwrtd are both gated on
# `#![cfg(target_os = "linux")]`, so a macOS `cargo clippy` sees
# them as empty crates and silently skips all their lints. On
# 2026-04-20 this let ~40 commits of clippy-1.95 warnings (and
# one genuine test flake) pile up between CI runs we actually
# looked at. `make ci-check` runs the same fmt + clippy + test
# suite CI does, inside a Linux container. Running it before
# every push catches CI failures in ~30s (cached) instead of
# the 3-5 min CI round-trip.
#
# Install via `make install-hooks` (symlinks this file into
# `.git/hooks/pre-push`). Skip a single push with
# `git push --no-verify`. Disable entirely by `rm .git/hooks/pre-push`.
#
# Fast path: if Docker isn't running, the hook prints a warning
# and exits 0 rather than blocking. Rationale: a dev on a laptop
# without Docker booted shouldn't be unable to push hotfixes;
# CI still catches the failure upstream. `make ci-check` output
# explains how to fix if the hook fails.

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

# Honor opt-out for emergencies. OXWRT_SKIP_CI_CHECK=1 git push
if [[ "${OXWRT_SKIP_CI_CHECK:-0}" == "1" ]]; then
    echo "pre-push: OXWRT_SKIP_CI_CHECK=1 set; skipping ci-check"
    exit 0
fi

# If nothing would actually be pushed (remote already has every
# commit), skip. Git still invokes the hook for no-op pushes.
# stdin carries `<local_ref> <local_sha> <remote_ref> <remote_sha>`
# per pushed ref; an empty stdin means nothing to push.
stdin_content=$(cat)
if [[ -z "$stdin_content" ]]; then
    exit 0
fi

# Docker availability check — bail soft if absent. We do want the
# hook to enforce quality, but not to make `git push` impossible
# on a workstation where Docker is still booting.
if ! docker info >/dev/null 2>&1; then
    echo "pre-push: warning — docker not available; skipping ci-check"
    echo "pre-push:   start Docker and re-push, or run 'make ci-check' manually."
    exit 0
fi

echo "pre-push: running 'make ci-check' (override with OXWRT_SKIP_CI_CHECK=1)"
if ! make ci-check; then
    echo ""
    echo "pre-push: ci-check FAILED — push aborted."
    echo "pre-push: fix the errors above, or bypass once with 'git push --no-verify'."
    exit 1
fi
