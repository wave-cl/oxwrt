# Releasing oxwrt

The happy path — from clean tree to a GitHub Release with signed
firmware — is three commands. Everything else in this file is
pre-flight checks, one-time setup, and the "something went wrong"
branch.

```sh
scripts/release.sh minor --dry-run     # preview CHANGELOG + version
scripts/release.sh minor               # bump + commit + tag locally
git push origin main v0.X.Y            # CI takes it from here
```

The `v*` tag triggers `.github/workflows/release.yml`, which
builds the aarch64 sysupgrade image, signs it with the key
stored as the `OXWRT_SIGNING_KEY` repo secret, and publishes a
GitHub Release with the `.bin` + `.bin.sig` + `oxctl-*` binaries
attached.

## Pre-flight checklist

Run through these before `scripts/release.sh`. All five take
under two minutes on cached state.

1. **Working tree clean.**
   ```sh
   git status           # empty
   ```
   `release.sh` refuses to run otherwise; catches the "forgot to
   commit that one edit" footgun.

2. **On `main`, up to date with origin.**
   ```sh
   git fetch origin && git log HEAD..origin/main     # empty
   ```
   Tagging a stale commit and pushing would put the tag at
   a non-tip commit — recoverable, but confusing in the GitHub
   Releases UI.

3. **CI green on origin/main.**
   ```sh
   gh run list --branch main --limit 3
   ```
   fmt + clippy + test + QEMU all green on the head of main. If
   the pre-push hook is installed (see `make install-hooks`) you
   also have local coverage.

4. **`make ci-check` passes locally.**
   ```sh
   make ci-check
   ```
   Mirror of the Linux-container test suite. Catches clippy
   drift that macOS `cargo clippy` masks (cfg(target_os=linux)).

5. **Bench smoke-test.**
   Flash the current `main` onto the bench router, confirm:
   - Wi-Fi SSID joins with baked passphrase.
   - `oxctl status` responds via sQUIC control plane.
   - `oxctl diag links` lists all expected interfaces.

   If any of the above fails, fix on main before tagging. A
   broken release is worse than a delayed one.

## One-time setup: release-signing keypair

Done once per repo. The private key never leaves the build host
except as an encrypted GitHub Actions secret.

```sh
# 1. Build the oxctl client.
cargo build --release -p oxwrtctl-cli

# 2. Generate a fresh 32-byte ed25519 seed.
head -c 32 /dev/urandom > provisioning/release-signing.key
chmod 0600 provisioning/release-signing.key

# 3. Derive the companion pubkey.
OXWRT_SIGNING_KEY_PATH=provisioning/release-signing.key \
  ./target/release/oxctl --sign --print-pubkey \
  | xxd -r -p > provisioning/release-pubkey.ed25519

# 4. Sanity-check sizes.
test "$(wc -c < provisioning/release-pubkey.ed25519)" = 32 \
  && test "$(wc -c < provisioning/release-signing.key)" = 32 \
  && echo "keypair OK"

# 5. Store the private key as a GitHub secret.
#    Copy the hex output of:
xxd -p -c 64 provisioning/release-signing.key
#    Paste it into https://github.com/wave-cl/oxwrt/settings/secrets/actions
#    as a new repo SECRET named OXWRT_SIGNING_KEY.
#
# 6. Store the public key as a GitHub Actions variable (NOT a
#    secret — it's public by design; every built image carries
#    it embedded).
xxd -p -c 64 provisioning/release-pubkey.ed25519
#    Paste it into https://github.com/wave-cl/oxwrt/settings/variables/actions
#    as a new repo VARIABLE named OXWRT_RELEASE_PUBKEY_HEX. The
#    release workflow re-creates provisioning/release-pubkey.ed25519
#    from this variable on every run, so CI-built images bake
#    the right pubkey without committing the file to the repo.
```

`provisioning/` is gitignored, so neither file can accidentally
land in a commit. Back up `provisioning/release-signing.key`
somewhere safe (encrypted USB / password manager) — losing it
means every future release needs a new signing keypair, which
invalidates every already-deployed router's baked pubkey until
they sysupgrade to an image carrying the new one.

### Rotating the signing key

If the private key leaks or the backup is lost:

1. Generate a new keypair (steps 2–5 above).
2. Cut a release with the new pubkey baked in (the image will
   still verify incoming updates against whatever pubkey it was
   built with).
3. **Operators holding devices on the old pubkey must flash the
   new image via U-Boot recovery** — they can't `oxctl update`
   to it, because the new image's signature verifies against the
   new key, not the old one their device has. Plan rotation
   accordingly.

## What the CI release workflow does

On `git push origin v0.X.Y`, `.github/workflows/release.yml`:

1. Checks out the tagged commit + the sibling `squic-rust`.
2. Cross-builds `oxwrtd` for `aarch64-unknown-linux-musl`.
3. Builds the OpenWrt sysupgrade image via `make imagebuilder-image`.
4. Signs the `.bin` with the `OXWRT_SIGNING_KEY` repo secret via
   `oxctl --sign`, producing `<image>.bin.sig` next to it.
5. Cross-builds `oxctl` binaries for Linux-x86_64 (host-side
   consumers) and macOS-aarch64 (dev laptops).
6. Creates a GitHub Release at the tag with:
   - `<image>-sysupgrade.bin`
   - `<image>-sysupgrade.bin.sig`
   - `oxctl-linux-x86_64`
   - `oxctl-darwin-aarch64`
   - Release notes body = the just-prepended CHANGELOG section.

Typical run: ~12-15 minutes. First-run on a new GitHub Actions
cache is ~25 minutes (Docker + imagebuilder tarball download).

## Post-release verification

After the CI job finishes:

1. Open `https://github.com/wave-cl/oxwrt/releases/tag/v0.X.Y`.
   Confirm `.bin`, `.bin.sig`, `oxctl-*` are all attached.

2. Verify the signature locally (from a fresh clone so you're
   checking the published artifact, not a local build):
   ```sh
   curl -LO https://github.com/wave-cl/oxwrt/releases/download/v0.X.Y/<image>-sysupgrade.bin
   curl -LO https://github.com/wave-cl/oxwrt/releases/download/v0.X.Y/<image>-sysupgrade.bin.sig

   # Re-hash + verify against the baked pubkey.
   sha256sum <image>-sysupgrade.bin
   # The sig is hex(ed25519_sign(sha256(bin))). Verify against
   # provisioning/release-pubkey.ed25519 with any ed25519 verifier;
   # easiest is to run a signed `oxctl update` against the bench
   # router below — it's what actually matters in prod.
   ```

3. Flash the bench router via `oxctl update`:
   ```sh
   oxctl <bench-addr> update <image>-sysupgrade.bin
   oxctl <bench-addr> apply --confirm
   ```
   Device reboots. After boot, `oxctl <bench-addr> status` shows
   the new version.

4. If any step fails, unpublish the release first (GitHub UI → mark
   as pre-release), triage, and either patch forward or roll the
   tag back (next section).

## Emergency rollback

If a published release is broken:

```sh
# Untag locally + push the delete.
git tag -d v0.X.Y
git push origin :v0.X.Y

# The GitHub Release page stays but without a backing tag
# becomes marked as "Draft" in the UI. Use the web UI to
# delete the release entry itself if you want a clean slate.
```

No need to rewrite history; the next release on a fixed main
picks up where the broken one left off. Operators who already
pulled `v0.X.Y` and flashed have a working (if broken) device —
the `oxctl update` path is idempotent, so `v0.X.Y+1` overwrites
cleanly once published.

## Version scheme

Loose semver:

- **patch** (`0.X.Y` → `0.X.Y+1`): bug fixes, documentation,
  build-system tweaks. No config schema changes, no RPC
  additions, no wire-format breaks.
- **minor** (`0.X.Y` → `0.X+1.0`): new config fields (with sane
  defaults), new RPCs, feature additions. Backward-compatible.
- **major** (`0.X.Y` → `X+1.0.0`): config schema breakage, wire
  format changes, removed RPCs. Migration notes required in the
  CHANGELOG.

Pre-1.0: minor-version bumps may contain small breakage if the
CHANGELOG calls it out. Post-1.0: the major/minor/patch contract
is strict.
