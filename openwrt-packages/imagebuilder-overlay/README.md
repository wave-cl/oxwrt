# imagebuilder-overlay

Side-by-side overlay for the OpenWrt imagebuilder — lets us bake the
`oxwrtd` binary and its procd init script into a stock OpenWrt image
*without* replacing procd/netifd/fw4. This is the "safe" deployment
path used during hardware bring-up: oxwrt runs as a side binary with
`--control-only` alongside the stock stack.

The `openwrt-packages/oxwrtd/Makefile` package is the *other* path
(full PID-1 takeover via `/sbin/init` symlink); that one is used by the
final image, not during iteration.

## Usage

Download the imagebuilder for your target (`mediatek/filogic` on the
GL-MT6000 / Flint 2) into `$PROJECT_ROOT/imagebuilder/` — this directory
is `.gitignore`d because it's a multi-GB download. Then invoke its
`image` target with:

```sh
make image PROFILE=glinet_gl-mt6000 \
  FILES=$PROJECT_ROOT/openwrt-packages/imagebuilder-overlay/files \
  PACKAGES="..."
```

Before building, drop the cross-built `oxwrtd` binary into
`files/usr/bin/` (we keep it out of git since it's a build artifact):

```sh
make rust-oxwrtd
cp target/aarch64-unknown-linux-musl/release/oxwrtd \
   openwrt-packages/imagebuilder-overlay/files/usr/bin/oxwrtd
```

## What's in `files/`

- `etc/init.d/oxwrtd` — procd init script. Starts oxwrtd in
  `--control-only` mode at `START=95` (post-network, post-firewall).
- `etc/uci-defaults/99-oxwrtd` — one-shot first-boot hook that runs
  `/etc/init.d/oxwrtd enable`, creating the rc.d symlinks. uci-defaults
  scripts self-delete after successful execution.
