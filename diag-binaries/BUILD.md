# Diagnostic binary builds

Static aarch64-linux-musl binaries for the `DIAG_BINARIES` whitelist
in `oxwrtd/src/control/server.rs`. Each runs inside the standard
container hardening pipeline (caps drop + no_new_privs + seccomp +
landlock). The binaries ship at `/usr/lib/oxwrt/diag/bin/` on the
firmware's squashfs rootfs, protected by dm-verity.

All builds use Docker Desktop (aarch64 on Apple Silicon) with an
Alpine container — a native build inside Docker IS the cross-build.

## ping (iputils)

```sh
docker run --rm -v /tmp/iputils-build:/out alpine:latest sh -c '
  apk add build-base meson linux-headers libcap-dev libcap-static git
  git clone --depth=1 https://github.com/iputils/iputils.git /tmp/src
  cd /tmp/src
  meson setup build \
    -Dc_link_args=-static \
    -DBUILD_MANS=false -DBUILD_HTML_MANS=false \
    -DUSE_IDN=false -DUSE_GETTEXT=false \
    -DNO_SETCAP_OR_SUID=true \
    --default-library=static
  ninja -C build
  strip build/ping/ping -o /out/ping
'
cp /tmp/iputils-build/ping diag-binaries/ping
```

- 348 KB stripped, static-pie, no runtime deps
- Hardening: `caps_retain = ["NET_RAW"]`, everything else default

## traceroute (Dmitry Butskoy)

```sh
docker run --rm -v /tmp/traceroute-build:/out alpine:latest sh -c '
  apk add build-base linux-headers
  wget -q "https://sourceforge.net/projects/traceroute/files/traceroute/traceroute-2.1.5/traceroute-2.1.5.tar.gz" -O /tmp/tr.tar.gz
  cd /tmp && tar xzf tr.tar.gz && cd traceroute-2.1.5
  make LDFLAGS="-static -s"
  cp traceroute/traceroute /out/traceroute
'
cp /tmp/traceroute-build/traceroute diag-binaries/traceroute
```

- 199 KB stripped, static-pie, no runtime deps
- Hardening: `caps_retain = ["NET_RAW"]`

## drill (ldns — replaces BIND dig)

BIND's `dig` has 15+ dynamic deps; `drill` from NLnet Labs' ldns
library is functionally equivalent with only 2 deps (ldns + libcrypto).
Build from source with static OpenSSL:

```sh
docker run --rm -v /tmp/drill-build:/out alpine:latest sh -c '
  apk add build-base openssl-dev openssl-libs-static ldns-dev ldns-static
  wget -q "https://nlnetlabs.nl/downloads/ldns/ldns-1.8.4.tar.gz" -O /tmp/ldns.tar.gz
  cd /tmp && tar xzf ldns.tar.gz && cd ldns-1.8.4
  ./configure --disable-shared --enable-static --with-drill --with-ssl
  make -j$(nproc)
  gcc -static -o /out/drill \
    drill/chasetrace.o drill/dnssec.o drill/drill.o \
    drill/drill_util.o drill/error.o drill/root.o \
    drill/securetrace.o drill/work.o \
    compat/b64_pton.o compat/b64_ntop.o \
    .libs/libldns.a -lssl -lcrypto -lpthread
  strip /out/drill
'
cp /tmp/drill-build/drill diag-binaries/drill
```

- 4.8 MB stripped (OpenSSL static is large), static-pie, no runtime deps
- Hardening: default profile (no extra caps)
- Usage: `diag drill example.com`, `diag drill example.com @1.1.1.1 MX`

## ss (iproute2)

Socket inspection tool. Build from Alpine-patched iproute2 source:

```sh
docker run --rm -v /tmp/ss-build:/out alpine:latest sh -c '
  apk add build-base linux-headers bison flex libmnl-dev libmnl-static \
          libcap-dev libcap-static alpine-sdk
  mkdir -p /tmp/abuild && cd /tmp/abuild
  git clone --depth=1 https://git.alpinelinux.org/aports
  cd aports/main/iproute2 && source APKBUILD
  wget -q "https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-${pkgver}.tar.gz" -O /tmp/ip2.tar.gz
  cd /tmp && tar xzf ip2.tar.gz && cd iproute2-${pkgver}
  for p in /tmp/abuild/aports/main/iproute2/*.patch; do
    [ -f "$p" ] && patch -p1 < "$p"
  done
  ./configure --prefix=/usr && make -j$(nproc)
  gcc -static -o /out/ss \
    misc/ss.o misc/ssfilter.tab.o misc/ssfilter_check.o \
    lib/libutil.a lib/libnetlink.a -lmnl -lcap
  strip /out/ss
'
cp /tmp/ss-build/ss diag-binaries/ss
```

- 347 KB stripped, static-pie, no runtime deps
- Hardening: `caps_retain = ["NET_ADMIN"]` (socket diag netlink)
- Usage: `diag ss`, `diag ss -tl`
- Note: Alpine patches are required — upstream iproute2 has SIOCGSTAMPNS
  redefinition conflicts with musl kernel headers.

## Verification

After building, verify each binary:
```sh
file diag-binaries/ping
# → ELF 64-bit LSB pie executable, ARM aarch64, ... static-pie linked, ... stripped

# End-to-end via the supervisor:
docker run --rm --privileged --cgroupns=private \
  -v "$PWD/target/aarch64-unknown-linux-musl/release/oxwrtd:/oxwrtd:ro" \
  alpine:latest sh -c '
    mkdir -p /usr/lib/oxwrt/diag/bin
    cp /diag-binaries/ping /usr/lib/oxwrt/diag/bin/ping
    # ... start supervisor, call: diag ping 127.0.0.1 3
  '
```
