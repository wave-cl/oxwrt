#!/bin/sh
# uart-capture.sh — capture serial console from the Flint 2 during boot.
#
# Use case: UART adapter soldered to J1 on the GL-MT6000 PCB, USB-TTL
# plugged into the Mac. We run this script, power-cycle or sysupgrade
# the router, and the script captures every byte the console emits
# from that moment until we ctrl-C — through U-Boot banner, kernel
# boot log, procd preinit, and into userspace login or hang.
#
# Usage:
#   ./scripts/uart-capture.sh             # auto-detect tty + log to default path
#   ./scripts/uart-capture.sh /dev/tty... # explicit device
#   ./scripts/uart-capture.sh -o log.txt  # custom log path
#
# Defaults:
#   Baud      115200 (MediaTek + GL.iNet convention)
#   Format    8N1, no flow control (matches the J1 header specs per
#             the OpenWrt hardware wiki for gl-mt6000)
#   Log path  build/uart/<timestamp>-boot.log
#
# When the session ends (ctrl-a ctrl-q in picocom, or ctrl-c if we
# fall back to `cat`), the full log is split into phases for quick
# scanning — uboot / kernel / procd / userspace — so we don't have to
# grep across a 5000-line log by hand.

set -eu

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEFAULT_LOGDIR="$PROJ_ROOT/build/uart"
BAUD="${BAUD:-115200}"

DEVICE=""
LOGFILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) LOGFILE="$2"; shift 2 ;;
        -b) BAUD="$2"; shift 2 ;;
        -h|--help)
            sed -n '/^# uart-capture/,/^$/p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        /dev/*) DEVICE="$1"; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# Auto-detect if not given. macOS names USB serial devices
# /dev/tty.usbserial-* (legacy/dial-in) or /dev/cu.usbserial-*
# (call-up / "use for outbound"). For terminal apps we want cu.*.
# CH340 adapters show up as /dev/cu.wchusbserial-*; FTDI as
# /dev/cu.usbserial-AXXXXXX; CP2102 as /dev/cu.SLAB_USBtoUART on
# older drivers or /dev/cu.usbserial-0001 on newer.
if [ -z "$DEVICE" ]; then
    # glob across the common names; prefer cu.* over tty.*
    for g in /dev/cu.usbserial-* /dev/cu.wchusbserial-* /dev/cu.SLAB_* /dev/tty.usbserial-* /dev/tty.wchusbserial-*; do
        for d in $g; do
            if [ -c "$d" ]; then DEVICE="$d"; break 2; fi
        done
    done
fi

if [ -z "$DEVICE" ] || [ ! -c "$DEVICE" ]; then
    echo "Error: couldn't auto-detect a USB-serial adapter on the Mac." >&2
    echo "Plug the USB-TTL adapter in, then run:" >&2
    echo "  ls /dev/cu.usbserial* /dev/cu.wchusbserial* /dev/cu.SLAB_* 2>/dev/null" >&2
    echo "and pass the path as the first arg." >&2
    exit 1
fi

mkdir -p "$DEFAULT_LOGDIR"
if [ -z "$LOGFILE" ]; then
    TS=$(date +%Y%m%d-%H%M%S)
    LOGFILE="$DEFAULT_LOGDIR/${TS}-boot.log"
fi

echo "=== UART capture ==="
echo "device: $DEVICE"
echo "baud:   $BAUD"
echo "log:    $LOGFILE"
echo ""
echo "Tip: power-cycle or \`sysupgrade -n\` the router NOW to capture"
echo "     the full boot sequence. Press ctrl-a ctrl-q (picocom) or"
echo "     ctrl-c (cat) to end the capture."
echo ""
echo "==================="

# Pick the reader. picocom is the nicest (supports input + reliable
# exit); `screen` has exit-hotkey collisions with tmux; `cat` is the
# dumb fallback (read-only, exits on ctrl-c).
if command -v picocom >/dev/null 2>&1; then
    picocom --baud "$BAUD" --imap lfcrlf --omap crlf --flow n \
        --log "$LOGFILE" --quiet "$DEVICE"
elif command -v screen >/dev/null 2>&1; then
    # screen -L logs to a file; append a space + `...` after -L to
    # force a logfile (screen's flag parsing is particular).
    echo "(using screen; ctrl-a k to end)"
    screen -L -Logfile "$LOGFILE" "$DEVICE" "$BAUD"
else
    # Dumb reader — no input, just dump bytes. stty sets line params.
    stty -f "$DEVICE" "$BAUD" cs8 -cstopb -parenb raw -echo
    echo "(no picocom or screen; using cat. ctrl-c to end.)"
    cat "$DEVICE" | tee "$LOGFILE"
fi

echo ""
echo "=== capture ended ==="
echo "Log: $LOGFILE ($(wc -l < "$LOGFILE") lines, $(wc -c < "$LOGFILE") bytes)"
echo ""
echo "=== phases (line counts) ==="
printf "  U-Boot    "; grep -c -E "^U-Boot |bootargs=|Loading Environment" "$LOGFILE" 2>/dev/null || echo 0
printf "  Kernel    "; grep -c -E "^\[ *[0-9]+\.[0-9]+\]" "$LOGFILE" 2>/dev/null || echo 0
printf "  procd     "; grep -c -E "procd:" "$LOGFILE" 2>/dev/null || echo 0
printf "  uci-def.. "; grep -c -E "uci-default" "$LOGFILE" 2>/dev/null || echo 0
printf "  oxwrtd  "; grep -c -E "oxwrtd" "$LOGFILE" 2>/dev/null || echo 0

echo ""
echo "=== tail of capture (last 20 lines) ==="
tail -20 "$LOGFILE"

echo ""
echo "Common greps:"
echo "  grep -E 'panic|BUG|oops|Kernel panic' $LOGFILE"
echo "  grep -E 'Call trace|Backtrace' -A 10 $LOGFILE"
echo "  grep 'procd:' $LOGFILE | tail -20"
