#!/usr/bin/env bash
#
# wix-burn-extract.sh
#
# Extract a WiX Burn bootstrapper (.exe) into its constituent files on Linux.
# A Burn bootstrapper is a Windows PE that has one or more CAB archives glued
# to the end of it; the largest of those (the "WixAttachedContainer") holds
# 1..N MSI packages, each of which holds the actual payload.
#
#   .exe (PE)
#    + UI CAB (small)                <- what plain `7z x` sees
#    + WixAttachedContainer (large)  <- MSI(s) live here
#        = CAB -> 1..N .msi -> real files
#
# The script:
#   1. Scans the .exe for MSCF signatures and picks the biggest CAB.
#   2. Carves it out with dd.
#   3. Unpacks it with 7z to reveal one or more MSIs.
#   4. Runs msiextract on each MSI so file names are restored.
#
# Usage:
#   wix-burn-extract.sh [-o OUTDIR] [-k] <installer.exe|installer.zip>
#
# Requires: p7zip-full  msitools  file  python3  (unzip for .zip inputs)

set -euo pipefail

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [-o OUTDIR] [-k] <installer.exe|installer.zip>

Extract a WiX Burn bootstrapper into its component files.

Options:
  -o OUTDIR   Output directory (default: <installer-name>.extracted)
  -k          Keep the intermediate .cab and .msi files alongside the tree
  -h          Show this help
EOF
}

OUTDIR=""
KEEP=0
while getopts ":o:kh" opt; do
    case $opt in
        o) OUTDIR=$OPTARG ;;
        k) KEEP=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done
shift $((OPTIND-1))
[ $# -eq 1 ] || { usage; exit 2; }

INPUT=$(readlink -f "$1")
[ -f "$INPUT" ] || die "not a file: $INPUT"

for t in 7z msiextract msiinfo file python3 dd; do
    command -v "$t" >/dev/null \
        || die "missing tool: $t  (Debian: sudo apt install p7zip-full msitools file python3)"
done

BASE=$(basename "$INPUT")
STEM=${BASE%.*}
: "${OUTDIR:=${PWD}/${STEM}.extracted}"
mkdir -p "$OUTDIR"
WORK=$(mktemp -d -t wix-burn.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# ----- step 1: get to a .exe --------------------------------------------------
EXE=""
case "$INPUT" in
    *.zip|*.ZIP)
        command -v unzip >/dev/null || die "missing tool: unzip  (Debian: sudo apt install unzip)"
        info "unzipping $BASE"
        unzip -q -o -d "$WORK/unzip" "$INPUT"
        EXE=$(find "$WORK/unzip" -type f -iname '*.exe' | head -n1)
        [ -n "$EXE" ] || die "no .exe found inside $BASE"
        ;;
    *)
        EXE=$INPUT
        ;;
esac
info "bootstrapper: $EXE"
file "$EXE" | sed 's/^/    /' >&2
case "$(file -b "$EXE")" in
    PE32*|PE32+*) : ;;
    *) die "input is not a Windows PE executable" ;;
esac

# ----- step 2: locate the payload CAB inside the PE ---------------------------
info "scanning for MSCF (CAB) signatures"
mapfile -t CANDIDATES < <(
python3 - "$EXE" <<'PY'
import mmap, struct, sys
with open(sys.argv[1], 'rb') as f, mmap.mmap(f.fileno(), 0, prot=1) as m:
    off, hits = 0, []
    while (p := m.find(b'MSCF', off)) >= 0:
        if p + 12 <= len(m):
            cb = struct.unpack_from('<I', m, p+8)[0]
            if cb > 4096 and p + cb <= len(m):
                hits.append((p, cb))
        off = p + 4
    hits.sort(key=lambda x: -x[1])
    for p, cb in hits:
        print(f'{p} {cb}')
PY
)
[ ${#CANDIDATES[@]} -gt 0 ] || die "no CAB signature found in $EXE"

for c in "${CANDIDATES[@]}"; do
    read -r off cb <<<"$c"
    printf '    candidate  offset=%-12d size=%d\n' "$off" "$cb" >&2
done
read -r OFF LEN <<<"${CANDIDATES[0]}"
info "using largest candidate: offset=$OFF  length=$LEN"

# ----- step 3: carve the payload CAB and unpack it ----------------------------
CAB="$WORK/attached.cab"
info "carving CAB -> $CAB"
dd if="$EXE" of="$CAB" bs=1M iflag=skip_bytes,count_bytes \
   skip="$OFF" count="$LEN" status=none
file "$CAB" | grep -q Cabinet || die "carved region is not a valid CAB"

CAB_OUT="$WORK/cab_out"
mkdir -p "$CAB_OUT"
info "expanding CAB with 7z"
7z x -bd -y -o"$CAB_OUT" "$CAB" >/dev/null

# ----- step 4: identify + rename every MSI ------------------------------------
MSIS=()
for f in "$CAB_OUT"/*; do
    [ -f "$f" ] || continue
    if file -b "$f" | grep -q 'MSI Installer'; then
        subj=$(file -b "$f" \
               | sed -n 's/.*Subject: \([^,]*\).*/\1/p' \
               | tr -c '[:alnum:]._-' '_' \
               | sed 's/_\+/_/g;s/^_//;s/_$//')
        ver=$(msiinfo export "$f" Property 2>/dev/null \
              | tr -d '\r' \
              | awk -F'\t' '$1=="ProductVersion"{print $2}' | head -n1 \
              | tr -c '[:alnum:]._\n-' '_' | tr -d '\n')
        newname="${subj:-package}${ver:+_$ver}.msi"
        i=1
        while [ -e "$WORK/$newname" ]; do
            newname="${subj:-package}${ver:+_$ver}_$i.msi"; i=$((i+1))
        done
        mv "$f" "$WORK/$newname"
        MSIS+=("$WORK/$newname")
        info "found MSI: $newname"
    fi
done
[ ${#MSIS[@]} -gt 0 ] || die "no MSI found inside the payload CAB"

# ----- step 5: msiextract each MSI --------------------------------------------
for m in "${MSIS[@]}"; do
    stem=$(basename "$m" .msi)
    dest="$OUTDIR/$stem"
    mkdir -p "$dest"
    info "extracting $(basename "$m") -> $dest"
    (cd "$dest" && msiextract "$m" >/dev/null)
done

if [ $KEEP -eq 1 ]; then
    cp "${MSIS[@]}" "$OUTDIR/"
    cp "$CAB"       "$OUTDIR/"
    info "kept intermediate .cab and .msi files in $OUTDIR"
fi

info "done. output: $OUTDIR"
echo
echo "Firmware / ELF payloads (if any):"
found=0
while IFS= read -r -d '' f; do
    found=1
    printf '  %-60s  %10s  %s\n' \
        "$(realpath --relative-to="$OUTDIR" "$f")" \
        "$(stat -c %s "$f")" \
        "$(file -b "$f" | cut -c1-70)"
done < <(find "$OUTDIR" -type f \( -iname '*.mbn' -o -iname '*.elf' \) -print0)
[ $found -eq 0 ] && echo "  (none)"
