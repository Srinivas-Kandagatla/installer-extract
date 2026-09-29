# wix-burn-extract

Extract a **WiX Burn** Windows bootstrapper (`.exe`) on Linux, all the way down
to the payload files (drivers, firmware, DLLs, ...).

Works on any installer built with the WiX Toolset Burn engine — a very common
choice for vendor driver and runtime installers.

## Why a script?

A Burn bootstrapper is a Windows PE with **more than one CAB glued to the end
of it**. Running plain `7z x installer.exe` only sees the first (small) UI
CAB — the real payload lives in the larger **WixAttachedContainer** that
comes after it and holds one or more `.msi` files. Each `.msi` in turn stores
its files with obfuscated names like `fil7A7E5B9F...` that need the MSI's
`File` table to be resolved back to real names.

This script automates the whole chain:

```
installer.exe (PE)
 ├─ UI CAB                (skipped)
 └─ WixAttachedContainer  ─→ 7z x ─→ *.msi ─→ msiextract ─→ real files
```

## Requirements (Debian / Ubuntu)

```bash
sudo apt install --no-install-recommends \
     p7zip-full msitools file python3 unzip
```

| Tool | Package | Used for |
|------|---------|----------|
| `7z` | `p7zip-full` | Unpacking the carved CAB |
| `msiextract`, `msiinfo` | `msitools` | Extracting MSIs with real filenames |
| `file` | `file` | Identifying carved bytes as a CAB / MSI |
| `python3` | `python3` | 3-line MSCF-signature scanner |
| `unzip` | `unzip` | Optional — only if input is a `.zip` |
| `dd`, `find`, `awk`, `sed`, `readlink`, `stat` | `coreutils` / `findutils` | POSIX helpers |

Optional but handy for inspecting the extracted firmware:

```bash
sudo apt install binutils           # readelf, objdump
```

Works unchanged on Debian 12 (bookworm), 13 (trixie) and sid, and on Ubuntu.
Only packages from `main` — no non-free needed.

## Install

```bash
git clone <this repo>            # or just copy the script
cd installer-extract
chmod +x wix-burn-extract.sh
# Optional: put it on PATH
sudo install -m 0755 wix-burn-extract.sh /usr/local/bin/wix-burn-extract
```

## Usage

```
wix-burn-extract.sh [-o OUTDIR] [-k] <installer.exe|installer.zip>
```

Options:

- `-o OUTDIR` — where to write the extracted tree
  (default: `<installer-name>.extracted/` in the current directory).
- `-k` — keep the carved `attached.cab` and every renamed `.msi` in `OUTDIR`
  alongside the extracted tree (useful for archiving or re-running
  `msiinfo`).
- `-h` — help.

The input can be a `.exe` directly, or a `.zip` containing the `.exe`
(the script picks the first `.exe` it finds inside).

## Examples

Extract a bootstrapper `.exe` directly:

```bash
./wix-burn-extract.sh some-driver-installer.exe
```

Input wrapped in a `.zip` (the script picks the first `.exe` inside):

```bash
./wix-burn-extract.sh some-driver-installer.zip
```

Send output somewhere specific and keep the intermediate `.cab` / `.msi`:

```bash
./wix-burn-extract.sh -k -o /tmp/out some-driver-installer.exe
```

## What you get

Inside `OUTDIR/` there is one sub-directory per MSI found in the bootstrapper,
named after the MSI's product / version, with the original Windows-style
directory layout the installer would have deployed:

```
some-driver-installer.extracted/
├── <ProductName>_<Version>/
│   └── <Manufacturer>/.../
│       ├── ...sys, ...dll, ...inf, ...cat      # kernel + user-mode files
│       └── ...mbn, ...elf                      # firmware payloads (if any)
└── <ProductName>_<Version>/
    └── ...
```

At the end the script prints a one-line summary of every `.mbn` / `.elf`
payload it found, along with size and `file(1)` classification.

## Peeking inside an MSI without extracting

Even without this script, `msitools` on its own is very useful:

```bash
msiinfo tables  package.msi              # list MSI tables
msiinfo export  package.msi Property     # ProductName, ProductVersion, ...
msiinfo export  package.msi File         # fil-hash  →  real file name
msiextract      package.msi              # extract with real names into cwd
```

## Troubleshooting

- **"no CAB signature found"** — the input is not a Burn bootstrapper. Check
  with `file installer.exe`; a real Burn bootstrapper is a `PE32 executable
  ... GUI, Intel i386` and its `.rsrc` mentions `WixBundle`.
- **"carved region is not a valid CAB"** — the largest MSCF candidate turned
  out to be a false hit inside the payload. Rare, but you can override by
  running the underlying steps by hand (see below).
- **`msiextract` says "unable to open stream"** — the MSI is corrupt, or
  Debian's `msitools` is very old; upgrade to ≥ 0.100.

## Doing it by hand (what the script does under the hood)

```bash
# 1. find MSCF (CAB) signatures — pick the biggest cbCabinet:
python3 -c "
import mmap, struct, sys
p=sys.argv[1]
with open(p,'rb') as f, mmap.mmap(f.fileno(),0,prot=1) as m:
    off=0
    while (i:=m.find(b'MSCF',off))>=0:
        cb=struct.unpack_from('<I',m,i+8)[0]; print(hex(i), cb); off=i+4
" installer.exe

# 2. carve it out
dd if=installer.exe of=payload.cab bs=1M iflag=skip_bytes,count_bytes \
   skip=<offset> count=<cbCabinet> status=progress

# 3. unpack the CAB → one or more MSIs
7z x -opayload_out payload.cab
file payload_out/*                 # confirm "MSI Installer"

# 4. extract each MSI with real filenames
mkdir out && (cd out && msiextract ../payload_out/a0)
```
