# machoinfo

Rapid Mach-O binary triage for macOS - pure Go, zero dependencies.

Sibling tool to [peinfo](https://github.com/redduxz/peinfo) (PE triage for Windows binaries).

## What it reads

- **Headers** - fat/universal + thin binaries, cpu types, file type, header flags, min-OS, UUID
- **Segments & sections** - VM layout, protections, per-section Shannon entropy
- **Dylibs & rpaths** - every `LC_LOAD*` dylib, `LC_RPATH` entries, install name
- **Symbols** - external imports/exports
- **Code signature** - superblob walk: signature status (none/adhoc/signed), hardened runtime, stapled notarization ticket, CodeDirectory flags, bundle identifier, Team ID
- **Entitlements** - decoded from the embedded XML plist

## Findings engine

Automatic flags, tuned for triage signal over noise:

- unsigned / ad-hoc-signed binaries
- signed third-party binaries missing **hardened runtime** (Apple platform binaries exempt)
- **risky entitlements** - `get-task-allow`, `allow-dyld-environment-variables`, `disable-library-validation`, W^X-off, unsigned-exec-memory, private entitlements, JIT
- **rpath hygiene** - relative `LC_RPATH`s, rpaths into user-writable dirs, `@rpath` dylib loads
- setuid/setgid bits
- high-entropy sections (packed/encrypted-looking; DWARF debug sections excluded)

## Usage

```sh
machoinfo                   # interactive shell (animated, tab-completion)
machoinfo <file>            # full triage dump
machoinfo <dir>             # recursive scan - prints only flagged binaries
machoinfo --procs           # triage all running processes
machoinfo --all /bin        # include clean results too
machoinfo --json <file>     # machine-readable output
machoinfo --findings-only <file>
```

### Interactive shell

Run `machoinfo` with no args in a terminal to drop into the REPL.
`open <file>` loads a binary, then drill down without re-parsing:
`findings`, `ents`, `sections`, `dylibs`, `strings`, `json`, and more.
Tab completes commands and paths; arrow-key history; ctrl-d exits.
Scans run across all cores (`scan`, `procs`).

## Example

```
/System/Applications/Calculator.app/Contents/MacOS/Calculator  (3M, -rwxr-xr-x)
  type:    executable x86_64,arm64
  flags:   noundefs dyldlink twolevel pie
  min os:  26.3.0
  sign:    signed
  ident:   com.apple.calculator
  entitlements (11):
    com.apple.security.app-sandbox = true
    ...
```

## Build

```sh
go build -o machoinfo .
```

No cgo, no external deps - works cross-compiled.
