# SusStringFinder

A simple static string scanner in C — the "YARA-lite" of the BlueTeam-tools
collection. Scans files (or whole directories recursively) for suspicious
substrings commonly seen in malware, obfuscated scripts, and
living-off-the-land attack patterns.

## How it works

For every file, the whole thing gets read into memory and checked against
a fixed list of ~28 signatures — plain substrings like `eval(`,
`base64_decode`, `Invoke-Expression`, `certutil -decode`, etc. — matched
case-insensitively. Every hit gets reported with the byte offset, which
signature matched, a severity level, and a short snippet of surrounding
text so you can see the match in context.

That's the entire technique: read the file, slide through it looking for
known bad substrings. No parsing, no heuristics, no entropy analysis — real
tools like YARA/ClamAV do all of that on top. This is the simplest possible
version of the idea.

**Important:** a match here is a _flag for a closer look_, not a verdict.
Plenty of legitimate scripts use `eval()`, shell calls, or `CreateObject`.
This is a triage tool, the same way a metal detector beeping doesn't mean
there's a bomb — it means "worth checking."

## Building

```bash
make
```

or manually:

```bash
gcc -Wall -Wextra -std=c99 -O2 -o SusStringFinder src/main.c src/scanner.c src/signatures.c src/reporter.c
```

A debug build with AddressSanitizer + UndefinedBehaviorSanitizer (for
catching memory bugs during development) is available via:

```bash
make debug
```

## Usage

```bash
./SusStringFinder <file>              # scan a single file
./SusStringFinder -r <directory>      # recursively scan a directory
```

Example:

```bash
./SusStringFinder -r ./samples
```

## Sample output

```
Scanning: samples/dropper.ps1
  [HIGH    ] offset 99       pattern: Invoke-Expression    (PowerShell dynamic execution)
      ...m/stage2.ps1").Invoke-Expression $payload....
  [MEDIUM  ] offset 17       pattern: Net.WebClient        (.NET web client, common download-and-execute pattern)
      ...c = New-Object Net.WebClient.$payload = $wc.DownloadString...

------------------------------------------------------------
Summary
  files scanned : 3
  files flagged : 2
  total matches : 6
------------------------------------------------------------
```

## Signature categories

- **Code execution** — `eval(`, `system(`, `Invoke-Expression`, etc.
- **Obfuscation/encoding** — `base64_decode`, `-EncodedCommand`, `certutil -decode`, etc.
- **Living-off-the-land / persistence** — `mshta`, `regsvr32`, `WScript.Shell`, `AutoOpen`, etc.
- **Network/exfil** — `DownloadString`, `Net.WebClient`, silent `curl`/`wget`, etc.

Full list is in `src/signatures.c` — easy to extend with your own patterns.

## Project structure

```
SusStringFinder/
├── src/
│   ├── signatures.h/.c   # the pattern list + severity levels
│   ├── scanner.h/.c      # core file-reading + matching logic
│   ├── reporter.h/.c     # colored terminal output
│   └── main.c            # CLI + directory walking
├── samples/              # a few harmless test files with suspicious-looking content
└── Makefile
```

## A note on memory safety

Since this is C, a few deliberate choices worth calling out:

- Files are read with `fread()` into a `malloc()`'d buffer sized from
  `ftell()`, with the actual bytes-read count checked against the expected
  size — a short/failed read is treated as an error rather than silently
  scanning a partial buffer.
- Fixed-size buffers (like the match `context` field) are always filled
  with an explicit bounded copy and manually null-terminated, rather than
  relying on functions like `strcpy` that don't stop at a buffer boundary.
- The debug build (`make debug`) runs under AddressSanitizer +
  UndefinedBehaviorSanitizer specifically to catch buffer overruns, use-
  after-free, and similar memory bugs during development.

## Why this exists

Built to explore basic static-analysis/malware-triage concepts, and as a
C project to sit alongside the Java/Python port scanners in this repo —
a chance to work with raw file I/O, manual string matching, and directory
traversal at a lower level than Python/Java usually require. AI-assisted
build; understood and tested by me, including running it under sanitizer
builds to confirm there are no memory bugs.

## Ideas for extending it

- Support simple wildcard/regex patterns instead of just literal substrings
- Load signatures from an external file instead of hardcoding them, so the list can be updated without recompiling
- Add a `--json`/`--csv` export option to match the other tools in this repo
- Basic entropy calculation to flag high-entropy blobs (a common indicator of packed/encrypted payloads) even without a literal string match

## License

MIT
