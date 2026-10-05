# nsioc

Search Citrix NetScaler **technical support bundles** (`show techsupport`) for the public indicators of
compromise (IOCs) of **CVE-2026-88771, CVE-2026-88772** (CTX697096) and **CVE-2026-88779** (CTX697174).

- Written in Go, **standard library only** (no third-party packages).
- **Read-only.** Bundles are streamed; archives (`.tar`, `.gz`, `.tgz`, `.bz2`, nested) are unpacked in memory and
  never extracted to disk, so archive entry names (e.g. `../..`) cannot write anywhere. Only symlink-free regular files
  inside the scanned folder are opened. Nothing is written except the optional report files.
- The indicators and detection patterns are ported from
  [ThomasPoppelgaard/netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker)
  (script v1.12, MIT). See `THIRD_PARTY_NOTICES.md`.

## Build

```sh
go build -o nsioc ./cmd/nsioc                                      # this machine
GOOS=windows GOARCH=amd64 go build -o nsioc.exe ./cmd/nsioc        # Windows (a build is included: nsioc.exe)
```

## Use

```sh
nsioc /path/to/extracted/bundle                  # search a directory (or a .tar.gz / single file)
nsioc -out report.txt -json report.json /path/to/bundle
nsioc -inventory /path/to/bundle                 # what is in the bundle and how each file is classified
```

Recommended order: run `-inventory` first and check that the sources you expect are found, then run the search.

| Flag | Meaning |
|---|---|
| `-out FILE` | also save the report (attacker text is defanged: `;|&$<>` become `_`, `http:` becomes `hxxp:`). Refused if the path is inside the scanned bundle, is a symlink or special file, or is the file being scanned |
| `-json FILE` | also save findings, coverage, run statistics and per-line timestamps as JSON (input for `summarize`) |
| `-min LEVEL` | lowest severity shown: `info`, `lead`, `check`, `targeted`, `suspect`, `compromise` (default `check`) |
| `-inventory` | print structure only (folders, extensions, classification, first-line *shape* of unknown files); no contents |
| `-redact=false` | with `-inventory`: show real paths (default masks IPs and long numbers) |
| `-map key=regex` | tell nsioc what a file is by name, e.g. `-map 'nslog=my_log_name'`; keys are listed by `-rules` |
| `-max-lines N` | matching lines shown per rule per file (default 5) |
| `-workers N` | files scanned in parallel (default: CPU count) |
| `-defang` | defang attacker text on screen too |
| `-rules` | list rules, indicator counts and `-map` keys |
| `-v` | print each file as it is scanned |

## Reading the result

See **[RESULTS.md](RESULTS.md)** for what every finding means, how to triage, and what to do next. In short:

1. **Coverage** (top of the report): which evidence sources the bundle contained (`ns.conf`, `ns.log`,
   `httpaccess`, shell history, `httpd.conf`, cron, web folders, ...) and how many days each log covers.
   A source that is missing, or a log with under 7 days, limits what a "clean" result means.
2. **Findings**, most serious first:

| Level | Meaning |
|---|---|
| COMPROMISE | evidence that a command ran or a payload exists (webshell, implant, backdoor user, known hash, `/vpn/c` served 200) |
| SUSPECT | injected commands in logs, or a payload name referenced in output/config - verify |
| TARGETED | attack traffic: known attacker IP/domain, probes, base64 payloads (decoded in the report) |
| CHECK | needs a human look; some are normal on a healthy box (e.g. system users, stock cron lines) |
| LEAD | opportunistic scanner IP - hunting lead only, do not act on this alone |
| INFO | context: build vs fixed builds, SAML configured |

Exit status: `0` nothing above LEAD, `1` CHECK/TARGETED, `2` SUSPECT/COMPROMISE, `3` error.

## Summaries for management and investigators

```sh
nsioc -max-lines 20 -json report.json /path/to/bundle        # scan; keep more sample lines for the summary
nsioc summarize report.json -out summary.md                  # executive (1 page) + investigator (2 pages), Markdown
nsioc summarize report.json -fixdate "2026-10-01 12:00"      # also split attack lines before/after the fix
nsioc summarize -audience exec report.json                   # exec | investigator | both
```

Local and deterministic: no network, no AI service. The **executive summary** gives the bottom line, key facts, decisions
and how far to trust the result. The **investigator summary** gives coverage, a timeline, findings by attack stage with
*how to tell if it worked* and next steps, cross-finding correlations, and a prioritised checklist. The wording is
conservative: it says "indicated" or "not established", and never that a system is clean. Reports from older versions
(JSON schema 1) must be re-scanned.

## What it searches

- **Content patterns** in logs, configs and command output: log-poisoning command injection (`pitboss`/`NSPPE`,
  `${IFS}`), base64 in User-Agent strings, `/vpn/c`, CLI audit changes (users, EPA `NO_AUTH`), `httpd.conf`
  webshell aliases and PHP handlers, startup/cron persistence, shell history, `nsaaad` crashes, payload processes.
- **File names** of known webshells, implants and payloads, and **SHA-256** of every file against the published hashes.
- **99 attacker IPs, 97 scanner IPs, 15 domains, 34 hashes.**
- Files are classified by name, then by content, so renamed files are still searched with the right rules.

## Limits

- Only **published** indicators are searched. A clean result is **not proof** the appliance was never compromised.
  Use it together with the official Citrix IoC scan.
- A support bundle is a snapshot: no file times, no running processes, no memory, and logs only reach back as far
  as the appliance kept them. Attackers can also clean up.
- Not ported from the original script: before/after-fix tagging, comparison of `ns.conf` against older saved copies,
  and checks that need a live system.
- Tested on synthetic bundles only; the file layout of a real bundle may need `-map` tweaks.
- The Windows build is cross-compiled and untested on Windows.

## Refreshing the indicators

`perl cmd/nsioc/gen_iocdata.pl ctx697096_check.sh > cmd/nsioc/iocdata.go` regenerates the IP/domain/hash tables
from a newer checker script (the line numbers in `gen_iocdata.pl` refer to v1.12). Detection patterns in
`cmd/nsioc/rules.go` are ported by hand.
