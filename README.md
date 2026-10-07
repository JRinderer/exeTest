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

This repository holds two programs:

| Program | Purpose |
|---|---|
| `nsioc` | search **one** bundle for the CVE-2026-88771/88772/88779 indicators (this page) |
| `ipxref` | compare **many** bundles and list the IP addresses that appear in more than one (see [ipxref](#ipxref-compare-many-bundles)) |

## Build

```sh
go build -o nsioc ./cmd/nsioc                                      # this machine
GOOS=windows GOARCH=amd64 go build -o nsioc.exe ./cmd/nsioc        # Windows (a build is included: nsioc.exe)
go build -o ipxref ./cmd/ipxref                                    # the cross-bundle comparison
GOOS=windows GOARCH=amd64 go build -o ipxref.exe ./cmd/ipxref
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
| `-ioc-file FILE` | your own indicators, one per line (webhook host, URL or command string); kept out of the repo. `#` comments; `${IFS}` in an entry also matches `$IFS`, `%24%7BIFS%7D`, a space, `+`, `%20`; `re:<regex>` for a regex. Graded by where it is found: cron/startup/cron log or ns.log/messages/history = SUSPECT, any other file = CHECK |
| `-v` | print each file as it is scanned |

## Reading the result

For what to do on the appliance after a finding (paths, commands, what to look for), see **[INVESTIGATE.md](INVESTIGATE.md)**.

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
- **Compressed files:** gzip, bzip2 and tar are recognised by their first bytes, not their name, so rotated logs such as
  `ns.log.0.gz`, `ns.log.1.gz` or even an extensionless gzip `ns.log.0` are unpacked and searched. **xz, zstd, `.Z`,
  7-zip and lz4** cannot be read with Go's standard library; such files are listed under a `!!! ... COULD NOT BE READ`
  warning (in the report, the JSON and both summaries) and are **not searched**. Decompress them on a copy and re-run.
- **UAC (Unix-like Artifacts Collector) output** can be scanned like a bundle (folder, `.tar.gz`, or a `.zip` holding `.tar.gz` collections: zips are read in place, encrypted zip entries are listed as not read; a zip with several hosts is reported as one scan, the path in each finding names the host).
  Collected logs, configs, cron and web files are searched as usual. The `bodyfile` is read as a **file listing**: each
  entry's path goes through the file-name rules and is shown with its modification time. `hash_executables*` lists are
  searched for the published **SHA-256** values only (UAC's default MD5/SHA-1 lists cannot be matched). What UAC does not
  collect (for example `ns.conf` or `/var/core`, depending on the profile) is simply absent, so check the coverage table.
  Tested on a synthetic UAC tree only.
- Tested on synthetic bundles only; the file layout of a real bundle may need `-map` tweaks.
- The Windows build is cross-compiled and untested on Windows.

## Refreshing the indicators

`perl cmd/nsioc/gen_iocdata.pl ctx697096_check.sh > cmd/nsioc/iocdata.go` regenerates the IP/domain/hash tables
from a newer checker script (the line numbers in `gen_iocdata.pl` refer to v1.12). Detection patterns in
`cmd/nsioc/rules.go` are ported by hand.

## ipxref: compare many bundles

**Step-by-step instructions: [cmd/ipxref/README.md](cmd/ipxref/README.md).**

`ipxref` reads a folder that holds all your bundles and reports **every IP address found, and in which bundle(s)**,
flagging the ones on the published threat lists (use `-min-bundles 2` for only IPs shared between bundles). Standard library only, read-only, same path-safety rules as `nsioc`.

```sh
ipxref -csv ips.csv /path/to/folder-of-bundles           # every IP to a CSV; the screen shows a short summary
ipxref -csv ips.csv -out report.txt -print /path/to/folder   # also a full text report (and show it on screen)
ipxref -min-bundles 5 -ignore known_good.txt /path/to/folder
```

- **What is a bundle:** each immediate subfolder (an extracted bundle) or archive file (`.tar.gz`, `.tgz`, `.gz`,
  `.bz2`) in the folder you give. At least two are needed.
- **The report** starts with a summary and a table of the bundles, then a **LOG HISTORY** table, then lists the IPs
  grouped by how many bundles they appear in, starting with **IN ALL N BUNDLES**. Each IP shows its total hits, the
  bundles it was found in (with hits and dates per bundle) and the typical files it appears in, so you can judge the
  context.
- **How far back the logs go:** LOG HISTORY gives each bundle's oldest and newest log entry and how many days that
  covers (read across all rotated logs, `.gz` included), the period that *every* bundle covers, and warnings for
  bundles with under 7 days of logs, no dated lines, or logs that do not overlap in time. Each IP also shows
  **First seen / Last seen**, taken from the timestamps of the log lines that contain it. An IP found only in a
  config or command output has no date. Log lines without a year (plain syslog) are placed in the year of the
  bundle's newest dated line, and marked "(year inferred)".
- **Rotated and compressed logs** (`ns.log.0`, `ns.log.1.gz`, ...) are read; gzip/bzip2 are detected by content, so a
  missing `.gz` extension does not matter. xz, zstd, `.Z`, 7-zip and lz4 files cannot be read and are listed in a
  warning at the top of the report (their IPs are missing until you decompress them).
- **Threat IPs:** a **KNOWN THREAT IPs** section lists, per bundle, every address that is on the published attacker
  lists `nsioc` uses (known attackers, password-spray ranges and, as weak "leads", GreyNoise-tagged scanners), even if it
  is in only one bundle. `-threats FILE` exports the complete list: `.csv` gives one row per IP per bundle (open it in
  Excel and filter by bundle), any other name gives readable text by bundle and by IP. `-no-scanners` drops the weak
  scanner leads. The IP tables are generated from the same source as `nsioc`
  (`perl cmd/nsioc/gen_iocdata.pl ctx697096_check.sh ips > cmd/ipxref/iocdata.go`).
- **Noise is filtered by default:** private, loopback, link-local and reserved addresses, netmasks (`255.255.255.0`),
  version numbers (`Build 14.1.73.37`) and binary files. `-include-private` and `-include-versions` turn the
  filters off.
- **`-ignore FILE`** drops addresses you know are normal (your DNS, NTP, VIPs, monitoring). One IP or CIDR range per
  line, `#` for comments.

| Flag | Meaning |
|---|---|
| `-min-bundles N` | list IPs found in at least N bundles (default 1 = every IP; 2 = only shared IPs) |
| `-max-ips N` | most IPs printed on screen (default 300, threat IPs always shown; the `-out` file and CSV have every IP) |
| `-full` | always list every bundle for each IP, however many |
| `-csv FILE` | **main output:** one row per IP (every IP by default): threat flag, bundle names, a hits column per bundle, first/last seen. Written to `ipxref_ips.csv` if you give no output file. Refused if inside the searched folder |
| `-out FILE`, `-print` | the full readable text report: save it / also show it on screen (by default only a short summary is printed) |
| `-bundles-csv FILE` | one row per bundle, with its oldest and newest log entry |
| `-threats FILE` | export threat IPs found in each bundle (`.csv` or text) |
| `-threats-only` | show only the threat IPs per bundle (skips the shared-IP list and log history) |
| `-no-scanners` | leave weak scanner-lead IPs out of the threat report |
| `-workers N`, `-v` | parallel files, progress |

An address in many bundles can be an attacker or scanner hitting every appliance, but it can equally be shared
infrastructure. It is a lead, not a verdict. IPv4 only.
