# ipxref: find IP addresses that show up in more than one Tech Support Bundle

`ipxref` reads a folder that holds **all** of your Citrix NetScaler technical support bundles and produces a report
that answers three questions:

1. **Which IP addresses appear in more than one bundle** (and which appear in *all* of them), and which bundles?
2. **How far back do each bundle's logs go**, and when was each IP first and last seen?
3. **Which IPs on the published attacker lists** (the same lists the `nsioc` tool uses) were found, and in which bundle?

It is one small program with no install and no dependencies. It only reads your bundles; it never changes them.

---

## 1. Get the program

A Windows build is in the repository root: **`ipxref.exe`**. Copy it to any folder. (For Mac or Linux, build it with
Go: `go build -o ipxref ./cmd/ipxref`.)

## 2. Put your bundles in one folder

Each bundle must be **its own subfolder** (an extracted bundle) **or its own archive file** (`.tar.gz`, `.tgz`,
`.gz`, `.bz2`) inside one parent folder. You need at least two.

```
C:\bundles\                      <- the folder you give to ipxref
    siteA\                       <- one extracted bundle (contains etc, flash, netscaler, nsconfig, shell, var)
    siteB\
    siteC.tar.gz                 <- an archive also works
    notes.txt                    <- ignored (not a folder or archive); it is listed as "not treated as bundles"
```

The name shown in the report is the subfolder or archive name (without `.tar.gz`), so give them recognisable names.
Rotated logs inside a bundle (`ns.log.0.gz`, `ns.log.1.gz`, ...) are read automatically.

## 3. Run it

Open a command prompt or PowerShell in the folder that holds `ipxref.exe`:

```
ipxref.exe C:\bundles
```

That prints the report on screen. To also **save** it, and export the **threat IPs**, write the files to a folder
*outside* the bundles folder:

```
ipxref.exe -out C:\reports\ips.txt -csv C:\reports\ips.csv -threats C:\reports\threats.csv C:\bundles
```

If a path has spaces, put it in quotes: `ipxref.exe -out "C:\my reports\ips.txt" "C:\my bundles"`.

On Mac or Linux the same command works with `./ipxref /path/to/bundles`.

A large set of bundles can take a few minutes. Add `-v` to see progress.

### Only want the threat IPs? Use `-threats-only`

```
ipxref.exe -threats-only C:\bundles
ipxref.exe -threats-only -out C:\reports\threats.txt -threats C:\reports\threats.csv C:\bundles
```

This skips the shared-IP list and log history and shows **only** the IPs from the published attacker lists, with the
bundle each one was found in (by bundle, then by IP). `-threats` still writes the file, `-out` saves the screen text,
`-no-scanners` leaves out the weak scanner leads, and `-ignore` still applies. (`-csv` cannot be combined with it.)

## 4. What you get

### On screen / in `-out` (text report)

| Section | What it tells you |
|---|---|
| **SUMMARY** | how many distinct IPs there were, how many appear in 2+ bundles, how many in *all* bundles |
| **BUNDLES COMPARED** | each bundle with its file count, size and number of distinct IPs |
| **LOG HISTORY** | for each bundle: oldest and newest log entry and how many days that covers; the period that *every* bundle's logs cover; warnings for bundles with under 7 days of logs or no dated logs |
| **KNOWN THREAT IPs** | for each bundle, the addresses found that are on the published attacker lists (first 12 per bundle; use `-threats` for all) |
| **IN ALL N BUNDLES** / **IN k OF N BUNDLES** | the shared IPs, most widespread first. The "in all" heading names the bundles. Each IP shows total hits, first/last seen, **the name of every bundle it was found in** (with hits and dates), the bundles it was *not* found in (when few), and the files it appears in. Lists longer than 40 bundles are cut to the 40 with most hits; use `-full` or the CSV for all |
| **HOW TO READ THIS** | a short legend |

Warnings appear at the top if any file could not be read (see Troubleshooting).

### `-csv ips.csv` (opens in Excel)

One row per shared IP: `ip, bundles_found_in, bundles_total, in_all_bundles, total_hits, first_seen, last_seen,
days_between, bundles (hits), dates_per_bundle, typical_files`.

### `-threats threats.csv` or `threats.txt`

Lists the threat IPs found **in each bundle**, even if an IP is in only one bundle.

- A name ending in **`.csv`** writes a spreadsheet with **one row per threat IP per bundle**:
  `bundle, threat_ip, type, listed_by, hits, first_seen, last_seen, found_in_files, bundles_with_this_ip`.
  In Excel, filter the `bundle` column to see everything found in one bundle.
- Any other name (for example `threats.txt`) writes readable text: a section **by bundle**, then **by IP** (which
  bundles each threat IP was in).

Threat types: **known attacker** (published exploitation IPs), **password-spray range**, and **scanner (lead)**
(opportunistic scanners tagged by GreyNoise, which is weak evidence). Use `-no-scanners` to leave the scanner leads out.

## 5. Options

| Option | What it does |
|---|---|
| `-out FILE` | save the text report |
| `-csv FILE` | save the shared-IP list as CSV |
| `-threats FILE` | save the threat IPs per bundle (`.csv` = spreadsheet, otherwise text) |
| `-threats-only` | show **only** the threat IPs per bundle (no shared-IP list or log history) |
| `-no-scanners` | leave weak scanner-lead IPs out of the threat report |
| `-min-bundles N` | list IPs found in at least N bundles (default 2). Use the number of bundles to see only IPs in *all* of them |
| `-ignore FILE` | leave out addresses you know are normal (see below) |
| `-max-ips N` | most IPs printed in the text report (default 300). The CSV always has all of them |
| `-full` | always list every bundle for each IP, however many |
| `-include-private` | also count private and reserved addresses (left out by default) |
| `-include-versions` | also count version-looking numbers such as `Build 14.1.73.37` (left out by default) |
| `-workers N` | how many files are read in parallel (default: your CPU count) |
| `-v` | show progress |

`-out`, `-csv` and `-threats` refuse to write inside the bundles folder (so your evidence is not changed), refuse to
write to a symlink, and refuse to use the same file twice.

### Leaving out normal addresses (`-ignore`)

An IP in many bundles is not necessarily bad: DNS servers, NTP servers, monitoring and your own public addresses
appear everywhere. Put them in a text file, one IP or CIDR range per line, `#` for comments:

```
# known good
8.8.8.8
203.0.113.0/24      # our public VIPs
```

then run `ipxref.exe -ignore C:\reports\known_good.txt C:\bundles`. Ignored addresses are also removed from the
threat report.

## 6. What is counted, and what is left out

- Only **IPv4** addresses in **text files** (logs, configs, command output).
- Left out by default: private, loopback, link-local and reserved addresses; netmasks such as `255.255.255.0`;
  version numbers such as `Build 14.1.73.37` or `NS13.1.64.24`; binary files. The report footer shows how many
  address-like strings were left out.
- **Dates** come from the timestamps on log lines. Log lines with no year (plain syslog style) are placed in the year
  of the bundle's newest dated line and are marked "(year inferred)". An IP found only in a config or command output
  has no date.

## 7. Troubleshooting

| You see | What it means / what to do |
|---|---|
| `found 1 bundle(s) ... need at least 2` | The folder you gave holds one bundle (or the bundles are nested deeper). Point `ipxref` at the **parent** folder whose immediate children are the bundles |
| `!!! N FILE(S) COULD NOT BE READ` | Some files are compressed with a format `ipxref` cannot open (xz, zstd, `.Z`, zip, 7-zip, lz4). They were **not searched**, so their IPs are missing. Decompress copies of them and run again |
| `-out ... is inside the searched folder` | Save the report somewhere outside the bundles folder |
| A bundle shows "none found" under LOG HISTORY | It has no log lines with a recognisable timestamp, so its IPs get no dates |
| The "in all bundles" list is full of normal addresses | Add them to an `-ignore` file |

## 8. What it does NOT tell you

- **Direction.** It does not say whether an IP connected *to* the appliance or the appliance connected *to* it. It only
  reports where the address appears.
- **Whether an attack worked.** An IP in a bundle shows contact or a reference to it, not success. Use `nsioc` to
  analyse a single bundle in depth.
- An IP shared by many bundles may be an attacker or scanner hitting every appliance, but it may equally be shared
  infrastructure. It is a lead, not a verdict.
- The threat lists are a snapshot (the `netscaler-ctx697096-checker` script, v1.12). They do not update themselves.
  To refresh them from a newer copy of that script:
  `perl cmd/nsioc/gen_iocdata.pl ctx697096_check.sh ips > cmd/ipxref/iocdata.go`, then rebuild.
