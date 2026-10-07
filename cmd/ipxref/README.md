# ipxref: find IP addresses that show up in more than one Tech Support Bundle

`ipxref` reads a folder that holds **all** of your Citrix NetScaler technical support bundles and produces a report
that answers three questions:

1. **Every IP address found, and in which bundle(s)**: the ones in *all* bundles first, then those in some, and finally
   those found in **only one** bundle. (Use `-min-bundles 2` to see only IPs shared between bundles.)
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

**Zip files** work too: every archive (such as a UAC `.tar.gz`) inside a `.zip` becomes its own bundle, named
`zipname/archivename`, so one zip with several collections gives one bundle per host. Other files in the zip are
not read (a warning gives the count).

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
ipxref.exe -csv C:\reports\all_ips.csv C:\TechSupport
```

The **results go to the CSV file**. The screen shows only a short summary: one line per bundle (files, oldest and
newest log entry, IPs found, threat IPs), the totals, any warnings, and the files that were written. Create the
report folder first, and keep it **outside** the bundles folder.

If you give **no output file at all**, `ipxref` writes `ipxref_ips.csv` in the folder you ran it from:

```
ipxref.exe C:\TechSupport
```

Other files you can ask for in the same run:

```
ipxref.exe -csv C:\reports\all_ips.csv -threats C:\reports\threats.csv -bundles-csv C:\reports\bundles.csv -out C:\reports\full_report.txt C:\TechSupport
```

| File | What is in it |
|---|---|
| `-csv` | **every IP**, one row each: threat flag, bundle names, a hits column per bundle, first/last seen |
| `-threats` | only the threat IPs, one row per IP per bundle (`.csv`), or readable text for any other name |
| `-bundles-csv` | one row per bundle: files, IP counts, threat IPs, **oldest and newest log entry** and days of logs |
| `-out` | the full readable text report with every IP (the long version of what used to print on screen) |

To see the full text report **on screen** as well, add `-print`.

If a path has spaces, put it in quotes: `ipxref.exe -csv "C:\my reports\ips.csv" "C:\my bundles"`.
On Mac or Linux the same command works with `./ipxref -csv ips.csv /path/to/bundles`.

A large set of bundles can take a few minutes. Add `-v` to see progress.

### Only want the threat IPs? Use `-threats-only`

```
ipxref.exe -threats-only -threats C:\reports\threats.csv C:\TechSupport
```

This lists **only** the IPs from the published attacker lists, with the bundle each was found in. With no `-threats`
file it writes `ipxref_threats.csv` in the current folder. (`-csv` cannot be combined with it.)

## 4. What you get

### The text report (`-out`, or `-print` on screen)

| Section | What it tells you |
|---|---|
| **SUMMARY** | how many distinct IPs there were, how many appear in only one bundle, how many are shared and how many are in *all* bundles, and how many are threat IPs |
| **BUNDLES COMPARED** | each bundle with its file count, size and number of distinct IPs |
| **LOG HISTORY** | for each bundle: oldest and newest log entry and how many days that covers; the period that *every* bundle's logs cover; warnings for bundles with under 7 days of logs or no dated logs |
| **KNOWN THREAT IPs** | for each bundle, the addresses found that are on the published attacker lists (first 12 per bundle; use `-threats` for all) |
| **IN ONLY ONE BUNDLE** | every IP found in just one bundle, listed under that bundle in a compact table (hits, threat flag, first/last seen, file). Threat IPs come first in each bundle |
| **IN ALL N BUNDLES** / **IN k OF N BUNDLES** | the shared IPs, most widespread first. **Every shared IP says whether it is on the threat lists** (`<<< THREAT IP: KNOWN ATTACKER` next to the address, and a `Threat list:` line). The "in all" heading names the bundles. Each IP shows total hits, first/last seen, **the name of every bundle it was found in** (with hits and dates), the bundles it was *not* found in (when few), and the files it appears in. Lists longer than 40 bundles are cut to the 40 with most hits; use `-full` or the CSV for all |
| **HOW TO READ THIS** | a short legend |

Warnings appear at the top if any file could not be read (see Troubleshooting).

### `-csv ips.csv` (opens in Excel)

One row per IP **found in the bundles** (every IP by default; shared IPs and single-bundle IPs alike). The columns, in order:

| Column | Meaning |
|---|---|
| `ip` | the address |
| `is_threat_ip` | **YES** if the address is on the published attacker lists, otherwise `no` |
| `threat_type` | `known attacker`, `password-spray range` or `scanner (lead)` (blank if not a threat IP) |
| `bundles_found_in` / `in_all_bundles` | how many bundles it is in, and `yes` if it is in every one |
| `found_in_bundles` | the **names** of the bundles it was found in |
| `<bundle name> (hits)` | **one column per bundle** with the number of times the IP appears there; **blank = not found in that bundle** |
| `total_hits`, `first_seen`, `last_seen`, `days_between` | totals and dates from the log lines |
| `dates_per_bundle`, `typical_files` | the dates and files per bundle |
| `threat_listed_by` | who published the threat IP (blank if not a threat IP) |

To see only the IPs that are in **all** your bundles, run with `-min-bundles` set to the number of bundles
(for example `-min-bundles 4`), or filter `in_all_bundles` = `yes` in Excel. To see only IPs in **one** bundle, filter
`bundles_found_in` = `1`. To see only threat IPs, filter `is_threat_ip` = `YES`.

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
| `-dir FOLDER` | the folder that holds the bundles. Optional: you can instead put the folder last on the command line (`ipxref.exe C:\bundles`) |
| `-out FILE` | save the full readable text report (every IP) |
| `-print` | also print the full text report on screen (by default only a short summary is shown) |
| `-bundles-csv FILE` | one row per bundle, including oldest and newest log entry |
| `-csv FILE` | **the main output**: every IP as CSV (default file `ipxref_ips.csv` if you give no output file) |
| `-threats FILE` | save the threat IPs per bundle (`.csv` = spreadsheet, otherwise text) |
| `-threats-only` | show **only** the threat IPs per bundle (no shared-IP list or log history) |
| `-no-scanners` | leave weak scanner-lead IPs out of the threat report |
| `-min-bundles N` | list IPs found in at least N bundles. **Default 1 = every IP, even if it is in only one bundle.** Use 2 for only shared IPs, or the number of bundles for only IPs in *all* of them |
| `-ignore FILE` | leave out addresses you know are normal (see below) |
| `-max-ips N` | with `-print`: most IPs printed on screen (default 300; 0 = no limit). Threat IPs are always printed. The `-out` file and the CSV always have **every** IP |
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
| `!!! N FILE(S) COULD NOT BE READ` | Some files are compressed with a format `ipxref` cannot open (xz, zstd, `.Z`, 7-zip, lz4). They were **not searched**, so their IPs are missing. Decompress copies of them and run again |
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
