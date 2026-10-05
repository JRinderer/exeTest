# Reading the nsioc results

This guide explains what the report says and what to do with each kind of finding.
For how to run the tool, see `README.md`.

The descriptions of the attacks and indicators come from the research collected in the upstream checker
([netscaler-ctx697096-checker](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker), script v1.12) and
the vendor and researcher reports it credits. They are not independently verified here, and the indicators are
unofficial community guidance, not Citrix's own IoC list.

## Want it condensed?

`nsioc summarize report.json` turns a JSON report (`nsioc -json report.json <bundle>`) into a one-page executive
summary and a two-page investigator summary, with the same "how to tell if it worked" guidance for each finding.
Add `-fixdate "YYYY-MM-DD HH:MM"` to split attack lines before and after the fix. See `README.md` for the options.
This guide remains the full reference for every finding.

**Where do I look on the appliance, and what do I look for?** See [INVESTIGATE.md](INVESTIGATE.md), a field guide that
maps each finding to the paths, commands and signs to check.

## 1. The 60-second summary

| You see | It means | Do this |
|---|---|---|
| **VERDICT: COMPROMISE INDICATORS FOUND** | at least one finding shows an attacker ran something or left a payload | stop; treat the appliance as compromised until proven otherwise (section 6) |
| **VERDICT: SUSPECT items found** | injected commands or payload names appear, but there is no proof they ran | review each one; compare with the `ns.log` timeline and the build date (section 5) |
| **VERDICT: attack traffic seen (targeted)** | the box was probed or attacked | decide whether the attempts came before or after it was patched |
| **VERDICT: no known-bad indicators, but CHECK items...** | nothing known-bad, but some items need a human look | confirm each CHECK item is expected |
| **VERDICT: none ... found** | none of the published indicators were found *in the sources the bundle contained* | read the COVERAGE section before relying on it |

A clean result is **not** proof the appliance was never compromised. Only published indicators are searched,
a support bundle holds only a snapshot, and logs only reach back as far as the appliance kept them.

## 2. How the report is laid out

1. **Header**: what was scanned, file count, size, run time.
2. **COVERAGE**: which evidence sources were found (`ns.conf`, `ns.log`, `httpaccess`, shell history, ...), how many
   files and lines, and the time span each log covers. `[x]` found, `[ ]` missing. `WARNING` lines flag logs with
   under 7 days of history, no recognised timestamps, or no rotated copies. "(recognised by content)" means the file
   name did not match, so the tool identified it by what is inside.
3. **Findings**, most serious first, one block per rule and file:
   ```
   [rule-id] what it means
       source: who published the indicator
     path/to/file  (N matches)
         line 123: the matching text (control characters shown as ".")
   ```
   Base64 payloads in User-Agent strings are decoded in brackets after the line.
4. **WARNINGS**: files that could not be read completely (truncated or corrupt archives).
5. **SUMMARY** counts per severity, then the **VERDICT**.

Exit status: `0` nothing above LEAD, `1` CHECK/TARGETED, `2` SUSPECT/COMPROMISE, `3` error.

## 3. Severity levels

| Level | Meaning | Typical confidence |
|---|---|---|
| **COMPROMISE** | a payload, webshell, implant or backdoor exists, or a command demonstrably ran | high; false positives are rare but possible (see notes per rule) |
| **SUSPECT** | injected commands in logs, or a payload name referenced; execution not proven | medium; needs the timeline |
| **TARGETED** | attack traffic or a probe against the appliance | high that it was attacked, says nothing about whether it worked |
| **CHECK** | needs a human decision; often normal on a healthy appliance | low on its own |
| **LEAD** | an IP that opportunistic scanners used; hunting lead only | low; do not block or conclude on this alone |
| **INFO** | context (build version, SAML configured) | n/a |

## 4. Finding reference

"Benign" lists the usual harmless cause so you can dismiss quickly. "Next" is what to look at.

### 4.1 Log evidence of the command-injection attack (CVE-2026-88771)

The reported attack works by putting shell commands into a login name or User-Agent so they land in a log, which a
daily NetScaler check later executes. These findings look for those injected strings.

| Rule | Level | Means | Benign | Next |
|---|---|---|---|---|
| `log-pitboss-injection` | SUSPECT | a fake `pitboss`/`NSPPE` message, `${IFS}` (shell space trick) or an encoded `;sh`/`;curl` in `ns.log`, `messages`, `notice.log` or `nsvpn.log` | very rare | read the full line; note the time; look for the files it tried to write (`file-*`, `artefact-name`) |
| `log-pitboss-generic` | SUSPECT | a `pitboss` packet-engine message carrying a shell character (`;`, backtick, `$(`, `&&`, `\|\|` or their URL-encoded forms) | rare | same as above |
| `log-shell-injection` | SUSPECT | a logon-related `ns.log`/`nsvpn.log` line containing shell metacharacters followed by a command name | **the broadest rule**; ordinary lines with `user`/`login` plus `;` or `\|` can match | read the line; real attacks show a command like `curl`, `sh`, `wget`, `base64` |
| `http-login-payload` | TARGETED | attack text (`pitboss`, `NSPPE`, `%3B`, `${IFS}`, `curl`, `wget`) inside a request to a login page, in the HTTP logs | none expected | still visible after `ns.log` rotated; check the source IP |
| `ua-base64-index` | TARGETED | a base64 command parked in the User-Agent as `INDEX:<b64>` (decoded in the report) | none | read the decoded command |
| `ua-base64-php` | TARGETED | base64 PHP (`PD9...` = `<?`) in a User-Agent, typically on `/vpn/media/*.ico`; webshell staging | none | decoded text shown; check whether a file was then created |
| `ua-base64-whole` | TARGETED | a User-Agent that is *only* a base64 string | some odd clients | read the decoded text |
| `ua-base64-ktag` | TARGETED | a payload staged as `K:<base64>#` in the User-Agent (1 Oct variant) | none | read the decoded text |
| `log-exploit-strings` | TARGETED | known exploit strings in logs: webshell alias names, canary files, reverse-shell fragments (`/dev/tcp/`), webshell header names, Platypus API paths | none expected | note the string and time; check matching file findings |
| `log-recon-marker` | TARGETED | recon markers `vp_probe_nonexist` or `scanner-probe` logins: the box was found and tested | none | note source IPs |
| `http-nsepa-probe` | TARGETED | 1-byte `nsepa.deb` requests (HTTP 206): a pre-check before attacking | none | note source IPs |
| `http-webshell-probe` | TARGETED | requests for `.ctxs.receiver` / `.slap.receiver`: someone checking whether the webshell exists | none | **check the HTTP status**: 404 = absent, 200 = present |
| `http-vpn-c-probe` | TARGETED | request for `/vpn/c`, where a stolen config archive is served; not a 200 | none | a 404 means the archive was absent |
| `http-vpn-c-200` | **COMPROMISE** | `/vpn/c` answered 200: the config archive (`ns.conf`, keys) was likely downloaded | none | assume configuration and secrets are stolen; rotate them (section 6) |
| `http-nsconmsg` | TARGETED | a web request to `/nsconmsg`, a CLI tool that is never a web path; seen when a webshell is used | none | check the status code and source |
| `http-xsh-inventory` | TARGETED | a `/download/x.sh` request or the fake `Team-NetScaler-Inventory` user agent | none | note source IPs |
| `http-gateway-pkg-errors` | TARGETED | errors for `.deb`/`.sig`/`.php`/`.ico` files in Gateway folders: possible webshell staging | **possible**: broken client downloads | check whether the file exists (`file-*` findings) |
| `http-headless-chrome` | CHECK | a `HeadlessChrome` user agent in the VPN access log: browser automation | **yes**: monitoring tools use it | check source, URL and time |
| `http-b64decode` | CHECK | `b64decode` / `base64_decode` in an HTTP log | **possible** | read the line |
| `httperror-script-refs` | CHECK | a `.php`/`.sh`/`.pl`/`.rpm`/`.tgz` reference in `httperror` (management GUI notices are ignored) | **common** | read the lines; look for requests that are not the GUI |

### 4.2 Memory-corruption and crash evidence (CVE-2026-88772 DTLS, CVE-2026-88779 SAML)

| Rule | Level | Means | Benign | Next |
|---|---|---|---|---|
| `dtls-crash` | TARGETED | DTLS handshake failure ("Internal Error") or packet-engine crash lines (`orphan rings`, `NOT restarting NSPPE`) | **yes**: crashes can have other causes | both a handshake failure and a crash close together point to a DTLS exploit attempt; compare times |
| `nsaaad-crash` | CHECK | the authentication daemon `nsaaad` crashed or hit its restart limit: the signature of the SAML crash attack | **possible**: other causes | see if SAML is configured (`conf-saml`) and the build (`conf-build`) |
| `file-core-nsaaad` | CHECK | an `nsaaad` core dump exists | as above | same; Citrix Support wants these dumps |
| `file-core-dump` | CHECK | a core or crash file | **common** after any crash | check names and dates |

### 4.3 Management-plane and admin abuse

| Rule | Level | Means | Benign | Next |
|---|---|---|---|---|
| `conf-sec-monitor` | **COMPROMISE** | a backdoor superuser named `sec_monitor` | none | remove, investigate, rotate credentials |
| `conf-epa-no-auth` | **COMPROMISE** | EPA default group is `NO_AUTH` in the config; EPA scans are effectively off. `NO_AUTH` is the attacker's name, not a NetScaler default | none | see who changed it (compare `ns.conf.N` copies, `cli-*` findings) |
| `cli-epa-no-auth` | **COMPROMISE** | the same change was made by a CLI command recorded in `ns.log` | none | read the user, time, `Remote_ip`; `127.0.0.1` means run from a shell on the appliance |
| `admin-persistence-script` | **COMPROMISE** | one file that adds and binds a user, sets `NO_AUTH`, unbinds policies and saves the config | none | preserve the file; it is the attacker's script |
| `cli-user-epa-changes` | CHECK | a user/EPA/policy command in the CLI audit log | **normal admin work** | confirm each was your admin; `Remote_ip 127.0.0.1` is suspicious |
| `cli-failed-nitro-login` | CHECK | a failed management (NITRO) login from a **public** address. The attack reportedly begins with one | possible: password guessing | means the management interface is reachable from the internet; restrict it |
| `conf-system-user` | CHECK | a system user other than `nsroot` | **common** | confirm each user is yours; unsaved additions are not in `ns.conf` |
| `conf-epa-policy-unbind` | CHECK | an authentication/VPN policy unbind in a saved config | normal admin changes | check against older saved configs |
| `monuploadd-wr` | CHECK | `ns_monuploadd_err.pl` run by hand with `-WR`, which forces the check that runs waiting attack text | rare | confirm who ran it |
| `vulnerable-monuploadd` | CHECK | the file *is* the vulnerable copy of `ns_monuploadd_err.pl` | **normal on a vulnerable build** | on a fixed build, the file was put back or the upgrade did not replace it |

### 4.4 Configuration, persistence and cleanup

| Rule | Level | Means | Benign | Next |
|---|---|---|---|---|
| `httpd-webshell-alias` | COMPROMISE | an Apache alias exposing a webshell (`receiver.min...css`, `LogonUISimple...style`, an alias to a hidden file) | none | find the target file |
| `httpd-php-enabled` | COMPROMISE | `httpd.conf` turns PHP on (`php_flag engine on`, `SetHandler php`) | none | read the line and the file it covers |
| `httpd-nonphp-as-php` | COMPROMISE | a non-`.php` extension (`.deb`, `.sig`, ...) is run as PHP | none | the report names the extensions |
| `httpd-aliasmatch-gateway` | COMPROMISE | an `AliasMatch` pointing into Gateway folders | rare | review the rule |
| `startup-persistence` | COMPROMISE | a Python one-liner, decoder or reversed path string in a startup file | rare | review the line |
| `nsafter-suspicious` | COMPROMISE | a suspicious command in `nsafter.sh`, which runs after every boot | rare | review; a changed `nsafter.sh` you did not make is persistence |
| `cron-wipe` | COMPROMISE | a user cron job that deletes or empties logs or files: trace wiping | rare | find who created it |
| `cron-agent-pl` | SUSPECT | a cron entry starting a known implant (`nsmon.pl`, `.slap` agent, `slapshot`, `whipd`) | none | review the entry and the files it names |
| `cron-downloader` | CHECK | a cron line that downloads from the network | **possible**: some stock jobs | compare with a clean appliance of the same build |

### 4.5 Files, processes and listeners (present only if the bundle contains them)

| Rule | Level | Means |
|---|---|---|
| `file-webshell-hidden` | COMPROMISE | a hidden webshell file (`.ctxs*`, `.slap*`, `.local_journal`) |
| `file-saml-kit` | COMPROMISE | the SAML-attack kit (`.slap/`, `.ux/`, `slapshot.py`, `whipd.py`, `loot_*`, `httpd.conf.slap.bak`) |
| `file-exploit-marker` | COMPROMISE | an exploit marker or output file (`nx_verify.html`, `wtw*`, `watchTowr*`, `c88771*`, `xua.html`, `id009*`) |
| `file-nsmon` | COMPROMISE | the `nsmon.pl` Perl implant (`/var/tmp/.nsmon`, `/var/tmp/.s`) |
| `file-payload-dropped` | COMPROMISE | a file known payloads drop (`lula`, `update_c*.pl`, `/var/1.py`, `x.sh`, `.ns_suidcmd`, `update_result_*.tgz`, `/vpn/c`) |
| `file-tunnel` | COMPROMISE | a tunnel artefact (`.uxdport`, `.uxdlock`) |
| `file-platypus` | COMPROMISE | Platypus C2 agent files (`/var/core/.ns-cache`, `/netscaler.local/ns_*.pl`) |
| `file-legacy-notrobin` | COMPROMISE | a leftover of the **2020** CVE-2019-19781 backdoor: an older, separate compromise |
| `file-payload-target` | SUSPECT | a file payloads write stolen data or loaders into (`insight-new.js`, `admin_ui/e.txt`, `admin_ui/log.txt`) |
| `file-config-staging` | CHECK | a copy of `ns.conf` or key files, or config exports, in a web or temp folder: a stolen config waiting to be fetched |
| `file-shell-in-vartmp` | CHECK | a shell binary in `/var/tmp` |
| `file-hidden-web` | CHECK | a hidden file in a web folder; compare with a clean appliance of the same build |
| `file-dot-custom` | CHECK | a `.dot` file under `LogonPoint/custom` |
| `file-php-outside-gui` | CHECK | PHP/XHTML under `/var/netscaler` outside `admin_ui` and `websocketd` (customisations can be legitimate) |
| `known-malicious-hash` | COMPROMISE | the file's SHA-256 matches a published malicious sample. Very reliable |
| `artefact-name` | SUSPECT | a known payload name appears in a listing, command output or config. It says the name exists, not that the file does |
| `ps-payload` | COMPROMISE | a payload process in the process listing (`lula`, `update_c*`, `nsmon.pl`, `xd7h`, `gsocket`, `slapshot`, ...) |
| `ps-decoy-name` | COMPROMISE | a process with a Platypus decoy name (`system-health`, `health-monitor`, `healthd`, ...) |
| `sockstat-listener` | COMPROMISE | a Python/Perl listener on 9909/9910 (SAML-attack kit) or 41000-41999 (`nsmon` implant) |
| `setuid-sh` | COMPROMISE | a setuid `/bin/sh` or `/var/tmp/sh` in a file listing |

### 4.6 Webshell code and payload content

| Rule | Level | Means |
|---|---|---|
| `web-php-code` | COMPROMISE | PHP or webshell code where none belongs (`LogonPoint/custom`, `/var/vpn`) |
| `web-whipshot-x-ux` | COMPROMISE | webshell reading commands from `HTTP_X_UX*` headers (WHIPSHOT, per Mandiant) |
| `web-whipshot-nsc` | COMPROMISE | `eval`/`system` on `HTTP_NSC_CLIENTTYPE` / `HTTP_NSC_LDAP` in the custom or Gateway plugin folders (NetScaler's own GUI PHP is excluded) |
| `web-obfuscated-code` | COMPROMISE | generic obfuscated webshell code: `eval` of a decoder, `eval`/`assert` on request input, `preg_replace /e`, `create_function`. Could rarely match a customisation |
| `unit42-deb-strings` | COMPROMISE | the key, token or passphrase of the Unit 42 `.deb` webshell; matches renamed copies |
| `slap-webshell-token` | COMPROMISE | the first half of the SAML-attack kit's webshell token |
| `slapshot-marker` | COMPROMISE | the `UXD_IDLE_EXIT` marker of the SLAPSHOT tunnel |
| `platypus-bootstrap` | COMPROMISE | the Platypus agent bootstrap script (its token differs per victim, so no fixed hash) |
| `platypus-binary` | COMPROMISE | the Platypus agent's signing key or strings |

### 4.7 Shell history (needs `sh.log` / `bash.log`)

| Rule | Level | Means | Benign | Next |
|---|---|---|---|---|
| `hist-platypus-bootstrap` | SUSPECT | a Platypus agent bootstrap download | none | read the line and time |
| `hist-postexploit` | CHECK | `ldapsearch`, `openssl s_client`, `ns_gui/vpn`: how attackers pull AD credentials via the LDAP bind account | **admins use these** | confirm who ran it |
| `hist-key-theft` | CHECK | commands touching `/flash/nsconfig/keys`, `F1.key`/`F2.key`, `database.php`, `LDAPTLS_REQCERT` | possible admin work | if it was before patching, rotate keys and passwords |
| `hist-kill-snmpd` | CHECK | `customsnmpd` killed (covering tracks) | rare | confirm who ran it |

### 4.8 Known attacker infrastructure and scanners

| Rule | Level | Means | Next |
|---|---|---|---|
| `known-attacker-ip` | TARGETED | one of the 99 published attacker IPs appears. The title says which IP and who published it | check the log type and time; a single line proves contact, not success |
| `known-attacker-domain` | TARGETED | one of 15 attacker, C2 or exfiltration domains appears (includes `webhook.site`, `gsocket.io`, `oast.fun`, which are also used legitimately) | check the context |
| `password-spray-range` | TARGETED | an IP in a published spray range (`138.226.239.0/24`, `185.136.15.0/24`, `77.91.71.0/24`, `93.152.219.115`) | count failed logins |
| `scanner-ip` | LEAD | one of 97 opportunistic scanners tagged by GreyNoise; often residential proxies | hunting lead only. Do not block or conclude on this alone |

### 4.9 Context

| Rule | Level | Means |
|---|---|---|
| `conf-build` | INFO / CHECK | the build from the `ns.conf` header against the fixed builds. `CHECK` with "VULNERABLE" means it is below the CTX697096 fix (14.1: 73.37, 13.1: 64.24, 13.1-FIPS: 37.279); 13.0 and 12.1 are end-of-life. FIPS builds use different numbers, so verify those by hand |
| `conf-saml` | INFO | SAML is configured, so CVE-2026-88779 applies. Fixed in 14.1-73.41, 13.1-64.28, 13.1-FIPS 37.282 |

## 5. Triage: before or after the fix?

The scan report does **not** tag attack lines as before or after the patch (`nsioc summarize -fixdate` can split
the dated lines for you). This matters a lot:

- An injection attempt **before** the fixed build was installed may have run (the injected command is reportedly
  picked up by a background job up to about 24 hours later).
- An attempt **after** the fix probably did not run, **except** that the upstream notes commands were reported
  running on CTX697096-fixed builds from 2 Oct 2026 until the CVE-2026-88779 fix.

Work it out yourself:
1. Take the build from `conf-build` and find when it was installed (upgrade entries in `ns.log`/`messages`, or
   your change records).
2. Compare it with the time of each TARGETED/SUSPECT line. Remember syslog lines have no year.
3. Check the COVERAGE time span: if the logs start *after* the fix, you cannot see the before period at all.
   Use firewall or proxy logs for it.

## 6. If you have COMPROMISE findings

These are the points the upstream checker gives; confirm against current Citrix guidance (it cites CTX694799):

1. **Do not reboot or upgrade yet.** Some traces exist only in memory, and a reboot clears `/tmp`.
2. Preserve evidence: this report, the bundle, `/var/log`, the flagged files, a VPX snapshot or memory capture.
3. Check the **HA peer**: HA file sync copies webshells to the other node.
4. Isolate or fail over, disable HA sync, rebuild rather than clean, rotate **all** secrets (including the key
   encryption key) and revoke certificates, especially if `/vpn/c` returned 200 or key files were touched.
5. Involve incident response and Citrix Support, and run the official Citrix IoC scan too.

## 7. Limits to keep in mind

- Only **published** indicators are searched; a new variant will not match.
- A support bundle has no file times, no live process timing and no memory. Missing sources are listed in COVERAGE.
- `log-shell-injection`, `httperror-script-refs`, `http-b64decode`, `artefact-name` and the `CHECK` items can be noisy;
  they are prompts for review, not conclusions.
- A single line from a LEAD or TARGETED IP shows contact, not compromise.
- Findings are listed per rule and file, with only the first matching lines shown (`-max-lines` changes this). The
  `(N matches)` figure is the full count.
