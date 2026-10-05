# If a search finds something: where to look on the appliance and what to look for

This is a field guide for following up a finding from `nsioc` or `ipxref`. Find the finding type in your report, then
use the matching section. (`RESULTS.md` explains what each finding *means*; this explains what to *do* on the device.)

**Sources and limits.** The locations and file names come from the community checker the tools are based on
(`netscaler-ctx697096-checker`, v1.12) and its credited researchers, plus Citrix's public guidance
([CTX694799](https://support.citrix.com/external/article/CTX694799/steps-to-take-if-netscaler-adc-is-suspec.html)). I have
not run these steps on a live appliance. Commands are standard FreeBSD shell and NetScaler CLI; try them in a lab first.
Follow Citrix's current guidance where it differs.

---

## 0. Before you touch the appliance

1. **Run Citrix's official IoC scan first** (NetScaler Console > Security Advisory) and keep the result. Some traces
   exist only in memory.
2. **Do not reboot or upgrade yet.** A reboot clears `/tmp` and in-memory evidence.
3. **Preserve:** a VPX snapshot (per CTX694799), the support bundle, `/var/log`, the flagged files, and logs held
   remotely (syslog server, NetScaler Console, firewall). Hash what you copy (`sha256 file`).
4. **Check both HA nodes.** HA file sync copies webshells to the peer, and a clean node does not clear its partner.
5. **Use read-only commands** (`ls`, `grep`, `find`, `cat`). Do not edit or delete anything yet. Anything you run on a
   compromised box can be hidden by the attacker, so trust the offline bundle copy over live output where you can.
6. **Note the time zone.** Compare log times (ns.log shows GMT in `MM/DD/YYYY:HH:MM:SS`) with the build install date.

---

## 1. Injected commands in logs (`log-*`, `ua-*`, `http-login-payload`, `log-exploit-strings`)

**What it is:** an attempt to get a command executed through a log line (login name or User-Agent).

| Where | What to look for |
|---|---|
| `/var/log/ns.log*`, `messages*`, `notice.log*`, `nsvpn.log*` (rotated ones are `.gz`: use `zgrep`) | The line itself: `pitboss`, `NSPPE;`, `${IFS}`, `curl`/`fetch`/`wget`/`sh` after a `;` or `\|`. Note the **time** and the **host or URL** in the command |
| `/var/log/httpaccess*.log`, `httperror*.log` | The same time window: requests to `/nf/auth/doAuthentication.do`, `/cgi/login`, `/p/u/doLogon.do`; decoded base64 in the User-Agent |

**Did it run? Look for any of these from that time onward:**
- the file the command tried to write (`/v`, `/var/tmp/wtw*`, `/var/tmp/.s`, `x.sh`): `ls -la /var/tmp /tmp /`;
- new or recently changed files: `find /var /tmp /netscaler /nsconfig -type f -mtime -30 2>/dev/null`;
- an outbound connection to the host named in the command (**firewall logs**; the bundle cannot show this);
- a new user or changed config (section 5).

**Timing:** an attempt *before* the fixed build was installed may have run (the command is picked up by a daily job, up
to about 24 hours later). One *after* it probably did not, except from 2 Oct 2026 on builds without the CVE-2026-88779
fix. `log-shell-injection` is broad: dismiss it if the line is ordinary text.

## 2. Webshells and web server changes (`file-webshell-hidden`, `web-*`, `httpd-*`, `http-webshell-probe`, `unit42-*`)

| Where | What to look for |
|---|---|
| `/var/netscaler/logon/LogonPoint/custom/`, `/var/vpn/` | **Hidden files** (`.ctxs.receiver`, `.slap*`, `.local_journal`), any PHP: `grep -rlE '<\?php\|passthru\|eval\(' /var/netscaler/logon /var/vpn` |
| `/var/netscaler/gui/vpn/scripts/`, `/var/netscaler/gui/vpns/scripts/`, `/netscaler/ns_gui/vpn/media/` | Only client packages and images belong here. PHP, shell or text files are suspect; so are `.deb`, `.sig` or `.ico` files holding code |
| `/etc/httpd.conf` and `/nsconfig/httpd.conf` | An `Alias` for `receiver.min.*.css` or `LogonUISimple.html.style.min.*`; `php_flag engine on`; `AddType application/x-httpd-php .deb` (any extension that is not `.php`); `AliasMatch` into `vpn/media` or `vpn/scripts`. `/etc/httpd.conf` is rebuilt at boot; the webshell file is not |
| `/var/log/httpaccess*.log` | Requests for the webshell URL: **`200` means it exists**, `404` means it did not. Look at POSTs and odd cookies/headers (`HTTP_X_UX*`) |

Compare with a clean appliance of the **same build** before concluding. **Do not open or execute** a suspected webshell:
copy it, hash it, and compare the hash with the `known-malicious-hash` finding.

## 3. Dropped payloads, implants and running processes (`file-*`, `ps-*`, `sockstat-listener`, `setuid-sh`, `artefact-name`)

| Where | What to look for |
|---|---|
| `/var/tmp`, `/tmp`, `/`, `/var` (top level) | `lula`, `update_c*.pl`, `/var/1.py`, `x.sh`, `.s`, `watchTowr*`, `wtw*` |
| `/var/tmp/.nsmon/`, `/nsconfig/.slap/`, `/flash/nsconfig/.slap/`, `/var/tmp/.ux/` | The `nsmon.pl` and SAML-attack kits (`slapshot.py`, `whipd.py`, `agent.pl`, `boot.sh`, `loot_*`) |
| `/var/core/.ns-cache/`, `/netscaler.local/`, `/var/python/bin/customsnmpd` | Platypus agent. A `customsnmpd` of about 19 MB is a replaced binary (compare size and hash with a clean build). `client.crt` and `client.key` mean it enrolled |
| `/var/netscaler/.ns_suidcmd`, `ls -l /bin/sh /var/tmp/sh` | A privilege helper; a **setuid** shell (an `s` in the permissions) |
| `ps auxww`, `sockstat -4l` | Processes named `nsmon.pl`, `update_c*`, `lula`, `gsocket`; decoy names (`system-health`, `healthd`); **listeners on 9909/9910 or 41000-41999** |

Hash anything suspicious (`sha256 -q file`) and compare it with the published hashes. **Capture memory or a snapshot before
any restart** if a process is running.

## 4. Persistence (`cron-*`, `startup-persistence`, `nsafter-suspicious`)

| Where | What to look for |
|---|---|
| `/var/cron/tabs/` (every user: root, nobody, nsroot), `/etc/crontab` | Lines that run `nsmon.pl`, `agent.pl`, `.slap/boot.sh`, download with `curl`/`wget`/`fetch`, or **delete logs** (`rm`, `truncate`, `> /var/log/...`) |
| `/nsconfig/nsafter.sh` (runs after **every boot**) | Anything other than your approved content: `python`, `base64`, `curl`, `chmod +s`, writes into web folders |
| `/nsconfig/rc.netscaler`, `/flash/nsconfig/rc.netscaler`, `/etc/rc` | Python one-liners, decoders, `.slap` lines |

If a file you did not change was modified recently (`ls -la` shows the date), treat it as suspect. Preserve it **before** removing.

## 5. Admin and config changes (`conf-sec-monitor`, `conf-epa-no-auth`, `cli-*`, `conf-system-user`, `admin-persistence-script`)

| Where | What to look for |
|---|---|
| CLI: `show system user`, `show ns runningConfig` | Any account you do not recognise (the reported backdoor is **`sec_monitor`**), especially with a superuser policy. An account added but not saved appears here but **not** in `ns.conf` |
| `/nsconfig/ns.conf` and the older copies `/nsconfig/ns.conf.0`, `.1`, ... | **Date the change:** a user missing from an older copy was added after it. Look for `-defaultEPAGroup NO_AUTH` (EPA effectively off) and authentication/VPN policies that were bound in an old copy and are not now |
| `grep CMD_EXECUTED /var/log/ns.log*` | The CLI audit log. Check **user** and **`Remote_ip`**: `127.0.0.1` means the command was run from a shell **on the appliance**, which is typical of a payload, not of an admin at a console |
| `/var/tmp`, `/tmp`, `/nsconfig` | A script that adds a user, sets `NO_AUTH`, unbinds policies and runs `save ns config` |
| `grep 'Command "login' /var/log/ns.log*` with `Status "ERROR"` | Failed management logins from **public** addresses: the management interface is reachable from the internet. Restrict it |

## 6. Stolen configuration or credentials (`http-vpn-c-200`, `hist-*`, `file-config-staging`)

| Where | What to look for |
|---|---|
| `/var/log/httpaccess*.log` | `GET /vpn/c` answered **200**, with a large response size, means the archive of `/flash/nsconfig` was served |
| `/var/netscaler/gui/vpn/c`, `/netscaler/ns_gui/vpn/c` | The staged archive itself |
| `/var/tmp/c1.txt`, `c2.txt`, `labels.txt`, and copies of `ns.conf`, `.F1.key`, `.F2.key` in web or temp folders | A config or key export waiting to be fetched |
| `/var/log/sh.log*`, `bash.log*` (shell history) | `ldapsearch`, `openssl s_client`, anything touching `/flash/nsconfig/keys`, `F1.key`, `F2.key`, `database.php`; `kill` of `customsnmpd` |

**If theft is likely, treat these as exposed and rotate them:** every password and secret in `ns.conf` (LDAP bind account,
RADIUS and SNMP secrets, local users, API credentials), SSL private keys and their certificates (revoke), and the
key-encryption key.

## 7. Crashes, SAML and DTLS (`nsaaad-crash`, `dtls-crash`, `file-core-*`, `conf-saml`)

| Where | What to look for |
|---|---|
| `/var/core/` | `nsaaad-*.gz` cores (the authentication daemon) and packet-engine cores. **Keep them for Citrix Support** |
| `/var/log/messages*`, `ns.log*` | Repeated `nsaaad` exits and "maximum number of restarts", or appliance restarts followed by the **HA peer** failing the same way |
| `/nsconfig/ns.conf` | `add authentication samlAction` or `samlIdPProfile`: SAML is configured, so CVE-2026-88779 applies |
| `show version` | Whether the build has the SAML fix (14.1-73.41, 13.1-64.28, 13.1-FIPS 37.282) |
| `ps -axo lstart,command \| grep NSPPE` | Packet engines started well **after** boot: they crashed and restarted (possible DTLS exploitation) |

Until you upgrade: Citrix's Global Deny List signatures or a responder policy from Citrix Support. The upstream checker
suggests `stat denylist global AAA_REQUEST` to check the Console signatures. Crashes alone do not prove an attack.

## 8. A threat IP appears in a bundle (`ipxref` threat flag, `known-attacker-ip`)

An IP in a bundle shows **contact**, not success. To judge it:
1. **Pivot on the address** across `ns.log`, `httpaccess*.log`, `httperror*.log` and `nsvpn.log` in the bundle.
2. **Read the status codes and paths.** `404`/`403` on `/vpn/c` or a webshell path is a failed probe; `200` on a
   sensitive path is a concern. Look for `nsepa.deb` 1-byte probes, `/cgi/login` or `doAuthentication.do` abuse.
3. **Check the firewall and proxy logs for traffic from the appliance to that IP.** That outbound direction is what
   matters most, and a support bundle often cannot show it.
4. **Check the other appliances** (`ipxref` shows which bundles): the same address in several suggests a campaign.
5. Treat a **`scanner (lead)`** as weak. Do not block or conclude on it alone.

---

## 9. If a compromise is confirmed

(Per CTX694799 and the checker's guidance; check Citrix's current version.)
1. Stay calm and **preserve evidence first** (section 0). Capture memory or a snapshot.
2. **Isolate or fail over,** disable HA sync, and check the peer.
3. **Rebuild** rather than clean; do not rely on removing the files you found.
4. **Rotate all secrets** and revoke certificates (section 6), including the key-encryption key.
5. Patch to the fixed builds (CTX697096, and CTX697174 where SAML is used).
6. **Engage Citrix Support and your incident response team,** and review the firewall and SIEM logs for the whole
   exposure window.

A clean result from these tools, or from any search of a bundle, is **not proof** an appliance was never compromised.
