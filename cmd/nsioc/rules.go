package main

// Detection rules adapted from ctx697096_check.sh (Thomas Poppelgaard, MIT licence),
// https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker
//
// The original runs live on a NetScaler (find, ps, crontab ...). A technical support
// bundle ("show techsupport") is a static snapshot, so the checks that make sense there
// are kept: the same patterns are applied to the collected log, config and command-output
// files. Checks that need a live system (process start times, file mtimes, sockets) are
// only done where the bundle holds the output of the matching command.

import (
	"encoding/base64"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Severity orders findings. 0 means "no override" for Rule.Eval.
type Severity int

const (
	Info Severity = iota + 1
	Lead
	Check
	Targeted
	Suspect
	Compromise
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Lead:
		return "LEAD"
	case Check:
		return "CHECK"
	case Targeted:
		return "TARGETED"
	case Suspect:
		return "SUSPECT"
	case Compromise:
		return "COMPROMISE"
	}
	return "?"
}

// Rule is a per-line content rule.
type Rule struct {
	ID       string
	Sev      Severity
	Desc     string
	Ref      string
	Path     *regexp.Regexp // lower-cased logical path must match (nil = any file)
	NotPath  *regexp.Regexp
	Re       *regexp.Regexp
	And      *regexp.Regexp // second pattern that must also match the line
	Not      *regexp.Regexp // pattern that must NOT match the line
	Lits     []string       // lower-case prefilter: at least one must occur in the lower-cased line
	Bin      bool           // also run on binary files
	NoCmt    bool           // skip lines starting with '#'
	Group    string         // part of a multi-pattern file rule (all parts must match in one file)
	groupBit int
	Eval     func(line []byte) (extra string, sev Severity, ok bool)
}

// PathRule matches the (lower-cased) logical path of a file in the bundle.
type PathRule struct {
	ID    string
	Sev   Severity
	Desc  string
	Ref   string
	Re    *regexp.Regexp
	NotRe *regexp.Regexp
}

// groupRule: all member patterns must match somewhere in the same file.
type groupRule struct {
	ID    string
	Sev   Severity
	Desc  string
	Ref   string
	Parts int
}

func re(p string) *regexp.Regexp { return regexp.MustCompile(p) }

var (
	pNS      = re(`(^|/)(ns\.log|messages|notice\.log|nsvpn\.log)([._-]|$)`)
	pNSLog   = re(`(^|/)(ns\.log|nsvpn\.log)([._-]|$)`)
	pNSMsg   = re(`(^|/)(ns\.log|messages)([._-]|$)`)
	pHTTP    = re(`(^|/)http(access|error)[^/]*$`)
	pHTTPAcc = re(`(^|/)httpaccess[^/]*$`)
	pHTTPErr = re(`(^|/)httperror[^/]*$`)
	pVPNAcc  = re(`(^|/)httpaccess-vpn`)
	pHist    = re(`(^|/)(sh\.log|bash\.log)([._-]|$)|\.(bash|sh)_history$|nscli_history`)
	pHttpd   = re(`(^|/)httpd\.conf`)
	pRC      = re(`(^|/)(rc\.netscaler|rc|rc\.conf\.defaults)$|(^|/)ns\.conf`)
	pAfter   = re(`(^|/)nsafter\.sh$`)
	pCronUsr = re(`(^|/)(var/)?cron/tabs/`)
	pCron    = re(`crontab|cron/tabs/`)
	pWeb     = re(`(^|/)(var/netscaler/(logon|gui)|netscaler/(ns_gui|portal)|var/vpn)/`)
	pWhip    = re(`(^|/)(var/netscaler/logon/logonpoint/custom|var/vpn|var/netscaler/gui/vpns?/scripts|netscaler/ns_gui/vpn/(scripts|media))/`)
	pLogged  = re(`(^|/)(http(access|error)[^/]*|ns\.log|messages|notice\.log|nsvpn\.log)([._-]|$)`)

	cmdList = `sh|bash|csh|tcsh|curl|wget|fetch|tftp|ftp|nc|ncat|python[0-9.]*|perl|php|id|uname|echo|cat|chmod|chown|rm|mv|cp|base64|openssl|mkfifo|kill|touch`
)

var (
	shellCmdRe  = "\\x60|\\$\\(|[|;&][[:space:]]*(" + cmdList + ")([[:space:]<>;|&\\x60]|\\$|$)"
	notShellCmd = re(`shell_command=`)
	b64Index    = re(`INDEX:([A-Za-z0-9+/=]{8,})`)
	b64PD9      = re(`[^A-Za-z0-9+/:](PD9[A-Za-z0-9+/]{16,}={0,2})`)
	b64WholeUA  = re(`" "([A-Za-z0-9+/]{40,}={0,2})"`)
	b64KTag     = re(`"[A-Za-z]{1,8}:([A-Za-z0-9+/=]{40,})#?"`)
	remoteIP    = re(`Remote_ip ([0-9.]+)`)
	buildHdr    = re(`^#NS([0-9]+\.[0-9]+)[[:space:]]+Build[[:space:]]+([0-9]+)\.([0-9]+)`)
	userLine    = re(`^(add|bind) system user[[:space:]]+("[^"]+"|[^[:space:]]+)`)
)

func printable(b []byte, max int) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else {
			out = append(out, ' ')
		}
		if len(out) >= max {
			break
		}
	}
	return strings.TrimSpace(string(out))
}

// b64Decode returns an Eval that appends the decoded base64 payload captured by group 1.
func b64Decode(r *regexp.Regexp, max int) func([]byte) (string, Severity, bool) {
	return func(line []byte) (string, Severity, bool) {
		m := r.FindSubmatch(line)
		if m == nil {
			return "", 0, true
		}
		s := strings.TrimRight(string(m[1]), "=")
		b, err := base64.RawStdEncoding.DecodeString(s)
		if err != nil && len(s) > 0 {
			// tolerate a truncated last quantum
			b, _ = base64.RawStdEncoding.DecodeString(s[:len(s)-len(s)%4])
		}
		return "  [base64 decoded: " + printable(b, max) + "]", 0, true
	}
}

func isPrivate(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return true
	}
	return p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast()
}

// buildVerdict compares a build against the CTX697096 / CTX697174 fixed builds.
func buildVerdict(rel string, maj, min int) (string, Severity) {
	ge := func(m, n, fm, fn int) bool { return m > fm || (m == fm && n >= fn) }
	var fixed, saml bool
	var fixTxt, samlTxt string
	switch rel {
	case "14.1":
		fixed, fixTxt = ge(maj, min, 73, 37), "14.1-73.37"
		saml, samlTxt = ge(maj, min, 73, 41), "14.1-73.41"
	case "13.1":
		if maj == 37 { // 13.1-FIPS / NDcPP train
			fixed, fixTxt = ge(maj, min, 37, 279), "13.1-37.279 (FIPS/NDcPP)"
			saml, samlTxt = ge(maj, min, 37, 282), "13.1-37.282 (FIPS/NDcPP)"
		} else {
			fixed, fixTxt = ge(maj, min, 64, 24), "13.1-64.24"
			saml, samlTxt = ge(maj, min, 64, 28), "13.1-64.28"
		}
	default:
		return "release " + rel + " is end of life and has no CTX697096 fix - VULNERABLE, upgrade to 14.1", Check
	}
	if !fixed {
		return "build is BELOW the CTX697096 fix (" + fixTxt + ") - VULNERABLE (CVE-2026-88771/88772 exploited in the wild)", Check
	}
	if !saml {
		return "CTX697096 fix present (>= " + fixTxt + "); CVE-2026-88779 (SAML) fix needs >= " + samlTxt + " if SAML is configured", Info
	}
	return "CTX697096 and CVE-2026-88779 fixes present (>= " + samlTxt + ")", Info
}

func buildRule(line []byte) (string, Severity, bool) {
	m := buildHdr.FindSubmatch(line)
	if m == nil {
		return "", 0, false
	}
	maj, _ := strconv.Atoi(string(m[2]))
	min, _ := strconv.Atoi(string(m[3]))
	v, sev := buildVerdict(string(m[1]), maj, min)
	return "  [NS" + string(m[1]) + " build " + string(m[2]) + "." + string(m[3]) + ": " + v + "]", sev, true
}

func systemUserRule(line []byte) (string, Severity, bool) {
	m := userLine.FindSubmatch(line)
	if m == nil {
		return "", 0, false
	}
	if strings.Trim(string(m[2]), `"`) == "nsroot" {
		return "", 0, false
	}
	return "", 0, true
}

func nitroLoginRule(line []byte) (string, Severity, bool) {
	m := remoteIP.FindSubmatch(line)
	if m == nil || isPrivate(string(m[1])) {
		return "", 0, false
	}
	return "  [public source " + string(m[1]) + "]", 0, true
}

// addTypePHP flags AddType/AddHandler application/x-httpd-php with any extension other than .php/.phps.
func addTypePHP(line []byte) (string, Severity, bool) {
	l := string(line)
	i := strings.Index(strings.ToLower(l), "x-httpd-php")
	if i < 0 {
		return "", 0, false
	}
	var odd []string
	for _, f := range strings.Fields(l[i+len("x-httpd-php"):]) {
		e := strings.ToLower(strings.Trim(f, `"'`))
		if strings.HasPrefix(e, ".") && e != ".php" && e != ".phps" {
			odd = append(odd, e)
		}
	}
	if len(odd) == 0 {
		return "", 0, false
	}
	return "  [non-.php extension(s) run as PHP: " + strings.Join(odd, " ") + "]", 0, true
}

// Group ids for the admin-persistence payload script (Deyda v9.43): all five commands in one file.
const grpAdminPersist = "admin-persist"

var groupRules = map[string]groupRule{
	grpAdminPersist: {ID: "admin-persistence-script", Sev: Compromise, Parts: 5,
		Desc: "one file adds+binds a system user, sets EPA default group NO_AUTH, unbinds auth/VPN policies and saves the config (admin-persistence payload)",
		Ref:  "Deyda v9.43 / Wiz"},
}

var rules = []Rule{
	// ---- command-injection / log poisoning (CVE-2026-88771) --------------------------------
	{ID: "log-shell-injection", Sev: Suspect, Path: pNSLog, Not: notShellCmd,
		Re: re(`(?i)user|login|logon|agent|aaa`), And: re(shellCmdRe),
		Lits: []string{"`", "$(", ";", "|", "&"},
		Desc: "shell metacharacters in a logon-related ns.log/nsvpn.log entry (CVE-2026-88771 exploitation attempt)", Ref: "watchTowr, Lupovis"},
	{ID: "log-pitboss-injection", Sev: Suspect, Path: pNS, Not: notShellCmd,
		Re:   re(`died[[:space:]]+NSPPE(-[0-9]+)?[[:space:]]*(;|%3B)|missed too many heartbeats[^"]*(;|%3B)|authenticate user :?[[:space:]]*pitboss|\$\{?IFS\}?|%24%7BIFS%7D|pitboss.*(IFS|b64decode|base64|(;|%3B)[[:space:]]*(sh|bash|curl|wget|fetch|tftp|nc|python|perl|php))|(%3B|%7C)(sh|bash|curl|wget|fetch|tftp|nc|python|perl|php)`),
		Lits: []string{"nsppe", "heartbeats", "pitboss", "ifs", "%3b", "%7c"},
		Desc: "fake pitboss message / ${IFS} / encoded command injected via the login name", Ref: "Lupovis, CERT-EU, watchTowr PoC"},
	{ID: "log-pitboss-generic", Sev: Suspect, Path: pNS, Not: notShellCmd,
		Re: re(`(?i)pitboss.*(nsppe|ppe|packet.*engine|core)`), And: re(`(?i);|\x60|\$\(|&&|\|\||%3b|%60|%7c|%24%28|%26%26|%3e|%3c`),
		Lits: []string{"pitboss"},
		Desc: "pitboss packet-engine message carrying a shell metacharacter (log poisoning)", Ref: "Elastic rule 'Potential NetScaler Log Poisoning Command Injection Attempt'"},
	{ID: "ua-base64-index", Sev: Targeted, Path: pHTTP,
		Re: b64Index, Lits: []string{"index:"}, Eval: b64Decode(b64Index, 150),
		Desc: "base64 command parked in the User-Agent as INDEX:<b64> (two-stage variant)", Ref: "CERT-EU"},
	{ID: "ua-base64-php", Sev: Targeted, Path: pHTTPAcc, Not: re(`INDEX:`),
		Re: re(`"[^"]*[^A-Za-z0-9+/:]PD9[A-Za-z0-9+/]{16,}={0,2}[^"]*"`), Lits: []string{"pd9"}, Eval: b64Decode(b64PD9, 140),
		Desc: "base64 PHP (PD9...) in the User-Agent - webshell staging through the access log", Ref: "eSentire, CERT-EU"},
	{ID: "ua-base64-whole", Sev: Targeted, Path: pHTTPAcc,
		Re: re(`" "[A-Za-z0-9+/]{40,}={0,2}"`), Eval: b64Decode(b64WholeUA, 150),
		Desc: "User-Agent consisting only of a base64 string", Ref: "Kevin Beaumont"},
	{ID: "ua-base64-ktag", Sev: Targeted, Path: pNS, Not: re(`INDEX:`),
		Re: re(`"[A-Za-z]{1,8}:[A-Za-z0-9+/=]{40,}#?"`), Eval: b64Decode(b64KTag, 150),
		Desc: "base64 payload staged in a K:<base64># User-Agent (1 Oct variant)", Ref: "Gotham"},
	{ID: "log-exploit-strings", Sev: Targeted, Path: pLogged, Not: notShellCmd,
		Re:   re(`LogonPoint/custom/receiver(\.v[0-9]+)?\.min(\.[0-9a-f]+)?\.css|httpworkbench|NX-CVE-OK|nx_verify|wtw888|ns-88771-poc|PoCbit|c88771\.json|xua\.html|xd7h/|nsmon\.pl|\.nsmon/|update_c08937|/dev/tcp/|nc[[:space:]]+-e[[:space:]]|chmod[[:space:]]+\+?6555|nsshutdown[^a-z]{1,8}-R|base64[[:space:]]+-w0|exec-ok|HTTP_X_UX|HTTP_NSC_(LDAP|CLIENTTYPE)|e826d7ddf3c85920|NSC_TASS|gsocket|platypus-agent|/api/v1/agents/enroll|LogonUISimple\.html\.style\.min|;#[[:space:]]*NSX[0-9a-fA-F]|fetch(\$\{?IFS\}?|[[:space:]]|%20)+-q?o|:443/t/[0-9a-f]{6}|/api/v1/install/|AGENT_TOKEN|plt_[a-z0-9]{12,}\.`),
		Lits: []string{"receiver", "httpworkbench", "nx-cve-ok", "nx_verify", "wtw888", "88771-poc", "pocbit", "c88771", "xua.html", "xd7h", "nsmon", "update_c08937", "/dev/tcp/", "-e", "6555", "nsshutdown", "-w0", "exec-ok", "http_x_ux", "http_nsc_", "e826d7ddf3c85920", "nsc_tass", "gsocket", "platypus-agent", "/api/v1/", "logonuisimple", ";#", "fetch", ":443/t/", "agent_token", "plt_"},
		Desc: "exploit strings (webshell alias, OOB domain, canary, payload files, reverse shells, webshell header names)", Ref: "Gotham, Mandiant, Unit 42, TENEX, PitScaler"},
	{ID: "http-nsepa-probe", Sev: Targeted, Path: pHTTPAcc,
		Re: re(`nsepa\.deb`), And: re(`" 206 1 `), Lits: []string{"nsepa.deb"},
		Desc: "1-byte nsepa.deb pre-check probe (HTTP 206) - the box was found and tested", Ref: "Gotham"},
	{ID: "log-recon-marker", Sev: Targeted, Path: pLogged,
		Re: re(`vp_probe_nonexist|scanner-probe`), Lits: []string{"vp_probe_nonexist", "scanner-probe"},
		Desc: "recon marker vp_probe_nonexist / scanner-probe login", Ref: "Gotham"},
	{ID: "http-webshell-probe", Sev: Targeted, Path: pHTTPAcc,
		Re: re(`ctxs\.receiver|slap\.receiver`), Lits: []string{"receiver"},
		Desc: "request for .ctxs.receiver / .slap.receiver (webshell probing; check the HTTP status)", Ref: "Gotham"},
	{ID: "http-vpn-c-200", Sev: Compromise, Path: re(`(^|/)(httpaccess[^/]*|ns\.log|nsvpn\.log|messages)`),
		Re: re(`"(GET|HEAD|POST) /vpns?/c[ ?][^"]*" 200 `), Lits: []string{"/vpn"},
		Desc: "/vpn/c served with HTTP 200 - stolen-config archive (ns.conf, keys) likely downloaded", Ref: "Rapid7"},
	{ID: "http-vpn-c-probe", Sev: Targeted, Path: re(`(^|/)(httpaccess[^/]*|ns\.log|nsvpn\.log|messages)`), Not: re(`" 200 `),
		Re: re(`"(GET|HEAD|POST) /vpns?/c[ ?]`), Lits: []string{"/vpn"},
		Desc: "request for /vpn/c (stolen-config archive path; 404 = absent)", Ref: "Rapid7"},
	{ID: "http-nsconmsg", Sev: Targeted, Path: re(`(^|/)(httpaccess[^/]*|ns\.log|nsvpn\.log|messages)`),
		Re: re(`"[A-Z]+ /[^ "]*nsconmsg`), Lits: []string{"nsconmsg"},
		Desc: "web request to /nsconmsg (a CLI tool, never a web path) - webshell use pattern", Ref: "Corelight"},
	{ID: "http-xsh-inventory", Sev: Targeted, Path: re(`(^|/)(httpaccess[^/]*|ns\.log|nsvpn\.log|messages)`),
		Re: re(`/download/x\.sh|Team-NetScaler-Inventory`), Lits: []string{"x.sh", "team-netscaler"},
		Desc: "/download/x.sh payload or fake Team-NetScaler-Inventory user agent", Ref: "PitScaler, Gotham"},
	{ID: "dtls-crash", Sev: Targeted, Path: pNSMsg,
		Re:   re(`ClientVersion DTLSv1\.0.*Handshake failure-Internal Error|exit with orphan rings|NOT restarting NSPPE`),
		Lits: []string{"dtls", "orphan rings", "not restarting"},
		Desc: "possible CVE-2026-88772 (DTLS) attempt / packet-engine crash", Ref: "Mandiant, Deyda"},
	{ID: "http-login-payload", Sev: Targeted, Path: pHTTP,
		Re:   re(`(?i)(/nf/auth/doAuthentication\.do|/cgi/login|/p/u/doLogon\.do|/logon/LogonPoint/tmindex\.html|/logon/LogonPoint/Authentication/GetUserName)[^[:cntrl:]]*(pitboss|NSPPE|PPE unexpectedly died|missed too many heartbeats|%3B|%60|\$\{IFS\}|curl[[:space:]]|wget[[:space:]]|fetch[[:space:]])`),
		Lits: []string{"doauthentication", "/cgi/login", "dologon", "tmindex", "getusername"},
		Desc: "attack payload in a request to a login page (still visible after ns.log rotated)", Ref: "Deyda v9.28"},
	{ID: "http-gateway-pkg-errors", Sev: Targeted, Path: pHTTPErr,
		Re: re(`(?i)/vpns?/scripts/[^ ]*\.(deb|sig|php)|/vpn/media/[^ ]*\.ico`), Lits: []string{"/vpn"},
		Desc: "errors for package/signature/icon files in Gateway folders (possible webshell staging)", Ref: "Mandiant/GTIG, eSentire"},
	{ID: "http-headless-chrome", Sev: Check, Path: pVPNAcc,
		Re: re(`HeadlessChrome`), Lits: []string{"headlesschrome"},
		Desc: "HeadlessChrome user agent in VPN access log (automation; can be legitimate monitoring)", Ref: "Deyda"},
	{ID: "http-b64decode", Sev: Check, Path: pHTTP,
		Re: re(`(?i)b64decode|base64_decode`), Lits: []string{"b64decode", "base64_decode"},
		Desc: "b64decode / base64_decode string in an HTTP log", Ref: "Deyda"},
	{ID: "httperror-script-refs", Sev: Check, Path: pHTTPErr, Not: re(`admin_ui`),
		Re: re(`\.(php|sh|pl|rpm|tgz)([^a-zA-Z]|$)`), Lits: []string{".php", ".sh", ".pl", ".rpm", ".tgz"},
		Desc: ".php/.sh/.pl/.rpm/.tgz reference in the httperror log (management GUI notices ignored)", Ref: "Deyda v9.28"},

	// ---- management-plane abuse in the CLI audit log ---------------------------------------
	{ID: "cli-epa-no-auth", Sev: Compromise, Path: pNS, Not: re(`Status "ERROR`),
		Re: re(`(?i)defaultEPAGroup[[:space:]]+"?NO_AUTH`), And: re(`CMD_EXECUTED`), Lits: []string{"no_auth"},
		Desc: "EPA default group set to NO_AUTH by a CLI command (admin-persistence payload; EPA scan effectively off)", Ref: "Wiz, Deyda v9.43"},
	{ID: "cli-user-epa-changes", Sev: Check, Path: pNS, Not: re(`(?i)Status "ERROR|defaultEPAGroup[[:space:]]+"?NO_AUTH`),
		Re:  re(`(?i)Command "(add system user|bind system user|set authentication epaAction|unbind authentication (vserver|policylabel)|unbind vpn vserver|show ns runningConfig -outfile)`),
		And: re(`CMD_EXECUTED`), Lits: []string{"command \""},
		Desc: "user / EPA / policy command in the CLI audit log (Remote_ip 127.0.0.1 = run from a shell on the appliance)", Ref: "Wiz, LevelBlue"},
	{ID: "cli-failed-nitro-login", Sev: Check, Path: pNS,
		Re: re(`(?i)Command "login`), And: re(`CMD_EXECUTED`), Lits: []string{"command \"login"}, Eval: func(l []byte) (string, Severity, bool) {
			if !strings.Contains(string(l), `Status "ERROR`) {
				return "", 0, false
			}
			return nitroLoginRule(l)
		},
		Desc: "failed management/NITRO login from a public address - CVE-2026-88771 is staged through one; management interface reachable from the internet", Ref: "craigsblackie root-cause analysis"},
	{ID: "nsaaad-crash", Sev: Check, Path: pNSMsg,
		Re:   re(`(?i)\(nsaaad\).*exited on signal|proc nsaaad.*(SIGNALED|EXITED)|monitored processes have exited|maximum number of restarts|nsaaad unexpectedly died due to receiving signal|Pitboss declaring system failure`),
		Lits: []string{"nsaaad", "monitored processes", "maximum number of restarts", "declaring system failure"},
		Desc: "authentication daemon nsaaad crash - crafted SAML requests (CVE-2026-88779, CTX697174)", Ref: "Citrix SAML guidance"},
	{ID: "monuploadd-wr", Sev: Check, Path: re(`(^|/)(bash\.log|sh\.log|notice\.log)|history`),
		Re: re(`ns_monuploadd_err\.pl[^|]*-WR`), Lits: []string{"ns_monuploadd_err"},
		Desc: "ns_monuploadd_err.pl run by hand with -WR (forces the check that runs waiting attack text)", Ref: "CISA Sigma"},

	// ---- shell history ---------------------------------------------------------------------
	{ID: "hist-postexploit", Sev: Check, Path: pHist,
		Re: re(`ldapsearch|openssl[[:space:]]+s_client|ns_gui/vpn`), Lits: []string{"ldapsearch", "s_client", "ns_gui/vpn"},
		Desc: "shell history: ldapsearch / openssl s_client / ns_gui/vpn (LDAP credential theft via the bind account)", Ref: "Kevin Beaumont"},
	{ID: "hist-platypus-bootstrap", Sev: Suspect, Path: pHist,
		Re: re(`/api/v1/install/|AGENT_TOKEN|plt_[a-z0-9]{12,}\.`), Lits: []string{"/api/v1/install/", "agent_token", "plt_"},
		Desc: "shell history: Platypus agent bootstrap download", Ref: "TENEX"},
	{ID: "hist-kill-snmpd", Sev: Check, Path: pHist,
		Re: re(`kill[^|;]*customsnmpd|customsnmpd[^|;]*kill|pkill[^|;]*snmp`), Lits: []string{"snmp"},
		Desc: "shell history: customsnmpd killed (covering tracks)", Ref: "LevelBlue"},
	{ID: "hist-key-theft", Sev: Check, Path: pHist,
		Re:   re(`/flash/nsconfig/keys|F[12]\.key|database\.php|LDAPTLS_REQCERT|cp[[:space:]]+/usr/bin/bash|del[[:space:]]+/etc/auth\.conf`),
		Lits: []string{"nsconfig/keys", ".key", "database.php", "ldaptls", "/usr/bin/bash", "auth.conf"},
		Desc: "shell history touching keys / config / auth files (possible key or credential theft)", Ref: "Deyda"},

	// ---- configuration ---------------------------------------------------------------------
	{ID: "conf-build", Sev: Info, Re: buildHdr, Lits: []string{"#ns"}, Eval: buildRule,
		Desc: "NetScaler build (ns.conf header) against the CTX697096 / CTX697174 fixed builds", Ref: "CTX697096, CTX697174"},
	{ID: "conf-sec-monitor", Sev: Compromise, Re: re(`(add|bind) system user "?sec_monitor`), Lits: []string{"sec_monitor"},
		Desc: "backdoor superuser account sec_monitor", Ref: "LevelBlue"},
	{ID: "conf-epa-no-auth", Sev: Compromise, Not: re(`CMD_EXECUTED`),
		Re: re(`(?i)epaAction[[:space:]].*-defaultEPAGroup[[:space:]]+"?NO_AUTH`), Lits: []string{"no_auth"},
		Desc: "EPA default group NO_AUTH in the configuration - EPA scan effectively off (attacker group name, not a NetScaler default)", Ref: "Wiz"},
	{ID: "conf-system-user", Sev: Check,
		Re: userLine, Lits: []string{"system user"}, Eval: systemUserRule,
		Desc: "system user other than nsroot - confirm each one is yours", Ref: "LevelBlue, Wiz"},
	{ID: "conf-saml", Sev: Info,
		Re: re(`^add authentication (samlAction|samlIdPProfile) `), Lits: []string{"saml"},
		Desc: "SAML configured - CVE-2026-88779 (CTX697174) applies; needs 14.1-73.41 / 13.1-64.28 / 13.1-37.282", Ref: "CTX697174"},
	{ID: "conf-epa-policy-unbind", Sev: Check, Path: re(`ns\.conf`),
		Re: re(`(?i)^unbind (authentication (vserver|policylabel)|vpn vserver) `), Lits: []string{"unbind"},
		Desc: "unbind of authentication / VPN policy in a saved config", Ref: "Wiz"},

	// ---- httpd.conf ------------------------------------------------------------------------
	{ID: "httpd-php-enabled", Sev: Compromise, Path: pHttpd, NoCmt: true,
		Re: re(`(?i)^[[:space:]]*(php_flag|php_admin_flag)[[:space:]]+engine[[:space:]]+on|^[[:space:]]*SetHandler[[:space:]]+.*php`), Lits: []string{"engine", "sethandler"},
		Desc: "httpd.conf enables PHP (php_flag engine on / SetHandler php)", Ref: "Beazley, CERT-EU"},
	{ID: "httpd-webshell-alias", Sev: Compromise, Path: pHttpd, NoCmt: true,
		Re: re(`receiver(\\?\.v[0-9]+)?\\?\.min|LogonUISimple\\?\.html\\?\.style|^[[:space:]]*Alias(Match)?[[:space:]].*/\.[^/[:space:]]+[[:space:]]*$`), Lits: []string{"receiver", "logonuisimple", "alias"},
		Desc: "httpd alias exposing a webshell", Ref: "Gotham, TENEX"},
	{ID: "httpd-nonphp-as-php", Sev: Compromise, Path: pHttpd, NoCmt: true,
		Re: re(`(?i)Add(Handler|Type)[[:space:]]+["']?application/x-httpd-php["']?[[:space:]]+\.`), Lits: []string{"x-httpd-php"}, Eval: addTypePHP,
		Desc: "httpd.conf runs a non-.php extension as PHP", Ref: "Mandiant/GTIG"},
	{ID: "httpd-aliasmatch-gateway", Sev: Compromise, Path: pHttpd, NoCmt: true,
		Re: re(`(?i)^[[:space:]]*AliasMatch.*(/vpns?/(media|theme|themes|images|help|logon|support)/|vpns?/scripts/)`), Lits: []string{"aliasmatch"},
		Desc: "httpd.conf AliasMatch into Gateway folders", Ref: "Mandiant/GTIG"},

	// ---- persistence -----------------------------------------------------------------------
	{ID: "startup-persistence", Sev: Compromise, Path: pRC, NoCmt: true,
		Re:   re(`(?i)python[0-9.]*[[:space:]]+-c|base64[.](b64|b85)decode|zlib[.]decompress|fnoc[.]dptth|php[.]xedni|relacsten|hs/pmt/rav/|tnioPnogoL|gifnocsn`),
		Lits: []string{"python", "base64", "zlib", "fnoc.dptth", "php.xedni", "relacsten", "hs/pmt/rav/", "tniopnogol", "gifnocsn"},
		Desc: "startup file holds a Python one-liner, decoder or reversed path string", Ref: "Deyda"},
	{ID: "nsafter-suspicious", Sev: Compromise, Path: pAfter, NoCmt: true,
		Re:   re(`(?i)python[0-9.]*|base64|b64decode|zlib|curl|wget|fetch[[:space:]]|(^|[^a-z])nc[[:space:]]|chmod[[:space:]]+[ug]?\+?s|chmod[[:space:]]+[0-7]*[4-7][0-7]{3}|/var/netscaler/logon|/netscaler/ns_gui|/var/vpn|/var/netscaler/gui|httpd\.conf`),
		Desc: "suspicious command in nsafter.sh (runs after every boot)", Ref: "Beazley"},
	{ID: "cron-wipe", Sev: Compromise, Path: pCronUsr, NoCmt: true,
		Re:   re(`(rm[[:space:]]+-|rm[[:space:]]+/|truncate|find[^|;]*-delete|find[^|;]*-exec[[:space:]]+rm|(^|[^0-9>])>[[:space:]]*/var/(log|nslog|tmp|core)|cat[[:space:]]+/dev/null[[:space:]]*>)`),
		And:  re(`/var/log|/var/nslog|/var/tmp|/tmp|/var/core|/var/netscaler|/netscaler|/var/vpn|history|\.log`),
		Desc: "user cron job that deletes or empties logs / files (trace wiping)", Ref: "Beazley"},
	{ID: "cron-agent-pl", Sev: Suspect, Path: pCron, NoCmt: true,
		Re: re(`agent\.pl|nsmon\.pl|\.nsmon/|\.slap/|slapshot|whipd`), Lits: []string{"agent.pl", "nsmon", ".slap", "slapshot", "whipd"},
		Desc: "cron entry starting a known implant (nsmon.pl / .slap agent / slapshot / whipd)", Ref: "Arctic Wolf, SAML-attack kit"},
	{ID: "cron-downloader", Sev: Check, Path: pCron, NoCmt: true, Not: re(`(?i)(curl|wget|fetch)[^|;&]*[[:space:]]"?(https?://)?(localhost|127\.0\.0\.1)([:/"[:space:]]|$)`),
		Re: re(`(curl|wget|fetch)[[:space:]]`), Lits: []string{"curl", "wget", "fetch"},
		Desc: "cron line that downloads from the network", Ref: "Deyda"},

	// ---- artefact names mentioned in non-log text (listings, ps/find output, configs) ------
	{ID: "artefact-name", Sev: Suspect, NotPath: pLogged,
		Re:   re(`\.ctxs\.receiver|\.slap\.receiver|receiver\.v[0-9]+\.min|/\.slap\b|\.slap[-.]|slapshot\.py|whipd\.py|nx_verify\.html|/wtw888|watchTowr|c88771|xua\.html|/\.nsmon|\.nsmon/|nsmon\.pl|update_c[0-9a-f]+\.pl|\.uxd(port|lock)|\.ns_suidcmd|\.local_journal|update_result_[A-Za-z0-9_.-]*\.tgz|/\.ns-cache|/netscaler\.local/|loot_(nsconfig|nshist|httpd|diag)|\.s2loot|ns-88771-poc|insight-new\.js|/xd7h/|/var/1\.py|/var/nstmp/\.nscache|/var/tmp/\.ux\b|httpd\.conf\.slap\.bak|id009\.txt`),
		Lits: []string{"receiver", ".slap", "slapshot", "whipd", "nx_verify", "wtw888", "watchtowr", "c88771", "xua.html", ".nsmon", "nsmon.pl", "update_c", ".uxd", ".ns_suidcmd", ".local_journal", "update_result_", ".ns-cache", "netscaler.local", "loot_", ".s2loot", "88771-poc", "insight-new", "xd7h", "/var/1.py", ".nscache", "/.ux", "id009"},
		Desc: "name of a known payload / webshell / implant file referenced (listing, command output or config)", Ref: "multiple (see README of the checker)"},

	// ---- live-state output (ps, sockstat) -------------------------------------------------
	{ID: "ps-payload", Sev: Compromise,
		Re:   re(`^[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]+[0-9.]+[[:space:]]+[0-9.]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+.*(\blula\b|update_c[0-9a-f]+|nsmon\.pl|\.nsmon/|xd7h|gs-netcat|gsocket|/\.ns-cache|/netscaler\.local|/\.x([[:space:]]|$)|/var/1\.py|slapshot\.py|whipd\.py|/\.slap/)`),
		Lits: []string{"lula", "update_c", "nsmon", "xd7h", "gs-netcat", "gsocket", "ns-cache", "netscaler.local", "/.x", "/var/1.py", "slapshot", "whipd", ".slap"},
		Desc: "payload process in the process listing", Ref: "Gotham, Arctic Wolf, TENEX"},
	{ID: "ps-decoy-name", Sev: Compromise,
		Re:   re(`^[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]+[0-9.]+[[:space:]]+[0-9.]+[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+([^[:space:]]*/)?(system-health|health-monitor|sys-health|node-health|healthd)([[:space:]]|$)`),
		Lits: []string{"health"},
		Desc: "process with a Platypus decoy name", Ref: "TENEX"},
	{ID: "sockstat-listener", Sev: Compromise,
		Re:   re(`\b(python|perl)[^[:space:]]*[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]+tcp[^[:space:]]*[[:space:]]+[^[:space:]]*:(9909|9910|41[0-9]{3})[[:space:]]`),
		Lits: []string{"python", "perl"},
		Desc: "Python/Perl listener on 9909/9910 (SAML-attack kit) or 41000-41999 (nsmon implant)", Ref: "Arctic Wolf, SAML-attack kit"},
	{ID: "setuid-sh", Sev: Compromise,
		Re: re(`^[-l][-rwx]{2}[sS][-rwxsS]{6}[+.]?[[:space:]].*[[:space:]]/(bin|var/tmp)/sh([[:space:]]|$)`), Lits: []string{"/sh"},
		Desc: "setuid shell (/bin/sh or /var/tmp/sh) in a file listing", Ref: "GreyNoise, Deyda"},

	// ---- content of web-served files ---------------------------------------------------------
	{ID: "web-php-code", Sev: Compromise, Path: re(`(^|/)(logonpoint/custom|var/vpn)/`),
		Re: re(`<\?php|passthru[[:space:]]*\(|NSC_TASS`), Lits: []string{"<?php", "passthru", "nsc_tass"},
		Desc: "PHP / webshell code in LogonPoint/custom or /var/vpn", Ref: "GreyNoise"},
	{ID: "web-whipshot-x-ux", Sev: Compromise, Path: pWhip,
		Re: re(`HTTP_X_UX`), Lits: []string{"http_x_ux"},
		Desc: "WHIPSHOT-style webshell: command read from HTTP_X_UX*", Ref: "Mandiant"},
	{ID: "web-whipshot-nsc", Sev: Compromise, Path: pWhip,
		Re: re(`HTTP_NSC_(CLIENTTYPE|LDAP)`), And: re(`eval|base64_decode|assert|system|passthru|shell_exec`), Lits: []string{"http_nsc_"},
		Desc: "WHIPSHOT-style webshell: eval/exec on HTTP_NSC_CLIENTTYPE / HTTP_NSC_LDAP", Ref: "Mandiant"},
	{ID: "web-obfuscated-code", Sev: Compromise, Path: pWeb,
		Re:   re(`eval[[:space:]]*\([[:space:]]*(gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode|strrev)[[:space:]]*\(|(eval|assert)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|preg_replace[[:space:]]*\([[:space:]]*.[^,]{0,80}/[imsxuADSUX]*e[imsxuADSUX]*.[[:space:]]*,|create_function[[:space:]]*\(`),
		Lits: []string{"eval", "assert", "preg_replace", "create_function"},
		Desc: "generic obfuscated webshell code (eval of decoder, eval/assert on request input, preg_replace /e, create_function)", Ref: "Nextron THOR webshell rules"},

	// ---- content strings that are specific wherever they appear -----------------------------
	{ID: "unit42-deb-strings", Sev: Compromise, Bin: true,
		Re: re(`7489a0f93c67fa5cdaeb4b921d90594d|e826d7ddf3c85920|Rhfajaf1H992`), Lits: []string{"7489a0f93c67", "e826d7ddf3c8", "rhfajaf1h992"},
		Desc: "RC4 key / login token / passphrase of the Unit 42 .deb webshell (matches renamed copies)", Ref: "Unit 42"},
	{ID: "slap-webshell-token", Sev: Compromise, Bin: true,
		Re: re(`072874c28950cf7b`), Lits: []string{"072874c28950cf7b"},
		Desc: "first half of the SAML-attack kit webshell token", Ref: "community analysis of dropper 380d56"},
	{ID: "slapshot-marker", Sev: Compromise, Bin: true,
		Re: re(`UXD_IDLE_EXIT`), Lits: []string{"uxd_idle_exit"},
		Desc: "SLAPSHOT tunnel marker UXD_IDLE_EXIT", Ref: "Mandiant"},
	{ID: "platypus-bootstrap", Sev: Compromise, Bin: true,
		Re: re(`Platypus agent bootstrap|PLATYPUS_INGRESS_CA|AGENT_TOKEN='plt_`), Lits: []string{"platypus agent bootstrap", "platypus_ingress_ca", "agent_token='plt_"},
		Desc: "Platypus C2 agent bootstrap script (token differs per victim, so no fixed hash)", Ref: "TENEX, Nextron THOR"},
	{ID: "platypus-binary", Sev: Compromise, Bin: true,
		Re: re(`S8GEj/Ibzw/Zy9Z5u4saQyn0h59enf9Mk3J2m70tTMs=|platypus-agent|platypus://`), Lits: []string{"s8gej/ibzw", "platypus-agent", "platypus://"},
		Desc: "Platypus C2 agent binary signing key / strings", Ref: "TENEX"},

	// ---- multi-command payload script (admin persistence) -----------------------------------
	{ID: "ap-1", Group: grpAdminPersist, Re: re(`(?i)add[[:space:]]+system[[:space:]]+user[[:space:]]`), Lits: []string{"add"}},
	{ID: "ap-2", Group: grpAdminPersist, Re: re(`(?i)bind[[:space:]]+system[[:space:]]+user[[:space:]]`), Lits: []string{"bind"}},
	{ID: "ap-3", Group: grpAdminPersist, Re: re(`(?i)set[[:space:]]+authentication[[:space:]]+epaAction.*-defaultEPAGroup[[:space:]]+NO_AUTH`), Lits: []string{"no_auth"}},
	{ID: "ap-4", Group: grpAdminPersist, Re: re(`(?i)unbind[[:space:]]+(authentication[[:space:]]+(vserver|policylabel)|vpn[[:space:]]+vserver)`), Lits: []string{"unbind"}},
	{ID: "ap-5", Group: grpAdminPersist, Re: re(`(?i)save[[:space:]]+ns[[:space:]]+config`), Lits: []string{"save"}},
}

// pathRules fire when a file with a matching name exists in the bundle.
var pathRules = []PathRule{
	{ID: "file-webshell-hidden", Sev: Compromise, Desc: "hidden webshell file (.ctxs* / .slap* / .local_journal)", Ref: "GreyNoise, LevelBlue, SAML-attack kit",
		Re: re(`(^|/)\.(ctxs|slap|local_journal)[^/]*$`)},
	{ID: "file-saml-kit", Sev: Compromise, Desc: "SAML-attack kit file (.slap/, .ux/, slapshot.py, whipd.py, loot_*, httpd.conf.slap.bak)", Ref: "community analysis of dropper 380d56",
		Re: re(`/\.slap(/|$)|/\.ux/|(^|/)(slapshot|whipd)\.py$|(^|/)loot_[^/]*$|httpd\.conf\.slap\.bak|/var/tmp/\.slap-|\.s2loot|(^|/)tmp/\.slap`)},
	{ID: "file-exploit-marker", Sev: Compromise, Desc: "marker/output file written by an exploit payload (nx_verify.html, wtw*, watchTowr*, boom*, c88771*, xua.html, id009*)", Ref: "watchTowr, Gotham",
		Re: re(`(^|/)(nx_verify\.html|c88771[^/]*|xua\.html|id009[^/]*)$|(var/)?tmp/(wtw|watchtowr|boom)[^/]*$|/wt88771[^/]*$`)},
	{ID: "file-nsmon", Sev: Compromise, Desc: "nsmon.pl Perl implant (/var/tmp/.nsmon, /var/tmp/.s)", Ref: "Arctic Wolf",
		Re: re(`/\.nsmon(/|$)|(^|/)nsmon\.pl$|(^|/)var/tmp/\.s$`)},
	{ID: "file-payload-dropped", Sev: Compromise, Desc: "file dropped by a known payload (lula, update_c*.pl, /var/1.py, x.sh, .ns_suidcmd, update_result_*.tgz, /vpn/c)", Ref: "Gotham, PitScaler, Unit 42, LevelBlue, Rapid7",
		Re: re(`(^|/)lula$|(^|/)update_c[^/]*\.pl$|(^|/)var/1\.py$|(var/tmp|tmp)/x\.sh$|(^|/)\.ns_suidcmd$|(^|/)update_result_[^/]*\.tgz$|(gui|ns_gui)/vpn/c$`)},
	{ID: "file-tunnel", Sev: Compromise, Desc: "tunnel artefact (.uxdport / .uxdlock)", Ref: "Mandiant",
		Re: re(`\.uxd(port|lock)`)},
	{ID: "file-platypus", Sev: Compromise, Desc: "Platypus C2 agent files (/var/core/.ns-cache, /netscaler.local/ns_*.pl)", Ref: "TENEX",
		Re: re(`/\.ns-cache(/|$)|/netscaler\.local/`)},
	{ID: "file-payload-target", Sev: Suspect, Desc: "file payloads write stolen data or loaders into (insight-new.js, admin_ui/e.txt, admin_ui/log.txt)", Ref: "Gotham, Deyda",
		Re: re(`(^|/)insight-new\.js$|admin_ui/(e|log)\.txt$`)},
	{ID: "file-legacy-notrobin", Sev: Compromise, Desc: "leftover of the 2020 CVE-2019-19781 backdoor NOTROBIN (older, separate compromise)", Ref: "Gotham",
		Re: re(`/var/nstmp/\.nscache|(^|/)tmp/\.init$`)},
	{ID: "file-config-staging", Sev: Check, Desc: "config export / copy of ns.conf or key file in a web or temp folder (stolen config waiting to be downloaded)", Ref: "Deyda v9.43",
		Re: re(`(var/vpn|var/netscaler/(logon|gui)|netscaler/ns_gui|var/tmp|(^|/)tmp)/(.*/)?(ns\.conf|\.f[12]\.key)$|var/tmp/(c1|c2|labels)\.txt$`)},
	{ID: "file-shell-in-vartmp", Sev: Check, Desc: "shell binary in /var/tmp", Ref: "Deyda",
		Re: re(`(^|/)var/tmp/sh$`)},
	{ID: "file-hidden-web", Sev: Check, Desc: "hidden file in a web-served folder - compare with a clean appliance of the same build", Ref: "Gotham",
		Re:    re(`(^|/)(var/netscaler/(logon|gui)|netscaler/(ns_gui|portal)|var/vpn)/(.*/)?\.[^/]+$`),
		NotRe: re(`/admin_ui/php/system/\.htaccess$|/\.(ctxs|slap|local_journal)`)},
	{ID: "file-dot-custom", Sev: Check, Desc: ".dot file under LogonPoint/custom", Ref: "Deyda",
		Re: re(`logonpoint/custom/[^/]*\.dot$`)},
	{ID: "file-php-outside-gui", Sev: Check, Desc: "PHP/XHTML file under /var/netscaler outside admin_ui and websocketd", Ref: "Deyda v9.28",
		Re: re(`(^|/)var/netscaler/.*\.(php|xhtml)$`), NotRe: re(`var/netscaler/(gui/admin_ui|websocketd)/`)},
	{ID: "file-core-nsaaad", Sev: Check, Desc: "nsaaad core dump (authentication daemon crash, CVE-2026-88779 / SAML)", Ref: "Citrix SAML guidance",
		Re: re(`(^|/)var/core/[^/]*nsaaad`)},
	{ID: "file-core-dump", Sev: Check, Desc: "core / crash file (possible exploit attempt)", Ref: "Mandiant",
		Re: re(`(^|/)var/(core|crash)/[^/]+$`), NotRe: re(`/(bounds|minfree)$|nsaaad`)},
}
