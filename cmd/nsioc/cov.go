package main

// Coverage: which evidence sources the bundle actually contained, and how far back the
// logs reach. A "clean" result is only as good as the sources that were searched.

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"
)

type covSource struct {
	Key     string // short name for -map overrides
	Name    string
	Re      string   // matched against the lower-cased logical path; first match wins
	Timed   bool     // log with timestamps
	Loc     bool     // a location (folder) rather than a file type; counted separately
	Canon   []string // virtual paths shown to path-restricted rules when the file is classified into this source
	Enables string   // what the search can see when this source is present
}

const never = `\x00never\x00` // sources recognised by content only

// Type sources first (first match wins), then location sources (first match wins, independent of type).
var covSources = []covSource{
	{"conf", "ns.conf (saved config)", `(^|/)ns\.conf$`, false, false, []string{"virtual/ns.conf"}, "rogue users, EPA NO_AUTH, SAML config, build/version"},
	{"confold", "ns.conf.N (older saved configs)", `(^|/)ns\.conf\.[0-9]+$`, false, false, []string{"virtual/ns.conf.0"}, "config history (users or policies added/removed over time)"},
	{"nslog", "ns.log", `(^|/)ns\.log([._-]|$)`, true, false, []string{"virtual/ns.log"}, "CVE-2026-88771 command injection, CLI audit (user/EPA changes), DTLS/NSPPE and nsaaad crashes"},
	{"messages", "messages", `(^|/)messages([._-]|$)`, true, false, []string{"virtual/messages"}, "log poisoning via pitboss, crashes, daily-check lines"},
	{"notice", "notice.log", `(^|/)notice\.log([._-]|$)`, true, false, []string{"virtual/notice.log"}, "injection and crash evidence (secondary)"},
	{"nsvpn", "nsvpn.log", `(^|/)nsvpn\.log([._-]|$)`, true, false, []string{"virtual/nsvpn.log"}, "login-name injection logged by the authentication daemon"},
	{"httpvpn", "httpaccess-vpn.log", `(^|/)httpaccess-vpn`, true, false, []string{"virtual/httpaccess-vpn.log"}, "Gateway probes, webshell requests, HeadlessChrome, /vpn/c"},
	{"httpacc", "httpaccess.log", `(^|/)httpaccess[^/]*$`, true, false, []string{"virtual/httpaccess.log"}, "management/web probes, base64 User-Agent payloads, nsepa.deb probes"},
	{"httperr", "httperror.log", `(^|/)httperror[^/]*$`, true, false, []string{"virtual/httperror.log"}, "webshell staging errors, script references"},
	{"history", "shell history (sh.log / bash.log)", `(^|/)(sh\.log|bash\.log)([._-]|$)|\.(bash|sh)_history$|nscli_history`, true, false, []string{"virtual/bash.log"}, "post-exploitation: ldapsearch, key/config theft, snmpd kill, Platypus bootstrap"},
	{"httpd", "httpd.conf", `(^|/)httpd\.conf`, false, false, []string{"virtual/httpd.conf"}, "webshell aliases, PHP handlers on non-.php files"},
	{"cron", "cron (user crontabs)", `(^|/)(var/)?cron/tabs/|(^|/)crontab$`, false, false, []string{"virtual/var/cron/tabs/root"}, "implant persistence, trace-wiping jobs"},
	{"startup", "startup scripts (rc.netscaler / nsafter.sh)", `(^|/)(rc\.netscaler|nsafter\.sh)$`, false, false, []string{"virtual/rc.netscaler", "virtual/nsafter.sh"}, "persistence"},
	{"ps", "process listing (ps output)", never, false, false, nil, "payload processes, decoy process names"},
	{"sockets", "socket listing (sockstat / netstat output)", never, false, false, nil, "implant listeners, connections to known attacker infrastructure"},
	{"listings", "file listings (ls -l output)", never, false, false, nil, "setuid shell, dropped payload names"},
	{"web", "location: web folders (logon / gui / vpn)", `(^|/)(var/netscaler/(logon|gui)|netscaler/(ns_gui|portal)|var/vpn)/`, false, true, []string{"virtual/var/netscaler/logon/file"}, "webshell files and code, known file hashes"},
	{"tmp", "location: /var/tmp and /tmp", `(^|/)(var/tmp|tmp)/`, false, true, []string{"virtual/var/tmp/file"}, "dropped payloads and implant folders, known file hashes"},
	{"core", "location: core / crash files (/var/core)", `(^|/)var/(core|crash)/`, false, true, []string{"virtual/var/core/file"}, "CVE-2026-88772 / 88779 crash evidence"},
}

var covIdx = func() map[string]int {
	m := map[string]int{}
	for i, s := range covSources {
		m[s.Key] = i
	}
	return m
}()

var covRe = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(covSources))
	for i, s := range covSources {
		out[i] = re(s.Re)
	}
	return out
}()

type covStat struct {
	Files     int
	ByContent int // files classified by content because the name did not match
	Lines     int64
	Bytes     int64
	// Timestamps: syslog lines carry no year, so the two kinds are tracked separately.
	MinY, MaxY time.Time // with a year
	MinN, MaxN time.Time // without a year (year 2001 placeholder)
}

func (c *covStat) merge(o *covStat) {
	c.Files += o.Files
	c.ByContent += o.ByContent
	c.Lines += o.Lines
	c.Bytes += o.Bytes
	c.MinY, c.MaxY = span(c.MinY, c.MaxY, o.MinY, o.MaxY)
	c.MinN, c.MaxN = span(c.MinN, c.MaxN, o.MinN, o.MaxN)
}

func span(a, b, c, d time.Time) (time.Time, time.Time) {
	lo, hi := a, b
	if !c.IsZero() && (lo.IsZero() || c.Before(lo)) {
		lo = c
	}
	if !d.IsZero() && (hi.IsZero() || d.After(hi)) {
		hi = d
	}
	return lo, hi
}

func (c *covStat) note(t time.Time, hasYear bool) {
	if hasYear {
		c.MinY, c.MaxY = span(c.MinY, c.MaxY, t, t)
	} else {
		c.MinN, c.MaxN = span(c.MinN, c.MaxN, t, t)
	}
}

var monNames = map[string]time.Month{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}

func dig(b []byte) (int, bool) {
	v := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int(c-'0')
	}
	return v, len(b) > 0
}

// parseTS reads the three timestamp styles seen in NetScaler logs:
//
//	Apache   [29/Sep/2026:00:10:12 -0300]
//	ns.log   09/29/2026:00:10:12 GMT
//	syslog   Sep 29 00:10:12     (no year)
func parseTS(l []byte) (t time.Time, hasYear, ok bool) {
	if len(l) >= 26 {
		if i := bytes.IndexByte(l[:min(len(l), 64)], '['); i >= 0 && len(l) >= i+21 {
			s := l[i+1:]
			if s[2] == '/' && s[6] == '/' && s[11] == ':' {
				d, o1 := dig(s[0:2])
				y, o2 := dig(s[7:11])
				h, o3 := dig(s[12:14])
				mi, o4 := dig(s[15:17])
				sc, o5 := dig(s[18:20])
				if mo, k := monNames[strings.ToLower(string(s[3:6]))]; k && o1 && o2 && o3 && o4 && o5 {
					return time.Date(y, mo, d, h, mi, sc, 0, time.UTC), true, true
				}
			}
		}
	}
	if len(l) >= 19 && l[2] == '/' && l[5] == '/' && l[10] == ':' {
		mo, o1 := dig(l[0:2])
		d, o2 := dig(l[3:5])
		y, o3 := dig(l[6:10])
		h, o4 := dig(l[11:13])
		mi, o5 := dig(l[14:16])
		sc, o6 := dig(l[17:19])
		if o1 && o2 && o3 && o4 && o5 && o6 && mo >= 1 && mo <= 12 {
			return time.Date(y, time.Month(mo), d, h, mi, sc, 0, time.UTC), true, true
		}
	}
	if len(l) >= 15 && l[3] == ' ' && l[9] == ':' && l[12] == ':' {
		if mo, k := monNames[strings.ToLower(string(l[0:3]))]; k {
			d, o1 := dig(bytes.TrimSpace(l[4:6]))
			h, o2 := dig(l[7:9])
			mi, o3 := dig(l[10:12])
			sc, o4 := dig(l[13:15])
			if o1 && o2 && o3 && o4 {
				return time.Date(2001, mo, d, h, mi, sc, 0, time.UTC), false, true
			}
		}
	}
	return time.Time{}, false, false
}

func fmtSpan(c *covStat) string {
	var parts []string
	if !c.MinY.IsZero() {
		parts = append(parts, fmt.Sprintf("%s .. %s", c.MinY.Format("2006-01-02 15:04"), c.MaxY.Format("2006-01-02 15:04")))
	}
	if !c.MinN.IsZero() {
		if d := c.MaxN.Sub(c.MinN).Hours() / 24; d >= 0 && d <= 300 {
			parts = append(parts, fmt.Sprintf("%s .. %s (year not in log)", c.MinN.Format("Jan _2 15:04"), c.MaxN.Format("Jan _2 15:04")))
		} else {
			parts = append(parts, "year not in log; range crosses New Year or is too wide to trust")
		}
	}
	return strings.Join(parts, "; ")
}

func spanDays(c *covStat) (float64, bool) {
	switch {
	case !c.MinY.IsZero():
		return c.MaxY.Sub(c.MinY).Hours() / 24, true
	case !c.MinN.IsZero():
		d := c.MaxN.Sub(c.MinN).Hours() / 24
		if d < 0 || d > 300 {
			return 0, false
		}
		return d, true
	}
	return 0, false
}

var (
	sApacheAcc = re(`^\S+ \S+ \S+ \[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}\] "`)
	sApacheErr = re(`^\[[A-Za-z]{3} [A-Za-z]{3} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)? [0-9]{4}\] \[`)
	sNSLog     = re(`<local[0-9]\.[a-z]+>.*(PPE-[0-9]|CMD_EXECUTED| : default )|CMD_EXECUTED`)
	sShellCmd  = re(`shell_command=`)
	sSyslog    = re(`^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} `)
	sConf      = re(`^(#NS[0-9]+\.[0-9]+ Build|(add|set|bind|enable|link) (ns|server|service|serviceGroup|lb|cs|vpn|authentication|system|ssl|responder|rewrite|policy|netProfile|network) )`)
	sHttpd     = re(`^(LoadModule |ServerRoot |Alias |AliasMatch |<Directory|<VirtualHost|Listen |DocumentRoot |AddType |SetHandler |ErrorLog |CustomLog )`)
	sPS        = re(`^USER +PID +%CPU +%MEM|^[^ ]+ +[0-9]+ +[0-9.]+ +[0-9.]+ +[0-9]+ +[0-9]+ +[^ ]+ +[^ ]+ +[^ ]+ +[0-9:.]+ `)
	sSock      = re(`^USER +COMMAND +PID +FD +PROTO|^Active Internet connections|^(tcp|udp)[46]? +[0-9]+ +[0-9]+ `)
	sLsl       = re(`^[-dlcbps][-rwxsStT]{9}[+@.]? +[0-9]+ +[^ ]+ +[^ ]+ +`)
	sVPNPath   = re(`"[A-Z]+ /(vpns?|logon|cgi)/`)
)

// sniff classifies a text file by content when its name told us nothing.
// It returns a covSources key, or "" when nothing fits.
func sniff(head []byte) string {
	lines := bytes.Split(head, []byte("\n"))
	if len(lines) > 1 {
		lines = lines[:len(lines)-1] // last line may be cut by the peek limit
	}
	if len(lines) > 60 {
		lines = lines[:60]
	}
	cnt := map[string]int{}
	vpn, n := 0, 0
	for _, l := range lines {
		l = bytes.TrimRight(l, "\r")
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		n++
		switch {
		case sApacheAcc.Match(l):
			cnt["httpacc"]++
			if sVPNPath.Match(l) {
				vpn++
			}
		case sApacheErr.Match(l):
			cnt["httperr"]++
		case sShellCmd.Match(l):
			cnt["history"]++
		case sNSLog.Match(l):
			cnt["nslog"]++
		case sConf.Match(l):
			cnt["conf"]++
		case sHttpd.Match(l):
			cnt["httpd"]++
		case sPS.Match(l):
			cnt["ps"]++
		case sSock.Match(l):
			cnt["sockets"]++
		case sLsl.Match(l):
			cnt["listings"]++
		case sSyslog.Match(l):
			cnt["messages"]++
		}
	}
	if n == 0 {
		return ""
	}
	for _, k := range []string{"httpacc", "httperr", "history", "nslog", "conf", "httpd", "ps", "sockets", "listings", "messages"} {
		need := 3
		if k == "messages" {
			need = (n + 1) / 2 // generic syslog: most lines must look like it
		}
		if n < 3 {
			need = 1
		}
		if cnt[k] >= need && (cnt[k]*10 >= n*3 || k == "conf") {
			if k == "httpacc" && vpn*2 >= cnt[k] {
				return "httpvpn"
			}
			return k
		}
	}
	return ""
}

// shape describes the layout of a line without revealing its content: letters become a/A, digits 9.
func shape(head []byte) string {
	for _, l := range bytes.Split(head, []byte("\n")) {
		l = bytes.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		if len(l) > 70 {
			l = l[:70]
		}
		out := make([]byte, len(l))
		for i, c := range l {
			switch {
			case c >= '0' && c <= '9':
				c = '9'
			case c >= 'a' && c <= 'z':
				c = 'a'
			case c >= 'A' && c <= 'Z':
				c = 'A'
			case c < 0x20 || c >= 0x7f:
				c = '?'
			}
			out[i] = c
		}
		return string(out)
	}
	return ""
}

// anyPath reports whether the pattern matches the real path or one of the virtual paths the
// file was classified into (by name override or by content).
func anyPath(r *regexp.Regexp, lp string, vps []string) bool {
	if r.MatchString(lp) {
		return true
	}
	for _, v := range vps {
		if r.MatchString(v) {
			return true
		}
	}
	return false
}
