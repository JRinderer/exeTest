package main

// User-supplied indicators (-ioc-file): webhook hosts, URLs or whole command strings that are kept out of the
// repository. Each entry becomes rules so the same text is graded by WHERE it was found:
//
//	in a cron/startup file                        SUSPECT   cron-ioc-config: the job is configured
//	in the cron run log / cron lines of messages  SUSPECT   cron-ioc-ran: the job was executed
//	in ns.log / messages / shell history          SUSPECT   (an attempt, or a command that was typed)
//	anywhere else                                 CHECK     (mentioned in some other file)

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	iocCfg     = re(`crontab|cron/tabs/|(^|/)(nsafter\.sh|rc\.netscaler|rc)$|(^|/)etc/cron`)
	iocCronLog = re(`(^|/)log/cron([._-]|$)`)
	iocMsgs    = re(`(^|/)(messages|syslog)([._-]|$)`)
	iocCronish = re(iocCfg.String() + `|` + iocCronLog.String())
	// a syslog line written by cron itself ("Oct  5 10:00:01 host /usr/sbin/cron[123]: (user) CMD (...)"),
	// anchored at the start of the line so text smuggled into another log cannot pass for one
	cronLineRe = re(`^(<[0-9]+>)?[A-Z][a-z]{2} +[0-9]+ [0-9:]{8} +[^ ]+ +([^ ]*/)?cron\[[0-9]+\]`)
	cronUserRe = re(`\(([A-Za-z0-9._-]+)\) CMD`)
	iocLogish  = re(`(^|/)(ns\.log|messages|notice\.log|nsvpn\.log)([._-]|$)|(^|/)(sh\.log|bash\.log)([._-]|$)|\.(bash|sh)_history$|nscli_history`)

	// ${IFS} and its usual disguises: $IFS, $%7BIFS%7D, %24%7BIFS%7D, a space, '+' or %20.
	ifsToken = regexp.MustCompile(`(?i)\$\{IFS\}|\$IFS\b`)
	ifsAlt   = `(?:\$\{IFS\}|\$IFS|\$%7BIFS%7D|%24%7BIFS%7D|%24IFS|[[:space:]]+|\+|%20)`
)

// iocPattern turns one line of the IOC file into a case-insensitive regexp and a lower-case prefilter.
// "re:<regex>" is used as written; anything else is a literal in which ${IFS} also matches its disguises.
func iocPattern(entry string) (*regexp.Regexp, string, error) {
	if rx, ok := strings.CutPrefix(entry, "re:"); ok {
		r, err := regexp.Compile("(?i)" + rx)
		return r, "", err
	}
	parts := ifsToken.Split(entry, -1)
	best := ""
	for i, p := range parts {
		if len(p) > len(best) {
			best = p
		}
		parts[i] = regexp.QuoteMeta(p)
	}
	r, err := regexp.Compile("(?i)" + strings.Join(parts, ifsAlt))
	return r, strings.ToLower(best), err
}

// LoadIOCFile reads one indicator per line ('#' starts a comment, blank lines are ignored) and adds the rules.
func (s *Scanner) LoadIOCFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for ln := 1; sc.Scan(); ln++ {
		e := strings.TrimSpace(sc.Text())
		if e == "" || e[0] == '#' {
			continue
		}
		if len(e) < 4 {
			return n, fmt.Errorf("%s:%d: %q is too short to be a useful indicator", path, ln, e)
		}
		r, lit, err := iocPattern(e)
		if err != nil {
			return n, fmt.Errorf("%s:%d: %v", path, ln, err)
		}
		var lits []string
		if lit != "" {
			lits = []string{lit}
		}
		const ref = "user IOC file"
		ran := func(line []byte) (string, Severity, bool) { s.noteRun(line); return "", 0, true }
		s.rules = append(s.rules,
			&Rule{ID: "cron-ioc-config", Sev: Suspect, Path: iocCfg, NotPath: iocCronLog, Re: r, Lits: lits, NoCmt: true,
				Desc: "your indicator is CONFIGURED in a cron / startup file: a scheduled job names it (this alone does not show it ran)", Ref: ref},
			&Rule{ID: "cron-ioc-ran", Sev: Suspect, Path: iocCronLog, Re: r, Lits: lits, Eval: ran,
				Desc: "your indicator is in the cron run log: cron EXECUTED a command containing it", Ref: ref},
			&Rule{ID: "cron-ioc-ran", Sev: Suspect, Path: iocMsgs, Re: r, And: cronLineRe, Lits: lits, Eval: ran,
				Desc: "your indicator is in a cron line of the system log: cron EXECUTED a command containing it", Ref: ref},
			&Rule{ID: "ioc-log", Sev: Suspect, Path: iocLogish, Re: r, Not: cronLineRe, Lits: lits,
				Desc: "your indicator found in ns.log / messages / shell history: an attempt, or a typed command; execution needs a matching file, cron entry or connection", Ref: ref},
			&Rule{ID: "ioc-other", Sev: Check, NotPath: re(iocCronish.String() + "|" + iocLogish.String()), Re: r, Lits: lits,
				Desc: "your indicator found in a file that is neither a cron/startup file nor a log", Ref: ref},
		)
		n++
		s.iocOn = true
	}
	return n, sc.Err()
}

// noteRun records one cron run line that names an indicator: when it happened and which user ran it.
func (s *Scanner) noteRun(line []byte) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	s.runN++
	if t, hasYear, ok := parseTS(line); ok {
		s.runSpan.note(t, hasYear)
	}
	if m := cronUserRe.FindSubmatch(line); m != nil {
		if s.runUsers == nil {
			s.runUsers = map[string]bool{}
		}
		s.runUsers[string(m[1])] = true
	}
}
