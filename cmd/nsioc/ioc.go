package main

// User-supplied indicators (-ioc-file): webhook hosts, URLs or whole command strings that are kept out of the
// repository. Each entry becomes three rules so the same text is graded by WHERE it was found:
//
//	in a cron/startup file or the cron run log   SUSPECT   (persistence, or proof the job ran)
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
	iocCronish = re(`crontab|cron/tabs/|(^|/)log/cron([._-]|$)|(^|/)(nsafter\.sh|rc\.netscaler|rc)$|(^|/)etc/cron`)
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
		s.rules = append(s.rules,
			&Rule{ID: "cron-ioc", Sev: Suspect, Path: iocCronish, Re: r, Lits: lits, NoCmt: true,
				Desc: "your indicator found in a cron / startup file or the cron run log: a scheduled job names it (or ran it)", Ref: ref},
			&Rule{ID: "ioc-log", Sev: Suspect, Path: iocLogish, Re: r, Lits: lits,
				Desc: "your indicator found in ns.log / messages / shell history: an attempt, or a typed command; execution needs a matching file, cron entry or connection", Ref: ref},
			&Rule{ID: "ioc-other", Sev: Check, NotPath: re(iocCronish.String() + "|" + iocLogish.String()), Re: r, Lits: lits,
				Desc: "your indicator found in a file that is neither a cron/startup file nor a log", Ref: ref},
		)
		n++
	}
	return n, sc.Err()
}
