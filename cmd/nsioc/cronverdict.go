package main

// The question behind -ioc-file is "is a cron task running this command?". Three separate facts answer it,
// and each comes from a different file, so they are put side by side and never merged into one score:
//
//	configured  a crontab / startup file names the indicator            (cron-ioc-config)
//	executed    cron's own log shows a run of a command containing it    (cron-ioc-ran)
//	attempted   the indicator was sent to the appliance (ns.log etc.)    (ioc-log)

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	cronConfirmed  = "CONFIRMED-RUNNING"
	cronNotSeen    = "CONFIGURED-NO-RUN-SEEN"
	cronNoLog      = "CONFIGURED-NO-CRON-LOG"
	cronRunNoEntry = "RUN-SEEN-NO-ENTRY"
	cronAttempt    = "ATTEMPT-ONLY"
	cronNone       = "NONE"
)

type cronVerdict struct {
	State string
	Runs  int
	Text  string
}

func (s *Scanner) cronVerdict(findings []*agg, defang bool) cronVerdict {
	if !s.iocOn {
		return cronVerdict{}
	}
	show := func(t string) string {
		if defang {
			return defangText(t)
		}
		return t
	}
	var cfg, ran, att []*agg
	for _, a := range findings {
		switch a.ID {
		case "cron-ioc-config":
			cfg = append(cfg, a)
		case "cron-ioc-ran":
			ran = append(ran, a)
		case "ioc-log", "log-pitboss-injection", "log-pitboss-generic":
			att = append(att, a)
		}
	}
	s.runMu.Lock()
	runs, runSpan, users := s.runN, s.runSpan, keys(s.runUsers)
	mtimes := map[string]int64{}
	for k, v := range s.cfgMtime {
		mtimes[k] = v
	}
	s.runMu.Unlock()
	cl := s.cov[covIdx["cronlog"]]
	ms := s.cov[covIdx["messages"]]

	var state string
	switch {
	case len(cfg) > 0 && runs > 0:
		state = cronConfirmed
	case len(cfg) > 0 && cl.Files == 0:
		state = cronNoLog
	case len(cfg) > 0:
		state = cronNotSeen
	case runs > 0:
		state = cronRunNoEntry
	case len(att) > 0:
		state = cronAttempt
	default:
		state = cronNone
	}

	var b strings.Builder
	b.WriteString("\n=== CRON VERDICT (your indicators) ===\n")
	headline := map[string]string{
		cronConfirmed:  "A cron entry names your indicator AND cron's log shows it executing. This is the cron task running that command.",
		cronNotSeen:    "A cron entry names your indicator, but the cron log holds no run of it. Not shown to be running; see 'Cron log reach' for whether the log could have shown it.",
		cronNoLog:      "A cron entry names your indicator, but this collection has no cron run log, so whether it ran CANNOT be determined from it.",
		cronRunNoEntry: "Cron ran a command containing your indicator, but no crontab entry for it was found (removed, or not collected).",
		cronAttempt:    "Only attempts: your indicator (or a pitboss injection) appears in logs, with no cron entry and no cron run. Nothing shows it executed.",
		cronNone:       "Your indicators were not found in any cron file, cron log or log.",
	}[state]
	fmt.Fprintf(&b, "State: %s\n  %s\n\n", state, headline)

	if len(cfg) > 0 {
		b.WriteString("  Configured : ")
		for i, a := range cfg {
			if i > 0 {
				b.WriteString("               ")
			}
			fmt.Fprintf(&b, "%s", a.File)
			if mt := lookupMtime(mtimes, a.File); mt > 0 {
				fmt.Fprintf(&b, "  (file last modified %s UTC, from the bodyfile)", time.Unix(mt, 0).UTC().Format("2006-01-02 15:04:05"))
			}
			b.WriteString("\n")
			if len(a.Lines) > 0 {
				fmt.Fprintf(&b, "                 line %d: %s\n", a.Lines[0].N, show(a.Lines[0].Text))
			}
		}
	} else {
		b.WriteString("  Configured : no cron / startup file names an indicator\n")
	}
	if runs > 0 {
		fmt.Fprintf(&b, "  Executed   : %d run line(s)", runs)
		if sp := fmtSpan(&runSpan); sp != "" {
			fmt.Fprintf(&b, ", %s", sp)
		}
		if len(users) > 0 {
			fmt.Fprintf(&b, ", as user %s", strings.Join(users, ", "))
		}
		b.WriteString("\n")
		for _, a := range ran {
			fmt.Fprintf(&b, "               in %s\n", a.File)
		}
		if len(ran) > 0 && len(ran[0].Lines) > 0 {
			fmt.Fprintf(&b, "               e.g. %s\n", show(ran[0].Lines[0].Text))
		}
	} else {
		b.WriteString("  Executed   : no cron run line names an indicator\n")
	}
	switch {
	case cl.Files > 0:
		fmt.Fprintf(&b, "  Cron log reach: %d cron log file(s), %d lines, %s\n", cl.Files, cl.Lines, orNone(fmtSpan(&cl)))
	case ms.Files > 0:
		fmt.Fprintf(&b, "  Cron log reach: no var/log/cron; cron lines can still be in messages (%d file(s), %s)\n", ms.Files, orNone(fmtSpan(&ms)))
	default:
		b.WriteString("  Cron log reach: no cron log and no messages file in this collection: absence of a run proves nothing\n")
	}
	if len(att) > 0 {
		total, first := 0, ""
		for _, a := range att {
			total += a.Total
			for _, h := range a.Lines {
				if h.Time != "" && (first == "" || h.Time < first) {
					first = h.Time
				}
			}
		}
		fmt.Fprintf(&b, "  Attempted  : %d log line(s) carry the indicator or a pitboss injection", total)
		if first != "" {
			fmt.Fprintf(&b, ", earliest seen %s", first)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n  NOT shown by this tool: that the request reached the webhook or succeeded (needs firewall / proxy / DNS logs),\n")
	b.WriteString("  or who created the entry. Compare the times above: an entry edited after an injection attempt, then runs, is a pattern.\n")
	return cronVerdict{State: state, Runs: runs, Text: b.String()}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func orNone(s string) string {
	if s == "" {
		return "no timestamps recognised"
	}
	return s
}

// lookupMtime finds the bodyfile modification time for a finding's file ("[root]/var/cron/tabs/nobody",
// "uac.zip!/[root]/var/cron/tabs/nobody") by matching the end of the path against bodyfile names.
func lookupMtime(m map[string]int64, file string) int64 {
	lf := "/" + strings.ToLower(file)
	best, bl := int64(0), 0
	for name, mt := range m {
		if len(name) > bl && strings.HasSuffix(lf, name) {
			best, bl = mt, len(name)
		}
	}
	return best
}
