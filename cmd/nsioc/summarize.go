package main

// "nsioc summarize report.json": turns a JSON report into a one-page executive summary and a two-page
// investigator summary (Markdown). Deterministic and local: no network, no external service.
//
// Wording rule: the bundle can show that something was attempted or left behind, rarely that it worked.
// The text therefore says "indicated", "not established" or "cannot be assessed", and never "safe".

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	maxReportBytes = 512 << 20
	maxExecLines   = 48  // about one page
	maxInvLines    = 110 // about two pages
)

func runSummarize(args []string) int {
	fs := flag.NewFlagSet("summarize", flag.ContinueOnError)
	out := fs.String("out", "", "also write the summary to this Markdown file")
	who := fs.String("audience", "both", "exec, investigator or both")
	fix := fs.String("fixdate", "", `when the fixed build started running, "YYYY-MM-DD" or "YYYY-MM-DD HH:MM"; tags attack lines before/after`)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: nsioc summarize [flags] report.json\n\nReads a JSON report written by  nsioc -json report.json <bundle>  and writes an executive\nsummary (one page) and an investigator summary (two pages). Tip: scan with -max-lines 20 for more samples.\n\n")
		fs.PrintDefaults()
	}
	// allow the report path before or after the flags
	var path string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return 3
		}
		if fs.NArg() == 0 {
			break
		}
		if path != "" {
			fmt.Fprintln(os.Stderr, "only one report file can be summarised at a time")
			return 3
		}
		path, rest = fs.Arg(0), fs.Args()[1:]
	}
	if path == "" {
		fs.Usage()
		return 3
	}
	if *who != "exec" && *who != "investigator" && *who != "both" {
		fmt.Fprintln(os.Stderr, "-audience must be exec, investigator or both")
		return 3
	}
	var fixT *time.Time
	if *fix != "" {
		t, err := parseFix(*fix)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		fixT = &t
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	outPath, err := checkOutput("-out", *out, abs, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	doc, err := loadReport(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	text := buildSummary(doc, fixT, *who)
	fmt.Print(text)
	if outPath != "" {
		if err := writeReport(outPath, []byte(text)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
	}
	return 0
}

func parseFix(s string) (time.Time, error) {
	for _, l := range []string{"2006-01-02 15:04", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf(`-fixdate %q not understood; use "YYYY-MM-DD" or "YYYY-MM-DD HH:MM"`, s)
}

// loadReport reads the JSON report through an os.Root on its folder (no path can leave it).
func loadReport(abs string) (*reportDoc, error) {
	dir, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	f, err := dir.Open(filepath.Base(abs))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", abs)
	}
	var doc reportDoc
	if err := json.NewDecoder(io.LimitReader(f, maxReportBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: not a valid nsioc JSON report: %v", abs, err)
	}
	if doc.Schema < reportSchema {
		return nil, fmt.Errorf("%s is an older report format (schema %d); run the scan again with this version of nsioc and -json", abs, doc.Schema)
	}
	if doc.Schema > reportSchema {
		return nil, fmt.Errorf("%s is from a newer nsioc (schema %d); update nsioc", abs, doc.Schema)
	}
	return &doc, nil
}

// ---------------------------------------------------------------------------------------------------

type ruleAgg struct {
	ID         string
	Desc       string
	Sev        Severity
	Total      int
	Files      []string
	Distinct   map[string]bool // distinct descriptions (e.g. one per attacker IP)
	SamplePath string
	SampleLine int
}

type analysis struct {
	doc    *reportDoc
	gen    time.Time
	fix    *time.Time
	rules  map[string]*ruleAgg
	list   []*ruleAgg // severity, then matches, descending
	groups map[Severity]int

	buildKnown, buildVuln, samlGap bool
	buildText                      string
	bRel                           string
	bMaj, bMin                     int

	srcFound, srcTotal, gaps int
	missing                  []string
	minDays, maxDays         float64
	logSources               int

	first, last            time.Time
	dated                  int
	before, after, undated int
	atkOK, atkTotal        int // sampled lines from known attacker IPs in HTTP logs: HTTP 200 vs all
}

var (
	reStatus = regexp.MustCompile(`"[A-Z]+ [^"]*" ([0-9]{3}) `)
	sevOf    = func(s string) Severity { v, _ := parseSev(s); return v }
)

func analyse(doc *reportDoc, fix *time.Time) *analysis {
	a := &analysis{doc: doc, fix: fix, rules: map[string]*ruleAgg{}, groups: map[Severity]int{}, minDays: -1}
	a.gen, _ = time.Parse(time.RFC3339, doc.Generated)
	if a.gen.IsZero() {
		a.gen = time.Now().UTC()
	}
	for _, c := range doc.Coverage {
		if c.Loc {
			continue
		}
		a.srcTotal++
		if !c.Found {
			a.missing = append(a.missing, c.Source)
			if c.Key == "conf" || isTimedKey(c.Key) {
				a.gaps++
			}
			continue
		}
		a.srcFound++
		if isTimedKey(c.Key) {
			a.logSources++
			if c.Days > 0 {
				if a.minDays < 0 || c.Days < a.minDays {
					a.minDays = c.Days
				}
				if c.Days > a.maxDays {
					a.maxDays = c.Days
				}
				if c.Days < 7 {
					a.gaps++
				}
			} else {
				a.gaps++
			}
		}
	}

	var times []struct {
		t   string
		sev Severity
	}
	for _, f := range doc.Findings {
		sev := sevOf(f.Severity)
		a.groups[sev]++
		r := a.rules[f.Rule]
		if r == nil {
			r = &ruleAgg{ID: f.Rule, Desc: f.Desc, Sev: sev, Distinct: map[string]bool{}}
			a.rules[f.Rule] = r
		}
		r.Total += f.Matches
		r.Distinct[f.Desc] = true
		if len(r.Files) < 3 && !contains(r.Files, f.File) {
			r.Files = append(r.Files, f.File)
		}
		if r.SamplePath == "" {
			r.SamplePath = f.File
			if len(f.Lines) > 0 {
				r.SampleLine = f.Lines[0].Line
			}
		}
		for _, l := range f.Lines {
			if l.Time != "" && sev >= Targeted {
				times = append(times, struct {
					t   string
					sev Severity
				}{l.Time, sev})
			}
			if f.Rule == "known-attacker-ip" {
				if m := reStatus.FindStringSubmatch(l.Text); m != nil {
					a.atkTotal++
					if m[1] == "200" {
						a.atkOK++
					}
				}
			}
			if f.Rule == "conf-build" {
				a.noteBuild(l.Text)
			}
		}
	}
	for _, r := range a.rules {
		a.list = append(a.list, r)
	}
	sort.Slice(a.list, func(i, j int) bool {
		if a.list[i].Sev != a.list[j].Sev {
			return a.list[i].Sev > a.list[j].Sev
		}
		if a.list[i].Total != a.list[j].Total {
			return a.list[i].Total > a.list[j].Total
		}
		return a.list[i].ID < a.list[j].ID
	})

	// timeline: years missing from syslog times are inferred from the report's dated lines, else its date
	year := a.gen.Year()
	cnt := map[int]int{}
	for _, tm := range times {
		if !strings.HasPrefix(tm.t, "--") && len(tm.t) >= 4 {
			var y int
			fmt.Sscanf(tm.t[:4], "%d", &y)
			cnt[y]++
		}
	}
	best := 0
	for y, c := range cnt {
		if c > best {
			best, year = c, y
		}
	}
	for _, tm := range times {
		t, ok := a.parseHit(tm.t, year)
		if !ok {
			a.undated++
			continue
		}
		a.dated++
		if a.first.IsZero() || t.Before(a.first) {
			a.first = t
		}
		if t.After(a.last) {
			a.last = t
		}
		if fix != nil {
			if t.Before(*fix) {
				a.before++
			} else {
				a.after++
			}
		}
	}
	return a
}

func isTimedKey(k string) bool {
	switch k {
	case "nslog", "messages", "notice", "nsvpn", "httpvpn", "httpacc", "httperr", "history":
		return true
	}
	return false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (a *analysis) parseHit(ts string, year int) (time.Time, bool) {
	if strings.HasPrefix(ts, "--") {
		t, err := time.Parse("2006-01-02T15:04:05", fmt.Sprintf("%04d-%s", year, ts[2:]))
		if err != nil {
			return time.Time{}, false
		}
		if t.After(a.gen.Add(24 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		return t, true
	}
	t, err := time.Parse("2006-01-02T15:04:05", ts)
	return t, err == nil
}

// noteBuild keeps the newest build seen in ns.conf headers.
func (a *analysis) noteBuild(line string) {
	m := buildHdr.FindStringSubmatch(line)
	if m == nil {
		return
	}
	var maj, min int
	fmt.Sscanf(m[2], "%d", &maj)
	fmt.Sscanf(m[3], "%d", &min)
	text, sev := buildVerdict(m[1], maj, min)
	label := fmt.Sprintf("%s-%d.%d", m[1], maj, min)
	if a.buildKnown && (m[1] < a.bRel || (m[1] == a.bRel && (maj < a.bMaj || (maj == a.bMaj && min <= a.bMin)))) {
		return // keep the newest build seen (older saved configs may carry older headers)
	}
	a.buildKnown, a.buildText, a.bRel, a.bMaj, a.bMin = true, label, m[1], maj, min
	a.buildVuln = sev == Check
	a.samlGap = strings.Contains(text, "CVE-2026-88779 (SAML) fix needs")
}

func (a *analysis) has(ids ...string) bool {
	for _, id := range ids {
		if _, ok := a.rules[id]; ok {
			return true
		}
	}
	return false
}

func (a *analysis) total(ids ...string) int {
	n := 0
	for _, id := range ids {
		if r, ok := a.rules[id]; ok {
			n += r.Total
		}
	}
	return n
}

// distinctIPs counts distinct attacker IPs (one finding description per IP).
func (a *analysis) distinctIPs() int {
	if r, ok := a.rules["known-attacker-ip"]; ok {
		return len(r.Distinct)
	}
	return 0
}

func when(t time.Time) string { return t.Format("2 Jan 2006 15:04") }

func short(p string, n int) string {
	if len(p) <= n {
		return p
	}
	return "..." + p[len(p)-n+3:]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// ---------------------------------------------------------------------------------------------------

func buildSummary(doc *reportDoc, fix *time.Time, who string) string {
	a := analyse(doc, fix)
	var parts []string
	if who == "exec" || who == "both" {
		parts = append(parts, a.executive())
	}
	if who == "investigator" || who == "both" {
		// keep within about two pages: show fewer finding types per stage until it fits
		inv := ""
		for n := 3; n >= 1; n-- {
			inv = a.investigator(n)
			if strings.Count(inv, "\n") <= maxInvLines {
				break
			}
		}
		parts = append(parts, inv)
	}
	return strings.Join(parts, "\n---\n\n")
}

func (a *analysis) headline() (string, string) {
	c := a.groups
	switch {
	case c[Compromise] > 0:
		return "COMPROMISE INDICATED", fmt.Sprintf("Evidence consistent with a compromise was found (%s). Treat the appliance as compromised until an investigation shows otherwise.", plural(c[Compromise], "high-severity finding", "high-severity findings"))
	case c[Suspect] > 0:
		return "SUSPICIOUS ACTIVITY", "Signs of attempted exploitation, or references to known attack files, were found. The bundle does not establish that any attacker command ran."
	case c[Targeted] > 0:
		return "TARGETED, NO SUCCESS SEEN", "The appliance was targeted. No evidence that the attacks succeeded was found in the sources this bundle contained."
	case c[Check] > 0:
		return "REVIEW NEEDED", fmt.Sprintf("No known-bad indicators were found, but %s need a human decision.", plural(c[Check], "item", "items"))
	}
	return "NO PUBLISHED INDICATORS FOUND", "None of the published indicators were found in the sources this bundle contained."
}

func (a *analysis) executive() string {
	var b strings.Builder
	w := func(f string, args ...any) { fmt.Fprintf(&b, f+"\n", args...) }
	head, detail := a.headline()
	w("# Executive summary: NetScaler technical support bundle")
	w("")
	w("*Bundle:* `%s` · *Scanned:* %s · *Tool:* nsioc %s", short(a.doc.Bundle, 60), a.gen.Format("2 Jan 2006"), a.doc.Version)
	w("")
	w("## Bottom line: %s", head)
	w("")
	w("%s", detail)
	if a.gaps > 0 {
		w("")
		w("**This is not a clean bill of health.** %s", a.limitSentence())
	}
	w("")
	w("## Key facts")
	w("")
	w("- **Findings:** %d compromise, %d suspect, %d targeted, %d to review.", a.groups[Compromise], a.groups[Suspect], a.groups[Targeted], a.groups[Check])
	switch {
	case a.buildKnown && a.buildVuln:
		w("- **Software version:** %s is **below the fixed build** for the exploited vulnerabilities (CVE-2026-88771/88772).", a.buildText)
	case a.buildKnown && a.samlGap:
		w("- **Software version:** %s has the main fix; the SAML fix (CVE-2026-88779) is still needed if SAML is used.", a.buildText)
	case a.buildKnown:
		w("- **Software version:** %s includes the published fixes.", a.buildText)
	default:
		w("- **Software version:** could not be read from the bundle (no `ns.conf` header found).")
	}
	if !a.first.IsZero() {
		w("- **Activity window:** %s to %s (%s%s).", when(a.first), when(a.last), plural(a.dated, "dated line", "dated lines"), a.yearNote())
	}
	if n := a.distinctIPs(); n > 0 {
		w("- **Attack sources:** %s from published attacker lists appear in the logs.", plural(n, "IP address", "IP addresses"))
	}
	if a.fix != nil && a.dated > 0 {
		w("- **Relative to the fix (%s):** %d dated attack lines before it, %d after.", a.fix.Format("2 Jan 2006"), a.before, a.after)
	}
	if phases := a.themeBullets(); len(phases) > 0 {
		w("")
		w("## What was found")
		w("")
		for _, p := range phases {
			w("- %s", p)
		}
	}
	w("")
	w("## Decisions for management")
	w("")
	for _, d := range a.decisions() {
		w("- %s", d)
	}
	w("")
	w("## How far to trust this")
	w("")
	w("- Only **published** indicators were searched; a new technique would not match.")
	w("- The bundle is a snapshot of selected files: **%d of %d** expected evidence sources were present%s.", a.srcFound, a.srcTotal, a.daysNote())
	w("- Details, and how to tell whether an attack succeeded, are in the investigator summary and the full report.")
	return b.String()
}

func (a *analysis) yearNote() string {
	for _, c := range a.doc.Findings {
		for _, l := range c.Lines {
			if strings.HasPrefix(l.Time, "--") {
				return "; year inferred where the log omits it"
			}
		}
	}
	return ""
}

func (a *analysis) daysNote() string {
	if a.logSources == 0 {
		return ", and **no log files** were found"
	}
	if a.minDays >= 0 {
		if a.maxDays < 1 {
			return "; the logs cover under a day"
		}
		return fmt.Sprintf("; the logs cover about %.0f–%.0f days", a.minDays, a.maxDays)
	}
	return ""
}

func (a *analysis) limitSentence() string {
	var s []string
	if len(a.missing) > 0 {
		s = append(s, fmt.Sprintf("%s were missing", plural(len(a.missing), "evidence source", "evidence sources")))
	}
	if a.minDays >= 0 && a.minDays < 7 {
		s = append(s, "some logs hold under 7 days of history")
	}
	if a.logSources == 0 {
		s = append(s, "no log files were found")
	}
	if len(s) == 0 {
		return "Some evidence sources were short or missing."
	}
	return strings.ToUpper(s[0][:1]) + s[0][1:] + joinRest(s[1:]) + ", so an attack outside what the bundle holds cannot be ruled out."
}

func joinRest(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return "; " + strings.Join(s, "; ")
}

// themeBullets: one plain-language line per attack stage that has findings at SUSPECT or above.
func (a *analysis) themeBullets() []string {
	byPhase := map[string]int{}
	for _, r := range a.list {
		if r.Sev >= Suspect {
			byPhase[playbookFor(r.ID).Phase]++
		}
	}
	say := map[string]string{
		phExec:    "**Payloads or execution evidence:** files, processes or webshell code associated with the known attacks.",
		phPersist: "**Persistence or admin changes:** unexpected admin accounts, settings or startup entries.",
		phTheft:   "**Data or credential theft:** signs the configuration or keys were taken.",
		phAttempt: "**Attack attempts in the logs:** injected commands or exploit strings.",
		phContext: "**Cleanup or context:** signs that evidence may have been removed.",
	}
	var out []string
	for _, p := range phaseOrder {
		if byPhase[p] > 0 {
			out = append(out, fmt.Sprintf("%s (%s).", strings.TrimSuffix(say[p], "."), plural(byPhase[p], "finding type", "finding types")))
		}
	}
	return out
}

func (a *analysis) decisions() []string {
	var d []string
	if a.groups[Compromise] > 0 {
		d = append(d, "**Authorise incident response now.** Do not reboot or upgrade before evidence is captured; plan a rebuild and rotation of keys, passwords and certificates.")
	} else if a.groups[Suspect] > 0 {
		d = append(d, "**Authorise a focused investigation** of the suspect items (see the investigator summary) before deciding the appliance is clean.")
	}
	if a.buildKnown && a.buildVuln {
		d = append(d, "**Patch** to the fixed build for this release. An upgrade alone does not remove an implant that is already present.")
	} else if a.buildKnown && a.samlGap && a.has("conf-saml") {
		d = append(d, "**Patch for CVE-2026-88779** (SAML crash vulnerability) on appliances that use SAML.")
	}
	if a.has("cli-failed-nitro-login") {
		d = append(d, "**Restrict the management interface** to admin networks; failed logins from public addresses suggest it is reachable from the internet.")
	}
	if a.gaps > 0 {
		d = append(d, "**Obtain additional logs** (firewall, proxy, SIEM, older archives) for the period this bundle does not cover.")
	}
	d = append(d, "**Run the official Citrix IoC scan** as well; this tool only knows the community-published indicators.")
	return d
}

// ---------------------------------------------------------------------------------------------------

func (a *analysis) investigator(perPhase int) string {
	var b strings.Builder
	w := func(f string, args ...any) { fmt.Fprintf(&b, f+"\n", args...) }
	head, _ := a.headline()
	w("# Investigator summary")
	w("")
	w("*Result:* **%s** · *Findings:* %d compromise, %d suspect, %d targeted, %d check, %d lead", head,
		a.groups[Compromise], a.groups[Suspect], a.groups[Targeted], a.groups[Check], a.groups[Lead])
	w("*Basis:* up to %d sample lines per rule per file; the full counts are in the report. Missing evidence is not shown as absent.", a.doc.Stats.MaxLines)
	w("")
	w("## 1. Scope and coverage")
	w("")
	w("%d files, %.0f MB scanned. Evidence sources found: **%d of %d**.", a.doc.Stats.Files, float64(a.doc.Stats.Bytes)/1048576, a.srcFound, a.srcTotal)
	var logs []string
	for _, c := range a.doc.Coverage {
		if c.Found && isTimedKey(c.Key) {
			d := "no timestamps"
			if c.Days > 0 {
				d = fmt.Sprintf("~%.0f d", c.Days)
			} else if c.Span != "" {
				d = "<1 d"
			}
			logs = append(logs, fmt.Sprintf("%s (%s)", c.Source, d))
		}
	}
	if len(logs) > 0 {
		w("- **Logs present:** %s.", strings.Join(logs, ", "))
	}
	if len(a.missing) > 0 {
		m := a.missing
		if len(m) > 6 {
			m = append(append([]string{}, m[:6]...), fmt.Sprintf("+%d more", len(a.missing)-6))
		}
		w("- **Not in the bundle (cannot be assessed):** %s.", strings.Join(m, "; "))
	}
	w("")
	w("## 2. Timeline and the fix")
	w("")
	switch {
	case a.dated == 0:
		w("No dated attack lines were available (config and file findings carry no time). Establish the build install date from `ns.log` upgrade entries or change records.")
	case a.fix == nil:
		w("Attack-related lines run from **%s** to **%s**%s. Run `nsioc summarize -fixdate \"YYYY-MM-DD HH:MM\"` with the time the fixed build started running to split before and after.", when(a.first), when(a.last), a.yearNote())
		w("Remember: an attempt **before** the fix may have run; one **after** probably did not, except from 2 Oct 2026 on builds without the CVE-2026-88779 fix.")
	default:
		w("Fix running since **%s**. Dated attack lines: **%d before**, **%d after** (%d undated). Lines before the fix may have run; lines after probably did not, except from 2 Oct 2026 on builds without the CVE-2026-88779 fix.", when(*a.fix), a.before, a.after, a.undated)
	}
	if a.fix != nil && a.before == 0 && a.dated > 0 {
		w("All dated attack lines are after the fix. Check that the logs reach back before it: if not, the earlier period cannot be seen.")
	}
	w("")
	w("## 3. Findings by stage and how to tell if it worked")
	w("")
	for _, ph := range phaseOrder {
		var rs []*ruleAgg
		extra := 0
		for _, r := range a.list {
			if playbookFor(r.ID).Phase != ph || r.Sev < Check {
				continue
			}
			if len(rs) < perPhase {
				rs = append(rs, r)
			} else {
				extra++
			}
		}
		if len(rs) == 0 {
			continue
		}
		w("")
		w("**%s**", phaseTitle[ph])
		for _, r := range rs {
			pb := playbookFor(r.ID)
			where := short(r.SamplePath, 48)
			if r.SampleLine > 0 {
				where += fmt.Sprintf(":%d", r.SampleLine)
			}
			n := ""
			if len(r.Distinct) > 1 {
				n = fmt.Sprintf(", %d distinct", len(r.Distinct))
			}
			w("- **%s** `%s`, %s%s. e.g. `%s`", r.Sev, r.ID, plural(r.Total, "match", "matches"), n, where)
			w("  *How to tell:* %s", pb.Success)
			w("  *Next:* %s", pb.Next)
		}
		if extra > 0 {
			w("- ...and %s in this stage; see the report.", plural(extra, "more finding type", "more finding types"))
		}
	}
	w("")
	w("## 4. Correlations")
	w("")
	cs := a.correlations()
	if len(cs) == 0 {
		w("No cross-finding patterns were triggered. That is not evidence of absence; see section 1.")
	}
	for _, c := range cs {
		w("- %s", c)
	}
	w("")
	w("## 5. Next steps")
	w("")
	for i, s := range a.nextSteps() {
		w("%d. %s", i+1, s)
	}
	return b.String()
}

func (a *analysis) correlations() []string {
	var c []string
	inj := a.total("log-pitboss-injection", "log-pitboss-generic")
	artefacts := a.has("known-malicious-hash", "artefact-name", "ps-payload", "setuid-sh", "file-nsmon", "file-payload-dropped", "file-webshell-hidden", "file-exploit-marker", "file-saml-kit", "web-php-code")
	switch {
	case inj > 0 && artefacts:
		c = append(c, "**Injected commands in logs AND a payload artefact present:** execution is likely. Match the artefact's time to the injection time.")
	case inj > 0:
		c = append(c, fmt.Sprintf("**%s injected-command lines but no payload artefact in this bundle:** the bundle cannot show whether they ran; check the appliance filesystem and outbound logs.", plural(inj, "line", "line")))
	}
	if a.has("http-vpn-c-200") {
		c = append(c, "**`/vpn/c` returned 200:** the configuration archive was likely downloaded; treat ns.conf secrets and keys as exposed.")
	}
	if a.atkTotal > 0 {
		c = append(c, fmt.Sprintf("**Known attacker IPs:** %d of %d sampled HTTP lines were answered with 200 (sample only; check the paths requested).", a.atkOK, a.atkTotal))
	}
	if a.has("conf-sec-monitor", "conf-epa-no-auth", "cli-epa-no-auth", "admin-persistence-script") {
		c = append(c, "**Attacker-created admin access indicated** (backdoor user or EPA disabled). Date it from older saved configs and the CLI audit log.")
	}
	if a.buildKnown && a.buildVuln && (inj > 0 || a.has("log-shell-injection", "ua-base64-index", "http-login-payload")) {
		c = append(c, fmt.Sprintf("**Attack attempts against a vulnerable build (%s):** the exposure window matters; establish how long this build was running.", a.buildText))
	}
	if a.has("nsaaad-crash") && a.has("conf-saml") && a.samlGap {
		c = append(c, "**SAML configured, no SAML fix, nsaaad crashes present:** consistent with the CVE-2026-88779 attack.")
	}
	if a.has("cron-wipe", "hist-kill-snmpd") {
		c = append(c, "**Cleanup indicators:** logs may be incomplete; obtain external logs.")
	}
	if a.has("cli-failed-nitro-login") {
		c = append(c, "**Management interface exposed:** failed logins from public addresses; the reported attack begins this way.")
	}
	return c
}

func (a *analysis) nextSteps() []string {
	var s []string
	if a.groups[Compromise] > 0 || a.groups[Suspect] > 0 {
		s = append(s, "**Preserve first:** this report, the bundle, `/var/log` and any flagged files; capture memory or a VM snapshot. Do not reboot or upgrade yet.")
	}
	top := 0
	var starts []string
	for _, r := range a.list {
		if r.Sev >= Suspect && top < 3 {
			starts = append(starts, fmt.Sprintf("`%s` (%s)", r.ID, short(r.SamplePath, 40)))
			top++
		}
	}
	if len(starts) > 0 {
		s = append(s, "**Open these first:** "+strings.Join(starts, "; ")+".")
	}
	s = append(s, "**Date the activity:** compare the attack lines with when the fixed build started (`-fixdate`) and with the log window in section 1.")
	if a.groups[Compromise] > 0 {
		s = append(s, "**Check the HA peer** (file sync copies webshells), then isolate or fail over, rebuild rather than clean, and rotate **all** secrets incl. the key-encryption key, plus certificates.")
	}
	if a.has("http-vpn-c-200", "hist-key-theft", "file-config-staging") {
		s = append(s, "**Treat secrets as exposed** (config or keys likely taken): rotate keys, passwords, LDAP bind and API credentials, and revoke certificates.")
	}
	if len(a.missing) > 0 || a.gaps > 0 {
		s = append(s, "**Close the evidence gaps:** collect firewall, proxy, SIEM and archived logs for the period not covered; re-run on a fuller bundle.")
	}
	s = append(s, "**Run the official Citrix IoC scan** on the appliance and bring in Citrix Support; this tool only knows community-published indicators.")
	return s
}
