// nsioc searches Citrix NetScaler technical support bundles ("show techsupport") for the
// public indicators of compromise of CVE-2026-88771 / 88772 / 88779 collected in
// https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker (script v1.12).
//
// Standard library only. Read-only: bundles are streamed, archives (.tar, .gz, .tgz,
// .bz2, nested) are unpacked in memory and nothing is written except the optional report.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const version = "1.0"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "summarize" {
		os.Exit(runSummarize(os.Args[2:]))
	}
	var (
		dir      = flag.String("dir", "", "directory (or single file / archive) to search; may also be given as the first argument")
		out      = flag.String("out", "", "also write the report to this file (attacker text defanged)")
		jsonOut  = flag.String("json", "", "also write the findings as JSON to this file")
		defang   = flag.Bool("defang", false, "defang attacker text on screen as well (always on in the --out file)")
		maxPer   = flag.Int("max-lines", 5, "matching lines shown per rule per file")
		minSev   = flag.String("min", "check", "lowest severity to show: info, lead, check, targeted, suspect, compromise")
		workers  = flag.Int("workers", runtime.NumCPU(), "files scanned in parallel")
		listRule = flag.Bool("rules", false, "list the loaded rules and indicator counts, then exit")
		iocFile  = flag.String("ioc-file", "", "file of your own indicators (one per line, # comments; ${IFS} also matches its disguises; re:<regex> for a regex)")
		verbose  = flag.Bool("v", false, "print every file as it is scanned")
		inv      = flag.Bool("inventory", false, "print what the bundle contains (structure only, no file contents) instead of findings; use it to check classification")
		redact   = flag.Bool("redact", true, "with -inventory: mask IPs, long numbers and dates in paths so the output is safe to read out or share")
		maps     mapFlag
	)
	flag.Var(&maps, "map", "override how a file type is recognised by name: key=regex (repeatable, regex matched against the lower-cased path; see -rules for keys)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "nsioc %s - search Citrix technical support bundles for CVE-2026-88771/88772/88779 IOCs\n\n", version)
		fmt.Fprintf(os.Stderr, "usage: nsioc [flags] <directory>\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nexit status: 0 nothing above LEAD, 1 CHECK/TARGETED findings, 2 SUSPECT/COMPROMISE findings, 3 error\n")
	}
	flag.Parse()
	if *dir == "" && flag.NArg() > 0 {
		*dir = flag.Arg(0)
	}

	for _, m := range maps {
		k, rx, ok := strings.Cut(m, "=")
		i, known := covIdx[k]
		if !ok || !known {
			fmt.Fprintf(os.Stderr, "-map %q: expected key=regex with a key from -rules\n", m)
			os.Exit(3)
		}
		c, err := regexp.Compile(rx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "-map %q: %v\n", m, err)
			os.Exit(3)
		}
		covRe[i] = c
	}
	sc := NewScanner(*maxPer)
	if *iocFile != "" {
		n, err := sc.LoadIOCFile(*iocFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "-ioc-file:", err)
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "loaded %d indicator(s) from %s\n", n, *iocFile)
	}
	if *listRule {
		printRules(sc)
		return
	}
	if *dir == "" {
		flag.Usage()
		os.Exit(3)
	}
	floor, ok := parseSev(*minSev)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown severity %q\n", *minSev)
		os.Exit(3)
	}
	root, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	st, err := os.Stat(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}

	outPath, err := checkOutput("-out", *out, root, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	jsonPath, err := checkOutput("-json", *jsonOut, root, outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}

	// All reads go through an os.Root opened on the scanned folder: a path that leaves it (".." or a
	// symlink pointing outside) is refused by the Go runtime itself, with no check-then-open gap.
	scanDir, only := root, "" // only: the single file name when a file (not a folder) was given
	if !st.IsDir() {
		scanDir, only = filepath.Dir(root), filepath.Base(root)
	}
	rootFS, err := os.OpenRoot(scanDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	defer rootFS.Close()

	start := time.Now()
	jobs := make(chan string, 64)
	var wg sync.WaitGroup
	var skipped int64
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rel := range jobs { // rel is slash-separated and relative to scanDir
				if *verbose {
					fmt.Fprintln(os.Stderr, "scanning", rel)
				}
				f, err := openRegular(rootFS, rel)
				if err != nil {
					sc.warn("%s: %v", rel, err)
					continue
				}
				sc.ScanReader(rel, f)
				f.Close()
			}
		}()
	}
	if st.IsDir() {
		fs.WalkDir(rootFS.FS(), ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				sc.warn("%s: %v", p, err)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() { // symlinks, FIFOs, sockets, devices: never opened
				atomic.AddInt64(&skipped, 1)
				return nil
			}
			jobs <- p
			return nil
		})
	} else {
		jobs <- only
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(start)

	findings := sc.sorted()
	hdr := fmt.Sprintf("nsioc %s: searched %s\n", version, root)
	stats := fmt.Sprintf("%d files (%d archives unpacked in memory, %d non-regular skipped), %.1f MB, %d lines, %s\n",
		sc.files, sc.archives, skipped, float64(sc.bytes)/1048576, sc.lines, elapsed.Round(time.Millisecond))

	if *inv {
		text := renderInventory(hdr, stats, sc, *redact)
		fmt.Print(text)
		if outPath != "" {
			if err := writeReport(outPath, []byte(text)); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(3)
			}
		}
		return
	}
	screen := render(hdr, stats, findings, sc.warnings, sc.cov, sc.unread, floor, *defang)
	fmt.Print(screen)
	if outPath != "" {
		if err := writeReport(outPath, []byte(render(hdr, stats, findings, sc.warnings, sc.cov, sc.unread, floor, true))); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		}
	}
	if jsonPath != "" {
		if err := writeJSON(jsonPath, findings, sc, root); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		}
	}
	os.Exit(exitCode(findings))
}

func parseSev(s string) (Severity, bool) {
	for v := Info; v <= Compromise; v++ {
		if strings.EqualFold(v.String(), s) {
			return v, true
		}
	}
	return 0, false
}

func (s *Scanner) sorted() []*agg {
	r := append([]*agg(nil), s.results...)
	sort.Slice(r, func(i, j int) bool {
		if r[i].Sev != r[j].Sev {
			return r[i].Sev > r[j].Sev
		}
		if r[i].ID != r[j].ID {
			return r[i].ID < r[j].ID
		}
		if r[i].Desc != r[j].Desc {
			return r[i].Desc < r[j].Desc
		}
		return r[i].File < r[j].File
	})
	return r
}

func exitCode(f []*agg) int {
	code := 0
	for _, a := range f {
		switch {
		case a.Sev >= Suspect:
			return 2
		case a.Sev >= Check:
			code = 1
		}
	}
	return code
}

func defangText(s string) string {
	s = strings.NewReplacer("https:", "hxxps:", "http:", "hxxp:").Replace(s)
	return strings.Map(func(r rune) rune {
		switch r {
		case ';', '|', '&', '`', '$', '<', '>':
			return '_'
		}
		return r
	}, s)
}

func render(hdr, stats string, f []*agg, warns []string, cov []covStat, unread []string, floor Severity, defang bool) string {
	var b strings.Builder
	b.WriteString(hdr)
	b.WriteString(stats)
	b.WriteString("Indicators: github.com/ThomasPoppelgaard/netscaler-ctx697096-checker (v1.12). A clean result is NOT proof of no compromise:\n")
	b.WriteString("only published indicators are searched, and the bundle holds only what 'show techsupport' collects. Run the official Citrix IoC scan too.\n\n")

	covText, covGaps := renderCoverage(cov)
	b.WriteString(covText)
	if len(unread) > 0 {
		covGaps++
		b.WriteString(renderUnreadable(unread))
	}

	counts := map[Severity]int{}
	for _, a := range f {
		counts[a.Sev]++
	}
	var cur Severity
	var curKey string
	for _, a := range f {
		if a.Sev < floor {
			continue
		}
		if a.Sev != cur {
			cur = a.Sev
			curKey = ""
			fmt.Fprintf(&b, "\n=== %s (%d result group(s)) ===\n", cur, counts[cur])
		}
		if k := a.ID + "\x00" + a.Desc; k != curKey {
			curKey = k
			fmt.Fprintf(&b, "\n[%s] %s\n    source: %s\n", a.ID, a.Desc, a.Ref)
		}
		fmt.Fprintf(&b, "  %s", a.File)
		if a.Total > 1 {
			fmt.Fprintf(&b, "  (%d matches)", a.Total)
		}
		b.WriteString("\n")
		for _, h := range a.Lines {
			t := h.Text
			if defang {
				t = defangText(t)
			}
			if h.N > 0 {
				fmt.Fprintf(&b, "      line %d: %s\n", h.N, t)
			} else {
				fmt.Fprintf(&b, "      %s\n", t)
			}
		}
		if a.Total > len(a.Lines) {
			fmt.Fprintf(&b, "      ... and %d more\n", a.Total-len(a.Lines))
		}
	}
	if len(warns) > 0 {
		b.WriteString("\n=== WARNINGS (files that could not be read completely) ===\n")
		for _, w := range warns {
			b.WriteString("  " + w + "\n")
		}
	}
	b.WriteString("\n=== SUMMARY ===\n")
	for v := Compromise; v >= Info; v-- {
		fmt.Fprintf(&b, "  %-10s %d\n", v, counts[v])
	}
	switch {
	case counts[Compromise] > 0:
		b.WriteString("\nVERDICT: COMPROMISE INDICATORS FOUND. Do not reboot or upgrade yet; preserve evidence and follow Citrix CTX694799.\n")
	case counts[Suspect] > 0:
		b.WriteString("\nVERDICT: SUSPECT items found - review each one.\n")
	case counts[Targeted] > 0:
		b.WriteString("\nVERDICT: attack traffic seen (targeted). Check whether it succeeded, and whether it came before or after the fix.\n")
	case counts[Check] > 0:
		b.WriteString("\nVERDICT: no known-bad indicators, but CHECK items need a human look.\n")
	default:
		b.WriteString("\nVERDICT: none of the published indicators were found in the sources this bundle contained.\n")
		if covGaps > 0 {
			fmt.Fprintf(&b, "         CAUTION: %d evidence source(s) are missing or short - see COVERAGE. This is not a clean bill of health.\n", covGaps)
		}
	}
	return b.String()
}

type jsonFinding struct {
	Severity string   `json:"severity"`
	Rule     string   `json:"rule"`
	Desc     string   `json:"description"`
	Source   string   `json:"source"`
	File     string   `json:"file"`
	Matches  int      `json:"matches"`
	Lines    []jsonLn `json:"lines,omitempty"`
}

type jsonLn struct {
	Line int    `json:"line,omitempty"`
	Time string `json:"time,omitempty"`
	Text string `json:"text"`
}

// reportDoc is the JSON report. schema 2 adds identification, run statistics and per-line timestamps;
// "nsioc summarize" reads it.
type reportDoc struct {
	Schema    int           `json:"schema"`
	Tool      string        `json:"tool"`
	Version   string        `json:"version"`
	Bundle    string        `json:"bundle"`
	Generated string        `json:"generated"`
	Stats     reportStats   `json:"stats"`
	Coverage  []jsonCov     `json:"coverage"`
	Findings  []jsonFinding `json:"findings"`
	// Unreadable lists compressed files in a format nsioc cannot open (xz, zstd, ...): their content was NOT searched.
	Unreadable []string `json:"unreadable,omitempty"`
}

type reportStats struct {
	Files    int64 `json:"files"`
	Archives int64 `json:"archives"`
	Lines    int64 `json:"lines"`
	Bytes    int64 `json:"bytes"`
	MaxLines int   `json:"max_lines_per_rule_per_file"`
}

const reportSchema = 2

func writeJSON(path string, f []*agg, sc *Scanner, bundle string) error {
	out := make([]jsonFinding, 0, len(f))
	for _, a := range f {
		j := jsonFinding{Severity: a.Sev.String(), Rule: a.ID, Desc: a.Desc, Source: a.Ref, File: a.File, Matches: a.Total}
		for _, h := range a.Lines {
			j.Lines = append(j.Lines, jsonLn{h.N, h.Time, defangText(h.Text)})
		}
		out = append(out, j)
	}
	doc := reportDoc{
		Schema: reportSchema, Tool: "nsioc", Version: version, Bundle: bundle,
		Generated: time.Now().UTC().Format(time.RFC3339),
		Stats:     reportStats{sc.files, sc.archives, sc.lines, sc.bytes, sc.maxPer},
		Coverage:  coverJSON(sc.cov), Findings: out, Unreadable: sc.unread,
	}
	var buf bytes.Buffer
	if err := writeIndented(&buf, doc); err != nil {
		return err
	}
	return writeReport(path, buf.Bytes())
}

func writeIndented(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

func printRules(s *Scanner) {
	fmt.Printf("content rules : %d (incl. %d multi-pattern group parts)\n", len(rules), func() int {
		n := 0
		for _, r := range rules {
			if r.Group != "" {
				n++
			}
		}
		return n
	}())
	fmt.Printf("path rules    : %d\n", len(pathRules))
	fmt.Printf("attacker IPs  : %d\nscanner IPs   : %d\ndomains       : %d\nfile hashes   : %d\n", len(attackerIPs), len(scannerIPs), len(attackerDomains), len(knownHashes))
	fmt.Println()
	fmt.Println("source keys for -map key=regex:")
	for _, c := range covSources {
		kind := "type"
		if c.Loc {
			kind = "location"
		}
		fmt.Printf("  %-9s %-9s %s\n", c.Key, kind, c.Name)
	}
	fmt.Println()
	for _, r := range rules {
		if r.Group == "" {
			fmt.Printf("%-10s %-26s %s\n", r.Sev, r.ID, r.Desc)
		}
	}
	for _, g := range groupRules {
		fmt.Printf("%-10s %-26s %s\n", g.Sev, g.ID, g.Desc)
	}
	for _, p := range pathRules {
		fmt.Printf("%-10s %-26s %s (file name)\n", p.Sev, p.ID, p.Desc)
	}
}

type jsonCov struct {
	Source  string  `json:"source"`
	Key     string  `json:"key"`
	Loc     bool    `json:"location,omitempty"`
	Found   bool    `json:"found"`
	Files   int     `json:"files"`
	Lines   int64   `json:"lines"`
	Span    string  `json:"time_span,omitempty"`
	Days    float64 `json:"days,omitempty"`
	Enables string  `json:"enables"`
}

func coverJSON(cov []covStat) []jsonCov {
	out := make([]jsonCov, 0, len(covSources))
	for i, src := range covSources {
		c := &cov[i]
		days, _ := spanDays(c)
		out = append(out, jsonCov{src.Name, src.Key, src.Loc, c.Files > 0, c.Files, c.Lines, fmtSpan(c), days, src.Enables})
	}
	return out
}

type mapFlag []string

func (m *mapFlag) String() string     { return strings.Join(*m, ",") }
func (m *mapFlag) Set(v string) error { *m = append(*m, v); return nil }

// renderCoverage lists which evidence sources the bundle held and how far back the logs reach.
// It returns the text and the number of gaps (missing key sources, logs with under 7 days).
func renderCoverage(cov []covStat) (string, int) {
	var b strings.Builder
	gaps := 0
	b.WriteString("=== COVERAGE: evidence sources found in this bundle ===\n")
	for i, src := range covSources {
		c := &cov[i]
		if c.Files == 0 {
			switch {
			case src.Loc:
				fmt.Fprintf(&b, "  [ ] %-44s not present (normal for a support bundle) - cannot see: %s\n", src.Name, src.Enables)
			default:
				fmt.Fprintf(&b, "  [ ] %-44s NOT FOUND - cannot see: %s\n", src.Name, src.Enables)
				if src.Timed || src.Key == "conf" {
					gaps++
				}
			}
			continue
		}
		fmt.Fprintf(&b, "  [x] %-44s %d file(s)", src.Name, c.Files)
		if c.Lines > 0 {
			fmt.Fprintf(&b, ", %d lines", c.Lines)
		}
		if c.ByContent > 0 {
			fmt.Fprintf(&b, " (%d recognised by content, name did not match)", c.ByContent)
		}
		b.WriteString("\n")
		if src.Timed {
			if sp := fmtSpan(c); sp != "" {
				days, ok := spanDays(c)
				fmt.Fprintf(&b, "        time span: %s", sp)
				if ok {
					fmt.Fprintf(&b, " (~%.1f days)", days)
				}
				b.WriteString("\n")
				if ok && days < 7 {
					b.WriteString("        WARNING: under 7 days of history - attacks before this window cannot be seen\n")
					gaps++
				}
			} else {
				b.WriteString("        WARNING: no timestamps recognised - cannot tell how far back this log reaches\n")
				gaps++
			}
			if c.Files == 1 {
				b.WriteString("        note: single file, no rotated copies in the bundle - older history may exist on the appliance\n")
			}
		}
	}
	b.WriteString("\n")
	return b.String(), gaps
}

var (
	rdIP  = regexp.MustCompile(`[0-9]{1,3}(\.[0-9]{1,3}){3}`)
	rdNum = regexp.MustCompile(`[0-9]{4,}`)
)

func redactPath(p string) string {
	return rdNum.ReplaceAllString(rdIP.ReplaceAllString(p, "<ip>"), "<n>")
}

// renderInventory describes what the bundle holds, structure only: names, sizes, classes and the
// shape of unrecognised files' first lines. No file contents are printed.
func renderInventory(hdr, stats string, sc *Scanner, redact bool) string {
	rp := func(p string) string {
		if redact {
			return redactPath(p)
		}
		return p
	}
	var b strings.Builder
	b.WriteString(hdr + stats)
	if redact {
		b.WriteString("(paths redacted: IPs -> <ip>, numbers of 4+ digits -> <n>; use -redact=false to see them)\n")
	}
	b.WriteString("\n")
	cov, _ := renderCoverage(sc.cov)
	b.WriteString(cov)
	if len(sc.unread) > 0 {
		b.WriteString(renderUnreadable(sc.unread))
	}

	inv := append([]invEntry(nil), sc.inv...)
	sort.Slice(inv, func(i, j int) bool { return inv[i].Path < inv[j].Path })

	// directories
	dirs := map[string]int{}
	exts := map[string]int{}
	for _, e := range inv {
		d := filepath.ToSlash(filepath.Dir(rp(e.Path)))
		dirs[d]++
		x := strings.ToLower(filepath.Ext(e.Path))
		if x == "" {
			x = "(none)"
		}
		exts[x]++
	}
	keys := make([]string, 0, len(dirs))
	for d := range dirs {
		keys = append(keys, d)
	}
	sort.Strings(keys)
	grouped := map[string]int{}
	if len(keys) > 80 {
		for _, d := range keys {
			parts := strings.Split(d, "/")
			if len(parts) > 3 {
				parts = parts[:3]
			}
			grouped[strings.Join(parts, "/")+"/..."] += dirs[d]
		}
		dirs = grouped
		keys = keys[:0]
		for d := range dirs {
			keys = append(keys, d)
		}
		sort.Strings(keys)
		b.WriteString("=== DIRECTORIES (grouped to 3 levels, more than 80 folders) ===\n")
	} else {
		b.WriteString("=== DIRECTORIES ===\n")
	}
	for _, d := range keys {
		fmt.Fprintf(&b, "  %5d  %s\n", dirs[d], d)
	}

	b.WriteString("\n=== FILE EXTENSIONS (archive suffixes already removed) ===\n")
	type kv struct {
		K string
		V int
	}
	var ev []kv
	for k, v := range exts {
		ev = append(ev, kv{k, v})
	}
	sort.Slice(ev, func(i, j int) bool { return ev[i].V > ev[j].V || (ev[i].V == ev[j].V && ev[i].K < ev[j].K) })
	for i, e := range ev {
		if i >= 15 {
			break
		}
		fmt.Fprintf(&b, "  %5d  %s\n", e.V, e.K)
	}

	b.WriteString("\n=== CLASSIFIED FILES (which source each file was counted as) ===\n")
	n := 0
	for _, e := range inv {
		if e.Class < 0 {
			continue
		}
		how := "name"
		if e.ByContent {
			how = "content"
		}
		if n < 150 {
			fmt.Fprintf(&b, "  %-9s %-40s %s\n", how, covSources[e.Class].Key, rp(e.Path))
		}
		n++
	}
	if n > 150 {
		fmt.Fprintf(&b, "  ... and %d more\n", n-150)
	}

	var un []invEntry
	for _, e := range inv {
		if e.Class < 0 {
			un = append(un, e)
		}
	}
	sort.Slice(un, func(i, j int) bool { return un[i].Size > un[j].Size })
	fmt.Fprintf(&b, "\n=== UNCLASSIFIED FILES: %d (largest first; searched with the general rules only) ===\n", len(un))
	b.WriteString("  If one of these is really a log or config, the 'first line shape' shows its format (a/A = letters, 9 = digits).\n")
	b.WriteString("  Then use  -map key=regex  to tell nsioc what it is, or describe the shape so the patterns can be extended.\n")
	for i, e := range un {
		if i >= 120 {
			fmt.Fprintf(&b, "  ... and %d more\n", len(un)-i)
			break
		}
		kind := "text"
		if e.Binary {
			kind = "binary"
		}
		fmt.Fprintf(&b, "  %10d B  %-6s %s\n", e.Size, kind, rp(e.Path))
		if e.Shape != "" {
			fmt.Fprintf(&b, "               first line shape: %s\n", e.Shape)
		}
	}
	return b.String()
}

// within reports whether path is dir itself or lies below it. Both must already be absolute and symlink-resolved.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolve returns the absolute path with symlinks resolved in every existing parent directory.
// The final element may not exist yet (an output file).
func resolve(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}

// checkOutput validates a report path before the scan starts. It refuses a path inside the scanned
// bundle (writing there would change the evidence and get rescanned), a path that is an existing
// symlink or non-regular file, and the same file as another output. An empty path means "not requested".
func checkOutput(flagName, p, root, other string) (string, error) {
	if p == "" {
		return "", nil
	}
	target, err := resolve(p)
	if err != nil {
		return "", fmt.Errorf("%s %q: %v", flagName, p, err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	if st, err := os.Stat(realRoot); err == nil && !st.IsDir() {
		realRoot = filepath.Dir(realRoot) // single-file scan: the evidence file's folder is not off limits, the file itself is
		if target == realRootFile(root) {
			return "", fmt.Errorf("%s %q is the input file", flagName, p)
		}
	} else if within(realRoot, target) {
		return "", fmt.Errorf("%s %q is inside the scanned directory; write the report elsewhere so the evidence is not changed", flagName, p)
	}
	if fi, err := os.Lstat(target); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return "", fmt.Errorf("%s %q exists and is not a regular file (symlink or special file); refusing to write to it", flagName, p)
		}
	}
	if other != "" && target == other {
		return "", fmt.Errorf("%s and -out point at the same file", flagName)
	}
	return target, nil
}

func realRootFile(root string) string {
	if r, err := filepath.EvalSymlinks(root); err == nil {
		return r
	}
	return root
}

// writeReport writes data to a path already validated by checkOutput. The file is created through an
// os.Root on its folder, so a symlink in the final path component cannot redirect the write elsewhere,
// and the opened file is re-checked to be a regular file.
func writeReport(path string, data []byte) error {
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	fh, err := dir.OpenFile(filepath.Base(path), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	if fi, err := fh.Stat(); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if _, err := fh.Write(data); err != nil {
		return err
	}
	return fh.Close()
}

// openRegular opens rel (relative to the scanned folder) through the os.Root, which refuses anything that
// would resolve outside it, and then refuses anything that is not a regular file at open time (for example
// a file replaced by a FIFO or device after the directory walk).
func openRegular(r *os.Root, rel string) (*os.File, error) {
	f, err := r.Open(filepath.FromSlash(rel))
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("not a regular file, skipped")
	}
	return f, nil
}

// renderUnreadable is shown right under COVERAGE: these files were not searched at all.
func renderUnreadable(unread []string) string {
	u := append([]string(nil), unread...)
	sort.Strings(u)
	var b strings.Builder
	fmt.Fprintf(&b, "!!! %d FILE(S) COULD NOT BE READ (compressed with a format nsioc cannot open) - their content was NOT searched:\n", len(u))
	for i, x := range u {
		if i >= 25 {
			fmt.Fprintf(&b, "      ... and %d more\n", len(u)-i)
			break
		}
		fmt.Fprintf(&b, "      %s\n", x)
	}
	b.WriteString("    Decompress them first (for example  xz -d  or  zstd -d  on a copy), then scan again. Until then, a clean result\n")
	b.WriteString("    does not cover them. Logs are often the oldest rotated ones, so the missing history may be the important part.\n\n")
	return b.String()
}
