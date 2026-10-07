package main

// -each: a folder that holds many bundles (UAC collections, one subfolder or archive each). Every bundle is
// scanned with its own Scanner so findings never mix between appliances; the result is one report per bundle
// plus a summary table (CSV and on screen).

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

type eachRow struct {
	Name                   string
	Files                  int64
	Worst                  Severity
	Counts                 map[Severity]int
	CronCfg, LogIOC, Other int // matching lines, not result groups
	CronFile               string
	State                  string
	Runs                   int
	Err                    string
}

func runEach(dir, outDir, csvPath, iocFile string, maxPer, workers int, verbose bool, floor Severity) int {
	root, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	if outDir == "" {
		outDir = "nsioc_reports"
	}
	if csvPath == "" {
		csvPath = "nsioc_each.csv"
	}
	absOut, _ := filepath.Abs(outDir)
	if within(root, absOut) {
		fmt.Fprintf(os.Stderr, "-out %q is inside the scanned folder; write reports elsewhere so the evidence is not changed\n", outDir)
		return 3
	}
	if err := os.MkdirAll(absOut, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	if p, _ := filepath.Abs(csvPath); within(root, p) {
		fmt.Fprintf(os.Stderr, "-csv %q is inside the scanned folder\n", csvPath)
		return 3
	}

	var rows []*eachRow
	used := map[string]bool{}
	for _, e := range entries {
		full := filepath.Join(root, e.Name())
		fi, err := os.Lstat(full)
		if err != nil || !(fi.IsDir() || fi.Mode().IsRegular()) { // symlinks and special files are never opened
			continue
		}
		row := &eachRow{Name: e.Name(), Counts: map[Severity]int{}}
		rows = append(rows, row)
		fmt.Fprintf(os.Stderr, "[%d] scanning %s\n", len(rows), e.Name())

		sc := NewScanner(maxPer)
		if iocFile != "" {
			if _, err := sc.LoadIOCFile(iocFile); err != nil {
				row.Err = err.Error()
				continue
			}
		}
		start := time.Now()
		skipped, err := scanTarget(sc, full, fi, workers, verbose)
		if err != nil {
			row.Err = err.Error()
			continue
		}
		findings := sc.sorted()
		row.Files = sc.files
		for _, a := range findings {
			row.Counts[a.Sev]++
			if a.Sev > row.Worst {
				row.Worst = a.Sev
			}
			switch a.ID {
			case "cron-ioc-config":
				row.CronCfg += a.Total
				if row.CronFile == "" {
					row.CronFile = a.File
				}
			case "ioc-log":
				row.LogIOC += a.Total
			case "ioc-other":
				row.Other += a.Total
			}
		}

		cv := sc.cronVerdict(findings, true)
		row.State, row.Runs = cv.State, cv.Runs

		base := unsafeName.ReplaceAllString(e.Name(), "_")
		for n := 2; used[base]; n++ {
			base = fmt.Sprintf("%s_%d", unsafeName.ReplaceAllString(e.Name(), "_"), n)
		}
		used[base] = true
		hdr := fmt.Sprintf("nsioc %s: searched %s\n", version, full)
		stats := fmt.Sprintf("%d files (%d archives unpacked in memory, %d non-regular skipped), %.1f MB, %d lines, %s\n",
			sc.files, sc.archives, skipped, float64(sc.bytes)/1048576, sc.lines, time.Since(start).Round(time.Millisecond))
		rep := render(hdr, stats, findings, sc.warnings, sc.cov, sc.unread, floor, true) + cv.Text
		if err := writeReport(filepath.Join(absOut, base+".txt"), []byte(rep)); err != nil {
			row.Err = err.Error()
		}
	}

	// Confirmed cron runs first, then by worst severity, so the bundles that need a look are at the top.
	rank := map[string]int{cronConfirmed: 6, cronRunNoEntry: 5, cronNoLog: 4, cronNotSeen: 3, cronAttempt: 2, cronNone: 1}
	sort.SliceStable(rows, func(i, j int) bool {
		if rank[rows[i].State] != rank[rows[j].State] {
			return rank[rows[i].State] > rank[rows[j].State]
		}
		if rows[i].Worst != rows[j].Worst {
			return rows[i].Worst > rows[j].Worst
		}
		return rows[i].CronCfg+rows[i].LogIOC > rows[j].CronCfg+rows[j].LogIOC
	})

	fmt.Printf("\n%-34s %-24s %-10s %5s %7s %6s\n", "BUNDLE", "CRON STATE", "WORST", "RUNS", "CONFIG", "LOGS")
	worst := Severity(0)
	for _, r := range rows {
		w := "-"
		if r.Worst > 0 {
			w = r.Worst.String()
		}
		st := r.State
		if r.Err != "" {
			w, st = "ERROR", "ERROR"
		}
		name := r.Name
		if len(name) > 34 {
			name = name[:31] + "..."
		}
		fmt.Printf("%-34s %-24s %-10s %5d %7d %6d\n", name, st, w, r.Runs, r.CronCfg, r.LogIOC)
		if r.Worst > worst {
			worst = r.Worst
		}
	}
	fmt.Println("\nRUNS = cron run lines naming your indicator; CONFIG = crontab / startup lines naming it; LOGS = ns.log / messages / history lines.")
	fmt.Println("Only CONFIRMED-RUNNING shows a cron task executing the command; open that bundle's report for the CRON VERDICT.")

	var recs [][]string
	recs = append(recs, []string{"bundle", "worst", "files", "compromise", "suspect", "targeted", "check", "lead", "info", "cron_state", "cron_run_lines", "cron_config_lines", "log_ioc_lines", "other_ioc_lines", "first_cron_config_file", "error"})
	for _, r := range rows {
		w := ""
		if r.Worst > 0 {
			w = r.Worst.String()
		}
		recs = append(recs, []string{csvSafe(r.Name), w, fmt.Sprint(r.Files),
			fmt.Sprint(r.Counts[Compromise]), fmt.Sprint(r.Counts[Suspect]), fmt.Sprint(r.Counts[Targeted]),
			fmt.Sprint(r.Counts[Check]), fmt.Sprint(r.Counts[Lead]), fmt.Sprint(r.Counts[Info]),
			r.State, fmt.Sprint(r.Runs), fmt.Sprint(r.CronCfg), fmt.Sprint(r.LogIOC), fmt.Sprint(r.Other), csvSafe(r.CronFile), csvSafe(r.Err)})
	}
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	w.WriteAll(recs)
	if err := writeReport(csvPath, []byte(sb.String())); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	fmt.Printf("\n%d bundle(s). Reports: %s   Summary table: %s\n", len(rows), absOut, csvPath)
	switch {
	case worst >= Suspect:
		return 2
	case worst >= Check:
		return 1
	}
	return 0
}

// csvSafe stops a spreadsheet from running a cell as a formula (names come from the evidence).
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
