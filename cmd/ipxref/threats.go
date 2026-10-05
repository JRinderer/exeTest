package main

// Threat IPs: addresses on the published attacker / scanner lists that nsioc uses (iocdata.go is generated
// from the same source, ThomasPoppelgaard/netscaler-ctx697096-checker v1.12). Unlike the shared-IP list, a threat
// IP is reported even if it appears in a single bundle.

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	catAttacker = "known attacker"
	catSpray    = "password-spray range"
	catScanner  = "scanner (lead)"
)

var catRank = map[string]int{catAttacker: 0, catSpray: 1, catScanner: 2}

type threatDB struct {
	attackers    map[uint32]string
	scanners     map[uint32]bool
	spray        []uint32 // /24 prefixes (address >> 8)
	sprayHost    uint32
	withScanners bool
}

func newThreatDB(withScanners bool) *threatDB {
	t := &threatDB{attackers: map[uint32]string{}, scanners: map[uint32]bool{}, withScanners: withScanners}
	for _, a := range attackerIPs {
		if v, ok := parseQuad([]byte(a.IP)); ok {
			t.attackers[v] = a.Source
		}
	}
	for _, a := range scannerIPs {
		if v, ok := parseQuad([]byte(a)); ok {
			t.scanners[v] = true
		}
	}
	// password-spray source ranges seen against a Gateway (Gotham Technology Group)
	for _, p := range []string{"138.226.239.0", "185.136.15.0", "77.91.71.0"} {
		if v, ok := parseQuad([]byte(p)); ok {
			t.spray = append(t.spray, v>>8)
		}
	}
	t.sprayHost, _ = parseQuad([]byte("93.152.219.115"))
	return t
}

func (t *threatDB) lookup(ip uint32) (cat, src string) {
	if s, ok := t.attackers[ip]; ok {
		return catAttacker, s
	}
	if ip == t.sprayHost {
		return catSpray, "Gotham Technology Group"
	}
	for _, p := range t.spray {
		if ip>>8 == p {
			return catSpray, "Gotham Technology Group"
		}
	}
	if t.withScanners && t.scanners[ip] {
		return catScanner, "GreyNoise-tagged scanner (hunting lead only)"
	}
	return "", ""
}

// threatEntry is one threat IP in one bundle.
type threatEntry struct {
	Bundle string
	B      int
	Row    *ipRow
	Seen   seen
}

// byBundle flattens the threat rows into per-bundle entries, attackers first, then most hits.
func byBundle(bundles []*bundle, r *result) map[int][]threatEntry {
	out := map[int][]threatEntry{}
	for _, row := range r.Threats {
		for _, sn := range row.Seen {
			out[sn.B] = append(out[sn.B], threatEntry{bundles[sn.B].Name, sn.B, row, sn})
		}
	}
	for b := range out {
		es := out[b]
		sort.Slice(es, func(i, j int) bool {
			ri, rj := catRank[es[i].Row.Threat], catRank[es[j].Row.Threat]
			if ri != rj {
				return ri < rj
			}
			if es[i].Seen.S.Hits != es[j].Seen.S.Hits {
				return es[i].Seen.S.Hits > es[j].Seen.S.Hits
			}
			return es[i].Row.IP < es[j].Row.IP
		})
		out[b] = es
	}
	return out
}

func (e threatEntry) dates(b *bundle) (first, last string) {
	if !e.Seen.R.OK {
		return "", ""
	}
	return e.Seen.R.Lo.Format("2 Jan 2006"), e.Seen.R.Hi.Format("2 Jan 2006")
}

func (e threatEntry) files(b *bundle) string {
	var f []string
	for i := 0; i < int(e.Seen.S.NEx); i++ {
		f = append(f, b.names[e.Seen.S.Ex[i]])
	}
	return strings.Join(f, ", ")
}

func countCats(r *result) (att, spray, scan int) {
	for _, row := range r.Threats {
		switch row.Threat {
		case catAttacker:
			att++
		case catSpray:
			spray++
		default:
			scan++
		}
	}
	return
}

func threatSummary(r *result, nBundles, withThreats int) string {
	att, spray, scan := countCats(r)
	var parts []string
	if att > 0 {
		parts = append(parts, fmt.Sprintf("%d known attacker", att))
	}
	if spray > 0 {
		parts = append(parts, fmt.Sprintf("%d password-spray range", spray))
	}
	if scan > 0 {
		parts = append(parts, fmt.Sprintf("%d scanner (lead only)", scan))
	}
	return fmt.Sprintf("%d threat IP%s found (%s), in %d of %d bundles.", len(r.Threats), pl(len(r.Threats)), strings.Join(parts, ", "), withThreats, nBundles)
}

// renderThreats is the section shown in the main report. It is capped per bundle; the export has everything.
func renderThreats(bundles []*bundle, r *result, exported bool) string {
	var b strings.Builder
	b.WriteString("KNOWN THREAT IPs (addresses on the published attacker lists nsioc uses)\n")
	b.WriteString("----------------------------------------------------------------------\n")
	if len(r.Threats) == 0 {
		b.WriteString("  None of the bundles contain an address from the published attacker or scanner lists.\n\n")
		return b.String()
	}
	bb := byBundle(bundles, r)
	with := len(bb)
	fmt.Fprintf(&b, "  %s\n", threatSummary(r, len(bundles), with))
	b.WriteString("  A threat IP is listed even if it appears in only one bundle. 'Lead' scanners are weak evidence.\n\n")
	const perBundle = 12
	for bi, bd := range bundles {
		es := bb[bi]
		if len(es) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s  (%d threat IP%s)\n", bd.Name, len(es), pl(len(es)))
		for i, e := range es {
			if i >= perBundle {
				fmt.Fprintf(&b, "      ... and %d more\n", len(es)-i)
				break
			}
			f, l := e.dates(bd)
			when := "no dated line"
			if f != "" {
				when = f
				if l != f {
					when += " to " + l
				}
			}
			hit := "hits"
			if e.Seen.S.Hits == 1 {
				hit = "hit "
			}
			fmt.Fprintf(&b, "      %-16s %-20s %7s %s   %s\n", ipString(e.Row.IP), e.Row.Threat, comma(e.Seen.S.Hits), hit, when)
		}
	}
	if exported {
		b.WriteString("\n  The complete list is in the -threats export file.\n")
	} else {
		b.WriteString("\n  Use  -threats threats.csv  (or threats.txt) to export the complete list.\n")
	}
	b.WriteString("\n")
	return b.String()
}

// renderThreatText is the plain-text export: by bundle, then by IP. No caps.
func renderThreatText(dir string, bundles []*bundle, r *result, withScanners bool) string {
	var b strings.Builder
	line := strings.Repeat("=", 78)
	fmt.Fprintf(&b, "%s\nTHREAT IPs FOUND IN EACH TECH SUPPORT BUNDLE\n%s\n", line, line)
	fmt.Fprintf(&b, "Folder searched: %s\nReport made    : %s   (ipxref %s)\n", dir, time.Now().Format("2 Jan 2006 15:04"), version)
	sc := "included as 'scanner (lead)'"
	if !withScanners {
		sc = "excluded (-no-scanners)"
	}
	fmt.Fprintf(&b, "Lists used     : published attacker IPs and password-spray ranges from the nsioc indicator set\n"+
		"                 (netscaler-ctx697096-checker v1.12); scanner IPs %s\n\n", sc)
	if len(r.Threats) == 0 {
		b.WriteString("No threat IPs were found in any bundle.\n")
		return b.String()
	}
	bb := byBundle(bundles, r)
	fmt.Fprintf(&b, "SUMMARY: %s\n", threatSummary(r, len(bundles), len(bb)))
	b.WriteString("Meaning: the address appears in the bundle's text files. It shows contact or reference, not that an attack\n")
	b.WriteString("succeeded. First/last seen come from the timestamps of the log lines that contain it.\n\n")

	fmt.Fprintf(&b, "%s\nBY BUNDLE\n%s\n", line, line)
	for bi, bd := range bundles {
		es := bb[bi]
		if len(es) == 0 {
			continue
		}
		att := 0
		for _, e := range es {
			if e.Row.Threat == catAttacker {
				att++
			}
		}
		fmt.Fprintf(&b, "\n%s   (%d threat IP%s, %d known attacker)\n", bd.Name, len(es), pl(len(es)), att)
		fmt.Fprintf(&b, "  %-16s  %-20s  %8s  %-12s  %-12s  %s\n", "IP address", "Type", "Hits", "First seen", "Last seen", "Found in")
		for _, e := range es {
			f, l := e.dates(bd)
			if f == "" {
				f, l = "-", "-"
			}
			fmt.Fprintf(&b, "  %-16s  %-20s  %8s  %-12s  %-12s  %s\n", ipString(e.Row.IP), e.Row.Threat, comma(e.Seen.S.Hits), f, l, e.files(bd))
		}
	}
	var clean []string
	for bi, bd := range bundles {
		if len(bb[bi]) == 0 {
			clean = append(clean, bd.Name)
		}
	}
	if len(clean) > 0 {
		b.WriteString("\n" + wrap("No threat IPs found in: ", clean, 100, "    "))
	}

	fmt.Fprintf(&b, "\n%s\nBY IP (which bundles each threat IP appeared in)\n%s\n\n", line, line)
	for _, row := range r.Threats {
		var names []string
		for _, sn := range row.Seen {
			names = append(names, bundles[sn.B].Name)
		}
		b.WriteString(wrap(fmt.Sprintf("%-16s  %-20s  %d bundle%s: ", ipString(row.IP), row.Threat, len(names), pl(len(names))), names, 100, strings.Repeat(" ", 42)))
		fmt.Fprintf(&b, "%18s  source: %s\n", "", row.ThreatSrc)
	}
	return b.String()
}

// renderThreatCSV: one row per threat IP per bundle (filter by the bundle column in a spreadsheet).
func renderThreatCSV(bundles []*bundle, r *result) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"bundle", "threat_ip", "type", "listed_by", "hits", "first_seen", "last_seen", "found_in_files", "bundles_with_this_ip"})
	bb := byBundle(bundles, r)
	for bi, bd := range bundles {
		for _, e := range bb[bi] {
			first, last := "", ""
			if e.Seen.R.OK {
				first, last = e.Seen.R.Lo.Format("2006-01-02"), e.Seen.R.Hi.Format("2006-01-02")
			}
			w.Write([]string{csvSafe(bd.Name), ipString(e.Row.IP), e.Row.Threat, csvSafe(e.Row.ThreatSrc),
				strconv.FormatInt(e.Seen.S.Hits, 10), first, last, csvSafe(e.files(bd)), strconv.Itoa(len(e.Row.Seen))})
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}
