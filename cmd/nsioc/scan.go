package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

const maxDepth = 6 // tar -> file -> gz -> ... nesting limit

type hit struct {
	N    int
	Text string
	Time string // "2026-09-29T00:10:12", or "--09-29T00:10:12" when the log has no year; empty if none
}

// agg collects the hits of one rule in one file.
type agg struct {
	Sev   Severity
	ID    string
	Desc  string
	Ref   string
	File  string
	Lines []hit
	Total int
}

type Scanner struct {
	maxPer int

	mu       sync.Mutex
	results  []*agg
	warnings []string

	files, archives, lines, bytes int64

	hashes    map[string]string
	attackers map[string]string
	scanners  map[string]bool
	domRe     *regexp.Regexp
	domLits   []string
	rules     []*Rule
	groupBits map[string]int // group -> number of member patterns
	cov       []covStat      // per covSources entry, guarded by mu
	unread    []string       // compressed files in a format we cannot open, guarded by mu
	inv       []invEntry     // every file scanned, guarded by mu
}

var sprayPrefixes = []string{"138.226.239.", "185.136.15.", "77.91.71."}

const sprayHost = "93.152.219.115"

func NewScanner(maxPer int) *Scanner {
	s := &Scanner{
		maxPer:    maxPer,
		hashes:    map[string]string{},
		attackers: map[string]string{},
		scanners:  map[string]bool{},
		groupBits: map[string]int{},
		cov:       make([]covStat, len(covSources)),
	}
	for _, h := range knownHashes {
		s.hashes[h.SHA256] = h.Source
	}
	for _, i := range attackerIPs {
		s.attackers[i.IP] = i.Source
	}
	for _, i := range scannerIPs {
		s.scanners[i] = true
	}
	alts := make([]string, 0, len(attackerDomains))
	for _, d := range attackerDomains {
		d = strings.ToLower(d)
		alts = append(alts, regexp.QuoteMeta(d))
		s.domLits = append(s.domLits, d)
	}
	s.domRe = regexp.MustCompile(`(?:^|[^a-z0-9-])(?:[a-z0-9-]+\.)*(` + strings.Join(alts, "|") + `)(?:[^a-z0-9-]|$)`)
	for i := range rules {
		r := &rules[i]
		if r.Group != "" {
			r.groupBit = s.groupBits[r.Group]
			s.groupBits[r.Group]++
		}
		s.rules = append(s.rules, r)
	}
	return s
}

func (s *Scanner) warn(format string, a ...any) {
	s.mu.Lock()
	s.warnings = append(s.warnings, fmt.Sprintf(format, a...))
	s.mu.Unlock()
}

// ScanReader scans one on-disk file (or any stream); archives are unpacked in memory, never to disk.
func (s *Scanner) ScanReader(logical string, r io.Reader) {
	atomic.AddInt64(&s.files, 1)
	s.stream(label(filepath.ToSlash(logical)), r, 0)
}

func (s *Scanner) stream(logical string, r io.Reader, depth int) {
	br := bufio.NewReaderSize(r, 256*1024)
	head, _ := br.Peek(512)
	switch {
	case depth < maxDepth && len(head) > 2 && head[0] == 0x1f && head[1] == 0x8b:
		zr, err := gzip.NewReader(br)
		if err != nil {
			s.warn("%s: bad gzip header: %v", logical, err)
			s.text(logical, br)
			return
		}
		atomic.AddInt64(&s.archives, 1)
		inner := strings.TrimSuffix(logical, ".gz")
		if strings.HasSuffix(inner, ".tgz") {
			inner = strings.TrimSuffix(inner, ".tgz") + ".tar"
		} else if inner == logical {
			inner = logical + "~gunzip"
		}
		s.stream(inner, zr, depth+1)
		if _, err := io.Copy(io.Discard, zr); err != nil {
			s.warn("%s: gzip stream ended early (%v) - bundle may be truncated or corrupt", logical, err)
		}
	case depth < maxDepth && len(head) >= 4 && head[0] == 'B' && head[1] == 'Z' && head[2] == 'h' && head[3] >= '1' && head[3] <= '9':
		atomic.AddInt64(&s.archives, 1)
		inner := strings.TrimSuffix(logical, ".bz2")
		if inner == logical {
			inner += "~bunzip2"
		}
		br2 := bzip2.NewReader(br)
		s.stream(inner, br2, depth+1)
		if _, err := io.Copy(io.Discard, br2); err != nil {
			s.warn("%s: bzip2 stream ended early (%v)", logical, err)
		}
	case depth < maxDepth && len(head) >= 4 && string(head[:4]) == "PK\x03\x04":
		s.zipStream(logical, r, br, depth)
	case depth < maxDepth && len(head) >= 262 && string(head[257:262]) == "ustar":
		atomic.AddInt64(&s.archives, 1)
		tr := tar.NewReader(br)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				s.warn("%s: tar read error: %v", logical, err)
				break
			}
			if h.Typeflag != tar.TypeReg && h.Typeflag != 0 {
				continue // directories, symlinks, devices
			}
			atomic.AddInt64(&s.files, 1)
			s.stream(logical+"!/"+label(strings.TrimPrefix(h.Name, "./")), tr, depth+1)
		}
	default:
		if name := unsupportedCompression(head); name != "" {
			s.mu.Lock()
			s.unread = append(s.unread, fmt.Sprintf("%s (%s)", logical, name))
			s.mu.Unlock()
			io.Copy(io.Discard, br)
			return
		}
		s.text(logical, br)
	}
}

// unsupportedCompression names compression formats the standard library cannot read. Such a file would
// otherwise look like binary data and be skipped silently, hiding a log the investigator expects to be searched.
func unsupportedCompression(h []byte) string {
	switch {
	case bytes.HasPrefix(h, []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}):
		return "xz"
	case bytes.HasPrefix(h, []byte{0x28, 0xB5, 0x2F, 0xFD}):
		return "zstd"
	case bytes.HasPrefix(h, []byte{0x1F, 0x9D}):
		return "compress (.Z)"
	case bytes.HasPrefix(h, []byte{'P', 'K', 0x03, 0x04}):
		return "zip"
	case bytes.HasPrefix(h, []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}):
		return "7-zip"
	case bytes.HasPrefix(h, []byte{0x04, 0x22, 0x4D, 0x18}):
		return "lz4"
	}
	return ""
}

func (s *Scanner) add(local map[string]*agg, key string, sev Severity, id, desc, ref, file string, n int, text string) {
	a := local[key]
	if a == nil {
		a = &agg{Sev: sev, ID: id, Desc: desc, Ref: ref, File: file}
		local[key] = a
	}
	a.Total++
	if len(a.Lines) < s.maxPer {
		a.Lines = append(a.Lines, hit{n, text, hitTime(n, text)})
	}
}

func clean(b []byte) string {
	if len(b) > 400 {
		b = b[:400]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if (c < 0x20 && c != '\t') || c >= 0x7f {
			c = '.'
		}
		out[i] = c
	}
	return strings.TrimSpace(string(out))
}

func (s *Scanner) text(logical string, br *bufio.Reader) {
	lp := strings.ToLower(logical)
	local := map[string]*agg{}

	for i := range pathRules {
		p := &pathRules[i]
		if p.Re.MatchString(lp) && (p.NotRe == nil || !p.NotRe.MatchString(lp)) {
			s.add(local, p.ID+"\x00"+logical, p.Sev, p.ID, p.Desc, p.Ref, logical, 0, logical)
		}
	}

	head, _ := br.Peek(8192)
	binary := bytes.IndexByte(head, 0) >= 0

	// Classify: by name first, by content when the name told us nothing. Path-restricted rules then
	// also see the "virtual" canonical path of that class, so renamed files are still searched.
	ci, li := -1, -1
	for i, r := range covRe {
		if covSources[i].Loc {
			if li < 0 && r.MatchString(lp) {
				li = i
			}
		} else if ci < 0 && r.MatchString(lp) {
			ci = i
		}
	}
	byContent := false
	if ci < 0 && !binary {
		if k := sniff(head); k != "" {
			ci, byContent = covIdx[k], true
		}
	}
	var vps []string
	if ci >= 0 {
		vps = append(vps, covSources[ci].Canon...)
	}
	if li >= 0 {
		vps = append(vps, covSources[li].Canon...)
	}
	var cs, ls covStat
	timed := ci >= 0 && covSources[ci].Timed
	ent := invEntry{Path: logical, Binary: binary, Class: -1, Loc: li}
	if ci >= 0 {
		ent.Class, ent.ByContent = ci, byContent
	} else if !binary {
		ent.Shape = shape(head)
	}

	isBody := bodyfileRe.MatchString(lp)
	isHashList := uacHashRe.MatchString(lp)

	var active []*Rule
	for _, r := range s.rules {
		if binary && !r.Bin {
			continue
		}
		if r.Path != nil && !anyPath(r.Path, lp, vps) {
			continue
		}
		if r.NotPath != nil && anyPath(r.NotPath, lp, vps) {
			continue
		}
		active = append(active, r)
	}

	h := sha256.New()
	var size int64
	lineNo := 0
	cont := false
	var lower []byte
	gmask := map[string]uint32{}

	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			h.Write(line)
			size += int64(len(line))
			if !cont {
				lineNo++
			}
			cont = err == bufio.ErrBufferFull
			body := bytes.TrimRight(line, "\r\n")
			lower = lower[:0]
			for _, c := range body {
				if c >= 'A' && c <= 'Z' {
					c += 32
				}
				lower = append(lower, c)
			}
			if timed && !cont {
				if t, hy, ok := parseTS(body); ok {
					cs.note(t, hy)
				}
			}
			s.line(local, logical, lineNo, body, lower, active, binary, gmask)
			if !cont {
				if isBody {
					s.bodyLine(local, logical, lineNo, body)
				}
				if isHashList {
					s.hashLine(local, logical, lineNo, body)
				}
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if err != io.EOF {
				s.warn("%s: read error: %v", logical, err)
			}
			break
		}
	}
	atomic.AddInt64(&s.bytes, size)
	atomic.AddInt64(&s.lines, int64(lineNo))

	if size > 0 {
		sum := hex.EncodeToString(h.Sum(nil))
		if src, ok := s.hashes[sum]; ok {
			s.add(local, "hash\x00"+logical, Compromise, "known-malicious-hash", "SHA-256 of this file matches a published IOC ("+src+")", "ctx697096_check.sh hash lists", logical, 0, sum)
		} else if sum == vulnerableMonuploaddHash {
			s.add(local, "monhash\x00"+logical, Check, "vulnerable-monuploadd", "this is the VULNERABLE ns_monuploadd_err.pl (14.1-66.59 / 72.61) - on a fixed build it was put back or not replaced", "ThreatUnpacked via Gotham", logical, 0, sum)
		}
	}
	if size < 1<<20 {
		for g, mask := range gmask {
			if gr, ok := groupRules[g]; ok && mask == (1<<uint(s.groupBits[g]))-1 {
				s.add(local, gr.ID+"\x00"+logical, gr.Sev, gr.ID, gr.Desc, gr.Ref, logical, 0, fmt.Sprintf("%d bytes", size))
			}
		}
	}

	ent.Size = size
	s.mu.Lock()
	if ci >= 0 {
		cs.Files, cs.Lines, cs.Bytes = 1, int64(lineNo), size
		if byContent {
			cs.ByContent = 1
		}
		s.cov[ci].merge(&cs)
	}
	if li >= 0 {
		ls.Files, ls.Lines, ls.Bytes = 1, int64(lineNo), size
		s.cov[li].merge(&ls)
	}
	s.inv = append(s.inv, ent)
	s.mu.Unlock()
	if len(local) == 0 {
		return
	}
	s.mu.Lock()
	for _, a := range local {
		s.results = append(s.results, a)
	}
	s.mu.Unlock()
}

func anyLit(lower []byte, lits []string) bool {
	for _, l := range lits {
		if bytes.Contains(lower, []byte(l)) {
			return true
		}
	}
	return false
}

func (s *Scanner) line(local map[string]*agg, file string, n int, line, lower []byte, active []*Rule, binary bool, gmask map[string]uint32) {
	for _, r := range active {
		if len(r.Lits) > 0 && !anyLit(lower, r.Lits) {
			continue
		}
		if r.NoCmt {
			if t := bytes.TrimLeft(line, " \t"); len(t) > 0 && t[0] == '#' {
				continue
			}
		}
		if !r.Re.Match(line) {
			continue
		}
		if r.And != nil && !r.And.Match(line) {
			continue
		}
		if r.Not != nil && r.Not.Match(line) {
			continue
		}
		extra, sev := "", r.Sev
		if r.Eval != nil {
			e, sv, ok := r.Eval(line)
			if !ok {
				continue
			}
			extra = e
			if sv != 0 {
				sev = sv
			}
		}
		if r.Group != "" {
			gmask[r.Group] |= 1 << uint(r.groupBit)
			continue
		}
		s.add(local, r.ID+"\x00"+file, sev, r.ID, r.Desc, r.Ref, file, n, clean(line)+extra)
	}
	if binary || bytes.Contains(line, []byte("shell_command=")) {
		return
	}
	s.ips(local, file, n, line)
	if anyLit(lower, s.domLits) {
		if m := s.domRe.FindSubmatch(lower); m != nil {
			d := string(m[1])
			s.add(local, "dom\x00"+d+"\x00"+file, Targeted, "known-attacker-domain",
				"attacker / C2 / exfil domain "+d+" (IFIN, Arctic Wolf, TENEX, Beazley, Gotham)", "ctx697096_check.sh GN_DOM", file, n, clean(line))
		}
	}
}

// ips finds every dotted-quad in the line (address boundaries respected: 1.2.3.4 never matches 1.2.3.45).
func (s *Scanner) ips(local map[string]*agg, file string, n int, line []byte) {
	for i := 0; i < len(line); {
		c := line[i]
		if c < '0' || c > '9' || (i > 0 && (line[i-1] == '.' || (line[i-1] >= '0' && line[i-1] <= '9'))) {
			i++
			continue
		}
		j, dots := i, 0
		for j < len(line) && ((line[j] >= '0' && line[j] <= '9') || line[j] == '.') {
			if line[j] == '.' {
				dots++
			}
			j++
		}
		tok := line[i:j]
		for len(tok) > 0 && tok[len(tok)-1] == '.' {
			tok = tok[:len(tok)-1]
			dots--
		}
		i = j
		if dots != 3 || len(tok) > 15 || !validQuad(tok) {
			continue
		}
		ip := string(tok)
		if src, ok := s.attackers[ip]; ok {
			s.add(local, "ip\x00"+ip+"\x00"+file, Targeted, "known-attacker-ip", "known exploitation IP "+ip+" ("+src+")", "ctx697096_check.sh GN_IPS", file, n, clean(line))
		} else if s.scanners[ip] {
			s.add(local, "sc\x00"+ip+"\x00"+file, Lead, "scanner-ip", "opportunistic scanner IP "+ip+" tagged by GreyNoise - hunting lead only, often residential/proxy", "ctx697096_check.sh OPP_IPRE", file, n, clean(line))
		} else if ip == sprayHost || hasAny(ip, sprayPrefixes) {
			s.add(local, "sp\x00"+ip+"\x00"+file, Targeted, "password-spray-range", "password-spray source range 138.226.239.0/24, 185.136.15.0/24, 77.91.71.0/24 or 93.152.219.115: "+ip, "Gotham", file, n, clean(line))
		}
	}
}

func hasAny(ip string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return false
}

func validQuad(tok []byte) bool {
	parts, v, nd := 0, 0, 0
	for _, c := range tok {
		if c == '.' {
			if nd == 0 {
				return false
			}
			parts++
			v, nd = 0, 0
			continue
		}
		v = v*10 + int(c-'0')
		nd++
		if nd > 3 || v > 255 {
			return false
		}
	}
	return nd > 0 && parts == 3
}

// invEntry is one scanned file, kept for -inventory.
type invEntry struct {
	Path      string
	Size      int64
	Binary    bool
	Class     int // covSources index, -1 = unclassified
	Loc       int // location source index, -1 = none
	ByContent bool
	Shape     string // layout of the first line (letters a/A, digits 9), unclassified text files only
}

// label makes a file name safe to print: archive entry names come from the bundle and may hold terminal
// control characters. The name is only ever a label - nothing is extracted or written to disk.
func label(n string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, n)
}

// maxZipMem caps how much of a zip nested inside another archive is held in memory (a zip needs random access; a
// zip that is a plain file on disk is read in place and has no cap).
const maxZipMem = 1 << 30

// zipStream scans every regular file in a zip, in memory. Each member goes back through stream, so a .tar.gz
// inside the zip (a UAC collection) is unpacked and searched like any other bundle.
func (s *Scanner) zipStream(logical string, r io.Reader, br *bufio.Reader, depth int) {
	var ra io.ReaderAt
	var size int64
	if f, ok := r.(*os.File); ok {
		fi, err := f.Stat()
		if err != nil {
			s.warn("%s: %v", logical, err)
			return
		}
		ra, size = f, fi.Size()
	} else {
		buf, err := io.ReadAll(io.LimitReader(br, maxZipMem+1))
		if err != nil || len(buf) > maxZipMem {
			s.mu.Lock()
			s.unread = append(s.unread, fmt.Sprintf("%s (zip inside an archive, over %d MB or unreadable)", logical, maxZipMem>>20))
			s.mu.Unlock()
			return
		}
		ra, size = bytes.NewReader(buf), int64(len(buf))
	}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		s.warn("%s: not a readable zip: %v", logical, err)
		return
	}
	atomic.AddInt64(&s.archives, 1)
	for _, f := range zr.File {
		name := logical + "!/" + label(strings.TrimPrefix(f.Name, "./"))
		if f.FileInfo().IsDir() || !f.Mode().IsRegular() {
			continue // directories, symlinks
		}
		if f.Flags&1 != 0 {
			s.mu.Lock()
			s.unread = append(s.unread, name+" (encrypted zip entry)")
			s.mu.Unlock()
			continue
		}
		rc, err := f.Open()
		if err != nil {
			s.warn("%s: %v", name, err)
			continue
		}
		atomic.AddInt64(&s.files, 1)
		s.stream(name, rc, depth+1)
		rc.Close()
	}
}
