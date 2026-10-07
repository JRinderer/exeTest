// ipxref compares a folder of Citrix NetScaler technical support bundles and reports the IP addresses
// that appear in more than one of them (and in all of them), with the bundles each one appears in.
//
// Standard library only. Read-only: bundles are streamed, archives are unpacked in memory, and the only
// thing written is the optional report.
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	version  = "1.0"
	maxDepth = 6
)

// ---------------------------------------------------------------------------------------------------
// data

type bstat struct {
	Hits  int64
	Files int
	Ex    [3]int32 // up to 3 example files inside the bundle (indexes into bundle.names)
	NEx   uint8
	Sp    span // earliest and latest dated log line this address appears in
}

type bundle struct {
	Name     string
	Kind     string // "folder", "archive" or "zip member"
	File     string // archive file name inside the searched folder
	ZipEntry string // set when the bundle is one archive inside a zip (File is then the zip)
	mu       sync.Mutex
	ips      map[uint32]*bstat
	files    int64
	binary   int64
	bytes    int64
	skipped  int64    // IPs dropped by the private/reserved/version filters (occurrences)
	unread   []string // files in a compression format we cannot open (guarded by mu)

	names    []string         // interned example file names (guarded by mu)
	nameIdx  map[string]int32 // guarded by mu
	lspan    span             // earliest and latest dated line of every log file (guarded by mu)
	logFiles int              // files that had dated lines (guarded by mu)

	ref      time.Time // reference date for years missing from syslog-style times
	refGuess bool      // no dated line had a year, so ref is today's date
	log      resolved  // log history of the whole bundle
}

func (b *bundle) intern(n string) int32 {
	if b.nameIdx == nil {
		b.nameIdx = map[string]int32{}
	}
	if i, ok := b.nameIdx[n]; ok {
		return i
	}
	b.names = append(b.names, n)
	b.nameIdx[n] = int32(len(b.names) - 1)
	return int32(len(b.names) - 1)
}

type scanner struct {
	includePrivate bool
	allowVersions  bool
	threats        *threatDB // every list, scanners included: such an IP is never dropped as a 'version'
	root           *os.Root
	mu             sync.Mutex
	warnings       []string
}

func (s *scanner) warn(f string, a ...any) {
	s.mu.Lock()
	s.warnings = append(s.warnings, fmt.Sprintf(f, a...))
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------------------------------
// IP extraction and filtering

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func parseQuad(tok []byte) (uint32, bool) {
	var v uint32
	octet, nd, parts := 0, 0, 0
	for _, c := range tok {
		if c == '.' {
			if nd == 0 {
				return 0, false
			}
			v = v<<8 | uint32(octet)
			parts++
			octet, nd = 0, 0
			continue
		}
		if nd == 1 && octet == 0 { // leading zero ("01.02.03.04" is not an address)
			return 0, false
		}
		octet = octet*10 + int(c-'0')
		nd++
		if nd > 3 || octet > 255 {
			return 0, false
		}
	}
	if nd == 0 || parts != 3 {
		return 0, false
	}
	return v<<8 | uint32(octet), true
}

// special reports private, loopback, link-local, CGNAT, multicast and reserved space.
func special(v uint32) bool {
	a, b, c := byte(v>>24), byte(v>>16), byte(v>>8)
	switch {
	case a == 0, a == 10, a == 127, a >= 224:
		return true
	case a == 100 && b >= 64 && b <= 127:
		return true
	case a == 169 && b == 254:
		return true
	case a == 172 && b >= 16 && b <= 31:
		return true
	case a == 192 && b == 168:
		return true
	case a == 192 && b == 0 && c == 0:
		return true
	case a == 198 && (b == 18 || b == 19):
		return true
	}
	return false
}

// netmask: 255.255.255.0 and friends are not addresses.
func netmask(v uint32) bool {
	inv := ^v
	return v>>24 >= 128 && inv&(inv+1) == 0
}

var versionWords = map[string]bool{"build": true, "version": true, "ver": true, "release": true, "rev": true,
	"fw": true, "firmware": true, "kernel": true, "v": true, "ns": true, "nsos": true}

// looksLikeVersion: "NS14.1.73.37", "v1.2.3.4", "Build 14.1.73.37", "version: 13.1.64.24".
func looksLikeVersion(line []byte, start int) bool {
	if start > 0 {
		c := line[start-1]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
			return true
		}
	}
	j := start
	for j > 0 && (line[j-1] == ' ' || line[j-1] == ':' || line[j-1] == '=' || line[j-1] == '\t') {
		j--
	}
	k := j
	for k > 0 && ((line[k-1] >= 'a' && line[k-1] <= 'z') || (line[k-1] >= 'A' && line[k-1] <= 'Z')) {
		k--
	}
	return k < j && versionWords[strings.ToLower(string(line[k:j]))]
}

// extract calls fn for every dotted-quad in the line (boundaries respected: 1.2.3.4 never matches
// inside 11.2.3.45 or 1.2.3.4.5).
func (s *scanner) extract(line []byte, fn func(ip uint32), skipped *int64) {
	for i := 0; i < len(line); {
		c := line[i]
		if !isDigit(c) || (i > 0 && (line[i-1] == '.' || isDigit(line[i-1]))) {
			i++
			continue
		}
		j, dots := i, 0
		for j < len(line) && (isDigit(line[j]) || line[j] == '.') {
			if line[j] == '.' {
				dots++
			}
			j++
		}
		start := i
		tok := line[i:j]
		i = j
		for len(tok) > 0 && tok[len(tok)-1] == '.' {
			tok = tok[:len(tok)-1]
			dots--
		}
		if dots != 3 || len(tok) > 15 {
			continue
		}
		ip, ok := parseQuad(tok)
		if !ok || netmask(ip) || ip == 0 || ip == 0xFFFFFFFF {
			continue
		}
		if !s.includePrivate && special(ip) {
			*skipped++
			continue
		}
		if !s.allowVersions && looksLikeVersion(line, start) {
			// the version filter is a guess (it also drops "ns 1.2.3.4" or "src_1.2.3.4"): never let it hide an
			// address that is on the published threat lists
			if cat, _ := s.threats.lookup(ip); cat == "" {
				*skipped++
				continue
			}
		}
		fn(ip)
	}
}

func ipString(v uint32) string {
	return strconv.Itoa(int(v>>24)) + "." + strconv.Itoa(int(v>>16&255)) + "." + strconv.Itoa(int(v>>8&255)) + "." + strconv.Itoa(int(v&255))
}

// ---------------------------------------------------------------------------------------------------
// reading bundles (folders and archives), all through an os.Root on the searched folder

func (s *scanner) stream(b *bundle, logical string, r io.Reader, depth int) {
	br := bufio.NewReaderSize(r, 256*1024)
	head, _ := br.Peek(512)
	switch {
	case depth < maxDepth && len(head) > 2 && head[0] == 0x1f && head[1] == 0x8b:
		zr, err := gzip.NewReader(br)
		if err != nil {
			s.warn("%s/%s: bad gzip header: %v", b.Name, logical, err)
			return
		}
		inner := strings.TrimSuffix(logical, ".gz")
		if strings.HasSuffix(inner, ".tgz") {
			inner = strings.TrimSuffix(inner, ".tgz") + ".tar"
		} else if inner == logical {
			inner += "~gunzip"
		}
		s.stream(b, inner, zr, depth+1)
		if _, err := io.Copy(io.Discard, zr); err != nil {
			s.warn("%s/%s: gzip stream ended early (%v): bundle may be truncated", b.Name, logical, err)
		}
	case depth < maxDepth && len(head) >= 4 && head[0] == 'B' && head[1] == 'Z' && head[2] == 'h' && head[3] >= '1' && head[3] <= '9':
		inner := strings.TrimSuffix(logical, ".bz2")
		if inner == logical {
			inner += "~bunzip2"
		}
		zr := bzip2.NewReader(br)
		s.stream(b, inner, zr, depth+1)
		io.Copy(io.Discard, zr)
	case depth < maxDepth && len(head) >= 4 && string(head[:4]) == "PK\x03\x04":
		s.zipStream(b, logical, r, br, depth)
	case depth < maxDepth && len(head) >= 262 && string(head[257:262]) == "ustar":
		tr := tar.NewReader(br)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				s.warn("%s/%s: tar read error: %v", b.Name, logical, err)
				break
			}
			if h.Typeflag != tar.TypeReg && h.Typeflag != 0 {
				continue
			}
			s.stream(b, label(strings.TrimPrefix(h.Name, "./")), tr, depth+1)
		}
	default:
		if name := unsupportedCompression(head); name != "" {
			b.mu.Lock()
			b.unread = append(b.unread, fmt.Sprintf("%s (%s)", logical, name))
			b.mu.Unlock()
			io.Copy(io.Discard, br)
			return
		}
		s.text(b, logical, br)
	}
}

// unsupportedCompression names compression formats the standard library cannot read. Such a file would
// otherwise look like binary data and be skipped silently.
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

// tail keeps the last n path components. Archive entries carry the bundle's top-level folder and folder
// bundles do not, so comparing the same file across bundles needs the common tail ("var/log/ns.log").
func tail(p string, n int) string {
	parts := strings.Split(p, "/")
	if len(parts) <= n {
		return p
	}
	return strings.Join(parts[len(parts)-n:], "/")
}

// label makes an archive entry name safe to print; it is only ever a label.
func label(n string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, n)
}

func (s *scanner) text(b *bundle, logical string, br *bufio.Reader) {
	head, _ := br.Peek(8192)
	if bytes.IndexByte(head, 0) >= 0 { // binary (e.g. nslog counters): skipped
		atomic.AddInt64(&b.binary, 1)
		io.Copy(io.Discard, br)
		return
	}
	type loc struct {
		n  int64
		sp span
	}
	local := map[uint32]*loc{}
	var size, skipped int64
	var fileSp span
	gotFirst, tries := false, 0
	var last [3][]byte // the last non-empty lines, to read the end of the log's time range
	nlast := 0
	var ips []uint32
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			size += int64(len(line))
			body := bytes.TrimRight(line, "\r\n")
			if len(body) > 0 {
				// first dated line (a config file has none: give up after 50 lines)
				if !gotFirst && tries < 50 {
					tries++
					if t, hy, ok := parseStamp(body); ok {
						fileSp.note(t, hy)
						gotFirst = true
					}
				}
				k := nlast % 3
				n := len(body)
				if n > 160 {
					n = 160
				}
				last[k] = append(last[k][:0], body[:n]...)
				nlast++
			}
			ips = ips[:0]
			s.extract(body, func(ip uint32) { ips = append(ips, ip) }, &skipped)
			if len(ips) > 0 {
				t, hy, ok := parseStamp(body)
				for _, ip := range ips {
					e := local[ip]
					if e == nil {
						e = &loc{}
						local[ip] = e
					}
					e.n++
					if ok {
						e.sp.note(t, hy)
					}
				}
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if err != io.EOF {
				s.warn("%s/%s: read error: %v", b.Name, logical, err)
			}
			break
		}
	}
	// last dated line: try the final three non-empty lines
	for i := 0; i < 3 && i < nlast; i++ {
		if t, hy, ok := parseStamp(last[(nlast-1-i)%3]); ok {
			fileSp.note(t, hy)
			break
		}
	}
	atomic.AddInt64(&b.files, 1)
	atomic.AddInt64(&b.bytes, size)
	atomic.AddInt64(&b.skipped, skipped)
	if !fileSp.empty() {
		b.mu.Lock()
		b.lspan.merge(fileSp)
		b.logFiles++
		b.mu.Unlock()
	}
	if len(local) == 0 {
		return
	}
	b.mu.Lock()
	ex := b.intern(tail(logical, 3))
	for ip, e := range local {
		st := b.ips[ip]
		if st == nil {
			st = &bstat{}
			b.ips[ip] = st
		}
		st.Hits += e.n
		st.Files++
		st.Sp.merge(e.sp)
		if st.NEx < 3 {
			st.Ex[st.NEx] = ex
			st.NEx++
		}
	}
	b.mu.Unlock()
}

type job struct {
	b    *bundle
	full string // path relative to the searched folder
	rel  string // path inside the bundle
}

func (s *scanner) openRegular(full string) (*os.File, error) {
	f, err := s.root.Open(filepath.FromSlash(full))
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("not a regular file, skipped")
	}
	return f, nil
}

// archiveKind reports whether a file in the searched folder is an archive (gzip, bzip2 or tar).
func (s *scanner) isArchive(name string) bool {
	f, err := s.openRegular(name)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	return (n > 2 && head[0] == 0x1f && head[1] == 0x8b) ||
		(n >= 4 && head[0] == 'B' && head[1] == 'Z' && head[2] == 'h') ||
		(n >= 262 && string(head[257:262]) == "ustar")
}

// ---------------------------------------------------------------------------------------------------
// output safety (same rules as nsioc): never write inside the searched folder, never follow symlinks

func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

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

func checkOutput(flagName, p, searched string, others ...string) (string, error) {
	if p == "" {
		return "", nil
	}
	target, err := resolve(p)
	if err != nil {
		return "", fmt.Errorf("%s %q: %v", flagName, p, err)
	}
	realRoot, err := filepath.EvalSymlinks(searched)
	if err != nil {
		return "", err
	}
	if within(realRoot, target) {
		return "", fmt.Errorf("%s %q is inside the searched folder; write the report elsewhere so the bundles are not changed", flagName, p)
	}
	if fi, err := os.Lstat(target); err == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular()) {
		return "", fmt.Errorf("%s %q exists and is not a regular file (symlink or special file); refusing to write to it", flagName, p)
	}
	for _, o := range others {
		if o != "" && o == target {
			return "", fmt.Errorf("%s points at the same file as another output", flagName)
		}
	}
	return target, nil
}

func writeFile(path string, data []byte) error {
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

// loadIgnore reads IPs and CIDR ranges (one per line, # comments) through an os.Root on the file's folder.
func loadIgnore(path string) ([]netip.Prefix, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
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
	var out []netip.Prefix
	sc := bufio.NewScanner(io.LimitReader(f, 8<<20))
	for n := 1; sc.Scan(); n++ {
		l := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" {
			continue
		}
		if p, err := netip.ParsePrefix(l); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(l); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		} else {
			return nil, fmt.Errorf("%s line %d: %q is not an IP address or CIDR range", path, n, l)
		}
	}
	return out, sc.Err()
}

// ---------------------------------------------------------------------------------------------------
// main

func main() {
	var (
		dir      = flag.String("dir", "", "folder that contains the bundles (one subfolder or archive per bundle); may be the first argument")
		out      = flag.String("out", "", "also write the full readable text report (every IP) to this file")
		csvOut   = flag.String("csv", "", "write one row per IP to this CSV file (opens in Excel): threat flag, bundle names, hits per bundle, dates. If you give no output file at all, ipxref_ips.csv is written in the current folder")
		minB     = flag.Int("min-bundles", 1, "list IPs found in at least this many bundles (1 = every IP, even if it is in only one bundle; 2 = only IPs shared between bundles)")
		maxIPs   = flag.Int("max-ips", 300, "most IPs listed on SCREEN (0 = no limit). The -out file and the CSV always have every IP")
		priv     = flag.Bool("include-private", false, "also count private, loopback and reserved addresses (excluded by default)")
		vers     = flag.Bool("include-versions", false, "also count version-looking numbers such as 'Build 14.1.73.37' (excluded by default)")
		ignore   = flag.String("ignore", "", "file of IPs / CIDR ranges to leave out (your DNS, NTP, VIPs, monitoring), one per line, # for comments")
		full     = flag.Bool("full", false, "always list every bundle (with hit counts) for each IP")
		threats  = flag.String("threats", "", "write the threat IPs found in each bundle to this file: .csv = spreadsheet (one row per IP per bundle), anything else = readable text")
		printRep = flag.Bool("print", false, "also print the full text report on screen (by default only a short summary is shown)")
		bundCSV  = flag.String("bundles-csv", "", "write one row per bundle (files, IP counts, threat IPs, oldest and newest log entry) to this CSV file")
		tOnly    = flag.Bool("threats-only", false, "only the threat IPs: no list of other IPs. Writes ipxref_threats.csv unless you give -threats FILE (.csv or text)")
		noScan   = flag.Bool("no-scanners", false, "leave opportunistic scanner IPs (weak 'lead' evidence) out of the threat report")
		workers  = flag.Int("workers", runtime.NumCPU(), "files read in parallel")
		verbose  = flag.Bool("v", false, "print progress")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ipxref %s - find IP addresses that appear in more than one Citrix technical support bundle\n\n", version)
		fmt.Fprintf(os.Stderr, "usage: ipxref [flags] <folder-of-bundles>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *dir == "" && flag.NArg() > 0 {
		*dir = flag.Arg(0)
	}
	if *dir == "" {
		flag.Usage()
		os.Exit(3)
	}
	if *minB < 1 {
		*minB = 1
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		fatal(err)
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		fatal(fmt.Errorf("%s is not a folder", *dir))
	}
	if *csvOut == "" && *out == "" && *threats == "" && *bundCSV == "" && !*printRep {
		if *tOnly {
			*threats = "ipxref_threats.csv"
		} else {
			*csvOut = "ipxref_ips.csv"
		}
	}
	outPath, err := checkOutput("-out", *out, abs)
	if err != nil {
		fatal(err)
	}
	csvPath, err := checkOutput("-csv", *csvOut, abs, outPath)
	if err != nil {
		fatal(err)
	}
	threatsPath, err := checkOutput("-threats", *threats, abs, outPath, csvPath)
	if err != nil {
		fatal(err)
	}
	bundlesPath, err := checkOutput("-bundles-csv", *bundCSV, abs, outPath, csvPath, threatsPath)
	if err != nil {
		fatal(err)
	}
	if *tOnly && *csvOut != "" {
		fatal(fmt.Errorf("-csv is the shared-IP list and cannot be used with -threats-only; use -threats FILE.csv for the threat IPs"))
	}
	var ign []netip.Prefix
	if *ignore != "" {
		if ign, err = loadIgnore(*ignore); err != nil {
			fatal(err)
		}
	}

	root, err := os.OpenRoot(abs)
	if err != nil {
		fatal(err)
	}
	defer root.Close()
	sc := &scanner{includePrivate: *priv, allowVersions: *vers, root: root, threats: newThreatDB(true)}

	// each immediate subfolder or archive is one bundle
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		fatal(err)
	}
	var bundles []*bundle
	var notBundles []string
	for _, e := range entries {
		switch {
		case e.IsDir():
			bundles = append(bundles, &bundle{Name: e.Name(), Kind: "folder", ips: map[uint32]*bstat{}})
		case e.Type().IsRegular() && sc.isZip(e.Name()):
			zb, other, err := sc.zipBundles(e.Name())
			if err != nil {
				sc.warn("%s: %v", e.Name(), err)
				notBundles = append(notBundles, e.Name())
				break
			}
			bundles = append(bundles, zb...)
			if other > 0 && len(zb) > 0 {
				sc.warn("%s: %d file(s) in the zip are not archives and were not read (only the archives inside a zip are compared)", e.Name(), other)
			}
		case e.Type().IsRegular() && sc.isArchive(e.Name()):
			n := e.Name()
			for _, suf := range []string{".tar.gz", ".tgz", ".tar.bz2", ".tar", ".gz", ".bz2"} {
				if strings.HasSuffix(strings.ToLower(n), suf) {
					n = n[:len(n)-len(suf)]
					break
				}
			}
			bundles = append(bundles, &bundle{Name: n, Kind: "archive", File: e.Name(), ips: map[uint32]*bstat{}})
		default:
			notBundles = append(notBundles, e.Name())
		}
	}
	if len(bundles) < 2 {
		fatal(fmt.Errorf("found %d bundle(s) in %s; need at least 2 to compare (each bundle must be its own subfolder or archive)", len(bundles), abs))
	}
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].Name < bundles[j].Name })
	if *verbose {
		fmt.Fprintf(os.Stderr, "found %d bundles\n", len(bundles))
	}

	start := time.Now()
	jobs := make(chan job, 128)
	var wg sync.WaitGroup
	var done int64
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				f, err := sc.openRegular(j.full)
				if err != nil {
					sc.warn("%s: %v", j.full, err)
					continue
				}
				if j.b.ZipEntry != "" {
					sc.zipMember(j.b, f)
				} else {
					sc.stream(j.b, j.rel, f, 0)
				}
				f.Close()
				if n := atomic.AddInt64(&done, 1); *verbose && n%500 == 0 {
					fmt.Fprintf(os.Stderr, "  %d files read\n", n)
				}
			}
		}()
	}
	for _, b := range bundles {
		if b.Kind == "archive" || b.ZipEntry != "" {
			jobs <- job{b, b.File, b.Name}
			continue
		}
		sub, err := fs.Sub(root.FS(), b.Name)
		if err != nil {
			sc.warn("%s: %v", b.Name, err)
			continue
		}
		fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				sc.warn("%s/%s: %v", b.Name, p, err)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() { // symlinks, FIFOs, sockets, devices are never opened
				return nil
			}
			jobs <- job{b, b.Name + "/" + p, p}
			return nil
		})
	}
	close(jobs)
	wg.Wait()

	rep := compare(bundles, ign, *minB, newThreatDB(!*noScan))
	took := time.Since(start)

	var written []string
	write := func(path string, data []byte, what string) {
		if path == "" {
			return
		}
		if err := writeFile(path, data); err != nil {
			fatal(err)
		}
		written = append(written, fmt.Sprintf("%s  (%s)", path, what))
	}
	threatData := func(textFallback string) []byte {
		if strings.EqualFold(filepath.Ext(threatsPath), ".csv") {
			d, err := renderThreatCSV(bundles, rep)
			if err != nil {
				fatal(err)
			}
			return d
		}
		return []byte(textFallback)
	}

	if *tOnly {
		text := unreadWarning(bundles) + renderThreatText(abs, bundles, rep, !*noScan)
		write(outPath, []byte(text), "threat IPs by bundle, text")
		if threatsPath != "" {
			write(threatsPath, threatData(text), "threat IPs, one row per IP per bundle")
		}
		if *printRep {
			fmt.Print(text)
		}
	} else {
		if outPath != "" {
			write(outPath, []byte(render(abs, bundles, rep, notBundles, sc.warnings, *minB, 0, *full, *priv, *vers, *ignore != "", threatsPath != "", took)), "full text report, every IP")
		}
		if csvPath != "" {
			data, err := renderCSV(bundles, rep)
			if err != nil {
				fatal(err)
			}
			write(csvPath, data, "every IP, one row each, with threat flag")
		}
		if threatsPath != "" {
			write(threatsPath, threatData(renderThreatText(abs, bundles, rep, !*noScan)), "threat IPs, one row per IP per bundle")
		}
		if *printRep {
			fmt.Print(render(abs, bundles, rep, notBundles, sc.warnings, *minB, *maxIPs, *full, *priv, *vers, *ignore != "", threatsPath != "", took))
		}
	}
	if bundlesPath != "" {
		data, err := renderBundlesCSV(bundles, rep)
		if err != nil {
			fatal(err)
		}
		write(bundlesPath, data, "one row per bundle")
	}
	fmt.Print(consoleSummary(abs, bundles, rep, sc.warnings, took, written, *printRep))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(3)
}

// ---------------------------------------------------------------------------------------------------
// comparison

type seen struct {
	B int // bundle index
	S *bstat
	R resolved // dates of the dated lines this address appears in, within this bundle
}

type ipRow struct {
	IP       uint32
	Seen     []seen // sorted by bundle index
	Hits     int64
	Typical  []string // most common example files
	Dated    bool     // at least one dated line
	Lo, Hi   time.Time
	Inferred bool // a date had no year in the log and was placed using the bundle's reference date

	Threat    string // category if the address is on a published attacker / scanner list
	ThreatSrc string
}

type result struct {
	Rows            []*ipRow // IPs in >= minBundles bundles, most widespread first
	DistinctPerBndl []int
	SharedPerBndl   []int
	TotalDistinct   int
	Ignored         int
	OverlapLo       time.Time // period covered by the logs of every bundle
	OverlapHi       time.Time
	HasOverlap      bool
	AllDated        bool     // every bundle has dated log lines
	NDated          int      // bundles that have dated log lines
	Threats         []*ipRow // addresses on the published threat lists, in any number of bundles
	NMulti          int      // IPs found in 2 or more bundles
	NSingle         int      // IPs found in only one bundle
	SinglePerBndl   []int    // IPs found only in this bundle, per bundle
	NAll            int      // IPs found in every bundle
	ThreatMulti     int      // threat IPs found in 2 or more bundles
	ThreatAll       int      // threat IPs found in every bundle
}

// prepare fixes each bundle's reference date and resolves its log history.
func prepare(bundles []*bundle) {
	for _, b := range bundles {
		if b.lspan.MaxY != 0 {
			b.ref = time.Unix(b.lspan.MaxY, 0).UTC()
		} else {
			var mx int64
			for _, st := range b.ips {
				if st.Sp.MaxY > mx {
					mx = st.Sp.MaxY
				}
			}
			if mx != 0 {
				b.ref = time.Unix(mx, 0).UTC()
			} else {
				b.ref, b.refGuess = time.Now().UTC(), true
			}
		}
		b.log = b.lspan.resolve(b.ref)
	}
}

// overlap finds the period that every bundle's logs cover.
func overlap(bundles []*bundle, r *result) {
	r.AllDated = true
	first := true
	for _, b := range bundles {
		if !b.log.OK {
			r.AllDated = false
			continue
		}
		r.NDated++
		if first {
			r.OverlapLo, r.OverlapHi, first = b.log.Lo, b.log.Hi, false
			continue
		}
		if b.log.Lo.After(r.OverlapLo) {
			r.OverlapLo = b.log.Lo
		}
		if b.log.Hi.Before(r.OverlapHi) {
			r.OverlapHi = b.log.Hi
		}
	}
	r.HasOverlap = r.NDated >= 2 && r.OverlapLo.Before(r.OverlapHi)
}

func compare(bundles []*bundle, ign []netip.Prefix, minB int, tdb *threatDB) *result {
	prepare(bundles)
	idx := map[uint32]*ipRow{}
	r := &result{DistinctPerBndl: make([]int, len(bundles)), SharedPerBndl: make([]int, len(bundles)), SinglePerBndl: make([]int, len(bundles))}
	ignored := map[uint32]bool{}
	for bi, b := range bundles {
		for ip, st := range b.ips {
			if len(ign) > 0 {
				if ignored[ip] {
					continue
				}
				a := netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)})
				skip := false
				for _, p := range ign {
					if p.Contains(a) {
						skip = true
						break
					}
				}
				if skip {
					ignored[ip] = true
					continue
				}
			}
			r.DistinctPerBndl[bi]++
			row := idx[ip]
			if row == nil {
				row = &ipRow{IP: ip}
				idx[ip] = row
			}
			sn := seen{B: bi, S: st}
			if !st.Sp.empty() {
				sn.R = st.Sp.resolve(b.ref)
			}
			row.Seen = append(row.Seen, sn)
			row.Hits += st.Hits
		}
	}
	r.Ignored = len(ignored)
	r.TotalDistinct = len(idx)
	for _, row := range idx {
		switch k := len(row.Seen); {
		case k == len(bundles):
			r.NAll++
			fallthrough
		case k >= 2:
			r.NMulti++
			for _, sn := range row.Seen {
				r.SharedPerBndl[sn.B]++
			}
		default:
			r.NSingle++
			r.SinglePerBndl[row.Seen[0].B]++
		}
	}
	for _, row := range idx {
		cat, src := "", ""
		if tdb != nil {
			cat, src = tdb.lookup(row.IP)
		}
		if len(row.Seen) < minB && cat == "" {
			continue
		}
		sort.Slice(row.Seen, func(i, j int) bool { return row.Seen[i].B < row.Seen[j].B })

		cnt := map[string]int{}
		for _, s := range row.Seen {
			for i := 0; i < int(s.S.NEx); i++ {
				cnt[bundles[s.B].names[s.S.Ex[i]]]++
			}
			if s.R.OK {
				if !row.Dated || s.R.Lo.Before(row.Lo) {
					row.Lo = s.R.Lo
				}
				if !row.Dated || s.R.Hi.After(row.Hi) {
					row.Hi = s.R.Hi
				}
				row.Dated = true
				row.Inferred = row.Inferred || s.R.Inferred
			}
		}
		type kv struct {
			K string
			V int
		}
		var kvs []kv
		for k, v := range cnt {
			kvs = append(kvs, kv{k, v})
		}
		sort.Slice(kvs, func(i, j int) bool { return kvs[i].V > kvs[j].V || (kvs[i].V == kvs[j].V && kvs[i].K < kvs[j].K) })
		for i := 0; i < len(kvs) && i < 3; i++ {
			row.Typical = append(row.Typical, kvs[i].K)
		}
		if len(row.Seen) >= minB {
			r.Rows = append(r.Rows, row)
		}
		if cat != "" {
			row.Threat, row.ThreatSrc = cat, src
			r.Threats = append(r.Threats, row)
			if len(row.Seen) >= 2 {
				r.ThreatMulti++
			}
			if len(row.Seen) == len(bundles) {
				r.ThreatAll++
			}
		}
	}
	sort.Slice(r.Threats, func(i, j int) bool {
		a, b := r.Threats[i], r.Threats[j]
		if catRank[a.Threat] != catRank[b.Threat] {
			return catRank[a.Threat] < catRank[b.Threat]
		}
		if len(a.Seen) != len(b.Seen) {
			return len(a.Seen) > len(b.Seen)
		}
		if a.Hits != b.Hits {
			return a.Hits > b.Hits
		}
		return a.IP < b.IP
	})
	overlap(bundles, r)
	sort.Slice(r.Rows, func(i, j int) bool {
		a, b := r.Rows[i], r.Rows[j]
		if len(a.Seen) != len(b.Seen) {
			return len(a.Seen) > len(b.Seen)
		}
		if len(a.Seen) == 1 && a.Seen[0].B != b.Seen[0].B {
			return a.Seen[0].B < b.Seen[0].B
		}
		if len(a.Seen) == 1 && (a.Threat != "") != (b.Threat != "") {
			return a.Threat != ""
		}
		if a.Hits != b.Hits {
			return a.Hits > b.Hits
		}
		return a.IP < b.IP
	})
	return r
}

// ---------------------------------------------------------------------------------------------------
// report

func comma(n int64) string {
	s := strconv.FormatInt(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// wrap breaks a comma-separated list into lines of at most width, each continuation indented.
func wrap(prefix string, items []string, width int, indent string) string {
	var b strings.Builder
	line := prefix
	for i, it := range items {
		piece := it
		if i < len(items)-1 {
			piece += ", "
		}
		if len(line)+len(piece) > width && strings.TrimSpace(line) != "" && line != prefix {
			b.WriteString(strings.TrimRight(line, " ") + "\n")
			line = indent
		}
		line += piece
	}
	b.WriteString(strings.TrimRight(line, " ") + "\n")
	return b.String()
}

func render(dir string, bundles []*bundle, r *result, notBundles, warns []string, minB, maxIPs int, full, priv, vers, ignoring, threatsExported bool, took time.Duration) string {
	var b strings.Builder
	n := len(bundles)
	line := strings.Repeat("=", 78)
	fmt.Fprintf(&b, "%s\nIP CROSS-REFERENCE: addresses found in more than one support bundle\n%s\n", line, line)
	fmt.Fprintf(&b, "Folder searched : %s\n", dir)
	fmt.Fprintf(&b, "Bundles compared: %d     Report made: %s     ipxref %s (%s)\n", n, time.Now().Format("2 Jan 2006 15:04"), version, took.Round(time.Second))
	filters := "public addresses only"
	if priv {
		filters = "ALL addresses, including private and reserved"
	}
	if !vers {
		filters += "; version numbers such as 'Build 14.1.73.37' left out"
	}
	if ignoring {
		filters += fmt.Sprintf("; %d addresses from your -ignore list left out", r.Ignored)
	}
	fmt.Fprintf(&b, "Counting        : %s\n\n", filters)

	b.WriteString(unreadWarning(bundles))

	fmt.Fprintf(&b, "SUMMARY\n-------\n")
	fmt.Fprintf(&b, "  %s distinct IP addresses were found across all %d bundles:\n", comma(int64(r.TotalDistinct)), n)
	fmt.Fprintf(&b, "    - %s %s in only ONE bundle\n", comma(int64(r.NSingle)), appear(r.NSingle))
	fmt.Fprintf(&b, "    - %s %s in 2 or more bundles (shared), of which %s %s in ALL %d bundles\n", comma(int64(r.NMulti)), appear(r.NMulti), comma(int64(r.NAll)), isAre(r.NAll), n)
	verb := "are"
	if len(r.Threats) == 1 {
		verb = "is"
	}
	fmt.Fprintf(&b, "  %d of them %s on the published threat lists (%d in more than one bundle, %d in ALL bundles). They are marked THREAT IP.\n", len(r.Threats), verb, r.ThreatMulti, r.ThreatAll)
	if minB > 1 {
		fmt.Fprintf(&b, "  This report lists only IPs found in at least %d bundles (-min-bundles).\n", minB)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "BUNDLES COMPARED\n----------------\n")
	nameW := 6
	for _, bd := range bundles {
		if len(bd.Name) > nameW {
			nameW = len(bd.Name)
		}
	}
	if nameW > 52 {
		nameW = 52
	}
	fmt.Fprintf(&b, "  %-*s  %9s  %8s  %12s  %s\n", nameW, "Bundle", "Files", "Size MB", "Distinct IPs", "Shared with others")
	for i, bd := range bundles {
		nm := bd.Name
		if len(nm) > nameW {
			nm = nm[:nameW-3] + "..."
		}
		fmt.Fprintf(&b, "  %-*s  %9s  %8.0f  %12s  %s\n", nameW, nm, comma(bd.files), float64(bd.bytes)/1048576, comma(int64(r.DistinctPerBndl[i])), comma(int64(r.SharedPerBndl[i])))
	}
	b.WriteString("\n")
	b.WriteString(renderLogHistory(bundles, r))
	b.WriteString(renderThreats(bundles, r, threatsExported))

	if len(r.Rows) == 0 {
		fmt.Fprintf(&b, "No IP address was found with the current settings (-min-bundles %d).\n", minB)
	}
	limit := maxIPs
	if limit <= 0 {
		limit = 1 << 30
	}
	type single struct{ ips, threats int }
	singles := map[int]*single{}
	for _, x := range r.Rows {
		if len(x.Seen) == 1 {
			sg := singles[x.Seen[0].B]
			if sg == nil {
				sg = &single{}
				singles[x.Seen[0].B] = sg
			}
			sg.ips++
			if x.Threat != "" {
				sg.threats++
			}
		}
	}
	lastSingleB := -1
	listed, omitted := 0, 0
	lastGroup := -1
	for _, row := range r.Rows {
		k := len(row.Seen)
		if k != lastGroup {
			lastGroup = k
			count := 0
			for _, x := range r.Rows {
				if len(x.Seen) == k {
					count++
				}
			}
			b.WriteString("\n")
			if k == n {
				fmt.Fprintf(&b, "%s\nIN ALL %d BUNDLES (%d IP%s)\n%s\n", line, n, count, pl(count), line)
				var all []string
				for _, bd := range bundles {
					all = append(all, bd.Name)
				}
				if !full && len(all) > 40 {
					all = append(all[:40], fmt.Sprintf("...and %d more", n-40))
				}
				b.WriteString(wrap("  Bundles: ", all, 100, "           "))
			} else if k == 1 {
				fmt.Fprintf(&b, "%s\nIN ONLY ONE BUNDLE (%d IP%s), listed under the bundle each was found in\n%s\n", line, count, pl(count), line)
			} else {
				fmt.Fprintf(&b, "%s\nIN %d OF %d BUNDLES (%d IP%s)\n%s\n", line, k, n, count, pl(count), line)
			}
		}
		if listed >= limit && row.Threat == "" { // the cap never hides a threat IP
			omitted++
			continue
		}
		if k == 1 { // one line per IP, grouped by bundle
			sn := row.Seen[0]
			if sn.B != lastSingleB {
				lastSingleB = sn.B
				sg := singles[sn.B]
				fmt.Fprintf(&b, "\n  %s  (%s IP%s found only in this bundle; %d on threat lists)\n", bundles[sn.B].Name, comma(int64(sg.ips)), pl(sg.ips), sg.threats)
				fmt.Fprintf(&b, "    %-16s  %8s  %-26s  %-12s  %-12s  %s\n", "IP address", "Hits", "Threat list", "First seen", "Last seen", "Found in")
			}
			threat := "no"
			if row.Threat != "" {
				threat = "YES: " + row.Threat
			}
			first, last := "-", "-"
			if sn.R.OK {
				first, last = sn.R.Lo.Format("2 Jan 2006"), sn.R.Hi.Format("2 Jan 2006")
			}
			var files []string
			for i := 0; i < int(sn.S.NEx); i++ {
				files = append(files, bundles[sn.B].names[sn.S.Ex[i]])
			}
			fmt.Fprintf(&b, "    %-16s  %8s  %-26s  %-12s  %-12s  %s\n", ipString(row.IP), comma(sn.S.Hits), threat, first, last, strings.Join(files, ", "))
			listed++
			continue
		}
		listed++
		mark := ""
		if row.Threat != "" {
			mark = "   <<< THREAT IP: " + strings.ToUpper(row.Threat)
		}
		fmt.Fprintf(&b, "\n%-16s  %s hits in %d bundle%s%s\n", ipString(row.IP), comma(row.Hits), k, pl(k), mark)
		if row.Threat != "" {
			fmt.Fprintf(&b, "    Threat list: YES, %s (listed by: %s)\n", row.Threat, row.ThreatSrc)
		} else {
			b.WriteString("    Threat list: no (not on the published attacker lists)\n")
		}
		if row.Dated {
			days := int(row.Hi.Sub(row.Lo).Hours()/24 + 0.5)
			if days == 0 {
				fmt.Fprintf(&b, "    Seen on: %s%s\n", dfull(row.Lo), yearMark(row.Inferred))
			} else {
				fmt.Fprintf(&b, "    First seen: %s    Last seen: %s    (%d day%s apart)%s\n", dfull(row.Lo), dfull(row.Hi), days, pl(days), yearMark(row.Inferred))
			}
		} else {
			b.WriteString("    Dates: none (only in files without timestamps, such as configs or command output)\n")
		}
		names := make([]string, 0, k)
		// always name the bundles (with hits and dates); very long lists are cut to the 40 with most hits
		crosses := row.Dated && row.Lo.Year() != row.Hi.Year()
		order := make([]int, len(row.Seen))
		for i := range order {
			order[i] = i
		}
		if !full && len(order) > 40 {
			sort.Slice(order, func(i, j int) bool { return row.Seen[order[i]].S.Hits > row.Seen[order[j]].S.Hits })
			order = order[:40]
			sort.Ints(order)
		}
		for _, i := range order {
			sn := row.Seen[i]
			names = append(names, fmt.Sprintf("%s (%s%s)", bundles[sn.B].Name, comma(sn.S.Hits), bundleDates(sn.R, crosses)))
		}
		b.WriteString(wrap(fmt.Sprintf("    Found in %d of %d: ", k, n), names, 100, "                  "))
		if len(order) < k {
			fmt.Fprintf(&b, "    ...and %d more bundles (all of them are in the CSV, or run with -full)\n", k-len(order))
		}
		if k < n && n-k <= 12 {
			have := map[int]bool{}
			for _, sn := range row.Seen {
				have[sn.B] = true
			}
			var missing []string
			for i, bd := range bundles {
				if !have[i] {
					missing = append(missing, bd.Name)
				}
			}
			b.WriteString(wrap("    Not found in: ", missing, 100, "                  "))
		}
		if len(row.Typical) > 0 {
			fmt.Fprintf(&b, "    Typical files: %s\n", strings.Join(row.Typical, ", "))
		}
	}
	if omitted > 0 {
		fmt.Fprintf(&b, "\n... %d more IPs not listed on screen (-max-ips %d; threat IPs are always listed). The -out file and the -csv file have every IP.\n", omitted, maxIPs)
	}

	b.WriteString("\nHOW TO READ THIS\n----------------\n")
	b.WriteString("  * 'Hits' is how many times the address appears in the bundle's text files (logs, configs, command output).\n")
	b.WriteString("  * 'First seen' / 'Last seen' come from the timestamps on the log lines that contain the address. They can only\n")
	b.WriteString("    be as old as the logs: see LOG HISTORY. An address in a config or in command output has no date.\n")
	b.WriteString("  * Log lines without a year (plain syslog style) are placed in the year of the bundle's newest dated line.\n")
	b.WriteString("  * An address in many bundles may be an attacker or scanner hitting every appliance, but it can just as\n")
	b.WriteString("    well be shared infrastructure: DNS or NTP servers, upstream routers, monitoring, your own public VIPs,\n")
	b.WriteString("    or a vendor service. Look at 'Typical files' to see the context before drawing a conclusion.\n")
	b.WriteString("  * Put addresses you know are normal in a file and pass it with -ignore to remove them from the report.\n")
	b.WriteString("  * Only IPv4 addresses are searched, and binary files (such as counters) are skipped.\n")
	if len(notBundles) > 0 {
		fmt.Fprintf(&b, "\nNot treated as bundles (not a folder or archive): %s\n", strings.Join(notBundles, ", "))
	}
	var skipped, bin int64
	for _, bd := range bundles {
		skipped += bd.skipped
		bin += bd.binary
	}
	fmt.Fprintf(&b, "\nLeft out by the filters: %s address-like strings (private/reserved ranges or version numbers); %s binary files skipped.\n", comma(skipped), comma(bin))
	if len(warns) > 0 {
		b.WriteString("\nWARNINGS (files that could not be read completely)\n")
		for i, w := range warns {
			if i >= 30 {
				fmt.Fprintf(&b, "  ... and %d more\n", len(warns)-i)
				break
			}
			b.WriteString("  " + w + "\n")
		}
	}
	return b.String()
}

func pl(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func csvSafe(v string) string {
	if v != "" && strings.ContainsAny(v[:1], "=+-@\t\r") {
		return "'" + v
	}
	return v
}

func renderCSV(bundles []*bundle, r *result) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	hdr := []string{"ip", "is_threat_ip", "threat_type", "bundles_found_in", "in_all_bundles", "found_in_bundles"}
	for _, bd := range bundles {
		hdr = append(hdr, csvSafe(bd.Name)+" (hits)") // one column per bundle: blank = not found there
	}
	hdr = append(hdr, "total_hits", "first_seen", "last_seen", "days_between", "dates_per_bundle", "typical_files", "threat_listed_by")
	w.Write(hdr)
	for _, row := range r.Rows {
		var names []string
		hits := make([]string, len(bundles))
		for _, sn := range row.Seen {
			names = append(names, bundles[sn.B].Name)
			hits[sn.B] = strconv.FormatInt(sn.S.Hits, 10)
		}
		inAll := "no"
		if len(row.Seen) == len(bundles) {
			inAll = "yes"
		}
		isThreat, threatType := "no", ""
		if row.Threat != "" {
			isThreat, threatType = "YES", row.Threat
		}
		first, lastSeen, dayStr := "", "", ""
		if row.Dated {
			first, lastSeen = row.Lo.Format("2006-01-02"), row.Hi.Format("2006-01-02")
			dayStr = strconv.Itoa(int(row.Hi.Sub(row.Lo).Hours()/24 + 0.5))
		}
		var perB []string
		for _, sn := range row.Seen {
			if sn.R.OK {
				perB = append(perB, fmt.Sprintf("%s: %s to %s", bundles[sn.B].Name, sn.R.Lo.Format("2006-01-02"), sn.R.Hi.Format("2006-01-02")))
			}
		}
		rec := []string{ipString(row.IP), isThreat, threatType, strconv.Itoa(len(row.Seen)), inAll, csvSafe(strings.Join(names, "; "))}
		rec = append(rec, hits...)
		rec = append(rec, strconv.FormatInt(row.Hits, 10), first, lastSeen, dayStr,
			csvSafe(strings.Join(perB, "; ")), csvSafe(strings.Join(row.Typical, "; ")), csvSafe(row.ThreatSrc))
		w.Write(rec)
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

func dfull(t time.Time) string { return t.Format("2 Jan 2006") }

func yearMark(inferred bool) string {
	if inferred {
		return "  (year inferred)"
	}
	return ""
}

// bundleDates is the short per-bundle date range shown after the hit count: ", 3 Sep to 5 Sep".
func bundleDates(r resolved, withYear bool) string {
	if !r.OK {
		return ""
	}
	f := "2 Jan"
	if withYear {
		f = "2 Jan 2006"
	}
	if r.Lo.Format("2006-01-02") == r.Hi.Format("2006-01-02") {
		return ", " + r.Lo.Format(f)
	}
	return ", " + r.Lo.Format(f) + " to " + r.Hi.Format(f)
}

// renderLogHistory shows how far back each bundle's logs reach and the period every bundle covers.
func renderLogHistory(bundles []*bundle, r *result) string {
	var b strings.Builder
	b.WriteString("LOG HISTORY (how far back each bundle's logs reach)\n---------------------------------------------------\n")
	nameW := 6
	for _, bd := range bundles {
		if len(bd.Name) > nameW {
			nameW = len(bd.Name)
		}
	}
	if nameW > 52 {
		nameW = 52
	}
	fmt.Fprintf(&b, "  %-*s  %-13s  %-13s  %9s  %s\n", nameW, "Bundle", "Oldest entry", "Newest entry", "Covers", "Dated log files")
	var short, undated []string
	guessed := false
	for _, bd := range bundles {
		nm := bd.Name
		if len(nm) > nameW {
			nm = nm[:nameW-3] + "..."
		}
		if !bd.log.OK {
			fmt.Fprintf(&b, "  %-*s  %-13s  %-13s  %9s  %d\n", nameW, nm, "none found", "-", "-", 0)
			undated = append(undated, bd.Name)
			continue
		}
		days := bd.log.Hi.Sub(bd.log.Lo).Hours() / 24
		cov := daysText(days)
		fmt.Fprintf(&b, "  %-*s  %-13s  %-13s  %9s  %d\n", nameW, nm, dfull(bd.log.Lo), dfull(bd.log.Hi), cov, bd.logFiles)
		if days < 7 {
			short = append(short, bd.Name)
		}
		if bd.log.Inferred && bd.refGuess {
			guessed = true
		}
	}
	b.WriteString("\n")
	who := "EVERY bundle's logs"
	if !r.AllDated {
		who = fmt.Sprintf("every bundle that has dated logs (%d of %d)", r.NDated, len(bundles))
	}
	switch {
	case r.HasOverlap:
		fmt.Fprintf(&b, "  Period covered by %s: %s to %s (%s).\n", who, dfull(r.OverlapLo), dfull(r.OverlapHi), daysText(r.OverlapHi.Sub(r.OverlapLo).Hours()/24))
		b.WriteString("  An address 'in all bundles' is only comparable inside this window; outside it some bundles have no logs.\n")
	case r.NDated >= 2:
		b.WriteString("  WARNING: the bundles' logs do not all overlap in time, so an address shared by several bundles may have been\n")
		b.WriteString("  seen at different periods. Check the First seen / Last seen dates before treating it as one event.\n")
	default:
		b.WriteString("  The overlap period cannot be worked out: fewer than two bundles have dated log lines.\n")
	}
	if len(short) > 0 {
		fmt.Fprintf(&b, "  WARNING: under 7 days of logs in: %s. Earlier activity cannot be seen there.\n", strings.Join(short, ", "))
	}
	if len(undated) > 0 {
		fmt.Fprintf(&b, "  WARNING: no dated log lines found in: %s (only addresses in logs get dates).\n", strings.Join(undated, ", "))
	}
	if guessed {
		b.WriteString("  Note: some bundles have no log line with a year, so today's year was assumed for their dates.\n")
	}
	b.WriteString("\n")
	return b.String()
}

// daysText: "<1 day", "1 day", "19 days".
func daysText(d float64) string {
	switch {
	case d < 1:
		return "<1 day"
	case d < 1.5:
		return "1 day"
	}
	return fmt.Sprintf("%.0f days", d)
}

// unreadWarning is the prominent notice about files in a compression format ipxref cannot open.
func unreadWarning(bundles []*bundle) string {
	var unread []string
	for _, bd := range bundles {
		for _, u := range bd.unread {
			unread = append(unread, bd.Name+"/"+u)
		}
	}
	if len(unread) == 0 {
		return ""
	}
	sort.Strings(unread)
	var b strings.Builder
	fmt.Fprintf(&b, "!!! %d FILE(S) COULD NOT BE READ (compressed with a format ipxref cannot open) - NOT searched, so IPs in them are missing:\n", len(unread))
	for i, u := range unread {
		if i >= 25 {
			fmt.Fprintf(&b, "      ... and %d more\n", len(unread)-i)
			break
		}
		fmt.Fprintf(&b, "      %s\n", u)
	}
	b.WriteString("    Decompress them first (for example  xz -d  or  zstd -d  on a copy) and run again; results are incomplete until then.\n\n")
	return b.String()
}

func appear(n int) string {
	if n == 1 {
		return "appears"
	}
	return "appear"
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// consoleSummary is what ipxref prints by default: a few lines, not the full report.
func consoleSummary(dir string, bundles []*bundle, r *result, warns []string, took time.Duration, written []string, alreadyPrinted bool) string {
	var b strings.Builder
	n := len(bundles)
	fmt.Fprintf(&b, "ipxref %s: compared %d bundles in %s (%s)\n\n", version, n, dir, took.Round(time.Second))
	nameW := 6
	for _, bd := range bundles {
		if len(bd.Name) > nameW {
			nameW = len(bd.Name)
		}
	}
	if nameW > 50 {
		nameW = 50
	}
	bb := byBundle(bundles, r)
	fmt.Fprintf(&b, "  %-*s  %8s  %-12s  %-12s  %10s  %10s\n", nameW, "Bundle", "Files", "Oldest log", "Newest log", "IPs found", "Threat IPs")
	for i, bd := range bundles {
		nm := bd.Name
		if len(nm) > nameW {
			nm = nm[:nameW-3] + "..."
		}
		oldest, newest := "none", "-"
		if bd.log.OK {
			oldest, newest = dfull(bd.log.Lo), dfull(bd.log.Hi)
		}
		fmt.Fprintf(&b, "  %-*s  %8s  %-12s  %-12s  %10s  %10d\n", nameW, nm, comma(bd.files), oldest, newest, comma(int64(r.DistinctPerBndl[i])), len(bb[i]))
	}
	fmt.Fprintf(&b, "\n  %s distinct IPs: %s in only one bundle, %s in 2 or more (%s in all %d).\n", comma(int64(r.TotalDistinct)), comma(int64(r.NSingle)), comma(int64(r.NMulti)), comma(int64(r.NAll)), n)
	if len(r.Threats) == 0 {
		b.WriteString("  Threat IPs: none found.\n")
	} else {
		var with []string
		for i, bd := range bundles {
			if len(bb[i]) > 0 {
				with = append(with, bd.Name)
			}
		}
		fmt.Fprintf(&b, "  Threat IPs: %d found, in %d of %d bundles: %s\n", len(r.Threats), len(with), n, strings.Join(with, ", "))
	}
	if !alreadyPrinted {
		if w := unreadWarning(bundles); w != "" {
			b.WriteString("\n" + w)
		}
	}
	if len(warns) > 0 {
		fmt.Fprintf(&b, "  %d file(s) could not be read completely (see the -out report for details); first: %s\n", len(warns), warns[0])
	}
	if len(written) > 0 {
		b.WriteString("\nFiles written:\n")
		for _, w := range written {
			fmt.Fprintf(&b, "  %s\n", w)
		}
	} else {
		b.WriteString("\nNo files written (use -csv, -out or -threats).\n")
	}
	return b.String()
}

// renderBundlesCSV: one row per bundle, including how far back its logs go.
func renderBundlesCSV(bundles []*bundle, r *result) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"bundle", "kind", "files_read", "size_mb", "distinct_ips", "ips_only_in_this_bundle", "ips_shared_with_other_bundles", "threat_ips",
		"oldest_log_entry", "newest_log_entry", "log_days", "dated_log_files", "year_inferred_for_some_dates"})
	bb := byBundle(bundles, r)
	for i, bd := range bundles {
		oldest, newest, days, inferred := "", "", "", "no"
		if bd.log.OK {
			oldest, newest = bd.log.Lo.Format("2006-01-02"), bd.log.Hi.Format("2006-01-02")
			days = strconv.Itoa(int(bd.log.Hi.Sub(bd.log.Lo).Hours()/24 + 0.5))
			if bd.log.Inferred {
				inferred = "yes"
			}
		}
		w.Write([]string{csvSafe(bd.Name), bd.Kind, strconv.FormatInt(bd.files, 10), fmt.Sprintf("%.0f", float64(bd.bytes)/1048576),
			strconv.Itoa(r.DistinctPerBndl[i]), strconv.Itoa(r.SinglePerBndl[i]), strconv.Itoa(r.SharedPerBndl[i]), strconv.Itoa(len(bb[i])),
			oldest, newest, days, strconv.Itoa(bd.logFiles), inferred})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// ---------------------------------------------------------------------------------------------------
// zip files: each archive inside a zip is its own bundle (a zip of UAC collections holds one .tar.gz per host)

const maxZipMem = 1 << 30

func isArchiveHead(head []byte) bool {
	return (len(head) > 2 && head[0] == 0x1f && head[1] == 0x8b) ||
		(len(head) >= 4 && head[0] == 'B' && head[1] == 'Z' && head[2] == 'h') ||
		(len(head) >= 262 && string(head[257:262]) == "ustar")
}

func (s *scanner) isZip(name string) bool {
	f, err := s.openRegular(name)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	return n == 4 && string(head) == "PK\x03\x04"
}

// zipBundles lists the archives inside a zip (by their first bytes, not their names). A zip with no archive in
// it becomes one bundle (its files are read as they are). other counts the non-archive files skipped otherwise.
func (s *scanner) zipBundles(name string) (out []*bundle, other int, err error) {
	f, err := s.openRegular(name)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return nil, 0, fmt.Errorf("not a readable zip: %v", err)
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	seen := map[string]int{}
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || !zf.Mode().IsRegular() {
			continue
		}
		if zf.Flags&1 != 0 {
			other++
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			other++
			continue
		}
		head := make([]byte, 512)
		n, _ := io.ReadFull(rc, head)
		rc.Close()
		if !isArchiveHead(head[:n]) {
			other++
			continue
		}
		n2 := filepath.Base(zf.Name)
		for _, suf := range []string{".tar.gz", ".tgz", ".tar.bz2", ".tar", ".gz", ".bz2"} {
			if strings.HasSuffix(strings.ToLower(n2), suf) {
				n2 = n2[:len(n2)-len(suf)]
				break
			}
		}
		bn := base + "/" + n2
		if seen[bn]++; seen[bn] > 1 {
			bn += "#" + strconv.Itoa(seen[bn])
		}
		out = append(out, &bundle{Name: bn, Kind: "zip member", File: name, ZipEntry: zf.Name, ips: map[uint32]*bstat{}})
	}
	if len(out) == 0 {
		return []*bundle{{Name: base, Kind: "archive", File: name, ips: map[uint32]*bstat{}}}, 0, nil
	}
	return out, other, nil
}

// zipMember reads the one archive a zip-member bundle stands for.
func (s *scanner) zipMember(b *bundle, f *os.File) {
	fi, err := f.Stat()
	if err != nil {
		s.warn("%s: %v", b.File, err)
		return
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		s.warn("%s: not a readable zip: %v", b.File, err)
		return
	}
	for _, zf := range zr.File {
		if zf.Name != b.ZipEntry {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			s.warn("%s/%s: %v", b.File, zf.Name, err)
			return
		}
		defer rc.Close()
		s.stream(b, label(filepath.Base(zf.Name)), rc, 0)
		return
	}
	s.warn("%s: %s not found in the zip", b.File, b.ZipEntry)
}

// zipStream reads a zip met while unpacking (a zip on disk is read in place, a nested one in memory).
func (s *scanner) zipStream(b *bundle, logical string, r io.Reader, br *bufio.Reader, depth int) {
	var ra io.ReaderAt
	var size int64
	if f, ok := r.(*os.File); ok {
		fi, err := f.Stat()
		if err != nil {
			s.warn("%s/%s: %v", b.Name, logical, err)
			return
		}
		ra, size = f, fi.Size()
	} else {
		buf, err := io.ReadAll(io.LimitReader(br, maxZipMem+1))
		if err != nil || len(buf) > maxZipMem {
			b.mu.Lock()
			b.unread = append(b.unread, fmt.Sprintf("%s (zip inside an archive, over %d MB or unreadable)", logical, maxZipMem>>20))
			b.mu.Unlock()
			return
		}
		ra, size = bytes.NewReader(buf), int64(len(buf))
	}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		s.warn("%s/%s: not a readable zip: %v", b.Name, logical, err)
		return
	}
	for _, zf := range zr.File {
		name := label(strings.TrimPrefix(zf.Name, "./"))
		if zf.FileInfo().IsDir() || !zf.Mode().IsRegular() {
			continue
		}
		if zf.Flags&1 != 0 {
			b.mu.Lock()
			b.unread = append(b.unread, name+" (encrypted zip entry)")
			b.mu.Unlock()
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			s.warn("%s/%s: %v", b.Name, name, err)
			continue
		}
		s.stream(b, name, rc, depth+1)
		rc.Close()
	}
}
