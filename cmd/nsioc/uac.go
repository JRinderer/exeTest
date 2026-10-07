package main

// Support for UAC (Unix-like Artifacts Collector) output: the bodyfile (a file listing in TSK format) and the
// hash_executables lists. Neither is a log, so the content rules cannot see what they are about: a bodyfile line
// is a file that EXISTS, and a hash line is a file that was HASHED.

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	bodyfileRe = regexp.MustCompile(`(^|/)bodyfile([._-][^/]*)?$|(^|/)bodyfile/`)
	uacHashRe  = regexp.MustCompile(`(^|/)hash_(executables|files)([._/-]|$)`)
	cfgNameRe  = regexp.MustCompile(`/var/cron/tabs/|/etc/cron|/nsconfig/(nsafter\.sh|rc\.netscaler)$`)
	sha256Re   = regexp.MustCompile(`(?i)(^|[^0-9a-f])([0-9a-f]{64})([^0-9a-f]|$)`)
)

// bodyfileEntry splits a TSK bodyfile line (MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime).
// The name may contain '|', so the 9 fixed fields are counted from the end.
func bodyfileEntry(line []byte) (name string, mtime int64, ok bool) {
	f := strings.Split(string(line), "|")
	n := len(f)
	if n < 11 {
		return "", 0, false
	}
	name = strings.Join(f[1:n-9], "|")
	if !strings.HasPrefix(name, "/") {
		return "", 0, false
	}
	name = strings.TrimSuffix(name, " (deleted)")
	mtime, _ = strconv.ParseInt(f[n-3], 10, 64)
	return name, mtime, true
}

// bodyLine applies the file-name rules to one bodyfile entry, so a planted file is reported as a file, not
// merely as a name mentioned in text. The finding shows the entry's modification time.
func (s *Scanner) bodyLine(local map[string]*agg, logical string, n int, line []byte) {
	name, mt, ok := bodyfileEntry(line)
	if !ok {
		return
	}
	lp := strings.ToLower(name)
	if mt > 0 && cfgNameRe.MatchString(lp) {
		s.runMu.Lock()
		if s.cfgMtime == nil {
			s.cfgMtime = map[string]int64{}
		}
		s.cfgMtime[lp] = mt
		s.runMu.Unlock()
	}
	for i := range pathRules {
		p := &pathRules[i]
		if p.Re.MatchString(lp) && (p.NotRe == nil || !p.NotRe.MatchString(lp)) {
			txt := name
			if mt > 0 {
				txt += "  [modified " + time.Unix(mt, 0).UTC().Format("2006-01-02 15:04:05") + " UTC]"
			}
			s.add(local, p.ID+"\x00"+logical, p.Sev, p.ID, p.Desc+" (listed in the bodyfile: the file existed when UAC ran)", p.Ref, logical, n, txt)
		}
	}
}

// hashLine looks for SHA-256 values (64 hex digits) that are on the published hash list. MD5 and SHA-1 lists
// cannot be matched: the published indicators are SHA-256 only.
func (s *Scanner) hashLine(local map[string]*agg, logical string, n int, line []byte) {
	if len(line) < 64 {
		return
	}
	for _, m := range sha256Re.FindAllSubmatch(line, -1) {
		sum := strings.ToLower(string(m[2]))
		if src, ok := s.hashes[sum]; ok {
			s.add(local, "listhash\x00"+logical, Compromise, "known-malicious-hash",
				"SHA-256 in a hash list matches a published IOC ("+src+")", "ctx697096_check.sh hash lists", logical, n, clean(line))
		}
	}
}
