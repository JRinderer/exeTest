package main

// Timestamps: how far back each bundle's logs reach, and when each IP was first and last seen.
//
// NetScaler logs use three styles:
//
//	Apache    [29/Sep/2026:00:10:12 -0300]            (year present)
//	ns.log    Sep 29 00:10:12 <local0.info> ... 09/29/2026:00:10:12 GMT   (the embedded date has the year)
//	syslog    Sep 29 00:10:12                         (NO year)
//
// A year-less time is stored with a placeholder year (2001) and the year is inferred per bundle when the report
// is made: it is the year of the bundle's newest dated log line, or the current year if no line has a year.

import (
	"bytes"
	"time"
)

// span is the earliest and latest time seen (unix seconds, 0 = none), kept separately for times that carry a
// year (Y) and times that do not (N, placeholder year 2001).
type span struct{ MinY, MaxY, MinN, MaxN int64 }

func (s *span) note(t int64, hasYear bool) {
	if hasYear {
		if s.MinY == 0 || t < s.MinY {
			s.MinY = t
		}
		if t > s.MaxY {
			s.MaxY = t
		}
		return
	}
	if s.MinN == 0 || t < s.MinN {
		s.MinN = t
	}
	if t > s.MaxN {
		s.MaxN = t
	}
}

func (s *span) merge(o span) {
	if o.MinY != 0 {
		s.note(o.MinY, true)
		s.note(o.MaxY, true)
	}
	if o.MinN != 0 {
		s.note(o.MinN, false)
		s.note(o.MaxN, false)
	}
}

func (s span) empty() bool { return s.MinY == 0 && s.MinN == 0 }

const placeholderYear = 2001

// resolved is a span with real dates.
type resolved struct {
	Lo, Hi   time.Time
	OK       bool
	Inferred bool // at least one end had no year in the log and was placed using the reference date
}

// resolve turns a span into real dates. ref is the bundle's reference date (its newest year-bearing log time).
func (s span) resolve(ref time.Time) resolved {
	var r resolved
	take := func(t time.Time) {
		if !r.OK {
			r.Lo, r.Hi, r.OK = t, t, true
			return
		}
		if t.Before(r.Lo) {
			r.Lo = t
		}
		if t.After(r.Hi) {
			r.Hi = t
		}
	}
	if s.MinY != 0 {
		take(time.Unix(s.MinY, 0).UTC())
		take(time.Unix(s.MaxY, 0).UTC())
	}
	for _, u := range []int64{s.MinN, s.MaxN} {
		if u == 0 {
			continue
		}
		p := time.Unix(u, 0).UTC()
		t := time.Date(ref.Year(), p.Month(), p.Day(), p.Hour(), p.Minute(), p.Second(), 0, time.UTC)
		if t.After(ref.Add(48 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		r.Inferred = true
		take(t)
	}
	return r
}

func d2(b []byte) (int, bool) {
	if len(b) != 2 || b[0] < '0' || b[0] > '9' || b[1] < '0' || b[1] > '9' {
		return 0, false
	}
	return int(b[0]-'0')*10 + int(b[1]-'0'), true
}

func d4(b []byte) (int, bool) {
	if len(b) != 4 {
		return 0, false
	}
	v := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int(c-'0')
	}
	return v, true
}

func monthNum(a, b, c byte) time.Month {
	k := uint32(a|0x20)<<16 | uint32(b|0x20)<<8 | uint32(c|0x20)
	switch k {
	case 'j'<<16 | 'a'<<8 | 'n':
		return 1
	case 'f'<<16 | 'e'<<8 | 'b':
		return 2
	case 'm'<<16 | 'a'<<8 | 'r':
		return 3
	case 'a'<<16 | 'p'<<8 | 'r':
		return 4
	case 'm'<<16 | 'a'<<8 | 'y':
		return 5
	case 'j'<<16 | 'u'<<8 | 'n':
		return 6
	case 'j'<<16 | 'u'<<8 | 'l':
		return 7
	case 'a'<<16 | 'u'<<8 | 'g':
		return 8
	case 's'<<16 | 'e'<<8 | 'p':
		return 9
	case 'o'<<16 | 'c'<<8 | 't':
		return 10
	case 'n'<<16 | 'o'<<8 | 'v':
		return 11
	case 'd'<<16 | 'e'<<8 | 'c':
		return 12
	}
	return 0
}

// nsDate finds MM/DD/YYYY:HH:MM:SS in the first 110 bytes (the date NetScaler writes inside ns.log lines).
func nsDate(l []byte) (int64, bool) {
	end := len(l)
	if end > 110 {
		end = 110
	}
	for i := 0; i+19 <= end; i++ {
		if l[i+2] != '/' || l[i+5] != '/' || l[i+10] != ':' || l[i+13] != ':' || l[i+16] != ':' {
			continue
		}
		if i > 0 && l[i-1] >= '0' && l[i-1] <= '9' {
			continue
		}
		mo, o1 := d2(l[i : i+2])
		d, o2 := d2(l[i+3 : i+5])
		y, o3 := d4(l[i+6 : i+10])
		h, o4 := d2(l[i+11 : i+13])
		mi, o5 := d2(l[i+14 : i+16])
		sc, o6 := d2(l[i+17 : i+19])
		if o1 && o2 && o3 && o4 && o5 && o6 && mo >= 1 && mo <= 12 && d >= 1 && d <= 31 && y >= 2000 && y < 2100 {
			return time.Date(y, time.Month(mo), d, h, mi, sc, 0, time.UTC).Unix(), true
		}
	}
	return 0, false
}

// parseStamp reads the timestamp at the start of a log line. hasYear is false for plain syslog times.
func parseStamp(l []byte) (unix int64, hasYear, ok bool) {
	// Apache: [29/Sep/2026:00:10:12 -0300], the '[' is usually within the first 64 bytes
	head := l
	if len(head) > 64 {
		head = head[:64]
	}
	if i := bytes.IndexByte(head, '['); i >= 0 && len(l) >= i+21 {
		s := l[i+1:]
		if s[2] == '/' && s[6] == '/' && s[11] == ':' && s[14] == ':' && s[17] == ':' {
			d, o1 := d2(s[0:2])
			y, o2 := d4(s[7:11])
			h, o3 := d2(s[12:14])
			mi, o4 := d2(s[15:17])
			sc, o5 := d2(s[18:20])
			if mo := monthNum(s[3], s[4], s[5]); mo != 0 && o1 && o2 && o3 && o4 && o5 {
				return time.Date(y, mo, d, h, mi, sc, 0, time.UTC).Unix(), true, true
			}
		}
	}
	// MM/DD/YYYY:HH:MM:SS at the very start
	if len(l) >= 19 && l[2] == '/' && l[5] == '/' && l[10] == ':' {
		if t, ok := nsDate(l); ok {
			return t, true, true
		}
	}
	// syslog: Sep 29 00:10:12 (day may be space padded)
	if len(l) >= 15 && l[3] == ' ' && l[9] == ':' && l[12] == ':' {
		if mo := monthNum(l[0], l[1], l[2]); mo != 0 {
			var d int
			var o1 bool
			if l[4] == ' ' {
				d, o1 = int(l[5]-'0'), l[5] >= '0' && l[5] <= '9'
			} else {
				d, o1 = d2(l[4:6])
			}
			h, o2 := d2(l[7:9])
			mi, o3 := d2(l[10:12])
			sc, o4 := d2(l[13:15])
			if o1 && o2 && o3 && o4 && d >= 1 && d <= 31 {
				// ns.log carries the full date a little further along: prefer it, it has the year
				if t, ok := nsDate(l[15:]); ok {
					return t, true, true
				}
				return time.Date(placeholderYear, mo, d, h, mi, sc, 0, time.UTC).Unix(), false, true
			}
		}
	}
	return 0, false, false
}
