package backend

import (
	"strconv"
	"strings"
	"time"
)

// ParseLookback converts an Elastic date-math "from" expression (now-6m,
// now-90d, now-1h/h) into a lookback duration. Returns 0 for anything it
// cannot parse: an unknown lookback must simply disable lookback checks.
func ParseLookback(from string) time.Duration {
	s := strings.TrimSpace(from)
	if i := strings.IndexByte(s, '/'); i >= 0 { // strip rounding suffix
		s = s[:i]
	}
	if !strings.HasPrefix(s, "now-") {
		return 0
	}
	return ParseInterval(s[len("now-"):])
}

// ParseInterval converts Elastic interval strings (5m, 1h, 2d, 30s) into a
// duration. Months and years are approximated; 0 means unparseable.
func ParseInterval(s string) time.Duration {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return 0
	}
	unit := s[len(s)-1]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n < 0 {
		return 0
	}
	d := time.Duration(n)
	switch unit {
	case 's':
		return d * time.Second
	case 'm':
		return d * time.Minute
	case 'h', 'H':
		return d * time.Hour
	case 'd':
		return d * 24 * time.Hour
	case 'w':
		return d * 7 * 24 * time.Hour
	case 'M':
		return d * 30 * 24 * time.Hour
	case 'y':
		return d * 365 * 24 * time.Hour
	}
	return 0
}
