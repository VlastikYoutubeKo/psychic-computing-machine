package slate

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const TemporaryReason = "temporarily_unavailable"

var reasons = map[string]Text{
	"limited_bandwidth":               {"Capacity limit reached", "This stream is unavailable because its bandwidth limit was reached."},
	"not_intended_for_public":         {"Private stream", "This stream is not intended for public distribution."},
	"unauthorized_redistribution":     {"Stream unavailable", "This access URL has been revoked."},
	"access_revoked_by_owner":         {"Access revoked", "The stream owner has revoked access to this URL."},
	"stream_permanently_discontinued": {"Stream discontinued", "This stream is permanently unavailable at this address."},
	TemporaryReason:                   {"Temporarily unavailable", "The source is not responding. Please try again shortly."},
}

type Text struct{ Title, Subtitle string }

func ValidReason(r string) bool { _, ok := reasons[r]; return ok }
func DefaultText(r string) Text {
	if t, ok := reasons[r]; ok {
		return t
	}
	return reasons["unauthorized_redistribution"]
}
func NormalizeText(t Text) (Text, error) {
	clean := func(s string, allowBreak bool) string {
		var b strings.Builder
		for _, r := range strings.ReplaceAll(s, "\r\n", "\n") {
			if r == '\n' && allowBreak {
				b.WriteRune(r)
			} else if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				b.WriteByte(' ')
			} else {
				b.WriteRune(r)
			}
		}
		s = strings.TrimSpace(b.String())
		if !allowBreak {
			s = strings.Join(strings.Fields(s), " ")
		}
		return s
	}
	t.Title = clean(t.Title, false)
	t.Subtitle = clean(t.Subtitle, true)
	if t.Title == "" || t.Subtitle == "" || utf8.RuneCountInString(t.Title) > 32 || utf8.RuneCountInString(t.Subtitle) > 90 || strings.Count(t.Subtitle, "\n") > 1 {
		return Text{}, errors.New("slate text outside length limits")
	}
	return t, nil
}

// wrapSubtitle keeps at most two lines of 45 runes; explicit breaks are kept
// when both sides fit. An unspaced 90-rune input splits into exactly 45/45.
func wrapSubtitle(s string) string {
	parts := strings.Split(s, "\n")
	if len(parts) == 2 && utf8.RuneCountInString(parts[0]) <= 45 && utf8.RuneCountInString(parts[1]) <= 45 {
		return s
	}
	flat := strings.Join(strings.Fields(s), " ")
	r := []rune(flat)
	if len(r) <= 45 {
		return flat
	}
	cut := 45
	for i := 45; i > 0; i-- {
		if r[i] == ' ' && len(r)-i-1 <= 45 {
			cut = i
			break
		}
	}
	return strings.TrimSpace(string(r[:cut])) + "\n" + strings.TrimSpace(string(r[cut:]))
}
func fitFontSize(s string, maximum int) int {
	longest := 0.0
	for _, line := range strings.Split(s, "\n") {
		width := 0.0
		for _, r := range line {
			switch {
			case r == 'W' || r == 'M':
				width += 1.12
			case r == 'w' || r == 'm':
				width += 0.95
			case r == ' ':
				width += 0.4
			case strings.ContainsRune("ilftj.,:;!'|", r):
				width += 0.5
			case unicode.IsUpper(r):
				width += 0.9
			case unicode.IsDigit(r):
				width += 0.75
			case r > 127:
				width += 1.15
			default:
				width += 0.7
			}
		}
		if width > longest {
			longest = width
		}
	}
	if longest == 0 {
		return maximum
	}
	// Width estimates are deliberately generous. Keep 1280px inside the
	// card's ~1450px usable width for FFmpeg font metric differences.
	n := int(1280 / longest)
	if n < 28 {
		n = 28
	}
	if n > maximum {
		n = maximum
	}
	return n
}
