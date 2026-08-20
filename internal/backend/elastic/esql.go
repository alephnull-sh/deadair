package elastic

import (
	"fmt"
	"strings"
	"unicode"
)

// esqlSourcePatterns extracts only the direct index expressions from a simple
// ES|QL FROM command. It deliberately rejects subqueries and other source
// commands: an unsupported query stays visible as unassessed instead of being
// mapped from a guess.
func esqlSourcePatterns(query string) ([]string, error) {
	query, err := trimESQLLeadingComments(query)
	if err != nil {
		return nil, err
	}
	if !hasKeywordPrefix(query, "FROM") {
		return nil, fmt.Errorf("ES|QL query does not start with a direct FROM command")
	}

	rest := strings.TrimSpace(query[len("FROM"):])
	if rest == "" {
		return nil, fmt.Errorf("ES|QL FROM command has no source expression")
	}
	end, err := esqlCommandEnd(rest)
	if err != nil {
		return nil, err
	}
	clause := strings.TrimSpace(rest[:end])
	if clause == "" {
		return nil, fmt.Errorf("ES|QL FROM command has no source expression")
	}
	if strings.ContainsAny(clause, "()") {
		return nil, fmt.Errorf("ES|QL FROM subqueries are not supported")
	}

	if at := esqlKeywordIndex(clause, "METADATA"); at >= 0 {
		clause = strings.TrimSpace(clause[:at])
	}
	if clause == "" {
		return nil, fmt.Errorf("ES|QL FROM command has no source expression")
	}

	parts, err := splitESQLSources(clause)
	if err != nil {
		return nil, err
	}
	patterns := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("ES|QL FROM command contains an empty source expression")
		}
		if strings.HasPrefix(part, "`") {
			if !strings.HasSuffix(part, "`") || len(part) < 2 {
				return nil, fmt.Errorf("ES|QL FROM command contains an unterminated quoted source")
			}
			part = strings.ReplaceAll(part[1:len(part)-1], "``", "`")
		}
		if strings.ContainsAny(part, " \t\r\n\"'") {
			return nil, fmt.Errorf("ES|QL FROM source %q is not a direct index expression", part)
		}
		if strings.HasPrefix(part, "?") || strings.HasPrefix(part, "$") {
			return nil, fmt.Errorf("ES|QL FROM source parameters are not supported")
		}
		if _, exists := seen[part]; exists {
			continue
		}
		seen[part] = struct{}{}
		patterns = append(patterns, part)
	}
	if len(patterns) == 0 {
		return nil, fmt.Errorf("ES|QL FROM command has no source expression")
	}
	return patterns, nil
}

func trimESQLLeadingComments(query string) (string, error) {
	query = strings.TrimPrefix(query, "\ufeff")
	for {
		query = strings.TrimSpace(query)
		switch {
		case strings.HasPrefix(query, "//"):
			if newline := strings.IndexByte(query, '\n'); newline >= 0 {
				query = query[newline+1:]
				continue
			}
			return "", fmt.Errorf("ES|QL query contains only a comment")
		case strings.HasPrefix(query, "/*"):
			end := strings.Index(query[2:], "*/")
			if end < 0 {
				return "", fmt.Errorf("ES|QL query contains an unterminated comment")
			}
			query = query[end+4:]
			continue
		default:
			return query, nil
		}
	}
}

func hasKeywordPrefix(s, keyword string) bool {
	if len(s) < len(keyword) || !strings.EqualFold(s[:len(keyword)], keyword) {
		return false
	}
	return len(s) == len(keyword) || unicode.IsSpace(rune(s[len(keyword)]))
}

func esqlCommandEnd(s string) (int, error) {
	quoted := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '`':
			if quoted && i+1 < len(s) && s[i+1] == '`' {
				i++
				continue
			}
			quoted = !quoted
		case '|':
			if !quoted {
				return i, nil
			}
		}
	}
	if quoted {
		return 0, fmt.Errorf("ES|QL FROM command contains an unterminated quoted source")
	}
	return len(s), nil
}

func esqlKeywordIndex(s, keyword string) int {
	quoted := false
	for i := 0; i+len(keyword) <= len(s); i++ {
		if s[i] == '`' {
			if quoted && i+1 < len(s) && s[i+1] == '`' {
				i++
				continue
			}
			quoted = !quoted
			continue
		}
		if quoted || !strings.EqualFold(s[i:i+len(keyword)], keyword) {
			continue
		}
		beforeOK := i == 0 || unicode.IsSpace(rune(s[i-1]))
		after := i + len(keyword)
		afterOK := after == len(s) || unicode.IsSpace(rune(s[after]))
		if beforeOK && afterOK {
			return i
		}
	}
	return -1
}

func splitESQLSources(clause string) ([]string, error) {
	var parts []string
	quoted := false
	start := 0
	for i := 0; i < len(clause); i++ {
		switch clause[i] {
		case '`':
			if quoted && i+1 < len(clause) && clause[i+1] == '`' {
				i++
				continue
			}
			quoted = !quoted
		case ',':
			if !quoted {
				parts = append(parts, clause[start:i])
				start = i + 1
			}
		}
	}
	if quoted {
		return nil, fmt.Errorf("ES|QL FROM command contains an unterminated quoted source")
	}
	return append(parts, clause[start:]), nil
}
