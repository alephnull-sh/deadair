package elastic

import (
	"fmt"
	"reflect"
	"testing"
)

func TestESQLSourcePatterns(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		want  []string
	}{
		{
			name:  "direct",
			query: `FROM logs-endpoint.events.* | WHERE event.category == "process"`,
			want:  []string{"logs-endpoint.events.*"},
		},
		{
			name:  "multiple and metadata",
			query: "from logs-*, auditbeat-* METADATA _id, _index\n| LIMIT 10",
			want:  []string{"logs-*", "auditbeat-*"},
		},
		{
			name:  "leading comments and duplicate",
			query: "// candidate rule\n/* direct sources */ FROM logs-*,logs-* | LIMIT 10",
			want:  []string{"logs-*"},
		},
		{
			name:  "quoted expression",
			query: "FROM `logs-special-*` | LIMIT 10",
			want:  []string{"logs-special-*"},
		},
		{
			name:  "remote",
			query: "FROM archive:logs-* | LIMIT 10",
			want:  []string{"archive:logs-*"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := esqlSourcePatterns(tt.query)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("patterns = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestESQLSourcePatternsRejectsUnsafeQueries(t *testing.T) {
	t.Parallel()
	tests := []string{
		"ROW value = 1",
		"FROM (FROM logs-* | WHERE true) | LIMIT 10",
		"FROM logs-*, (FROM audit-* | LIMIT 1) | LIMIT 10",
		"FROM ?source | LIMIT 10",
		"FROM $source | LIMIT 10",
		"FROM METADATA _id | LIMIT 10",
		"FROM logs-*, | LIMIT 10",
		"FROM `unterminated | LIMIT 10",
		"// comment only",
	}
	for i, query := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			t.Parallel()
			if got, err := esqlSourcePatterns(query); err == nil {
				t.Fatalf("patterns = %v, want an unsupported-query error", got)
			}
		})
	}
}
