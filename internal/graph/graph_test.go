package graph

import (
	"testing"

	"github.com/Big-Comfy/deadair/internal/backend"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"logs-*", "logs-endpoint.events.process-default", true},
		{"logs-*", "winlogbeat-2026.07", false},
		{"winlogbeat-*", "winlogbeat-2026.07", true},
		{"exact", "exact", true},
		{"exact", "exact2", false},
		{"*", "anything", true},
		{"*", "", true},
		{"", "", true},
		{"", "x", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "acb", false},
		{"*-default", "logs-foo-default", true},
		{"logs-*-default", "logs-foo-bar-default", true},
		{"logs-*", "logs-", true},
	}
	for _, tt := range tests {
		if got := Match(tt.pattern, tt.name); got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

func TestBuild(t *testing.T) {
	rules := []backend.Rule{
		{ID: "r1", Enabled: true, Patterns: []string{"logs-a-*"}},
		{ID: "r2", Enabled: true, Patterns: []string{"logs-*"}},
	}
	sources := []backend.Source{
		{Name: "logs-a-default", SizeBytes: 10},
		{Name: "logs-b-default", SizeBytes: 20},
		{Name: "metrics-default", SizeBytes: 30},
	}
	g := Build(rules, sources)

	if got := g.RulesFor("logs-a-default"); len(got) != 2 {
		t.Errorf("RulesFor(logs-a-default) = %v, want both rules", got)
	}
	if got := g.SourcesFor("r1"); len(got) != 1 || got[0] != "logs-a-default" {
		t.Errorf("SourcesFor(r1) = %v, want [logs-a-default]", got)
	}
	if got := g.RulesFor("metrics-default"); len(got) != 0 {
		t.Errorf("RulesFor(metrics-default) = %v, want none", got)
	}
}

func TestFilterSources(t *testing.T) {
	sources := []backend.Source{
		{Name: "logs-a-default"},
		{Name: "logs-b-default"},
		{Name: "metrics-default"},
	}
	tests := []struct {
		name    string
		include []string
		exclude []string
		want    []string
	}{
		{
			name: "default includes everything",
			want: []string{"logs-a-default", "logs-b-default", "metrics-default"},
		},
		{
			name:    "include narrows by wildcard",
			include: []string{"logs-*"},
			want:    []string{"logs-a-default", "logs-b-default"},
		},
		{
			name:    "exclude removes by wildcard",
			exclude: []string{"logs-b-*"},
			want:    []string{"logs-a-default", "metrics-default"},
		},
		{
			name:    "exclude wins over include",
			include: []string{"logs-*"},
			exclude: []string{"logs-b-*"},
			want:    []string{"logs-a-default"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterSources(sources, tt.include, tt.exclude)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", names(got), tt.want)
			}
			for i := range got {
				if got[i].Name != tt.want[i] {
					t.Fatalf("got %v, want %v", names(got), tt.want)
				}
			}
		})
	}
}

func names(sources []backend.Source) []string {
	out := make([]string, 0, len(sources))
	for _, s := range sources {
		out = append(out, s.Name)
	}
	return out
}
