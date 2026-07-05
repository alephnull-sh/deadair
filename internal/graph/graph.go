// Package graph builds the dependency graph between detection rules and the
// log sources their index patterns resolve to. The graph answers both
// directions of the same join: which detections go blind if a source
// degrades, and which telemetry is ingested but never read.
package graph

import (
	"github.com/Big-Comfy/deadair/internal/backend"
)

// Graph is the rule ↔ source dependency graph.
type Graph struct {
	Rules   []backend.Rule
	Sources []backend.Source

	ruleSources map[string][]string // rule ID -> source names
	sourceRules map[string][]string // source name -> rule IDs
}

// Build matches every rule's index patterns against every source name.
func Build(rules []backend.Rule, sources []backend.Source) *Graph {
	g := &Graph{
		Rules:       rules,
		Sources:     sources,
		ruleSources: make(map[string][]string, len(rules)),
		sourceRules: make(map[string][]string, len(sources)),
	}
	for _, r := range rules {
		for _, s := range sources {
			if MatchAny(r.Patterns, s.Name) {
				g.ruleSources[r.ID] = append(g.ruleSources[r.ID], s.Name)
				g.sourceRules[s.Name] = append(g.sourceRules[s.Name], r.ID)
			}
		}
	}
	return g
}

// FilterSources applies user source filters after backend inventory and
// before graph construction. Excludes win over includes; an empty include
// list means every source is included unless excluded.
func FilterSources(sources []backend.Source, include, exclude []string) []backend.Source {
	out := make([]backend.Source, 0, len(sources))
	for _, s := range sources {
		if len(include) > 0 && !MatchAny(include, s.Name) {
			continue
		}
		if MatchAny(exclude, s.Name) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// SourcesFor returns the names of the sources rule id depends on.
func (g *Graph) SourcesFor(ruleID string) []string { return g.ruleSources[ruleID] }

// RulesFor returns the IDs of the rules that consume the named source — its
// blast radius.
func (g *Graph) RulesFor(source string) []string { return g.sourceRules[source] }

// MatchAny reports whether name matches any of the patterns.
func MatchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if Match(p, name) {
			return true
		}
	}
	return false
}

// Match reports whether name matches pattern, where '*' matches any run of
// characters — the only wildcard Elasticsearch index patterns support.
func Match(pattern, name string) bool {
	px, nx := 0, 0
	star, mark := -1, 0
	for nx < len(name) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			star, mark = px, nx
			px++
		case px < len(pattern) && pattern[px] == name[nx]:
			px++
			nx++
		case star >= 0:
			mark++
			px, nx = star+1, mark
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
