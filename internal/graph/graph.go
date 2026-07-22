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
	Rules            []backend.Rule
	Sources          []backend.Source
	Resolutions      []backend.InputResolution
	NativeResolution bool

	ruleSources    map[string][]string                  // rule ID -> source names
	sourceRules    map[string][]string                  // source name -> rule IDs
	ruleResolution map[string][]backend.InputResolution // rule ID -> native evidence
}

// Build matches every rule's index patterns against every source name.
func Build(rules []backend.Rule, sources []backend.Source) *Graph {
	g := &Graph{
		Rules:          rules,
		Sources:        sources,
		ruleSources:    make(map[string][]string, len(rules)),
		sourceRules:    make(map[string][]string, len(sources)),
		ruleResolution: make(map[string][]backend.InputResolution, len(rules)),
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

// BuildResolved constructs the graph from backend-native resolution evidence.
// A resolution can only create an edge when it is resolved and the named
// source is present in the supplied inventory.
func BuildResolved(rules []backend.Rule, sources []backend.Source, resolutions []backend.InputResolution) *Graph {
	g := &Graph{
		Rules:            rules,
		Sources:          sources,
		Resolutions:      append([]backend.InputResolution(nil), resolutions...),
		NativeResolution: true,
		ruleSources:      make(map[string][]string, len(rules)),
		sourceRules:      make(map[string][]string, len(sources)),
		ruleResolution:   make(map[string][]backend.InputResolution, len(rules)),
	}
	inventory := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		inventory[source.Name] = struct{}{}
	}
	knownRules := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		knownRules[rule.ID] = struct{}{}
	}
	edges := make(map[string]map[string]struct{}, len(rules))
	for _, resolution := range resolutions {
		if _, ok := knownRules[resolution.RuleID]; !ok {
			continue
		}
		g.ruleResolution[resolution.RuleID] = append(g.ruleResolution[resolution.RuleID], resolution)
		if resolution.Status != backend.ResolutionResolved {
			continue
		}
		for _, source := range resolution.ResolvedSources {
			if _, ok := inventory[source]; !ok {
				continue
			}
			if edges[resolution.RuleID] == nil {
				edges[resolution.RuleID] = make(map[string]struct{})
			}
			if _, exists := edges[resolution.RuleID][source]; exists {
				continue
			}
			edges[resolution.RuleID][source] = struct{}{}
			g.ruleSources[resolution.RuleID] = append(g.ruleSources[resolution.RuleID], source)
			g.sourceRules[source] = append(g.sourceRules[source], resolution.RuleID)
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

// ResolutionsFor returns the backend-native input-resolution evidence stored
// for a rule.
func (g *Graph) ResolutionsFor(ruleID string) []backend.InputResolution {
	return g.ruleResolution[ruleID]
}

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
