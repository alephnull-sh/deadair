package report

// DiffResult is what changed between two scan reports of the same
// deployment. Works on redacted pairs too: digests are stable, so names
// still line up.
type DiffResult struct {
	NewlyDead         []DeadDetection     `json:"newly_dead,omitempty"`
	RecoveredDead     []RuleRef           `json:"recovered_dead,omitempty"`
	NewlyImpaired     []ImpairedDetection `json:"newly_impaired,omitempty"`
	RecoveredImpaired []RuleRef           `json:"recovered_impaired,omitempty"`
	NewlyDegraded     []SourceHealth      `json:"newly_degraded,omitempty"`
	RecoveredSources  []SourceHealth      `json:"recovered_sources,omitempty"`
	NewSources        []string            `json:"new_sources,omitempty"`
	RemovedSources    []string            `json:"removed_sources,omitempty"`
	NewlyUnused       []UnusedSource      `json:"newly_unused,omitempty"`
}

// Regressions counts the changes that should fail a gate.
func (d *DiffResult) Regressions() int {
	return len(d.NewlyDead) + len(d.NewlyImpaired) + len(d.NewlyDegraded)
}

func ruleKey(id, name string) string {
	if id != "" {
		return id
	}
	return name
}

// Diff compares an older report with a newer one.
func Diff(older, newer *Report) *DiffResult {
	d := &DiffResult{}

	oldDead := map[string]bool{}
	for _, x := range older.DeadDetections {
		oldDead[ruleKey(x.ID, x.Name)] = true
	}
	newDead := map[string]bool{}
	for _, x := range newer.DeadDetections {
		k := ruleKey(x.ID, x.Name)
		newDead[k] = true
		if !oldDead[k] {
			d.NewlyDead = append(d.NewlyDead, x)
		}
	}
	for _, x := range older.DeadDetections {
		if !newDead[ruleKey(x.ID, x.Name)] {
			d.RecoveredDead = append(d.RecoveredDead, RuleRef{ID: x.ID, Name: x.Name, Severity: x.Severity})
		}
	}

	oldImp := map[string]bool{}
	for _, x := range older.ImpairedDetections {
		oldImp[ruleKey(x.ID, x.Name)] = true
	}
	newImp := map[string]bool{}
	for _, x := range newer.ImpairedDetections {
		k := ruleKey(x.ID, x.Name)
		newImp[k] = true
		if !oldImp[k] {
			d.NewlyImpaired = append(d.NewlyImpaired, x)
		}
	}
	for _, x := range older.ImpairedDetections {
		if !newImp[ruleKey(x.ID, x.Name)] {
			d.RecoveredImpaired = append(d.RecoveredImpaired, RuleRef{ID: x.ID, Name: x.Name, Severity: x.Severity})
		}
	}

	degraded := func(status string) bool { return status == "stale" || status == "empty" }
	oldSrc := map[string]SourceHealth{}
	for _, s := range older.Sources {
		oldSrc[s.Name] = s
	}
	newSrc := map[string]SourceHealth{}
	for _, s := range newer.Sources {
		newSrc[s.Name] = s
		prev, existed := oldSrc[s.Name]
		switch {
		case !existed:
			d.NewSources = append(d.NewSources, s.Name)
		case degraded(s.Status) && !degraded(prev.Status):
			d.NewlyDegraded = append(d.NewlyDegraded, s)
		case !degraded(s.Status) && degraded(prev.Status):
			d.RecoveredSources = append(d.RecoveredSources, s)
		}
	}
	for _, s := range older.Sources {
		if _, ok := newSrc[s.Name]; !ok {
			d.RemovedSources = append(d.RemovedSources, s.Name)
		}
	}

	oldUnused := map[string]bool{}
	for _, u := range older.UnusedTelemetry {
		oldUnused[u.Name] = true
	}
	for _, u := range newer.UnusedTelemetry {
		if !oldUnused[u.Name] {
			d.NewlyUnused = append(d.NewlyUnused, u)
		}
	}
	return d
}
