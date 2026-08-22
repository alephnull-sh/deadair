package sentinel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/alephnull-sh/deadair/internal/backend"
)

const sentinelContentAPIVersion = "2025-09-01"

type provenanceAlertRuleJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Properties struct {
		AlertRuleTemplateName string `json:"alertRuleTemplateName"`
		TemplateVersion       string `json:"templateVersion"`
	} `json:"properties"`
}

type alertRuleTemplateJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Properties struct {
		DisplayName string `json:"displayName"`
		Version     string `json:"version"`
		Status      string `json:"status"`
	} `json:"properties"`
}

type contentTemplateJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		ContentID        string `json:"contentId"`
		ContentProductID string `json:"contentProductId"`
		Version          string `json:"version"`
		PackageVersion   string `json:"packageVersion"`
		DisplayName      string `json:"displayName"`
		ContentKind      string `json:"contentKind"`
		PackageID        string `json:"packageId"`
	} `json:"properties"`
}

type contentPackageJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		ContentID   string `json:"contentId"`
		Version     string `json:"version"`
		DisplayName string `json:"displayName"`
	} `json:"properties"`
}

type productPackageJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		ContentID        string `json:"contentId"`
		Version          string `json:"version"`
		InstalledVersion string `json:"installedVersion"`
		DisplayName      string `json:"displayName"`
	} `json:"properties"`
}

// ProvenanceEvidence follows only backend-native identifiers exposed on an
// installed rule. Display-name guesses are deliberately excluded because a
// false Content Hub association would be more misleading than an unlinked
// provenance record.
func (c *Client) ProvenanceEvidence(ctx context.Context, rules []backend.Rule) ([]backend.ProvenanceEvidence, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	observedAt := time.Now().UTC()
	installed, err := c.listProvenanceAlertRules(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return unavailableProvenance(rules, observedAt, "sentinel_rule_provenance", "installed rule provenance could not be read"), nil
	}
	byRule := indexBackendRules(rules)
	linked := make([]linkedInstalledRule, 0)
	seenLinked := make(map[string]bool)
	for _, raw := range installed {
		rule, ok := matchBackendRule(byRule, raw.Name, raw.ID)
		if !ok || strings.TrimSpace(raw.Properties.AlertRuleTemplateName) == "" {
			continue
		}
		key := provenanceKey(rule.ID) + "\x00" + provenanceKey(raw.Properties.AlertRuleTemplateName)
		if seenLinked[key] {
			continue
		}
		seenLinked[key] = true
		linked = append(linked, linkedInstalledRule{rule: rule, raw: raw})
	}
	if len(linked) == 0 {
		return nil, nil
	}

	templates, templateErr := c.listAlertRuleTemplates(ctx)
	if templateErr != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	templateIndex := indexAlertRuleTemplates(templates)
	evidence := make([]backend.ProvenanceEvidence, 0, len(linked)*2)
	for _, item := range linked {
		evidence = append(evidence, templateProvenance(item, templateIndex, templateErr, observedAt, c.workspaceResourcePath()))
	}

	contentTemplates, contentTemplateErr := c.listContentTemplates(ctx)
	if contentTemplateErr != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if contentTemplateErr != nil {
		for _, item := range linked {
			evidence = append(evidence, contentHubUnavailable(item, observedAt, c.workspaceResourcePath()))
		}
		return sortedProvenance(evidence), nil
	}

	installedPackages, installedPackageErr := c.listContentPackages(ctx)
	if installedPackageErr != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	contentIndex := indexContentTemplates(contentTemplates)
	installedPackageIndex := indexContentPackages(installedPackages)
	productPackageIndex := make(map[string]productPackageJSON)
	productPackageErrors := make(map[string]error)
	productPackageLoaded := make(map[string]bool)
	for _, item := range linked {
		content, ok := exactContentTemplate(contentIndex, item.raw.Properties.AlertRuleTemplateName)
		packageID := strings.TrimSpace(content.Properties.PackageID)
		key := provenanceKey(packageID)
		if !ok || key == "" {
			continue
		}
		if productPackageLoaded[key] {
			continue
		}
		productPackageLoaded[key] = true
		product, found, err := c.getProductPackage(ctx, packageID)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			productPackageErrors[key] = err
			continue
		}
		if found {
			productPackageIndex[key] = product
		}
	}
	for _, item := range linked {
		content, ok := exactContentTemplate(contentIndex, item.raw.Properties.AlertRuleTemplateName)
		if !ok || strings.TrimSpace(content.Properties.PackageID) == "" {
			continue
		}
		evidence = append(evidence, packageProvenance(
			item,
			content,
			installedPackageIndex,
			productPackageIndex,
			installedPackageErr,
			productPackageErrors[provenanceKey(content.Properties.PackageID)],
			observedAt,
			c.workspaceResourcePath(),
		))
	}
	return sortedProvenance(evidence), nil
}

type linkedInstalledRule struct {
	rule backend.Rule
	raw  provenanceAlertRuleJSON
}

func templateProvenance(item linkedInstalledRule, templates map[string]alertRuleTemplateJSON, listErr error, observedAt time.Time, scope string) backend.ProvenanceEvidence {
	templateID := strings.TrimSpace(item.raw.Properties.AlertRuleTemplateName)
	ref := backend.ProvenanceRef{ID: templateID, Kind: "sentinel_alert_rule_template", Scope: scope}
	evidence := backend.ProvenanceEvidence{
		RuleID:          item.rule.ID,
		BackendObjectID: item.rule.BackendObjectID,
		Provenance:      ref,
		Status:          backend.EvidenceIncomplete,
		Method:          "arm-alert-rule-template",
		ObservedAt:      observedAt,
	}
	if listErr != nil {
		evidence.Status = backend.EvidenceUnavailable
		evidence.Detail = "current template metadata could not be read"
		return evidence
	}
	template, ok := templates[provenanceKey(templateID)]
	if !ok {
		evidence.Detail = "current template metadata was not found"
		return evidence
	}
	evidence.Provenance.Name = strings.TrimSpace(template.Properties.DisplayName)
	installedVersion := strings.TrimSpace(item.raw.Properties.TemplateVersion)
	currentVersion := strings.TrimSpace(template.Properties.Version)
	if installedVersion == "" || currentVersion == "" {
		evidence.Detail = "template version metadata is incomplete"
		return evidence
	}
	evidence.Status = backend.EvidenceAssessed
	evidence.Detail = versionDetail(installedVersion, currentVersion)
	return evidence
}

func contentHubUnavailable(item linkedInstalledRule, observedAt time.Time, scope string) backend.ProvenanceEvidence {
	return backend.ProvenanceEvidence{
		RuleID:          item.rule.ID,
		BackendObjectID: item.rule.BackendObjectID,
		Provenance: backend.ProvenanceRef{
			ID:    strings.TrimSpace(item.raw.Properties.AlertRuleTemplateName) + "#content-hub",
			Kind:  "sentinel_content_hub",
			Scope: scope,
		},
		Status:     backend.EvidenceUnavailable,
		Method:     "arm-content-hub",
		ObservedAt: observedAt,
		Detail:     "Content Hub template metadata could not be read",
	}
}

func packageProvenance(item linkedInstalledRule, content contentTemplateJSON, installed map[string]contentPackageJSON, products map[string]productPackageJSON, installedErr, productErr error, observedAt time.Time, scope string) backend.ProvenanceEvidence {
	packageID := strings.TrimSpace(content.Properties.PackageID)
	ref := backend.ProvenanceRef{ID: packageID, Kind: "sentinel_content_package", Scope: scope}
	evidence := backend.ProvenanceEvidence{
		RuleID:          item.rule.ID,
		BackendObjectID: item.rule.BackendObjectID,
		Provenance:      ref,
		Status:          backend.EvidenceIncomplete,
		Method:          "arm-content-hub-package",
		ObservedAt:      observedAt,
	}
	if installedErr != nil || productErr != nil {
		evidence.Status = backend.EvidenceUnavailable
		evidence.Detail = "Content Hub package metadata could not be read"
		return evidence
	}
	installedPackage, installedOK := installed[provenanceKey(packageID)]
	productPackage, productOK := products[provenanceKey(packageID)]
	if installedOK {
		evidence.Provenance.Name = strings.TrimSpace(installedPackage.Properties.DisplayName)
	}
	if evidence.Provenance.Name == "" && productOK {
		evidence.Provenance.Name = strings.TrimSpace(productPackage.Properties.DisplayName)
	}
	if !installedOK {
		evidence.Detail = "linked Content Hub package is not installed"
		return evidence
	}
	if !productOK {
		evidence.Detail = "current Content Hub package metadata was not found"
		return evidence
	}
	installedVersion := strings.TrimSpace(installedPackage.Properties.Version)
	if installedVersion == "" {
		installedVersion = strings.TrimSpace(productPackage.Properties.InstalledVersion)
	}
	currentVersion := strings.TrimSpace(productPackage.Properties.Version)
	if installedVersion == "" || currentVersion == "" {
		evidence.Detail = "Content Hub package version metadata is incomplete"
		return evidence
	}
	evidence.Status = backend.EvidenceAssessed
	evidence.Detail = versionDetail(installedVersion, currentVersion)
	return evidence
}

func versionDetail(installed, current string) string {
	if installed == current {
		return "installed version " + installed + "; current"
	}
	return "installed version " + installed + "; current version " + current
}

func unavailableProvenance(rules []backend.Rule, observedAt time.Time, kind, detail string) []backend.ProvenanceEvidence {
	out := make([]backend.ProvenanceEvidence, 0, len(rules))
	for _, rule := range rules {
		out = append(out, backend.ProvenanceEvidence{
			RuleID:          rule.ID,
			BackendObjectID: rule.BackendObjectID,
			Provenance:      backend.ProvenanceRef{Kind: kind},
			Status:          backend.EvidenceUnavailable,
			Method:          "arm-provenance",
			ObservedAt:      observedAt,
			Detail:          detail,
		})
	}
	return sortedProvenance(out)
}

func indexBackendRules(rules []backend.Rule) map[string]backend.Rule {
	out := make(map[string]backend.Rule, len(rules)*2)
	for _, rule := range rules {
		if key := provenanceKey(rule.ID); key != "" {
			out[key] = rule
		}
		if key := provenanceKey(rule.BackendObjectID); key != "" {
			out[key] = rule
		}
	}
	return out
}

func matchBackendRule(index map[string]backend.Rule, name, id string) (backend.Rule, bool) {
	if rule, ok := index[provenanceKey(name)]; ok {
		return rule, true
	}
	rule, ok := index[provenanceKey(id)]
	return rule, ok
}

func indexAlertRuleTemplates(items []alertRuleTemplateJSON) map[string]alertRuleTemplateJSON {
	out := make(map[string]alertRuleTemplateJSON, len(items)*2)
	for _, item := range items {
		for _, value := range []string{item.ID, item.Name, resourceName(item.ID)} {
			if key := provenanceKey(value); key != "" {
				out[key] = item
			}
		}
	}
	return out
}

func indexContentTemplates(items []contentTemplateJSON) map[string]contentTemplateJSON {
	out := make(map[string]contentTemplateJSON, len(items)*3)
	for _, item := range items {
		for _, value := range []string{item.ID, item.Name, item.Properties.ContentID, resourceName(item.ID)} {
			if key := provenanceKey(value); key != "" {
				out[key] = item
			}
		}
	}
	return out
}

func exactContentTemplate(index map[string]contentTemplateJSON, templateID string) (contentTemplateJSON, bool) {
	item, ok := index[provenanceKey(templateID)]
	return item, ok
}

func indexContentPackages(items []contentPackageJSON) map[string]contentPackageJSON {
	out := make(map[string]contentPackageJSON, len(items)*3)
	for _, item := range items {
		for _, value := range []string{item.ID, item.Name, item.Properties.ContentID, resourceName(item.ID)} {
			if key := provenanceKey(value); key != "" {
				out[key] = item
			}
		}
	}
	return out
}

func provenanceKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func sortedProvenance(items []backend.ProvenanceEvidence) []backend.ProvenanceEvidence {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].RuleID != items[j].RuleID {
			return strings.ToLower(items[i].RuleID) < strings.ToLower(items[j].RuleID)
		}
		if items[i].Provenance.Kind != items[j].Provenance.Kind {
			return items[i].Provenance.Kind < items[j].Provenance.Kind
		}
		return strings.ToLower(items[i].Provenance.ID) < strings.ToLower(items[j].Provenance.ID)
	})
	return items
}

func (c *Client) listProvenanceAlertRules(ctx context.Context) ([]provenanceAlertRuleJSON, error) {
	return listSentinelContentPages[provenanceAlertRuleJSON](ctx, c, "alertRules", "installed alert-rule provenance")
}

func (c *Client) listAlertRuleTemplates(ctx context.Context) ([]alertRuleTemplateJSON, error) {
	return listSentinelContentPages[alertRuleTemplateJSON](ctx, c, "alertRuleTemplates", "alert-rule templates")
}

func (c *Client) listContentTemplates(ctx context.Context) ([]contentTemplateJSON, error) {
	return listSentinelContentPages[contentTemplateJSON](ctx, c, "contentTemplates", "installed Content Hub templates")
}

func (c *Client) listContentPackages(ctx context.Context) ([]contentPackageJSON, error) {
	return listSentinelContentPages[contentPackageJSON](ctx, c, "contentPackages", "installed Content Hub packages")
}

func (c *Client) getProductPackage(ctx context.Context, packageID string) (productPackageJSON, bool, error) {
	packageID = strings.TrimSpace(packageID)
	if packageID == "" {
		return productPackageJSON{}, false, nil
	}
	path := c.workspaceResourcePath() + "/providers/Microsoft.SecurityInsights/contentProductPackages/" + url.PathEscape(packageID)
	target := c.armEndpoint() + path + "?api-version=" + url.QueryEscape(sentinelContentAPIVersion)
	var product productPackageJSON
	if err := c.doARM(ctx, target, &product); err != nil {
		var statusErr *statusError
		if errors.As(err, &statusErr) && statusErr.code == http.StatusNotFound {
			return productPackageJSON{}, false, nil
		}
		return productPackageJSON{}, false, fmt.Errorf("reading Content Hub product package: %w", err)
	}
	return product, true, nil
}

type sentinelContentPage[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"nextLink"`
}

func listSentinelContentPages[T any](ctx context.Context, c *Client, resource, label string) ([]T, error) {
	path := c.workspaceResourcePath() + "/providers/Microsoft.SecurityInsights/" + resource
	target := c.armEndpoint() + path + "?api-version=" + url.QueryEscape(sentinelContentAPIVersion)
	seen := make(map[string]bool)
	var collected []T
	for page := 0; ; page++ {
		if page >= maxRulePages {
			return nil, fmt.Errorf("listing %s: pagination exceeded %d pages", label, maxRulePages)
		}
		if seen[target] {
			return nil, fmt.Errorf("listing %s: pagination cycle detected", label)
		}
		seen[target] = true
		var response sentinelContentPage[T]
		if err := c.doARM(ctx, target, &response); err != nil {
			return nil, fmt.Errorf("listing %s: %w", label, err)
		}
		collected = append(collected, response.Value...)
		if strings.TrimSpace(response.NextLink) == "" {
			return collected, nil
		}
		next, err := c.nextARMPage(target, response.NextLink)
		if err != nil {
			return nil, fmt.Errorf("listing %s: %w", label, err)
		}
		target = next
	}
}
