package cli

import (
	"net/url"
	"strings"

	"github.com/alephnull-sh/deadair/internal/backend"
	"github.com/alephnull-sh/deadair/internal/backend/elastic"
	"github.com/alephnull-sh/deadair/internal/backend/opensearch"
	"github.com/alephnull-sh/deadair/internal/backend/sentinel"
)

// Read targets from the actual client: fleet scans must not inherit links
// from a different instance or the command-line defaults.
func (o connOpts) navigationFor(c backend.Backend) connOpts {
	o.backendName = c.Name()
	o.esURL, o.kibanaURL, o.kibanaSpace, o.opensearchURL = "", "", "", ""
	o.azureSubscriptionID, o.azureResourceGroup, o.sentinelWorkspace = "", "", ""
	switch c := c.(type) {
	case *elastic.Client:
		o.esURL, o.kibanaURL, o.kibanaSpace = c.ESURL, c.KibanaURL, c.Space
	case *opensearch.Client:
		o.opensearchURL = c.URL
	case *sentinel.Client:
		o.azureSubscriptionID, o.azureResourceGroup, o.sentinelWorkspace = c.SubscriptionID, c.ResourceGroup, c.WorkspaceName
	}
	return o
}

func nativeBase(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return strings.TrimRight(u.String(), "/")
}

func (o connOpts) ruleURL(rule backend.Rule) string {
	if o.ruleFile != "" || o.backendName != "elastic" || rule.BackendObjectID == "" {
		return ""
	}
	base := nativeBase(o.kibanaURL)
	if base == "" {
		return ""
	}
	if o.kibanaSpace != "" && o.kibanaSpace != "default" {
		base += "/s/" + url.PathEscape(o.kibanaSpace)
	}
	return base + "/app/security/rules/id/" + url.PathEscape(rule.BackendObjectID)
}

func (o connOpts) sourceURL(source string) string {
	if o.backendName == "sentinel" {
		if strings.ContainsAny(source, "/:()") || o.azureSubscriptionID == "" || o.azureResourceGroup == "" || o.sentinelWorkspace == "" {
			return ""
		}
		return "https://portal.azure.com/#resource/subscriptions/" + url.PathEscape(o.azureSubscriptionID) + "/resourceGroups/" + url.PathEscape(o.azureResourceGroup) + "/providers/Microsoft.OperationalInsights/workspaces/" + url.PathEscape(o.sentinelWorkspace) + "/logs"
	}
	raw := o.esURL
	if o.backendName == "opensearch" {
		raw = o.opensearchURL
	}
	base := nativeBase(raw)
	if base == "" {
		return ""
	}
	return base + "/" + url.PathEscape(source) + "/_mapping"
}
